import os
import re
import json
import hashlib
import subprocess
import ast
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from config import *
from utils import *
from reports import ReportGenerator


class SecurityScanner:
    def __init__(
        self,
        project_root,
        smtp_config=None,
        report_dir=None,
        env_config=None,
        docker_config=None,
        host_config=None,
        db_config=None,
        skip_config=None,
    ):
        self.project_root = Path(project_root).resolve()
        self.smtp_config = smtp_config
        self.report_dir = (
            Path(report_dir).resolve() if report_dir else self.project_root / "var"
        )

        global \
            ENVIRONMENT_TYPE, \
            WEBSERVER_TYPE, \
            DOCKER_CONFIG, \
            HOST_CONFIG, \
            DB_CONFIG, \
            SKIP_OPTIONS
        if env_config:
            ENVIRONMENT_TYPE = env_config.get("type", "host")
            WEBSERVER_TYPE = env_config.get("webserver", "nginx")
        if docker_config:
            DOCKER_CONFIG = docker_config
        if host_config:
            HOST_CONFIG = host_config
        if db_config:
            DB_CONFIG = db_config
        if skip_config:
            # Update default SKIP_OPTIONS with provided config
            SKIP_OPTIONS.update(skip_config)

        # Results
        self.malicious_files = []
        self.suspicious_files = []
        self.misplaced_php = []
        self.modified_core = []
        self.log_evidence = []

        # Additional findings
        self.findings = defaultdict(list)
        self.critical_issues = 0
        self.warnings = 0
        self.info_items = 0
        self.report = []
        self.total_scanned = 0
        self.scan_start = None
        self.scan_end = None

    def log(self, message, level="INFO", details=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if level == "CRITICAL":
            self.critical_issues += 1
            log_critical(message)
        elif level == "WARNING":
            self.warnings += 1
            log_warning(message)
        elif level == "SUCCESS":
            log_ok(message)
        elif level == "INFO":
            self.info_items += 1
            log_info(message)
        else:
            print(message)
        log_entry = {"timestamp": timestamp, "level": level, "message": message}
        if details:
            log_entry["details"] = details
        self.report.append(log_entry)

    def add_finding(self, category, item):
        self.findings[category].extend(item if isinstance(item, list) else [item])

    def run(self):
        self.scan_start = datetime.now()
        print_banner()
        log_info(f"Project root: {self.project_root}")
        log_info(f"Scan started: {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        log_info("Mode: READ-ONLY (Detection & Suggestions Only)")
        print()

        if not SKIP_OPTIONS.get("project_files"):
            section_header("PHASE 1: Scanning for PHP in forbidden directories")
            self.scan_forbidden_directories()

            section_header("PHASE 2: Pattern-based malware detection")
            self.scan_all_php_files()
        else:
            log_info("Skipping Phase 1 & 2: Project file scanning")

        if not SKIP_OPTIONS.get("core_integrity"):
            section_header("PHASE 3: Core file integrity verification")
            self.verify_core_files()
        else:
            log_info("Skipping Phase 3: Core file integrity verification")

        if not SKIP_OPTIONS.get("logs"):
            section_header("PHASE 4: Searching access logs for attack evidence")
            self.scan_access_logs()
        else:
            log_info("Skipping Phase 4: Access log scanning")

        if not SKIP_OPTIONS.get("environment"):
            section_header("PHASE 5: Additional security checks")
            self.check_cron_jobs()
            self.check_suspicious_users()
            self.check_env_file()
            self.scan_malicious_sessions()
            self.scan_recent_modifications()
            self.scan_suspicious_pub_directory_extra()
            self.scan_writable_directories()
            self.scan_malicious_domains()
            self.check_network_connections()
            self.check_magento_version()
            self.check_file_permissions()
            self.scan_unicode_filenames()
            self.check_server_config()
        else:
            log_info("Skipping Phase 5: Additional security checks (environment)")

        if not SKIP_OPTIONS.get("database"):
            section_header("PHASE 6: Database security scan")
            self.scan_database()
        else:
            log_info("Skipping Phase 6: Database scan")

        if not SKIP_OPTIONS.get("php_config"):
            section_header("PHASE 7: PHP configuration audit")
            self.check_php_config()
        else:
            log_info("Skipping Phase 7: PHP configuration audit")

        self.scan_end = datetime.now()
        section_header("INCIDENT REPORT")
        reporter = ReportGenerator(self)
        reporter.generate_report()

    def scan_forbidden_directories(self):
        count = 0
        for no_php_dir in NO_PHP_DIRECTORIES:
            full_path = self.project_root / no_php_dir
            if not full_path.exists():
                continue
            # Scan for BOTH .php files AND any file containing PHP tags
            for f in full_path.rglob("*"):
                if f.is_dir():
                    continue
                count += 1
                rel = f.relative_to(self.project_root)

                is_php = f.suffix.lower() == ".php"
                content_threats = self._scan_file_content(f)

                if is_php or content_threats:
                    file_info = {
                        "path": str(f),
                        "relative": str(rel),
                        "size": f.stat().st_size,
                        "mtime": datetime.fromtimestamp(f.stat().st_mtime).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "sha256": self._file_hash(f),
                    }
                    if content_threats:
                        file_info["threats"] = content_threats
                        log_critical(
                            f"MALICIOUS in forbidden dir: {rel} ({', '.join(t[1] for t in content_threats[:3])})"
                        )
                        self.malicious_files.append(file_info)
                    elif is_php:
                        log_warning(
                            f"MISPLACED PHP: {rel} (size: {file_info['size']}B)"
                        )
                        self.misplaced_php.append(file_info)

        # Check for suspect filenames anywhere
        for suspect in SUSPECT_FILENAMES:
            for f in self.project_root.rglob(suspect):
                rel = f.relative_to(self.project_root)
                if "vendor" in str(rel):
                    continue
                log_warning(f"SUSPECT FILENAME: {rel}")
                self.findings["suspect_filenames"].append(str(rel))

        if count == 0:
            log_ok("No suspicious files found in forbidden directories")

    def scan_all_php_files(self):
        for scan_dir in [self.project_root / d for d in ["pub", "app", "lib", "setup"]]:
            if not scan_dir.exists():
                continue
            for php_file in scan_dir.rglob("*.php"):
                if "vendor" in str(php_file):
                    continue
                self.total_scanned += 1
                threats = self._scan_file_content(php_file)
                if threats:
                    rel = php_file.relative_to(self.project_root)
                    severity = (
                        "HIGH"
                        if any(t[0] == "malicious" for t in threats)
                        else "MEDIUM"
                    )
                    file_info = {
                        "path": str(php_file),
                        "relative": str(rel),
                        "size": php_file.stat().st_size,
                        "mtime": datetime.fromtimestamp(
                            php_file.stat().st_mtime
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                        "threats": threats,
                        "sha256": self._file_hash(php_file),
                    }
                    if severity == "HIGH":
                        if not any(
                            m["path"] == str(php_file) for m in self.malicious_files
                        ):
                            log_critical(f"MALWARE in {rel}: {threats[0][1]}")
                            self.malicious_files.append(file_info)
                    else:
                        if not any(
                            s["path"] == str(php_file) for s in self.suspicious_files
                        ):
                            self.suspicious_files.append(file_info)
        log_info(f"Scanned {self.total_scanned} PHP files")

    def _scan_file_content(self, filepath):
        threats = []
        is_image = filepath.suffix.lower() in [".jpg", ".jpeg", ".png", ".gif", ".webp"]

        try:
            # Read binary for magic byte verification
            with open(filepath, "rb") as f:
                header = f.read(2048)

            # Read text for pattern matching
            content = filepath.read_text(errors="ignore")
        except Exception:
            return threats

        # Perform magic byte verification for images
        real_type = self._verify_magic_bytes(header)

        # Flag if file extension doesn't match magic bytes (potential polyglot/masquerade)
        if is_image and real_type and real_type not in ["jpeg", "png", "gif", "webp"]:
            threats.append(
                (
                    "malicious",
                    f"Masquerade: extension is {filepath.suffix} but magic bytes suggest {real_type}",
                )
            )

        for pattern, description in MALICIOUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                # If it's an image, check if the pattern is in the middle/end (potential polyglot)
                if is_image:
                    # Basic check: if PHP code is found after image header area
                    if "<?php" in content.lower() or "eval(" in content.lower():
                        threats.append(("malicious", f"PolyShell: {description}"))
                    else:
                        # Could be false positive in metadata, but still worth flagging in forbidden dir
                        threats.append(("malicious", description))
                else:
                    threats.append(("malicious", description))

        if not threats:
            for pattern, description in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    rel = str(filepath.relative_to(self.project_root))
                    if not any(
                        safe in rel
                        for safe in ["vendor/", "dev/", "Test/", "test/", "phpseclib/"]
                    ):
                        threats.append(("suspicious", description))
        return threats

    def _verify_magic_bytes(self, header):
        """Verifies file type using magic bytes (first few bytes of file)."""
        if header.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if header.startswith(b"\x89PNG\x0d\x0a\x1a\x0a"):
            return "png"
        if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return "gif"
        if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
            return "webp"
        if header.startswith(b"<?php") or header.startswith(b"<?="):
            return "php"
        if header.startswith(b"#!"):
            return "script"
        return None

    def verify_core_files(self):
        git_dir = self.project_root / ".git"
        has_git = git_dir.exists()
        if not has_git:
            parent = self.project_root.parent
            while parent != parent.parent:
                if (parent / ".git").exists():
                    has_git = True
                    break
                parent = parent.parent
        for core_file in CORE_FILES_TO_VERIFY:
            full_path = self.project_root / core_file
            if not full_path.exists():
                continue
            if has_git:
                try:
                    result = subprocess.run(
                        ["git", "diff", "HEAD", "--", core_file],
                        capture_output=True,
                        text=True,
                        cwd=str(self.project_root),
                        timeout=10,
                    )
                    if result.stdout.strip():
                        log_warning(f"MODIFIED from git: {core_file}")
                        self.modified_core.append(
                            {"file": core_file, "sha256": self._file_hash(full_path)}
                        )
                    else:
                        log_ok(f"Clean (matches git): {core_file}")
                except Exception as e:
                    log_warning(f"Could not verify {core_file}: {e}")
            else:
                log_warning(f"No git — cannot verify: {core_file}")

    def scan_access_logs(self):
        found_logs = False
        if ENVIRONMENT_TYPE == "docker":
            nginx_cfg = DOCKER_CONFIG.get("nginx_container", {})
            container_name = nginx_cfg.get("name")
            log_path = nginx_cfg.get(
                "log_path", DOCKER_CONFIG.get("log_path", "/var/log/nginx/access.log")
            )

            if container_name:
                self.log(
                    f"Reading logs from container: {container_name}:{log_path}", "INFO"
                )
                content = self._read_remote_file(container_name, log_path)
                if content:
                    found_logs = True
                    for line_num, line in enumerate(content.splitlines(), 1):
                        # Check patterns
                        for pattern, description in LOG_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.log_evidence.append(
                                    {
                                        "log_file": f"docker:{container_name}:{log_path}",
                                        "line_number": line_num,
                                        "type": description,
                                    }
                                )
                                if len(self.log_evidence) <= 20:
                                    log_critical(f"ATTACK EVIDENCE: {description}")

                        # Check malicious IPs
                        for ip in MALICIOUS_IPS:
                            if ip in line:
                                self.log_evidence.append(
                                    {
                                        "log_file": f"docker:{container_name}:{log_path}",
                                        "line_number": line_num,
                                        "type": f"Malicious IP: {ip}",
                                    }
                                )
                                if len(self.log_evidence) <= 20:
                                    log_critical(f"MALICIOUS IP DETECTED: {ip}")
                else:
                    log_warning(
                        f"Could not read logs from container: {container_name}:{log_path}"
                    )
            else:
                log_warning(
                    "Docker environment but no Nginx container name provided for logs"
                )
        else:
            log_locations = HOST_CONFIG["log_paths"]
            project_log = str(self.project_root / "var" / "log" / "access.log")
            if project_log not in log_locations:
                log_locations.append(project_log)

            for log_path in log_locations:
                if not os.path.exists(log_path):
                    continue
                found_logs = True
                log_info(f"Scanning: {log_path}")
                try:
                    with open(log_path, "rt", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            # Check patterns
                            for pattern, description in LOG_PATTERNS:
                                if re.search(pattern, line, re.IGNORECASE):
                                    self.log_evidence.append(
                                        {
                                            "log_file": log_path,
                                            "line_number": line_num,
                                            "type": description,
                                        }
                                    )
                                    if len(self.log_evidence) <= 20:
                                        log_critical(f"ATTACK EVIDENCE: {description}")

                            # Check malicious IPs
                            for ip in MALICIOUS_IPS:
                                if ip in line:
                                    self.log_evidence.append(
                                        {
                                            "log_file": log_path,
                                            "line_number": line_num,
                                            "type": f"Malicious IP: {ip}",
                                        }
                                    )
                                    if len(self.log_evidence) <= 20:
                                        log_critical(f"MALICIOUS IP DETECTED: {ip}")
                except Exception as e:
                    log_warning(f"Error reading {log_path}: {e}")

        if not found_logs:
            log_warning("No access logs found. Check log paths manually.")

    def check_cron_jobs(self):
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines():
                    if not line.strip().startswith("#") and re.search(
                        r"(wget|curl|python|perl|bash|eval|base64)", line
                    ):
                        log_critical(f"SUSPICIOUS CRON: {line.strip()}")
            else:
                log_ok("No cron jobs found")
        except Exception as e:
            log_warning(f"Could not check cron: {e}")

    def check_suspicious_users(self):
        try:
            passwd_file = Path("/etc/passwd")
            if passwd_file.exists() and datetime.fromtimestamp(
                passwd_file.stat().st_mtime
            ) > datetime.now() - timedelta(days=30):
                log_warning(f"/etc/passwd modified recently")
        except Exception:
            pass

    def check_env_file(self):
        env_file = self.project_root / "app" / "etc" / "env.php"
        if env_file.exists():
            log_critical("app/etc/env.php exists — ALL CREDENTIALS MUST BE ROTATED")

    def scan_malicious_sessions(self):
        self.log("Scanning for malicious session files...", "INFO")
        sessions = []
        for p in [
            self.project_root / "var" / "session",
            self.project_root / "pub" / "media",
        ]:
            if not p.exists():
                continue
            for f in p.rglob("sess_*"):
                try:
                    c = f.read_text(errors="ignore")
                    if re.search(r'O:\d+:"', c) and any(
                        x in c for x in ["Monolog", "shell_exec"]
                    ):
                        sessions.append(
                            {
                                "file": str(f.relative_to(self.project_root)),
                                "size": f.stat().st_size,
                            }
                        )
                except:
                    pass
        if sessions:
            self.log(f"Found {len(sessions)} malicious session files!", "CRITICAL")
            self.add_finding("malicious_sessions", sessions)

    def scan_recent_modifications(self, days=7):
        recent = []
        cutoff = datetime.now() - timedelta(days=days)
        for f in self.project_root.rglob("*.php"):
            if "vendor" in f.parts:
                continue
            try:
                if datetime.fromtimestamp(f.stat().st_mtime) > cutoff:
                    recent.append(
                        {
                            "file": str(f.relative_to(self.project_root)),
                            "size": f.stat().st_size,
                        }
                    )
            except:
                pass
        if recent:
            self.log(f"Found {len(recent)} recently modified PHP files", "WARNING")
            self.add_finding("recent_modifications", recent)

    def scan_suspicious_pub_directory_extra(self):
        pass

    def scan_writable_directories(self):
        writable = []
        for dirpath, _, _ in os.walk(self.project_root):
            if "var" in dirpath:
                continue
            try:
                if os.stat(dirpath).st_mode & 0o002:
                    writable.append(
                        {"directory": str(Path(dirpath).relative_to(self.project_root))}
                    )
            except:
                pass
        if writable:
            self.log(f"Found {len(writable)} world-writable directories", "WARNING")
            self.add_finding("writable_directories", writable)

    def scan_malicious_domains(self):
        domains = []
        for f in self.project_root.rglob("*.php"):
            try:
                c = f.read_text(errors="ignore")
                for d in MALICIOUS_DOMAINS:
                    if d in c:
                        domains.append(
                            {"file": str(f.relative_to(self.project_root)), "domain": d}
                        )
            except:
                pass
        if domains:
            self.log(f"Found {len(domains)} files with malicious domains!", "CRITICAL")
            self.add_finding("malicious_domains", domains)

    def check_network_connections(self):
        try:
            r = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True)
            if r.returncode == 0:
                conn = [
                    l.strip()
                    for l in r.stdout.splitlines()
                    if "php" in l.lower() and "LISTEN" in l
                ]
                if conn:
                    self.log(f"Found {len(conn)} active web server connections", "INFO")
                    self.add_finding("network_connections", conn)
        except:
            pass

    def scan_unicode_filenames(self):
        self.log("Scanning for Unicode-obfuscated filenames...", "INFO")
        found = []
        for f in self.project_root.rglob("*"):
            if f.is_dir():
                continue
            name = f.name
            # Check if filename contains non-ASCII characters
            if any(ord(c) > 127 for c in name):
                rel = f.relative_to(self.project_root)
                found.append(str(rel))
                log_warning(f"UNICODE FILENAME: {rel}")
        if found:
            self.add_finding("unicode_filenames", found)
        else:
            log_ok("No Unicode-obfuscated filenames found")

    def _read_remote_file(self, container_name, file_path):
        """Read a file from a Docker container using 'docker exec'."""
        if not container_name:
            return None
        try:
            result = subprocess.run(
                ["docker", "exec", container_name, "cat", file_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception:
            return None

    def _run_remote_command(self, container_name, command_list):
        """Run a command inside a Docker container using 'docker exec'."""
        if not container_name:
            return None
        try:
            full_cmd = ["docker", "exec", container_name] + command_list
            result = subprocess.run(
                full_cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception:
            return None

    def check_server_config(self):
        self.log("Checking server configuration for PHP execution risks...", "INFO")

        vulnerable = False

        if ENVIRONMENT_TYPE == "docker":
            nginx_cfg = DOCKER_CONFIG.get("nginx_container", {})
            container_name = nginx_cfg.get("name")
            config_path = nginx_cfg.get("config_path", "/etc/nginx/nginx.conf")

            if container_name:
                self.log(
                    f"Reading Nginx config from container: {container_name}:{config_path}",
                    "INFO",
                )
                content = self._read_remote_file(container_name, config_path)
                if content:
                    if (
                        "location ~ \\.php$" in content
                        or "location ~ \\.php\\." in content
                    ):
                        if "pub/media" not in content and "/media" not in content:
                            log_critical(
                                f"POTENTIAL NGINX MISCONFIG (in container): {config_path} may allow PHP in media"
                            )
                            vulnerable = True
                        else:
                            log_ok(
                                f"NGINX (in container): PHP execution properly blocked in media dirs in {config_path}"
                            )

                    if re.search(r"location\s+\^~\s+/pub/media.*\{", content):
                        if (
                            "deny all"
                            not in content.split("location ^~ /pub/media")[1].split(
                                "}"
                            )[0]
                        ):
                            log_critical(
                                f"NGINX (in container): /pub/media may allow script execution: {config_path}"
                            )
                            vulnerable = True

                    # New Nginx Security & Performance Checks
                    for pattern, description in NGINX_CONFIG_CHECKS:
                        if not re.search(pattern, content, re.IGNORECASE):
                            log_warning(
                                f"NGINX CONFIG: {description} (in {config_path})"
                            )
                else:
                    log_warning(
                        f"Could not read config from container: {container_name}:{config_path}"
                    )
            else:
                log_warning(
                    "Docker environment but no Nginx container name provided in config.json"
                )
        else:
            if WEBSERVER_TYPE == "nginx":
                config_paths = (
                    HOST_CONFIG["nginx_config_paths"]
                    + list(Path(HOST_CONFIG["nginx_vhost_dir"]).glob("*"))
                    if Path(HOST_CONFIG["nginx_vhost_dir"]).exists()
                    else []
                )
            elif WEBSERVER_TYPE == "apache":
                config_paths = (
                    HOST_CONFIG["apache_config_paths"]
                    + list(Path(HOST_CONFIG["apache_vhost_dir"]).glob("*"))
                    if Path(HOST_CONFIG["apache_vhost_dir"]).exists()
                    else []
                )
            else:
                config_paths = (
                    HOST_CONFIG["nginx_config_paths"]
                    + HOST_CONFIG["apache_config_paths"]
                )

            for cfg in config_paths:
                if not cfg:
                    continue
                cfg_path = Path(cfg)
                if not cfg_path.exists():
                    continue

                try:
                    content = cfg_path.read_text(errors="ignore")

                    if WEBSERVER_TYPE == "nginx" or "nginx" in cfg.lower():
                        if (
                            "location ~ \\.php$" in content
                            or "location ~ \\.php\\." in content
                        ):
                            if "pub/media" not in content and "/media" not in content:
                                log_critical(
                                    f"POTENTIAL NGINX MISCONFIG: PHP execution not blocked in media dirs in {cfg}"
                                )
                                vulnerable = True
                            else:
                                log_ok(
                                    f"NGINX: PHP execution properly blocked in media dirs in {cfg}"
                                )

                        if re.search(r"location\s+\^~\s+/pub/media.*\{", content):
                            if (
                                "deny all"
                                not in content.split("location ^~ /pub/media")[1].split(
                                    "}"
                                )[0]
                            ):
                                log_critical(
                                    f"NGINX: /pub/media may allow script execution: {cfg}"
                                )
                                vulnerable = True

                        # New Nginx Security & Performance Checks
                        for pattern, description in NGINX_CONFIG_CHECKS:
                            if not re.search(pattern, content, re.IGNORECASE):
                                log_warning(f"NGINX CONFIG: {description} (in {cfg})")

                    elif WEBSERVER_TYPE == "apache" or "apache" in cfg.lower():
                        if (
                            '<FilesMatch ".php">' in content
                            or "SetHandler application/x-httpd-php" in content
                        ):
                            if "pub/media" not in content and "/media" not in content:
                                log_critical(
                                    f"POTENTIAL APACHE MISCONFIG: PHP execution not blocked in media dirs in {cfg}"
                                )
                                vulnerable = True
                            else:
                                log_ok(
                                    f"APACHE: PHP execution properly blocked in media dirs in {cfg}"
                                )

                except Exception as e:
                    log_warning(f"Could not read config {cfg}: {e}")

        if not vulnerable:
            log_ok(
                "Server configuration appears secure regarding PHP execution in media directories"
            )
        else:
            self.log(
                "Vulnerable server configuration detected - PHP may execute in media directories!",
                "CRITICAL",
            )

    def scan_database(self):
        self.log("Scanning Magento database for malicious content using PHP...", "INFO")

        # Load the permanent PHP scanner script
        # Using Path(__file__).parent to find it next to core_scanner.py
        script_path = Path(__file__).parent / "db_scan_tmp.php"

        if not script_path.exists():
            # Fallback to project root if not found next to script
            script_path = self.project_root / "db_scan_tmp.php"

        if not script_path.exists():
            log_warning(f"Database scanner script not found at {script_path}")
            return

        try:
            php_code = script_path.read_text()
            result = None

            if ENVIRONMENT_TYPE == "docker":
                php_container = DOCKER_CONFIG.get("php_container", {}).get("name")
                if php_container:
                    # Execute by piping content to docker exec -i (as requested by user)
                    # This avoids needing to copy the file to the container
                    self.log(f"Executing scanner in container: {php_container}", "INFO")
                    cmd = ["docker", "exec", "-i", php_container, "php"]
                    process = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    stdout, stderr = process.communicate(input=php_code)

                    if process.returncode == 0:
                        result = stdout
                    else:
                        log_warning(f"Docker PHP execution failed: {stderr}")
                else:
                    log_warning(
                        "Docker environment but no PHP container name provided for DB scan"
                    )
            else:
                # Local execution via pipe
                self.log("Executing scanner on host machine", "INFO")
                process = subprocess.Popen(
                    ["php"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                stdout, stderr = process.communicate(input=php_code)

                if process.returncode == 0:
                    result = stdout
                else:
                    log_warning(f"Local PHP execution failed: {stderr}")

            if result:
                try:
                    # Find the JSON part (in case there's extra output)
                    json_match = re.search(r"(\{.*\})", result, re.DOTALL)
                    if json_match:
                        data = json.loads(json_match.group(1))
                        if "error" in data:
                            log_warning(f"Database scan error: {data['error']}")
                        else:
                            found_count = len(data.get("findings", []))
                            scanned_tables = data.get("scanned_tables", [])
                            tables_str = (
                                ", ".join(scanned_tables)
                                if scanned_tables
                                else "standard tables"
                            )

                            if found_count > 0:
                                for finding in data["findings"]:
                                    self.log(
                                        f"MALICIOUS DB ENTRY in {finding['table']}.{finding['column']}: ID={finding['row_id']}",
                                        "CRITICAL",
                                    )
                                    self.add_finding("malicious_db_content", finding)
                                log_critical(
                                    f"Database scan completed: Found {found_count} malicious entries in: {tables_str}"
                                )
                            else:
                                log_ok(
                                    f"Database scan completed: No malicious entries found in: {tables_str}"
                                )
                    else:
                        log_warning(
                            f"Could not find JSON in PHP output: {result[:200]}..."
                        )
                except json.JSONDecodeError:
                    log_warning(
                        f"Failed to parse database scan results: {result[:200]}..."
                    )
        except Exception as e:
            log_warning(f"Error during database scan: {e}")

    def _get_database_credentials(self):
        if DB_CONFIG["mode"] == "auto":
            env_php_path = self.project_root / DB_CONFIG["env_php_path"]
            if not env_php_path.exists():
                env_php_path = Path(DB_CONFIG["env_php_path"])

            if env_php_path.exists():
                try:
                    content = env_php_path.read_text()

                    # Try using PHP to parse the file if available (most reliable)
                    php_cmd = (
                        f"php -r 'print(json_encode(include(\"{env_php_path}\")));'"
                    )
                    try:
                        import subprocess

                        # If in docker, try to run it in the PHP container
                        if ENVIRONMENT_TYPE == "docker":
                            php_container = DOCKER_CONFIG.get("php_container", {}).get(
                                "name"
                            )
                            if php_container:
                                result = self._run_remote_command(
                                    php_container,
                                    [
                                        "php",
                                        "-r",
                                        f'print(json_encode(include("{DB_CONFIG["env_php_path"]}")));',
                                    ],
                                )
                            else:
                                result = subprocess.check_output(
                                    php_cmd,
                                    shell=True,
                                    stderr=subprocess.STDOUT,
                                    text=True,
                                )
                        else:
                            result = subprocess.check_output(
                                php_cmd, shell=True, stderr=subprocess.STDOUT, text=True
                            )

                        if result:
                            full_config = json.loads(result)
                            db_data = (
                                full_config.get("db", {})
                                .get("connection", {})
                                .get("default", {})
                            )
                            if db_data:
                                return {
                                    "host": db_data.get("host", "127.0.0.1"),
                                    "port": 3306,  # Default
                                    "user": db_data.get("username", "root"),
                                    "password": db_data.get("password", ""),
                                    "database": db_data.get("dbname", "magento"),
                                }
                    except Exception:
                        pass  # Fallback to regex

                    # Fallback to Regex extraction if PHP is not available
                    db_config = {}
                    patterns = {
                        "host": r"\'host\'\s*=>\s*\'([^\']+)\'",
                        "user": r"\'username\'\s*=>\s*\'([^\']+)\'",
                        "password": r"\'password\'\s*=>\s*\'([^\']*)\'",
                        "database": r"\'dbname\'\s*=>\s*\'([^\']+)\'",
                    }

                    for key, pattern in patterns.items():
                        match = re.search(pattern, content)
                        if match:
                            db_config[key] = match.group(1)

                    if "host" in db_config:
                        return {
                            "host": db_config.get("host", "127.0.0.1"),
                            "port": 3306,
                            "user": db_config.get("user", "root"),
                            "password": db_config.get("password", ""),
                            "database": db_config.get("database", "magento"),
                        }
                except Exception as e:
                    self.log(f"Failed to parse env.php: {e}", "WARNING")
                    return None
            else:
                self.log(f"env.php not found at {env_php_path}", "WARNING")
                return None
        else:
            return DB_CONFIG["manual"]

    def check_php_config(self):
        self.log("Auditing PHP security configuration...", "INFO")

        php_info = None
        if ENVIRONMENT_TYPE == "docker":
            php_container = DOCKER_CONFIG.get("php_container", {}).get("name")
            if php_container:
                self.log(f"Reading PHP config from container: {php_container}", "INFO")
                php_info = self._run_remote_command(php_container, ["php", "-i"])
            else:
                log_warning("Docker environment but no PHP container name provided")
        else:
            try:
                php_info = subprocess.check_output(
                    ["php", "-i"], stderr=subprocess.STDOUT, text=True
                )
            except Exception:
                log_warning("Could not run 'php -i' on host machine")

        if not php_info:
            log_warning("Could not obtain PHP configuration info")
            return

        # Parse php -i output for relevant settings
        config_values = {}
        for line in php_info.splitlines():
            if " => " in line:
                parts = line.split(" => ")
                if len(parts) >= 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    config_values[key] = value

        vulnerabilities = []
        for setting, expected_pattern, description in PHP_INI_CHECKS:
            actual_value = config_values.get(setting)
            if actual_value is None:
                # Some settings might be slightly different in php -i output
                actual_value = next(
                    (v for k, v in config_values.items() if setting in k), None
                )

            is_secure = False
            if actual_value:
                if re.search(expected_pattern, actual_value, re.IGNORECASE):
                    is_secure = True

            if not is_secure:
                log_critical(
                    f"PHP CONFIG RISK: {description} (Current: {actual_value or 'Not set'})"
                )
                vulnerabilities.append(
                    {
                        "setting": setting,
                        "current_value": actual_value,
                        "description": description,
                    }
                )
            else:
                log_ok(f"PHP CONFIG: {setting} is secure")

        if vulnerabilities:
            self.add_finding("php_config_vulnerabilities", vulnerabilities)
        else:
            log_ok("PHP configuration audit passed (all critical checks secure)")

    def check_magento_version(self):
        composer_json = self.project_root / "composer.json"
        if composer_json.exists():
            try:
                data = json.loads(composer_json.read_text())
                version = data.get("version", "Unknown")
                log_info(f"Magento version (from composer): {version}")
                if version != "Unknown" and "2.4" in version:
                    # Very basic check, PolyShell affects many 2.x versions
                    log_warning(
                        f"Version {version} may be vulnerable to PolyShell (ensure patches are applied)"
                    )
            except:
                pass

    def check_file_permissions(self):
        # Check if pub/media is writable by web user (expected) but also check if it's world-writable
        media_dir = self.project_root / "pub" / "media"
        if media_dir.exists():
            mode = os.stat(media_dir).st_mode
            if mode & 0o002:
                log_critical("pub/media is WORLD WRITABLE! This is a high risk.")
            else:
                log_ok("pub/media permissions look standard")

    def _file_hash(self, filepath):
        try:
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha1.update(chunk)
                    sha256.update(chunk)

            s1 = sha1.hexdigest()
            if s1 in MALICIOUS_HASHES:
                log_critical(f"KNOWN MALICIOUS HASH DETECTED: {filepath.name}")
                self.add_finding("malicious_hashes", str(filepath))

            return sha256.hexdigest()
        except Exception:
            return "UNREADABLE"
