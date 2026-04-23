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
    def __init__(self, project_root, smtp_config=None, report_dir=None,
                 env_config=None, docker_config=None, host_config=None, db_config=None):
        self.project_root = Path(project_root).resolve()
        self.smtp_config = smtp_config
        self.report_dir = Path(report_dir).resolve() if report_dir else self.project_root / 'var'

        global ENVIRONMENT_TYPE, WEBSERVER_TYPE, DOCKER_CONFIG, HOST_CONFIG, DB_CONFIG
        if env_config:
            ENVIRONMENT_TYPE = env_config.get('type', 'host')
            WEBSERVER_TYPE = env_config.get('webserver', 'nginx')
        if docker_config:
            DOCKER_CONFIG = docker_config
        if host_config:
            HOST_CONFIG = host_config
        if db_config:
            DB_CONFIG = db_config

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

    def log(self, message, level='INFO', details=None):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if level == 'CRITICAL':
            self.critical_issues += 1
            log_critical(message)
        elif level == 'WARNING':
            self.warnings += 1
            log_warning(message)
        elif level == 'SUCCESS':
            log_ok(message)
        elif level == 'INFO':
            self.info_items += 1
            log_info(message)
        else:
            print(message)
        log_entry = {'timestamp': timestamp, 'level': level, 'message': message}
        if details: log_entry['details'] = details
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

        section_header("PHASE 1: Scanning for PHP in forbidden directories")
        self.scan_forbidden_directories()

        section_header("PHASE 2: Pattern-based malware detection")
        self.scan_all_php_files()

        section_header("PHASE 3: Core file integrity verification")
        self.verify_core_files()

        section_header("PHASE 4: Searching access logs for attack evidence")
        self.scan_access_logs()

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

        section_header("PHASE 6: Database security scan")
        self.scan_database()

        self.scan_end = datetime.now()
        section_header("INCIDENT REPORT")
        reporter = ReportGenerator(self)
        reporter.generate_report()

    def scan_forbidden_directories(self):
        count = 0
        for no_php_dir in NO_PHP_DIRECTORIES:
            full_path = self.project_root / no_php_dir
            if not full_path.exists(): continue
            # Scan for BOTH .php files AND any file containing PHP tags
            for f in full_path.rglob('*'):
                if f.is_dir(): continue
                count += 1
                rel = f.relative_to(self.project_root)
                
                is_php = f.suffix.lower() == '.php'
                content_threats = self._scan_file_content(f)
                
                if is_php or content_threats:
                    file_info = {
                        'path': str(f), 'relative': str(rel),
                        'size': f.stat().st_size,
                        'mtime': datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'sha256': self._file_hash(f)
                    }
                    if content_threats:
                        file_info['threats'] = content_threats
                        log_critical(f"MALICIOUS in forbidden dir: {rel} ({', '.join(t[1] for t in content_threats[:3])})")
                        self.malicious_files.append(file_info)
                    elif is_php:
                        log_warning(f"MISPLACED PHP: {rel} (size: {file_info['size']}B)")
                        self.misplaced_php.append(file_info)

        # Check for suspect filenames anywhere
        for suspect in SUSPECT_FILENAMES:
            for f in self.project_root.rglob(suspect):
                rel = f.relative_to(self.project_root)
                if 'vendor' in str(rel): continue
                log_warning(f"SUSPECT FILENAME: {rel}")
                self.findings['suspect_filenames'].append(str(rel))

        if count == 0: log_ok("No suspicious files found in forbidden directories")

    def scan_all_php_files(self):
        for scan_dir in [self.project_root / d for d in ['pub', 'app', 'lib', 'setup']]:
            if not scan_dir.exists(): continue
            for php_file in scan_dir.rglob('*.php'):
                if 'vendor' in str(php_file): continue
                self.total_scanned += 1
                threats = self._scan_file_content(php_file)
                if threats:
                    rel = php_file.relative_to(self.project_root)
                    severity = 'HIGH' if any(t[0] == 'malicious' for t in threats) else 'MEDIUM'
                    file_info = {
                        'path': str(php_file), 'relative': str(rel),
                        'size': php_file.stat().st_size,
                        'mtime': datetime.fromtimestamp(php_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'threats': threats, 'sha256': self._file_hash(php_file)
                    }
                    if severity == 'HIGH':
                        if not any(m['path'] == str(php_file) for m in self.malicious_files):
                            log_critical(f"MALWARE in {rel}: {threats[0][1]}")
                            self.malicious_files.append(file_info)
                    else:
                        if not any(s['path'] == str(php_file) for s in self.suspicious_files):
                            self.suspicious_files.append(file_info)
        log_info(f"Scanned {self.total_scanned} PHP files")

    def _scan_file_content(self, filepath):
        threats = []
        try: content = filepath.read_text(errors='ignore')
        except Exception: return threats
        for pattern, description in MALICIOUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE): threats.append(('malicious', description))
        if not threats:
            for pattern, description in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    rel = str(filepath.relative_to(self.project_root))
                    if not any(safe in rel for safe in ['vendor/', 'dev/', 'Test/', 'test/', 'phpseclib/']):
                        threats.append(('suspicious', description))
        return threats

    def verify_core_files(self):
        git_dir = self.project_root / '.git'
        has_git = git_dir.exists()
        if not has_git:
            parent = self.project_root.parent
            while parent != parent.parent:
                if (parent / '.git').exists():
                    has_git = True
                    break
                parent = parent.parent
        for core_file in CORE_FILES_TO_VERIFY:
            full_path = self.project_root / core_file
            if not full_path.exists(): continue
            if has_git:
                try:
                    result = subprocess.run(['git', 'diff', 'HEAD', '--', core_file], capture_output=True, text=True, cwd=str(self.project_root), timeout=10)
                    if result.stdout.strip():
                        log_warning(f"MODIFIED from git: {core_file}")
                        self.modified_core.append({'file': core_file, 'sha256': self._file_hash(full_path)})
                    else: log_ok(f"Clean (matches git): {core_file}")
                except Exception as e: log_warning(f"Could not verify {core_file}: {e}")
            else: log_warning(f"No git — cannot verify: {core_file}")

    def scan_access_logs(self):
        if ENVIRONMENT_TYPE == 'docker':
            nginx_cfg = DOCKER_CONFIG.get('nginx_container', {})
            log_locations = [nginx_cfg.get('log_path', DOCKER_CONFIG.get('log_path', '/var/log/nginx/access.log'))]
        else:
            log_locations = HOST_CONFIG['log_paths']
            project_log = str(self.project_root / 'var' / 'log' / 'access.log')
            if project_log not in log_locations:
                log_locations.append(project_log)
        found_logs = False
        for log_path in log_locations:
            if not os.path.exists(log_path): continue
            found_logs = True
            log_info(f"Scanning: {log_path}")
            try:
                with open(log_path, 'rt', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # Check patterns
                        for pattern, description in LOG_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.log_evidence.append({'log_file': log_path, 'line_number': line_num, 'type': description})
                                if len(self.log_evidence) <= 20: log_critical(f"ATTACK EVIDENCE: {description}")
                        
                        # Check malicious IPs
                        for ip in MALICIOUS_IPS:
                            if ip in line:
                                self.log_evidence.append({'log_file': log_path, 'line_number': line_num, 'type': f'Malicious IP: {ip}'})
                                if len(self.log_evidence) <= 20: log_critical(f"MALICIOUS IP DETECTED: {ip}")
            except Exception as e: log_warning(f"Error reading {log_path}: {e}")
        if not found_logs: log_warning("No access logs found. Check log paths manually.")

    def check_cron_jobs(self):
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines():
                    if not line.strip().startswith('#') and re.search(r'(wget|curl|python|perl|bash|eval|base64)', line):
                        log_critical(f"SUSPICIOUS CRON: {line.strip()}")
            else: log_ok("No cron jobs found")
        except Exception as e: log_warning(f"Could not check cron: {e}")

    def check_suspicious_users(self):
        try:
            passwd_file = Path('/etc/passwd')
            if passwd_file.exists() and datetime.fromtimestamp(passwd_file.stat().st_mtime) > datetime.now() - timedelta(days=30):
                log_warning(f"/etc/passwd modified recently")
        except Exception: pass

    def check_env_file(self):
        env_file = self.project_root / 'app' / 'etc' / 'env.php'
        if env_file.exists():
            log_critical("app/etc/env.php exists — ALL CREDENTIALS MUST BE ROTATED")

    def scan_malicious_sessions(self):
        self.log("Scanning for malicious session files...", 'INFO')
        sessions = []
        for p in [self.project_root / 'var' / 'session', self.project_root / 'pub' / 'media']:
            if not p.exists(): continue
            for f in p.rglob('sess_*'):
                try:
                    c = f.read_text(errors='ignore')
                    if re.search(r'O:\d+:"', c) and any(x in c for x in ['Monolog', 'shell_exec']):
                        sessions.append({'file': str(f.relative_to(self.project_root)), 'size': f.stat().st_size})
                except: pass
        if sessions:
            self.log(f"Found {len(sessions)} malicious session files!", 'CRITICAL')
            self.add_finding('malicious_sessions', sessions)

    def scan_recent_modifications(self, days=7):
        recent = []
        cutoff = datetime.now() - timedelta(days=days)
        for f in self.project_root.rglob('*.php'):
            if 'vendor' in f.parts: continue
            try:
                if datetime.fromtimestamp(f.stat().st_mtime) > cutoff:
                    recent.append({'file': str(f.relative_to(self.project_root)), 'size': f.stat().st_size})
            except: pass
        if recent:
            self.log(f"Found {len(recent)} recently modified PHP files", 'WARNING')
            self.add_finding('recent_modifications', recent)

    def scan_suspicious_pub_directory_extra(self):
        pass

    def scan_writable_directories(self):
        writable = []
        for dirpath, _, _ in os.walk(self.project_root):
            if 'var' in dirpath: continue
            try:
                if os.stat(dirpath).st_mode & 0o002:
                    writable.append({'directory': str(Path(dirpath).relative_to(self.project_root))})
            except: pass
        if writable:
            self.log(f"Found {len(writable)} world-writable directories", 'WARNING')
            self.add_finding('writable_directories', writable)

    def scan_malicious_domains(self):
        domains = []
        for f in self.project_root.rglob('*.php'):
            try:
                c = f.read_text(errors='ignore')
                for d in MALICIOUS_DOMAINS:
                    if d in c: domains.append({'file': str(f.relative_to(self.project_root)), 'domain': d})
            except: pass
        if domains:
            self.log(f"Found {len(domains)} files with malicious domains!", 'CRITICAL')
            self.add_finding('malicious_domains', domains)

    def check_network_connections(self):
        try:
            r = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
            if r.returncode == 0:
                conn = [l.strip() for l in r.stdout.splitlines() if 'php' in l.lower() and 'LISTEN' in l]
                if conn:
                    self.log(f"Found {len(conn)} active web server connections", 'INFO')
                    self.add_finding('network_connections', conn)
        except: pass

    def scan_unicode_filenames(self):
        self.log("Scanning for Unicode-obfuscated filenames...", 'INFO')
        found = []
        for f in self.project_root.rglob('*'):
            if f.is_dir(): continue
            name = f.name
            # Check if filename contains non-ASCII characters
            if any(ord(c) > 127 for c in name):
                rel = f.relative_to(self.project_root)
                found.append(str(rel))
                log_warning(f"UNICODE FILENAME: {rel}")
        if found:
            self.add_finding('unicode_filenames', found)
        else:
            log_ok("No Unicode-obfuscated filenames found")

    def check_server_config(self):
        self.log("Checking server configuration for PHP execution risks...", 'INFO')
        
        if ENVIRONMENT_TYPE == 'docker':
            nginx_cfg = DOCKER_CONFIG.get('nginx_container', {})
            config_path = nginx_cfg.get('config_path', '/etc/nginx/nginx.conf')
            config_paths = [config_path] if config_path else []
        else:
            if WEBSERVER_TYPE == 'nginx':
                config_paths = HOST_CONFIG['nginx_config_paths'] + list(Path(HOST_CONFIG['nginx_vhost_dir']).glob('*')) if Path(HOST_CONFIG['nginx_vhost_dir']).exists() else []
            elif WEBSERVER_TYPE == 'apache':
                config_paths = HOST_CONFIG['apache_config_paths'] + list(Path(HOST_CONFIG['apache_vhost_dir']).glob('*')) if Path(HOST_CONFIG['apache_vhost_dir']).exists() else []
            else:
                config_paths = HOST_CONFIG['nginx_config_paths'] + HOST_CONFIG['apache_config_paths']
        
        vulnerable = False
        
        for cfg in config_paths:
            if not cfg: continue
            cfg_path = Path(cfg)
            if not cfg_path.exists(): continue
            
            try:
                content = cfg_path.read_text(errors='ignore')
                
                if WEBSERVER_TYPE == 'nginx' or 'nginx' in cfg.lower():
                    if 'location ~ \\.php$' in content or 'location ~ \\.php\\.' in content:
                        if 'pub/media' not in content and '/media' not in content:
                            log_critical(f"POTENTIAL NGINX MISCONFIG: PHP execution not blocked in media dirs in {cfg}")
                            vulnerable = True
                        else:
                            log_ok(f"NGINX: PHP execution properly blocked in media dirs in {cfg}")
                    
                    if re.search(r'location\s+\^~\s+/pub/media.*\{', content):
                        if 'deny all' not in content.split('location ^~ /pub/media')[1].split('}')[0]:
                            log_critical(f"NGINX: /pub/media may allow script execution: {cfg}")
                            vulnerable = True
                            
                elif WEBSERVER_TYPE == 'apache' or 'apache' in cfg.lower():
                    if '<FilesMatch ".php">' in content or 'SetHandler application/x-httpd-php' in content:
                        if 'pub/media' not in content and '/media' not in content:
                            log_critical(f"POTENTIAL APACHE MISCONFIG: PHP execution not blocked in media dirs in {cfg}")
                            vulnerable = True
                        else:
                            log_ok(f"APACHE: PHP execution properly blocked in media dirs in {cfg}")
                            
            except Exception as e:
                log_warning(f"Could not read config {cfg}: {e}")
        
        if not vulnerable:
            log_ok("Server configuration appears secure regarding PHP execution in media directories")
        else:
            self.log("Vulnerable server configuration detected - PHP may execute in media directories!", 'CRITICAL')

    def scan_database(self):
        self.log("Scanning Magento database for malicious content...", 'INFO')
        
        db_creds = self._get_database_credentials()
        if not db_creds:
            self.log("Could not obtain database credentials. Skipping database scan.", 'WARNING')
            return
        
        try:
            import pymysql
        except ImportError:
            self.log("pymysql not installed. Installing...", 'INFO')
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', 'pymysql'], capture_output=True)
                import pymysql
            except Exception as e:
                self.log(f"Could not install pymysql: {e}. Database scan skipped.", 'WARNING')
                return
        
        try:
            connection = pymysql.connect(
                host=db_creds['host'],
                port=db_creds['port'],
                user=db_creds['user'],
                password=db_creds['password'],
                database=db_creds['database']
            )
            
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                for table in MAGENTO_DB_TABLES:
                    try:
                        cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
                        result = cursor.fetchone()
                        self.log(f"Scanning table {table} ({result['cnt']} rows)...", 'INFO')
                        
                        cursor.execute(f"DESCRIBE {table}")
                        columns = [row['Field'] for row in cursor.fetchall()]
                        
                        text_columns = [col for col in columns if any(t in col.lower() for t in ['content', 'value', 'config', 'data', 'script', 'code', 'html', 'body'])]
                        
                        if not text_columns:
                            continue
                        
                        for col in text_columns:
                            query = f"SELECT * FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"
                            cursor.execute(query)
                            
                            for row in cursor.fetchall():
                                value = str(row.get(col, ''))
                                for pattern, description in DB_MALICIOUS_PATTERNS:
                                    if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                                        self.log(f"MALICIOUS DB ENTRY in {table}.{col}: ID={row.get('config_id', row.get('block_id', 'unknown'))}", 'CRITICAL')
                                        self.add_finding('malicious_db_content', {
                                            'table': table,
                                            'column': col,
                                            'row_id': row.get('config_id', row.get('block_id', row.get('id', 'unknown'))),
                                            'pattern': description,
                                            'path': row.get('path', 'N/A')
                                        })
                                        break
                                        
                    except Exception as e:
                        self.log(f"Error scanning table {table}: {e}", 'WARNING')
                        
            connection.close()
            log_ok("Database scan completed")
            
        except Exception as e:
            self.log(f"Database connection failed: {e}", 'WARNING')

    def _get_database_credentials(self):
        if DB_CONFIG['mode'] == 'auto':
            env_php_path = self.project_root / DB_CONFIG['env_php_path']
            if not env_php_path.exists():
                env_php_path = Path(DB_CONFIG['env_php_path'])
            
            if env_php_path.exists():
                try:
                    content = env_php_path.read_text()
                    db_config = {}
                    exec(content, db_config)
                    
                    return {
                        'host': db_config.get('db', {}).get('host', '127.0.0.1'),
                        'port': int(db_config.get('db', {}).get('port', 3306)),
                        'user': db_config.get('db', {}).get('username', 'root'),
                        'password': db_config.get('db', {}).get('password', ''),
                        'database': db_config.get('db', {}).get('dbname', 'magento'),
                    }
                except Exception as e:
                    self.log(f"Failed to parse env.php: {e}", 'WARNING')
                    return None
            else:
                self.log(f"env.php not found at {env_php_path}", 'WARNING')
                return None
        else:
            return DB_CONFIG['manual']

    def check_magento_version(self):
        composer_json = self.project_root / 'composer.json'
        if composer_json.exists():
            try:
                data = json.loads(composer_json.read_text())
                version = data.get('version', 'Unknown')
                log_info(f"Magento version (from composer): {version}")
                if version != 'Unknown' and '2.4' in version:
                    # Very basic check, PolyShell affects many 2.x versions
                    log_warning(f"Version {version} may be vulnerable to PolyShell (ensure patches are applied)")
            except: pass

    def check_file_permissions(self):
        # Check if pub/media is writable by web user (expected) but also check if it's world-writable
        media_dir = self.project_root / 'pub' / 'media'
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
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            s1 = sha1.hexdigest()
            if s1 in MALICIOUS_HASHES:
                log_critical(f"KNOWN MALICIOUS HASH DETECTED: {filepath.name}")
                self.add_finding('malicious_hashes', str(filepath))
                
            return sha256.hexdigest()
        except Exception: return 'UNREADABLE'
