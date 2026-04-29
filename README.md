# Magento Security Incident Response Scanner Service

The **Magento Security Scanner** is a centralized service designed to monitor and audit multiple Magento projects on the same server for PHP webshells, object injection payloads, malware (including PolyShell/APSB25-94), and database-level injections.

By utilizing a centralized configuration, you can run security audits across your entire server fleet without modifying individual project files or leaving footprints in target directories.

## Architecture

- `security_scanner.py`: The central CLI service runner.
- `core_scanner.py`: The scanning engine (read-only advisory mode).
- `config.py`: Global detection patterns and malicious rules.
- `reports.py`: Dynamic reporting engine (HTML/JSON/Email).
- `config.json`: External configuration for multi-project management.

## Key Features

- **Advanced PolyShell Detection**: Detects polyglot files (valid image headers like GIF89a/JPEG/PNG with embedded PHP code) by analyzing binary headers and file content.
- **Binary Magic Byte Verification**: Validates file types using magic bytes to identify "Masquerade" attacks (e.g., a `.jpg` file that is actually a PHP script).
- **Database Scanning**: Scans `core_config_data`, `cms_block`, `cms_page`, and other tables for malicious JavaScript or PHP injections.
- **Server Configuration Audit**: Verifies Nginx/Apache configurations to ensure PHP execution is explicitly blocked in media and static directories.
- **Multi-Container Docker Support**: Seamlessly works with separate containers for Nginx, PHP-FPM, and Database.
- **REST API Log Analysis**: Searches access logs for specific PolyShell exploitation patterns targeting the Magento REST API.
- **Multi-Project Batch Scanning**: Audits multiple Magento installations in one run using a single JSON configuration.

## Installation & Setup

1. Copy the `config.json.sample` to `config.json`.
2. Configure your SMTP settings and list the absolute paths to your Magento projects.
3. Configure the environment and container settings for your Docker setup.
4. (Optional) Create a centralized logging directory (e.g., `/var/log/magento_scans`).

```json
{
  "smtp": {
    "host": "smtp.yourprovider.com",
    "port": 587,
    "user": "alerts@domain.com",
    "pass": "your_password",
    "to_email": "security_team@domain.com"
  },
  "projects": [
    "/var/www/html/project_a",
    "/var/www/html/project_b"
  ],
  "report_directory": "/var/log/magento_scans",

  "environment": {
    "type": "docker",
    "webserver": "nginx"
  },

  "docker": {
    "enabled": true,
    "nginx_container": {
      "name": "uat-nginx-1",
      "config_path": "/etc/nginx/nginx.conf",
      "log_path": "/var/log/nginx/access.log"
    },
    "php_container": {
      "name": "uat-fpm-1",
      "socket_path": "/var/run/php/php-fpm.sock"
    },
    "db_container": {
      "name": "uat-db-1",
      "port": 3306
    },
    "magento_root": "/var/www/html",
    "log_path": "/var/log/nginx/access.log"
  },

  "database": {
    "mode": "auto",
    "env_php_path": "app/etc/env.php"
  }
}
```

---

## Configuration Options

### Environment Configuration

| Setting | Description | Values |
|---------|-------------|--------|
| `environment.type` | Deployment environment | `host`, `docker`, `vagrant`, `custom` |
| `environment.webserver` | Web server type | `nginx`, `apache`, `custom` |

### Docker Configuration (when `type: "docker"`)

Supports **multi-container setups** where Nginx, PHP-FPM, and database run in separate containers.

| Setting | Description |
|---------|-------------|
| `docker.enabled` | Enable Docker mode |
| `docker.nginx_container.name` | Nginx container name (or null for auto-detect) |
| `docker.nginx_container.config_path` | Path to nginx config inside container |
| `docker.nginx_container.log_path` | Access log path inside nginx container |
| `docker.php_container.name` | PHP-FPM container name (or null for auto-detect) |
| `docker.php_container.socket_path` | PHP-FPM socket path inside container |
| `docker.db_container.name` | Database container name (or null for auto-detect) |
| `docker.db_container.port` | Database port exposed by container |
| `docker.magento_root` | Magento root path inside containers |
| `docker.log_path` | Fallback log path |

### Host Configuration (when `type: "host"`)

| Setting | Description |
|---------|-------------|
| `host.nginx_config_paths` | List of Nginx config file paths |
| `host.apache_config_paths` | List of Apache config file paths |
| `host.log_paths` | List of access log paths |

### Database Configuration

| Setting | Description | Values |
|---------|-------------|--------|
| `database.mode` | Credential source | `auto` (reads from env.php), `manual` |
| `database.env_php_path` | Path to Magento's env.php | Relative to project or absolute |
| `database.manual.*` | Manual DB credentials | host, port, user, password, database |
| `database.tables` | (Optional) List of tables to scan | Overrides default table list |

### Customizing Database Scans

The database scan uses a specialized PHP script [db_scan_tmp.php](file:///Users/durga/Project/magento-PolyShell-scan/PolyShell-scan/db_scan_tmp.php) located in the scanner directory.

To add more tables or custom patterns to the database scan:
1. Open `db_scan_tmp.php`.
2. Locate the `$tables` array (around line 73) and add your desired table names.
3. Locate the `$patterns` array (around line 76) and add your custom regex patterns and descriptions.

The scanner will automatically identify available columns in new tables and scan them for your patterns.

---

## Remote execution architecture

The scanner uses a "Read and Pipe" architecture for PHP execution, which is highly compatible with secure Docker environments:
- The PHP code is read from local scripts and piped directly to the target environment via `docker exec -i <container> php` or the host's `php` CLI.
- This avoids leaving temporary files in the target environment and ensures that any environment variables defined in the container (e.g., in `env.php`) are correctly resolved.

### Skip Options

You can skip specific phases of the scan by setting these options to `true` in `config.json`:

| Setting | Phase(s) Skipped | Description |
|---------|------------------|-------------|
| `skips.project_files` | Phase 1 & 2 | Skips scanning files in forbidden directories and pattern-based malware detection |
| `skips.core_integrity`| Phase 3 | Skips git integrity check of core files |
| `skips.logs`          | Phase 4 | Skips access log analysis for attack evidence |
| `skips.environment`   | Phase 5 | Skips additional security checks (cron, users, server config, etc.) |
| `skips.database`      | Phase 6 | Skips database scan for malicious content |
| `skips.php_config`    | Phase 7 | Skips PHP configuration audit |

---

## Advanced File Verification Logic

The scanner goes beyond simple extension checks to identify sophisticated attacks:

### 1. Magic Byte Verification
The scanner reads the first 2048 bytes of every file in forbidden directories to identify its **true type** based on binary headers.
- **Detected Types**: JPEG, PNG, GIF, WEBP, PHP, and Shell Scripts.

### 2. Masquerade Detection
If a file has an image extension (e.g., `.jpg`) but its magic bytes identify it as a PHP script, it is flagged as a **Masquerade** attack.

### 3. PolyShell / Polyglot Analysis
If a file has a **valid image header** but contains PHP execution tags (`<?php`, `eval(`, etc.) further down in its content, it is flagged as a **PolyShell** attack. This reduces false positives from valid image metadata while catching embedded malware.

---

## Docker Multi-Container Setup

If your Magento environment uses separate containers for Nginx, PHP-FPM, and database:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Nginx     │────▶│  PHP-FPM    │────▶│    MySQL    │
│  Container   │     │  Container  │     │  Container   │
│ uat-nginx-1 │     │ uat-fpm-1   │     │ uat-db-1    │
└─────────────┘     └─────────────┘     └─────────────┘
```

Configure each container in `config.json`:

```json
{
  "docker": {
    "nginx_container": {
      "name": "uat-nginx-1",
      "config_path": "/etc/nginx/nginx.conf",
      "log_path": "/var/log/nginx/access.log"
    },
    "php_container": {
      "name": "uat-fpm-1",
      "socket_path": "/var/run/php/php-fpm.sock"
    },
    "db_container": {
      "name": "uat-db-1",
      "port": 3306
    },
    "magento_root": "/var/www/html"
  }
}
```

---

## Execution Modes

### 1. Centralized Batch Scan (Service Mode)

Scan all projects defined in your `config.json` and save reports to your central logging directory.

```bash
sudo python3 security_scanner.py --config config.json
```

### 2. Manual Single Project Scan

Perform a quick ad-hoc scan on a specific directory. Reports will be saved in the project's `var/` folder.

```bash
sudo python3 security_scanner.py /path/to/magento --email your@email.com
```

---

## Server & PHP Configuration Audit

The scanner performs a deep audit of your web server (Nginx/Apache) and PHP environment for both **Security** and **Performance**.

### 1. Nginx Configuration Checks
- **PHP Execution Blocks**: Verifies that PHP cannot execute in `pub/media`, `pub/static`, or `var` directories.
- **Security Headers**: Checks for `X-Frame-Options` (Clickjacking protection) and `X-Content-Type-Options`.
- **Version Hiding**: Ensures `server_tokens off` is set to hide Nginx version.
- **Performance**: Checks for `gzip` compression, `keepalive_timeout`, and proper `client_max_body_size`.

### 2. PHP Configuration (php.ini) Audit
The scanner checks for Magento-specific security and performance recommendations:

#### Security Settings:
- **`disable_functions`**: Ensures dangerous functions like `exec`, `shell_exec`, `system`, etc., are disabled.
- **`allow_url_include`**: Verifies remote file inclusion is disabled (**Critical**).
- **`display_errors`**: Ensures errors are not leaked to end-users.
- **`session.use_strict_mode`**: Prevents session fixation attacks.

#### Performance Settings:
- **Opcache**: Verifies `opcache.enable` is On and has sufficient memory (`opcache.memory_consumption`).
- **Memory Limit**: Checks if `memory_limit` is at least 512M (Magento requirement).
- **Execution Time**: Ensures `max_execution_time` is sufficient for Magento processes.
- **Realpath Cache**: Checks `realpath_cache_size` for optimal file system performance.

---

## Technical Details

### Docker Environment Handling
The scanner is designed to run on the **host machine** but can audit services running inside **Docker containers**:
- **Log Scanning**: Uses `docker exec` to stream and analyze access logs from the Nginx container.
- **Config Audit**: Uses `docker exec` to read and verify Nginx/Apache configuration files inside containers.
- **Database Credentials**: Automatically attempts to use `php` inside the PHP-FPM container to safely parse `env.php` and extract database credentials.
- **File System**: Scans the project files directly from the host (assuming the project directory is mounted or accessible on the host).

### Advanced File Verification Logic
The scanner goes beyond simple extension checks to identify sophisticated attacks:
- **Magic Byte Verification**: Identifies the true file type (JPEG, PNG, PHP, etc.) based on binary headers.
- **Masquerade Detection**: Flags files where the extension (e.g., `.jpg`) doesn't match the actual binary type.
- **PolyShell Analysis**: Detects valid images containing hidden PHP execution tags, reducing false positives from image metadata.


1. **Phase 1**: Advanced binary & extension scanning in forbidden directories (`pub/media`, `var/session`, etc.)
2. **Phase 2**: Pattern-based malware detection in all PHP files.
3. **Phase 3**: Core file integrity verification (compares against `git HEAD`).
4. **Phase 4**: Access log analysis for REST API attack patterns and malicious IPs.
5. **Phase 5**: Additional security checks (Cron jobs, recent `/etc/passwd` changes, world-writable directories, etc.)
6. **Phase 6**: Database scan for XSS and PHP injections in CMS and configuration tables.

---

## Reports

All reports are prefixed with the project name to prevent overwriting in centralized mode:
- `project_name_security_report.html`: Visual security dashboard.
- `project_name_security_report.json`: Detailed machine-readable audit log.

---

## Security Best Practices

- **Strictly Read-Only**: This tool never modifies or deletes files. Review the "Mandatory Remediation Checklist" in the reports for manual cleanup steps.
- **Run with Sudo**: Necessary for accessing system logs, crontabs, and protected Magento files (`env.php`).
- **Database Credentials**: Use `mode: "auto"` to read from Magento's `env.php` - the scanner will NOT store or transmit these credentials.
- **Isolated Environment**: For Docker, ensure the host running the scanner has permission to execute `docker exec` commands.

---

## Requirements

- Python 3.7+
- `pymysql` (auto-installed for database scanning)
- Sudo access for log file and system configuration reading
