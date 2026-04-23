# Magento Security Incident Response Scanner Service

The **Magento Security Scanner** is a centralized service designed to monitor and audit multiple Magento projects on the same server for PHP webshells, object injection payloads, malware (including PolyShell/APSB25-94), and database-level injections.

By utilizing a centralized configuration, you can run security audits across your entire server fleet without modifying individual project files or leaving footprints in target directories.

## Architecture

- `security_scanner.py`: The central CLI service runner.
- `core_scanner.py`: The scanning engine (read-only advisory mode).
- `config.py`: Global detection patterns and malicious rules.
- `reports.py`: Dynamic reporting engine (HTML/JSON/Email).
- `config.json`: External configuration for multi-project management.

## Features

- **PolyShell Detection**: Detects polyglot files (GIF89a/JPEG/PNG headers with embedded PHP)
- **Database Scanning**: Scans `core_config_data`, `cms_block`, `cms_page` for malicious injections
- **Server Configuration Verification**: Checks Nginx/Apache config for PHP execution in media directories
- **Environment Support**: Works with host servers, Docker containers (single or multi-container), and Vagrant VMs
- **Multi-Container Docker Support**: Supports separate Nginx, PHP-FPM, and database containers
- **Multi-Project Batch Scanning**: Scan multiple Magento installations from a single command
- **REST API Log Analysis**: Detects PolyShell attack patterns in access logs

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
      "name": "magento2_nginx_1",
      "config_path": "/etc/nginx/nginx.conf",
      "log_path": "/var/log/nginx/access.log"
    },
    "php_container": {
      "name": "magento2_php_1",
      "socket_path": "/var/run/php/php-fpm.sock"
    },
    "db_container": {
      "name": "magento2_db_1",
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

---

## Docker Multi-Container Setup

If your Magento environment uses separate containers for Nginx, PHP-FPM, and database:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Nginx     │────▶│  PHP-FPM    │────▶│    MySQL    │
│  Container   │     │  Container  │     │  Container   │
│ magento2_   │     │  magento2_  │     │  magento2_  │
│ nginx_1     │     │  php_1      │     │  db_1       │
└─────────────┘     └─────────────┘     └─────────────┘
```

Configure each container in `config.json`:

```json
{
  "docker": {
    "nginx_container": {
      "name": "magento2_nginx_1",
      "config_path": "/etc/nginx/nginx.conf",
      "log_path": "/var/log/nginx/access.log"
    },
    "php_container": {
      "name": "magento2_php_1",
      "socket_path": "/var/run/php/php-fpm.sock"
    },
    "db_container": {
      "name": "magento2_db_1",
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

## Scan Phases

1. **Phase 1**: PHP files in forbidden directories (pub/media, var/session, etc.)
2. **Phase 2**: Pattern-based malware detection in PHP files
3. **Phase 3**: Core file integrity verification (git diff)
4. **Phase 4**: Access log analysis for attack evidence
5. **Phase 5**: Additional security checks (cron, permissions, etc.)
6. **Phase 6**: Database scan for malicious content

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
- **Isolated Environment**: For Docker, ensure the container has access to the log paths configured.

---

## Detected Threats

### PolyShell (APSB25-94)
- Polyglot files with image headers and embedded PHP
- REST API cart endpoint exploitation
- Malicious files in `pub/media/custom_options/quote/`

### Webshells
- eval()-based webshells
- Base64-encoded payloads
- Reverse shell patterns

### Database Injections
- JavaScript injections in CMS blocks
- Malicious configurations in core_config_data
- Backdoored admin users

---

## Requirements

- Python 3.7+
- `pymysql` (auto-installed for database scanning)
- Sudo access for log file and system configuration reading
