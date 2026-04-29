"""Configuration constants for Magento Security Scanner."""

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Environment Configuration
# SUPPORTED: 'host' (direct server), 'docker' (Docker container), 'vagrant', 'custom'
ENVIRONMENT_TYPE = 'host'

# Webserver Configuration
# SUPPORTED: 'nginx', 'apache', 'custom'
WEBSERVER_TYPE = 'nginx'

# Docker Configuration (used when ENVIRONMENT_TYPE = 'docker')
# Supports multi-container setups where nginx, PHP-FPM, and database are separate
DOCKER_CONFIG = {
    'enabled': True,
    'nginx_container': {
        'name': None,  # e.g., 'magento2_nginx_1' or None to auto-detect
        'config_path': '/etc/nginx/nginx.conf',
        'log_path': '/var/log/nginx/access.log',
    },
    'php_container': {
        'name': None,  # e.g., 'magento2_php_1' or None to auto-detect
        'socket_path': '/var/run/php/php-fpm.sock',
    },
    'db_container': {
        'name': None,  # e.g., 'magento2_db_1' or None to auto-detect
        'port': 3306,
    },
    'magento_root': '/var/www/html',
    'log_path': '/var/log/nginx/access.log',
}

# Host Machine Configuration (used when ENVIRONMENT_TYPE = 'host')
HOST_CONFIG = {
    'nginx_config_paths': [
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-enabled/default',
        '/etc/nginx/sites-enabled/magento',
    ],
    'apache_config_paths': [
        '/etc/apache2/apache2.conf',
        '/etc/apache2/sites-enabled/000-default.conf',
        '/etc/apache2/sites-enabled/magento.conf',
    ],
    'nginx_vhost_dir': '/etc/nginx/sites-enabled/',
    'apache_vhost_dir': '/etc/apache2/sites-enabled/',
    'log_paths': [
        '/var/log/nginx/access.log',
        '/var/log/apache2/access.log',
    ],
    'php_fpm_socket': '/var/run/php/php-fpm.sock',
}

# Database Configuration
# Set 'auto' to read from Magento's app/etc/env.php (recommended)
# Or specify manually: {'host': 'localhost', 'port': 3306, 'user': 'root', 'password': 'xxx', 'database': 'magento'}
DB_CONFIG = {
    'mode': 'auto',  # 'auto' or 'manual'
    'env_php_path': 'app/etc/env.php',  # Path relative to project root, or absolute
    'manual': {
        'host': '127.0.0.1',
        'port': 3306,
        'user': 'root',
        'password': '',
        'database': 'magento',
    }
}

# Magento Database Tables to Scan
MAGENTO_DB_TABLES = [
    'core_config_data',
    'cms_block',
    'cms_page',
    'widget_instance',
    'admin_user',
]

# Scan Control Options (Skip specific phases)
SKIP_OPTIONS = {
    'project_files': False,    # Skip Phase 1 & 2 (Scanning files for malware)
    'environment': False,      # Skip Phase 5 (Server config, cron, users, etc.)
    'core_integrity': False,   # Skip Phase 3 (Git integrity)
    'logs': False,             # Skip Phase 4 (Access logs)
    'database': False,         # Skip Phase 6 (Database scan)
    'php_config': False        # Skip Phase 7 (PHP configuration scan)
}

# PHP Security Configuration Checks
PHP_INI_CHECKS = [
    # Security
    ('disable_functions', r'exec|passthru|shell_exec|system|proc_open|popen', 'Critical functions not disabled'),
    ('allow_url_fopen', r'Off', 'allow_url_fopen is enabled (high risk)'),
    ('allow_url_include', r'Off', 'allow_url_include is enabled (critical risk)'),
    ('expose_php', r'Off', 'PHP version is exposed in headers'),
    ('display_errors', r'Off', 'Errors are displayed (information disclosure)'),
    ('open_basedir', r'.+', 'open_basedir is not set'),
    ('session.use_strict_mode', r'1|On', 'Session strict mode is disabled'),
    
    # Performance (Magento Recommendations)
    ('opcache.enable', r'1|On', 'Opcache is disabled (major performance impact)'),
    ('opcache.memory_consumption', r'64|128|256|512', 'Opcache memory is low (< 64MB)'),
    ('memory_limit', r'512M|768M|1G|2G|4G', 'PHP memory_limit is low (< 512M)'),
    ('max_execution_time', r'60|120|180|300|600|1800', 'max_execution_time is low (< 60s)'),
    ('realpath_cache_size', r'4096k|8192k', 'realpath_cache_size is low (performance impact)'),
]

# Nginx Configuration Checks
NGINX_CONFIG_CHECKS = [
    # Security
    (r'server_tokens\s+off', 'server_tokens is NOT off (version exposure)'),
    (r'add_header\s+X-Frame-Options', 'Missing X-Frame-Options header (clickjacking risk)'),
    (r'add_header\s+X-Content-Type-Options', 'Missing X-Content-Type-Options header'),
    (r'client_max_body_size\s+(\d+)M', 'client_max_body_size might be misconfigured'),
    
    # Performance
    (r'gzip\s+on', 'Gzip compression is disabled'),
    (r'keepalive_timeout', 'keepalive_timeout not configured'),
    (r'location\s+\^~\s+/pub/media', 'Explicit /pub/media location block is missing'),
]

# Patterns to detect malicious content in database
DB_MALICIOUS_PATTERNS = [
    (r'<script[^>]*>.*?(eval|base64_decode|document\.write).*?</script>', 'Malicious JavaScript injection'),
    (r'javascript:eval', 'JavaScript eval injection'),
    (r'document\.cookie', 'Cookie stealing script'),
    (r'img.*src.*onerror.*=', 'onerror injection'),
    (r'<\?php', 'Embedded PHP in content'),
    (r'eval\s*\(', 'eval() in content'),
    (r'base64_decode\s*\(', 'base64_decode() in content'),
]

# ─────────────────────────────────────────────────────────────────────────────

# Patterns that indicate malware / webshells in PHP files
MALICIOUS_PATTERNS = [
    # Webshell execution patterns
    (r'eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', 'Webshell: eval with user input'),
    (r'@eval\s*\(', 'Obfuscated eval call'),
    (r'assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', 'Webshell: assert with user input'),
    (r'preg_replace\s*\(.*/e', 'Code execution via preg_replace /e modifier'),
    (r'create_function\s*\(.*\$_(POST|GET|REQUEST)', 'Dynamic function creation with user input'),

    # Shell command execution
    (r'(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST)', 'Shell command execution with user input'),
    (r'@popen\s*\(', 'Obfuscated popen call'),
    (r'`\$_(GET|POST|REQUEST)', 'Backtick shell execution with user input'),

    # Obfuscation techniques
    (r'base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', 'Base64 decode with user input'),
    (r'gzinflate\s*\(\s*base64_decode', 'Obfuscated code: gzinflate+base64'),
    (r'str_rot13\s*\(\s*base64_decode', 'Obfuscated code: rot13+base64'),
    (r'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)', 'Character-by-character obfuscation'),
    (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', 'Hex-encoded strings'),

    # File manipulation
    (r'file_put_contents\s*\(.*\$_(POST|GET|REQUEST)', 'File write with user input (dropper)'),
    (r'fwrite\s*\(.*\$_(POST|GET|REQUEST)', 'File write with user input'),
    (r'move_uploaded_file.*\.php', 'PHP file upload handler'),

    # Network / reverse shell
    (r'fsockopen\s*\(', 'Network socket (potential reverse shell)'),
    (r'socket_create\s*\(', 'Raw socket creation'),
    (r'curl_exec.*\$_(POST|GET|REQUEST)', 'Remote URL fetch with user input'),

    # Specific patterns from this breach
    (r'@ob_end_clean\(\);@ob_end_clean\(\)', 'Known webshell pattern: double ob_end_clean'),
    (r'chr\(99\)', 'Obfuscated parameter name (chr(99)=c)'),
    (r'chr\(114\)', 'Obfuscated parameter (chr(114)=r)'),

    # Suspicious variable patterns
    (r'\$\w+\s*=\s*\$_(POST|GET|REQUEST|COOKIE)\[.*\];\s*@?(eval|system|exec|passthru)', 'Variable assignment then execution'),
    (r'@?extract\s*\(\s*\$_(POST|GET|REQUEST)', 'Variable injection via extract'),

    # Magento-specific attack patterns
    (r'Mage::app\(\).*getStore\(\).*getConfig\(.*crypt', 'Magento credential theft'),

    # New suspicious patterns from recent scan
    (r'6e585f289921393c', 'Malicious hardcoded key (Webshell payload)'),
    (r'pl6BA2jn', 'Trigger for kucing.php webshell'),
    (r'chr\(47\)\s*\.\s*chr\(47\)\s*\.\s*\'input\'', 'Obfuscated php://input access'),
    (r'isset\(\$_POST\[chr\(99\)\]\)', 'Malicious POST parameter check (chr 99 = c)'),
    (r'@eval\(\$_POST\[chr\(99\)\]\)', 'Webshell eval of POST parameter (chr 99 = c)'),
    (r'class\s+C\{public\s+function\s+__invoke\(\$p\)\s*\{eval\(\$p\.\'\'\);\}', 'Generic malicious invokable class'),

    # PolyShell specific
    (r'GIF89a.*<\?php', 'Polyglot: GIF89a header followed by PHP code'),
    (r'\xff\xd8\xff.*<\?php', 'Polyglot: JPEG header followed by PHP code'),
    (r'\x89PNG\x0d\x0a\x1a\x0a.*<\?php', 'Polyglot: PNG header followed by PHP code'),
    (r'<\?php\s+eval\(base64_decode\(\$_POST', 'PolyShell: Base64 eval in image/file'),
]


# Malicious domains
MALICIOUS_DOMAINS = [
    'tecnokauf.ru',
    'accesson20.html',
    'typical-idiot.com', # From "Typical Idiot Security" campaign
]

# Known malicious file hashes (SHA1)
MALICIOUS_HASHES = [
    'a17028468cb2a870d460676d6d6da3ad63706778e3',
    '4009d3fa8132195a2dab4dfa3affc8d2',
]

# Known malicious IP addresses
MALICIOUS_IPS = [
    '2.217.245.213',
    '18.220.50.153',
]

# Secondary suspicious patterns (lower confidence, flag for review)
SUSPICIOUS_PATTERNS = [
    (r'eval\s*\(', 'Contains eval() — review context'),
    (r'base64_decode\s*\(', 'Contains base64_decode — review context'),
    (r'gzinflate\s*\(', 'Contains gzinflate — review context'),
    (r'str_rot13\s*\(', 'Contains str_rot13 — review context'),
    (r'\\\\x[0-9a-fA-F]{2}', 'Contains hex-encoded chars'),
    (r'<\?php', 'Embedded PHP tag (suspicious in non-PHP files)'),
]

# Directories where PHP files should NEVER exist
NO_PHP_DIRECTORIES = [
    'pub/media',
    'pub/media/custom_options',
    'pub/media/catalog/product',
    'var/tmp',
    'var/log',
    'var/cache',
    'var/session',
    'media',
]

# Suspect filenames associated with PolyShell
SUSPECT_FILENAMES = [
    'json-shell.php',
    'bypass.phtml',
    'c.php',
    'rce.php',
    'kucing.php',
    'radio.php',
    'shell.php',
]

# Known clean Magento core files (sha256 checked against git)
CORE_FILES_TO_VERIFY = [
    'pub/get.php',
    'pub/index.php',
    'pub/static.php',
    'pub/cron.php',
    'pub/health_check.php',
    'index.php',
    'app/etc/config.php',
    'app/etc/env.php',
]

# Log files to search for attack evidence
LOG_PATTERNS = [
    (r'(?:GET|POST).*\?c=', 'Webshell command execution via ?c= parameter'),
    (r'custom_options/quote.*\.php', 'Access to uploaded webshell in custom_options'),
    (r'custom_options/quote.*\.(?:jpg|png|gif|webp)', 'Access to polyglot in custom_options'),
    (r'eval|base64|shell_exec', 'Suspicious keyword in request'),
    (r'\.php\?.*(?:cmd|exec|command|shell|passwd)', 'Common webshell parameters'),
    (r'(?:GET|POST)\s+/pub/get\.php', 'Access to compromised get.php'),
    (r'(?:GET|POST).*\.php.*(?:HTTP/[12]).*\s(?:200|301|302)\s', 'Successful PHP access in media dir'),
    (r'POST\s+/rest/V1/carts/mine/items', 'PolyShell exploit attempt (REST API cart items)'),
    (r'POST\s+/rest/default/V1/carts/guest-carts/.*/items', 'PolyShell exploit attempt (Guest cart items)'),
]