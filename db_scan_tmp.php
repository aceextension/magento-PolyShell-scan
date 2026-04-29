<?php
/**
 * Magento Database Security Scanner
 * This script is executed remotely via PHP CLI to scan for malicious injections.
 */

try {
    // 1. Try Magento Bootstrap (Recommended way to handle env files/secure configs)
    $bootstrapPath = null;
    foreach (['app/bootstrap.php', '/var/www/project/app/bootstrap.php', '../app/bootstrap.php'] as $path) {
        if (file_exists($path)) {
            $bootstrapPath = $path;
            break;
        }
    }

    $pdo = null;
    if ($bootstrapPath) {
        try {
            require $bootstrapPath;
            $bootstrap = \Magento\Framework\App\Bootstrap::create(BP, $_SERVER);
            $objectManager = $bootstrap->getObjectManager();
            $resource = $objectManager->get(\Magento\Framework\App\ResourceConnection::class);
            $connection = $resource->getConnection();
            
            // Get the underlying PDO object (getConnection() is the standard Zend/Magento way)
            if (method_exists($connection, 'getConnection')) {
                $pdo = $connection->getConnection();
            }
            
            if ($pdo instanceof PDO) {
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            } else {
                // If we can't get a PDO object, we'll fall back to manual parsing
                $pdo = null; 
            }
        } catch (Exception $e) {
            // Fallback to manual parsing if bootstrap fails
        }
    }

    // 2. Fallback to manual env.php parsing if Bootstrap failed or isn't available
    if (!$pdo) {
        $envPath = null;
        foreach (['app/etc/env.php', '/var/www/project/app/etc/env.php', '../app/etc/env.php'] as $path) {
            if (file_exists($path)) {
                $envPath = $path;
                break;
            }
        }

        if (!$envPath) {
            echo json_encode(['error' => 'Magento env.php or bootstrap.php not found.']);
            exit(1);
        }

        $env = include($envPath);
        if (!isset($env['db']['connection']['default'])) {
            echo json_encode(['error' => 'Database configuration not found in env.php']);
            exit(1);
        }

        $db = $env['db']['connection']['default'];
        $dsn = "mysql:host={$db['host']};dbname={$db['dbname']};charset=utf8mb4";
        $pdo = new PDO($dsn, $db['username'], $db['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 30
        ]);
    }

    $tables = ['core_config_data', 'cms_block', 'cms_page', 'widget_instance', 'admin_user', 'design_config_grid_flat'];
    $findings = [];
    
    $patterns = [
        ['pattern' => '/<script[^>]*>.*?(eval|base64_decode|document\.write|String\.fromCharCode|atob).*?<\\/script>/is', 'desc' => 'Malicious JavaScript injection'],
        ['pattern' => '/javascript:eval/i', 'desc' => 'JavaScript eval injection'],
        ['pattern' => '/document\\.cookie/i', 'desc' => 'Cookie stealing script'],
        ['pattern' => '/img.*src.*onerror.*=/i', 'desc' => 'onerror injection'],
        ['pattern' => '/<\\?php/i', 'desc' => 'Embedded PHP in content'],
        ['pattern' => '/(getConfigs|ConfigurableProduct|catalog_product_entity_varchar)/i', 'desc' => 'Potential PolyShell payload patterns'],
        ['pattern' => '/(google-analytics|hotjar|facebook-jssdk).*?(eval|atob|base64)/is', 'desc' => 'Suspicious tracking script modification']
    ];

    $scannedTables = [];
    foreach ($tables as $table) {
        // Check if table exists
        $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
        if (!$stmt->fetch()) continue;
        
        $scannedTables[] = $table;

        // Get columns
        $stmt = $pdo->query("DESCRIBE $table");
        $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        // Filter columns that might contain text/HTML/JS
        $textColumns = array_filter($columns, function($col) {
            return preg_match('/content|value|config|data|script|code|html|body|xml|text/i', $col);
        });

        if (empty($textColumns)) continue;

        foreach ($textColumns as $col) {
            $stmt = $pdo->query("SELECT * FROM $table WHERE $col IS NOT NULL AND $col != ''");
            while ($row = $stmt->fetch()) {
                $value = (string)$row[$col];
                foreach ($patterns as $p) {
                    if (preg_match($p['pattern'], $value)) {
                        $findings[] = [
                            'table' => $table,
                            'column' => $col,
                            'row_id' => $row['config_id'] ?? $row['block_id'] ?? $row['page_id'] ?? $row['user_id'] ?? $row['entity_id'] ?? 'unknown',
                            'pattern' => $p['desc'],
                            'path' => $row['path'] ?? 'N/A'
                        ];
                        break;
                    }
                }
            }
        }
    }
    
    echo json_encode(['findings' => $findings, 'scanned_tables' => $scannedTables]);
} catch (Exception $e) {
    echo json_encode(['error' => $e->getMessage()]);
    exit(1);
}
