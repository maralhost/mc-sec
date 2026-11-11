<?php
/**
 * MC-Sec — bootstrap and PSR-4 autoloader.
 *
 * Maps McSec\Foo\Bar to lib/Foo/Bar.php. Loaded by mcsec.php, hooks.php and the provisioning module
 * modules/servers/mcsec/mcsec.php (plans), so every entry point shares one version and one autoloader.
 */

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

if (!defined('MCSEC_VERSION')) {
    define('MCSEC_VERSION', '0.1.0');
    define('MCSEC_DIR', __DIR__);
    define('MCSEC_MODULE', 'mcsec');

    spl_autoload_register(static function (string $class): void {
        $prefix = 'McSec\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $file = MCSEC_DIR . '/lib/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require_once $file;
        }
    });
}
