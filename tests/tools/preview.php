<?php
// Visual preview of MC-Sec's pages for the RTL and UX check (skill mcsec-rtl-review): every page runs through the real
// controllers on a fake WHMCS with demo data, inside a minimal Lagom2 stand-in (Bootstrap 4 RTL-ish base styles).
//   php -S 127.0.0.1:8796 tests/tools/preview.php
// Client area: http://127.0.0.1:8796/index.php?m=mcsec (&as=viewer|new, &dark=1 for dark mode)
// Admin:       http://127.0.0.1:8796/addonmodules.php?module=mcsec&tier=view|ops|settings
// Delete tests/tmp/preview.sqlite to start the demo data again. Development only: never shipped.
declare(strict_types=1);

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path !== '/index.php' && $path !== '/addonmodules.php') {
    header('Location: /index.php?m=mcsec');
    return true;
}
@mkdir(dirname(__DIR__) . '/tmp', 0777, true);
$dbFile = dirname(__DIR__) . '/tmp/preview.sqlite';
$fresh = !is_file($dbFile) || filesize($dbFile) === 0;
if ($fresh) {
    touch($dbFile);
}
putenv('SQLITE_FILE=' . $dbFile);
ob_start();
require dirname(__DIR__) . '/bootstrap.php';
require __DIR__ . '/demo.php';
ob_end_clean();
session_start();
$GLOBALS['__fails'] = 0;
if ($fresh) {
    demo_data();
} else {
    $tz = new DateTimeZone('Asia/Tehran');
    \McSec\Clock::$fixed = (new DateTimeImmutable('2026-11-11 10:30', $tz))->getTimestamp();
    \McSec\Ai::$mock = fn () => ['ok' => false, 'error' => 'preview'];
}
$dark = ($_GET['dark'] ?? '') === '1';
$who = match ($_GET['as'] ?? '') {
    'viewer' => [11, 1],
    'new' => [5, 5],
    default => [1, 1],
};
login($who[0], $who[1]);
\McSec\Client\Controller::$testMode = true;
$keep = fn (string $u) => $u . (str_contains($u, '?') ? '&' : '?') . http_build_query(array_filter(['as' => $_GET['as'] ?? '', 'dark' => $dark ? '1' : '']));

if ($path === '/addonmodules.php') {
    admin((string) ($_GET['tier'] ?? 'settings'));
    $body = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
    $title = 'MC-Sec admin';
} else {
    $_GET['m'] = 'mcsec';
    $r = \McSec\Client\Controller::handle();
    if (isset($r['json'])) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($r['json'], JSON_UNESCAPED_UNICODE);
        return true;
    }
    if (isset($r['redirect'])) {
        header('Location: ' . $keep('/' . ltrim((string) $r['redirect'], '/')));
        return true;
    }
    $body = (string) ($r['vars']['mcsec_html'] ?? '');
    $title = (string) ($r['pagetitle'] ?? 'MC-Sec');
}
?><!doctype html>
<html lang="fa" dir="rtl" class="<?= $dark ? 'lagom-dark-mode' : '' ?>">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title><?= htmlspecialchars($title) ?> - مارال کلاد</title>
<style>
:root{--body-bg:#f3f5f9;--ui-block-bg:#fff;--text-body-color:#334155;--text-heading-color:#0f172a;--text-lighter-color:#5b6778;--ui-block-divider-color:#e2e8f0;--brand-primary:#1d4ed8;--input-border-color:#cbd5e1;--input-bg:#fff}
html.lagom-dark-mode{--body-bg:#0f1419;--ui-block-bg:#161b22;--text-body-color:#c9d1d9;--text-heading-color:#e6edf3;--text-lighter-color:#9ba7b4;--ui-block-divider-color:#30363d;--brand-primary:#58a6ff;--brand-primary-lighter-4:rgba(88,166,255,.12);--brand-primary-lighter-3:rgba(88,166,255,.2);--input-border-color:#30363d;--input-bg:#0d1117}
body{margin:0;background:var(--body-bg);font-family:Tahoma,sans-serif;font-size:15px;color:var(--text-body-color)}
.lagom-top{background:var(--ui-block-bg);border-bottom:1px solid var(--ui-block-divider-color);padding:12px 24px;display:flex;gap:16px;align-items:center}
.lagom-top b{color:var(--text-heading-color)}.wrap{max-width:1320px;margin:24px auto;padding:0 16px}
.btn{display:inline-flex;align-items:center;padding:6px 14px;border:1px solid transparent;border-radius:8px;font:inherit;cursor:pointer;text-decoration:none}
.btn-primary{background:var(--brand-primary);color:#fff}.btn-default{background:var(--ui-block-bg);border-color:var(--input-border-color);color:var(--text-heading-color)}.btn-link{background:none;color:var(--brand-primary)}.btn-block{width:100%}
.form-control{display:block;width:100%;padding:6px 10px;border:1px solid var(--input-border-color);font:inherit;background:var(--input-bg);color:var(--text-heading-color)}
.table{width:100%;border-collapse:collapse}.table th,.table td{padding:8px;border-top:1px solid var(--ui-block-divider-color)}
.alert{padding:12px;border-radius:8px}.alert-success{background:#e3f6ea}.alert-danger{background:#fde6e6}.alert-info{background:#e2f0fb}.alert-warning{background:#fdf1d8}
html.lagom-dark-mode .alert-success{background:rgba(74,222,128,.12)}html.lagom-dark-mode .alert-danger{background:rgba(252,165,165,.12)}html.lagom-dark-mode .alert-info{background:rgba(147,197,253,.12)}html.lagom-dark-mode .alert-warning{background:rgba(251,191,36,.12)}
a{color:var(--brand-primary)}
</style></head>
<body class="lagom"><div class="lagom-top"><b>مارال کلاد</b><span>پیش‌نمایش MC-Sec</span>
<a href="<?= htmlspecialchars($keep('/index.php?m=mcsec')) ?>">ناحیه‌ی کاربری</a><a href="/addonmodules.php?module=mcsec">پنل مدیر</a>
<a href="?<?= htmlspecialchars(http_build_query(array_merge($_GET, ['dark' => $dark ? '' : '1']))) ?>"><?= $dark ? 'روشن' : 'تیره' ?></a></div>
<div class="wrap"><?= $body ?></div></body></html>
