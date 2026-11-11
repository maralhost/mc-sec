<?php
// Live self-test on the WHMCS server (read-only for WHMCS data): loads WHMCS, then checks the module's tables, the
// worker's last run, and every configured backend (OASM sign-in, Osmedeus reachability and auth, the AI endpoint,
// the bots) with the module's own settings. Nothing is created on the backends.
//   php tools/selftest.php /path/to/whmcs
declare(strict_types=1);

$whmcs = rtrim($argv[1] ?? '', '/');
if ($whmcs === '' || !is_file($whmcs . '/init.php')) {
    fwrite(STDERR, "usage: php tools/selftest.php /path/to/whmcs (the folder with init.php)\n");
    exit(2);
}
chdir($whmcs);
require $whmcs . '/init.php';
require_once $whmcs . '/modules/addons/mcsec/bootstrap.php';

$line = fn (bool $ok, string $what, string $msg) => printf("%s %-22s %s\n", $ok ? '[ok]  ' : '[FAIL]', $what, $msg);
$fails = 0;
try {
    $v = \McSec\Settings::get('schema_version');
    $line($v === MCSEC_VERSION, 'schema', 'installed ' . ($v ?: 'none') . ', files ' . MCSEC_VERSION);
    $fails += $v === MCSEC_VERSION ? 0 : 1;
    $w = (int) \McSec\Settings::get('last_worker_at');
    $line($w > time() - 900, 'worker', $w > 0 ? 'last run ' . (time() - $w) . ' s ago' : 'never ran (is the WHMCS cron running?)');
    foreach (['builtin', 'oasm', 'osmedeus'] as $e) {
        $eng = \McSec\Scans::engine($e);
        if (!$eng->configured()) {
            $line(true, $e, 'not configured (skipped)');
            continue;
        }
        $h = $eng->health();
        $line($h['ok'], $e, $h['message'] . (isset($h['ms']) ? ' (' . $h['ms'] . ' ms)' : ''));
        $fails += $h['ok'] ? 0 : 1;
    }
    if (\McSec\Ai::configured()) {
        $r = \McSec\Ai::chat('Reply with JSON only.', 'Return {"ok":true}', true, 30);
        $line($r['ok'], 'ai', $r['ok'] ? 'model answered' : $r['error']);
        $fails += $r['ok'] ? 0 : 1;
    } else {
        $line(true, 'ai', 'off (basic reports from the knowledge base)');
    }
    foreach (['telegram', 'bale'] as $b) {
        if (\McSec\Settings::secret($b . '_token') === '') {
            continue;
        }
        $r = \McSec\Notify::bot($b, 'getMe', []);
        $line($r['ok'], $b, $r['ok'] ? '@' . ($r['json']['result']['username'] ?? '?') : $r['error']);
        $fails += $r['ok'] ? 0 : 1;
    }
    $dns = \McSec\Net::txt('google.com');
    $line((bool) $dns, 'dns', $dns ? 'TXT lookups work' : 'TXT lookup failed: DNS verification will not work');
} catch (\Throwable $e) {
    $line(false, 'error', $e->getMessage());
    $fails++;
}
exit($fails > 0 ? 1 : 0);
