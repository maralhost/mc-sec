<?php
// 0.24.0: the way out. With «مسیر خروجی» set, every connection to a customer's own site leaves through one of the
// admin's SOCKS5 locations (never from the WHMCS server's own address), locations are tried in turn, and a broken
// setting sends nothing at all.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\Egress;
use McSec\Http;
use McSec\Settings;
use McSec\Verify;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'cdn_origin_scan' => '1', 'monitor_enabled' => '1'] as $k => $v) {
    setting($k, $v);
}
Accounts::ensure(1);
$proof = Accounts::proof(Accounts::get(1));
$token = (string) Accounts::get(1)->verify_token;
$calls = [];
$deadFrom = [];
http_mock(function ($method, $url, $headers, $body, $opt = []) use (&$calls, &$deadFrom, $proof) {
    $via = (string) ($opt['proxy']['name'] ?? '');
    $calls[] = ['url' => $url, 'via' => $via, 'egress' => !empty($opt['egress']), 'pin' => (string) ($opt['resolve'] ?? '')];
    if (in_array($via, $deadFrom, true)) {
        return ['status' => 0, 'error' => 'connection timed out', 'body' => ''];
    }
    return ['status' => 200, 'body' => str_contains($url, 'mcsec-verify') ? $proof . "\n" : '<html><head></head><body>ok</body></html>'];
});
$set = function (string $v) {
    Settings::setSecret('egress_proxies', $v);
    Egress::forget();
};
$reset = function () use (&$calls) {
    $calls = [];
};

section('off by default');
ok(!Egress::on() && Egress::alive(), 'no way out is set: connections are direct, as before');
Verify::onServer('shop.example', '93.184.216.60', true, $proof, $token);
ok($calls && !array_filter($calls, fn ($c) => $c['via'] !== ''), 'no proxy is used');

section('the locations');
$set("ir=socks5://user:p%40ss@10.0.0.5:1080, de=socks5h://203.0.113.7:1081\nbad=http://x.example:8080");
$p = Egress::parse();
ok(Egress::on() && Egress::names() === ['ir', 'de'] && $p['bad'] === 1 && $p['ok'][0]['pass'] === 'p@ss' && $p['ok'][1]['port'] === 1081, 'named SOCKS5 locations are read; anything else is counted as unreadable');
$c = Egress::curl($p['ok'][0]);
ok($c[CURLOPT_PROXY] === '10.0.0.5:1080' && $c[CURLOPT_PROXYTYPE] === CURLPROXY_SOCKS5 && $c[CURLOPT_PROXYUSERPWD] === 'user:p@ss' && Egress::curl($p['ok'][1])[CURLOPT_PROXYTYPE] === CURLPROXY_SOCKS5,
    'plain SOCKS5 always: the name is resolved here and the proxy gets the address already checked (the pin holds)');

section('every connection to a customer\'s site goes through it');
$reset();
$r = Verify::onServer('shop.example', '93.184.216.60', true, $proof, $token);
ok($r['ok'] && $calls && !array_filter($calls, fn ($c) => $c['via'] !== 'ir' || !str_ends_with($c['pin'], ':93.184.216.60')), 'the origin-server test: through the first location, still pinned to the vetted IP');
$src = fn (string $f) => (string) file_get_contents(dirname(__DIR__) . '/modules/addons/mcsec/lib/' . $f);
$missing = [];
foreach (['Verify.php', 'Engines/Builtin.php', 'Monitor.php'] as $f) {
    preg_match_all('~Http::(request|multi)\((?:[^;]|;(?!\n))*?;\n~s', $src($f), $m);
    foreach ($m[0] as $call) {
        // ($opt of Verify::onServer and of Builtin::fetch carries 'egress' => true: asserted by the calls above and below)
        if (!str_contains($call, "'egress' => true") && !str_contains($call, '$opt') && !preg_match('~Http::multi\(\$reqs, \$timeout, true\)~', $call)) {
            $missing[] = $f . ': ' . substr(preg_replace('~\s+~', ' ', $call), 0, 80);
        }
    }
}
ok(!$missing, 'every request of the proof, the built-in check and monitoring asks for the way out (' . implode(' | ', $missing) . ')');
ok(str_contains($src('Notify.php'), "'max_bytes' => 65536, 'egress' => true"), 'and so does the customer\'s webhook');
ok(!preg_match('~stream_socket_client\(~', preg_replace('~if \(\\\\McSec\\\\Egress::on\(\)\).*?\} else \{.*?\n        \}~s', '', $src('Engines/Builtin.php'), 1)) || str_contains($src('Engines/Builtin.php'), '\McSec\Egress::connect($connectTo, 443'), 'the certificate probe dials through it');
ok(str_contains($src('Engines/Builtin.php'), '\McSec\Egress::connect($ip, (int) $p, 2.0)'), 'and so do the port probes');
$reset();
Http::request('GET', 'https://oasm.test/api/health', [], null, ['timeout' => 5]);
ok(count($calls) === 1 && $calls[0]['via'] === '', 'our own engines and vendors are not customers\' sites: no proxy');

section('several locations');
$reset();
$deadFrom = ['ir'];
$r = Http::request('GET', 'https://shop.example/', [], null, ['egress' => true]);
ok($r['status'] === 200 && $r['via'] === 'de' && array_column($calls, 'via') === ['ir', 'de'], 'what the first location cannot reach is asked from the next');
$m = Http::multi(['a' => ['url' => 'https://shop.example/', 'resolve' => 'shop.example:443:93.184.216.60']], 5, true);
ok($m['a']['ok'] && $m['a']['via'] === 'de', 'monitoring too: a site is unreachable only when no location reaches it');
$deadFrom = ['ir', 'de'];
$reset();
$r = Http::request('GET', 'https://shop.example/', [], null, ['egress' => true]);
ok($r['status'] === 0 && array_column($calls, 'via') === ['ir', 'de'], 'when none reaches it, it fails; nothing is tried without a proxy');
$deadFrom = [];

section('fail closed');
$set('http://proxy.example:8080');
$reset();
$r = Http::request('GET', 'https://shop.example/', [], null, ['egress' => true]);
ok(Egress::on() && Egress::route() === [] && $r['status'] === 0 && !$calls && str_contains($r['error'], 'nothing was sent directly'), 'a setting that cannot be read sends nothing at all');
ok(!Verify::onServer('shop.example', '93.184.216.60', true, $proof, $token)['ok'] && !$calls, 'no proof is fetched directly either');
ok(Http::multi(['a' => ['url' => 'https://shop.example/']], 5, true)['a']['ok'] === false && !$calls, 'nor a monitoring probe');
Egress::$dial = fn () => 'proxy_down';
$threw = false;
try {
    (new \McSec\Engines\Builtin())->run('domain', 'shop.example');
} catch (\Throwable $e) {
    $threw = str_contains($e->getMessage(), 'egress');
}
ok($threw && !$calls, 'the built-in check does not run at all');
dns_a('mon.example', '93.184.216.61');
Db::table('mod_mcsec_assets')->insert(['client_id' => 1, 'kind' => 'domain', 'value' => 'mon.example', 'status' => 'verified', 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now(), 'mon_at' => 0]);
$out = \McSec\Monitor::due(microtime(true) + 10);
ok(($out['skip'] ?? '') === 'egress proxy down' && !$calls && (string) Db::table('mod_mcsec_assets')->where('value', 'mon.example')->value('mon_status') !== 'down', 'monitoring waits: no site is called down because our own proxy is');

section('the raw probes');
$set('ir=socks5://10.0.0.5:1080,de=socks5://203.0.113.7:1081');
$dialed = [];
Egress::$dial = function (array $loc, string $ip, int $port) use (&$dialed) {
    $dialed[] = $loc['name'] . ' ' . $ip . ':' . $port;
    return $loc['name'] === 'ir' ? 'proxy_down' : fopen('php://memory', 'r+');
};
$s = Egress::connect('93.184.216.60', 443, 2.0, $via);
ok(is_resource($s) && $via === 'de' && $dialed === ['ir 93.184.216.60:443', 'de 93.184.216.60:443'], 'a dead proxy is followed by the next location');
$dialed = [];
Egress::connect('93.184.216.60', 22, 2.0, $via);
ok($dialed[0] === 'de 93.184.216.60:22', 'and is tried last for a minute');
Egress::$dial = fn () => false;
ok(Egress::connect('93.184.216.60', 23, 2.0) === null, 'a port that no location reaches is closed');

section('the admin');
admin('settings');
$page = function (array $post = []): string {
    $_SERVER['REQUEST_METHOD'] = $post ? 'POST' : 'GET';
    $_GET = ['module' => 'mcsec', 'mcsa' => 'settings'];
    $_POST = $post ? $post + ['mcsa_csrf' => \McSec\Auth::csrf()] : [];
    return \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
};
$set('ir=socks5://user:SECRETPASS@10.77.66.55:1080');
$h = $page();
ok(str_contains($h, 'مسیر خروجی') && str_contains($h, 'egress_test') && !str_contains($h, 'SECRETPASS') && !str_contains($h, '10.77.66.55'), 'the setting is there; its value is never shown back');
dns_a('my.maralcloud.test', '93.184.216.90');
Egress::$dial = fn (array $loc, string $ip, int $port) => fopen('php://memory', 'r+');
$h = $page(['mcsa_act' => 'egress_test']);
ok(str_contains($h, '«ir»: کار می‌کند') && !str_contains($h, 'SECRETPASS'), '«آزمودن مسیر خروجی» says which location works');
Egress::$dial = fn () => 'proxy_down';
ok(str_contains($page(['mcsa_act' => 'egress_test']), 'هیچ مسیری کار نمی‌کند'), 'and says plainly when none does');
ok(!str_contains(\McSec\SetupAdvisor::catalogue(), 'SECRETPASS') && !str_contains(\McSec\SetupAdvisor::catalogue(), '10.77.66.55'), 'the AI setup guide never sees it');
ok(!str_contains((string) Db::table('mod_mcsec_settings')->where('k', 'egress_proxies')->value('v'), 'SECRETPASS'), 'it is stored encrypted');
Egress::$dial = null;
done();
