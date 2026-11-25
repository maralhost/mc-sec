<?php
// 0.25.0: monitoring from every egress location at once. A site that answers from one location and not from
// another is up, and the customer is told from where it cannot be reached; a location that is itself broken blames
// nobody; nothing ever goes out without a proxy.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\Egress;
use McSec\Kv;
use McSec\Monitor;
use McSec\Settings;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'monitor_enabled' => '1', 'monitor_minutes' => '5'] as $k => $v) {
    setting($k, $v);
}
login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
$mk = function (string $v, int $cid = 1): int {
    dns_a($v, '93.184.216.' . (40 + Db::table('mod_mcsec_assets')->count()));
    return Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $cid, 'kind' => 'domain', 'value' => $v, 'status' => 'verified', 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now(), 'mon_at' => 0]);
};
$row = fn (int $id) => Db::table('mod_mcsec_assets')->where('id', $id)->first();
$a = $mk('open.example');
$b = $mk('geo.example');
$c = $mk('dead.example');
$other = $mk('theirs.example', 2);
dns_a('my.maralcloud.test', '93.184.216.90');
// which location reaches which site
$blocked = ['geo.example' => ['ایران'], 'dead.example' => ['ایران', 'de'], 'theirs.example' => ['de']];
$calls = [];
http_mock(function ($method, $url, $headers, $body, $opt = []) use (&$calls, &$blocked) {
    $via = (string) ($opt['proxy']['name'] ?? '');
    $host = (string) parse_url($url, PHP_URL_HOST);
    $calls[] = [$host, $via];
    return in_array($via, $blocked[$host] ?? [], true) ? ['status' => 0, 'error' => 'connection timed out', 'body' => ''] : ['status' => 200, 'body' => 'ok'];
});
$healthy = ['ایران' => true, 'de' => true];
Egress::$dial = function (array $loc) use (&$healthy) {
    return !empty($healthy[$loc['name']]) ? fopen('php://memory', 'r+') : 'proxy_down';
};
Settings::setSecret('egress_proxies', 'ایران=socks5://10.1.1.1:1080, de=socks5://10.2.2.2:1080');
Egress::forget();
$pass = function () use (&$calls) {
    $calls = [];
    Db::table('mod_mcsec_assets')->where('id', '>', 0)->update(['mon_at' => 0]);
    Clock::$fixed += 600;
    return Monitor::due(microtime(true) + 20);
};
$notices = fn (int $cid, string $ev) => Db::table('mod_mcsec_notices')->where('client_id', $cid)->where('event', $ev)->count();

section('off by default: locations only back each other up');
$pass();
ok(!array_filter($calls, fn ($x) => $x[1] === '') && count(array_filter($calls, fn ($x) => $x[0] === 'open.example')) === 1, 'one request per site, through a proxy');
ok(Kv::get('monloc:' . $b) === null && $row($b)->mon_status === 'up', 'a site reached through the second location is simply up');

section('every location at once');
setting('monitor_locations', '1');
$pass();
$per = fn (string $h) => array_values(array_unique(array_map(fn ($x) => $x[1], array_filter($calls, fn ($x) => $x[0] === $h))));
ok($per('open.example') === ['ایران', 'de'] && !array_filter($calls, fn ($x) => $x[1] === ''), 'each site is asked from every location, never without a proxy');
ok($row($a)->mon_status === 'up' && Kv::get('monloc:' . $a) === null, 'a site that answers everywhere: nothing to say');
ok($row($b)->mon_status === 'up' && Kv::json('monloc:' . $b)['bad'] === ['ایران'] && $notices(1, 'site_partial') === 0, 'a site that answers from one location only is up; one pass is not enough to tell the customer');
$pass();
ok($notices(1, 'site_partial') === 1 && $row($b)->mon_status === 'up' && $notices(1, 'site_down') === 1 && $row($c)->mon_status === 'down', 'after two passes: told once from where it is not reachable; the site no location reaches is down');
$n = Db::table('mod_mcsec_notices')->where('client_id', 1)->where('event', 'site_partial')->first();
ok(str_contains((string) $n->title . (string) $n->body, 'ایران') && str_contains((string) $n->title, 'geo.example'), 'the notice names the site and the location');
ok($notices(2, 'site_partial') === 1 && !str_contains((string) Db::table('mod_mcsec_notices')->where('client_id', 2)->where('event', 'site_partial')->value('title'), 'geo.example'), 'each account hears only about its own site');
$pass();
$pass();
ok($notices(1, 'site_partial') === 1, 'the same picture is not repeated');
$h = html(client_get(['p' => 'asset', 'id' => $b]));
ok(str_contains($h, 'نه از همه‌جا') && str_contains($h, 'ایران'), 'the page of the site says so');
ok(Monitor::status($row($b))[1] === 'warn' && Monitor::status($row($a))[1] === 'ok' && Monitor::status($row($c))[1] === 'err', 'three states: up, up but not from everywhere, down');

section('it changes, it clears');
$blocked['geo.example'] = ['de'];
$pass();
$pass();
ok($notices(1, 'site_partial') === 2, 'another location: a new notice');
$blocked['geo.example'] = [];
$pass();
ok(Kv::get('monloc:' . $b) === null && Monitor::status($row($b))[1] === 'ok', 'reachable from everywhere again: forgotten');

section('a broken location blames nobody');
$healthy['ایران'] = false;
Db::table('mod_mcsec_kv')->where('k', 'like', 'egress:%')->delete();
$blocked['open.example'] = ['ایران'];
$before = $notices(1, 'site_partial');
$pass();
$pass();
ok($notices(1, 'site_partial') === $before && $row($a)->mon_status === 'up' && Kv::get('monloc:' . $a) === null, 'a location that cannot reach our own address is not believed: no site is blamed for it, and the other one carries on');
$healthy['de'] = false;
Db::table('mod_mcsec_kv')->where('k', 'like', 'egress:%')->delete();
$out = $pass();
ok(($out['skip'] ?? '') === 'egress proxy down' && !$calls && $row($a)->mon_status === 'up', 'no location at all: monitoring waits, nothing goes out directly, no site is called down');

section('escaping');
$healthy = ['<b>x</b>' => true, 'de' => true];
ok(Egress::names() === ['ایران', 'de'], 'a location name is letters, digits, dash and underscore only');
Kv::setJson('monloc:' . $a, ['bad' => ['<script>alert(9)</script>'], 'ok' => ['de'], 'n' => 2, 'told' => true], 600);
ok(!str_contains(html(client_get(['p' => 'asset', 'id' => $a])), '<script>alert(9)'), 'whatever is stored is shown as text');
Egress::$dial = null;
done();
