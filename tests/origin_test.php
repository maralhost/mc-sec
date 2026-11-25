<?php
// 0.18.0 a site behind a CDN can be checked on its own server: the customer names the server's IP, the module asks
// THAT server (pinned to the IP, by the site's name) for this account's proof, and only then sends web checks
// straight there. The server's certificate can be ignored. Naming somebody else's server gets nothing. Also: the
// start-up checklist can be put away. IDOR, CSRF/nonce, viewer, SSRF (private and CDN IPs), XSS.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Assets;
use McSec\Clock;
use McSec\Db;
use McSec\Engines\Builtin;
use McSec\Engines\Oasm;
use McSec\Verify;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'welcome_credits' => '0', 'cdn_origin_scan' => '1', 'cdn_list' => "myedge 198.51.100.0/24", 'daily_scan_cap' => '200'] as $k => $v) {
    setting($k, $v);
}
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
$proof = Accounts::proof(Accounts::get(1));
$token = (string) Accounts::get(1)->verify_token;
$mk = function (string $v, int $client = 1): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $client, 'kind' => 'domain', 'value' => $v, 'status' => 'verified', 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now(), 'cdn' => 'myedge', 'cdn_checked_at' => Clock::now()]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
$row = fn (int $id) => Db::table('mod_mcsec_assets')->where('id', $id)->first();
$site = $mk('shop.example');
dns_a('shop.example', '198.51.100.20'); // the CDN's edge
$ORIGIN = '93.184.216.60';
// the origin server: answers by the name it is asked for, only when the connection is pinned to it
$srv = ['file' => $proof . "\n", 'home' => '<html><head><title>shop</title></head><body>hi</body></html>', 'tls' => 'ok', 'up' => true, 'http' => true, 'headers' => []];
$calls = [];
http_mock(function ($method, $url, $headers, $body, $opt = []) use (&$srv, &$calls, $ORIGIN) {
    $calls[] = ['url' => $url, 'opt' => $opt];
    $pin = (string) ($opt['resolve'] ?? '');
    $host = (string) parse_url($url, PHP_URL_HOST);
    $https = str_starts_with($url, 'https://');
    if ($pin !== $host . ':' . ($https ? 443 : 80) . ':' . $ORIGIN || !$srv['up'] || (!$https && !$srv['http'])) {
        return ['status' => 0, 'error' => 'connection refused', 'body' => ''];
    }
    if ($https && ($srv['tls'] !== 'ok' || $host !== 'shop.example') && !empty($opt['verify'])) {
        return ['status' => 0, 'error' => 'SSL certificate problem: self-signed certificate', 'body' => ''];
    }
    if ($host !== 'shop.example') {
        return ['status' => 200, 'body' => '<html><head></head><body>default site of the server</body></html>', 'headers' => []];
    }
    $path = (string) parse_url($url, PHP_URL_PATH);
    if ($path === Verify::FILE_PATH) {
        return $srv['file'] === '' ? ['status' => 404, 'body' => 'nf'] : ['status' => 200, 'body' => $srv['file']];
    }
    return $path === '/' ? ['status' => 200, 'body' => $srv['home'], 'headers' => $srv['headers']] : ['status' => 404, 'body' => ''];
});
$post = fn (array $p, bool $nonce = true, ?int $asset = null) => client_post('asset_origin', $p + ['asset' => (string) ($asset ?? $site->id)], ['p' => 'asset', 'id' => (string) ($asset ?? $site->id)], $nonce);

section('the form');
$h = html(client_get(['p' => 'asset', 'id' => $site->id]));
ok(str_contains($h, 'name="origin"') && str_contains($h, 'name="tls_skip"') && str_contains($h, 'گواهی SSL سرور را نادیده بگیر') && str_contains($h, 'ثبت و آزمودن سرور'), 'the CDN card asks for the server\'s IP, with the «ignore SSL» tick');
ok(str_contains($h, 'تا این دیده نشود، هیچ بررسی دیگری مستقیم به آن سرور فرستاده نمی‌شود') && str_contains($h, 'گواهی SSL معتبری برای همین نام'), 'and says nothing goes direct before the test, and what counts as proof');
$plain = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 1, 'kind' => 'domain', 'value' => 'nocdn.example', 'status' => 'verified', 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now(), 'cdn_checked_at' => Clock::now()]);
ok(str_contains(html(client_get(['p' => 'asset', 'id' => $plain])), 'این سایت پشت CDN یا پروکسی است؟'), 'a domain whose CDN we did not recognise can name its server too (closed drawer)');

section('the site is on that server');
$r = $post(['origin' => $ORIGIN]);
$a = $row((int) $site->id);
ok((int) $a->origin_id > 0 && (int) $a->origin_ok_at > 0 && str_contains(flash_of($r), 'این سایت روی همین سرور است'), 'the server holds this account\'s proof file for this site: the direct route stands');
$pinned = array_filter($calls, fn ($c) => str_contains($c['url'], 'shop.example'));
ok($pinned && !array_filter($pinned, fn ($c) => ($c['opt']['resolve'] ?? '') === '' || !str_ends_with((string) $c['opt']['resolve'], ':' . $ORIGIN)) && !array_filter($calls, fn ($c) => !empty($c['opt']['follow'])), 'every request of the test is pinned to that IP, by the site\'s name, and follows no redirect');
ok(Assets::direct($a) === ['ip' => $ORIGIN, 'tls_skip' => false], 'the direct route: the IP, certificate checked');
$h = html(client_get(['p' => 'asset', 'id' => $site->id]));
ok(str_contains($h, 'بله، آزموده شد') && str_contains($h, 'دوباره بیازما') && str_contains($h, 'مستقیم از همین سرور پرسیده می‌شود'), 'the card shows the result and a way to test again');

section('a certificate that is publicly valid for the name is proof by itself');
$srv['file'] = '';
$r = $post(['retest' => '1']);
ok((int) $row((int) $site->id)->origin_ok_at > 0 && Verify::onServer('shop.example', $ORIGIN, false, $proof, $token)['how'] === 'cert', 'no file on the server, but it shows a valid certificate for this very name: accepted');
ok(!Verify::onServer('shop.example', $ORIGIN, true, $proof, $token)['ok'], 'with «ignore SSL» ticked the certificate proves nothing');

section('somebody else\'s server, or no proof');
$srv['tls'] = 'self';
$srv['file'] = '';
$r = $post(['retest' => '1']);
ok((int) $row((int) $site->id)->origin_ok_at === 0 && str_contains(flash_of($r), 'فایل تأیید') && Assets::direct($row((int) $site->id)) === null, 'the server answers but has no proof for this site: no direct route, and the reason is said');
ok(str_contains(html(client_get(['p' => 'asset', 'id' => $site->id])), 'هنوز دیده نشد') && str_contains(html(client_get(['p' => 'asset', 'id' => $site->id])), 'vfile=1'), 'the card says so and offers the proof file');
$srv['file'] = 'mcsec-verify=' . str_repeat('a', 32);
ok(!Assets::testOrigin($row((int) $site->id))['ok'], 'another account\'s code on the server is not this account\'s proof');
$srv['file'] = '<html>' . $proof . '</html>';
ok(!Assets::testOrigin($row((int) $site->id))['ok'], 'a page that only contains the code is not the proof');
$srv['file'] = '';
$srv['home'] = '<html><head><meta name="mcsec-verification" content="' . $token . '"></head><body></body></html>';
ok(Assets::testOrigin($row((int) $site->id))['ok'], 'the meta tag in the head of the site, served by that server, counts');
$srv['home'] = '<html><head></head><body><p>' . htmlspecialchars_decode('<meta name="mcsec-verification" content="' . $token . '">') . '</p></body></html>';
ok(!Assets::testOrigin($row((int) $site->id))['ok'], 'the tag echoed into the body does not');
$srv['home'] = '<html><head></head><body></body></html>';
$srv['file'] = $proof;
$srv['up'] = false;
$r = $post(['retest' => '1']);
ok(str_contains(flash_of($r), 'جواب نداد') && (int) $row((int) $site->id)->origin_ok_at === 0, 'a server that does not answer: said plainly');
$srv['up'] = true;
// a victim's server named for the attacker's own domain: it answers with its default site, never with the proof
$evil = $mk('attacker.example');
dns_a('attacker.example', '198.51.100.21');
$r = $post(['origin' => $ORIGIN], true, (int) $evil->id);
ok((int) $row((int) $evil->id)->origin_ok_at === 0 && Assets::direct($row((int) $evil->id)) === null, 'naming a server that does not hold your site gets no direct route');

section('ignoring the server\'s certificate');
$srv['tls'] = 'self-signed';
$srv['http'] = false; // an HTTPS-only server, as most are behind a CDN
$r = $post(['retest' => '1']);
ok(str_contains(flash_of($r), 'گواهی SSL این سرور') && str_contains(flash_of($r), 'نادیده بگیر') && (int) $row((int) $site->id)->origin_ok_at === 0, 'a certificate that is not valid for the site stops the test, and the message points to the tick');
$r = $post(['retest' => '1', 'tls_skip' => '1']);
$a = $row((int) $site->id);
ok((int) $a->origin_ok_at > 0 && (int) $a->origin_tls_skip === 1 && Assets::direct($a) === ['ip' => $ORIGIN, 'tls_skip' => true], 'with the tick the test passes and the choice is kept');
ok(str_contains(html(client_get(['p' => 'asset', 'id' => $site->id])), 'گواهی سرور نادیده گرفته می‌شود') && preg_match('~name="tls_skip" value="1" checked~', html(client_get(['p' => 'asset', 'id' => $site->id]))) === 1, 'the card shows it');

section('the web checks go straight to the server');
$srv['headers'] = ['server' => ['nginx/1.18.0']];
$GLOBALS['__certs']['shop.example'] = ['days' => -3, 'not_after' => '2026-11-22', 'issuer' => 'self', 'cn' => 'shop.example', 'san' => ['shop.example'], 'valid_host' => true, 'self_signed' => true, 'protocol' => 'TLSv1.3'];
$calls = [];
$res = (new Builtin())->run('domain', 'shop.example', [], [], Assets::direct($row((int) $site->id)));
$web = array_filter($calls, fn ($c) => str_contains($c['url'], '://shop.example/'));
ok(($res['direct'] ?? '') === $ORIGIN && $web && !array_filter($web, fn ($c) => !str_ends_with((string) ($c['opt']['resolve'] ?? ''), ':' . $ORIGIN)), 'hygiene asks the origin server, by the site\'s name, never the CDN edge');
ok(in_array('nginx/1.18.0', array_map(fn ($s) => $s['value'], array_filter($res['surface'], fn ($s) => $s['kind'] === 'tech')), true), 'and sees what the server itself says');
ok(!array_filter($res['findings'], fn ($f) => str_starts_with((string) $f['key'], 'builtin.tls.')) && !array_filter($res['surface'], fn ($s) => $s['kind'] === 'cert'), 'with «ignore SSL» the server\'s certificate is neither judged nor reported');
$strict = (new Builtin())->run('domain', 'shop.example', [], [], ['ip' => $ORIGIN, 'tls_skip' => false]);
ok((bool) array_filter($strict['findings'], fn ($f) => $f['key'] === 'builtin.tls.expired'), 'without it, the server\'s certificate is judged as before');
$calls = [];
$via = (new Builtin())->run('domain', 'shop.example', [], []);
ok(!isset($via['direct']) && !array_filter($calls, fn ($c) => str_ends_with((string) ($c['opt']['resolve'] ?? ''), ':' . $ORIGIN)), 'no direct route: the public way, as always');
// right before it is used, the route is tested again
$srv['file'] = '';
ok(Assets::direct($row((int) $site->id), true) === null && (int) $row((int) $site->id)->origin_ok_at === 0, 'the worker tests again before using the route: a server that stopped holding the site is dropped');
$srv['file'] = $proof;
Assets::testOrigin($row((int) $site->id));

section('engine tools are told the site\'s name');
ok(Oasm::vhostConfig('katana', ['host' => 'shop.example']) === ['headers' => ['Host: shop.example']] && Oasm::vhostConfig('ffuf', ['host' => 'shop.example']) === ['headers' => ['Host: shop.example']], 'katana and ffuf: a Host header line');
ok(Oasm::vhostConfig('nikto', ['host' => 'shop.example']) === ['vhost' => 'shop.example'] && Oasm::vhostConfig('wpscan', ['host' => 'shop.example', 'tls_skip' => true]) === ['vhost' => 'shop.example', 'disableTlsChecks' => true], 'nikto and wpscan: vhost, and wpscan the TLS switch');
ok(Oasm::vhostConfig('nuclei', ['host' => 'shop.example']) === [] && Oasm::vhostConfig('zap', ['host' => 'shop.example']) === [], 'nuclei and zap have no such setting: nothing is invented');
ok(Oasm::vhostConfig('katana', ['host' => "evil\r\nX-Injected: 1"]) === [] && Oasm::vhostConfig('nikto', ['host' => 'a b;rm -rf']) === [] && Oasm::vhostConfig('katana', []) === [], 'a name that is not a plain host name is never passed on');

section('guards');
ok(str_contains(flash_of($post(['origin' => '10.0.0.5'])), 'IP') && !str_contains(flash_of($post(['origin' => '10.0.0.5'])), 'روی همین سرور است'), 'a private IP is refused');
ok(!Verify::onServer('shop.example', '127.0.0.1', true, $proof, $token)['ok'] && !Verify::onServer('shop.example', '198.51.100.20', true, $proof, $token)['ok'] && !Verify::onServer('shop.example', 'not-an-ip', true, $proof, $token)['ok'], 'the test itself refuses loopback, a CDN edge and anything that is not an IP');
$n = count($calls);
ok(str_contains(flash_of($post(['retest' => '1', 'mcs_csrf' => 'bad'])), 'منقضی') && str_contains(flash_of($post(['origin' => $ORIGIN], false)), 'یک بار') && count($calls) === $n, 'CSRF and nonce: nothing is sent to any server');
login(11, 1);
ok(str_contains(flash_of($post(['retest' => '1'])), 'فقط اجازه‌ی دیدن') && count($calls) === $n, 'a viewer cannot test');
login(2, 2);
$r = client_post('asset_origin', ['asset' => (string) $site->id, 'retest' => '1', 'tls_skip' => '1'], ['p' => 'asset', 'id' => (string) $site->id]);
ok(count($calls) === $n && (int) $row((int) $site->id)->origin_tls_skip === 1 && (int) $row((int) $site->id)->origin_ok_at > 0, 'IDOR: another account cannot test or change it');
login(1, 1);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['m' => 'mcsec', 'p' => 'asset', 'id' => (string) $site->id, 'a' => 'asset_origin', 'retest' => '1'];
$_POST = [];
\McSec\Client\Controller::handle();
ok(count($calls) === $n, 'a GET never sends a request to the server');
setting('cdn_origin_scan', '0');
ok(Assets::direct($row((int) $site->id)) === null, 'the admin\'s switch off: no direct route');
setting('cdn_origin_scan', '1');
$post(['origin' => '']);
$a = $row((int) $site->id);
ok((int) $a->origin_id === 0 && (int) $a->origin_ok_at === 0 && (int) $a->origin_tls_skip === 0, 'unlinking the server clears the route and the tick');
Db::table('mod_mcsec_assets')->where('id', $site->id)->update(['origin_note' => '<script>alert(9)</script>', 'origin_id' => (int) Db::table('mod_mcsec_assets')->where('value', $ORIGIN)->value('id')]);
ok(!str_contains(html(client_get(['p' => 'asset', 'id' => $site->id])), '<script>alert(9)</script>'), 'the stored note is escaped');

section('the start-up checklist can be put away');
login(5, 5);
Accounts::ensure(5);
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'شروع کار') && str_contains($h, 'value="setup_hide"') && str_contains($h, 'بستن') && str_contains($h, '<details class="mcs-guide" open>'), 'a new account sees the checklist with a close button, and the guide open');
$r = client_post('setup_hide', [], ['p' => 'home'], false);
$h = html(client_get(['p' => 'home']));
ok(isset($r['redirect']) && !str_contains($h, 'mcs-onboard') && str_contains($h, 'را نشان بده') && !str_contains($h, '<details class="mcs-guide" open>'), 'closed: the checklist is gone, the guide stays shut, one quiet line brings it back');
login(1, 1);
Db::table('mod_mcsec_assets')->where('client_id', 5)->delete();
login(5, 5);
client_post('setup_hide', ['show' => '1'], ['p' => 'home'], false);
ok(str_contains(html(client_get(['p' => 'home'])), 'mcs-onboard'), 'and it comes back when asked');
client_post('setup_hide', [], ['p' => 'home'], false);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['m' => 'mcsec', 'p' => 'home', 'a' => 'setup_hide', 'show' => '1'];
$_POST = [];
ok(!str_contains(html(\McSec\Client\Controller::handle()), 'mcs-onboard'), 'a GET does not change the choice');
ok(str_contains(flash_of(client_post('setup_hide', ['mcs_csrf' => 'bad'], ['p' => 'home'], false)), 'منقضی'), 'CSRF');

done();
