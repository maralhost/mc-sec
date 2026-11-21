<?php
// 0.5.0: the overview in two views (simple and advanced), the per-person view switch, the status sentence, and site
// screenshots copied from OASM (stored, validated, served only to their own account). No network: Http::$mock only.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Assets;
use McSec\Client\HomeViews;
use McSec\Clock;
use McSec\Db;
use McSec\Findings;
use McSec\Kv;
use McSec\Notify;
use McSec\Shots;

Clock::$fixed = strtotime('2026-11-21T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'monitor_enabled' => '1', 'oasm_url' => 'https://oasm.test'] as $k => $v) {
    setting($k, $v);
}
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
$mk = function (string $value, string $kind = 'domain', int $client = 1, array $extra = []): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId($extra + ['client_id' => $client, 'kind' => $kind, 'value' => $value, 'status' => 'verified', 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
$jpeg = "\xFF\xD8\xFF\xE0" . str_repeat('x', 400);
$png = "\x89PNG\r\n\x1A\n" . str_repeat('y', 400);

section('the status sentence');
$none = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
$sc = ['score' => 80, 'label' => 'خوب', 'tone' => 'good', 'scanned' => 1, 'partial' => 0];
ok(HomeViews::sentence($sc, ['critical' => 1, 'high' => 2] + $none, 1, 3) === '۳ کار فوری دارید؛ یکی از سایت‌ها هم از دسترس خارج است.', 'urgent work and an outage, most serious first');
ok(HomeViews::sentence($sc, ['high' => 1] + $none, 0, 3) === 'یک کار فوری دارید.', 'one urgent job');
ok(HomeViews::sentence($sc, $none, 2, 3) === '۲ سایت از دسترس خارج است.', 'outage only');
ok(str_contains(HomeViews::sentence($sc, ['medium' => 4] + $none, 0, 3), 'مشکل فوری ندارید') && str_contains(HomeViews::sentence($sc, $none, 0, 3), 'همه‌چیز خوب است'), 'nothing urgent, and all good');
ok(str_contains(HomeViews::sentence(['score' => -1] + $sc, $none, 0, 2), 'هنوز اسکنی نگرفته‌اید') && str_contains(HomeViews::sentence($sc, $none, 0, 0), 'دارایی تأییدشده‌ای ندارید'), 'not scanned yet, and no assets yet');

section('screenshots: stored only when safe');
$shop = $mk('shop.example', 'domain', 1, ['last_scan_at' => Clock::now() - 600, 'score' => 49, 'counts' => json_encode(['critical' => 1, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 0]), 'mon_status' => 'up', 'mon_at' => Clock::now() - 300, 'mon_since' => Clock::now() - 9000, 'mon_cert_end' => '2026-12-02']);
$blog = $mk('blog.example', 'domain', 1, ['last_scan_at' => Clock::now() - 900, 'score' => 91, 'counts' => json_encode($none), 'mon_status' => 'down', 'mon_at' => Clock::now() - 300, 'mon_since' => Clock::now() - 1800, 'mon_note' => 'HTTP 502', 'partial' => 'فایروال جلوی بررسی را گرفت (HTTP 403)']);
$srv = $mk('198.51.100.7', 'ip', 1, ['last_scan_at' => Clock::now() - 900, 'score' => 79, 'counts' => json_encode(['high' => 1] + $none)]);
$theirs = $mk('other.example', 'domain', 2);
$fetched = [];
$body = $jpeg;
http_mock(function ($m, $url, $h, $b, $opt) use (&$fetched, &$body) {
    $fetched[] = $url;
    return ['status' => 200, 'body' => $body];
});
$sig = '?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123';
ok(Shots::save($shop, [['host' => 'www.shop.example', 'port' => 443, 'path' => '/api/storage/screenshot/aaa.png' . $sig], ['host' => 'shop.example', 'port' => 80, 'path' => '/api/storage/screenshot/bbb.png' . $sig],
    ['host' => 'shop.example', 'port' => 443, 'path' => '/api/storage/screenshot/ccc.png' . $sig]]), 'saved');
ok(count($fetched) === 1 && str_starts_with($fetched[0], 'https://oasm.test/api/storage/screenshot/ccc.png?'), 'one download: the asset\'s own host on 443, from the OASM address in the settings');
$got = Shots::get(1, (int) $shop->id);
ok($got !== null && $got['mime'] === 'image/jpeg' && $got['bytes'] === $jpeg, 'type from the bytes themselves (OASM names it .png, it is a JPEG)');
$fetched = [];
foreach (['https://evil.example/x.png?a=1', '//evil.example/api/storage/x?a=1', '/api/storage/../auth/admin?a=1', '/api/other/x.png?a=1', '/api/storage/screenshot/x.png', "/api/storage/screenshot/x.png?a=1\nHost: evil"] as $bad) {
    Shots::save($blog, [['host' => 'blog.example', 'port' => 443, 'path' => $bad]]);
}
ok($fetched === [] && Shots::get(1, (int) $blog->id) === null, 'a path that is not OASM\'s own storage route is never fetched');
$body = '<html><script>alert(9)</script></html>';
ok(!Shots::save($blog, [['host' => 'blog.example', 'port' => 443, 'path' => '/api/storage/screenshot/d.png' . $sig]]) && Shots::get(1, (int) $blog->id) === null, 'not an image: not stored');
$body = "\xFF\xD8\xFF" . str_repeat('z', 800000);
ok(!Shots::save($blog, [['host' => 'blog.example', 'port' => 443, 'path' => '/api/storage/screenshot/e.png' . $sig]]), 'too large: not stored');
$body = $png;
ok(Shots::save($shop, [['host' => 'shop.example', 'port' => 443, 'path' => '/api/storage/screenshot/f.png' . $sig]]) && Shots::get(1, (int) $shop->id)['mime'] === 'image/png' && Db::table('mod_mcsec_shots')->where('asset_id', $shop->id)->count() === 1, 'a newer picture replaces the old one');
Shots::save($theirs, [['host' => 'other.example', 'port' => 443, 'path' => '/api/storage/screenshot/g.png' . $sig]]);

section('screenshots: served only to their own account');
$r = client_get(['p' => 'shot', 'id' => (string) $shop->id]);
ok(($r['raw']['mime'] ?? '') === 'image/png' && $r['raw']['bytes'] === $png, 'the owner gets the picture');
ok(client_get(['p' => 'shot', 'id' => (string) $theirs->id])['raw'] === null && client_get(['p' => 'shot', 'id' => '999999'])['raw'] === null, 'another account\'s picture or an unknown id: nothing (IDOR)');
login(2, 2);
ok(client_get(['p' => 'shot', 'id' => (string) $shop->id])['raw'] === null && client_get(['p' => 'shot', 'id' => (string) $theirs->id])['raw'] !== null, 'and the other way round');
\McSec\Auth::$testClient = null;
ok(!isset(client_get(['p' => 'shot', 'id' => (string) $shop->id])['raw']), 'not signed in: no picture');
$who = login(1, 1);
Db::table('mod_mcsec_shots')->where('asset_id', $shop->id)->update(['data' => base64_encode('<svg onload=alert(9)>'), 'mime' => 'image/svg+xml']);
ok(Shots::get(1, (int) $shop->id) === null, 'a row that is not a JPEG or PNG is never served');
Shots::save($shop, [['host' => 'shop.example', 'port' => 443, 'path' => '/api/storage/screenshot/f.png' . $sig]]);

section('simple view (default)');
$sid = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 1, 'asset_id' => $shop->id, 'profile' => 'vuln', 'engine' => 'oasm', 'status' => 'completed', 'queued_at' => Clock::now() - 700, 'finished_at' => Clock::now() - 600]);
$scan = Db::table('mod_mcsec_scans')->where('id', $sid)->first();
Findings::ingest($scan, $shop, [
    ['key' => 'oasm.cve-2024-27956', 'title' => 'SQL Injection <script>alert(9)</script>', 'severity' => 'critical', 'location' => 'https://shop.example/x', 'cve' => ['CVE-2024-27956'], 'tags' => ['nuclei'], 'kb' => 'sqli'],
    ['key' => 'oasm.csrf', 'title' => 'Absence of Anti-CSRF Tokens', 'severity' => 'medium', 'location' => 'https://shop.example/cart', 'tags' => ['zap']],
    ['key' => 'oasm.low', 'title' => 'Minor thing', 'severity' => 'low', 'location' => 'https://shop.example/', 'tags' => ['zap']],
], false);
$hs = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 1, 'asset_id' => $srv->id, 'profile' => 'hygiene', 'engine' => 'builtin', 'status' => 'completed', 'queued_at' => Clock::now() - 900]);
Findings::ingest(Db::table('mod_mcsec_scans')->where('id', $hs)->first(), $srv, [['key' => 'builtin.port.3306', 'title' => 'درگاه MySQL روی اینترنت باز است', 'severity' => 'high', 'location' => '198.51.100.7:3306', 'kb' => 'port-exposed']], false);
Db::table('mod_mcsec_assets')->where('id', $blog->id)->update(['score' => 91, 'last_scan_at' => Clock::now() - 900]);
foreach ([['kind' => 'port', 'value' => 'shop.example:443'], ['kind' => 'port', 'value' => 'shop.example:80'], ['kind' => 'tech', 'value' => 'WordPress'], ['kind' => 'tech', 'value' => '<b>nginx</b>'], ['kind' => 'cert', 'value' => 'shop.example:443', 'meta' => json_encode(['not_after' => '2026-12-02', 'issuer' => "Let's Encrypt"])]] as $s) {
    Db::table('mod_mcsec_surface')->insert($s + ['client_id' => 1, 'asset_id' => $shop->id, 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
}
Notify::event(1, 'site_down', ['asset' => 'blog.example', 'asset_id' => (int) $blog->id, 'note' => 'HTTP 502'], 't1');
Notify::event(2, 'site_down', ['asset' => 'other.example', 'asset_id' => (int) $theirs->id, 'note' => 'secret-of-account-2'], 't2');
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'class="mcs-card mcs-hero"') && str_contains($h, 'کار فوری دارید') && str_contains($h, 'از دسترس خارج است'), 'a sentence says how things are');
ok(str_contains($h, 'اول این‌ها را انجام دهید') && substr_count($h, 'چطور رفع کنم؟') === 3 && strpos($h, 'SQL Injection') < strpos($h, 'درگاه MySQL'), 'three jobs, the critical one first');
ok(!str_contains($h, '<script>alert(9)') && !str_contains($h, '<b>nginx</b>'), 'finding titles and scanned technology names are escaped');
ok(str_contains($h, 'class="mcs-sites"') && substr_count($h, 'class="mcs-site') >= 3 && str_contains($h, 'p=shot&amp;id=' . (int) $shop->id) && !str_contains($h, 'p=shot&amp;id=' . (int) $blog->id), 'a card per site; a picture only where one is stored');
ok(str_contains($h, 'mcs-site is-down') && str_contains($h, 'SSL: ۱۱ روز') && str_contains($h, 'فوری') && str_contains($h, 'ناقص'), 'cards show outage, certificate days, urgent work and incomplete checks');
ok(str_contains($h, 'چه چیزی عوض شد؟') && str_contains($h, 'blog.example از دسترس خارج شد') && !str_contains($h, 'other.example') && !str_contains($h, 'secret-of-account-2'), 'recent changes of this account only');
ok(!str_contains($h, 'class="mcs-stats"') && !str_contains($h, 'به تفکیک ابزار'), 'no tables of the advanced view here');
ok(str_contains($h, 'mcs-viewswitch') && str_contains($h, 'name="view" value="advanced"') && str_contains($h, 'mcs-view-on'), 'the switch is a form (works without JavaScript)');

section('the view switch');
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['m' => 'mcsec', 'p' => 'home', 'a' => 'view_mode', 'view' => 'advanced'];
$_POST = [];
\McSec\Client\Controller::handle();
ok(HomeViews::mode($who) === 'simple', 'a GET never changes the view');
$_SERVER['REQUEST_METHOD'] = 'POST';
$_GET = ['m' => 'mcsec'];
$_POST = ['a' => 'view_mode', 'view' => 'advanced', 'token' => 'whmcs-token', 'mcs_csrf' => 'wrong'];
\McSec\Client\Controller::handle();
ok(HomeViews::mode($who) === 'simple', 'nor a POST without the CSRF token');
$r = client_post('view_mode', ['view' => 'advanced'], [], false);
ok(($r['redirect'] ?? '') === 'index.php?m=mcsec' && HomeViews::mode($who) === 'advanced', 'switched, then back to the overview');
ok(HomeViews::mode(['client_id' => 1, 'user_id' => 77]) === 'simple' && HomeViews::mode(['client_id' => 2, 'user_id' => 1]) === 'simple', 'each person keeps their own view');
client_post('view_mode', ['view' => '<script>'], [], false);
ok(Kv::get('view:1:1') === 'simple', 'anything else means simple');
client_post('view_mode', ['view' => 'advanced'], [], false);

section('advanced view');
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'class="mcs-stats"') && str_contains($h, 'کار فوری') && str_contains($h, '۱ بحرانی، ۱ بالا') && str_contains($h, '۱ از ۲') && str_contains($h, '۱۱ روز'), 'the strip: urgent work, availability and the nearest certificate');
ok(str_contains($h, 'دارایی‌های شما') && str_contains($h, 'mcs-dots') && substr_count($h, '<i class="c"></i>') >= 1 && str_contains($h, 'mcs-scorebar'), 'one row per asset with its findings as squares and a score bar');
ok(str_contains($h, '443') && str_contains($h, 'WordPress') && !str_contains($h, '<b>nginx</b>') && str_contains($h, 'گواهی‌های SSL') && str_contains($h, 'Let&#039;s Encrypt'), 'ports, technologies and certificates, escaped');
ok(str_contains($h, 'به تفکیک ابزار') && str_contains($h, 'Nuclei') && str_contains($h, 'ZAP') && str_contains($h, 'بررسی پایه'), 'open findings per tool');
ok(!str_contains($h, 'class="mcs-card mcs-hero"') && !str_contains($h, 'class="mcs-sites"'), 'not the simple view');
ok(!str_contains($h, 'other.example'), 'never another account\'s assets');
ok(HomeViews::toolOf('builtin', '') === 'بررسی پایه' && HomeViews::toolOf('oasm', 'wordpress,zap') === 'ZAP' && HomeViews::toolOf('oasm', 'x') === 'OASM', 'tool of a finding');
login(2, 2, true);
ok(str_contains(html(client_get(['p' => 'home'])), 'mcs-viewswitch'), 'support behind "login as client" sees the page');
$who = login(1, 1);

section('housekeeping');
Assets::remove($who, (int) $shop->id);
ok(Shots::get(1, (int) $shop->id) === null && Shots::get(2, (int) $theirs->id) !== null, 'removing an asset removes its picture, and only its own');

done();
