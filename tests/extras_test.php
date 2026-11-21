<?php
// 0.10.0 extras, each behind its own switch (all off by default): domain expiry from WHMCS data, the box on a hosting
// service's page, CSV of findings, emerging-threat alerts, setting a discovered host aside, AI second opinion,
// assistant suggestions and the assistant in a linked bot chat. IDOR, CSRF/nonce, XSS, credits, no writes to tbl*.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Ai;
use McSec\Assistant;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Findings;
use McSec\Intel;
use McSec\Reports;
use McSec\Settings;
use McSec\Surface;
use McSec\Watch;

Clock::$fixed = strtotime('2026-11-21T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'welcome_credits' => '0', 'oasm_url' => 'https://oasm.test', 'oasm_email' => 'svc@oasm.test',
    'ai_base_url' => 'https://ai.test/v1', 'ai_model' => 'm1'] as $k => $v) {
    setting($k, $v);
}
Settings::setSecret('oasm_password', 'svc-pass');
Settings::setSecret('ai_key', 'k');
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
Credits::credit(1, 100, 'paid', 'topup', 'topup:ex1', 'test');
$mk = function (string $value, int $client = 1, string $status = 'verified', array $more = []): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId($more + ['client_id' => $client, 'kind' => 'domain', 'value' => $value, 'status' => $status, 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
$shop = $mk('shop.example', 1, 'verified', ['oasm_target' => 't-shop', 'score' => 72, 'last_scan_at' => Clock::now() - 3600]);
$other = $mk('other.example', 2);
$finding = function (int $client, object $asset, string $title, string $loc, string $sev = 'high', array $more = []): int {
    return (int) Db::table('mod_mcsec_findings')->insertGetId($more + ['client_id' => $client, 'asset_id' => $asset->id, 'fp' => sha1($title . $loc), 'engine' => 'oasm', 'profile' => 'vuln', 'title' => $title,
        'severity' => $sev, 'status' => 'open', 'location' => $loc, 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
};
$notices = fn (int $c, string $ev) => Db::rows(Db::table('mod_mcsec_notices')->where('client_id', $c)->where('event', $ev)->orderBy('id'));

section('everything is off by default');
foreach (['domain_watch', 'service_box', 'export_csv', 'threat_alerts', 'host_mute', 'ai_opinion', 'assistant_bots'] as $k) {
    ok(!Settings::bool($k), $k . ' is off until the admin turns it on');
}
admin('settings');
$_GET = ['module' => 'mcsec', 'mcsa' => 'settings'];
$_SERVER['REQUEST_METHOD'] = 'GET';
$adminHtml = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(str_contains($adminHtml, 'قابلیت‌های تکمیلی') && str_contains($adminHtml, 'set_domain_watch') && str_contains($adminHtml, 'set_host_mute') && str_contains($adminHtml, 'set_assistant_bots'), 'the admin settings page has a switch for each');

section('domain expiry (from WHMCS data, no scan)');
$schema = \WHMCS\Database\Capsule::schema();
$schema->table('tbldomains', function ($t) {
    $t->string('expirydate', 10)->default('0000-00-00');
    $t->integer('donotrenew')->default(0);
});
as_whmcs(function () {
    Db::table('tbldomains')->where('domain', 'shop-maral.ir')->update(['expirydate' => Clock::today(6), 'donotrenew' => 1]);
    Db::table('tbldomains')->insert(['userid' => 2, 'domain' => 'other-soon.ir', 'status' => 'Active', 'expirydate' => Clock::today(20)]);
    Db::table('tbldomains')->insert(['userid' => 1, 'domain' => 'far.ir', 'status' => 'Active', 'expirydate' => Clock::today(200)]);
    Db::table('tbldomains')->insert(['userid' => 9, 'domain' => 'stranger.ir', 'status' => 'Active', 'expirydate' => Clock::today(3)]);
});
ok(Watch::domains() === 0 && !$notices(1, 'domain_expiring'), 'switch off: nothing is announced');
setting('domain_watch', '1');
$n = Watch::domains();
$mine = $notices(1, 'domain_expiring');
ok($n === 2 && count($mine) === 1 && str_contains($mine[0]->title, 'shop-maral.ir') && str_contains($mine[0]->title, '۶ روز') && str_contains($mine[0]->body, 'خاموش'), 'a domain that ends in 6 days is announced, saying auto-renew is off');
ok(count($notices(2, 'domain_expiring')) === 1 && !$notices(9, 'domain_expiring') && !str_contains(json_encode($mine), 'far.ir'), 'each account only its own; no workspace, no notice; a far date, no notice');
Watch::domains();
ok(count($notices(1, 'domain_expiring')) === 1, 'the same band is announced once');
Clock::$fixed += 5 * 86400;
Watch::domains();
ok(count($notices(1, 'domain_expiring')) === 2, 'one day left: announced again (30, 7 and 1 day bands)');
Clock::$fixed -= 5 * 86400;

section('the box on a hosting service page');
ok(Watch::serviceBox(1, 'shop.example') === '', 'switch off: no box');
setting('service_box', '1');
$b = Watch::serviceBox(1, 'shop.example');
ok(str_contains($b, '۷۲') && str_contains($b, 'p=asset&amp;id=' . $shop->id), 'a scanned site: its score and a link to it');
$b = Watch::serviceBox(1, 'New-Site.example');
ok(str_contains($b, 'هنوز بررسی نشده') && str_contains($b, 'add=new-site.example'), 'a site not added yet: one step to add it');
ok(!str_contains(Watch::serviceBox(1, 'other.example'), 'p=asset&amp;id='), 'another account\'s asset is never linked');
ok(Watch::serviceBox(1, '"><script>alert(9)</script>') === '' && Watch::serviceBox(1, '') === '', 'a service name that is not a domain: no box');
$h = html(client_get(['p' => 'assets', 'add' => 'new-site.example']));
ok(str_contains($h, '>new-site.example</textarea>'), 'the add form arrives filled in');
ok(!str_contains(html(client_get(['p' => 'assets', 'add' => '</textarea><script>alert(9)</script>'])), '<script>alert(9)'), 'a bad value in the address is not put in the form');
$out = run_hook('ClientAreaProductDetailsOutput', ['service' => (object) ['domain' => 'shop.example']]);
ok(str_contains(implode('', array_map('strval', $out)), '۷۲'), 'the hook returns the box');

section('CSV of findings');
$f1 = $finding(1, $shop, '=HYPERLINK("http://evil","x")', 'https://shop.example/a', 'critical', ['cve' => 'CVE-2026-0001']);
$f2 = $finding(1, $shop, 'عنوان "با" نقل‌قول', 'https://shop.example/b', 'low');
$fo = $finding(2, $other, 'secret of the other account', 'https://other.example/');
$r = client_get(['p' => 'findings', 'csv' => '1']);
ok(!isset($r['raw']) && !str_contains(html($r), 'csv=1'), 'switch off: no file and no link');
setting('export_csv', '1');
ok(str_contains(html(client_get(['p' => 'findings'])), 'csv=1'), 'the findings page links to the file');
$r = client_get(['p' => 'findings', 'csv' => '1', 'status' => 'all']);
$csv = (string) ($r['raw']['bytes'] ?? '');
ok(str_starts_with($csv, "\xEF\xBB\xBF") && str_starts_with((string) ($r['raw']['mime'] ?? ''), 'text/csv') && substr_count($csv, "\r\n") === 3, 'a CSV with a BOM: the header and this account\'s two findings');
ok(str_contains($csv, '"\'=HYPERLINK(""http://evil"",""x"")"') && str_contains($csv, '"عنوان ""با"" نقل‌قول"'), 'a formula is defused and quotes are doubled');
ok(!str_contains($csv, 'secret of the other account'), 'nothing of another account');
ok(substr_count((string) client_get(['p' => 'findings', 'csv' => '1', 'severity' => 'critical'])['raw']['bytes'], "\r\n") === 2, 'the page\'s filters apply');

section('emerging-threat alert');
Db::table('mod_mcsec_surface')->insert(['client_id' => 1, 'asset_id' => $shop->id, 'kind' => 'tech', 'value' => 'Nginx:1.25', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
Db::table('mod_mcsec_surface')->insert(['client_id' => 1, 'asset_id' => $shop->id, 'kind' => 'tech', 'value' => 'Nginx Unit', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
Db::table('mod_mcsec_surface')->insert(['client_id' => 2, 'asset_id' => $other->id, 'kind' => 'tech', 'value' => 'PHP:8.1', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
$kev = ['vulnerabilities' => [['cveID' => 'CVE-2026-1111', 'vendorProject' => 'F5', 'product' => 'NGINX', 'vulnerabilityName' => 'NGINX <b>Buffer</b> Overflow', 'dateAdded' => Clock::today(-2)],
    ['cveID' => 'CVE-2020-2222', 'vendorProject' => 'PHP Group', 'product' => 'PHP', 'vulnerabilityName' => 'old', 'dateAdded' => '2020-01-01'],
    ['cveID' => 'CVE-2026-3333', 'vendorProject' => 'Microsoft', 'product' => 'Multiple Products', 'vulnerabilityName' => 'x', 'dateAdded' => Clock::today(-1)]]];
for ($i = 0; $i < 120; $i++) {
    $kev['vulnerabilities'][] = ['cveID' => 'CVE-2019-' . (10000 + $i), 'vendorProject' => 'V', 'product' => 'Thing' . $i, 'vulnerabilityName' => 'n', 'dateAdded' => '2019-05-05'];
}
setting('kev_url', 'https://kev.test/kev.json');
http_mock(fn ($method, $url) => str_contains($url, 'kev.test') ? ['status' => 200, 'body' => json_encode($kev)] : ['status' => 500, 'body' => '{}']);
ok(Intel::refreshKev() === 123, 'the catalogue is read');
$row = Db::table('mod_mcsec_intel')->where('cve', 'CVE-2026-1111')->first();
ok($row->product === 'NGINX' && $row->vendor === 'F5' && $row->name === 'NGINX Buffer Overflow', 'what each entry is about is kept, without markup');
ok(Intel::threatAlerts() === 0 && !$notices(1, 'threat_alert'), 'switch off: nobody is told');
setting('threat_alerts', '1');
$sent = Intel::threatAlerts();
$t = $notices(1, 'threat_alert');
ok($sent === 1 && count($t) === 1 && str_contains($t[0]->title, 'NGINX') && str_contains($t[0]->body, 'CVE-2026-1111') && str_contains($t[0]->body, 'shop.example'), 'the account that runs nginx hears about the new nginx entry, with its own asset named');
ok(str_contains($t[0]->body, 'حتماً آسیب‌پذیر نیست'), 'the message says seeing the technology is not proof');
ok(!$notices(2, 'threat_alert'), 'an old entry (PHP, 2020) and "Multiple Products" alert nobody');
Intel::threatAlerts();
ok(count($notices(1, 'threat_alert')) === 1 && Db::table('mod_mcsec_scans')->count() === 0 && Credits::balance(1)['total'] === 100, 'told once; no scan is started and no credit is taken');

section('a discovered host set aside');
$hid = (int) Db::table('mod_mcsec_surface')->insertGetId(['client_id' => 1, 'asset_id' => $shop->id, 'kind' => 'host', 'value' => 'status.shop.example', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
$self = (int) Db::table('mod_mcsec_surface')->insertGetId(['client_id' => 1, 'asset_id' => $shop->id, 'kind' => 'host', 'value' => 'shop.example', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
$ohid = (int) Db::table('mod_mcsec_surface')->insertGetId(['client_id' => 2, 'asset_id' => $other->id, 'kind' => 'host', 'value' => 'x.other.example', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
$fh = $finding(1, $shop, 'Exposed panel', 'https://status.shop.example/admin');
$calls = [];
http_mock(function ($method, $url, $headers, $body) use (&$calls) {
    $path = (string) parse_url($url, PHP_URL_PATH);
    $calls[] = [$method, $path, json_decode((string) $body, true) ?: []];
    if ($path === '/api/auth/sign-in/email') {
        return ['status' => 200, 'body' => '{}', 'headers' => ['set-cookie' => ['session=ok; Path=/']]];
    }
    if ($path === '/api/auth/sign-up/email' || $path === '/api/users' || $path === '/api/workspaces' || $path === '/api/workspaces/configs') {
        return ['status' => 200, 'body' => '{"id":"ws-1"}'];
    }
    if ($path === '/api/assets/host') {
        return ['status' => 200, 'body' => json_encode(['data' => [['id' => 'h-1', 'host' => 'shop.example'], ['id' => 'h-2', 'host' => 'status.shop.example']]])];
    }
    if ($path === '/api/assets/toggle') {
        return ['status' => 201, 'body' => '{}'];
    }
    return ['status' => 200, 'body' => '{}'];
});
Accounts::update(1, ['oasm_workspace' => 'ws-1', 'oasm_user' => 'mcsec-c1@mcsec.invalid', 'oasm_secret' => \McSec\Crypto::encrypt('pw')]);
ok(!str_contains(html(client_get(['p' => 'asset', 'id' => $shop->id])), 'host_mute'), 'switch off: no button');
$r = client_post('host_mute', ['id' => $hid, 'on' => '1'], ['p' => 'asset', 'id' => $shop->id]);
ok((int) Db::table('mod_mcsec_surface')->where('id', $hid)->value('muted') === 0, 'switch off: the action is refused');
setting('host_mute', '1');
$h = html(client_get(['p' => 'asset', 'id' => $shop->id]));
ok(substr_count($h, 'name="a" value="host_mute"') === 1 && str_contains($h, 'مال من نیست'), 'a button next to the discovered host, not next to the asset itself');
client_post('host_mute', ['id' => $ohid, 'on' => '1'], ['p' => 'asset', 'id' => $shop->id]);
client_post('host_mute', ['id' => $self, 'on' => '1'], ['p' => 'asset', 'id' => $shop->id]);
ok((int) Db::table('mod_mcsec_surface')->where('id', $ohid)->value('muted') === 0 && (int) Db::table('mod_mcsec_surface')->where('id', $self)->value('muted') === 0, 'another account\'s host (IDOR) and the asset itself cannot be set aside');
$calls = [];
$r = client_post('host_mute', ['id' => $hid, 'on' => '1'], ['p' => 'asset', 'id' => $shop->id]);
$toggle = array_values(array_filter($calls, fn ($c) => $c[1] === '/api/assets/toggle'));
ok((int) Db::table('mod_mcsec_surface')->where('id', $hid)->value('muted') === 1 && count($toggle) === 1 && $toggle[0][2] === ['assetId' => 'h-2', 'isEnabled' => false], 'set aside: switched off in OASM by the host\'s own id');
$fr = Db::table('mod_mcsec_findings')->where('id', $fh)->first();
ok($fr->status === 'accepted' && $fr->status_note === Surface::MUTE_NOTE && Db::table('mod_mcsec_findings')->where('id', $f1)->value('status') === 'open', 'its open finding is closed with a fixed note; findings on the asset itself stay');
$scan = (object) ['id' => 900, 'engine' => 'oasm', 'profile' => 'vuln'];
$res = Findings::ingest($scan, $shop, [['title' => 'New on aside host', 'key' => 'k1', 'severity' => 'high', 'location' => 'https://status.shop.example/x'], ['title' => 'New on shop', 'key' => 'k2', 'severity' => 'low', 'location' => 'https://shop.example/y']], false);
ok($res['seen'] === 1 && !Db::table('mod_mcsec_findings')->where('title', 'New on aside host')->exists() && Db::table('mod_mcsec_findings')->where('title', 'New on shop')->exists(), 'a later scan records nothing for the host that was set aside');
ok(str_contains(html(client_get(['p' => 'asset', 'id' => $shop->id])), 'کنار گذاشته'), 'the page marks it');
client_post('host_mute', ['id' => $hid, 'on' => '0'], ['p' => 'asset', 'id' => $shop->id]);
ok((int) Db::table('mod_mcsec_surface')->where('id', $hid)->value('muted') === 0 && Db::table('mod_mcsec_findings')->where('id', $fh)->value('status') === 'open', 'brought back: scanned again and its finding reopens');
http_mock(fn () => ['status' => 500, 'body' => '{}']);
\McSec\Kv::forget('oasm:s:1');
$r = client_post('host_mute', ['id' => $hid, 'on' => '1'], ['p' => 'asset', 'id' => $shop->id]);
ok((int) Db::table('mod_mcsec_surface')->where('id', $hid)->value('muted') === 2 && str_contains(flash_of($r), 'دوباره تلاش'), 'the engine cannot be reached: set aside here, the engine is retried later, and the customer is told');
login(11, 1);
client_post('host_mute', ['id' => $hid, 'on' => '0'], ['p' => 'asset', 'id' => $shop->id]);
ok((int) Db::table('mod_mcsec_surface')->where('id', $hid)->value('muted') === 2, 'a viewer cannot change it');
login(1, 1);

section('AI second opinion');
$asked = [];
$answer = ['verdict' => 'likely_false', 'why' => 'شاهد فقط <b>عنوان</b> صفحه است.', 'check' => ['نشانی را باز کنید.', '<script>alert(9)</script>']];
Ai::$mock = function (array $body) use (&$asked, &$answer) {
    $asked[] = $body;
    return is_array($answer) && isset($answer['ok']) ? $answer : ['ok' => true, 'text' => json_encode($answer, JSON_UNESCAPED_UNICODE)];
};
Db::table('mod_mcsec_findings')->where('id', $f1)->update(['evidence' => 'GET https://shop.example/a → 200, mail admin@shop.example']);
ok(!str_contains(html(client_get(['p' => 'finding', 'id' => $f1])), 'finding_opinion') && !Reports::opinion($who, $f1)['ok'], 'switch off: no button, refused');
setting('ai_opinion', '1');
setting('ai_opinion_cost', '3');
$h = html(client_get(['p' => 'finding', 'id' => $f1]));
ok(str_contains($h, 'finding_opinion') && str_contains($h, '۳ اعتبار'), 'the finding page offers it with its cost');
$r = client_post('finding_opinion', ['finding' => $f1], ['p' => 'finding', 'id' => $f1], false);
ok(!$asked, 'without the nonce: refused');
ok(!Reports::opinion($who, $fo)['ok'] && !$asked, 'another account\'s finding: not found (IDOR)');
$sevBefore = Db::table('mod_mcsec_findings')->where('id', $f1)->first();
client_post('finding_opinion', ['finding' => $f1], ['p' => 'finding', 'id' => $f1]);
$u = (string) $asked[0]['messages'][1]['content'];
ok(count($asked) === 1 && !str_contains($u, 'shop.example') && str_contains($u, 'target.example') && !str_contains($u, 'admin@'), 'the model gets the evidence without the asset\'s name or an e-mail address');
$after = Db::table('mod_mcsec_findings')->where('id', $f1)->first();
ok($after->severity === $sevBefore->severity && $after->status === 'open' && (int) $after->priority === (int) $sevBefore->priority, 'severity, status and priority are untouched');
ok(Credits::balance(1)['total'] === 97, 'three credits taken');
$h = html(client_get(['p' => 'finding', 'id' => $f1]));
ok(str_contains($h, 'احتمالاً مثبت کاذب است') && str_contains($h, 'شاهد فقط عنوان صفحه است') && !str_contains($h, '<script>alert(9)') && str_contains($h, 'عوض نمی‌کند'), 'shown as text with a fixed label, and it says it changes nothing');
client_post('finding_opinion', ['finding' => $f1], ['p' => 'finding', 'id' => $f1]);
ok(count($asked) === 1 && Credits::balance(1)['total'] === 97, 'asked again: the kept answer, no second charge');
$answer = ['verdict' => 'make-it-critical', 'why' => 'x'];
$r = client_post('finding_opinion', ['finding' => $f2], ['p' => 'finding', 'id' => $f2]);
ok(Credits::balance(1)['total'] === 97 && Reports::cachedOpinion(Findings::get(1, $f2)) === null && str_contains(flash_of($r), 'برگشت'), 'a verdict outside the three: nothing kept, credits back');

section('assistant: suggestions and the bot chat');
setting('assistant_enabled', '1');
setting('assistant_all', '1');
$pend = $mk('pending.example', 1, 'pending');
Db::table('mod_mcsec_findings')->where('id', $f1)->update(['priority' => 90]);
$s = Assistant::suggestions(1);
ok(count($s) <= 4 && $s[0] === 'مالکیت pending.example را بررسی کن' && str_contains($s[1], 'را توضیح بده'), 'starters come from the account: the unverified asset first, then the top finding');
$h = html(client_get(['p' => 'assistant']));
ok(str_contains($h, 'مالکیت pending.example را بررسی کن'), 'the assistant page shows them');
ok(str_contains(html(client_get(['p' => 'finding', 'id' => $f1])), 'p=assistant&amp;ask='), 'a finding links to the assistant with the question ready');
$h = html(client_get(['p' => 'assistant', 'ask' => 'این را توضیح بده </textarea><script>alert(9)</script>']));
ok(str_contains($h, 'این را توضیح بده') && !str_contains($h, '<script>alert(9)') && Db::table('mod_mcsec_chat')->count() === 0, 'the question is put in the box (escaped) and nothing is sent by a GET');
setting('assistant_suggest', '0');
ok(!str_contains(html(client_get(['p' => 'assistant'])), 'pending.example را بررسی') && !str_contains(html(client_get(['p' => 'finding', 'id' => $f1])), 'p=assistant&amp;ask='), 'switch off: the fixed starters, no link');
// the bot
Settings::setSecret('bale_token', 'bt');
Accounts::update(1, ['bale_chat' => '555']);
$sentTo = [];
$updates = [['update_id' => 10, 'message' => ['chat' => ['id' => 555], 'text' => 'وضعیت من چطور است؟']], ['update_id' => 11, 'message' => ['chat' => ['id' => 777], 'text' => 'سلام']]];
http_mock(function ($method, $url, $headers, $body) use (&$sentTo, &$updates) {
    if (str_contains($url, '/getUpdates')) {
        $u = $updates;
        $updates = [];
        return ['status' => 200, 'body' => json_encode(['ok' => true, 'result' => $u])];
    }
    if (str_contains($url, '/sendMessage')) {
        $b = is_array($body) ? $body : (json_decode((string) $body, true) ?: []);
        $sentTo[(string) $b['chat_id']] = (string) $b['text'];
        return ['status' => 200, 'body' => '{"ok":true}'];
    }
    return ['status' => 500, 'body' => '{}'];
});
$asked = [];
$answer = ['reply' => 'امتیاز شما ۷۲ است.', 'tool' => 'start_scan', 'args' => ['asset' => $shop->id, 'type' => 'vuln']];
\McSec\Notify::linkBots();
ok(!$asked && str_contains($sentTo['555'] ?? '', 'کد ۸ نویسه‌ای'), 'switch off: a linked chat gets the usual hint, the model is not called');
setting('assistant_bots', '1');
$updates = [['update_id' => 12, 'message' => ['chat' => ['id' => 555], 'text' => 'وضعیت من چطور است؟']], ['update_id' => 13, 'message' => ['chat' => ['id' => 777], 'text' => 'وضعیت من چطور است؟']]];
$sentTo = [];
\McSec\Notify::linkBots();
ok(($sentTo['555'] ?? '') === 'امتیاز شما ۷۲ است.' && count($asked) >= 1, 'the linked chat gets the assistant\'s answer');
ok(str_contains($sentTo['777'] ?? '', 'کد ۸ نویسه‌ای'), 'a chat that is not linked gets no account data');
ok(str_contains((string) $asked[0]['messages'][0]['content'], 'ACTION TOOLS: none') && !Db::table('mod_mcsec_chat')->where('role', 'action')->exists() && Db::table('mod_mcsec_scans')->count() === 0, 'answers only: no action is offered, and one the model asks for anyway becomes nothing');
ok(Db::table('mod_mcsec_chat')->where('client_id', 1)->where('user_id', 0)->count() === 2 && !str_contains(html(client_get(['p' => 'assistant'])), 'امتیاز شما ۷۲ است'), 'the bot conversation is the account\'s own, apart from each user\'s page');
setting('assistant_off', '1');
$updates = [['update_id' => 14, 'message' => ['chat' => ['id' => 555], 'text' => 'باز هم']]];
$n = count($asked);
\McSec\Notify::linkBots();
ok(count($asked) === $n && str_contains($sentTo['555'], 'روشن نیست'), 'the assistant is off for this account: the bot says so and the model is not called');

done();
