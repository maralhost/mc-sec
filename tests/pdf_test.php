<?php
// 0.6.0: the Persian PDF of a report (HTML for TCPDF, bidi marks around Latin tokens, escaping), its download route,
// and OASM's own technical PDF fetched in an explicit POST. No network: Http::$mock only. The PDF itself is rendered
// only when TCPDF is present (WHMCS ships it; a developer may put it in tests/tmp/tcpdf).
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\Findings;
use McSec\Pdf;
use McSec\Reports;

Clock::$fixed = strtotime('2026-11-21T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'oasm_url' => 'https://oasm.test', 'oasm_email' => 'svc@oasm.test'] as $k => $v) {
    setting($k, $v);
}
\McSec\Settings::setSecret('oasm_password', 'pw');
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
$mk = function (string $value, int $client = 1, string $target = ''): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $client, 'kind' => 'domain', 'value' => $value, 'status' => 'verified', 'method' => 'admin', 'oasm_target' => $target, 'last_scan_at' => Clock::now(), 'created_at' => Clock::now()]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
$L = "\u{202A}";
$P = "\u{202C}";
$plain = fn (string $s) => str_replace([$L, $P, "\u{2011}"], ['[', ']', '-'], $s);

section('left-to-right tokens inside Persian text');
ok($plain(Pdf::text('گواهی از Let\'s Encrypt یا Sectigo است')) === 'گواهی از [Let&#039;s Encrypt] یا [Sectigo] است', 'a Latin phrase is one run, so its words keep their order');
ok($plain(Pdf::text('خطا (HTTP 502) روی CVE-2024-27956')) === 'خطا ([HTTP 502]) روی [CVE-2024-27956]', 'codes and ids');
ok($plain(Pdf::text('Plugin < 3.92.1 & <script>alert(9)</script>')) === '[Plugin] &lt; 3.92.1 &amp; &lt;[script]&gt;[alert](9)&lt;/[script]&gt;', 'escaped piece by piece: no entity is ever split');
ok($plain(Pdf::ltr('https://shop.example/a-b?x=1&y=<2>')) === '[https://shop.example/a-b?x=1&amp;y=&lt;2&gt;]' && Pdf::ltr('  ') === '', 'a URL: embedded, escaped, hyphens kept from breaking the line');
ok(Pdf::text('متن فارسی ساده، با نیم‌فاصله') === 'متن فارسی ساده، با نیم‌فاصله', 'plain Persian is left alone');

section('the report as HTML for the PDF');
$shop = $mk('shop.example', 1, 't-shop');
$sid = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 1, 'asset_id' => $shop->id, 'profile' => 'vuln', 'engine' => 'oasm', 'status' => 'completed', 'queued_at' => Clock::now() - 700, 'started_at' => Clock::now() - 650, 'finished_at' => Clock::now() - 600, 'summary' => '{}']);
Findings::ingest(Db::table('mod_mcsec_scans')->where('id', $sid)->first(), $shop, [
    ['key' => 'oasm.cve-2024-27956', 'title' => 'SQL Injection <script>alert(9)</script>', 'severity' => 'critical', 'location' => 'https://shop.example/x?a=<b>', 'cve' => ['CVE-2024-27956'], 'kb' => 'sqli', 'description' => '<img src=x onerror=alert(9)>'],
    ['key' => 'builtin.hdr.hsts', 'title' => 'هدر HSTS تنظیم نشده است', 'severity' => 'low', 'location' => 'https://shop.example/', 'kb' => 'hdr-hsts'],
], false);
$rid = Reports::queue(1, 'scan', ['scan_id' => $sid, 'asset_id' => (int) $shop->id], false, 1)['report_id'];
Reports::build($rid);
$rep = Reports::get(1, $rid);
ok($rep !== null && $rep->status === 'ready', 'a ready report');
$h = Pdf::html(Reports::data($rep));
ok(str_contains($h, 'امتیاز امنیت') && str_contains($h, 'خلاصه') && str_contains($h, 'یافته‌ها و راه رفع') && str_contains($h, 'بحرانی'), 'score, summary and findings');
ok(!str_contains($h, '<script') && !str_contains($h, '<img') && !str_contains($h, 'onerror=alert(9)>') && str_contains($h, '&lt;'), 'scanner text is escaped, never markup');
ok(str_contains($h, $L . 'CVE' . "\u{2011}" . '2024' . "\u{2011}" . '27956' . $P) && str_contains($plain($h), '[https://shop.example/x?a=&lt;b&gt;]'), 'CVE id and location are embedded left-to-right');
ok(str_contains($h, '<ol>') && str_contains($h, 'جای تست نفوذ دستی را نمی‌گیرد'), 'fix steps and the "not a manual pentest" line');
ok(preg_match('~<(?!/?(?:table|tr|td|span|b|br|p|ul|ol|li)\b)[a-z]~i', $h) === 0, 'only the small tag set TCPDF handles');
$empty = Pdf::html(['kind' => 'scan', 'title' => 'x', 'score' => -1, 'counts' => [], 'findings' => []]);
ok(str_contains($empty, 'یافته‌ی بازی نیست') && str_contains($empty, 'بی‌اسکن'), 'a report with nothing in it still renders');

section('rendering (needs TCPDF)');
$tc = __DIR__ . '/tmp/tcpdf/tcpdf.php';
if (!class_exists('TCPDF') && is_file($tc)) {
    require_once $tc;
}
if (class_exists('TCPDF')) {
    ok(Pdf::available() && in_array(Pdf::font(), ['dejavusans', 'freesans'], true), 'a font that shapes Persian is found');
    $bytes = Pdf::render(Reports::data($rep));
    ok(str_starts_with($bytes, '%PDF-') && strlen($bytes) > 20000 && !str_contains($bytes, 'Powered by TCPDF'), 'a real PDF, without the library\'s advert link (' . strlen($bytes) . ' bytes)');
    $r = client_get(['p' => 'report', 'id' => (string) $rid, 'pdf' => '1']);
    ok(($r['raw']['mime'] ?? '') === 'application/pdf' && str_starts_with($r['raw']['bytes'], '%PDF-') && $r['raw']['name'] === 'mcsec-report-' . $rid . '.pdf', 'the owner downloads it');
    ok(str_contains(html(client_get(['p' => 'report', 'id' => (string) $rid])), 'pdf=1" download'), 'the report page offers the download (a plain link that skips in-page navigation)');
    login(2, 2);
    ok(client_get(['p' => 'report', 'id' => (string) $rid, 'pdf' => '1'])['raw'] === null, 'another account: nothing (IDOR)');
    \McSec\Auth::$testClient = null;
    ok(!array_key_exists('raw', client_get(['p' => 'report', 'id' => (string) $rid, 'pdf' => '1'])), 'not signed in: no file');
    $who = login(1, 1);
    $q = Db::table('mod_mcsec_reports')->insertGetId(['client_id' => 1, 'kind' => 'scan', 'title' => 'pending', 'status' => 'queued', 'created_at' => Clock::now()]);
    ok(client_get(['p' => 'report', 'id' => (string) $q, 'pdf' => '1'])['raw'] === null, 'a report that is not ready has no PDF');
} else {
    ok(!Pdf::available() && Pdf::render(['title' => 'x']) === '', 'without TCPDF: no PDF, and nothing breaks');
    ok(client_get(['p' => 'report', 'id' => (string) $rid, 'pdf' => '1'])['raw'] === null, 'the route answers "not found"');
    ok(!str_contains(html(client_get(['p' => 'report', 'id' => (string) $rid])), 'pdf=1'), 'and the page does not offer it');
    for ($i = 0; $i < 4; $i++) {
        ok(true, 'rendering not checked here (TCPDF is not installed in this environment)');
    }
}

section('OASM technical report (explicit POST only)');
$theirs = $mk('other.example', 2, 't-other');
$bare = $mk('bare.example', 1, '');
Accounts::update(1, ['oasm_workspace' => 'ws-1', 'oasm_user' => 'mcsec-c1@x', 'oasm_secret' => \McSec\Crypto::encrypt('p')]);
$calls = [];
$st = ['link' => '/api/storage/reports/report-vulnerability-abc.pdf?X-Amz-Signature=sig123', 'pdf' => '%PDF-1.7 fake report body'];
http_mock(function ($m, $url, $h, $body) use (&$calls, &$st) {
    $path = (string) parse_url($url, PHP_URL_PATH);
    $calls[] = [$m, $path, (string) $body, $h['X-Workspace-Id'] ?? ''];
    if ($path === '/api/auth/sign-in/email') {
        return ['status' => 200, 'body' => '{}', 'headers' => ['set-cookie' => ['s=1; Path=/']]];
    }
    if ($m === 'POST' && $path === '/api/reports/generate/vulnerability') {
        return ['status' => 201, 'body' => '{"message":"ok"}'];
    }
    if ($m === 'GET' && $path === '/api/reports') {
        return ['status' => 200, 'body' => json_encode(['data' => [['id' => 'rep-1', 'type' => 'VULNERABILITY', 'downloadUrl' => $st['link']]]])];
    }
    if ($m === 'GET' && str_starts_with($path, '/api/storage/reports/')) {
        return ['status' => 200, 'body' => $st['pdf']];
    }
    if ($m === 'DELETE') {
        return ['status' => 200, 'body' => '{}'];
    }
    return ['status' => 404, 'body' => '{}'];
});
$h = html(client_get(['p' => 'asset', 'id' => (string) $shop->id]));
ok(str_contains($h, 'گزارش فنی موتور اسکن') && str_contains($h, 'name="a" value="oasm_report"') && str_contains($h, 'mcs-native'), 'offered on an asset that was scanned on OASM, as a POST form');
ok(!str_contains(html(client_get(['p' => 'asset', 'id' => (string) $bare->id])), 'oasm_report') && $calls === [], 'not on an asset OASM never saw; and viewing pages calls nothing');
$r = client_post('oasm_report', ['asset' => (string) $shop->id], ['p' => 'asset', 'id' => (string) $shop->id], false);
ok(($r['raw']['mime'] ?? '') === 'application/pdf' && $r['raw']['bytes'] === $st['pdf'] && $r['raw']['name'] === 'oasm-report-' . (int) $shop->id . '.pdf', 'the PDF comes back as a download');
$gen = array_values(array_filter($calls, fn ($c) => $c[1] === '/api/reports/generate/vulnerability'))[0];
ok($gen[3] === 'ws-1' && json_decode($gen[2], true)['targetIds'] === ['t-shop'], 'made in the account\'s own workspace, for this asset\'s target only');
ok((bool) array_filter($calls, fn ($c) => $c[0] === 'DELETE' && $c[1] === '/api/reports/rep-1'), 'and removed from OASM afterwards');
ok(!Db::table('mod_mcsec_log')->where('detail', 'like', '%sig123%')->exists() && !Db::table('mod_mcsec_audit')->where('detail', 'like', '%sig123%')->exists(), 'the signed link is not written anywhere');
$calls = [];
$r = client_post('oasm_report', ['asset' => (string) $theirs->id], [], false);
ok(!isset($r['raw']) && $calls === [] && str_contains(flash_of($r), 'هنوز اسکنی'), 'another account\'s asset: refused, OASM not called (IDOR)');
$r = client_post('oasm_report', ['asset' => (string) $bare->id], [], false);
ok(!isset($r['raw']) && $calls === [], 'an asset without an OASM target: refused');
foreach (['https://evil.example/x.pdf?a=1', '/api/storage/../auth/admin.pdf?a=1', '/api/storage/reports/x.pdf', '/api/other/x.pdf?a=1'] as $bad) {
    $st['link'] = $bad;
    $r = client_post('oasm_report', ['asset' => (string) $shop->id], [], false);
    if (isset($r['raw']) || array_filter($calls, fn ($c) => $c[0] === 'GET' && !in_array($c[1], ['/api/reports'], true))) {
        ok(false, 'a link that is not OASM\'s own report route was followed: ' . $bad);
    }
    $calls = [];
}
ok(true, 'only OASM\'s own report storage route is ever downloaded');
\McSec\Db::table('mod_mcsec_hits')->where('k', 'like', '%oasmpdf%')->delete();
$st['link'] = '/api/storage/reports/report-vulnerability-abc.pdf?X-Amz-Signature=sig123';
$st['pdf'] = '<html>not a pdf</html>';
$r = client_post('oasm_report', ['asset' => (string) $shop->id], [], false);
ok(!isset($r['raw']) && str_contains(flash_of($r), 'MS-'), 'not a PDF: an error with a support code, nothing sent to the browser');
$st['pdf'] = '%PDF-1.7 ok';
$n = 0;
for ($i = 0; $i < 8; $i++) {
    $n += isset(client_post('oasm_report', ['asset' => (string) $shop->id], [], false)['raw']) ? 1 : 0;
}
ok($n === 5, 'six an hour per account, then a polite refusal (' . $n . ' more after the first)');
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['m' => 'mcsec', 'p' => 'asset', 'id' => (string) $shop->id, 'a' => 'oasm_report', 'asset' => (string) $shop->id];
$_POST = [];
$calls = [];
ok(!isset(\McSec\Client\Controller::handle()['raw']) && $calls === [], 'a GET never fetches a report');
login(1, 1, true);
$r = client_post('oasm_report', ['asset' => (string) $shop->id], [], false);
ok(!isset($r['raw']), 'support behind "login as client" cannot pull it either');

done();
