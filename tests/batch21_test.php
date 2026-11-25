<?php
// 0.21.0: findings mapped to OWASP Top 10 / ISO 27001, a read-only link to one report (expiry, password), a badge
// for the customer's own site, the account's own name on its PDF, two scans compared, and where the servers are.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Compliance;
use McSec\Db;
use McSec\Pdf;
use McSec\Reports;
use McSec\Shares;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'welcome_credits' => '0'] as $k => $v) {
    setting($k, $v);
}
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
Accounts::update(1, ['terms_at' => Clock::now()]);
$asset = fn (int $cid, string $v, string $kind = 'domain', string $status = 'verified') => Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $cid, 'kind' => $kind, 'value' => $v, 'status' => $status, 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
$n = 0;
$find = function (int $cid, int $aid, string $kb, string $sev, array $x = []) use (&$n) {
    $n++;
    return Db::table('mod_mcsec_findings')->insertGetId($x + ['client_id' => $cid, 'asset_id' => $aid, 'fp' => 'fp' . $n, 'engine' => 'builtin', 'profile' => 'hygiene', 'source_key' => 'k' . $n, 'kb' => $kb,
        'title' => 'Finding ' . $n, 'severity' => $sev, 'location' => 'https://x.example/' . $n, 'status' => 'open', 'first_seen_at' => Clock::now() - 86400, 'last_seen_at' => Clock::now()]);
};
$scan = fn (int $cid, int $aid, int $end, string $status = 'completed', string $profile = 'hygiene') => Db::table('mod_mcsec_scans')->insertGetId(['client_id' => $cid, 'asset_id' => $aid, 'profile' => $profile, 'engine' => 'builtin', 'status' => $status,
    'queued_at' => $end - 60, 'started_at' => $end - 50, 'finished_at' => $end]);
$report = function (int $cid, int $aid) {
    $id = Db::table('mod_mcsec_reports')->insertGetId(['client_id' => $cid, 'kind' => 'asset', 'asset_id' => $aid, 'title' => 'Report of ' . $cid, 'status' => 'queued', 'created_at' => Clock::now()]);
    Reports::build($id);
    return $id;
};
$a1 = $asset(1, 'one.example');
$b1 = $asset(2, 'other.example');
$find(1, $a1, 'hdr-hsts', 'medium');
$find(1, $a1, 'sqli', 'critical');
$find(1, $a1, 'xss', 'high');
$find(1, $a1, 'cve-patch', 'high');
$find(1, $a1, '', 'low');
$find(2, $b1, 'ssrf', 'critical', ['title' => 'Secret of two']);

section('mapping to OWASP Top 10 and ISO 27001');
$s = Compliance::summary([['kbk' => 'sqli', 'severity' => 'critical'], ['kbk' => 'xss', 'severity' => 'high'], ['kbk' => 'hdr-hsts', 'severity' => 'medium'], ['kbk' => 'nope', 'severity' => 'high']]);
ok($s['owasp']['A03'] === ['n' => 2, 'severity' => 'critical'] && $s['owasp']['A02']['n'] === 1 && $s['owasp']['A10']['n'] === 0 && $s['iso']['A.8.26']['n'] === 2 && $s['unmapped'] === 1, 'a fixed table from the kb key; an unknown key is counted apart');
ok(count($s['owasp']) === 10, 'all ten categories are listed, seen or not');
$r0 = $report(1, $a1);
ok(!isset(Reports::data(Reports::get(1, $r0))['compliance']['owasp']) && !str_contains(html(client_get(['p' => 'report', 'id' => $r0])), 'OWASP Top 10 (2021)'), 'off by default: no mapping in the report');
setting('report_compliance', '1');
$r1 = $report(1, $a1);
$d = Reports::data(Reports::get(1, $r1));
ok(($d['compliance']['owasp']['A03']['n'] ?? 0) === 2 && ($d['compliance']['owasp']['A06']['n'] ?? 0) === 1 && ($d['compliance']['unmapped'] ?? 0) === 1 && ($d['compliance']['owasp']['A10']['n'] ?? 9) === 0, 'the report carries the mapping of this asset only');
$h = html(client_get(['p' => 'report', 'id' => $r1]));
ok(str_contains($h, 'OWASP Top 10 (2021)') && str_contains($h, 'ISO/IEC 27001:2022') && str_contains($h, 'نه گواهی انطباق') && str_contains($h, 'دیده نشد'), 'the page shows both tables and says it is not a certificate');
if (Pdf::available()) {
    $html = Pdf::html($d);
    ok(str_contains($html, 'OWASP Top 10 (2021)') && str_contains($html, 'نه گواهی انطباق'), 'the PDF has the same section');
}

section('a read-only link to one report');
$r2 = $report(2, $b1);
ok(!Shares::create($who, $r1, 7, '')['ok'] && !str_contains(html(client_get(['p' => 'report', 'id' => $r1])), 'report_share'), 'off by default');
setting('report_share', '1');
ok(str_contains(html(client_get(['p' => 'report', 'id' => $r1])), 'value="report_share"'), 'the form is on the report page');
ok(!Shares::create($who, $r2, 7, '')['ok'], 'another account\'s report cannot be shared');
ok(!Shares::create($who, $r1, 365, '')['ok'] && !Shares::create($who, $r1, 7, '123')['ok'], 'only the listed durations; a password is at least six characters');
$r = client_post('report_share', ['report' => $r1, 'days' => '7'], ['p' => 'report', 'id' => $r1]);
$row = Db::table('mod_mcsec_shares')->where('client_id', 1)->where('kind', 'report')->first();
ok($row && preg_match('~^[a-f0-9]{48}$~', (string) $row->token) && (int) $row->expires_at === Clock::now() + 7 * 86400 && str_contains(html($r), 'p=shared&amp;t=' . $row->token), 'a link with a long random token and an expiry; the page shows it');
ok(Db::table('mod_mcsec_shares')->count() === 1 && !str_starts_with(flash_of(client_post('report_share', ['report' => $r1, 'days' => '7', 'mcs_nonce' => 'x'], ['p' => 'report', 'id' => $r1])), 'پیوند ساخته') && Db::table('mod_mcsec_shares')->count() === 1, 'making a link needs a fresh nonce');
client_get(['p' => 'report', 'id' => $r1, 'a' => 'report_share', 'report' => $r1, 'days' => '7']);
ok(Db::table('mod_mcsec_shares')->count() === 1, 'a GET makes nothing');
login(11, 1);
client_post('report_share', ['report' => $r1, 'days' => '7'], ['p' => 'report', 'id' => $r1]);
ok(Db::table('mod_mcsec_shares')->count() === 1, 'a view-only user cannot share');
\McSec\Auth::$testClient = null;
$pub = fn (string $t, ?string $pw = null) => html($pw === null ? client_get(['p' => 'shared', 't' => $t]) : (function () use ($t, $pw) {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = ['m' => 'mcsec', 'p' => 'shared', 't' => $t];
    $_POST = ['pw' => $pw];
    return \McSec\Client\Controller::handle();
})());
$h = $pub((string) $row->token);
ok(str_contains($h, 'Finding 2') && str_contains($h, 'Report of 1') && !str_contains($h, 'Secret of two'), 'without a login the link shows that report');
ok(!str_contains($h, 'p=finding') && !str_contains($h, 'p=assets') && !str_contains($h, 'mcs_csrf') && !str_contains($h, 'report_share'), 'and nothing that leads into the account');
$res = client_get(['p' => 'shared', 't' => (string) $row->token]);
ok(($res['requirelogin'] ?? true) === false, 'the page asks for no login');
ok(str_contains($pub(str_repeat('a', 48)), 'در دسترس نیست') && str_contains($pub('<script>alert(9)</script>'), 'در دسترس نیست') && !str_contains($pub('<script>alert(9)</script>'), '<script>alert(9)'), 'a wrong or made-up token opens nothing');
$who = login(1, 1);
$pw = Shares::create($who, $r1, 1, 'correct horse');
ok($pw['ok'] && Db::table('mod_mcsec_shares')->where('token', $pw['token'])->value('pass') !== 'correct horse' && !str_contains((string) Db::table('mod_mcsec_audit')->orderByDesc('id')->value('detail'), 'correct horse'), 'a password is kept as a hash only, and is not in the log');
\McSec\Auth::$testClient = null;
$h = $pub($pw['token']);
ok(str_contains($h, 'name="pw"') && !str_contains($h, 'Finding 2'), 'a link with a password shows only the password box');
ok(str_contains($pub($pw['token'], 'wrong'), 'رمز درست نیست') && !str_contains($pub($pw['token'], 'wrong'), 'Finding 2'), 'a wrong password shows nothing');
ok(str_contains($pub($pw['token'], 'correct horse'), 'Finding 2'), 'the right one opens it');
for ($i = 0; $i < 12; $i++) {
    $last = $pub($pw['token'], 'guess' . $i);
}
ok(str_contains($last, 'تلاش‌های زیادی') && !str_contains($pub($pw['token'], 'correct horse'), 'Finding 2'), 'after ten tries in an hour the link stops answering, even to the right password');
Clock::$fixed += 2 * 86400;
ok(str_contains($pub($pw['token'], 'correct horse'), 'در دسترس نیست') && str_contains($pub((string) $row->token), 'Finding 2'), 'an expired link is closed; the other one still opens');
$who = login(1, 1);
ok(!Shares::revoke(login(2, 2), (int) $row->id)['ok'], 'another account cannot withdraw it');
$who = login(1, 1);
client_post('report_unshare', ['share' => (int) $row->id], ['p' => 'report', 'id' => $r1], false);
\McSec\Auth::$testClient = null;
ok(str_contains($pub((string) $row->token), 'در دسترس نیست'), 'a withdrawn link is closed at once');
$who = login(1, 1);
$t3 = Shares::create($who, $r1, 30, '')['token'];
setting('report_share', '0');
\McSec\Auth::$testClient = null;
ok(str_contains($pub($t3), 'در دسترس نیست'), 'turning the feature off closes every link');
setting('report_share', '1');
Db::table('mod_mcsec_reports')->where('id', $r1)->update(['title' => '<script>alert(9)</script>']);
ok(!str_contains($pub($t3), '<script>alert(9)'), 'the public page escapes what it shows');

section('a badge for the customer\'s own site');
$who = login(1, 1);
$ip = $asset(1, '93.184.216.34', 'ip');
$pending = $asset(1, 'pending.example', 'domain', 'pending');
ok(!Shares::badge($who, $a1, true)['ok'] && !str_contains(html(client_get(['p' => 'asset', 'id' => $a1])), 'asset_badge'), 'off by default');
setting('site_badge', '1');
ok(!Shares::badge($who, $b1, true)['ok'] && !Shares::badge($who, $ip, true)['ok'] && !Shares::badge($who, $pending, true)['ok'], 'only for a verified domain of this account');
client_post('asset_badge', ['asset' => $a1, 'on' => '1'], ['p' => 'asset', 'id' => $a1]);
$b = Shares::badgeOf(1, $a1);
ok($b && (int) $b->expires_at === 0 && str_contains(html(client_get(['p' => 'asset', 'id' => $a1])), 'p=badge&amp;t=' . $b->token), 'the page of the domain shows the badge and its code');
$svg = (string) Shares::badgeSvg((string) $b->token);
ok(str_starts_with($svg, '<svg') && str_contains($svg, 'بررسی به‌روز نیست') && !str_contains($svg, 'one.example'), 'without a recent scan it says the check is not current');
$scan(1, $a1, Clock::now() - 3 * 86400);
$svg = (string) Shares::badgeSvg((string) $b->token);
ok(str_contains($svg, 'آخرین بررسی') && str_contains($svg, 'پایش امنیتی') && !preg_match('~امن است|secure<~u', $svg), 'after a completed scan it shows the date, and never says "secure"');
ok(str_contains((string) Shares::badgeSvg((string) $b->token, 'en'), 'Security monitored'), 'English on request');
\McSec\Auth::$testClient = null;
$raw = client_get(['p' => 'badge', 't' => (string) $b->token])['raw'] ?? null;
ok(is_array($raw) && $raw['mime'] === 'image/svg+xml' && str_starts_with($raw['bytes'], '<svg'), 'served as a picture without a login');
$none = client_get(['p' => 'badge', 't' => 'nope']);
ok(array_key_exists('raw', $none) && $none['raw'] === null && Shares::badgeSvg((string) $row->token) === null && Shares::open((string) $b->token, null)['state'] === 'none', 'a wrong token gives nothing; a badge token opens no report and a report token no badge');
Clock::$fixed += 40 * 86400;
ok(str_contains((string) Shares::badgeSvg((string) $b->token), 'بررسی به‌روز نیست'), 'it turns stale when the last scan is older than 35 days');
Db::table('mod_mcsec_assets')->where('id', $a1)->update(['status' => 'lapsed']);
ok(str_contains((string) Shares::badgeSvg((string) $b->token), 'بررسی به‌روز نیست'), 'and when the domain is no longer verified');
Db::table('mod_mcsec_assets')->where('id', $a1)->update(['status' => 'verified']);
$who = login(1, 1);
client_post('asset_badge', ['asset' => $a1, 'on' => '0'], ['p' => 'asset', 'id' => $a1]);
ok(Shares::badgeSvg((string) $b->token) === null, 'removed with one click');

section('the account\'s own name on its PDF');
ok(!Pdf::ownAllowed(1), 'nobody by default');
client_post('brand_save', ['brand_name' => 'Agency'], ['p' => 'reports'], false);
ok((string) (Accounts::get(1)->brand_name ?? '') === '' && !str_contains(html(client_get(['p' => 'reports'])), 'brand_save'), 'an account that may not cannot set it');
setting('pdf_whitelabel', '7, 1');
ok(Pdf::ownAllowed(1) && Pdf::ownAllowed(7) && !Pdf::ownAllowed(2) && !Pdf::ownAllowed(17), 'the admin lists the accounts');
ok(Pdf::asClient(1, fn () => Pdf::brand()) === Pdf::brand(), 'without a name of its own the default stays');
client_post('brand_save', ['brand_name' => 'Agency <script>alert(9)</script>', 'brand_contact' => 'agency.example'], ['p' => 'reports'], false);
Accounts::forget();
$own = Pdf::asClient(1, fn () => [Pdf::brand(), Pdf::template()['contact'], Pdf::template()['footer']]);
ok(str_starts_with($own[0], 'Agency') && $own[1] === 'agency.example' && $own[2] === $own[0], 'with one, the PDF carries its name and contact line');
ok(Pdf::$own === null && Pdf::asClient(2, fn () => Pdf::brand()) === Pdf::brand(), 'only while its own PDF is made, and only for that account');
ok(Pdf::available() ? !str_contains(html(client_get(['p' => 'reports'])), '<script>alert(9)') : true, 'the form escapes the name');
setting('pdf_whitelabel', '*');
ok(Pdf::ownAllowed(2), '* opens it for everyone');

section('two scans compared');
Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
$c1 = $asset(1, 'cmp.example');
$s1 = $scan(1, $c1, Clock::now() - 10 * 86400);
$s2 = $scan(1, $c1, Clock::now() - 5 * 86400);
$s3 = $scan(1, $c1, Clock::now() - 86400);
$sx = $scan(2, $b1, Clock::now() - 86400);
$sy = $scan(1, $a1, Clock::now() - 86400);
$find(1, $c1, 'xss', 'high', ['title' => 'Old open', 'first_scan_id' => $s1]);
$find(1, $c1, 'xss', 'high', ['title' => 'Came later', 'first_scan_id' => $s3]);
$find(1, $c1, 'xss', 'low', ['title' => 'Was fixed', 'first_scan_id' => $s1, 'status' => 'fixed', 'fixed_scan_id' => $s2, 'fixed_at' => Clock::now() - 5 * 86400]);
Db::table('mod_mcsec_surface')->insert([['client_id' => 1, 'asset_id' => $c1, 'kind' => 'port', 'value' => 'cmp.example:8443', 'first_scan_id' => $s3, 'first_seen_at' => Clock::now() - 86400, 'last_seen_at' => Clock::now(), 'gone_at' => 0],
    ['client_id' => 1, 'asset_id' => $c1, 'kind' => 'port', 'value' => 'cmp.example:21', 'first_scan_id' => $s1, 'first_seen_at' => Clock::now() - 10 * 86400, 'last_seen_at' => Clock::now() - 6 * 86400, 'gone_at' => Clock::now() - 5 * 86400]]);
$h = html(client_get(['p' => 'compare', 'from' => $s1, 'to' => $s3]));
ok(str_contains($h, 'Came later') && str_contains($h, 'Was fixed') && !str_contains($h, 'Old open') && str_contains($h, 'cmp.example:8443') && str_contains($h, 'cmp.example:21'), 'what appeared, what was fixed and what changed on the surface between the two');
ok(str_contains(html(client_get(['p' => 'scan', 'id' => $s3])), 'p=compare&amp;from=' . $s2 . '&amp;to=' . $s3), 'a scan links to the comparison with the one before it');
foreach ([[$sx, $s3], [$s1, $sx], [$sy, $s3], [$s3, $s1], [0, $s3]] as [$f, $t]) {
    $bad[] = str_contains(html(client_get(['p' => 'compare', 'from' => $f, 'to' => $t])), 'Came later');
}
ok(!in_array(true, $bad, true), 'never another account\'s scan, another asset\'s, or the two the wrong way round');

section('where the servers are');
$geo = fn (int $cid, int $aid, string $ip, array $m) => Db::table('mod_mcsec_surface')->insert(['client_id' => $cid, 'asset_id' => $aid, 'kind' => 'ip', 'value' => $ip, 'meta' => json_encode($m), 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now(), 'gone_at' => 0]);
$geo(1, $a1, '93.184.216.34', ['cc' => 'DE', 'country' => 'Germany', 'lat' => 50.1, 'lon' => 8.7]);
$geo(1, $a1, '93.184.216.35', ['cc' => 'IR', 'country' => '<script>alert(9)</script>', 'lat' => 35.7, 'lon' => 51.4]);
$geo(1, $a1, '93.184.216.36', ['cc' => 'zz<', 'country' => 'Bad', 'lat' => 1, 'lon' => 1]);
$geo(2, $b1, '93.184.216.99', ['cc' => 'US', 'country' => 'Otherland', 'lat' => 40, 'lon' => -100]);
ok(!str_contains(html(client_get(['p' => 'home'])), 'class="mcs-world"'), 'off by default');
setting('geo_map', '1');
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'class="mcs-world"') && str_contains($h, 'Germany') && !str_contains($h, 'Otherland') && !str_contains($h, 'Bad<') && !str_contains($h, '<script>alert(9)'), 'the overview shows this account\'s countries on a map, escaped');
$w = \McSec\Client\Charts::world([[51.4, 35.7], [999, -999]]);
ok(substr_count($w, '<circle') > 600 && str_contains($w, 'cx="231.4" cy="54.3"') && str_contains($w, 'cx="360" cy="180"'), 'a dotted map made here, with a marker for each place (clamped to the map)');

section('WHMCS tables');
ok(Db::table('tblusers_clients')->count() === 12 && Db::table('tblclients')->count() === 10, 'nothing was written to tbl*');
done();
