<?php
// 0.13.0 two languages: Persian is the source and stays byte-for-byte; English comes from lang/en. The language is
// the visitor's in the client area and the account's own in background work. Every customer page renders in English
// with no Persian left in the section's own text, left to right, Latin digits, Gregorian dates.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Kb;
use McSec\Lang;
use McSec\Notify;
use McSec\Text;
use WHMCS\Database\Capsule;

Clock::$fixed = strtotime('2026-11-24T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'welcome_credits' => '0', 'assistant_enabled' => '1', 'assistant_all' => '1', 'export_csv' => '1', 'host_mute' => '1'] as $k => $v) {
    setting($k, $v);
}
$fa = fn (string $s) => preg_match('~[\x{0600}-\x{06FF}]~u', $s) === 1;
/** Persian runs left in a page, without the parts that are data (what the account typed, the admin's own texts). */
$left = function (string $html): array {
    $html = preg_replace('~<(script|style)\b.*?</\1>~s', '', $html) ?? $html;
    $text = html_entity_decode(strip_tags(preg_replace('~<[^>]+>~', ' ', $html) ?? ''), ENT_QUOTES, 'UTF-8');
    preg_match_all('~[\x{0600}-\x{06FF}][\x{0600}-\x{06FF}\x{200C}\s]*~u', $text, $m);
    $attrs = [];
    preg_match_all('~(?:title|aria-label|placeholder|alt|value|data-mcs-confirm)="([^"]*[\x{0600}-\x{06FF}][^"]*)"~u', $html, $a);
    return array_values(array_unique(array_map('trim', array_merge($m[0], $a[1]))));
};

section('the dictionary is complete and well formed');
$out = [];
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/tools/i18n.php') . ' 2>&1', $out, $code);
ok($code === 0, 'tools/i18n.php: every customer-facing Persian text has English (' . trim((string) end($out)) . ')');
ok(count(Lang::all()) > 1500, 'the dictionary is loaded from lang/en (' . count(Lang::all()) . ' entries)');

section('Lang');
Lang::$force = null;
Lang::set(null);
$_SESSION['Language'] = 'english';
ok(Lang::code() === 'en' && !Lang::rtl() && Lang::attrs() === 'dir="ltr" lang="en"', 'the visitor\'s WHMCS language decides: english is English, left to right');
Lang::set(null);
$_SESSION['Language'] = 'farsi';
ok(Lang::code() === 'fa' && Lang::rtl(), 'farsi is Persian, right to left');
Lang::set(null);
unset($_SESSION['Language']);
$_SESSION['uid'] = 2;
as_whmcs(fn () => Capsule::table('tblclients')->where('id', 2)->update(['language' => 'german']));
ok(Lang::code() === 'en', 'no session language: the account\'s own; any language that is not Persian gets English');
Lang::set(null);
$_SESSION['uid'] = 3;
ok(Lang::code() === 'fa', 'an account with no language: the system\'s default (farsi)');
unset($_SESSION['uid']);
Lang::set(null);
ok(Lang::forClient(2) === 'en' && Lang::forClient(1) === 'fa', 'forClient reads each account\'s language');
Lang::$force = 'fa';
ok(Lang::t('{n} دقیقه پیش', ['n' => '۳']) === '۳ دقیقه پیش', 'Persian: the text itself, placeholders filled');
$in = Lang::with('en', fn () => [Lang::code(), Lang::t('{n} دقیقه پیش', ['n' => '3']), Lang::t('متنی که ترجمه ندارد')]);
ok($in === ['en', '3 min ago', 'متنی که ترجمه ندارد'], 'with(): English inside, placeholders filled, a text without English stays Persian');
ok(Lang::code() === 'fa', 'with() puts the language back');
try {
    Lang::with('en', function () {
        throw new RuntimeException('x');
    });
} catch (RuntimeException $e) {
}
ok(Lang::code() === 'fa', 'with() puts the language back after an exception too');

section('digits, dates and money');
ok(Text::fa(1405) === '۱۴۰۵' && Text::num(1234567) === '۱٬۲۳۴٬۵۶۷' && str_contains(Text::date(Clock::now()), 'آذر ۱۴۰۵') && Text::ymd('2026-11-24') === '۳ آذر ۱۴۰۵', 'Persian: Persian digits, Jalali dates');
Lang::$force = 'en';
ok(Text::fa(1405) === '1405' && Text::num(1234567) === '1,234,567', 'English: Latin digits and separators');
ok(Text::date(Clock::now()) === '24 Nov 2026, 13:30' && Text::ymd('2026-11-24') === '24 Nov 2026' && Text::ago(Clock::now() - 7200) === '2 h ago', 'English: Gregorian dates, "ago" in English');
ok(!$fa(Text::money(1200000.0, (object) ['code' => 'IRR', 'prefix' => '', 'suffix' => '', 'format' => 4])), 'English: money without Persian');
ok(Text::e('بحرانی') === 'Critical' && Text::e('<b>دامنه‌ی من</b>') === '&lt;b&gt;دامنه‌ی من&lt;/b&gt;', 'e(): a whole label is translated, anything else is only escaped');
ok(Text::toAscii('۱۲۳') === '123', 'input in Persian digits is still read');

section('an English visitor: every page');
Lang::$force = 'en';
$who = login(1, 1);
Accounts::ensure(1);
Credits::credit(1, 100, 'paid', 'topup', 'topup:i18n', 'test');
$aid = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 1, 'kind' => 'domain', 'value' => 'shop.example', 'status' => 'verified', 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now(), 'last_scan_at' => Clock::now() - 3600, 'score' => 62]);
$pid = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 1, 'kind' => 'domain', 'value' => 'new.example', 'status' => 'pending', 'created_at' => Clock::now(), 'next_check_at' => Clock::now() + 600]);
$ipid = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 1, 'kind' => 'ip', 'value' => '93.184.216.9', 'status' => 'pending', 'created_at' => Clock::now(), 'next_check_at' => Clock::now() + 600]);
$sid = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 1, 'asset_id' => $aid, 'profile' => 'hygiene', 'engine' => 'builtin', 'status' => 'completed', 'progress' => 100, 'queued_at' => Clock::now() - 4000, 'started_at' => Clock::now() - 3900,
    'finished_at' => Clock::now() - 3600, 'summary' => json_encode(['new' => 2, 'fixed' => 0, 'reopened' => 0, 'seen' => 2, 'open' => ['high' => 1, 'medium' => 1]])]);
$rid = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 1, 'asset_id' => $aid, 'profile' => 'vuln', 'engine' => 'oasm', 'status' => 'running', 'progress' => 40, 'stage' => 'x', 'queued_at' => Clock::now() - 600, 'started_at' => Clock::now() - 500]);
$xid = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 1, 'asset_id' => $aid, 'profile' => 'hygiene', 'engine' => 'builtin', 'status' => 'failed', 'error' => 'x', 'error_ref' => 'MS-AAAAAA', 'queued_at' => Clock::now() - 9000, 'started_at' => Clock::now() - 8900, 'finished_at' => Clock::now() - 8800]);
$fid = Db::table('mod_mcsec_findings')->insertGetId(['client_id' => 1, 'asset_id' => $aid, 'fp' => sha1('a'), 'engine' => 'builtin', 'source_key' => 'builtin.hdr.hsts', 'kb' => 'hdr-hsts', 'title' => 'HSTS header is missing', 'severity' => 'medium', 'status' => 'open',
    'location' => 'https://shop.example/', 'first_seen_at' => Clock::now() - 3600, 'last_seen_at' => Clock::now() - 3600, 'first_scan_id' => $sid]);
Db::table('mod_mcsec_findings')->insert(['client_id' => 1, 'asset_id' => $aid, 'fp' => sha1('b'), 'engine' => 'builtin', 'source_key' => 'builtin.tls.expired', 'kb' => 'tls-expired', 'title' => 'TLS certificate has expired', 'severity' => 'high', 'status' => 'open',
    'location' => 'shop.example:443', 'first_seen_at' => Clock::now() - 3600, 'last_seen_at' => Clock::now() - 3600, 'first_scan_id' => $sid]);
$pages = [['home'], ['assets'], ['asset', $aid], ['asset', $pid], ['asset', $ipid], ['scans'], ['scan', $sid], ['scan', $rid], ['scan', $xid], ['findings'], ['finding', $fid], ['reports'], ['schedules'], ['recipes'], ['assistant'], ['support'], ['notify'], ['credits'], ['activity']];
$bad = [];
$ltr = true;
foreach ($pages as $p) {
    $h = html(client_get(['p' => $p[0]] + (isset($p[1]) ? ['id' => $p[1]] : [])));
    $ltr = $ltr && str_contains($h, 'dir="ltr" lang="en"') && !str_contains($h, 'dir="rtl"') && !str_contains($h, 'lang="fa"');
    foreach ($left($h) as $run) {
        $bad[] = $p[0] . (isset($p[1]) ? '#' . $p[1] : '') . ': ' . mb_substr($run, 0, 60);
    }
}
ok($ltr, 'every page is left to right and says lang="en"');
ok(!$bad, 'no Persian left in any page (' . count($bad) . '): ' . implode(' | ', array_slice($bad, 0, 12)));
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'Cyber Security') && str_contains($h, 'Overview') && !preg_match('~[۰-۹]~u', (string) preg_replace('~<script\b.*?</script>~s', '', $h)), 'the overview: English menu, Latin digits');
$h = html(client_get(['p' => 'home', 'view' => 'x']));
client_post('view_mode', ['view' => 'advanced'], ['p' => 'home'], false);
ok(!$left(html(client_get(['p' => 'home']))), 'the advanced overview has no Persian either');
$h = html(client_get(['p' => 'finding', 'id' => $fid]));
ok(($k = Kb::get('hdr-hsts')) !== null && !$fa($k['title'] . $k['why'] . implode('', $k['steps']) . ($k['effort'] ?? '') . ($k['maral'] ?? '')) && str_contains($h, htmlspecialchars($k['title'], ENT_QUOTES)), 'the fix guide of a finding is English');
$allKb = '';
foreach (array_keys(Kb::ENTRIES) as $key) {
    $e = Kb::get($key);
    $allKb .= $e['title'] . $e['why'] . implode('', $e['steps']) . ($e['effort'] ?? '') . ($e['maral'] ?? '') . implode('', array_map(fn ($s) => $s['label'] . $s['code'], $e['snippets'] ?? []));
}
ok(!$fa($allKb), 'the whole knowledge base (' . count(Kb::ENTRIES) . ' entries) is English');
$r = client_post('add_asset', ['targets' => ''], ['p' => 'assets']);
ok(!$fa(flash_of($r)) && flash_of($r) !== '', 'an error message is English: ' . flash_of($r));
$r = client_post('support_send', ['topic' => 'other', 'text' => 'short'], ['p' => 'support']);
ok(!$fa(flash_of($r)) && flash_of($r) !== '', 'a refused request is explained in English');
$r = client_post('support_send', ['topic' => 'finding', 'finding' => $fid, 'text' => 'Please check this finding, I fixed it already.'], ['p' => 'support']);
$t = as_whmcs(fn () => Capsule::table('tbltickets')->orderByDesc('id')->first());
ok($t !== null && str_starts_with($t->title, '[امنیت سایبری]') && str_contains($t->message, 'یافته شماره‌ی') && str_contains($t->message, 'Please check this finding'), 'the ticket itself is Persian for the support team, with the customer\'s own words as written');
ok(!$left(html(client_get(['p' => 'support', 'sent' => (string) Db::table('mod_mcsec_requests')->max('id')]))), 'the confirmation is English');
$pub = html(client_get(['p' => 'scanner']));
ok(str_contains($pub, 'dir="ltr"') && !$left($pub), 'the public scanner page is English');

section('Persian stays Persian');
Lang::$force = 'fa';
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'dir="rtl" lang="fa"') && str_contains($h, 'نمای کلی') && str_contains($h, 'مرکز پایش امنیت') && !str_contains($h, 'Overview'), 'a Persian visitor sees Persian');
ok(Kb::get('hdr-hsts')['title'] === Kb::ENTRIES['hdr-hsts']['title'], 'the knowledge base is untouched in Persian');

section('background work writes in the account\'s language');
Lang::$force = null;
Lang::set('fa');
Accounts::ensure(2);
Notify::event(2, 'credits_added', ['credits' => 25, 'note' => ''], 'i18n:en');
Notify::event(1, 'credits_added', ['credits' => 25, 'note' => ''], 'i18n:fa');
$n2 = Db::table('mod_mcsec_notices')->where('client_id', 2)->orderByDesc('id')->first();
$n1 = Db::table('mod_mcsec_notices')->where('client_id', 1)->orderByDesc('id')->first();
ok($n2 !== null && !$fa((string) $n2->title . (string) $n2->body) && str_contains((string) $n2->title . (string) $n2->body, '25'), 'an English account gets its notice in English: ' . ($n2->title ?? ''));
ok($n1 !== null && $fa((string) $n1->title), 'a Persian account gets it in Persian, in the same run');
ok(Lang::code() === 'fa', 'and the language of the run is put back');

section('the admin panel is Persian');
Lang::$force = null;
Lang::set(null);
$_SESSION['Language'] = 'english';
admin();
$_GET = ['module' => 'mcsec'];
$_POST = [];
$_SERVER['REQUEST_METHOD'] = 'GET';
$h = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(str_contains($h, 'dir="rtl" lang="fa"') && str_contains($h, 'نمای کلی') && !str_contains($h, 'Critical'), 'whatever the admin\'s WHMCS language');
unset($_SESSION['Language']);
Lang::$force = 'fa';

done();
