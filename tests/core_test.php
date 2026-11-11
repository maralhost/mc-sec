<?php
// Units: target parsing, apex, blocklist, public IPs, schedules (Jalali), score, AI JSON and masking, crypto, install.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Ai;
use McSec\Crypto;
use McSec\Findings;
use McSec\Installer;
use McSec\Net;
use McSec\Schedules;
use McSec\Score;
use McSec\Text;

section('Net::parse');
$cases = [
    'Example.COM' => ['domain', 'example.com'], 'https://Shop.Example.com/path?x=1' => ['domain', 'shop.example.com'], 'example.com.' => ['domain', 'example.com'],
    'example.com/blog' => ['domain', 'example.com'], 'example.com:8443' => ['domain', 'example.com'], '۲۰۳.۰.۱۱۳.۱۰' => ['ip', '203.0.113.10'],
    '203.0.113.0/28' => ['cidr', '203.0.113.0/28'], '203.0.113.9/28' => ['cidr', '203.0.113.0/28'], '203.0.113.9/32' => ['ip', '203.0.113.9'],
    '2001:DB8::1' => ['ip', '2001:db8::1'],
];
foreach ($cases as $in => [$kind, $value]) {
    $r = Net::parse($in);
    ok(($r['kind'] ?? '') === $kind && ($r['value'] ?? '') === $value, "parse {$in} → {$kind} {$value} (got " . json_encode($r, JSON_UNESCAPED_UNICODE) . ')');
}
foreach (['', 'not a domain', '*.example.com', '10.0.0.0/8', 'exa_mple..com', 'http://', 'a.b.c.d.e/16'] as $bad) {
    ok(isset(Net::parse($bad)['error']), 'parse rejects «' . $bad . '»');
}
section('apex, parents, within');
ok(Net::apex('a.b.shop.example.co.ir') === 'example.co.ir', 'apex co.ir');
ok(Net::apex('www.example.com') === 'example.com', 'apex com');
ok(Net::parents('a.shop.example.com') === ['shop.example.com', 'example.com'], 'parents');
ok(Net::within('x.example.com', 'example.com') && !Net::within('badexample.com', 'example.com'), 'within is label-aware');
section('blocklist and public IPs');
ok(Net::blocked('domain', 'portal.mof.gov.ir') === '*.gov.ir', 'gov.ir blocked by default');
ok(Net::blocked('domain', 'example.ir') === '', 'example.ir allowed');
ok(Net::blocked('ip', '10.1.2.3', "10.0.0.0/8") === '10.0.0.0/8', 'cidr blocklist');
ok(!Net::isPublicIp('10.0.0.1') && !Net::isPublicIp('127.0.0.1') && !Net::isPublicIp('100.64.1.1') && !Net::isPublicIp('192.0.2.1') && !Net::isPublicIp('fd00::1'), 'private ranges rejected');
ok(Net::isPublicIp('8.8.8.8') && Net::isPublicIp('185.165.116.14'), 'public IPs accepted');
ok(Net::inCidr('203.0.113.7', '203.0.113.0/28') && !Net::inCidr('203.0.113.17', '203.0.113.0/28'), 'inCidr');
section('webhook SSRF guard');
dns_a('hooks.example.test', '93.184.216.34');
dns_a('internal.example.test', '10.0.0.5');
ok(Net::publicUrl('https://hooks.example.test/x')['ok'] === true, 'public webhook ok');
ok(Net::publicUrl('https://internal.example.test/x')['ok'] === false, 'webhook to a private IP refused');
ok(Net::publicUrl('https://user:pw@hooks.example.test/')['ok'] === false, 'credentials in URL refused');
ok(Net::publicUrl('https://hooks.example.test:6379/')['ok'] === false, 'odd port refused');
ok(Net::publicUrl('file:///etc/passwd')['ok'] === false, 'file scheme refused');

section('Jalali and schedules');
ok(Schedules::toGregorian(1405, 8, 20) === [2026, 11, 11], 'J 1405-08-20 = G 2026-11-11');
ok(Schedules::toGregorian(1404, 1, 1) === [2025, 3, 21], 'Nowruz 1404');
[$jy, $jm, $jd] = Text::jalali(2026, 11, 11);
ok([$jy, $jm, $jd] === [1405, 8, 20], 'G→J');
$tz = new DateTimeZone('Asia/Tehran');
$now = (new DateTimeImmutable('2026-11-11 10:00', $tz))->getTimestamp(); // Wednesday
$d = Schedules::nextRun(['id' => 0, 'freq' => 'daily', 'hour' => 3], $now);
ok((new DateTimeImmutable('@' . $d))->setTimezone($tz)->format('Y-m-d H:i') === '2026-11-12 03:00', 'daily next = tomorrow 03:00');
$w = Schedules::nextRun(['id' => 0, 'freq' => 'weekly', 'dow' => 6, 'hour' => 2], $now);
ok((new DateTimeImmutable('@' . $w))->setTimezone($tz)->format('Y-m-d H:i D') === '2026-11-14 02:00 Sat', 'weekly next Saturday');
$m = Schedules::nextRun(['id' => 0, 'freq' => 'monthly', 'dom' => 1, 'hour' => 4], $now);
ok((new DateTimeImmutable('@' . $m))->setTimezone($tz)->format('Y-m-d H:i') === '2026-11-22 04:00', 'monthly = 1 Azar 1405 (2026-11-22)');
$m2 = Schedules::nextRun(['id' => 0, 'freq' => 'monthly', 'dom' => 25, 'hour' => 4], $now);
ok((new DateTimeImmutable('@' . $m2))->setTimezone($tz)->format('Y-m-d') === '2026-11-16', 'monthly = 25 Aban (2026-11-16)');
ok(\McSec\Credits::period($now) === '1405-08', 'credit period is the Jalali month');

section('score');
ok(Score::fromCounts(Findings::emptyCounts()) === 100, 'clean = 100');
ok(Score::fromCounts(['critical' => 1] + Findings::emptyCounts()) <= 49, 'one critical caps at 49');
ok(Score::fromCounts(['high' => 1] + Findings::emptyCounts()) <= 79, 'one high caps at 79');
ok(Score::fromCounts(['low' => 50] + Findings::emptyCounts()) > Score::fromCounts(['medium' => 50] + Findings::emptyCounts()), 'lows weigh less than mediums');
ok(Score::label(95) === 'عالی' && Score::label(10) === 'بحرانی', 'labels');

section('findings helpers');
ok(Findings::severity('CRITICAL') === 'critical' && Findings::severity('moderate') === 'medium' && Findings::severity('unknown') === 'info', 'severity normalization');
ok(Findings::fingerprint(1, 'k', 'https://a.com/x?y=1') === Findings::fingerprint(1, 'K', 'http://A.com/x/'), 'fingerprint ignores scheme, case, query, trailing slash');
ok(Findings::fingerprint(1, 'k', 'a.com') !== Findings::fingerprint(2, 'k', 'a.com'), 'fingerprint per asset');

section('AI helpers');
ok(Ai::parseJson("```json\n{\"a\":1}\n```") === ['a' => 1], 'json in fences');
ok(Ai::parseJson('here: {"a":2} thanks') === ['a' => 2], 'json with text around');
ok(Ai::parseJson('nope') === null, 'no json');
$masked = Ai::mask('mail me at boss@corp.ir, call 09121234567, key sk-abcdefghijklmnopqrstu, password=hunter2');
ok(!str_contains($masked, 'boss@corp.ir') && !str_contains($masked, '09121234567') && !str_contains($masked, 'sk-abcdef') && !str_contains($masked, 'hunter2'), 'PII and secrets masked: ' . $masked);

section('crypto');
$enc = Crypto::encrypt('s3cret-ü');
ok($enc !== 's3cret-ü' && Crypto::decrypt($enc) === 's3cret-ü', 'encrypt/decrypt round trip');
ok(Crypto::decrypt('garbage') === '' && Crypto::decrypt('mcs1:g:AAAA') === '', 'bad ciphertext reads empty');
ok(preg_match('~^[2-9A-HJ-NP-Z]{8}$~', Crypto::code(8)) === 1, 'link code alphabet');

section('install is idempotent and additive');
Installer::install();
Installer::install();
ok(\WHMCS\Database\Capsule::schema()->hasTable('mod_mcsec_findings') && \WHMCS\Database\Capsule::schema()->hasColumn('mod_mcsec_assets', 'autoscan'), 'tables and columns present after reinstall');
$src = '';
foreach (glob(dirname(__DIR__) . '/modules/addons/mcsec/{,lib/,lib/*/}*.php', GLOB_BRACE) as $f) {
    // code only: comments may name the forbidden words to forbid them
    foreach (token_get_all((string) file_get_contents($f)) as $t) {
        $src .= is_array($t) ? (in_array($t[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $t[1]) : $t;
    }
}
ok(!preg_match('~->drop\(|dropIfExists|dropColumn|DROP TABLE|TRUNCATE~i', $src), 'no DROP/TRUNCATE anywhere in the module');
ok(!preg_match('~noemail~', $src), 'noemail never sent');
done();
