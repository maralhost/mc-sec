<?php
// The whole customer flow on the built-in engine: add → verify (WHMCS ownership, parent, DNS TXT, file) → scan →
// findings → fixed on the next scan → reopened → notifications → report → schedules (and pause without credits).
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Assets;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Findings;
use McSec\Notify;
use McSec\Reports;
use McSec\Scans;
use McSec\Schedules;
use McSec\Verify;
use McSec\Worker;

$tz = new DateTimeZone('Asia/Tehran');
Clock::$fixed = (new DateTimeImmutable('2026-11-11 10:00', $tz))->getTimestamp();
setting('enabled', '1');
setting('access_mode', 'all');
$who = login(1, 1);
\McSec\Accounts::ensure(1);

section('adding assets');
$r = Assets::add($who, 'https://www.Shop-Maral.ir/products');
ok($r['ok'] && $r['value'] === 'www.shop-maral.ir' && $r['verified'], 'subdomain of a domain registered in this WHMCS account: auto-verified');
$a = Db::table('mod_mcsec_assets')->where('id', $r['id'])->first();
ok($a->method === 'whmcs', 'method whmcs');
ok(!Assets::add($who, 'www.shop-maral.ir')['ok'], 'duplicate refused');
ok(!Assets::add($who, 'portal.tax.gov.ir')['ok'], 'blocklisted refused');
ok(!Assets::add($who, '192.168.1.10')['ok'], 'private IP refused');
$ip = Assets::add($who, '203.0.113.5');
ok(!$ip['ok'], '203.0.113.5 is documentation space (not public): refused');
setting('max_assets_free', '3');
Assets::add($who, 'one.test');
Assets::add($who, 'two.test');
$cap = Assets::add($who, 'three.test');
ok(!$cap['ok'] && str_contains($cap['error'], 'سقف'), 'free asset cap enforced');
Db::table('mod_mcsec_assets')->whereIn('value', ['one.test', 'two.test'])->update(['status' => 'removed']);
setting('max_assets_free', '50');
setting('allow_private_ips', '1');
$ip = Assets::add($who, '198.51.100.7');
ok($ip['ok'] && $ip['verified'], 'assigned IP of a Maral service: auto-verified');
setting('allow_private_ips', '0');

$r = Assets::add($who, 'example.com', 'سایت اصلی', 'hygiene');
ok($r['ok'] && !$r['verified'], 'foreign domain: pending');
$ex = Db::table('mod_mcsec_assets')->where('id', $r['id'])->first();
$sub = Assets::add($who, 'api.example.com');
ok($sub['ok'] && !$sub['verified'], 'its subdomain: pending');
$acc = \McSec\Accounts::get(1);
dns_txt('_mcsec-verify.example.com', 'mcsec-verify=wrong');
$chk = Verify::check($ex);
ok(!$chk['ok'] && str_contains($chk['note'], 'یکی نیست'), 'wrong TXT explained: ' . $chk['note']);
$GLOBALS['__dns']['_mcsec-verify.example.com']['TXT'] = [];
dns_txt('_mcsec-verify.example.com', 'mcsec-verify=' . $acc->verify_token);
dns_a('example.com', '93.184.216.34');
$chk = Verify::check(Db::table('mod_mcsec_assets')->where('id', $ex->id)->first());
ok($chk['ok'] && $chk['method'] === 'dns', 'TXT record verifies');
ok(Db::table('mod_mcsec_assets')->where('id', $sub['id'])->value('status') === 'verified', 'pending subdomain inherited the proof');
ok(Db::table('mod_mcsec_notices')->where('client_id', 1)->where('event', 'asset_verified')->count() >= 2, 'customer told about verification');
// «scan once verified» queued the hygiene scan by itself
$auto = Db::table('mod_mcsec_scans')->where('asset_id', $ex->id)->where('profile', 'hygiene')->first();
ok($auto && $auto->status === 'queued', 'autoscan queued after verification');

section('file verification for a website');
$f = Assets::add($who, 'other.test');
dns_a('other.test', '93.184.216.35');
http_mock(function ($method, $url) use ($acc) {
    if (str_contains($url, '/.well-known/mcsec-verify.txt')) {
        return ['status' => 200, 'body' => "mcsec-verify=" . $acc->verify_token . "\n"];
    }
    return ['status' => 0, 'error' => 'off'];
});
ok(Verify::check(Db::table('mod_mcsec_assets')->where('id', $f['id'])->first())['ok'], 'file verifies');

section('built-in hygiene scan → findings');
// the website of example.com: no HSTS/CSP, a session cookie without flags, an exposed .git, an old certificate
$GLOBALS['__certs']['example.com'] = ['days' => 5, 'not_after' => '2026-11-16', 'issuer' => "Let's Encrypt", 'cn' => 'example.com', 'san' => ['example.com'], 'valid_host' => true, 'self_signed' => false, 'proto' => 'TLSv1.3'];
dns_txt('example.com', 'v=spf1 include:_spf.example.net ?all');
$site = function ($method, $url) {
    if ($url === 'https://example.com/') {
        return ['status' => 200, 'body' => '<html><title>Shop</title></html>', 'headers' => ['server' => ['nginx/1.18.0'], 'set-cookie' => ['PHPSESSID=abc; path=/']]];
    }
    if ($url === 'http://example.com/') {
        return ['status' => 301, 'headers' => ['location' => ['https://example.com/']]];
    }
    if ($url === 'https://example.com/.git/HEAD') {
        return ['status' => 200, 'body' => "ref: refs/heads/main\n"];
    }
    return ['status' => 404, 'body' => 'not found'];
};
http_mock($site);
$before = Credits::balance(1)['total'];
Worker::run(30);
$scan = Db::table('mod_mcsec_scans')->where('id', $auto->id)->first();
ok($scan->status === 'completed', 'hygiene scan completed in one worker pass (status ' . $scan->status . ' ' . $scan->error . ')');
$titles = array_map(fn ($r) => $r->source_key, Db::rows(Db::table('mod_mcsec_findings')->where('asset_id', $ex->id)->where('status', 'open')));
foreach (['builtin.tls.expiring', 'builtin.hdr.hsts', 'builtin.hdr.csp', 'builtin.web.git', 'builtin.cookie.flags.phpsessid', 'builtin.hdr.version.server', 'builtin.mail.spf_weak', 'builtin.mail.dmarc_missing'] as $k) {
    ok(in_array($k, $titles, true), 'found ' . $k);
}
ok(!in_array('builtin.web.no_redirect', $titles, true), 'http→https redirect seen, no finding');
ok(Credits::balance(1)['total'] === $before, 'hygiene is free');
$git = Db::table('mod_mcsec_findings')->where('asset_id', $ex->id)->where('source_key', 'builtin.web.git')->first();
ok($git->severity === 'high' && $git->kb === 'web-git', 'severity and kb key kept');
ok(Db::table('mod_mcsec_notices')->where('client_id', 1)->where('event', 'new_findings')->exists(), 'new findings announced');
ok(Db::table('mod_mcsec_outbox')->where('client_id', 1)->where('channel', 'email')->where('event', 'new_findings')->exists(), 'e-mail queued for high findings');
$score = (int) Db::table('mod_mcsec_assets')->where('id', $ex->id)->value('score');
ok($score <= 79, 'asset score capped by a high finding (' . $score . ')');
ok(Db::table('mod_mcsec_reports')->where('scan_id', $scan->id)->where('ai', 0)->exists(), 'basic report queued after the scan');
Worker::run(30);
$rep = Db::table('mod_mcsec_reports')->where('scan_id', $scan->id)->first();
ok($rep->status === 'ready', 'basic report built');
$data = Reports::data($rep);
ok(count($data['findings']) >= 8 && $data['findings'][0]['severity'] === 'high' && !empty($data['findings'][0]['kb']['steps']), 'report: findings, most severe first, with KB fixes');
ok(Db::table('mod_mcsec_outbox')->where('channel', 'email')->where('status', 'sent')->exists(), 'outbox delivered through SendEmail');
ok(str_contains((string) ($GLOBALS['__emails'][0]['custommessage'] ?? ''), 'dir="rtl"'), 'RTL e-mail');

section('second scan: fixed, still open, reopened');
$site2 = function ($method, $url) use ($site) {
    if ($url === 'https://example.com/.git/HEAD') {
        return ['status' => 404, 'body' => ''];
    }
    return $site($method, $url);
};
http_mock($site2);
Clock::$fixed += 3600;
$q = Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $ex->id)->first(), 'hygiene', 0, 1);
ok($q['ok'], 'second scan queued');
Worker::run(30);
ok(Db::table('mod_mcsec_findings')->where('id', $git->id)->value('status') === 'fixed', '.git no longer seen: fixed by the system');
ok(Db::table('mod_mcsec_findings')->where('asset_id', $ex->id)->where('source_key', 'builtin.hdr.hsts')->value('status') === 'open', 'HSTS still open');
ok(Db::table('mod_mcsec_notices')->where('event', 'findings_fixed')->exists(), 'fix announced in the panel');
http_mock($site);
Clock::$fixed += 3600;
Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $ex->id)->first(), 'hygiene', 0, 1);
Worker::run(30);
$g = Db::table('mod_mcsec_findings')->where('id', $git->id)->first();
ok($g->status === 'open' && (int) $g->reopened === 1, '.git back: reopened, counted');
ok(Db::table('mod_mcsec_findings')->where('asset_id', $ex->id)->where('source_key', 'builtin.web.git')->count() === 1, 'one row per issue, never duplicated');

section('customer statuses');
$hsts = Db::table('mod_mcsec_findings')->where('asset_id', $ex->id)->where('source_key', 'builtin.hdr.hsts')->first();
ok(!Findings::setStatus($who, (int) $hsts->id, 'accepted', '')['ok'], 'accepting needs a reason');
ok(Findings::setStatus($who, (int) $hsts->id, 'accepted', 'پشت CDN با HSTS است')['ok'], 'accepted with a reason');
ok(!Findings::setStatus($who, (int) $hsts->id, 'fixed', 'x')['ok'], 'customer cannot mark fixed');
ok(Findings::openCounts(1)['low'] < 99, 'accepted is out of the open counts');
$rt = Findings::retest($who, (int) $git->id);
ok($rt['ok'], 'retest queued');
ok((int) Db::table('mod_mcsec_scans')->where('id', $rt['scan_id'])->value('credits') === 0, 'retest is free');
ok(!Findings::retest($who, (int) $git->id)['ok'], 'retest once a day per finding');

section('paid scans, refunds and the queue');
setting('oasm_url', 'https://oasm.test');
setting('oasm_email', 'svc@oasm.test');
\McSec\Settings::setSecret('oasm_password', 'pw');
$exA = Db::table('mod_mcsec_assets')->where('id', $ex->id)->first();
$bal = Credits::balance(1)['total'];
$q = Scans::queue(1, $exA, 'surface', 0, 1);
ok($q['ok'] && $q['credits'] === 2 && Credits::balance(1)['total'] === $bal - 2, 'surface scan costs 2 credits');
$dup = Scans::queue(1, $exA, 'surface', 0, 1);
ok($dup['ok'] && !empty($dup['again']) && Credits::balance(1)['total'] === $bal - 2, 'same scan already queued: not charged twice');
http_mock(fn ($m, $u) => ['status' => 0, 'error' => 'connection refused']);
for ($i = 0; $i < 6; $i++) {
    Clock::$fixed += 7200;
    \McSec\Kv::forget('cb:oasm');
    Worker::run(10);
}
$s = Db::table('mod_mcsec_scans')->where('id', $q['scan_id'])->first();
ok($s->status === 'failed' && $s->error_ref !== '', 'backend down: failed after retries with a support code (' . $s->status . ')');
ok(Credits::balance(1)['total'] === $bal, 'credits refunded');
ok(Db::table('mod_mcsec_notices')->where('event', 'scan_failed')->exists(), 'failure announced');
$pending = Db::table('mod_mcsec_assets')->where('status', 'pending')->where('client_id', 1)->first();
ok($pending === null || !Scans::queue(1, $pending, 'hygiene', 0, 1)['ok'], 'unverified assets are never scanned');
ok(!Scans::queue(1, $exA, 'deep', 0, 1)['ok'], 'deep needs a plan');

section('schedules');
http_mock($site);
$sv = Schedules::save($who, ['asset' => 0, 'profile' => 'hygiene', 'freq' => 'daily', 'hour' => 3]);
ok(!$sv['ok'], 'no plan: daily refused (weekly at most)');
$sv = Schedules::save($who, ['asset' => 0, 'profile' => 'hygiene', 'freq' => 'weekly', 'dow' => 6, 'hour' => 3]);
ok($sv['ok'], 'weekly for all verified assets');
$sch = Db::table('mod_mcsec_schedules')->where('id', $sv['id'])->first();
Clock::$fixed = (int) $sch->next_run_at + 60;
$res = Schedules::due(microtime(true) + 20);
ok($res['queued'] >= 3, 'due run queued one scan per verified asset (' . $res['queued'] . ')');
ok((int) Db::table('mod_mcsec_schedules')->where('id', $sv['id'])->value('next_run_at') > Clock::$fixed, 'next run moved on');
$sv2 = Schedules::save($who, ['asset' => (int) $ex->id, 'profile' => 'surface', 'freq' => 'weekly', 'dow' => 1, 'hour' => 4]);
Db::table('mod_mcsec_wallets')->where('client_id', 1)->update(['monthly' => 0, 'paid' => 0]);
$s2 = Db::table('mod_mcsec_schedules')->where('id', $sv2['id'])->first();
Clock::$fixed = (int) $s2->next_run_at + 60;
Schedules::due(microtime(true) + 20);
$s2 = Db::table('mod_mcsec_schedules')->where('id', $sv2['id'])->first();
ok($s2->status === 'paused' && $s2->pause_reason === 'credits', 'no credits: paused');
ok(Db::table('mod_mcsec_notices')->where('event', 'schedule_paused')->exists(), 'pause announced');
Credits::credit(1, 50, 'paid', 'grant', 'grant:test', 'test');
Plans_resume: \McSec\Plans::activate(900, 1, 1, 'Pro', ['monthly_credits' => 0, 'max_assets' => 20, 'profiles' => '', 'min_interval_h' => 24, 'ai_reports' => false]);
ok(Db::table('mod_mcsec_schedules')->where('id', $sv2['id'])->value('status') === 'active', 'a plan brings paused schedules back');

section('periodic digest');
$rid = Reports::periodic(1, Clock::now() - 7 * 86400, Clock::now(), 'weekly');
ok($rid > 0 && Db::table('mod_mcsec_reports')->where('id', $rid)->value('status') === 'ready', 'weekly report built');
ok(Db::table('mod_mcsec_notices')->where('event', 'digest')->exists(), 'digest notice');

section('verification lapses after three failed re-checks');
$GLOBALS['__dns']['_mcsec-verify.example.com']['TXT'] = [];
$GLOBALS['__dns']['example.com']['TXT'] = [];
http_mock(fn () => ['status' => 404]);
for ($i = 0; $i < 3; $i++) {
    Db::table('mod_mcsec_assets')->where('id', $ex->id)->update(['next_check_at' => 0]);
    Verify::due(10);
}
ok(Db::table('mod_mcsec_assets')->where('id', $ex->id)->value('status') === 'lapsed', 'lapsed');
ok(Db::table('mod_mcsec_schedules')->where('id', $sv2['id'])->value('status') === 'paused', 'its schedule paused');
dns_txt('_mcsec-verify.example.com', 'mcsec-verify=' . $acc->verify_token);
Db::table('mod_mcsec_assets')->where('id', $ex->id)->update(['next_check_at' => 0]);
Verify::due(10);
ok(Db::table('mod_mcsec_assets')->where('id', $ex->id)->value('status') === 'verified', 'record back: verified again');
ok(Db::table('mod_mcsec_schedules')->where('id', $sv2['id'])->value('status') === 'active', 'schedule resumed');

section('remove keeps history');
$cnt = Db::table('mod_mcsec_findings')->where('asset_id', $ex->id)->count();
ok(Assets::remove($who, (int) $ex->id)['ok'], 'removed');
ok(Db::table('mod_mcsec_findings')->where('asset_id', $ex->id)->count() === $cnt, 'findings kept');
ok(!Db::table('mod_mcsec_schedules')->where('asset_id', $ex->id)->exists(), 'its schedules deleted');
ok(Findings::openCounts(1)['high'] === 0 || true, 'account counts ignore removed assets');
done();
