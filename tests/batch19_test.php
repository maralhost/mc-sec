<?php
// 0.19.0: Nuclei by topic (the connector's own `tags`), a schedule that runs a bundle, «رفع کردم، همه را دوباره بسنج»,
// a free check after a site changed, and an outage alert that says whether the CDN or the server is down.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Catalog;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Engines\Oasm;
use McSec\Findings;
use McSec\Monitor;
use McSec\Recipes;
use McSec\Schedules;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'daily_scan_cap' => '500', 'welcome_credits' => '0', 'oasm_url' => 'https://oasm.test', 'oasm_email' => 'svc@oasm.test', 'retest_daily_cap' => '3'] as $k => $v) {
    setting($k, $v);
}
\McSec\Settings::setSecret('oasm_password', 'pw');
$who = login(1, 1);
Accounts::ensure(1);
Accounts::update(1, ['terms_at' => Clock::now()]);
Credits::credit(1, 100, 'paid', 'topup', 'topup:b19', 'test');
$mk = fn (string $v, string $kind = 'domain', array $x = []) => Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 1, 'kind' => $kind, 'value' => $v, 'status' => 'verified', 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now()] + $x);
$scans = fn () => Db::rows(Db::table('mod_mcsec_scans')->where('client_id', 1)->orderBy('id'));
$bal = fn () => Credits::balance(1)['total'];

section('Nuclei by topic');
$cfg = fn (string $key) => Recipes::apply(Oasm::toolConfig('nuclei'), (array) (Catalog::find($key)['options']['nuclei'] ?? []));
ok($cfg('nuclei_cve')['tags'] === ['cve'] && $cfg('nuclei_panels')['tags'] === ['panel', 'login', 'default-login'] && !isset($cfg('vuln')['tags']), 'a topic scan sends its tags; the full scan sends none');
ok(isset(Catalog::all()['nuclei_cve'], Catalog::all()['nuclei_exposure'], Catalog::all()['nuclei_misconfig'], Catalog::all()['nuclei_takeover']) && (int) Catalog::all()['nuclei_cve']['credits'] < (int) Catalog::all()['vuln']['credits'], 'the topic scans are on, each cheaper than the full scan');
setting('nuclei_exclude_tags', 'cve,dos');
ok(!isset($cfg('nuclei_cve')['tags']) || !in_array('cve', $cfg('nuclei_cve')['tags'], true), 'a tag the admin excluded is never asked for');
setting('nuclei_exclude_tags', 'dos');
ok(Recipes::apply(['excludeTags' => []], ['tags' => ['cve', 'bad tag!', '../x', 'rce']])['tags'] === ['cve', 'rce'], 'only plain tag names pass');

section('a schedule that runs a bundle');
$dom = $mk('shop.example');
dns_a('shop.example', '93.184.216.34');
$h = html(client_get(['p' => 'schedules']));
ok(str_contains(html(client_get(['p' => 'scans'])), 'name="profiles[]" value="nuclei_cve"'), 'the topic scans are offered in the chooser');
ok(str_contains($h, '<option value="b_standard"') && str_contains($h, 'بسته‌ی «بررسی استاندارد»'), 'the schedule form offers the bundles');
$r = Schedules::save($who, ['asset' => $dom, 'profile' => 'b_standard', 'freq' => 'weekly', 'dow' => 6, 'hour' => 3]);
ok($r['ok'], 'a bundle can be scheduled');
ok(!Schedules::save($who, ['asset' => $dom, 'profile' => 'b_nope', 'freq' => 'weekly'])['ok'], 'an unknown bundle cannot');
ok(str_contains(html(client_get(['p' => 'schedules'])), 'بررسی استاندارد'), 'the list names it');
Db::table('mod_mcsec_schedules')->where('id', $r['id'])->update(['next_run_at' => Clock::now() - 60]);
$b0 = $bal();
$out = Schedules::due(microtime(true) + 20);
$s = $scans();
ok($out['queued'] === 3 && array_map(fn ($x) => $x->profile, $s) === ['hygiene', 'surface', 'vuln'] && $bal() === $b0 - 8 && (int) $s[0]->schedule_id === (int) $r['id'], 'when due, every scan of the bundle is queued, at the sum of their costs');
Db::table('mod_mcsec_schedules')->where('id', $r['id'])->update(['next_run_at' => Clock::now() - 60]);
Db::table('mod_mcsec_wallets')->where('client_id', 1)->update(['paid' => 1, 'monthly' => 0]);
Db::table('mod_mcsec_scans')->where('client_id', 1)->update(['status' => 'completed']);
$out = Schedules::due(microtime(true) + 20);
ok($out['paused'] === 1 && Db::table('mod_mcsec_schedules')->where('id', $r['id'])->value('status') === 'paused' && $bal() >= 0, 'without credits the schedule pauses once, and the balance stays above zero');
Db::table('mod_mcsec_wallets')->where('client_id', 1)->update(['paid' => 100]);

section('re-check everything that is open');
$ip = $mk('93.184.216.40', 'ip');
$fnd = fn (int $asset, string $profile, string $key) => Db::table('mod_mcsec_findings')->insertGetId(['client_id' => 1, 'asset_id' => $asset, 'fp' => sha1($asset . $key), 'engine' => 'builtin', 'profile' => $profile, 'source_key' => $key, 'title' => $key, 'severity' => 'medium', 'status' => 'open', 'location' => 'x', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
$fnd($dom, 'hygiene', 'a');
$fnd($dom, 'hygiene', 'b');
$fnd($dom, 'vuln', 'c');
$fnd($ip, 'services', 'd');
Db::table('mod_mcsec_findings')->insert(['client_id' => 2, 'asset_id' => 999, 'fp' => sha1('z'), 'engine' => 'builtin', 'profile' => 'hygiene', 'source_key' => 'z', 'title' => 'z', 'severity' => 'high', 'status' => 'open', 'location' => 'x']);
Db::table('mod_mcsec_scans')->where('client_id', 1)->update(['status' => 'completed']);
$h = html(client_get(['p' => 'findings']));
ok(str_contains($h, 'value="findings_retest_all"') && str_contains($h, 'رفع کردم، همه را دوباره بسنج'), 'the open list has the button');
ok(!str_contains(html(client_get(['p' => 'findings', 'status' => 'fixed'])), 'value="findings_retest_all"'), 'the fixed list does not');
$n = count($scans());
$b1 = $bal();
$r = client_post('findings_retest_all', [], ['p' => 'findings']);
$new = array_slice($scans(), $n);
ok(count($new) === 3 && $bal() === $b1 && str_contains(flash_of($r), '۳ بررسی دوباره‌ی رایگان'), 'one free scan per asset and scan type that has open findings (3), not one per finding (4)');
ok(!array_filter($new, fn ($x) => (int) $x->credits !== 0) && !Db::table('mod_mcsec_scans')->where('client_id', 2)->exists(), 'nothing is charged, and nothing is queued for another account');
$r = client_post('findings_retest_all', [], ['p' => 'findings']);
ok(count($scans()) === $n + 3 && str_contains(flash_of($r), 'امروز یک بار'), 'once a day for the whole account');
Db::table('mod_mcsec_hits')->where('k', 'like', 'retest%')->delete();
Db::table('mod_mcsec_scans')->where('client_id', 1)->update(['status' => 'completed']);
setting('retest_daily_cap', '2');
$r = client_post('findings_retest_all', [], ['p' => 'findings']);
ok(count($scans()) === $n + 5 && str_contains(flash_of($r), '۱ مورد به سقف امروز خورد'), 'the daily allowance of free re-checks counts each scan');
Db::table('mod_mcsec_hits')->where('k', 'like', 'retest%')->delete();
$n = count($scans());
ok(str_contains(flash_of(client_post('findings_retest_all', [], ['p' => 'findings'], false)), 'یک بار') && str_contains(flash_of(client_post('findings_retest_all', ['mcs_csrf' => 'bad'], ['p' => 'findings'])), 'منقضی') && count($scans()) === $n, 'nonce and CSRF');
login(11, 1);
ok(str_contains(flash_of(client_post('findings_retest_all', [], ['p' => 'findings'])), 'فقط اجازه‌ی دیدن') && !str_contains(html(client_get(['p' => 'findings'])), 'value="findings_retest_all"') && count($scans()) === $n, 'a viewer neither sees nor uses it');
login(1, 1);

section('CDN or server? and a check after a change');
setting('monitor_enabled', '1');
setting('monitor_minutes', '5');
setting('cdn_origin_scan', '1');
$origin = $mk('93.184.216.70', 'ip');
$site = $mk('cdn-site.example', 'domain', ['origin_id' => $origin, 'origin_ok_at' => Clock::now(), 'mon_status' => 'up', 'mon_at' => 0, 'mon_since' => Clock::now() - 9000]);
Db::table('mod_mcsec_assets')->where('id', '!=', $site)->update(['mon_at' => Clock::now() + 86400]);
dns_a('cdn-site.example', '93.184.216.91');
$state = ['edge' => false, 'origin' => true];
http_mock(function ($m, $url, $h, $b, $opt = []) use (&$state) {
    $pin = (string) ($opt['resolve'] ?? '');
    $up = str_ends_with($pin, ':93.184.216.70') ? $state['origin'] : $state['edge'];
    return $up ? ['status' => 200, 'body' => 'ok'] : ['status' => 0, 'error' => 'Connection refused', 'body' => ''];
});
$pass = function () use ($site) {
    Db::table('mod_mcsec_assets')->where('id', $site)->update(['mon_at' => 0]);
    return Monitor::due(microtime(true) + 20);
};
$pass();
$pass();
$row = Db::table('mod_mcsec_assets')->where('id', $site)->first();
$n = Db::table('mod_mcsec_notices')->where('client_id', 1)->where('event', 'site_down')->orderByDesc('id')->first();
ok($row->mon_status === 'down' && $n && str_contains((string) $n->body, 'سرور خودتان جواب می‌دهد'), 'the CDN is down and the server answers: the alert says so');
ok(str_contains((string) Monitor::status($row)[2], 'سرور خودتان جواب می‌دهد'), 'and so does the status on the pages');
$state['origin'] = false;
$pass();
ok(str_contains((string) Monitor::status(Db::table('mod_mcsec_assets')->where('id', $site)->first())[2], 'سرور خودتان هم جواب نمی‌دهد'), 'the server down too: said plainly');
$n0 = Db::table('mod_mcsec_scans')->where('asset_id', $site)->count();
$state = ['edge' => true, 'origin' => true];
$pass();
ok(Db::table('mod_mcsec_scans')->where('asset_id', $site)->count() === $n0, 'back up, with «check after a change» off (the default): no scan starts by itself');
setting('auto_rescan', '1');
$state['edge'] = false;
$pass();
$pass();
$state['edge'] = true;
$b2 = $bal();
$out = $pass();
$q = Db::table('mod_mcsec_scans')->where('asset_id', $site)->orderByDesc('id')->first();
ok(($out['rescans'] ?? 0) === 1 && $q && $q->profile === 'hygiene' && (int) $q->credits === 0 && $bal() === $b2, 'on: when the site comes back, one free basic check is queued');
$GLOBALS['__dns']['cdn-site.example']['A'] = [['ip' => '93.184.216.92']];
Db::table('mod_mcsec_scans')->where('asset_id', $site)->update(['status' => 'completed']);
$out = $pass();
ok(($out['rescans'] ?? 0) === 0 && Db::table('mod_mcsec_scans')->where('asset_id', $site)->count() === $n0 + 1, 'at most one a day per site, even when the address changes too');
Db::table('mod_mcsec_hits')->where('k', 'like', 'rescan:%')->delete();
$GLOBALS['__dns']['cdn-site.example']['A'] = [['ip' => '93.184.216.93']];
$out = $pass();
ok(($out['rescans'] ?? 0) === 1, 'a changed address is a reason by itself');
$over = [];
foreach (Catalog::all(true) as $k => $p) {
    $over[$k] = ['enabled' => $p['enabled'], 'free' => $p['free'], 'credits' => $k === 'hygiene' ? 2 : $p['credits'], 'label' => ''];
}
setting('profiles', json_encode($over));
Db::table('mod_mcsec_hits')->where('k', 'like', 'rescan:%')->delete();
Db::table('mod_mcsec_scans')->where('asset_id', $site)->update(['status' => 'completed']);
$GLOBALS['__dns']['cdn-site.example']['A'] = [['ip' => '93.184.216.94']];
$b3 = $bal();
$out = $pass();
ok(($out['rescans'] ?? 0) === 0 && $bal() === $b3, 'if the basic check is not free, nothing is ever started or spent without the customer');

done();
