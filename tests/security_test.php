<?php
// Security of the client and admin paths: IDOR across accounts, CSRF and WHMCS token, one-time nonce, XSS in every
// customer-controlled field, viewer permission, "Login as Owner" read-only, access gating, admin tiers, secrets.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Assets;
use McSec\Auth;
use McSec\Clock;
use McSec\Db;
use McSec\Settings;

Clock::$fixed = strtotime('2026-11-11T10:00:00Z');
setting('enabled', '1');
setting('access_mode', 'all');
$xss = '<script>alert(9)</script>';

// client 2 owns an asset, a finding, a scan and a report
$who2 = login(2, 2);
\McSec\Accounts::ensure(2);
$a2 = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 2, 'kind' => 'domain', 'value' => 'secret-two.test', 'label' => $xss, 'status' => 'verified', 'method' => 'dns', 'created_at' => Clock::now()]);
$s2 = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 2, 'asset_id' => $a2, 'profile' => 'hygiene', 'engine' => 'builtin', 'status' => 'completed', 'queued_at' => Clock::now()]);
$f2 = Db::table('mod_mcsec_findings')->insertGetId(['client_id' => 2, 'asset_id' => $a2, 'fp' => sha1('x'), 'engine' => 'builtin', 'title' => 'Two ' . $xss, 'severity' => 'high', 'location' => 'https://secret-two.test/' . $xss,
    'description' => $xss, 'evidence' => $xss, 'status' => 'open', 'first_scan_id' => $s2, 'last_scan_id' => $s2, 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
$r2 = Db::table('mod_mcsec_reports')->insertGetId(['client_id' => 2, 'kind' => 'account', 'title' => 'R2', 'status' => 'ready', 'data' => '{}', 'created_at' => Clock::now()]);

section('IDOR: client 1 cannot see or touch client 2');
login(1, 1);
foreach ([['asset', $a2], ['finding', $f2], ['scan', $s2], ['report', $r2]] as [$p, $id]) {
    $h = html(client_get(['p' => $p, 'id' => (string) $id]));
    ok(!str_contains($h, 'secret-two') && !str_contains($h, 'R2') && str_contains($h, 'پیدا نشد'), "GET {$p} of another account shows «not found»");
}
$pr = client_get(['p' => 'scan', 'id' => (string) $s2, 'progress' => '1']);
ok(($pr['json']['ok'] ?? true) === false, 'progress JSON of another account refused');
client_post('asset_remove', ['asset' => (string) $a2]);
ok(Db::table('mod_mcsec_assets')->where('id', $a2)->value('status') === 'verified', 'cannot remove another account\'s asset');
client_post('finding_status', ['finding' => (string) $f2, 'status' => 'accepted', 'note' => 'hijack attempt']);
ok(Db::table('mod_mcsec_findings')->where('id', $f2)->value('status') === 'open', 'cannot change another account\'s finding');
client_post('scan_start', ['asset' => (string) $a2, 'profile' => 'hygiene', 'terms' => '1']);
ok(Db::table('mod_mcsec_scans')->where('asset_id', $a2)->where('client_id', 1)->count() === 0 && Db::table('mod_mcsec_scans')->where('asset_id', $a2)->count() === 1, 'cannot scan another account\'s asset');
client_post('schedule_save', ['asset' => (string) $a2, 'profile' => 'hygiene', 'freq' => 'weekly', 'dow' => '6', 'hour' => '3']);
ok(!Db::table('mod_mcsec_schedules')->where('asset_id', $a2)->exists(), 'cannot schedule another account\'s asset');
client_post('report_create', ['kind' => 'asset', 'asset' => (string) $a2]);
ok(!Db::table('mod_mcsec_reports')->where('client_id', 1)->where('asset_id', $a2)->exists(), 'cannot report on another account\'s asset');

section('CSRF, WHMCS token, nonce');
$_SERVER['REQUEST_METHOD'] = 'POST';
$_GET = ['m' => 'mcsec', 'p' => 'assets'];
$_POST = ['a' => 'add_asset', 'targets' => 'csrf.example.com', 'token' => 'whmcs-token'];
$r = \McSec\Client\Controller::handle();
ok(!Db::table('mod_mcsec_assets')->where('value', 'csrf.example.com')->exists() && str_contains(flash_of($r), 'منقضی'), 'no module CSRF token: refused');
$_POST = ['a' => 'add_asset', 'targets' => 'csrf.example.com', 'mcs_csrf' => Auth::csrf()];
\McSec\Client\Controller::handle();
ok(!Db::table('mod_mcsec_assets')->where('value', 'csrf.example.com')->exists(), 'no WHMCS token: refused');
$n = \McSec\Nonce::issue(1, 1, 'form');
client_post('add_asset', ['targets' => 'nonce-one.example.com', 'mcs_nonce' => $n], ['p' => 'assets']);
client_post('add_asset', ['targets' => 'nonce-two.example.com', 'mcs_nonce' => $n], ['p' => 'assets']);
ok(Db::table('mod_mcsec_assets')->where('value', 'nonce-one.example.com')->exists() && !Db::table('mod_mcsec_assets')->where('value', 'nonce-two.example.com')->exists(), 'a nonce works once');
$n2 = \McSec\Nonce::issue(2, 2, 'form');
client_post('add_asset', ['targets' => 'stolen-nonce.example.com', 'mcs_nonce' => $n2], ['p' => 'assets']);
ok(!Db::table('mod_mcsec_assets')->where('value', 'stolen-nonce.example.com')->exists(), 'another person\'s nonce refused');
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['m' => 'mcsec', 'p' => 'assets', 'a' => 'add_asset', 'targets' => 'get.example.com'];
$_POST = [];
\McSec\Client\Controller::handle();
ok(!Db::table('mod_mcsec_assets')->where('value', 'get.example.com')->exists(), 'GET never changes anything');

section('XSS: customer-controlled text is escaped everywhere');
login(2, 2);
foreach (['assets' => [], 'asset' => ['id' => (string) $a2], 'findings' => [], 'finding' => ['id' => (string) $f2], 'home' => [], 'scans' => [], 'activity' => []] as $p => $q) {
    $h = html(client_get(['p' => $p] + $q));
    ok(!str_contains($h, $xss) && !preg_match('~<script>alert~i', $h), "page {$p} escapes stored script");
}
Db::table('mod_mcsec_notices')->insert(['client_id' => 2, 'event' => 'digest', 'title' => $xss, 'body' => $xss, 'link' => 'javascript:alert(1)', 'ref' => 'xss:1', 'created_at' => Clock::now()]);
$h = html(client_get(['p' => 'notify']));
ok(!str_contains($h, $xss), 'notices escaped');
$r = client_post('add_asset', ['targets' => 'label.example.com', 'label' => $xss], ['p' => 'assets']);
$h = html(client_get(['p' => 'assets']));
ok(!str_contains($h, $xss), 'label escaped in the list');

section('viewer permission and Login as Owner');
login(11, 1); // products only
$h = html(client_get(['p' => 'assets']));
ok(str_contains($h, 'دارایی') && !str_contains($h, 'name="targets"'), 'viewer sees the list without the add form');
$r = client_post('add_asset', ['targets' => 'viewer.example.com'], ['p' => 'assets']);
ok(!Db::table('mod_mcsec_assets')->where('value', 'viewer.example.com')->exists() && str_contains(flash_of($r), 'اجازه'), 'viewer cannot add');
login(12, 1); // manageproducts
client_post('add_asset', ['targets' => 'manager.example.com'], ['p' => 'assets']);
ok(Db::table('mod_mcsec_assets')->where('value', 'manager.example.com')->exists(), 'a user with manageproducts can add');
$r = client_post('buy_pack', ['pack' => 'p50'], ['p' => 'credits']);
ok(str_contains(flash_of($r), 'فاکتور'), 'but cannot buy credit without the invoices permission');
login(1, 1, true);
$r = client_post('add_asset', ['targets' => 'masq.example.com'], ['p' => 'assets']);
ok(!Db::table('mod_mcsec_assets')->where('value', 'masq.example.com')->exists(), 'Login as Owner: read-only by default');
setting('masq_actions', '1');
client_post('add_asset', ['targets' => 'masq.example.com'], ['p' => 'assets']);
ok(Db::table('mod_mcsec_assets')->where('value', 'masq.example.com')->value('created_by') == 1, 'allowed when the setting is on');
setting('masq_actions', '0');

section('access gating');
setting('access_mode', 'list');
setting('access_clients', '2');
login(1, 1);
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'هنوز برای حساب شما باز نشده') && !str_contains($h, 'class="mcs-shell"'), 'account outside the trial list sees only a notice');
setting('enabled', '0');
login(2, 2);
ok(str_contains(html(client_get(['p' => 'home'])), 'باز نشده'), 'feature off: closed for everyone');
setting('enabled', '1');
setting('access_mode', 'all');

section('admin tiers and secrets');
admin('view');
$_SERVER['REQUEST_METHOD'] = 'POST';
$_GET = ['mcsa' => 'settings'];
$_POST = ['mcsa_act' => 'save_settings', 'mcsa_csrf' => Auth::csrf(), 'set_menu_label' => 'hacked'];
$out = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(Settings::get('menu_label') !== 'hacked' && str_contains($out, 'اجازه'), 'view tier cannot save settings');
admin('ops');
$_POST = ['mcsa_act' => 'grant', 'mcsa_csrf' => Auth::csrf(), 'grant_client' => '2', 'grant_amount' => '25', 'grant_bucket' => 'paid', 'grant_note' => 'جبران'];
\McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(\McSec\Credits::balance(2)['paid'] >= 25, 'ops can grant credits');
$_POST = ['mcsa_act' => 'grant', 'mcsa_csrf' => 'bad', 'grant_client' => '2', 'grant_amount' => '1000'];
\McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(\McSec\Credits::balance(2)['paid'] < 1000, 'bad CSRF: no grant');
admin('settings');
$_POST = ['mcsa_act' => 'save_engines', 'mcsa_csrf' => Auth::csrf(), 'set_oasm_url' => 'https://oasm.example', 'set_oasm_password' => 'top-secret-pw'];
\McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(Settings::secret('oasm_password') === 'top-secret-pw' && !str_contains(Settings::get('oasm_password'), 'top-secret'), 'secret stored encrypted');
$_SERVER['REQUEST_METHOD'] = 'GET';
$_POST = [];
$_GET = ['mcsa' => 'setup'];
$page = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(!str_contains($page, 'top-secret-pw'), 'secret never shown back');
$_POST = ['mcsa_act' => 'save_engines', 'mcsa_csrf' => Auth::csrf(), 'set_oasm_password' => ''];
$_SERVER['REQUEST_METHOD'] = 'POST';
\McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(Settings::secret('oasm_password') === 'top-secret-pw', 'empty field keeps the stored secret');
$_POST = ['mcsa_act' => 'save_engines', 'mcsa_csrf' => Auth::csrf(), 'set_oasm_url' => 'javascript:alert(1)'];
$out = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(Settings::get('oasm_url') === 'https://oasm.example', 'engine URL must be http(s)');
\McSec\Trace::error('engine', 'x', 'login failed', ['password' => 'p@ss', 'nested' => ['api_key' => 'k', 'ok' => 'v']]);
$d = (string) Db::table('mod_mcsec_log')->orderByDesc('id')->value('detail');
ok(!str_contains($d, 'p@ss') && !str_contains($d, '"k"') && str_contains($d, '[hidden]'), 'secrets scrubbed from the technical log');
done();
