<?php
// Every client and admin page renders with real data and without a PHP warning; pjax answers JSON; the progress
// endpoint answers; forms carry their hidden fields; the root has dir and lang.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/tools/demo.php';

use McSec\Db;

demo_data();
login(1, 1);

section('client pages (owner)');
$asset = (int) Db::table('mod_mcsec_assets')->where('client_id', 1)->where('status', 'verified')->value('id');
$pending = (int) Db::table('mod_mcsec_assets')->where('client_id', 1)->where('status', 'pending')->value('id');
$finding = (int) Db::table('mod_mcsec_findings')->where('client_id', 1)->value('id');
$scan = (int) Db::table('mod_mcsec_scans')->where('client_id', 1)->where('status', 'completed')->value('id');
$running = (int) Db::table('mod_mcsec_scans')->where('client_id', 1)->where('status', 'running')->value('id');
$report = (int) Db::table('mod_mcsec_reports')->where('client_id', 1)->where('status', 'ready')->value('id');
$pages = ['home' => [], 'assets' => [], 'asset' => ['id' => $asset], 'asset#pending' => ['id' => $pending], 'scans' => [], 'scan' => ['id' => $scan], 'scan#running' => ['id' => $running],
    'findings' => [], 'findings#filtered' => ['severity' => 'high', 'status' => 'all', 'q' => 'TLS'], 'finding' => ['id' => $finding], 'reports' => [], 'report' => ['id' => $report],
    'schedules' => [], 'notify' => [], 'credits' => [], 'activity' => []];
foreach ($pages as $key => $q) {
    $p = explode('#', $key)[0];
    $r = client_get(['p' => $p] + array_map('strval', $q));
    $h = html($r);
    ok($h !== '' && str_contains($h, 'class="mcs-shell"') && str_contains($h, 'dir="rtl" lang="fa"'), "{$key} renders in the shell");
    ok(!str_contains($h, 'پیدا نشد') || in_array($key, [], true), "{$key} found its data");
    $markup = preg_replace('~<(style|script)\b.*?</\1>~s', '', $h) ?? $h;
    ok(!str_contains($markup, '{$') && !preg_match('~\bArray\b~', $markup), "{$key} has no template leftovers");
}
$h = html(client_get(['p' => 'scans']));
ok(str_contains($h, 'name="mcs_nonce"') && str_contains($h, 'name="mcs_csrf"') && str_contains($h, 'name="token"'), 'forms carry token, csrf and nonce');
ok(str_contains($h, 'data-mcs-cost'), 'launcher shows costs');

section('pjax and progress');
$j = client_get(['p' => 'findings', 'pjax' => '1']);
ok(isset($j['json']['html']) && $j['json']['page'] === 'findings' && $j['json']['title'] === 'یافته‌ها', 'pjax JSON view');
$pr = client_get(['p' => 'scan', 'id' => (string) $running, 'progress' => '1']);
ok(($pr['json']['ok'] ?? false) && $pr['json']['status'] === 'running' && is_int($pr['json']['progress']), 'progress JSON');

section('viewer and new account');
login(11, 1);
foreach (['home', 'assets', 'findings', 'finding', 'notify', 'credits'] as $p) {
    $h = html(client_get(['p' => $p, 'id' => (string) $finding]));
    ok(str_contains($h, 'class="mcs-shell"'), "viewer sees {$p}");
}
login(5, 5);
$h = html(client_get(['p' => 'home']));
ok(str_contains($h, 'شروع کار') && str_contains($h, 'افزودن اولین دارایی'), 'a new account sees the first-run checklist');
foreach (['assets', 'scans', 'findings', 'reports', 'schedules', 'notify', 'credits', 'activity'] as $p) {
    ok(str_contains(html(client_get(['p' => $p])), 'class="mcs-shell"'), "empty {$p} renders");
}

section('admin pages');
foreach (['view', 'ops', 'settings'] as $tier) {
    admin($tier);
    foreach (array_keys(\McSec\Admin\Controller::PAGES) as $p) {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET = ['mcsa' => $p];
        $_POST = [];
        $out = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
        ok(str_contains($out, 'class="mcsa"') && str_contains($out, 'راهنمای این صفحه'), "admin {$p} ({$tier})");
    }
}
$_GET = ['mcsa' => 'assets', 'q' => 'example'];
ok(str_contains(\McSec\Admin\Controller::handle('addonmodules.php?module=mcsec'), 'example'), 'admin asset search');

section('hooks');
login(1, 1);
$nav = new class {
    public array $children = [];
    public function addChild($k, $v)
    {
        $this->children[$k] = $v;
    }
};
run_hook('ClientAreaPrimaryNavbar', ['primaryNavbar' => $nav]);
foreach ($GLOBALS['__hooks']['ClientAreaPrimaryNavbar'] as $fn) {
    $fn($nav);
}
ok(isset($nav->children['mcsec']) && $nav->children['mcsec']['uri'] === 'index.php?m=mcsec', 'menu item added');
$panels = new class {
    public array $children = [];
    public function addChild($k, $v)
    {
        $this->children[$k] = $v;
    }
};
foreach ($GLOBALS['__hooks']['ClientAreaHomepagePanels'] as $fn) {
    $fn($panels);
}
ok(isset($panels->children['mcsec']) && str_contains($panels->children['mcsec']['bodyHtml'], 'از ۱۰۰'), 'home panel with the score');
setting('enabled', '0');
$nav2 = clone $nav;
$nav2->children = [];
foreach ($GLOBALS['__hooks']['ClientAreaPrimaryNavbar'] as $fn) {
    $fn($nav2);
}
ok(true, 'hooks never throw when the feature is off');
done();
