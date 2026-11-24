<?php
// 0.16.0 a wide catalogue that stays easy: scan types in categories, ready-made bundles, several types in one go.
// The cost is the sum, taken once per scan; a type that is not for an asset's kind is left out; nothing a customer
// sends can run a type that is off, not in the plan or another account's. Heavy and untried tools ship switched off.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Catalog;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Engines\Oasm;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'daily_scan_cap' => '500', 'welcome_credits' => '0', 'oasm_url' => 'https://oasm.test', 'oasm_email' => 'svc@oasm.test'] as $k => $v) {
    setting($k, $v);
}
\McSec\Settings::setSecret('oasm_password', 'pw');
$who = login(1, 1);
Accounts::ensure(1);
Accounts::update(1, ['terms_at' => Clock::now()]);
Credits::credit(1, 100, 'paid', 'topup', 'topup:c1', 'test');
$mk = fn (string $v, string $kind = 'domain') => Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 1, 'kind' => $kind, 'value' => $v, 'status' => 'verified', 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
$dom = $mk('shop.example');
$ip = $mk('93.184.216.40', 'ip');
[$dom2, $dom3, $dom4, $dom5] = [$mk('two.example'), $mk('three.example'), $mk('four.example'), $mk('five.example')];
foreach (['two', 'three', 'four', 'five'] as $d) {
    dns_a($d . '.example', '93.184.216.35');
}
dns_a('shop.example', '93.184.216.34');
$bal = fn () => Credits::balance(1)['total'];
$scans = fn () => Db::rows(Db::table('mod_mcsec_scans')->where('client_id', 1)->orderBy('id'));
$start = fn (array $p) => client_post('scan_start', $p, ['p' => 'scans']);

section('the catalogue');
$all = Catalog::all(true);
ok(count($all) >= 25, 'both engines and every tool: ' . count($all) . ' scan types');
$bad = array_filter($all, fn ($p) => !isset(Catalog::CATEGORIES[$p['cat'] ?? '']) || ($p['desc'] ?? '') === '' || ($p['eta'] ?? '') === '' || !$p['kinds']);
ok(!$bad, 'every type has a category, a description, a duration and asset kinds');
$toolsOk = true;
foreach ($all as $p) {
    foreach ((array) ($p['tools'] ?? []) as $t) {
        $toolsOk = $toolsOk && isset(Catalog::TOOLS[$t]) && array_intersect($p['kinds'], Catalog::TOOLS[$t]['kinds']) === $p['kinds'];
    }
}
ok($toolsOk, 'every tool of a type is a known tool that accepts the type\'s asset kinds');
$on = Catalog::all();
$heavyOn = array_filter($on, fn ($p, $k) => !in_array($k, ['services', 'services_quick'], true) && Catalog::risk($p) === 'heavy', ARRAY_FILTER_USE_BOTH);
ok(!$heavyOn, 'no new heavy type is on by itself');
ok(!array_filter($on, fn ($p) => $p['engine'] === 'osmedeus') && !array_filter($on, fn ($p) => array_intersect((array) ($p['tools'] ?? []), ['nikto', 'rustscan', 'ffuf', 'dirsearch', 'arjun', 'acunetix', 'wpscan'])), 'Osmedeus flows and untried or keyed tools wait for the admin');
ok(isset($on['vuln_quick'], $on['web_quick'], $on['services_quick'], $on['full_web']) && (int) $on['vuln_quick']['credits'] < (int) $on['vuln']['credits'], 'the gentler variants of tools already in use are on, and cheaper');
$g = Catalog::grouped(Catalog::forClient(1));
ok(array_keys($g) === array_values(array_intersect(array_keys(Catalog::CATEGORIES), array_keys($g))) && isset($g['start']['hygiene'], $g['vuln']['vuln'], $g['web']['web'], $g['server']['services']), 'grouped in the order of the categories');

section('gentler settings reach the engine and only ever lower');
$cfg = fn (string $key, string $tool) => \McSec\Recipes::apply(Oasm::toolConfig($tool), (array) (Catalog::find($key)['options'][$tool] ?? []));
ok($cfg('vuln_quick', 'nuclei')['severity'] === ['high', 'critical'] && count($cfg('vuln', 'nuclei')['severity']) === 5, 'the quick vulnerability scan asks only for high and critical');
ok($cfg('web_quick', 'katana')['depth'] === 1 && $cfg('web', 'katana')['depth'] === 3 && $cfg('services_quick', 'nmap')['topPorts'] === 100, 'the quick web scan crawls one level; the quick port scan checks 100 ports');
setting('tool_configs', '{"nmap":{"topPorts":50}}');
ok($cfg('services_quick', 'nmap')['topPorts'] === 50, 'a profile option never raises what the admin set lower');
setting('tool_configs', '{}');

section('the chooser stays short');
$h = html(client_get(['p' => 'scans']));
ok(str_contains($h, 'name="bundles[]" value="b_standard"') && str_contains($h, 'پیشنهاد ما') && substr_count($h, 'name="bundles[]" value=') === 3, 'three ready-made picks come first, one marked as ours');
ok(preg_match('~name="bundles\[\]" value="b_standard"[^>]* checked~', $h) === 1 && !preg_match('~name="profiles\[\]"[^>]* checked~', $h), 'the standard pick is already chosen: one click starts');
ok(str_contains($h, '<details class="mcs-drawer mcs-allscans">') && str_contains($h, 'انتخاب دقیق‌تر'), 'everything else is behind one click, closed');
ok(str_contains($h, 'شناسایی و سطح حمله') && str_contains($h, 'وب‌سایت و برنامه‌ی وب') && str_contains($h, 'سرور و شبکه') && str_contains($h, 'name="profiles[]" value="vuln_quick"'), 'inside: the categories with their types as tick boxes');
ok(!str_contains($h, 'value="osm_extensive"') && !str_contains($h, 'value="content"'), 'types that are off are not shown');
ok(str_contains($h, '۸ اعتبار') && str_contains($h, 'data-mcs-bundle="hygiene,surface,vuln"'), 'a bundle shows the sum of its types (0 + 2 + 6)');
$h = html(client_get(['p' => 'scans', 'profile' => 'web']));
ok(str_contains($h, '<details class="mcs-drawer mcs-allscans" open>') && preg_match('~name="profiles\[\]" value="web"[^>]* checked~', $h) === 1 && !preg_match('~name="bundles\[\]"[^>]* checked~', $h), 'a link to one type opens the list with it ticked and no bundle');

section('several at once');
$b0 = $bal();
$r = $start(['assets' => [$dom], 'bundles' => ['b_standard']]);
$s = $scans();
ok(count($s) === 3 && array_map(fn ($x) => $x->profile, $s) === ['hygiene', 'surface', 'vuln'] && $bal() === $b0 - 8, 'the standard bundle: three scans in order, 8 credits');
ok(str_contains(flash_of($r), '۳ اسکن در صف قرار گرفت') && str_contains(flash_of($r), '۸ اعتبار'), 'the message says how many and what it cost');
$b1 = $bal();
$r = $start(['assets' => [$dom2], 'bundles' => ['b_standard'], 'profiles' => ['vuln', 'vuln_quick']]);
ok(count($scans()) === 7 && $bal() === $b1 - 11, 'a type ticked twice (bundle and list) runs once: 4 scans, 0+2+6+3 credits');
$b2 = $bal();
$n = count($scans());
$r = $start(['assets' => [$dom, $ip], 'profiles' => ['web_quick', 'services_quick']]);
$new = array_slice($scans(), $n);
ok(count($new) === 2 && $bal() === $b2 - 7 && [(int) $new[0]->asset_id, $new[0]->profile] === [$dom, 'web_quick'] && [(int) $new[1]->asset_id, $new[1]->profile] === [$ip, 'services_quick'], 'two kinds of asset: each gets only the scans made for it');
$n = count($scans());
$r = $start(['assets' => [$dom], 'profiles' => ['services_quick']]);
ok(count($scans()) === $n && str_contains(flash_of($r), 'برای دامنه اجرا نمی‌شود'), 'one type on the wrong kind of asset: refused with a reason');
$n = count($scans());
$b4 = $bal();
$start(['assets' => [$dom2], 'bundles' => ['b_standard']]);
ok(count($scans()) === $n && $bal() === $b4, 'asking again while the same scans are still waiting starts nothing new and costs nothing');
$r = $start(['assets' => [$dom]]);
ok(count($scans()) === $n && str_contains(flash_of($r), 'نوع اسکن را انتخاب کنید'), 'nothing chosen: nothing queued');
$r = $start(['assets' => [$dom3], 'profile' => 'hygiene']);
ok(count($scans()) === $n + 1 && str_contains((string) ($r['redirect'] ?? ''), 'p=scan&id='), 'the old single-type form still works and goes to the scan');

section('what cannot be chosen');
$n = count($scans());
$b3 = $bal();
$start(['assets' => [$dom], 'profiles' => ['osm_extensive', 'content', 'pro', 'nope', 'u999', '../x'], 'bundles' => ['b_nope', ['x']]]);
ok(count($scans()) === $n && $bal() === $b3, 'types that are off, unknown or another account\'s cannot be sent in');
Db::table('mod_mcsec_wallets')->where('client_id', 1)->update(['paid' => 4, 'monthly' => 0]);
$n = count($scans());
$r = $start(['assets' => [$dom4], 'bundles' => ['b_standard']]);
ok(count($scans()) === $n + 2 && $bal() === 2 && str_contains(flash_of($r), 'اعتبار کافی نیست'), 'credits run out part way: what could be paid is queued, the rest is refused, the balance never goes below zero');
login(11, 1);
$n = count($scans());
$start(['assets' => [$dom5], 'bundles' => ['b_quick']]);
ok(count($scans()) === $n, 'a viewer cannot start scans');
login(1, 1);
$n = count($scans());
client_post('scan_start', ['assets' => [$dom5], 'bundles' => ['b_quick']], ['p' => 'scans'], false);
ok(count($scans()) === $n, 'no nonce: nothing');

section('the admin can open more');
admin('settings');
$over = [];
foreach (Catalog::all(true) as $k => $p) {
    $over[$k] = ['enabled' => $p['enabled'] || $k === 'content', 'free' => $p['free'], 'credits' => $p['credits'], 'label' => ''];
}
setting('profiles', json_encode($over));
ok(isset(Catalog::all()['content']) && str_contains(html(client_get(['p' => 'scans'])), 'name="profiles[]" value="content"') && str_contains(html(client_get(['p' => 'scans'])), 'درخواست زیاد به هدف'), 'a type the admin switches on appears in its category, with the heavy-load warning');
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['module' => 'mcsec', 'mcsa' => 'pricing'];
$_POST = [];
$h = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(str_contains($h, 'osm_extensive') && str_contains($h, 'ports_all') && str_contains($h, 'وب‌سایت و برنامه‌ی وب'), 'the pricing page lists every type with its category');

done();
