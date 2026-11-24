<?php
// 0.8.0 advanced mode: a customer's own scan (recipe) from allowed tools with named choices only; it is a profile like
// any other, so ownership, blocklist, credits and plan rules still apply. IDOR, CSRF/nonce, XSS, no free text to tools.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Catalog;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Recipes;
use McSec\Rules;
use McSec\Scans;
use McSec\Settings;

Clock::$fixed = strtotime('2026-11-21T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'daily_scan_cap' => '200', 'welcome_credits' => '0', 'oasm_url' => 'https://oasm.test', 'oasm_email' => 'svc@oasm.test', 'nuclei_rate' => '10'] as $k => $v) {
    setting($k, $v);
}
Settings::setSecret('oasm_password', 'svc-pass');
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
Credits::credit(1, 500, 'paid', 'topup', 'topup:adv1', 'test');
Credits::credit(2, 500, 'paid', 'topup', 'topup:adv2', 'test');
$mk = function (string $value, string $kind = 'domain', int $client = 1, string $status = 'verified'): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $client, 'kind' => $kind, 'value' => $value, 'status' => $status, 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now(), 'oasm_target' => 't-' . md5($value)]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
dns_a('shop.example', '93.184.216.80');
dns_a('other.example', '93.184.216.90');
$shop = $mk('shop.example');
$srv = $mk('93.184.216.80', 'ip');
$pending = $mk('new.example', 'domain', 1, 'pending');
$other = $mk('other.example', 'domain', 2);

$calls = [];
http_mock(function ($method, $url, $headers, $body) use (&$calls) {
    $path = (string) parse_url($url, PHP_URL_PATH) . (parse_url($url, PHP_URL_QUERY) ? '?' . parse_url($url, PHP_URL_QUERY) : '');
    $b = json_decode((string) $body, true) ?: [];
    $calls[] = [$method, $path, $b];
    if ($path === '/api/auth/sign-in/email') {
        return ['status' => 200, 'body' => '{}', 'headers' => ['set-cookie' => ['session=ok; Path=/']]];
    }
    if ($path === '/api/auth/admin/create-user') {
        return ['status' => 200, 'body' => '{"user":{"id":"u1"}}'];
    }
    if ($method === 'POST' && $path === '/api/workspaces') {
        return ['status' => 201, 'body' => '{"id":"ws-1"}'];
    }
    if ($path === '/api/workspaces/configs') {
        return ['status' => 200, 'body' => '{}'];
    }
    if ($path === '/api/targets/bulk') {
        return ['status' => 201, 'body' => json_encode(['created' => [['id' => 't-' . md5((string) $b['targets'][0]['value'])]]])];
    }
    if (preg_match('~^/api/targets/t-[0-9a-f]+$~', $path)) {
        return ['status' => 200, 'body' => '{"id":"x"}'];
    }
    if (str_starts_with($path, '/api/tools?')) {
        $data = [];
        foreach (array_keys(Catalog::TOOLS) as $n) {
            $data[] = ['id' => 'tool-' . $n, 'name' => $n, 'type' => 'connector', 'isInstalled' => true, 'hasConfigProfile' => false, 'isReady' => false, 'availableWorkersCount' => 0];
        }
        return ['status' => 200, 'body' => json_encode(['data' => $data])];
    }
    if (preg_match('~^/api/tools/tool-([a-z]+)/config-profiles~', $path)) {
        return ['status' => $method === 'POST' ? 201 : 200, 'body' => $method === 'GET' ? '[]' : '{"id":"p1"}'];
    }
    if ($method === 'POST' && $path === '/api/projects') {
        return ['status' => 201, 'body' => '{"id":"proj-1"}'];
    }
    if ($method === 'GET' && $path === '/api/projects/proj-1') {
        return ['status' => 200, 'body' => '{"id":"proj-1","projectWorkflows":[{"id":"bind-1"}]}'];
    }
    if ($method === 'POST' && str_ends_with($path, '/run')) {
        return ['status' => 201, 'body' => '{"jobHistoryId":"jh-1"}'];
    }
    return ['status' => 404, 'body' => '{}'];
});

section('off by default; plan-only when on');
ok(!Recipes::allowed(1) && !Recipes::save($who, ['name' => 'x y', 'tools' => ['nuclei']])['ok'], 'advanced mode is off until the admin turns it on');
ok(!str_contains(html(client_get(['p' => 'scans'])), 'p=recipes'), 'no link or menu entry while off');
setting('advanced_enabled', '1');
$r = Recipes::save($who, ['name' => 'بررسی من', 'tools' => ['nuclei']]);
ok(!Recipes::allowed(1) && !$r['ok'] && str_contains($r['error'], 'پلن'), 'plan-only: an account without a plan cannot build one');
ok(str_contains(html(client_get(['p' => 'recipes'])), 'برای حساب‌های دارای پلن'), 'the page says why, with a way forward');
mcsecplan_CreateAccount(['serviceid' => 801, 'userid' => 1, 'pid' => 1, 'configoption1' => '0', 'configoption2' => '20', 'configoption3' => '', 'configoption4' => '24', 'configoption5' => 'on']);
ok(Recipes::allowed(1) && !Recipes::allowed(2), 'with a plan: allowed; client 2 (no plan) still not');

section('building: allowed tools only, fixed order, named choices only');
ok(array_keys(Recipes::tools()) === ['katana', 'nmap', 'nuclei', 'zap'], 'the admin\'s default list, in pipeline order');
$r = Recipes::save($who, ['name' => 'وب کامل', 'tools' => ['zap', 'nuclei', 'katana', 'ffuf', 'rm -rf', 'acunetix'],
    'options' => ['nuclei' => ['severity' => 'high', 'speed' => 'slow', 'rateLimit' => '9999', 'templateIds' => 'x'], 'katana' => ['depth' => '9; id'], 'zap' => ['scanMode' => 'full']]]);
ok($r['ok'], 'saved');
$row = Recipes::get(1, $r['id']);
ok($row->tools === 'katana,nuclei,zap', 'unknown and not-allowed tools dropped; order fixed (crawl first, then test)');
ok(json_decode($row->options, true) === ['nuclei' => ['severity' => 'high', 'speed' => 'slow']], 'only named choices are stored; rateLimit, templateIds, a bad depth and scanMode are gone');
$p = Recipes::profile($row);
ok($p['key'] === 'u' . $r['id'] && $p['kinds'] === ['domain'] && $p['credits'] === 16 && $p['engine'] === 'oasm' && $p['enabled'], 'profile: domain only (katana), cost 4 + 6 + 6');
ok(!Recipes::save($who, ['name' => 'بد', 'tools' => ['katana', 'nmap']])['ok'], 'katana (domain) + nmap (IP) share no asset kind: refused');
ok(!Recipes::save($who, ['name' => 'بد', 'tools' => []])['ok'] && !Recipes::save($who, ['name' => '', 'tools' => ['nuclei']])['ok'], 'no tool or no name: refused');
setting('advanced_tools', 'nuclei,katana,zap,nmap,gau,ffuf,wpscan');
ok(!isset(Recipes::tools()['wpscan']), 'a tool that needs a key is hidden until the key is set');
ok(!Recipes::save($who, ['name' => 'زیاد', 'tools' => ['gau', 'katana', 'ffuf', 'nuclei', 'zap']])['ok'], 'more than 4 tools refused');
setting('advanced_tools', 'nuclei,katana,zap,nmap');
setting('advanced_max', '3');
$ip = Recipes::save($who, ['name' => 'سرور', 'tools' => ['nmap', 'nuclei'], 'options' => ['nmap' => ['ports' => '100']]]);
$x = Recipes::save($who, ['name' => 'سومی', 'tools' => ['nuclei']]);
ok($ip['ok'] && $x['ok'] && !Recipes::save($who, ['name' => 'چهارمی', 'tools' => ['nuclei']])['ok'], 'the per-account limit holds');
ok(Recipes::remove($who, $x['id'])['ok'] && !Recipes::remove($who, $x['id'])['ok'], 'removed once');

section('choices can only make a tool gentler');
$base = \McSec\Engines\Oasm::toolConfig('nuclei');
$got = Recipes::apply($base, ['severity' => ['high', 'critical'], 'rate' => 'half', 'concurrency' => 2]);
ok($got['rateLimit'] === 5 && $got['concurrency'] === 2 && $got['severity'] === ['high', 'critical'] && $got['interactsh'] === $base['interactsh'], 'half the admin\'s rate, fewer severities, the rest untouched');
ok(Recipes::apply($base, ['rateLimit' => 9999, 'concurrency' => 500, 'interactsh' => true, 'excludeTags' => []]) === $base, 'nothing can raise a rate or switch a safety off');
ok(Recipes::apply(['depth' => 3], ['depth' => 2])['depth'] === 2 && Recipes::apply(['depth' => 2], ['depth' => 3])['depth'] === 2, 'numbers only go down');

section('it is a profile: listed for its owner only, priced, and scanned through the same gate');
$mine = Catalog::forClient(1);
ok(isset($mine[$p['key']]) && $mine[$p['key']]['allowed'] && $mine[$p['key']]['credits'] === 16, 'in the owner\'s list');
ok(!isset(Catalog::forClient(2)[$p['key']]), 'not in another account\'s list');
ok(Catalog::label($p['key']) === 'وب کامل' && Catalog::label('vuln') !== 'vuln' && Catalog::label('nope') === 'nope', 'labels resolve for built-in and custom scans');
$before = Credits::balance(1)['total'];
$q = Scans::queue(1, $shop, $p['key'], 0, 1);
ok($q['ok'] && $q['credits'] === 16 && Credits::balance(1)['total'] === $before - 16, 'queued: 16 credits taken');
ok(!Scans::queue(1, $pending, $p['key'], 0, 1)['ok'], 'an unverified asset is refused as always');
ok(!Scans::queue(1, $srv, $p['key'], 0, 1)['ok'], 'an IP is refused for a domain-only scan');
$who2 = login(2, 2);
$steal = Scans::queue(2, $other, $p['key'], 0, 2);
ok(!$steal['ok'] && Credits::balance(2)['total'] === 500, 'IDOR: another account cannot run someone else\'s scan (even on its own asset)');
ok(Recipes::get(2, $r['id']) === null && !Recipes::remove($who2, $r['id'])['ok'] && !Recipes::save($who2, ['id' => $r['id'], 'name' => 'دزدی', 'tools' => ['nuclei']])['ok'], 'IDOR: cannot read, remove or change it either');
$who = login(1, 1);
Rules::save(['scope' => 'client', 'target' => 1, 'spend_pct' => 50]);
ok(Catalog::forClient(1)[$p['key']]['credits'] === 8, 'the account\'s price rule applies to custom scans too');
Rules::disable((int) Db::table('mod_mcsec_rules')->where('enabled', 1)->value('id'));
setting('blocklist', 'shop.example');
$q2 = Scans::queue(1, $shop, 'u' . $ip['id'], 0, 1);
ok(!$q2['ok'], 'the blocklist still wins');
setting('blocklist', '');

section('the pipeline OASM gets: fixed order, MC-Sec settings plus the named choices');
Scans::dispatch(microtime(true) + 20);
$proj = null;
foreach ($calls as $c) {
    if ($c[0] === 'POST' && $c[1] === '/api/projects') {
        $proj = $c[2];
    }
}
$tools = $proj['tools'] ?? [];
ok(count($tools) === 3 && array_column($tools, 'toolId') === ['tool-katana', 'tool-nuclei', 'tool-zap'] && array_column($tools, 'stage') === [1, 2, 3], 'three stages in order');
$nu = $tools[1]['config'] ?? [];
ok(($nu['rateLimit'] ?? 0) === 5 && ($nu['severity'] ?? []) === ['high', 'critical'] && ($nu['concurrency'] ?? 0) === 2 && ($nu['interactsh'] ?? null) === false, 'nuclei: half rate, high and critical only, no out-of-band probes');
ok(($tools[2]['config']['scanMode'] ?? '') === 'baseline' && !isset($nu['templateIds']), 'zap stays in baseline mode; nothing typed reached a tool');
$scan = Db::table('mod_mcsec_scans')->where('id', $q['scan_id'])->first();
ok($scan->status === 'running' && json_decode($scan->backend_meta, true)['tools'] === ['katana', 'nuclei', 'zap'], 'the scan runs and remembers its tools (it collects only their findings)');

section('removed or no longer allowed: no new scans, old ones keep their name');
setting('advanced_tools', 'nuclei,katana');
ok(Catalog::get($p['key']) === null && !isset(Catalog::forClient(1)[$p['key']]), 'the admin removed ZAP from the list: this scan cannot start any more');
ok(Catalog::find($p['key'])['label'] === 'وب کامل', 'but its scans still show their name');
ok(str_contains(html(client_get(['p' => 'recipes'])), 'یکی از ابزارها در دسترس نیست'), 'and the page says why');
setting('advanced_tools', 'nuclei,katana,zap,nmap');
Recipes::remove($who, $ip['id']);
ok(Catalog::get('u' . $ip['id']) === null && Catalog::label('u' . $ip['id']) === 'سرور', 'a removed scan: gone for new scans, named in history');
mcsecplan_TerminateAccount(['serviceid' => 801, 'userid' => 1, 'pid' => 1]);
ok(!Recipes::allowed(1) && Catalog::get($p['key']) === null, 'without the plan the custom scan stops');
mcsecplan_CreateAccount(['serviceid' => 802, 'userid' => 1, 'pid' => 1, 'configoption1' => '0', 'configoption2' => '20', 'configoption3' => '', 'configoption4' => '24', 'configoption5' => 'on']);

section('client area: page, CSRF, nonce, permissions, XSS');
$page = html(client_get(['p' => 'recipes']));
ok(str_contains($page, 'این بخش چه کار می‌کند؟') && str_contains($page, 'name="tools[]"') && str_contains($page, 'name="opt[nuclei][severity]"') && str_contains($page, 'وب کامل'), 'the page lists my scans and the builder');
ok(!str_contains($page, 'value="acunetix"') && !str_contains($page, 'value="ffuf"'), 'tools the admin did not allow are not offered');
ok(str_contains(html(client_get(['p' => 'scans'])), 'p=recipes') && str_contains(html(client_get(['p' => 'scans'])), 'value="' . $p['key'] . '"'), 'the launcher offers the custom scan and links to the builder');
$n = Db::table('mod_mcsec_recipes')->count();
$_SERVER['REQUEST_METHOD'] = 'POST';
$_GET = ['m' => 'mcsec'];
$_POST = ['a' => 'recipe_save', 'p' => 'recipes', 'name' => 'بی توکن', 'tools' => ['nuclei'], 'token' => 'whmcs-token', 'mcs_csrf' => 'wrong', 'mcs_nonce' => \McSec\Nonce::issue(1, 1, 'form')];
\McSec\Client\Controller::handle();
client_post('recipe_save', ['p' => 'recipes', 'name' => 'بی nonce', 'tools' => ['nuclei']], [], false);
ok(Db::table('mod_mcsec_recipes')->count() === $n, 'wrong CSRF or no nonce: nothing saved');
$r3 = client_post('recipe_save', ['p' => 'recipes', 'name' => '<script>alert(9)</script>', 'tools' => ['nuclei', ['x']], 'opt' => ['nuclei' => ['severity' => ['a' => 'b'], 'speed' => 'slow']]]);
ok(str_contains((string) ($r3['redirect'] ?? ''), 'p=recipes&saved='), 'saved through the form (odd shapes in the request are ignored)');
$page = html(client_get(['p' => 'recipes']));
ok(!str_contains($page, '<script>alert(9)') && str_contains($page, 'alert(9)'), 'a hostile name is shown as text');
ok(!str_contains(html(client_get(['p' => 'scans'])), '<script>alert(9)'), 'in the launcher too');
$newId = (int) Db::table('mod_mcsec_recipes')->max('id');
ok(str_contains(html(client_get(['p' => 'recipes', 'edit' => (string) $newId])), 'ذخیره‌ی تغییرها'), 'edit form prefilled');
login(2, 2);
ok(!str_contains(html(client_get(['p' => 'recipes', 'edit' => (string) $r['id']])), 'وب کامل'), 'IDOR: another account sees nothing of it, even with ?edit=');
client_post('recipe_remove', ['p' => 'recipes', 'id' => (string) $r['id']]);
ok(Recipes::get(1, $r['id']) !== null, 'IDOR: nor can it remove it through the form');
login(11, 1); // viewer
$n = Db::table('mod_mcsec_recipes')->count();
client_post('recipe_save', ['p' => 'recipes', 'name' => 'بیننده', 'tools' => ['nuclei']]);
ok(Db::table('mod_mcsec_recipes')->count() === $n && !str_contains(html(client_get(['p' => 'recipes'])), 'name="tools[]"'), 'a viewer can look but not build');
login(1, 1, true); // masquerading admin
client_post('recipe_remove', ['p' => 'recipes', 'id' => (string) $r['id']]);
ok(Recipes::get(1, $r['id']) !== null, '«ورود به‌جای مشتری» changes nothing');
done();
