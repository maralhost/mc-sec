<?php
// 0.4.0: scan types as data (multi-tool OASM pipelines), tool settings and secrets, admin-built scan types, each
// profile owning its own tools' findings, and one finding per issue across a domain and its subdomain assets.
// OASM shapes are the ones read live on staging (v0.12.1, 2026-11-21). No network: Http::$mock only.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Assets;
use McSec\Catalog;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Engines\Oasm;
use McSec\Findings;
use McSec\Scans;
use McSec\Settings;

Clock::$fixed = strtotime('2026-11-21T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'daily_scan_cap' => '200', 'oasm_url' => 'https://oasm.test', 'oasm_email' => 'svc@oasm.test'] as $k => $v) {
    setting($k, $v);
}
Settings::setSecret('oasm_password', 'svc-pass');
$who = login(1, 1);
Accounts::ensure(1);
Credits::credit(1, 500, 'paid', 'topup', 'topup:pl', 'test');
$mk = function (string $value, string $kind = 'domain', int $client = 1): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $client, 'kind' => $kind, 'value' => $value, 'status' => 'verified', 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now(), 'oasm_target' => 't-' . md5($value)]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
dns_a('shop.example', '93.184.216.80');
$shop = $mk('shop.example');
$srv = $mk('93.184.216.80', 'ip');

$calls = [];
$st = ['installed' => ['nuclei' => true], 'profiles' => [], 'projects' => 0, 'status' => 'in_progress', 'vulns' => []];
http_mock(function ($method, $url, $headers, $body) use (&$calls, &$st) {
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
            $data[] = ['id' => 'tool-' . $n, 'name' => $n, 'type' => 'connector', 'isInstalled' => !empty($st['installed'][$n]), 'hasConfigProfile' => isset($st['profiles'][$n]),
                'isReady' => !empty($st['installed'][$n]) && isset($st['profiles'][$n]), 'availableWorkersCount' => 0];
        }
        return ['status' => 200, 'body' => json_encode(['data' => $data])];
    }
    if ($method === 'POST' && $path === '/api/tools/install') {
        $st['installed'][substr((string) $b['toolId'], 5)] = true;
        return ['status' => 201, 'body' => '{}'];
    }
    if (preg_match('~^/api/tools/tool-([a-z]+)/config-profiles(?:/(\w+))?$~', $path, $m)) {
        if ($method === 'GET') {
            return ['status' => 200, 'body' => json_encode(isset($st['profiles'][$m[1]]) ? [['id' => 'p' . $m[1], 'name' => 'MC-Sec', 'config' => $st['profiles'][$m[1]]]] : [])];
        }
        $st['profiles'][$m[1]] = $b['config'];
        return ['status' => $method === 'POST' ? 201 : 200, 'body' => '{"id":"p' . $m[1] . '"}'];
    }
    if ($method === 'POST' && $path === '/api/projects') {
        $st['projects']++;
        return ['status' => 201, 'body' => json_encode(['id' => 'proj-' . $st['projects']])];
    }
    if ($method === 'GET' && preg_match('~^/api/projects/(proj-\d+)$~', $path, $m)) {
        return ['status' => 200, 'body' => json_encode(['id' => $m[1], 'projectWorkflows' => [['id' => 'bind-' . $m[1]]]])];
    }
    if ($method === 'POST' && preg_match('~^/api/projects/(proj-\d+)/workflows/bind-proj-\d+/run$~', $path, $m)) {
        return ['status' => 201, 'body' => json_encode(['jobHistoryId' => 'jh-' . $m[1] . '-' . count($calls)])];
    }
    if ($method === 'POST' && preg_match('~^/api/projects/proj-\d+/archive$~', $path)) {
        return ['status' => 201, 'body' => '{}'];
    }
    if ($method === 'GET' && preg_match('~^/api/projects/(proj-\d+)/runs~', $path)) {
        $runs = [];
        foreach ($calls as $i => $c) {
            if ($c[0] === 'POST' && str_ends_with($c[1], '/run')) {
                $runs[] = ['id' => 'jh-' . explode('/', $c[1])[3] . '-' . ($i + 1), 'status' => $st['status'], 'isCompleted' => $st['status'] !== 'in_progress', 'stepsTotal' => 2,
                    'stepsDone' => $st['status'] === 'completed' ? 2 : 1, 'stepsFailed' => 0];
            }
        }
        return ['status' => 200, 'body' => json_encode(['data' => $runs])];
    }
    if (str_starts_with($path, '/api/assets?')) {
        return ['status' => 200, 'body' => '{"data":[{"id":"s1","value":"web.test:443","port":443}],"hasNextPage":false}']; // the scanner reached a service
    }
    if (str_starts_with($path, '/api/vulnerabilities?')) {
        return ['status' => 200, 'body' => json_encode(['data' => $st['vulns'], 'hasNextPage' => false])];
    }
    if (str_starts_with($path, '/api/jobs-registry')) {
        return ['status' => 200, 'body' => '{"data":[{"status":"completed","category":"vulnerabilities"}]}']; // the run really had a job
    }
    return ['status' => 404, 'body' => '{"message":"not mocked ' . $path . '"}'];
});
$posted = function (string $path) use (&$calls): array {
    return array_values(array_filter($calls, fn ($c) => $c[0] === 'POST' && $c[1] === $path));
};
$run = function (object $asset, string $profile) use ($who): object {
    Clock::$fixed += 120;
    $q = Scans::queue((int) $asset->client_id, Db::table('mod_mcsec_assets')->where('id', $asset->id)->first(), $profile, 0, $who['user_id']);
    if (empty($q['ok'])) {
        return (object) ['status' => 'refused', 'error' => (string) ($q['error'] ?? ''), 'id' => 0, 'summary' => ''];
    }
    Scans::dispatch(microtime(true) + 10);
    return Db::table('mod_mcsec_scans')->where('id', $q['scan_id'])->first();
};
$finish = function (object $scan) use (&$st): object {
    $st['status'] = 'completed';
    Clock::$fixed += 120;
    Scans::pollRunning(microtime(true) + 10);
    $st['status'] = 'in_progress';
    return Db::table('mod_mcsec_scans')->where('id', $scan->id)->first();
};

section('catalogue: scan types are data');
$all = Catalog::all(true);
ok(($all['vuln']['tools'] ?? []) === ['nuclei'] && ($all['web']['tools'] ?? []) === ['katana', 'zap'] && $all['web']['kinds'] === ['domain'], 'vulnerability and web scans are tool lists');
ok($all['services']['kinds'] === ['ip', 'cidr'] && Catalog::risk($all['services']) === 'heavy', 'the Nmap scan takes IPs only (ports are probed only on the account\'s own addresses)');
ok(Catalog::get('pro') === null && Catalog::get('wordpress') === null && Catalog::get('urls') === null && Catalog::get('web') !== null, 'key-needing and not-yet-readable types are off by default');
foreach ($all as $k => $p) {
    foreach ((array) ($p['tools'] ?? []) as $t) {
        if (!isset(Catalog::TOOLS[$t]) || array_diff($p['kinds'], Catalog::TOOLS[$t]['kinds'])) {
            ok(false, "profile {$k}: tool {$t} unknown or does not accept every kind of the profile");
        }
    }
}
ok(Catalog::risk($all['web']) === 'light' && Catalog::risk($all['hygiene']) === '', 'risk class from the tools');

section('a two-tool pipeline (web: katana then zap)');
$s = $run($shop, 'web');
ok($s->status === 'running', 'started (' . $s->status . ' ' . ($s->error ?? '') . ')');
ok(count($posted('/api/tools/install')) === 2 && isset($st['profiles']['katana'], $st['profiles']['zap']), 'both tools installed and given a config profile in the client workspace');
$proj = $posted('/api/projects')[0][2];
ok(count($proj['tools']) === 2 && $proj['tools'][0]['toolId'] === 'tool-katana' && $proj['tools'][0]['stage'] === 1 && $proj['tools'][0]['category'] === 'url_discovery' && $proj['tools'][0]['input'] === ['host']
    && $proj['tools'][1]['toolId'] === 'tool-zap' && $proj['tools'][1]['stage'] === 2 && $proj['tools'][1]['category'] === 'vulnerabilities', 'steps in order, with OASM\'s own category and input of each tool');
ok($proj['tools'][1]['config']['scanMode'] === 'baseline' && $proj['tools'][0]['config']['rateLimit'] === 10, 'gentle settings: ZAP baseline (no active attack), katana at 10 requests a second');
$meta = json_decode((string) $s->backend_meta, true);
ok($meta['kind'] === 'pipeline' && $meta['tools'] === ['katana', 'zap'], 'the scan remembers its tools');
$p = (new Oasm())->poll($s, $shop, Catalog::get('web'));
ok($p['status'] === 'running' && str_contains($p['stage'], 'Katana') && str_contains($p['stage'], 'گام 2 از 2'), 'progress names the tools and the step (' . $p['stage'] . ')');

section('each scan type owns the findings of its own tools');
$st['vulns'] = [
    ['name' => 'Absence of Anti-CSRF Tokens', 'severity' => 'medium', 'affectedUrl' => 'http://shop.example/cart', 'tool' => ['name' => 'zap'], 'cveId' => []],
    ['name' => 'SQL Injection', 'severity' => 'critical', 'affectedUrl' => 'http://shop.example/item', 'tool' => ['name' => 'acunetix'], 'cveId' => []],
    ['name' => 'Git Config Exposure', 'severity' => 'medium', 'affectedUrl' => 'http://shop.example/.git/config', 'tool' => ['name' => 'nuclei'], 'cveId' => []],
];
$s = $finish($s);
$keys = fn (int $assetId) => array_map(fn ($r) => $r->source_key . ':' . $r->profile . ':' . $r->status, Db::rows(Db::table('mod_mcsec_findings')->where('asset_id', $assetId)->orderBy('id')));
ok($s->status === 'completed' && $keys((int) $shop->id) === ['oasm.absence-of-anti-csrf-tokens:web:open'], 'the web scan took ZAP\'s finding only (' . implode(' | ', $keys((int) $shop->id)) . ')');
$v = $finish($run($shop, 'vuln'));
ok($v->status === 'completed' && in_array('oasm.git-config-exposure:vuln:open', $keys((int) $shop->id), true) && count($keys((int) $shop->id)) === 2, 'the vulnerability scan took nuclei\'s; nothing duplicated');
$st['vulns'] = [$st['vulns'][0]];
$v = $finish($run($shop, 'vuln'));
ok(in_array('oasm.git-config-exposure:vuln:fixed', $keys((int) $shop->id), true) && in_array('oasm.absence-of-anti-csrf-tokens:web:open', $keys((int) $shop->id), true), 'nuclei no longer sees its finding: fixed; ZAP\'s finding is untouched by a nuclei scan');

section('tools that need a key');
setting('profiles', json_encode(['pro' => ['enabled' => true, 'free' => true]]));
$bal = Credits::balance(1)['total'];
$s = $run($shop, 'pro');
ok($s->status === 'failed' && $s->error_ref !== '' && Credits::balance(1)['total'] === $bal, 'Acunetix without a key: refused at once, credits back (' . $s->status . ')');
ok(!array_filter($calls, fn ($c) => $c[0] === 'POST' && $c[1] === '/api/tools/tool-acunetix/config-profiles'), 'nothing was sent to OASM for it');
setting('acunetix_url', 'https://acx.test:3443/');
Settings::setSecret('acunetix_key', 'KEY-ONE');
setting('acunetix_verify_tls', '0');
$calls = [];
$s = $run($shop, 'pro');
ok($s->status === 'running' && ($st['profiles']['acunetix']['apiKey'] ?? '') === 'KEY-ONE' && $st['profiles']['acunetix']['url'] === 'https://acx.test:3443' && $st['profiles']['acunetix']['disableTlsChecks'] === true, 'with a key: the secret goes into the workspace\'s tool profile');
$proj = $posted('/api/projects')[0][2];
ok(!str_contains((string) json_encode($proj), 'KEY-ONE') && !isset($proj['tools'][0]['config']['apiKey']), 'the pipeline itself carries no secret');
ok(!str_contains((string) Db::table('mod_mcsec_scans')->where('id', $s->id)->value('backend_meta'), 'KEY-ONE') && !Db::table('mod_mcsec_log')->where('detail', 'like', '%KEY-ONE%')->exists(), 'nor do the scan row or the log');
$finish($s);
Settings::setSecret('acunetix_key', 'KEY-TWO');
$calls = [];
$s = $run($shop, 'pro');
ok(($st['profiles']['acunetix']['apiKey'] ?? '') === 'KEY-TWO' && (bool) array_filter($calls, fn ($c) => $c[0] === 'PATCH' && $c[1] === '/api/tools/tool-acunetix/config-profiles/pacunetix'), 'a rotated key reaches the workspace at the next scan');
$finish($s);
$calls = [];
$finish($run($shop, 'pro'));
ok(!array_filter($calls, fn ($c) => str_contains($c[1], '/config-profiles') && $c[0] !== 'GET'), 'unchanged settings: the profile is not written again');

section('scope still rules');
$r = Scans::queue(1, $shop, 'services', 0, 1);
ok(!$r['ok'] && str_contains($r['error'], 'دامنه'), 'the Nmap scan is refused for a domain');
$s = $run($srv, 'services');
ok($s->status === 'running', 'and runs on the account\'s own IP');
$finish($s);
setting('blocklist', Settings::get('blocklist') . "\nshop.example");
ok(!Scans::queue(1, $shop, 'web', 0, 1)['ok'], 'a blocked asset is refused for every scan type');
setting('blocklist', "*.gov.ir");

section('admin: tool settings');
setting('tool_configs', json_encode(['zap' => ['maxSpiderDuration' => 12, 'apiKey' => 'x', 'proxy' => 'http://evil', 'bad key!' => 1], 'nuclei' => ['rateLimit' => 3]]));
$z = Oasm::toolConfig('zap');
ok($z['maxSpiderDuration'] === 12 && $z['scanMode'] === 'baseline' && !isset($z['apiKey'], $z['proxy'], $z['bad key!']), 'single keys can be tuned; secrets, proxies and odd keys are ignored');
setting('tool_configs', '{}');

section('admin: scan types built from tools');
admin('settings');
$post = function (string $act, array $data, bool $csrf = true): string {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = ['module' => 'mcsec', 'mcsa' => 'pricing'];
    $_POST = $data + ['mcsa_act' => $act, 'mcsa_csrf' => $csrf ? \McSec\Auth::csrf() : 'bad'];
    return \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
};
$form = ['cp_key' => 'Web Full!', 'cp_label' => 'وب کامل <script>alert(9)</script>', 'cp_tools' => 'katana, nuclei ,zap, rm -rf', 'cp_credits' => '۱۵', 'cp_free' => '1', 'cp_enabled' => '1'];
ok(str_contains($post('save_custom', $form, false), 'منقضی') && Catalog::custom() === [], 'CSRF: refused');
admin('ops');
$post('save_custom', $form);
ok(Catalog::custom() === [], 'an ops-level admin cannot add scan types');
admin('settings');
$h = $post('save_custom', $form);
$c = Catalog::custom()['c_webfull'] ?? null;
ok($c !== null && $c['tools'] === ['katana', 'nuclei', 'zap'] && $c['kinds'] === ['domain'] && $c['credits'] === 15 && $c['engine'] === 'oasm', 'saved: key cleaned, unknown tools dropped, Persian digits read, kinds = what every tool accepts');
ok(!str_contains($h, '<script>alert(9)') && str_contains($h, 'c_webfull'), 'the name is escaped on the page');
ok(isset(Catalog::forClient(1, 'domain')['c_webfull']) && !isset(Catalog::forClient(1, 'ip')['c_webfull']), 'customers see it for domains only');
ok(str_contains($post('save_custom', ['cp_key' => 'mix', 'cp_label' => 'ناجور', 'cp_tools' => 'katana,nmap']), 'نوع دارایی مشترک') && !isset(Catalog::custom()['c_mix']), 'tools with no asset kind in common: refused with the reason');
ok(str_contains($post('save_custom', ['cp_key' => 'x', 'cp_label' => '', 'cp_tools' => 'nuclei']), 'لازم است'), 'key and name are required');
$calls = [];
$s = $run($shop, 'c_webfull');
ok($s->status === 'running' && count($posted('/api/projects')[0][2]['tools']) === 3, 'a customer can run it: a three-step pipeline');
ok(str_contains($post('delete_custom', ['cp_key' => 'c_webfull']), 'در صف یا در حال اجرا') && isset(Catalog::custom()['c_webfull']), 'not removed while one of its scans is running');
$finish($s);
ok(str_contains($post('delete_custom', ['cp_key' => 'c_webfull']), 'برداشته شد') && Catalog::custom() === [], 'removed afterwards');
setting('custom_profiles', json_encode([['key' => 'hygiene', 'label' => 'x', 'tools' => ['nuclei']], ['key' => 'c_ok', 'label' => 'x', 'tools' => ['../etc']], 'junk', ['key' => 'c_big', 'label' => 'x', 'tools' => array_keys(Catalog::TOOLS)]]));
ok(Catalog::custom() === [], 'a tampered setting cannot shadow a built-in type, smuggle an unknown tool or build an oversized pipeline');
setting('custom_profiles', '[]');

section('one issue, one finding (a domain and its subdomain as two assets)');
dns_a('one.example', '93.184.216.90');
dns_a('www.one.example', '93.184.216.90');
$apex = $mk('one.example');
$sub = $mk('www.one.example');
$other = $mk('www.one.example', 'domain', 2);
$issue = ['name' => 'Exposed panel', 'severity' => 'high', 'affectedUrl' => 'https://www.one.example:8443/admin', 'tool' => ['name' => 'nuclei'], 'cveId' => []];
$st['vulns'] = [$issue, ['name' => 'Apex issue', 'severity' => 'low', 'affectedUrl' => 'https://one.example/', 'tool' => ['name' => 'nuclei'], 'cveId' => []]];
$finish($run($apex, 'vuln'));
$finish($run($sub, 'vuln'));
$rows = Db::rows(Db::table('mod_mcsec_findings')->where('source_key', 'oasm.exposed-panel'));
ok(count($rows) === 1 && (int) $rows[0]->asset_id === (int) $sub->id && (int) $rows[0]->client_id === 1, 'seen from both scans: one row, filed under the subdomain asset');
ok((int) Db::table('mod_mcsec_findings')->where('source_key', 'oasm.apex-issue')->value('asset_id') === (int) $apex->id, 'the apex keeps its own finding');
ok(!Db::table('mod_mcsec_findings')->where('asset_id', $other->id)->exists(), 'another account\'s asset of the same name is never touched');
ok(Assets::counts(Db::table('mod_mcsec_assets')->where('id', $sub->id)->first())['high'] === 1 && Assets::counts(Db::table('mod_mcsec_assets')->where('id', $apex->id)->first())['high'] === 0, 'counted once, in the score of the asset it belongs to');
$st['vulns'] = [$st['vulns'][1]];
$finish($run($apex, 'vuln'));
ok(Db::table('mod_mcsec_findings')->where('source_key', 'oasm.exposed-panel')->value('status') === 'open', 'last confirmed by the subdomain\'s own scan: an apex scan that misses it does not close it');
$finish($run($sub, 'vuln'));
ok(Db::table('mod_mcsec_findings')->where('source_key', 'oasm.exposed-panel')->value('status') === 'fixed', 'the subdomain\'s scan no longer sees it: fixed');
// only the apex is ever scanned: it files the finding under the subdomain and is also the one that closes it
dns_a('two.example', '93.184.216.91');
$apex2 = $mk('two.example');
$sub2 = $mk('api.two.example');
$st['vulns'] = [['name' => 'Open API docs', 'severity' => 'medium', 'affectedUrl' => 'https://api.two.example/docs', 'tool' => ['name' => 'nuclei'], 'cveId' => []]];
$finish($run($apex2, 'vuln'));
$row = Db::table('mod_mcsec_findings')->where('source_key', 'oasm.open-api-docs')->first();
ok($row !== null && (int) $row->asset_id === (int) $sub2->id && $row->status === 'open', 'found by the apex scan, filed under the subdomain asset');
$st['vulns'] = [];
$finish($run($apex2, 'vuln'));
ok(Db::table('mod_mcsec_findings')->where('id', $row->id)->value('status') === 'fixed' && Assets::counts(Db::table('mod_mcsec_assets')->where('id', $sub2->id)->first())['medium'] === 0, 'the same apex scan no longer sees it: fixed, and the subdomain\'s counts follow');
ok(Findings::hostOf('https://Shop.Example.com:8443/x?y') === 'shop.example.com' && Findings::hostOf('10.0.0.1:22') === '10.0.0.1' && Findings::hostOf('[2001:db8::1]:443') === '2001:db8::1' && Findings::hostOf('plain.example') === 'plain.example', 'host of a location');

done();
