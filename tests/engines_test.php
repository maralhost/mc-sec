<?php
// Engine adapters against simulated OASM (v0.12.1 shapes, checked live on staging) and Osmedeus v5 (source shapes).
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Crypto;
use McSec\Db;
use McSec\Engines\Oasm;
use McSec\Engines\Osmedeus;
use McSec\Settings;

Clock::$fixed = strtotime('2026-11-11T10:00:00Z');
setting('oasm_url', 'https://oasm.test');
setting('oasm_email', 'svc@oasm.test');
Settings::setSecret('oasm_password', 'svc-pass');
Accounts::ensure(1);
Db::table('mod_mcsec_assets')->insert(['id' => 50, 'client_id' => 1, 'kind' => 'domain', 'value' => 'example.com', 'status' => 'verified', 'method' => 'dns', 'created_at' => Clock::now()]);
$asset = Db::table('mod_mcsec_assets')->where('id', 50)->first();

section('OASM: per-client user, workspace, target, discovery, results');
$calls = [];
$state = ['run_done' => false, 'nuclei_installed' => false, 'nuclei_profile' => false, 'workers_online' => 2, 'pl_status' => 'in_progress', 'pl_error' => '', 'project_gone' => false, 'projects' => 0];
http_mock(function ($method, $url, $headers, $body) use (&$calls, &$state) {
    $path = (string) parse_url($url, PHP_URL_PATH) . (parse_url($url, PHP_URL_QUERY) ? '?' . parse_url($url, PHP_URL_QUERY) : '');
    $calls[] = [$method, $path, $headers['X-Workspace-Id'] ?? '', $headers['Origin'] ?? '', $body];
    $b = json_decode((string) $body, true) ?: [];
    if ($path === '/api/auth/sign-in/email') {
        $who = $b['email'] === 'svc@oasm.test' && $b['password'] === 'svc-pass' ? 'svc' : (str_starts_with((string) $b['email'], 'mcsec-c1@') ? 'c1' : '');
        return $who === '' ? ['status' => 401, 'body' => '{"message":"Invalid"}'] : ['status' => 200, 'body' => '{"token":"x"}', 'headers' => ['set-cookie' => ['session=' . $who . '-cookie; Path=/; HttpOnly']]];
    }
    $cookie = '';
    if ($path === '/api/auth/admin/create-user') {
        return ['status' => 200, 'body' => json_encode(['user' => ['id' => 'u1', 'email' => $b['email']]])];
    }
    if ($method === 'POST' && $path === '/api/workspaces') {
        return ['status' => 201, 'body' => json_encode(['id' => 'ws-1', 'name' => $b['name']])];
    }
    if ($method === 'PATCH' && $path === '/api/workspaces/configs') {
        return ['status' => 200, 'body' => '{"message":"ok"}'];
    }
    if ($path === '/api/targets/bulk') {
        return ['status' => 201, 'body' => json_encode(['created' => [['id' => 't-1', 'value' => 'example.com', 'type' => 'DOMAIN']], 'skipped' => [], 'totalRequested' => 1, 'totalCreated' => 1, 'totalSkipped' => 0])];
    }
    if ($method === 'GET' && $path === '/api/targets/t-1') {
        return ['status' => 200, 'body' => '{"id":"t-1"}'];
    }
    if (str_starts_with($path, '/api/targets/t-1/runs')) {
        $run = ['id' => 'run-1', 'createdAt' => '2026-11-11T10:00:10Z', 'status' => $state['run_done'] ? 'completed' : 'in_progress', 'isCompleted' => $state['run_done'],
            'workflowName' => 'Domain discovery', 'jobsTotal' => 4, 'jobsDone' => $state['run_done'] ? 4 : 2, 'jobsFailed' => 0, 'jobsRunning' => 1, 'currentTool' => 'naabu', 'newVulnerabilities' => 0];
        return ['status' => 200, 'body' => json_encode(['data' => [$run], 'total' => 1, 'hasNextPage' => false])];
    }
    if (str_starts_with($path, '/api/assets?')) {
        return ['status' => 200, 'body' => json_encode(['data' => [
            ['id' => 'a1', 'value' => 'www.example.com:443', 'port' => 443, 'ipAddresses' => ['93.184.216.34'], 'httpResponses' => ['title' => 'Shop', 'webserver' => 'nginx', 'status_code' => 200, 'url' => 'https://www.example.com', 'tech' => ['WordPress', 'PHP'],
                'tls' => ['not_after' => '2027-01-01T00:00:00Z', 'issuer_dn' => 'R3', 'subject_cn' => 'www.example.com', 'tls_version' => 'tls13']]],
            ['id' => 'a2', 'value' => 'db.example.com:3306', 'port' => 3306, 'ipAddresses' => [], 'httpResponses' => null],
            // shape seen live on OASM v0.12.1: httpx failed on SSH but the row still has a URL
            ['id' => 'a3', 'value' => 'www.example.com:22', 'port' => 22, 'ipAddresses' => ['93.184.216.34'], 'httpResponses' => ['url' => 'http://www.example.com:22', 'failed' => true, 'status_code' => 0, 'tech' => [], 'tls' => null]],
        ], 'hasNextPage' => false])];
    }
    if (str_starts_with($path, '/api/vulnerabilities?')) {
        return ['status' => 200, 'body' => json_encode(['data' => [['id' => 'v1', 'name' => 'WordPress XML-RPC Enabled', 'severity' => 'medium', 'affectedUrl' => 'https://www.example.com/xmlrpc.php',
            'description' => 'XML-RPC is enabled', 'solution' => 'Disable it', 'references' => ['https://wordpress.org'], 'cveId' => [], 'cweId' => ['CWE-200'], 'cvssScore' => 5.3, 'tags' => ['wordpress'],
            'extractedResults' => ['<methodResponse>']]], 'hasNextPage' => false])];
    }
    if (str_starts_with($path, '/api/tools?')) {
        // live shape (0.12.1): availableWorkersCount is 0 for every connector, even while a node worker runs them
        return ['status' => 200, 'body' => json_encode(['data' => [
            ['id' => 'tool-zap', 'name' => 'zap', 'type' => 'connector', 'isInstalled' => false, 'isReady' => null, 'hasConfigProfile' => false, 'availableWorkersCount' => 0],
            ['id' => 'tool-nuclei', 'name' => 'nuclei', 'type' => 'connector', 'isInstalled' => $state['nuclei_installed'], 'isReady' => $state['nuclei_installed'] && $state['nuclei_profile'], 'hasConfigProfile' => $state['nuclei_profile'], 'availableWorkersCount' => 0],
        ]])];
    }
    if ($method === 'POST' && $path === '/api/tools/tool-nuclei/config-profiles') {
        $state['nuclei_profile'] = true;
        return ['status' => 201, 'body' => json_encode(['id' => 'prof-1', 'config' => $b['config'] ?? []])];
    }
    if ($method === 'POST' && $path === '/api/projects') {
        $state['projects']++;
        $state['project_gone'] = false;
        return ['status' => 201, 'body' => json_encode(['id' => 'proj-' . $state['projects'], 'name' => $b['name'], 'totalAssets' => 1])];
    }
    if ($method === 'GET' && preg_match('~^/api/projects/(proj-\d+)$~', $path, $pm)) {
        return ['status' => 200, 'body' => json_encode(['id' => $pm[1], 'projectWorkflows' => [['id' => 'bind-' . $pm[1]]]])];
    }
    if ($method === 'POST' && preg_match('~^/api/projects/(proj-\d+)/workflows/(bind-proj-\d+)/run$~', $path, $pm)) {
        return $state['project_gone'] ? ['status' => 404, 'body' => '{"message":"Project not found"}'] : ['status' => 201, 'body' => json_encode(['jobHistoryId' => 'jh-' . $pm[1], 'assets' => 1])];
    }
    if ($method === 'POST' && preg_match('~^/api/projects/proj-\d+/archive$~', $path)) {
        return ['status' => 201, 'body' => '{}'];
    }
    if ($method === 'GET' && preg_match('~^/api/projects/(proj-\d+)/runs~', $path, $pm)) {
        $done = $state['pl_status'] !== 'in_progress';
        return ['status' => 200, 'body' => json_encode(['data' => [['id' => 'jh-' . $pm[1], 'status' => $state['pl_status'], 'isCompleted' => $done, 'stepsTotal' => 1,
            'stepsDone' => $state['pl_status'] === 'completed' ? 1 : 0, 'stepsFailed' => $state['pl_status'] === 'failed' ? 1 : 0, 'newVulnerabilities' => 0], ['id' => 'jh-other', 'status' => 'completed', 'isCompleted' => true]]])];
    }
    if (str_starts_with($path, '/api/jobs-registry?jobHistoryId=')) {
        return ['status' => 200, 'body' => json_encode(['data' => [['status' => 'failed', 'tool' => ['name' => 'nuclei'], 'errorLogs' => $state['pl_error'] !== '' ? [['logMessage' => $state['pl_error']]] : []]], 'total' => 1])];
    }
    if ($method === 'POST' && str_starts_with($path, '/api/jobs-registry/histories/')) {
        return ['status' => 201, 'body' => '{}'];
    }
    if ($path === '/api/vulnerabilities/scan') {
        return ['status' => 201, 'body' => '{"message":"ok"}'];
    }
    if (str_starts_with($path, '/api/workers?')) {
        $ws = [];
        for ($i = 0; $i < 3; $i++) {
            $ws[] = ['id' => 'w' . $i, 'isOnline' => $i < $state['workers_online']];
        }
        return ['status' => 200, 'body' => json_encode(['data' => $ws, 'total' => 3])];
    }
    if ($path === '/api/health') {
        return ['status' => 200, 'body' => '{"status":"ok"}'];
    }
    if ($path === '/api/metadata') {
        return ['status' => 200, 'body' => '{"currentVersion":"v0.12.1"}'];
    }
    if ($method === 'GET' && str_starts_with($path, '/api/workspaces?')) {
        return ['status' => 200, 'body' => json_encode(['data' => [['id' => 'svc-ws', 'name' => 'service']], 'total' => 1])];
    }
    if ($method === 'POST' && $path === '/api/tools/install') {
        $state['nuclei_installed'] = ($b['toolId'] ?? '') === 'tool-nuclei';
        return ['status' => 201, 'body' => '{"tool":{"name":"nuclei"}}'];
    }
    return ['status' => 404, 'body' => '{"message":"not mocked ' . $path . '"}'];
});
$oasm = new Oasm();
ok($oasm->configured(), 'configured');
Db::table('mod_mcsec_scans')->insert(['id' => 700, 'client_id' => 1, 'asset_id' => 50, 'profile' => 'surface', 'engine' => 'oasm', 'status' => 'queued', 'queued_at' => Clock::now(), 'started_at' => Clock::now()]);
$scan = Db::table('mod_mcsec_scans')->where('id', 700)->first();
$r = $oasm->start($scan, $asset, \McSec\Catalog::get('surface'));
ok($r['ok'] && $r['ref'] === 't-1' && $r['meta']['ws'] === 'ws-1', 'started on the client\'s own workspace and target (' . json_encode($r, JSON_UNESCAPED_UNICODE) . ')');
$acc = Accounts::get(1);
ok(str_starts_with((string) $acc->oasm_user, 'mcsec-c1@') && Crypto::decrypt((string) $acc->oasm_secret) !== '', 'client OASM user created, password stored encrypted');
$createUser = array_values(array_filter($calls, fn ($c) => $c[1] === '/api/auth/admin/create-user'));
$wsCreate = array_values(array_filter($calls, fn ($c) => $c[0] === 'POST' && $c[1] === '/api/workspaces'));
ok(count($createUser) === 1 && count($wsCreate) === 1, 'one user, one workspace');
$bulk = array_values(array_filter($calls, fn ($c) => $c[1] === '/api/targets/bulk'))[0];
ok($bulk[2] === 'ws-1' && $bulk[3] === 'https://oasm.test' && str_contains((string) $bulk[4], '"DOMAIN"'), 'target created in ws-1 with Origin and type DOMAIN');
ok(!array_filter($calls, fn ($c) => str_contains($c[1], 're-scan')), 'new target: no re-scan call (creation starts discovery)');
ok(Db::table('mod_mcsec_assets')->where('id', 50)->value('oasm_target') === 't-1', 'target id remembered');
Db::table('mod_mcsec_scans')->where('id', 700)->update(['status' => 'running', 'backend_ref' => 't-1', 'backend_meta' => json_encode($r['meta'])]);
$scan = Db::table('mod_mcsec_scans')->where('id', 700)->first();
$p = $oasm->poll($scan, $asset, \McSec\Catalog::get('surface'));
ok($p['status'] === 'running' && $p['progress'] === 50 && str_contains($p['stage'], 'naabu'), 'progress 50% while naabu runs');
$state['run_done'] = true;
ok($oasm->poll($scan, $asset, \McSec\Catalog::get('surface'))['status'] === 'completed', 'completed');
$c = $oasm->collect($scan, $asset, \McSec\Catalog::get('surface'));
$kinds = array_count_values(array_column($c['surface'], 'kind'));
ok(($kinds['host'] ?? 0) === 2 && ($kinds['port'] ?? 0) === 3 && ($kinds['tech'] ?? 0) === 2 && ($kinds['cert'] ?? 0) === 1, 'surface: hosts, ports, tech, cert (' . json_encode($kinds) . ')');
$ssh = array_values(array_filter($c['surface'], fn ($x) => $x['value'] === 'www.example.com:22'));
ok(count($ssh) === 1 && $ssh[0]['meta'] === [], 'failed HTTP probe (SSH): port kept, no made-up URL');
ok($c['findings'] === [] && $c['kinds'] === ['host', 'port'], 'discovery: no vulnerability list, hosts/ports fully covered');
$exp = \McSec\Scans::exposureFindings($c['surface']);
ok(count($exp) === 1 && $exp[0]['key'] === 'builtin.port.3306' && $exp[0]['severity'] === 'high', 'MySQL on the internet becomes a finding');
$v = Oasm::normalize(['name' => 'X', 'severity' => 'HIGH', 'host' => 'h', 'ports' => ['8080'], 'cveId' => ['CVE-2024-1'], 'extractedResults' => ['a']]);
ok($v['location'] === 'h:8080' && $v['key'] === 'oasm.cve-2024-1' && $v['evidence'] === 'a', 'normalize: location from host+port, key from CVE');

section('OASM: vulnerability scan through a polite pipeline, session renewal on 401');
Db::table('mod_mcsec_scans')->insert(['id' => 701, 'client_id' => 1, 'asset_id' => 50, 'profile' => 'vuln', 'engine' => 'oasm', 'status' => 'queued', 'queued_at' => Clock::now(), 'started_at' => Clock::now()]);
$asset = Db::table('mod_mcsec_assets')->where('id', 50)->first();
\McSec\Kv::set('oasm:s:1', Crypto::encrypt('session=expired'), 3600);
$calls = [];
$prev = \McSec\Http::$mock;
http_mock(function ($m, $u, $h, $b, $o) use ($prev) {
    if (str_contains((string) ($o['cookie'] ?? ''), 'expired')) {
        return ['status' => 401, 'body' => '{"message":"Unauthorized"}'];
    }
    return $prev($m, $u, $h, $b, $o);
});
$vuln = \McSec\Catalog::get('vuln');
$r = $oasm->start(Db::table('mod_mcsec_scans')->where('id', 701)->first(), $asset, $vuln);
ok($r['ok'] && $r['meta']['kind'] === 'pipeline' && $r['meta']['tools'] === ['nuclei'] && $r['meta']['project'] === 'proj-1' && $r['meta']['run'] === 'jh-proj-1', 'vuln scan started as a project run, after signing in again (' . json_encode($r['meta'] ?? $r) . ')');
ok(Crypto::decrypt((string) \McSec\Kv::get('oasm:s:1')) === 'session=c1-cookie', 'fresh client session cached');
$inst = array_values(array_filter($calls, fn ($c) => $c[1] === '/api/tools/install'));
ok(count($inst) === 1 && $inst[0][2] === 'ws-1' && str_contains((string) $inst[0][4], 'tool-nuclei'), 'nuclei installed in the client workspace (availableWorkersCount 0 does not stop it)');
$prof = array_values(array_filter($calls, fn ($c) => $c[1] === '/api/tools/tool-nuclei/config-profiles'));
ok(count($prof) === 1 && $prof[0][2] === 'ws-1', 'a default config profile is created so OASM calls the tool ready');
$proj = json_decode((string) array_values(array_filter($calls, fn ($c) => $c[0] === 'POST' && $c[1] === '/api/projects'))[0][4], true);
$cfg = $proj['tools'][0]['config'] ?? [];
ok(($cfg['rateLimit'] ?? 0) === 10 && ($cfg['concurrency'] ?? 0) === 5 && ($cfg['interactsh'] ?? null) === false && ($cfg['excludeTags'] ?? []) === ['dos', 'fuzz', 'intrusive'], 'pipeline carries the polite settings (10 req/s, no interactsh, no dos/fuzz/intrusive)');
ok($proj['scopeRules'] === [['mode' => 'include', 'type' => 'target', 'value' => 't-1']] && $proj['tools'][0]['toolId'] === 'tool-nuclei' && empty($proj['runNow']), 'scope is exactly this asset\'s target');
ok(!array_filter($calls, fn ($c) => $c[1] === '/api/vulnerabilities/scan'), 'OASM\'s default scan (150 req/s, interactsh) is never used');
Db::table('mod_mcsec_scans')->where('id', 701)->update(['status' => 'running', 'backend_ref' => 't-1', 'backend_meta' => json_encode($r['meta'])]);
$s701 = Db::table('mod_mcsec_scans')->where('id', 701)->first();
$p = $oasm->poll($s701, $asset, $vuln);
ok($p['status'] === 'running' && str_contains($p['stage'], 'Nuclei'), 'running: found by its own run id among the project runs');
$state['pl_status'] = 'completed';
ok($oasm->poll($s701, $asset, $vuln)['status'] === 'completed', 'completed');
$c = $oasm->collect($s701, $asset, $vuln);
ok(count($c['findings']) === 1 && $c['findings'][0]['severity'] === 'medium' && $c['findings'][0]['cvss'] == 5.3 && $c['complete'] === true && $c['partial'] === '', 'nuclei finding normalized; a complete run');
ok($oasm->cancel($s701, $asset) && (bool) array_filter($calls, fn ($c) => $c[1] === '/api/jobs-registry/histories/jh-proj-1/cancel'), 'cancel targets the pipeline run');

// second scan of the same asset: the project is reused; changed settings make a new one
$calls = [];
$r2 = $oasm->start($s701, $asset, $vuln);
ok($r2['ok'] && $r2['meta']['project'] === 'proj-1' && !array_filter($calls, fn ($c) => $c[0] === 'POST' && $c[1] === '/api/projects'), 'next scan reuses the asset\'s project');
setting('nuclei_rate', '25');
$calls = [];
$r3 = $oasm->start($s701, $asset, $vuln);
$proj3 = json_decode((string) (array_values(array_filter($calls, fn ($c) => $c[0] === 'POST' && $c[1] === '/api/projects'))[0][4] ?? '{}'), true);
ok($r3['ok'] && $r3['meta']['project'] === 'proj-2' && ($proj3['tools'][0]['config']['rateLimit'] ?? 0) === 25 && (bool) array_filter($calls, fn ($c) => $c[1] === '/api/projects/proj-1/archive'), 'changed settings: old project archived, new one with the new rate');
setting('nuclei_rate', '100000');
setting('nuclei_exclude_tags', 'dos, bad tag!, <script>');
ok(Oasm::toolConfig('nuclei')['rateLimit'] === 150 && Oasm::toolConfig('nuclei')['excludeTags'] === ['dos'], 'settings are bounded and cleaned before they reach OASM');
setting('nuclei_rate', '10');
setting('nuclei_exclude_tags', 'dos,fuzz,intrusive');
$oasm->start($s701, $asset, $vuln);
$state['project_gone'] = true;
$before = $state['projects'];
$r4 = $oasm->start($s701, $asset, $vuln);
ok($r4['ok'] && $state['projects'] === $before + 1 && $r4['meta']['project'] === 'proj-' . $state['projects'], 'project deleted in OASM: made again');

// the target bans the scanner mid-scan (seen live): an incomplete assessment, credits back, nothing marked fixed
Db::table('mod_mcsec_scans')->whereIn('id', [700, 701])->update(['status' => 'completed']);
$old = Db::table('mod_mcsec_findings')->insertGetId(['client_id' => 1, 'asset_id' => 50, 'fp' => sha1('old-vuln'), 'engine' => 'oasm', 'profile' => 'vuln', 'title' => 'Earlier finding', 'severity' => 'high', 'status' => 'open', 'last_scan_id' => 701]);
$state['pl_status'] = 'in_progress';
$bal = \McSec\Credits::balance(1)['total'];
$q = \McSec\Scans::queue(1, $asset, 'vuln', 0, 1);
ok($q['ok'] && $q['credits'] > 0 && \McSec\Credits::balance(1)['total'] === $bal - $q['credits'], 'vuln scan queued and charged');
\McSec\Scans::dispatch(microtime(true) + 10);
ok(Db::table('mod_mcsec_scans')->where('id', $q['scan_id'])->value('status') === 'running', 'running in OASM');
$state['pl_status'] = 'failed';
$state['pl_error'] = "nuclei scan: 0 findings but 8069 template results were skipped (target marked unresponsive) — check target reachability and container network egress\n--- container logs ---";
$prevV = \McSec\Http::$mock;
http_mock(function ($m, $u, $h, $b, $o) use ($prevV) {
    return str_contains($u, '/api/vulnerabilities?') ? ['status' => 200, 'body' => '{"data":[],"hasNextPage":false}'] : $prevV($m, $u, $h, $b, $o);
});
Clock::$fixed += 120;
\McSec\Scans::pollRunning(microtime(true) + 10);
$s = Db::table('mod_mcsec_scans')->where('id', $q['scan_id'])->first();
$sum = json_decode((string) $s->summary, true);
ok($s->status === 'completed' && str_contains((string) ($sum['partial'] ?? ''), 'مسدود'), 'banned by the target: completed as an incomplete assessment, with the reason (' . $s->status . ' ' . $s->error . ')');
ok(\McSec\Credits::balance(1)['total'] === $bal && ($sum['refunded'] ?? 0) === $q['credits'], 'the customer got nothing, so the credits went back (' . \McSec\Credits::balance(1)['total'] . ' vs ' . $bal . ' ' . json_encode($sum, JSON_UNESCAPED_UNICODE) . ')');
ok(Db::table('mod_mcsec_findings')->where('id', $old)->value('status') === 'open', 'an earlier finding is not marked fixed by a scan that saw nothing');
ok(str_contains((string) Db::table('mod_mcsec_assets')->where('id', 50)->value('partial'), 'IP اسکنر'), 'asset marked incomplete, telling to allow the scanner IP');
$state['pl_status'] = 'in_progress';
$state['pl_error'] = 'connector image pull failed';
$q2 = \McSec\Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', 50)->first(), 'vuln', 0, 1);
if (empty($q2['ok'])) {
    echo '  q2: ' . json_encode($q2, JSON_UNESCAPED_UNICODE) . "\n";
}
\McSec\Scans::dispatch(microtime(true) + 10);
$state['pl_status'] = 'failed';
Clock::$fixed += 120;
\McSec\Scans::pollRunning(microtime(true) + 10);
$s2 = Db::table('mod_mcsec_scans')->where('id', $q2['scan_id'])->first();
ok($s2->status === 'failed' && $s2->error_ref !== '' && \McSec\Credits::balance(1)['total'] === $bal, 'any other OASM failure: failed with a support code, credits back (' . $s2->status . ')');
http_mock($prevV);
$state['pl_status'] = 'in_progress';
$state['pl_error'] = '';

$calls = [];
$h = $oasm->health();
ok($h['ok'] && $h['vuln'] === true && $h['workers'] === 2 && str_contains($h['message'], '۲'), 'setup test: workers online counted, nuclei known');
ok(!array_filter($calls, fn ($c) => $c[0] === 'POST' && $c[2] === 'svc-ws'), 'the test only reads (installs and creates nothing)');
$state['workers_online'] = 0;
$h = $oasm->health();
ok($h['ok'] && $h['vuln'] === false && str_contains($h['message'], 'هیچ کارگری'), 'no worker online: said plainly');
$state['workers_online'] = 2;
ok(\McSec\Catalog::get('recon') === null && \McSec\Catalog::get('deep') === null && isset(\McSec\Catalog::all(true)['deep']), 'Osmedeus profiles are off for customers by default (an admin can turn them on)');

section('Osmedeus: API key, run, progress, results');
setting('osm_url', 'http://osm.test:8811');
Settings::setSecret('osm_api_key', 'k-123');
$ocalls = [];
$runStatus = 'running';
http_mock(function ($method, $url, $headers, $body) use (&$ocalls, &$runStatus) {
    $path = (string) parse_url($url, PHP_URL_PATH);
    $q = (string) parse_url($url, PHP_URL_QUERY);
    $ocalls[] = [$method, $path, $headers['x-osm-api-key'] ?? '', $body];
    if (($headers['x-osm-api-key'] ?? '') !== 'k-123') {
        return ['status' => 401, 'body' => '{"error":true,"message":"Missing authorization header or session cookie"}'];
    }
    if ($method === 'POST' && $path === '/osm/api/runs') {
        return ['status' => 202, 'body' => json_encode(['message' => 'Run started', 'run_uuid' => 'uuid-1', 'job_id' => 'ab12cd34', 'status' => 'queued'])];
    }
    if ($path === '/osm/api/runs/uuid-1' && $method === 'GET') {
        return ['status' => 200, 'body' => json_encode(['data' => ['run_uuid' => 'uuid-1', 'status' => $runStatus, 'total_steps' => 20, 'completed_steps' => 5]])];
    }
    if ($path === '/osm/api/assets') {
        return ['status' => 200, 'body' => json_encode(['data' => [['asset_value' => 'api.example.com', 'asset_type' => 'subdomain', 'url' => 'https://api.example.com', 'status_code' => 200, 'host_ip' => '93.184.216.40',
            'open_ports' => ['443/https', '6379/tcp'], 'tech' => ['nginx:1.25'], 'last_seen_at' => '2026-11-11T10:30:00Z']], 'pagination' => ['total' => 1]])];
    }
    if ($path === '/osm/api/vulnerabilities') {
        return ['status' => 200, 'body' => json_encode(['data' => [
            ['vuln_info' => 'git-config', 'vuln_title' => 'Git Config Exposure', 'severity' => 'medium', 'asset_value' => 'https://api.example.com', 'last_seen_at' => '2026-11-11T10:40:00Z',
                'raw_vuln_json' => json_encode(['template-id' => 'git-config', 'matched-at' => 'https://api.example.com/.git/config', 'info' => ['name' => 'Git Config', 'severity' => 'medium', 'reference' => ['https://example.org/ref'], 'classification' => ['cwe-id' => ['cwe-200']]]])],
            ['vuln_info' => 'old-thing', 'vuln_title' => 'Seen long ago', 'severity' => 'high', 'asset_value' => 'x', 'last_seen_at' => '2026-10-01T00:00:00Z'],
        ]])];
    }
    if ($method === 'DELETE') {
        return ['status' => 200, 'body' => '{"message":"Run cancelled successfully"}'];
    }
    return ['status' => 404, 'body' => '{"error":true,"message":"nf"}'];
});
$osm = new Osmedeus();
ok($osm->configured(), 'configured with an API key');
Db::table('mod_mcsec_scans')->insert(['id' => 800, 'client_id' => 1, 'asset_id' => 50, 'profile' => 'deep', 'engine' => 'osmedeus', 'status' => 'queued', 'queued_at' => Clock::now(), 'started_at' => Clock::now()]);
$s = Db::table('mod_mcsec_scans')->where('id', 800)->first();
$r = $osm->start($s, $asset, \McSec\Catalog::all(true)['deep']);
ok($r['ok'] && $r['ref'] === 'uuid-1' && $r['meta']['space'] === 'mcsec-c1-a50', 'run started in its own Osmedeus workspace');
$post = json_decode((string) $ocalls[0][3], true);
ok($post['flow'] === 'general' && $post['target'] === 'example.com' && $post['params']['space_name'] === 'mcsec-c1-a50' && $post['params']['exclude_modules'] === 'enum-ipspace', 'flow, target, space_name; IP-space expansion excluded for a domain');
Db::table('mod_mcsec_scans')->where('id', 800)->update(['status' => 'running', 'backend_ref' => 'uuid-1', 'backend_meta' => json_encode($r['meta'])]);
$s = Db::table('mod_mcsec_scans')->where('id', 800)->first();
$p = $osm->poll($s, $asset, \McSec\Catalog::all(true)['deep']);
ok($p['status'] === 'running' && $p['progress'] === 25, 'progress from steps (25%)');
$runStatus = 'completed';
ok($osm->poll($s, $asset, \McSec\Catalog::all(true)['deep'])['status'] === 'completed', 'completed');
$c = $osm->collect($s, $asset, \McSec\Catalog::all(true)['deep']);
ok(count($c['findings']) === 1 && $c['findings'][0]['key'] === 'nuclei.git-config' && $c['findings'][0]['location'] === 'https://api.example.com/.git/config', 'only what this run saw; matched-at as location');
$ports = array_values(array_filter($c['surface'], fn ($x) => $x['kind'] === 'port'));
ok(count($ports) === 2 && $ports[1]['value'] === '93.184.216.40:6379', 'open ports from the asset rows');
$runStatus = 'failed';
$ocallsBefore = count($ocalls);
ok(Osmedeus::flowFor(['workflow' => 'general'], (object) ['kind' => 'ip']) === 'cidr', 'IPs go to the cidr flow');
ok(!Osmedeus::safe('example.com;rm -rf') && Osmedeus::safe('example.com'), 'shell metacharacters refused before submitting');
Settings::setSecret('osm_api_key', 'wrong');
$bad = $osm->poll($s, $asset, \McSec\Catalog::all(true)['deep']);
ok($bad['status'] === 'running', 'auth failure while polling does not fail the scan at once');
done();
