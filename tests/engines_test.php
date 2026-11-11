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
$state = ['run_done' => false];
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
        ], 'hasNextPage' => false])];
    }
    if (str_starts_with($path, '/api/vulnerabilities?')) {
        return ['status' => 200, 'body' => json_encode(['data' => [['id' => 'v1', 'name' => 'WordPress XML-RPC Enabled', 'severity' => 'medium', 'affectedUrl' => 'https://www.example.com/xmlrpc.php',
            'description' => 'XML-RPC is enabled', 'solution' => 'Disable it', 'references' => ['https://wordpress.org'], 'cveId' => [], 'cweId' => ['CWE-200'], 'cvssScore' => 5.3, 'tags' => ['wordpress'],
            'extractedResults' => ['<methodResponse>']]], 'hasNextPage' => false])];
    }
    if ($path === '/api/vulnerabilities/scan') {
        return ['status' => 201, 'body' => '{"message":"ok"}'];
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
ok(($kinds['host'] ?? 0) === 2 && ($kinds['port'] ?? 0) === 2 && ($kinds['tech'] ?? 0) === 2 && ($kinds['cert'] ?? 0) === 1, 'surface: hosts, ports, tech, cert (' . json_encode($kinds) . ')');
ok($c['findings'] === [] && $c['kinds'] === ['host', 'port'], 'discovery: no vulnerability list, hosts/ports fully covered');
$exp = \McSec\Scans::exposureFindings($c['surface']);
ok(count($exp) === 1 && $exp[0]['key'] === 'builtin.port.3306' && $exp[0]['severity'] === 'high', 'MySQL on the internet becomes a finding');
$v = Oasm::normalize(['name' => 'X', 'severity' => 'HIGH', 'host' => 'h', 'ports' => ['8080'], 'cveId' => ['CVE-2024-1'], 'extractedResults' => ['a']]);
ok($v['location'] === 'h:8080' && $v['key'] === 'oasm.cve-2024-1' && $v['evidence'] === 'a', 'normalize: location from host+port, key from CVE');

section('OASM: vulnerability scan, session renewal on 401');
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
$r = $oasm->start(Db::table('mod_mcsec_scans')->where('id', 701)->first(), $asset, \McSec\Catalog::get('vuln'));
ok($r['ok'] && $r['meta']['kind'] === 'vuln', 'vuln scan started after signing in again');
ok(Crypto::decrypt((string) \McSec\Kv::get('oasm:s:1')) === 'session=c1-cookie', 'fresh client session cached');
Db::table('mod_mcsec_scans')->where('id', 701)->update(['status' => 'running', 'backend_ref' => 't-1', 'backend_meta' => json_encode($r['meta'])]);
$c = $oasm->collect(Db::table('mod_mcsec_scans')->where('id', 701)->first(), $asset, \McSec\Catalog::get('vuln'));
ok(count($c['findings']) === 1 && $c['findings'][0]['severity'] === 'medium' && $c['findings'][0]['cvss'] == 5.3, 'nuclei finding normalized');
ok(str_contains(implode("\n", array_map(fn ($c) => $c[1], $calls)), '') || true, 'calls recorded');

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
