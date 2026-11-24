<?php
// 0.12.0 a scan is "finished" only with proof that the engine worked, and every scan has a journal an admin can open:
// found live: a web scan "finished" on a host where the scanner saw no open port, and its OASM workspace (owned by the
// client's own OASM user) was invisible to the admin. New target: discovery first, then the tools. Alerts for the admin.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Engines\Oasm;
use McSec\ScanLog;
use McSec\Scans;
use McSec\Settings;

Clock::$fixed = strtotime('2026-11-24T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'daily_scan_cap' => '200', 'welcome_credits' => '0', 'oasm_url' => 'https://oasm.test', 'oasm_email' => 'svc@oasm.test', 'refund_on_fail' => '1'] as $k => $v) {
    setting($k, $v);
}
Settings::setSecret('oasm_password', 'svc-pass');
$who = login(1, 1);
Accounts::ensure(1);
Credits::credit(1, 200, 'paid', 'topup', 'topup:sl1', 'test');
$mk = function (string $value): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 1, 'kind' => 'domain', 'value' => $value, 'status' => 'verified', 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
foreach (['pam.example', 'shop.example', 'gone.example'] as $d) {
    dns_a($d, '93.184.216.' . (10 + strlen($d)));
}
// OASM: what it holds decides the answers
$st = ['discovery_done' => false, 'services' => [], 'jobs' => [['status' => 'completed', 'category' => 'url_discovery'], ['status' => 'completed', 'category' => 'vulnerabilities']], 'run' => 'completed', 'vulns' => [], 'runs_500' => false];
$calls = [];
http_mock(function ($method, $url, $headers, $body) use (&$st, &$calls) {
    $path = (string) parse_url($url, PHP_URL_PATH) . (parse_url($url, PHP_URL_QUERY) ? '?' . parse_url($url, PHP_URL_QUERY) : '');
    $b = is_array($body) ? $body : (json_decode((string) $body, true) ?: []);
    $calls[] = [$method, $path];
    $j = fn ($x, $code = 200) => ['status' => $code, 'body' => json_encode($x)];
    if ($path === '/api/auth/sign-in/email') {
        return ['status' => 200, 'body' => '{}', 'headers' => ['set-cookie' => ['session=ok; Path=/']]];
    }
    if ($path === '/api/auth/admin/create-user') {
        return $j(['user' => ['id' => 'u1']]);
    }
    if ($path === '/api/workspaces') {
        return $j(['id' => 'ws-1'], 201);
    }
    if ($path === '/api/workspaces/configs') {
        return $j([]);
    }
    if ($path === '/api/targets/bulk') {
        return $j(['created' => [['id' => 't-' . md5((string) $b['targets'][0]['value'])]]], 201);
    }
    if (preg_match('~^/api/targets/t-[0-9a-f]+$~', $path)) {
        return $j(['id' => 'x']);
    }
    if (preg_match('~^/api/targets/t-[0-9a-f]+/runs~', $path)) {
        return $j(['data' => [['id' => 'd1', 'isCompleted' => $st['discovery_done'], 'status' => $st['discovery_done'] ? 'completed' : 'in_progress', 'workflowName' => 'Domain discovery', 'createdAt' => '2026-11-24T10:00:10Z']]]);
    }
    if (str_starts_with($path, '/api/tools?')) {
        return $j(['data' => [['id' => 'tool-katana', 'name' => 'katana', 'isInstalled' => true, 'hasConfigProfile' => false], ['id' => 'tool-zap', 'name' => 'zap', 'isInstalled' => true, 'hasConfigProfile' => false]]]);
    }
    if (preg_match('~^/api/tools/tool-[a-z]+/config-profiles~', $path)) {
        return $method === 'GET' ? $j([]) : $j(['id' => 'p1'], 201);
    }
    if ($method === 'POST' && $path === '/api/projects') {
        return $j(['id' => 'proj-1'], 201);
    }
    if ($method === 'GET' && $path === '/api/projects/proj-1') {
        return $j(['id' => 'proj-1', 'projectWorkflows' => [['id' => 'bind-1']]]);
    }
    if ($method === 'POST' && str_ends_with($path, '/run')) {
        return $j(['jobHistoryId' => 'jh-1'], 201);
    }
    if (str_starts_with($path, '/api/projects/proj-1/runs')) {
        if ($st['runs_500']) {
            return ['status' => 500, 'body' => '{"message":"boom secret-token-123"}'];
        }
        return $j(['data' => $st['run'] === 'none' ? [] : [['id' => 'jh-1', 'isCompleted' => $st['run'] !== 'in_progress', 'status' => $st['run'], 'stepsTotal' => 2, 'stepsDone' => $st['run'] === 'in_progress' ? 1 : 2]]]);
    }
    if (str_starts_with($path, '/api/jobs-registry')) {
        return $j(['data' => $st['jobs']]);
    }
    if (str_starts_with($path, '/api/assets?')) {
        return $j(['data' => $st['services'], 'hasNextPage' => false]);
    }
    if (str_starts_with($path, '/api/vulnerabilities?')) {
        return $j(['data' => $st['vulns'], 'hasNextPage' => false]);
    }
    return ['status' => 404, 'body' => '{"message":"not mocked ' . $path . '"}'];
});
$tick = function () {
    Clock::$fixed += 120;
    Scans::pollRunning(microtime(true) + 10);
};
$start = function (object $asset, string $profile = 'web') use ($who): object {
    Clock::$fixed += 120;
    $q = Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $asset->id)->first(), $profile, 0, $who['user_id']);
    Scans::dispatch(microtime(true) + 10);
    return Db::table('mod_mcsec_scans')->where('id', (int) ($q['scan_id'] ?? 0))->first();
};
$scan = fn (object $s) => Db::table('mod_mcsec_scans')->where('id', $s->id)->first();
$steps = fn (object $s) => array_map(fn ($e) => (string) $e->step, ScanLog::of((int) $s->id));
$posted = function (string $end) use (&$calls): int {
    return count(array_filter($calls, fn ($c) => $c[0] === 'POST' && str_ends_with($c[1], $end)));
};
admin('settings');
$adminPage = function (array $get): string {
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_GET = $get + ['module' => 'mcsec'];
    $_POST = [];
    return \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
};

section('a new target: discovery first, then the tools');
$pam = $mk('pam.example');
$bal = Credits::balance(1)['total'];
$s = $start($pam);
ok($s->status === 'running' && str_contains((string) $s->stage, 'شناخت دارایی') && $posted('/api/projects') === 0, 'the target was made just now: the tools are not started before its discovery');
$tick();
ok($posted('/run') === 0 && $scan($s)->status === 'running', 'discovery still running: still waiting');
$st['discovery_done'] = true;
$tick();
$m = json_decode((string) $scan($s)->backend_meta, true);
ok($posted('/api/projects') === 1 && $posted('/run') === 1 && ($m['run'] ?? '') === 'jh-1' && ($m['project'] ?? '') === 'proj-1' && empty($m['wait']), 'discovery ended: the pipeline starts and its run is remembered');

section('finished in OASM, but the scanner saw nothing: not a clean result');
$tick();
$f = $scan($s);
$sum = json_decode((string) $f->summary, true);
ok($f->status === 'completed' && str_contains((string) $f->stage, 'ناقص') && ($sum['partial'] ?? '') === Oasm::NO_SERVICE, 'no open port, no service, no finding: «ارزیابی ناقص» with the reason, never a clean «تمام شد»');
ok(Credits::balance(1)['total'] === $bal && ($sum['refunded'] ?? 0) === 10, 'the customer got nothing, so the credits went back');
ok(str_contains((string) Db::table('mod_mcsec_assets')->where('id', $pam->id)->value('partial'), 'IP اسکنر'), 'the asset is marked incomplete and says what to do (allow the scanner\'s IP)');
$ev = $sum['evidence'] ?? [];
ok(($ev['workspace'] ?? '') === 'ws-1' && ($ev['workspace_name'] ?? '') === 'mcsec-c1' && str_starts_with((string) ($ev['user'] ?? ''), 'mcsec-c1@') && ($ev['project'] ?? '') === 'proj-1' && ($ev['run'] ?? '') === 'jh-1'
    && ($ev['jobs'] ?? null) === 2 && ($ev['services'] ?? null) === 0 && ($ev['run_status'] ?? '') === 'completed', 'the proof is kept: workspace and its owner, target, project, run, jobs, what the scanner could reach');

section('the journal of a scan');
$log = ScanLog::of((int) $s->id);
ok(array_values(array_unique($steps($s))) === ['queue', 'start', 'poll', 'collect', 'alert'], 'queue, start, poll, collect, and an alert for the admin (' . implode(',', $steps($s)) . ')');
$startEv = array_values(array_filter($log, fn ($e) => $e->step === 'start'))[0];
$d = json_decode((string) $startEv->detail, true);
ok(count($d['calls']) >= 3 && $d['calls'][0]['path'] !== '' && isset($d['calls'][0]['status'], $d['calls'][0]['ms']) && !str_contains((string) $startEv->detail, 'svc-pass') && !str_contains((string) $startEv->detail, 'password'),
    'each engine call with its path, status and time; no request body and no secret');
ok(count(array_filter($steps($s), fn ($x) => $x === 'poll')) <= 4, 'a poll that changes nothing is not written');
$h = $adminPage(['mcsa' => 'scans', 'scan' => (string) $s->id]);
ok(str_contains($h, 'اسکن شماره‌ی ' . \McSec\Text::fa((int) $s->id)) && str_contains($h, 'mcsec-c1') && str_contains($h, 'ws-1') && str_contains($h, 'jh-1') && str_contains($h, 'proj-1') && str_contains($h, 'چرا ناقص؟'),
    'the admin page of the scan: where it lives in OASM and why it is incomplete');
ok(str_contains($h, 'در فهرست فضاهای کار خودتان دیده نمی‌شود') && str_contains($h, '/api/projects') && str_contains($h, 'لاگ این اسکن'), 'it explains why the admin does not see it in the console, and lists the calls');
$h = $adminPage(['mcsa' => 'scans']);
ok(str_contains($h, 'اسکن‌های نیازمند بررسی') && str_contains($h, 'scan=' . $s->id) && str_contains($h, 'تمام‌شده (۳۰ تای آخر)') && str_contains($h, 'name="scan"'), 'the scans page lists what needs a look, the finished ones, and finds a scan by number');
ok(str_contains($adminPage(['mcsa' => 'overview']), 'اسکن‌های نیازمند بررسی') && str_contains($adminPage(['mcsa' => 'overview']), 'mcsa-count'), 'the overview shows them and the tab carries a counter');
ok(str_contains($adminPage(['mcsa' => 'scans', 'scan' => '999999']), 'پیدا نشد'), 'an unknown number says so');

section('a real result stays a real result');
$st['services'] = [['id' => 's1', 'value' => 'shop.example:443', 'port' => 443]];
$st['vulns'] = [['id' => 'v1', 'name' => 'Missing header <script>alert(9)</script>', 'severity' => 'low', 'host' => 'shop.example', 'tool' => ['name' => 'zap']]];
$shop = $mk('shop.example');
Db::table('mod_mcsec_assets')->where('id', $shop->id)->update(['oasm_target' => 't-' . md5('shop.example')]);
$calls = [];
$s2 = $start($shop);
ok($posted('/run') === 1 && empty(json_decode((string) $s2->backend_meta, true)['wait']), 'a target OASM already knows: the tools start at once');
$tick();
$f2 = $scan($s2);
$sum2 = json_decode((string) $f2->summary, true);
ok($f2->status === 'completed' && $f2->stage === 'تمام شد' && !isset($sum2['partial']) && ($sum2['seen'] ?? 0) === 1 && ($sum2['evidence']['services'] ?? 0) === 1, 'services and a finding: a complete scan, with its proof');
ok(!in_array('alert', $steps($s2), true), 'no alert for a healthy scan');
ok(!str_contains($adminPage(['mcsa' => 'scans', 'scan' => (string) $s2->id]), '<script>alert(9)'), 'nothing from the scanned site is echoed raw');

section('no work at all, and an engine that fails');
$st['jobs'] = [];
$s3 = $start($shop, 'web');
$tick();
$sum3 = json_decode((string) $scan($s3)->summary, true);
ok(($sum3['partial'] ?? '') === Oasm::NO_WORK, 'the run has no job: «ارزیابی ناقص», the engine did nothing');
$st['jobs'] = [['status' => 'completed', 'category' => 'vulnerabilities']];
$st['run'] = 'in_progress';
$s4 = $start($shop, 'web');
$st['runs_500'] = true;
$tick();
$polls = array_values(array_filter(ScanLog::of((int) $s4->id), fn ($e) => $e->step === 'poll'));
$pd = json_decode((string) end($polls)->detail, true);
ok($polls && ($pd['calls'][0]['status'] ?? 0) === 500 && str_contains((string) ($pd['calls'][0]['answer'] ?? ''), 'boom'), 'a failed call is written with its status and a short piece of the answer');
$st['runs_500'] = false;
$st['run'] = 'none';
Clock::$fixed += 4 * 3600;
Scans::pollRunning(microtime(true) + 10);
$f4 = $scan($s4);
ok($f4->status === 'failed' && in_array('fail', $steps($s4), true) && in_array('alert', $steps($s4), true), 'the engine never started the run: failed, in the journal, with an alert');
ok(str_contains($adminPage(['mcsa' => 'scans', 'scan' => (string) $s4->id]), 'چرا ناموفق؟'), 'its page says why it failed');

section('alerts reach the admin\'s chat');
Settings::setSecret('bale_token', 'bt');
$sent = [];
$prev = \McSec\Http::$mock;
http_mock(function ($method, $url, $headers, $body) use (&$sent, $prev) {
    if (str_contains($url, '/sendMessage')) {
        $b = is_array($body) ? $body : (json_decode((string) $body, true) ?: []);
        $sent[] = $b;
        return ['status' => 200, 'body' => '{"ok":true}'];
    }
    if (str_contains($url, '/getUpdates')) {
        return ['status' => 200, 'body' => json_encode(['ok' => true, 'result' => [['update_id' => 1, 'message' => ['chat' => ['id' => 4242], 'text' => '/id']]]])];
    }
    return $prev($method, $url, $headers, $body);
});
$new = Db::table('mod_mcsec_scan_events')->where('step', 'alert')->where('level', 'new')->count();
ok($new >= 3 && ScanLog::deliverAlerts() === 0 && !$sent && Db::table('mod_mcsec_scan_events')->where('step', 'alert')->where('level', 'new')->count() === 0, 'no chat set: nothing is sent; the panel still lists them');
\McSec\Notify::linkBots();
ok(count($sent) === 1 && (string) $sent[0]['chat_id'] === '4242' && str_contains((string) $sent[0]['text'], '4242'), '/id in the bot answers the chat id, so the admin can fill the setting');
setting('ops_alert_bale', '4242');
$sent = [];
$st['run'] = 'completed';
$st['jobs'] = [];
$s5 = $start($shop, 'web');
$tick();
ok(ScanLog::deliverAlerts() === 1 && count($sent) === 1 && (string) $sent[0]['chat_id'] === '4242' && str_contains((string) $sent[0]['text'], 'اسکن شماره‌ی ' . $s5->id) && str_contains((string) $sent[0]['text'], 'shop.example'), 'with a chat set: one message with the scan number, the asset and where to look');
ok(ScanLog::deliverAlerts() === 0 && count($sent) === 1, 'sent once');
setting('ops_alerts', '0');
ok(!str_contains($adminPage(['mcsa' => 'overview']), 'اسکن‌های نیازمند بررسی'), 'switched off: the list is not shown');
setting('ops_alerts', '1');
Clock::$fixed += (ScanLog::KEEP_DAYS + 1) * 86400;
ok(ScanLog::purge() > 0 && !ScanLog::of((int) $s->id), 'journals older than ' . ScanLog::KEEP_DAYS . ' days are removed');

done();
