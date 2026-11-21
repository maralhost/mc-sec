<?php

declare(strict_types=1);

namespace McSec\Engines;

use McSec\Accounts;
use McSec\Catalog;
use McSec\Clock;
use McSec\Crypto;
use McSec\Db;
use McSec\Http;
use McSec\Kv;
use McSec\Settings;
use McSec\Trace;

/**
 * OASM (Open Attack Surface Management, github.com/oasm-platform/open-asm), checked live on v0.12.1:
 *  - auth: a service account signs in (POST /api/auth/sign-in/email, better-auth); the session cookie is kept
 *    encrypted in Kv and renewed on 401. The workspace API key does not open the REST endpoints.
 *  - isolation: one OASM workspace per WHMCS client (POST /api/workspaces), every call scoped with X-Workspace-Id.
 *  - targets: POST /api/targets/bulk (DOMAIN, IP, CIDR /24–/32); creating a target starts discovery by itself;
 *    POST /api/targets/{id}/re-scan runs it again.
 *  - vulnerability scan: nuclei through a project pipeline (POST /api/projects with tools[] and MC-Sec's settings,
 *    POST /api/projects/{id}/workflows/{binding}/run), checked live 2026-11-21. Not POST /api/vulnerabilities/scan.
 *  - progress: GET /api/targets/{id}/runs (discovery) or GET /api/projects/{id}/runs (pipeline: stepsDone/stepsTotal).
 *  - results: GET /api/assets (services host:port with HTTP response, tech, TLS), GET /api/vulnerabilities?targetId=.
 * OASM's own scheduler stays disabled (scanSchedule = disabled): MC-Sec schedules, charges and notifies.
 */
final class Oasm implements Engine
{
    /** The client whose OASM user the target/scan calls use (set from the asset in each entry point). */
    private int $cid = 0;

    public function key(): string
    {
        return 'oasm';
    }

    public function configured(): bool
    {
        return Settings::get('oasm_url') !== '' && Settings::get('oasm_email') !== '' && Settings::secret('oasm_password') !== '';
    }

    private function base(): string
    {
        return rtrim(Settings::get('oasm_url'), '/');
    }

    /**
     * One API call; logs in again once on 401. $clientId 0 = the service (admin) account, otherwise the client's own
     * OASM user (only a workspace's owner may create targets, and one user owns at most 5 workspaces).
     * @return array Http::request result
     */
    public function call(string $method, string $path, $body = null, string $workspace = '', int $timeout = 20, int $clientId = -1): array
    {
        $clientId = $clientId < 0 ? $this->cid : $clientId;
        $headers = ['Origin' => $this->base()];
        if ($workspace !== '') {
            $headers['X-Workspace-Id'] = $workspace;
        }
        $r = ['ok' => false, 'status' => 401, 'body' => '', 'json' => null, 'headers' => [], 'error' => 'OASM login failed', 'ms' => 0, 'url' => $path];
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $cookie = $this->session($clientId, $attempt > 0);
            if ($cookie === '') {
                return $r;
            }
            $r = Http::request($method, $this->base() . $path, $headers, $body, ['timeout' => $timeout, 'connect' => 6, 'verify' => Settings::bool('oasm_verify_tls'), 'cookie' => $cookie]);
            if ($r['status'] !== 401) {
                Http::circuitRecord('oasm', $r['status'] > 0 && $r['status'] < 500);
                return $r;
            }
        }
        return $r;
    }

    /** The session cookie of the service account (0) or of a client's OASM user, cached encrypted. */
    private function session(int $clientId, bool $fresh): string
    {
        $k = $clientId > 0 ? 'oasm:s:' . $clientId : 'oasm:session';
        if (!$fresh) {
            $c = Kv::get($k);
            if ($c !== null && $c !== '') {
                return Crypto::decrypt($c);
            }
        }
        if ($clientId > 0) {
            $acc = Accounts::get($clientId);
            [$email, $password] = [(string) ($acc->oasm_user ?? ''), Crypto::decrypt((string) ($acc->oasm_secret ?? ''))];
            if ($email === '' || $password === '') {
                return '';
            }
        } else {
            [$email, $password] = [Settings::get('oasm_email'), Settings::secret('oasm_password')];
        }
        $r = Http::request('POST', $this->base() . '/api/auth/sign-in/email', ['Origin' => $this->base()],
            ['email' => $email, 'password' => $password, 'rememberMe' => true], ['timeout' => 15, 'verify' => Settings::bool('oasm_verify_tls')]);
        $cookie = Http::cookies($r);
        if (!$r['ok'] || $cookie === '') {
            Trace::error('engine', 'oasm.login', 'OASM sign-in failed (' . ($clientId > 0 ? 'client ' . $clientId : 'service') . '): HTTP ' . $r['status'] . ' ' . $r['error'], ['body' => mb_substr($r['body'], 0, 300)]);
            Http::circuitRecord('oasm', false);
            return '';
        }
        Kv::set($k, Crypto::encrypt($cookie), 5 * 86400);
        return $cookie;
    }

    /** The client's own OASM user, created by the service account on first use. */
    public function user(int $clientId): void
    {
        $acc = Accounts::ensure($clientId);
        if ((string) $acc->oasm_user !== '' && (string) $acc->oasm_secret !== '') {
            return;
        }
        $domain = preg_replace('~[^a-z0-9.-]~', '', strtolower(Settings::get('oasm_user_domain'))) ?: 'mcsec.invalid';
        $email = 'mcsec-c' . $clientId . '@' . $domain;
        $password = Crypto::token(18);
        $r = $this->call('POST', '/api/auth/admin/create-user', ['email' => $email, 'name' => 'MC-Sec client ' . $clientId, 'password' => $password, 'role' => 'user'], '', 20, 0);
        if (!$r['ok']) {
            // already there from an earlier attempt whose answer was lost: reset its password through the admin API
            $u = $this->call('GET', '/api/auth/admin/list-users?searchField=email&searchOperator=contains&searchValue=' . rawurlencode($email), null, '', 20, 0);
            $id = '';
            foreach ((array) ($u['json']['users'] ?? []) as $row) {
                if (strtolower((string) ($row['email'] ?? '')) === $email) {
                    $id = (string) $row['id'];
                }
            }
            if ($id === '' || !$this->call('POST', '/api/auth/admin/set-user-password', ['userId' => $id, 'newPassword' => $password], '', 20, 0)['ok']) {
                throw new \RuntimeException('OASM user not created: HTTP ' . $r['status'] . ' ' . mb_substr($r['body'], 0, 200));
            }
        }
        Accounts::update($clientId, ['oasm_user' => $email, 'oasm_secret' => Crypto::encrypt($password)]);
    }

    /** The client's OASM workspace (owned by the client's OASM user), created on first use. */
    public function workspace(int $clientId): string
    {
        $acc = Accounts::ensure($clientId);
        if ((string) $acc->oasm_workspace !== '') {
            return (string) $acc->oasm_workspace;
        }
        $this->user($clientId);
        $r = $this->call('POST', '/api/workspaces', ['name' => 'mcsec-c' . $clientId, 'description' => 'MC-Sec client #' . $clientId], '', 20, $clientId);
        $id = (string) ($r['json']['id'] ?? $r['json']['data']['id'] ?? '');
        if ($id === '') {
            throw new \RuntimeException('OASM workspace not created: HTTP ' . $r['status'] . ' ' . mb_substr($r['body'], 0, 200));
        }
        // discovery of related assets on, auto-enable on (the target is the customer's verified scope)
        $this->call('PATCH', '/api/workspaces/configs', ['isAssetsDiscovery' => true, 'isAutoEnableAssetAfterDiscovered' => true], $id, 20, $clientId);
        Accounts::update($clientId, ['oasm_workspace' => $id]);
        return $id;
    }

    /** The OASM target of an asset: created (starting discovery) or found. @return array{id:string,created:bool} */
    public function target(object $asset, string $ws): array
    {
        $this->cid = (int) $asset->client_id;
        if ((string) $asset->oasm_target !== '') {
            $chk = $this->call('GET', '/api/targets/' . rawurlencode((string) $asset->oasm_target), null, $ws);
            if ($chk['ok']) {
                return ['id' => (string) $asset->oasm_target, 'created' => false];
            }
        }
        $type = ['domain' => 'DOMAIN', 'ip' => 'IP', 'cidr' => 'CIDR'][$asset->kind] ?? 'DOMAIN';
        $r = $this->call('POST', '/api/targets/bulk', ['targets' => [['value' => (string) $asset->value, 'type' => $type]]], $ws);
        $created = $r['json']['created'][0]['id'] ?? '';
        if ($created !== '') {
            Db::table('mod_mcsec_assets')->where('id', $asset->id)->update(['oasm_target' => (string) $created]);
            return ['id' => (string) $created, 'created' => true];
        }
        $find = $this->call('GET', '/api/targets?limit=5&value=' . rawurlencode((string) $asset->value), null, $ws);
        foreach ((array) ($find['json']['data'] ?? []) as $t) {
            if (strtolower((string) ($t['value'] ?? '')) === strtolower((string) $asset->value)) {
                Db::table('mod_mcsec_assets')->where('id', $asset->id)->update(['oasm_target' => (string) $t['id']]);
                return ['id' => (string) $t['id'], 'created' => false];
            }
        }
        throw new \RuntimeException('OASM target not created: HTTP ' . $r['status'] . ' ' . mb_substr($r['body'], 0, 200));
    }

    public function start(object $scan, object $asset, array $profile): array
    {
        $this->cid = (int) $asset->client_id;
        if (Http::circuitOpen('oasm')) {
            return ['ok' => false, 'error' => 'OASM موقتاً در دسترس نیست', 'retry' => true];
        }
        try {
            $ws = $this->workspace((int) $asset->client_id);
            $t = $this->target($asset, $ws);
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => mb_substr($e->getMessage(), 0, 200), 'retry' => true];
        }
        $since = gmdate('Y-m-d\TH:i:s\Z', Clock::now() - 30);
        $tools = array_values(array_filter(array_map('strval', (array) ($profile['tools'] ?? [])), fn ($n) => isset(Catalog::TOOLS[$n])));
        $kind = $tools ? 'pipeline' : 'discovery';
        if ($tools) {
            // tools run through a project pipeline with MC-Sec's own settings: OASM's built-in vulnerability scan uses
            // its defaults (150 requests a second, interactsh on), which gets the scanner banned by the target
            $steps = [];
            foreach ($tools as $i => $name) {
                $def = Catalog::TOOLS[$name];
                if (!in_array((string) $asset->kind, $def['kinds'], true)) {
                    return ['ok' => false, 'retry' => false, 'error' => $def['label'] . ' does not accept a ' . $asset->kind . ' target'];
                }
                if (isset($def['needs']) && Settings::secret($def['needs']) === '') {
                    return ['ok' => false, 'retry' => false, 'error' => $def['label'] . ' is not set up (setting ' . $def['needs'] . ' is empty)'];
                }
                $n = $this->tool($ws, $name, true);
                if (!$n['known'] || !$n['installed']) {
                    return ['ok' => false, 'retry' => false, 'error' => 'OASM cannot run ' . $name . ': ' . (!$n['known'] ? 'tool list not readable or tool missing' : 'not installed in workspace')];
                }
                $steps[] = ['toolId' => $n['id'], 'category' => $def['category'], 'input' => $def['input'], 'stage' => $i + 1, 'config' => self::toolConfig($name)];
            }
            try {
                $run = $this->runPipeline($asset, $ws, $t['id'], (string) $profile['key'], $steps);
            } catch (\Throwable $e) {
                return ['ok' => false, 'error' => mb_substr($e->getMessage(), 0, 200), 'retry' => true];
            }
            return ['ok' => true, 'ref' => $t['id'], 'meta' => ['ws' => $ws, 'since' => $since, 'kind' => $kind, 'tools' => $tools, 'project' => $run['project'], 'run' => $run['run']], 'progress' => 1, 'stage' => 'در صف موتور OASM'];
        } elseif (!$t['created']) {
            $r = $this->call('POST', '/api/targets/' . rawurlencode($t['id']) . '/re-scan', null, $ws);
        } else {
            $r = ['ok' => true, 'status' => 201, 'body' => ''];
        }
        if (!$r['ok']) {
            return ['ok' => false, 'error' => 'OASM: HTTP ' . $r['status'] . ' ' . mb_substr((string) $r['body'], 0, 160), 'retry' => $r['status'] === 0 || $r['status'] >= 500];
        }
        return ['ok' => true, 'ref' => $t['id'], 'meta' => ['ws' => $ws, 'since' => $since, 'kind' => $kind], 'progress' => 1, 'stage' => 'در صف موتور OASM'];
    }

    /**
     * A connector tool (nuclei, zap, …) in a workspace. With $prepare it is installed and given a default config
     * profile when missing: OASM calls a connector "ready" only once a profile exists (seen live, 0.12.1).
     * availableWorkersCount is NOT used: OASM reports 0 for every connector even while a node worker runs them.
     * @return array{known:bool,installed:bool,ready:bool,id:string}
     */
    public function tool(string $ws, string $name, bool $prepare, int $clientId = -1): array
    {
        $none = ['known' => false, 'installed' => false, 'ready' => false, 'id' => ''];
        $r = $this->call('GET', '/api/tools?limit=100', null, $ws, 20, $clientId);
        if (!$r['ok']) {
            return $none;
        }
        foreach ((array) ($r['json']['data'] ?? []) as $t) {
            if (strtolower((string) ($t['name'] ?? '')) !== $name || (string) ($t['id'] ?? '') === '') {
                continue;
            }
            $id = (string) $t['id'];
            $installed = !empty($t['isInstalled']);
            $ready = !empty($t['isReady']);
            if ($prepare && !$installed) {
                $installed = $this->call('POST', '/api/tools/install', ['toolId' => $id], $ws, 20, $clientId)['ok'];
            }
            if ($prepare && $installed) {
                $ready = $this->profile($ws, $id, $name, !empty($t['hasConfigProfile']), $clientId) || $ready;
            }
            return ['known' => true, 'installed' => $installed, 'ready' => $ready, 'id' => $id];
        }
        return $none;
    }

    /**
     * The default config profile of a tool in a workspace (name "MC-Sec"): MC-Sec's settings plus the tool's secrets
     * (Acunetix URL and key, WPScan token), which stay in the profile and never go into a pipeline. Written again only
     * when the settings changed (hash in Kv), so a rotated key reaches every workspace at its next scan.
     */
    private function profile(string $ws, string $toolId, string $name, bool $has, int $clientId): bool
    {
        $config = self::toolConfig($name) + self::toolSecrets($name);
        $hash = sha1((string) json_encode($config));
        $key = 'oasm:tp:' . substr(sha1($ws . '|' . $toolId), 0, 24);
        if ($has && Kv::get($key) === $hash) {
            return true;
        }
        $base = '/api/tools/' . rawurlencode($toolId) . '/config-profiles';
        $ok = false;
        if ($has) {
            foreach ((array) ($this->call('GET', $base, null, $ws, 20, $clientId)['json'] ?? []) as $p) {
                if (is_array($p) && (string) ($p['name'] ?? '') === 'MC-Sec' && (string) ($p['id'] ?? '') !== '') {
                    $ok = $this->call('PATCH', $base . '/' . rawurlencode((string) $p['id']), ['config' => $config], $ws, 20, $clientId)['ok'];
                }
            }
            if (!$ok && Kv::get($key) === null) {
                $ok = true; // a profile made by an operator in OASM: left as it is
            }
        }
        if (!$ok && !$has) {
            $ok = $this->call('POST', $base, ['name' => 'MC-Sec', 'isDefault' => true, 'config' => $config], $ws, 20, $clientId)['ok'];
        }
        if ($ok) {
            Kv::set($key, $hash);
        }
        return $ok;
    }

    /**
     * MC-Sec's settings for a tool, gentle by default: one request rate for every tool that has one (setting
     * nuclei_rate), no out-of-band probes, no dos/fuzz/intrusive templates, ZAP in baseline mode (spider and passive
     * checks, no active attack). An admin may override single keys per tool in the setting tool_configs.
     */
    public static function toolConfig(string $name): array
    {
        $rate = max(1, min(150, Settings::int('nuclei_rate')));
        $c = match ($name) {
            'nuclei' => [
                'concurrency' => max(1, min(50, Settings::int('nuclei_concurrency'))), 'rateLimit' => $rate,
                'interactsh' => Settings::bool('nuclei_interactsh'), 'excludeTags' => array_values(array_filter(Settings::csv('nuclei_exclude_tags'), fn ($t) => preg_match('~^[a-z0-9_-]{1,40}$~i', $t) === 1)),
                'followRedirects' => false, 'severity' => ['info', 'low', 'medium', 'high', 'critical'],
            ],
            'katana' => ['rateLimit' => $rate, 'concurrency' => 5, 'parallelism' => 2, 'depth' => 3, 'maxUrls' => 2000, 'crawlDuration' => 600, 'jsCrawl' => true],
            'zap' => ['scanMode' => 'baseline', 'maxSpiderDuration' => 5, 'maxSpiderDepth' => 5, 'threadPerHost' => 2],
            'gau' => ['threads' => 2, 'subs' => false],
            'nmap' => ['topPorts' => 1000, 'noPing' => true, 'retries' => 1, 'hostTimeout' => 600],
            'ffuf' => ['rate' => $rate, 'threads' => 5, 'wordlist' => 'common', 'maxTime' => 600, 'maxUrls' => 2000, 'autoCalibration' => true],
            'wpscan' => ['detectionMode' => 'passive', 'pluginsDetection' => 'passive', 'maxThreads' => 2],
            'acunetix' => ['criticality' => 10, 'maxScanTime' => 240],
            default => [],
        };
        $over = Settings::json('tool_configs')[$name] ?? null;
        foreach (is_array($over) ? $over : [] as $k => $v) {
            // secrets and addresses are settings of their own; anything else an admin may tune
            if (is_string($k) && preg_match('~^[A-Za-z][A-Za-z0-9]{1,40}$~', $k) && !in_array($k, ['apiKey', 'apiToken', 'url', 'proxy', 'headers', 'cookieString', 'httpAuth'], true) && (is_scalar($v) || is_array($v))) {
                $c[$k] = $v;
            }
        }
        return $c;
    }

    /** Secrets and addresses a tool needs, for its config profile only. */
    private static function toolSecrets(string $name): array
    {
        return match ($name) {
            'acunetix' => ['url' => rtrim(Settings::get('acunetix_url'), '/'), 'apiKey' => Settings::secret('acunetix_key'), 'disableTlsChecks' => !Settings::bool('acunetix_verify_tls')],
            'wpscan' => ['apiToken' => Settings::secret('wpscan_token')],
            default => [],
        };
    }

    /**
     * Runs a profile's tools on one target through an OASM project (the only place where a pipeline with its own tool
     * settings can be run on demand; checked live with katana → nuclei + zap). The project of an asset and profile is
     * kept (Kv) and reused; when the tools or settings changed it is archived and a new one made.
     * @param array<int,array{toolId:string,category:string,input:array,stage:int,config:array}> $steps
     * @return array{project:string,run:string}
     */
    private function runPipeline(object $asset, string $ws, string $targetId, string $kind, array $steps): array
    {
        $hash = substr(sha1($targetId . '|' . json_encode($steps)), 0, 16);
        $key = 'oasm:pl:' . (int) $asset->id . ':' . $kind;
        $pl = Kv::json($key);
        if (($pl['hash'] ?? '') === $hash && ($pl['project'] ?? '') !== '' && ($pl['binding'] ?? '') !== '') {
            $r = $this->call('POST', '/api/projects/' . rawurlencode($pl['project']) . '/workflows/' . rawurlencode($pl['binding']) . '/run', null, $ws);
            if ($r['ok'] && (string) ($r['json']['jobHistoryId'] ?? '') !== '') {
                return ['project' => (string) $pl['project'], 'run' => (string) $r['json']['jobHistoryId']];
            }
            if ($r['status'] === 0 || $r['status'] >= 500) {
                throw new \RuntimeException('OASM pipeline run: HTTP ' . $r['status']);
            }
            // the project was removed in OASM: make it again below
        } elseif (($pl['project'] ?? '') !== '') {
            $this->call('POST', '/api/projects/' . rawurlencode((string) $pl['project']) . '/archive', null, $ws);
        }
        $c = $this->call('POST', '/api/projects', [
            'name' => mb_substr('mcsec a' . (int) $asset->id . ' ' . $kind . ' ' . $asset->value, 0, 80), 'description' => 'MC-Sec ' . $kind . ' pipeline',
            'scopeRules' => [['mode' => 'include', 'type' => 'target', 'value' => $targetId]], 'autoAddAssets' => true,
            'tools' => $steps,
            'workflowName' => 'MC-Sec ' . $kind,
        ], $ws, 30);
        $pid = (string) ($c['json']['id'] ?? '');
        if (!$c['ok'] || $pid === '') {
            throw new \RuntimeException('OASM project not created: HTTP ' . $c['status'] . ' ' . mb_substr((string) $c['body'], 0, 160));
        }
        $g = $this->call('GET', '/api/projects/' . rawurlencode($pid), null, $ws);
        $bid = (string) ($g['json']['projectWorkflows'][0]['id'] ?? '');
        if ($bid === '') {
            throw new \RuntimeException('OASM project has no pipeline: HTTP ' . $g['status']);
        }
        Kv::setJson($key, ['project' => $pid, 'binding' => $bid, 'hash' => $hash]);
        $r = $this->call('POST', '/api/projects/' . rawurlencode($pid) . '/workflows/' . rawurlencode($bid) . '/run', null, $ws);
        $run = (string) ($r['json']['jobHistoryId'] ?? '');
        if (!$r['ok'] || $run === '') {
            throw new \RuntimeException('OASM pipeline run: HTTP ' . $r['status'] . ' ' . mb_substr((string) $r['body'], 0, 160));
        }
        return ['project' => $pid, 'run' => $run];
    }

    /** The project run a scan started, or null while OASM does not list it. */
    private function pipelineRun(array $m, int $timeout = 8): ?array
    {
        $r = $this->call('GET', '/api/projects/' . rawurlencode((string) $m['project']) . '/runs?limit=20', null, (string) ($m['ws'] ?? ''), $timeout);
        foreach ($r['ok'] ? (array) ($r['json']['data'] ?? []) : [] as $run) {
            if ((string) ($run['id'] ?? '') === (string) $m['run']) {
                return $run;
            }
        }
        return $r['ok'] ? [] : null;
    }

    /**
     * True when the jobs of a run ended because the target stopped answering the scanner (its firewall or web
     * protection banned the scanner's IP: seen live, within seconds, even at 10 requests a second).
     */
    private function blockedByTarget(array $m): bool
    {
        $r = $this->call('GET', '/api/jobs-registry?jobHistoryId=' . rawurlencode((string) $m['run']) . '&limit=20', null, (string) ($m['ws'] ?? ''), 15);
        foreach ((array) ($r['json']['data'] ?? []) as $job) {
            foreach ((array) ($job['errorLogs'] ?? []) as $log) {
                $msg = strtolower(substr((string) ($log['logMessage'] ?? ''), 0, 400));
                if (str_contains($msg, 'marked unresponsive') || str_contains($msg, 'target reachability')) {
                    return true;
                }
            }
        }
        return false;
    }

    public const BLOCKED = 'هدف هنگام اسکن دیگر پاسخ نداد؛ به احتمال زیاد فایروال یا محافظ وب سرور، IP اسکنر را مسدود کرده است. IP اسکنر را در آن مجاز کنید و دوباره اسکن بگیرید.';

    public function poll(object $scan, object $asset, array $profile): array
    {
        $this->cid = (int) $asset->client_id;
        $m = json_decode((string) $scan->backend_meta, true) ?: [];
        $ws = (string) ($m['ws'] ?? '');
        if (($m['run'] ?? '') !== '' && ($m['project'] ?? '') !== '') {
            $run = $this->pipelineRun($m);
            if ($run === null) {
                return ['status' => 'running', 'stage' => 'در انتظار پاسخ OASM'];
            }
            if (!$run) {
                return Clock::now() - (int) $scan->started_at > 3 * 3600 ? ['status' => 'failed', 'error' => 'OASM کار را شروع نکرد'] : ['status' => 'running', 'progress' => 2, 'stage' => 'در صف موتور OASM'];
            }
            if (!empty($run['isCompleted'])) {
                // "failed" because the target banned the scanner is an incomplete assessment (collect says why), not a broken scan
                $bad = in_array((string) ($run['status'] ?? ''), ['failed', 'cancelled'], true) && (int) ($run['stepsDone'] ?? 0) === 0;
                return $bad && !$this->blockedByTarget($m) ? ['status' => 'failed', 'error' => 'OASM: ' . $run['status']] : ['status' => 'completed', 'progress' => 100, 'stage' => 'تمام شد'];
            }
            $total = (int) ($run['stepsTotal'] ?? 0);
            $names = implode('، ', array_map(fn ($n) => Catalog::TOOLS[$n]['label'] ?? $n, (array) ($m['tools'] ?? ['nuclei'])));
            return ['status' => 'running', 'progress' => max(3, $total > 0 ? (int) min(95, floor(100 * (int) ($run['stepsDone'] ?? 0) / $total)) : 5),
                'stage' => 'در حال اجرا: ' . $names . ($total > 1 ? ' (گام ' . ((int) ($run['stepsDone'] ?? 0) + 1) . ' از ' . $total . ')' : '')];
        }
        $r = $this->call('GET', '/api/targets/' . rawurlencode((string) $scan->backend_ref) . '/runs?limit=10&sortOrder=DESC', null, $ws, 8);
        if (!$r['ok']) {
            return ['status' => 'running', 'stage' => 'در انتظار پاسخ OASM'];
        }
        $since = strtotime((string) ($m['since'] ?? '')) ?: (int) $scan->started_at;
        $runs = [];
        foreach ((array) ($r['json']['data'] ?? []) as $run) {
            $created = strtotime((string) ($run['createdAt'] ?? '')) ?: 0;
            $name = strtolower((string) ($run['workflowName'] ?? ''));
            $isVuln = str_contains($name, 'vulnerab') || str_contains($name, 'nuclei');
            if ($created >= $since && in_array($m['kind'] ?? '', ['vuln', 'pipeline'], true) === $isVuln) {
                $runs[] = $run;
            }
        }
        if (!$runs) {
            // nothing picked up yet; OASM workers may be busy
            $waited = Clock::now() - (int) $scan->started_at;
            return $waited > 3 * 3600 ? ['status' => 'failed', 'error' => 'OASM کار را شروع نکرد'] : ['status' => 'running', 'progress' => 2, 'stage' => 'در صف موتور OASM'];
        }
        $total = 0;
        $done = 0;
        $tool = '';
        $allDone = true;
        $failed = 0;
        foreach ($runs as $run) {
            $total += (int) ($run['jobsTotal'] ?? 0);
            $done += (int) ($run['jobsDone'] ?? 0);
            $failed += (int) ($run['jobsFailed'] ?? 0);
            $tool = $tool !== '' ? $tool : (string) ($run['currentTool'] ?? '');
            $allDone = $allDone && !empty($run['isCompleted']);
        }
        $status = (string) ($runs[0]['status'] ?? '');
        if ($allDone) {
            if (in_array($status, ['failed', 'cancelled'], true) && $done === 0) {
                return ['status' => 'failed', 'error' => 'OASM: ' . $status];
            }
            return ['status' => 'completed', 'progress' => 100, 'stage' => 'تمام شد'];
        }
        $pct = $total > 0 ? (int) min(95, floor(100 * $done / $total)) : 5;
        return ['status' => 'running', 'progress' => max(3, $pct), 'stage' => $tool !== '' ? 'در حال اجرا: ' . $tool : 'در حال اجرا'];
    }

    public function collect(object $scan, object $asset, array $profile): array
    {
        $this->cid = (int) $asset->client_id;
        $m = json_decode((string) $scan->backend_meta, true) ?: [];
        $ws = (string) ($m['ws'] ?? '');
        $tid = (string) $scan->backend_ref;
        $surface = [];
        $hosts = [];
        $shots = [];
        for ($page = 1; $page <= 10; $page++) {
            $r = $this->call('GET', '/api/assets?targetIds=' . rawurlencode($tid) . '&limit=100&page=' . $page, null, $ws, 30);
            if (!$r['ok']) {
                throw new \RuntimeException('OASM assets: HTTP ' . $r['status']);
            }
            foreach ((array) ($r['json']['data'] ?? []) as $a) {
                $value = (string) ($a['value'] ?? '');
                $host = preg_replace('~:\d+$~', '', $value) ?? $value;
                if ($host !== '' && !isset($hosts[$host])) {
                    $hosts[$host] = true;
                    $surface[] = ['kind' => 'host', 'value' => $host, 'meta' => ['ips' => array_slice((array) ($a['ipAddresses'] ?? []), 0, 8)]];
                }
                // httpx tries every open port; a failed probe (SSH on 22, seen live) still carries a made-up http:// URL
                $hr = is_array($a['httpResponses'] ?? null) && empty($a['httpResponses']['failed']) ? $a['httpResponses'] : [];
                if (is_string($a['screenshotPath'] ?? null) && $a['screenshotPath'] !== '' && count($shots) < 20) {
                    $shots[] = ['host' => $host, 'port' => (int) ($a['port'] ?? 0), 'path' => $a['screenshotPath']];
                }
                if (!empty($a['port'])) {
                    $surface[] = ['kind' => 'port', 'value' => $host . ':' . (int) $a['port'], 'meta' => array_filter([
                        'title' => mb_substr((string) ($hr['title'] ?? ''), 0, 120), 'server' => (string) ($hr['webserver'] ?? ''), 'status' => (int) ($hr['status_code'] ?? 0),
                        'url' => (string) ($hr['url'] ?? ''), 'scheme' => (string) ($hr['scheme'] ?? ''),
                    ])];
                }
                foreach ((array) ($hr['tech'] ?? []) as $tech) {
                    $surface[] = ['kind' => 'tech', 'value' => mb_substr(is_array($tech) ? (string) ($tech['name'] ?? '') : (string) $tech, 0, 120), 'meta' => ['host' => $host]];
                }
                if (is_array($hr['tls'] ?? null) && !empty($hr['tls'])) {
                    $tls = $hr['tls'];
                    $surface[] = ['kind' => 'cert', 'value' => $host . ':' . (int) ($a['port'] ?? 443), 'meta' => [
                        'not_after' => substr((string) ($tls['not_after'] ?? ''), 0, 10), 'issuer' => mb_substr((string) ($tls['issuer_dn'] ?? $tls['issuer_cn'] ?? ''), 0, 120),
                        'cn' => (string) ($tls['subject_cn'] ?? ''), 'proto' => (string) ($tls['tls_version'] ?? ''),
                    ]];
                }
            }
            if (empty($r['json']['hasNextPage'])) {
                break;
            }
        }
        $findings = [];
        $piped = in_array($m['kind'] ?? '', ['vuln', 'pipeline'], true);
        $mine = array_map('strtolower', (array) ($m['tools'] ?? ['nuclei']));
        if ($piped) {
            for ($page = 1; $page <= 20; $page++) {
                $r = $this->call('GET', '/api/vulnerabilities?targetId=' . rawurlencode($tid) . '&limit=100&page=' . $page, null, $ws, 30);
                if (!$r['ok']) {
                    throw new \RuntimeException('OASM vulnerabilities: HTTP ' . $r['status']);
                }
                foreach ((array) ($r['json']['data'] ?? []) as $v) {
                    // the target's list holds every tool's findings: each profile owns the findings of its own tools
                    $by = strtolower((string) (is_array($v['tool'] ?? null) ? ($v['tool']['name'] ?? '') : ''));
                    if ($by === '' || in_array($by, $mine, true)) {
                        $findings[] = self::normalize($v);
                    }
                }
                if (empty($r['json']['hasNextPage'])) {
                    break;
                }
            }
        }
        $out = ['findings' => $findings, 'surface' => $surface, 'kinds' => $piped ? [] : ['host', 'port'], 'complete' => true, 'shots' => $shots];
        if (($m['run'] ?? '') !== '' && ($m['project'] ?? '') !== '') {
            // a run the target cut short saw nothing: say so, and never mark earlier findings fixed because of it
            $run = $this->pipelineRun($m, 20) ?? [];
            $blocked = in_array((string) ($run['status'] ?? ''), ['failed', 'cancelled'], true) && $this->blockedByTarget($m);
            $out['partial'] = $blocked ? self::BLOCKED : '';
            $out['complete'] = !$blocked && (string) ($run['status'] ?? '') === 'completed';
        }
        return $out;
    }

    /** One OASM vulnerability → MC-Sec finding. */
    public static function normalize(array $v): array
    {
        $name = (string) ($v['name'] ?? 'Finding');
        $ports = array_values(array_filter((array) ($v['ports'] ?? [])));
        $loc = (string) ($v['affectedUrl'] ?? '');
        if ($loc === '') {
            $loc = (string) ($v['host'] ?? $v['ipAddress'] ?? '') . ($ports ? ':' . $ports[0] : '');
        }
        $evidence = array_slice(array_map('strval', (array) ($v['extractedResults'] ?? [])), 0, 10);
        $tags = array_slice(array_map('strval', (array) ($v['tags'] ?? [])), 0, 10);
        $tool = is_array($v['tool'] ?? null) ? (string) ($v['tool']['name'] ?? '') : '';
        return [
            'key' => 'oasm.' . strtolower(preg_replace('~[^A-Za-z0-9]+~', '-', (string) (($v['cveId'][0] ?? '') ?: $name)) ?? 'x'),
            'title' => $name, 'severity' => (string) ($v['severity'] ?? 'info'), 'location' => $loc,
            'description' => (string) ($v['description'] ?? $v['synopsis'] ?? ''), 'evidence' => $evidence ? implode("\n", $evidence) : '',
            'solution' => (string) ($v['solution'] ?? ''), 'refs' => array_slice(array_map('strval', (array) ($v['references'] ?? [])), 0, 10),
            'cve' => (array) ($v['cveId'] ?? []), 'cwe' => (array) ($v['cweId'] ?? []), 'cvss' => $v['cvssScore'] ?? null, 'epss' => $v['epssScore'] ?? null,
            'tags' => array_merge($tags, $tool !== '' ? [$tool] : []),
        ];
    }

    public function cancel(object $scan, object $asset): bool
    {
        $this->cid = (int) $asset->client_id;
        $m = json_decode((string) $scan->backend_meta, true) ?: [];
        if (($m['run'] ?? '') !== '') {
            return $this->call('POST', '/api/jobs-registry/histories/' . rawurlencode((string) $m['run']) . '/cancel', null, (string) ($m['ws'] ?? ''), 8)['ok'];
        }
        $r = $this->call('GET', '/api/targets/' . rawurlencode((string) $scan->backend_ref) . '/runs?limit=5&active=true', null, (string) ($m['ws'] ?? ''), 8);
        $ok = true;
        foreach ((array) ($r['json']['data'] ?? []) as $run) {
            if (empty($run['isCompleted']) && !empty($run['id'])) {
                $c = $this->call('POST', '/api/jobs-registry/histories/' . rawurlencode((string) $run['id']) . '/cancel', null, (string) ($m['ws'] ?? ''), 8);
                $ok = $ok && $c['ok'];
            }
        }
        return $ok;
    }

    public function health(): array
    {
        if (!$this->configured()) {
            return ['ok' => false, 'message' => 'آدرس، حساب سرویس یا رمز OASM تنظیم نشده است.'];
        }
        $h = Http::request('GET', $this->base() . '/api/health', [], null, ['timeout' => 8, 'verify' => Settings::bool('oasm_verify_tls')]);
        if ($h['status'] !== 200) {
            return ['ok' => false, 'message' => 'OASM پاسخ نداد: ' . ($h['error'] !== '' ? $h['error'] : 'HTTP ' . $h['status']), 'ms' => $h['ms']];
        }
        $meta = Http::request('GET', $this->base() . '/api/metadata', [], null, ['timeout' => 8, 'verify' => Settings::bool('oasm_verify_tls')]);
        $ver = (string) ($meta['json']['currentVersion'] ?? '');
        $w = $this->call('GET', '/api/workspaces?limit=1&page=1', null, '', 20, 0);
        if (!$w['ok']) {
            return ['ok' => false, 'message' => 'OASM در دسترس است ولی ورود حساب سرویس انجام نشد (HTTP ' . $w['status'] . ').', 'version' => $ver, 'ms' => $h['ms']];
        }
        $msg = 'OASM ' . $ver . ' در دسترس است و حساب سرویس وارد شد؛ کشف سطح حمله آماده است.';
        $sws = (string) ($w['json']['data'][0]['id'] ?? '');
        $n = $sws !== '' ? $this->tool($sws, 'nuclei', false, 0) : ['known' => false, 'installed' => false, 'ready' => false, 'id' => ''];
        $online = 0;
        if ($sws !== '') {
            foreach ((array) ($this->call('GET', '/api/workers?scope=cloud&limit=50', null, $sws, 20, 0)['json']['data'] ?? []) as $wk) {
                $online += !empty($wk['isOnline']) ? 1 : 0;
            }
        }
        $msg .= ' کارگر آنلاین: ' . \McSec\Text::fa($online) . '.';
        if ($online < 1) {
            $msg .= ' هیچ کارگری آنلاین نیست؛ اسکن‌ها در صف OASM می‌مانند.';
        } elseif ($n['known']) {
            $msg .= ' nuclei در فهرست ابزارهاست؛ برای اجرای آن (و هر ابزار نصب‌شدنی) دست‌کم یک کارگر باید در حالت node با Docker باشد. MC-Sec آن را در فضای هر مشتری خودکار نصب و با تنظیم ملایم اجرا می‌کند.';
        } else {
            $msg .= ' nuclei در فهرست ابزارهای OASM پیدا نشد؛ «اسکن آسیب‌پذیری» اجرا نمی‌شود.';
        }
        return ['ok' => true, 'message' => $msg, 'version' => $ver, 'ms' => $h['ms'], 'vuln' => $sws === '' ? null : ($n['known'] && $online > 0), 'workers' => $online];
    }
}
