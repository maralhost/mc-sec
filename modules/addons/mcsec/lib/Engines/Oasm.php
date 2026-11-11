<?php

declare(strict_types=1);

namespace McSec\Engines;

use McSec\Accounts;
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
 *    POST /api/targets/{id}/re-scan runs it again; POST /api/vulnerabilities/scan runs nuclei (vulnerability_scan_basic).
 *  - progress: GET /api/targets/{id}/runs (status, jobsDone/jobsTotal, currentTool).
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
        $kind = $profile['key'] === 'vuln' ? 'vuln' : 'discovery';
        if ($kind === 'vuln') {
            $r = $this->call('POST', '/api/vulnerabilities/scan', ['targetIds' => [$t['id']]], $ws);
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

    public function poll(object $scan, object $asset, array $profile): array
    {
        $this->cid = (int) $asset->client_id;
        $m = json_decode((string) $scan->backend_meta, true) ?: [];
        $ws = (string) ($m['ws'] ?? '');
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
            if ($created >= $since && (($m['kind'] ?? '') === 'vuln') === $isVuln) {
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
                $hr = is_array($a['httpResponses'] ?? null) ? $a['httpResponses'] : [];
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
        if (($m['kind'] ?? '') === 'vuln') {
            for ($page = 1; $page <= 20; $page++) {
                $r = $this->call('GET', '/api/vulnerabilities?targetId=' . rawurlencode($tid) . '&limit=100&page=' . $page, null, $ws, 30);
                if (!$r['ok']) {
                    throw new \RuntimeException('OASM vulnerabilities: HTTP ' . $r['status']);
                }
                foreach ((array) ($r['json']['data'] ?? []) as $v) {
                    $findings[] = self::normalize($v);
                }
                if (empty($r['json']['hasNextPage'])) {
                    break;
                }
            }
        }
        return ['findings' => $findings, 'surface' => $surface, 'kinds' => ($m['kind'] ?? '') === 'vuln' ? [] : ['host', 'port'], 'complete' => true];
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
        return ['ok' => true, 'message' => 'OASM ' . $ver . ' در دسترس است و حساب سرویس وارد شد.', 'version' => $ver, 'ms' => $h['ms']];
    }
}
