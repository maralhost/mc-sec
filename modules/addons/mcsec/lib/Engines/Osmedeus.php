<?php

declare(strict_types=1);

namespace McSec\Engines;

use McSec\Clock;
use McSec\Crypto;
use McSec\Http;
use McSec\Kv;
use McSec\Settings;
use McSec\Trace;

/**
 * Osmedeus v5 (github.com/j3ssie/osmedeus), from the v5.1.2 source (docs/research/osmedeus-api.md):
 *  - auth: header x-osm-api-key (preferred), else POST /osm/api/login → JWT (24 h), renewed on 401;
 *  - start: POST /osm/api/runs {flow, target, params.space_name} → run_uuid. space_name = mcsec-c<client>-a<asset>
 *    keeps every customer's results in its own Osmedeus workspace;
 *  - progress: GET /osm/api/runs/{uuid} (status, completed_steps/total_steps);
 *  - results: GET /osm/api/assets?workspace= and /osm/api/vulnerabilities?workspace= (filtered to what this run saw by
 *    last_seen_at), nuclei JSON in raw_vuln_json;
 *  - cancel: DELETE /osm/api/runs/{uuid} (a cancelled run may end as failed "context canceled").
 * Osmedeus has no queue: Scans enforces concurrency_osm. Targets are validated before submitting (no shell
 * metacharacters; domain flows get domains, IPs and ranges go to the cidr flow).
 */
final class Osmedeus implements Engine
{
    private const FORBIDDEN = " ;'\"|&`$(){}[]";

    public function key(): string
    {
        return 'osmedeus';
    }

    public function configured(): bool
    {
        return Settings::get('osm_url') !== '' && (Settings::secret('osm_api_key') !== '' || Settings::secret('osm_password') !== '');
    }

    private function base(): string
    {
        return rtrim(Settings::get('osm_url'), '/');
    }

    public function call(string $method, string $path, $body = null, int $timeout = 20): array
    {
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $headers = [];
            $key = Settings::secret('osm_api_key');
            if ($key !== '') {
                $headers['x-osm-api-key'] = $key;
            } else {
                $jwt = $this->jwt($attempt > 0);
                if ($jwt === '') {
                    return ['ok' => false, 'status' => 401, 'body' => '', 'json' => null, 'headers' => [], 'error' => 'Osmedeus login failed', 'ms' => 0, 'url' => $path];
                }
                $headers['Authorization'] = 'Bearer ' . $jwt;
            }
            $r = Http::request($method, $this->base() . '/osm/api' . $path, $headers, $body, ['timeout' => $timeout, 'connect' => 6, 'verify' => Settings::bool('osm_verify_tls')]);
            if ($r['status'] !== 401 || $key !== '') {
                Http::circuitRecord('osmedeus', $r['status'] > 0 && $r['status'] < 500);
                return $r;
            }
        }
        return $r;
    }

    private function jwt(bool $fresh): string
    {
        if (!$fresh) {
            $c = Kv::get('osm:jwt');
            if ($c !== null && $c !== '') {
                return Crypto::decrypt($c);
            }
        }
        $r = Http::request('POST', $this->base() . '/osm/api/login', [], ['username' => Settings::get('osm_username'), 'password' => Settings::secret('osm_password')],
            ['timeout' => 15, 'verify' => Settings::bool('osm_verify_tls')]);
        $token = (string) ($r['json']['token'] ?? '');
        if ($token === '') {
            Trace::error('engine', 'osm.login', 'Osmedeus login failed: HTTP ' . $r['status'] . ' ' . $r['error']);
            Http::circuitRecord('osmedeus', false);
            return '';
        }
        Kv::set('osm:jwt', Crypto::encrypt($token), 20 * 3600);
        return $token;
    }

    /** The flow for this asset: domain flows get domains; IPs and ranges go to the cidr flow. */
    public static function flowFor(array $profile, object $asset): string
    {
        $flow = (string) ($profile['workflow'] ?? 'general');
        if ($asset->kind !== 'domain') {
            return str_contains($flow, 'extensive') || $flow === 'general' ? 'cidr' : 'cidr';
        }
        return $flow;
    }

    public static function safe(string $v): bool
    {
        return $v !== '' && strpbrk($v, self::FORBIDDEN) === false;
    }

    public function start(object $scan, object $asset, array $profile): array
    {
        if (Http::circuitOpen('osmedeus')) {
            return ['ok' => false, 'error' => 'Osmedeus موقتاً در دسترس نیست', 'retry' => true];
        }
        $space = 'mcsec-c' . (int) $asset->client_id . '-a' . (int) $asset->id;
        $flow = self::flowFor($profile, $asset);
        if (!self::safe((string) $asset->value) || !self::safe($flow)) {
            return ['ok' => false, 'error' => 'هدف یا workflow نویسه‌ی غیرمجاز دارد', 'retry' => false];
        }
        $params = ['space_name' => $space, 'tactic' => 'default'];
        if ($asset->kind === 'domain') {
            // a domain's scope is its own names: never expand to the IP space (ASN/netblocks) of the hosts it uses
            $params['exclude_modules'] = 'enum-ipspace';
        }
        $r = $this->call('POST', '/runs', ['flow' => $flow, 'target' => (string) $asset->value, 'params' => $params, 'priority' => 'normal']);
        $uuid = (string) ($r['json']['run_uuid'] ?? '');
        if (!$r['ok'] || $uuid === '') {
            $msg = (string) ($r['json']['message'] ?? $r['error'] ?? '');
            return ['ok' => false, 'error' => 'Osmedeus: HTTP ' . $r['status'] . ' ' . mb_substr($msg, 0, 160), 'retry' => $r['status'] === 0 || $r['status'] >= 500];
        }
        return ['ok' => true, 'ref' => $uuid, 'meta' => ['space' => $space, 'flow' => $flow, 'job' => (string) ($r['json']['job_id'] ?? ''), 'since' => Clock::now()], 'progress' => 1, 'stage' => 'شروع ' . $flow];
    }

    public function poll(object $scan, object $asset, array $profile): array
    {
        $r = $this->call('GET', '/runs/' . rawurlencode((string) $scan->backend_ref), null, 8);
        if (!$r['ok']) {
            return $r['status'] === 404 ? ['status' => 'failed', 'error' => 'Osmedeus این اجرا را نمی‌شناسد'] : ['status' => 'running', 'stage' => 'در انتظار پاسخ Osmedeus'];
        }
        $run = (array) ($r['json']['data'] ?? []);
        $status = (string) ($run['status'] ?? 'running');
        $total = max(1, (int) ($run['total_steps'] ?? 0));
        $done = (int) ($run['completed_steps'] ?? 0);
        if ($status === 'completed') {
            return ['status' => 'completed', 'progress' => 100, 'stage' => 'تمام شد'];
        }
        if ($status === 'failed' || $status === 'cancelled') {
            $err = (string) ($run['error_message'] ?? $status);
            return ['status' => 'failed', 'error' => str_contains($err, 'context canceled') ? 'لغو شد' : 'Osmedeus: ' . mb_substr($err, 0, 160)];
        }
        $stage = 'گام ' . $done . ' از ' . $total;
        return ['status' => 'running', 'progress' => (int) max(2, min(97, floor(100 * $done / $total))), 'stage' => $stage];
    }

    public function collect(object $scan, object $asset, array $profile): array
    {
        $m = json_decode((string) $scan->backend_meta, true) ?: [];
        $space = (string) ($m['space'] ?? '');
        $since = (int) ($m['since'] ?? $scan->started_at) - 300;
        $surface = [];
        $findings = [];
        for ($offset = 0, $i = 0; $i < 10; $i++, $offset += 500) {
            $r = $this->call('GET', '/assets?workspace=' . rawurlencode($space) . '&limit=500&offset=' . $offset, null, 40);
            if (!$r['ok']) {
                throw new \RuntimeException('Osmedeus assets: HTTP ' . $r['status']);
            }
            $rows = (array) ($r['json']['data'] ?? []);
            foreach ($rows as $a) {
                if (!self::fresh($a, $since)) {
                    continue;
                }
                $host = (string) ($a['asset_value'] ?? '');
                if ($host !== '' && in_array($a['asset_type'] ?? '', ['subdomain', 'domain', 'http', 'ip', ''], true)) {
                    $surface[] = ['kind' => 'host', 'value' => mb_substr(preg_replace('~^https?://~', '', $host) ?? $host, 0, 255), 'meta' => ['ip' => (string) ($a['host_ip'] ?? '')]];
                }
                if (!empty($a['url'])) {
                    $surface[] = ['kind' => 'url', 'value' => mb_substr((string) $a['url'], 0, 255), 'meta' => ['status' => (int) ($a['status_code'] ?? 0), 'title' => mb_substr((string) ($a['title'] ?? ''), 0, 120)]];
                }
                foreach ((array) ($a['open_ports'] ?? []) as $p) {
                    $port = (int) $p;
                    if ($port > 0) {
                        $surface[] = ['kind' => 'port', 'value' => ($a['host_ip'] ?? '') !== '' ? $a['host_ip'] . ':' . $port : $host . ':' . $port, 'meta' => ['service' => (string) $p]];
                    }
                }
                foreach ((array) ($a['tech'] ?? []) as $t) {
                    $surface[] = ['kind' => 'tech', 'value' => mb_substr((string) $t, 0, 120), 'meta' => ['host' => $host]];
                }
                $tls = is_string($a['tls'] ?? null) ? json_decode((string) $a['tls'], true) : null;
                if (is_array($tls)) {
                    $surface[] = ['kind' => 'cert', 'value' => $host . ':443', 'meta' => ['not_after' => substr((string) ($tls['not_after'] ?? ''), 0, 10),
                        'issuer' => mb_substr((string) (is_array($tls['issuer_cn'] ?? null) ? implode(',', $tls['issuer_cn']) : ($tls['issuer_cn'] ?? $tls['issuer_dn'] ?? '')), 0, 120),
                        'proto' => (string) ($tls['tls_version'] ?? '')]];
                }
            }
            if (count($rows) < 500) {
                break;
            }
        }
        for ($offset = 0, $i = 0; $i < 10; $i++, $offset += 500) {
            $r = $this->call('GET', '/vulnerabilities?workspace=' . rawurlencode($space) . '&limit=500&offset=' . $offset, null, 40);
            if (!$r['ok']) {
                throw new \RuntimeException('Osmedeus vulnerabilities: HTTP ' . $r['status']);
            }
            $rows = (array) ($r['json']['data'] ?? []);
            foreach ($rows as $v) {
                if (self::fresh($v, $since)) {
                    $findings[] = self::normalize($v);
                }
            }
            if (count($rows) < 500) {
                break;
            }
        }
        return ['findings' => $findings, 'surface' => $surface, 'kinds' => ['host', 'port', 'url'], 'complete' => true];
    }

    /** Seen by this run (last_seen_at, else updated_at, after the run started). */
    private static function fresh(array $row, int $since): bool
    {
        $t = strtotime((string) ($row['last_seen_at'] ?? $row['updated_at'] ?? $row['created_at'] ?? '')) ?: 0;
        return $t === 0 || $t >= $since;
    }

    /** One Osmedeus (nuclei) vulnerability → MC-Sec finding. */
    public static function normalize(array $v): array
    {
        $raw = is_string($v['raw_vuln_json'] ?? null) ? (json_decode((string) $v['raw_vuln_json'], true) ?: []) : [];
        $info = is_array($raw['info'] ?? null) ? $raw['info'] : [];
        $cls = is_array($info['classification'] ?? null) ? $info['classification'] : [];
        $refs = $info['reference'] ?? [];
        $templ = (string) ($v['vuln_info'] ?? $raw['template-id'] ?? 'finding');
        $evidence = array_slice(array_map('strval', (array) ($raw['extracted-results'] ?? [])), 0, 10);
        return [
            'key' => 'nuclei.' . strtolower($templ),
            'title' => (string) ($v['vuln_title'] ?? $info['name'] ?? $templ),
            'severity' => (string) ($v['severity'] ?? $info['severity'] ?? 'info'),
            'location' => (string) ($raw['matched-at'] ?? $v['asset_value'] ?? ''),
            'description' => (string) ($v['vuln_desc'] ?? $info['description'] ?? ''),
            'evidence' => $evidence ? implode("\n", $evidence) : (string) ($v['vuln_poc'] ?? ''),
            'solution' => (string) ($info['remediation'] ?? ''),
            'refs' => array_slice(array_map('strval', is_array($refs) ? $refs : [$refs]), 0, 10),
            'cve' => (array) ($cls['cve-id'] ?? []), 'cwe' => (array) ($cls['cwe-id'] ?? []),
            'cvss' => $cls['cvss-score'] ?? null, 'epss' => $cls['epss-score'] ?? null,
            'tags' => array_slice(array_map('strval', (array) ($v['tags'] ?? $info['tags'] ?? [])), 0, 10),
        ];
    }

    public function cancel(object $scan, object $asset): bool
    {
        $r = $this->call('DELETE', '/runs/' . rawurlencode((string) $scan->backend_ref), null, 10);
        return $r['ok'] || $r['status'] === 400;
    }

    public function health(): array
    {
        if (!$this->configured()) {
            return ['ok' => false, 'message' => 'آدرس و کلید API (یا رمز) Osmedeus تنظیم نشده است.'];
        }
        $h = Http::request('GET', $this->base() . '/server-info', [], null, ['timeout' => 8, 'connect' => 5, 'verify' => Settings::bool('osm_verify_tls')]);
        if ($h['status'] === 0) {
            return ['ok' => false, 'message' => 'Osmedeus پاسخ نداد (' . $h['error'] . '). فایروال سرور Osmedeus باید IP سرور WHMCS را بپذیرد.', 'ms' => $h['ms']];
        }
        $ver = (string) ($h['json']['version'] ?? $h['json']['data']['version'] ?? '');
        $w = $this->call('GET', '/workflows?limit=1', null, 10);
        if (!$w['ok']) {
            return ['ok' => false, 'message' => 'Osmedeus در دسترس است ولی احراز هویت پذیرفته نشد (HTTP ' . $w['status'] . ').', 'version' => $ver, 'ms' => $h['ms']];
        }
        return ['ok' => true, 'message' => 'Osmedeus ' . $ver . ' در دسترس است.', 'version' => $ver, 'ms' => $h['ms']];
    }

    /** Installed flows (for the admin's workflow pick list). @return string[] */
    public function flows(): array
    {
        $r = $this->call('GET', '/workflows?limit=200&source=filesystem', null, 15);
        $out = [];
        foreach ((array) ($r['json']['data'] ?? []) as $w) {
            if (($w['kind'] ?? 'flow') === 'flow' && !empty($w['name'])) {
                $out[] = (string) $w['name'];
            }
        }
        sort($out);
        return $out;
    }
}
