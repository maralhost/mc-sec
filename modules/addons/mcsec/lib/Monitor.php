<?php

declare(strict_types=1);

namespace McSec;

use McSec\Engines\Builtin;

/**
 * Light monitoring, free and without credits (setting monitor_enabled, off by default): every verified domain of an
 * allowed account gets one GET to its home page every monitor_minutes, in parallel batches from the worker, and a
 * certificate check once a day.
 *  - "down" only after two failed checks in a row (one lost packet is not an outage); any HTTP answer below 500
 *    counts as up (a login page or a 403 still means the server answers);
 *  - when most checks of a pass fail at once, the WHMCS server's own network is the likely cause: nothing changes;
 *  - alerts: site_down, site_up (with how long it was down), ssl_expiring (once per certificate end date).
 * The address is resolved here and pinned (no private IPs unless allowed), the same as every other request.
 */
final class Monitor
{
    private const BATCH = 40;

    public static function due(float $deadline): array
    {
        if (!Settings::bool('monitor_enabled') || !Settings::bool('enabled')) {
            return ['skip' => 'off'];
        }
        $now = Clock::now();
        $every = max(5, Settings::int('monitor_minutes')) * 60;
        $rows = Db::rows(Db::table('mod_mcsec_assets')->where('kind', 'domain')->where('status', 'verified')->where('mon_at', '<=', $now - $every + 60)
            ->orderBy('mon_at')->limit(self::BATCH)->select(['id', 'client_id', 'kind', 'value', 'status', 'mon_status', 'mon_fails', 'mon_since', 'mon_note', 'mon_cert_at', 'mon_cert_end', 'origin_id', 'origin_ok_at', 'origin_tls_skip']));
        if (!$rows) {
            return ['checked' => 0];
        }
        // claim the batch first, so an account that is not allowed (or a skipped host) does not block the queue
        Db::table('mod_mcsec_assets')->whereIn('id', array_map(fn ($r) => (int) $r->id, $rows))->update(['mon_at' => $now]);
        $allowed = array_flip(Access::allowedIds(array_map(fn ($r) => (int) $r->client_id, $rows)));
        $targets = [];
        foreach ($rows as $r) {
            if (!isset($allowed[(int) $r->client_id]) || Net::blocked('domain', (string) $r->value) !== '') {
                continue;
            }
            $all = Net::ips((string) $r->value);
            $ips = array_values(array_filter($all, fn ($ip) => Net::isPublicIp($ip) || Settings::bool('allow_private_ips')));
            if ($all && !$ips) {
                continue; // only private addresses: not reachable from the internet, so not monitored (and never requested)
            }
            // no address at all is an outage worth telling ("the name no longer resolves")
            $targets[(int) $r->id] = ['row' => $r, 'ip' => $ips[0] ?? ''];
        }
        if (!$targets) {
            return ['checked' => 0];
        }
        if (!\McSec\Egress::alive()) {
            return ['checked' => 0, 'skip' => 'egress proxy down']; // never from this server's own address; no site is called down because of our proxy
        }
        $res = self::probe($targets, 'https', min(10, max(3, (int) ($deadline - microtime(true)))));
        $retry = array_filter($targets, fn ($t, $id) => !$res[$id]['ok'] && $t['ip'] !== '', ARRAY_FILTER_USE_BOTH);
        if ($retry && microtime(true) < $deadline) {
            foreach (self::probe($retry, 'http', 8) as $id => $x) {
                if ($x['ok']) {
                    $res[$id] = $x; // an HTTP-only site is up too
                }
            }
        }
        $failed = count(array_filter($res, fn ($x) => !self::isUp($x)));
        if (count($res) >= 5 && $failed / count($res) > 0.6) {
            Trace::warn('monitor', 'outage', 'most monitored sites failed at once; assuming a local network problem', ['checked' => count($res), 'failed' => $failed]);
            return ['checked' => count($res), 'skip' => 'local network'];
        }
        $out = ['checked' => count($res), 'down' => 0, 'up' => 0, 'certs' => 0, 'rescans' => 0];
        foreach ($targets as $id => $t) {
            $x = $res[$id] ?? ['ok' => false, 'status' => 0, 'error' => 'no address', 'ms' => 0];
            // a site behind a CDN that does not answer: its own server is asked too, so the alert can say which of the two is down
            if (!self::isUp($x) && (int) $t['row']->mon_fails >= 1 && ($direct = Assets::direct($t['row'])) !== null && microtime(true) < $deadline) {
                $x['origin'] = self::originUp((string) $t['row']->value, $direct) ? 'up' : 'down';
            }
            $ev = self::apply($t['row'], $x, $now);
            // the address of a site changed (a new server or a new CDN): worth a fresh look
            $ipKey = 'monip:' . $id;
            $was = Kv::get($ipKey);
            if ($t['ip'] !== '' && $was !== $t['ip']) {
                Kv::set($ipKey, $t['ip']);
                $out['rescans'] += $was !== null && $was !== '' ? self::rescan($t['row'], 'ip') : 0;
            }
            $out['rescans'] += $ev === 'site_up' ? self::rescan($t['row'], 'up') : 0;
            if ($ev !== '') {
                $out[$ev === 'site_down' ? 'down' : 'up']++;
            }
        }
        // certificates: once a day per site, a few per pass
        foreach ($targets as $id => $t) {
            if ($out['certs'] >= 5 || microtime(true) > $deadline) {
                break;
            }
            if ((int) $t['row']->mon_cert_at > $now - 86400 || !self::isUp($res[$id] ?? []) || $t['ip'] === '') {
                continue;
            }
            self::certCheck($t['row'], $t['ip'], $now);
            $out['certs']++;
        }
        return $out;
    }

    /** The site asked of its own server (pinned to the origin IP, by the site's name). */
    private static function originUp(string $host, array $direct): bool
    {
        foreach (['https' => 443, 'http' => 80] as $scheme => $port) {
            $r = Http::request('GET', $scheme . '://' . $host . '/', ['Accept' => 'text/html,*/*;q=0.8'], null,
                ['timeout' => 6, 'connect' => 3, 'verify' => false, 'max_bytes' => 4096, 'follow' => false, 'resolve' => $host . ':' . $port . ':' . $direct['ip'], 'egress' => true]);
            if ((int) $r['status'] > 0 && (int) $r['status'] < 500) {
                return true;
            }
        }
        return false;
    }

    /**
     * A free basic check after something about a site changed (it came back, its address or its certificate
     * changed): at most one a day per site, and only when the admin switched it on. @return int 1 when queued
     */
    private static function rescan(object $r, string $why): int
    {
        if (!Settings::bool('auto_rescan') || !RateLimit::hit('rescan:' . (int) $r->id, 1, 86400)) {
            return 0;
        }
        $profile = Catalog::get('hygiene');
        $asset = Db::table('mod_mcsec_assets')->where('id', (int) $r->id)->where('status', 'verified')->first();
        if (!$profile || !$asset || (int) $profile['credits'] > 0) {
            return 0; // only ever the free check: nothing is spent without the customer
        }
        $q = Lang::with(Lang::forClient((int) $r->client_id), fn () => Scans::queue((int) $r->client_id, $asset, 'hygiene', 0, 0));
        if ($q['ok'] && empty($q['again'])) {
            Audit::log((int) $r->client_id, 'auto_rescan', (string) $r->value, ['why' => $why, 'scan' => (int) $q['scan_id']]);
            return 1;
        }
        return 0;
    }

    /** @param array<int,array{row:object,ip:string}> $targets @return array<int,array{ok:bool,status:int,error:string,ms:int}> */
    private static function probe(array $targets, string $scheme, int $timeout): array
    {
        $reqs = [];
        $out = [];
        foreach ($targets as $id => $t) {
            $host = (string) $t['row']->value;
            if ($t['ip'] === '') {
                $out[$id] = ['ok' => false, 'status' => 0, 'error' => 'نام دامنه به هیچ IPی اشاره نمی‌کند', 'ms' => 0];
                continue;
            }
            $reqs[$id] = ['url' => $scheme . '://' . $host . '/', 'resolve' => $host . ':' . ($scheme === 'https' ? 443 : 80) . ':' . (str_contains($t['ip'], ':') ? '[' . $t['ip'] . ']' : $t['ip'])];
        }
        return $out + ($reqs ? Http::multi($reqs, $timeout, true) : []);
    }

    private static function isUp(array $x): bool
    {
        return !empty($x['ok']) && (int) ($x['status'] ?? 0) > 0 && (int) $x['status'] < 500;
    }

    /** Stores one result and raises the alert it causes. @return string event raised ('' = none) */
    private static function apply(object $r, array $x, int $now): string
    {
        $up = self::isUp($x);
        if ($up) {
            $was = (string) $r->mon_status;
            Db::table('mod_mcsec_assets')->where('id', $r->id)->update(['mon_status' => 'up', 'mon_fails' => 0, 'mon_note' => '', 'mon_since' => $was === 'up' && (int) $r->mon_since > 0 ? (int) $r->mon_since : $now]);
            if ($was === 'down') {
                Notify::event((int) $r->client_id, 'site_up', ['asset' => (string) $r->value, 'asset_id' => (int) $r->id, 'down_for' => max(0, $now - (int) $r->mon_since)], 'up:' . $r->id . ':' . $now);
                return 'site_up';
            }
            return '';
        }
        $note = (int) ($x['status'] ?? 0) > 0 ? 'HTTP ' . (int) $x['status'] : mb_substr(self::errorText((string) ($x['error'] ?? '')), 0, 160);
        $fails = (int) $r->mon_fails + 1;
        if (isset($x['origin'])) {
            Kv::set('monorigin:' . (int) $r->id, (string) $x['origin'], 3 * 86400);
        }
        if ($fails >= 2 && (string) $r->mon_status !== 'down') {
            Db::table('mod_mcsec_assets')->where('id', $r->id)->update(['mon_status' => 'down', 'mon_fails' => $fails, 'mon_note' => $note, 'mon_since' => $now]);
            Notify::event((int) $r->client_id, 'site_down', ['asset' => (string) $r->value, 'asset_id' => (int) $r->id, 'note' => $note, 'origin' => (string) ($x['origin'] ?? '')], 'down:' . $r->id . ':' . $now);
            return 'site_down';
        }
        Db::table('mod_mcsec_assets')->where('id', $r->id)->update(['mon_fails' => $fails, 'mon_note' => $note]);
        return '';
    }

    /** A plain Persian reason for a connection error (curl's text stays in the technical log, not with the customer). */
    public static function errorText(string $err): string
    {
        $e = strtolower($err);
        return match (true) {
            str_contains($e, 'timed out') || str_contains($e, 'timeout') => 'پاسخی در زمان مقرر نیامد',
            str_contains($e, 'refused') || str_contains($e, "couldn't connect") || str_contains($e, 'could not connect') => 'سرور اتصال را نپذیرفت',
            str_contains($e, 'resolve') => 'نام دامنه پیدا نشد',
            str_contains($e, 'ssl') || str_contains($e, 'tls') => 'خطای اتصال امن (TLS)',
            $e === '' || $e === 'no answer' => 'پاسخی نیامد',
            preg_match('~[\x{0600}-\x{06FF}]~u', $err) === 1 => $err,
            default => 'اتصال برقرار نشد',
        };
    }

    private static function certCheck(object $r, string $ip, int $now): void
    {
        $c = Builtin::certInfo((string) $r->value, $ip);
        $end = $c !== null ? (string) ($c['not_after'] ?? '') : '';
        Db::table('mod_mcsec_assets')->where('id', $r->id)->update(['mon_cert_at' => $now, 'mon_cert_end' => mb_substr($end, 0, 10)]);
        if ($end !== '' && (string) $r->mon_cert_end !== '' && mb_substr($end, 0, 10) !== (string) $r->mon_cert_end) {
            self::rescan($r, 'cert'); // a new certificate
        }
        if ($c === null || $end === '') {
            return;
        }
        $days = (int) $c['days'];
        if ($days <= max(1, Settings::int('monitor_ssl_days'))) {
            // once per certificate: a renewed one has another end date
            Notify::event((int) $r->client_id, 'ssl_expiring', ['asset' => (string) $r->value, 'asset_id' => (int) $r->id, 'days' => $days, 'end' => $end], 'ssl:' . $r->id . ':' . $end);
        }
    }

    /** Short status for pages: [label, tone, detail] or null when the site is not monitored. */
    public static function status(object $a): ?array
    {
        if (!Settings::bool('monitor_enabled') || $a->kind !== 'domain' || $a->status !== 'verified' || (string) ($a->mon_status ?? '') === '') {
            return null;
        }
        if ($a->mon_status === 'down') {
            // the note was stored by the worker in Persian: it gets its English here, when it is read
            $base = $a->mon_note !== '' ? Lang::t('از {since} — {note}', ['since' => Text::ago((int) $a->mon_since), 'note' => Lang::t((string) $a->mon_note)])
                : Lang::t('از {since}', ['since' => Text::ago((int) $a->mon_since)]);
            $o = (int) ($a->origin_ok_at ?? 0) > 0 ? Kv::get('monorigin:' . (int) $a->id) : null;
            return ['از دسترس خارج', 'err', $base . ($o === 'up' ? ' — ' . Lang::t('سرور خودتان جواب می‌دهد؛ مشکل از CDN یا تنظیم آن است') : ($o === 'down' ? ' — ' . Lang::t('سرور خودتان هم جواب نمی‌دهد') : ''))];
        }
        return ['در دسترس', 'ok', Lang::t('آخرین بررسی {when}', ['when' => Text::ago((int) $a->mon_at)])];
    }
}
