<?php

declare(strict_types=1);

namespace McSec;

/**
 * Vulnerability intelligence: CISA's Known Exploited Vulnerabilities (KEV) and FIRST's EPSS, kept per CVE in
 * mod_mcsec_intel, and the priority of each finding (0–100) built from them.
 *  priority = (CVSS, or a default per severity) × 10 × 1.3 when EPSS ≥ 0.5 × 1.5 when in KEV, at most 100.
 * An open KEV finding also caps the asset's score at 49, like a critical one (Score). Numbers come from this code,
 * never from the AI. Only CVE ids leave the server; feeds are fetched by the worker (setting intel_enabled).
 */
final class Intel
{
    private const SEV_BASE = ['critical' => 9.5, 'high' => 7.5, 'medium' => 5.0, 'low' => 2.5, 'info' => 0.5];

    public static function priority(string $severity, $cvss, $epss, bool $kev): int
    {
        $base = is_numeric($cvss) && (float) $cvss > 0 ? min(10.0, (float) $cvss) : (self::SEV_BASE[$severity] ?? 0.5);
        $p = $base * 10 * (is_numeric($epss) && (float) $epss >= 0.5 ? 1.3 : 1.0) * ($kev ? 1.5 : 1.0);
        return (int) max(1, min(100, round($p)));
    }

    /** CVE ids in a finding's cve column ("CVE-2021-44228,cve-2014-0160"). @return string[] */
    public static function cves(string $csv): array
    {
        preg_match_all('~CVE-\d{4}-\d{4,7}~i', $csv, $m);
        return array_values(array_unique(array_map('strtoupper', $m[0])));
    }

    /** Local facts for these CVEs (no network). @param string[] $cves @return array<string,object> */
    public static function lookup(array $cves): array
    {
        $out = [];
        foreach (array_chunk(array_values(array_unique($cves)), 500) as $chunk) {
            foreach (Db::rows(Db::table('mod_mcsec_intel')->whereIn('cve', $chunk)) as $r) {
                $out[(string) $r->cve] = $r;
            }
        }
        return $out;
    }

    /**
     * kev flag, EPSS and priority of one finding from local facts.
     * @param array<string,object> $facts lookup() of its CVEs
     * @return array{kev:int,epss:?float,priority:int}
     */
    public static function judge(string $severity, $cvss, $epss, string $cveCsv, array $facts): array
    {
        $kev = 0;
        $best = is_numeric($epss) ? (float) $epss : null;
        foreach (self::cves($cveCsv) as $c) {
            $x = $facts[$c] ?? null;
            if ($x === null) {
                continue;
            }
            $kev = max($kev, (int) $x->kev);
            if ($x->epss !== null && ($best === null || (float) $x->epss > $best)) {
                $best = (float) $x->epss;
            }
        }
        return ['kev' => $kev, 'epss' => $best, 'priority' => self::priority($severity, $cvss, $best, $kev === 1)];
    }

    /** Worker, twice a day: the KEV catalogue, EPSS of open CVEs, then kev/EPSS/priority of open findings. */
    public static function refresh(float $deadline): array
    {
        if (!Settings::bool('intel_enabled')) {
            return ['skip' => 'off'];
        }
        $out = ['kev' => self::refreshKev()];
        $out['epss'] = self::refreshEpss($deadline);
        $out['findings'] = self::apply($deadline);
        Settings::set('intel_last', Db::json(['at' => Clock::now()] + $out));
        return $out;
    }

    /** @return int|string CVEs in the catalogue, or 'error' */
    public static function refreshKev()
    {
        $url = Settings::get('kev_url');
        if (!preg_match('~^https://~i', $url)) {
            return 'error';
        }
        $r = Http::request('GET', $url, [], null, ['timeout' => 40, 'connect' => 8, 'max_bytes' => 24 * 1024 * 1024]);
        $list = $r['json']['vulnerabilities'] ?? null;
        if (!$r['ok'] || !is_array($list)) {
            Trace::warn('intel', 'kev', 'KEV catalogue not read: HTTP ' . $r['status'] . ' ' . mb_substr((string) $r['error'], 0, 120));
            return 'error';
        }
        $map = [];
        foreach ($list as $v) {
            $id = strtoupper((string) ($v['cveID'] ?? ''));
            if (preg_match('~^CVE-\d{4}-\d{4,7}$~', $id)) {
                $map[$id] = ['added' => substr((string) ($v['dateAdded'] ?? ''), 0, 10), 'ransom' => strcasecmp((string) ($v['knownRansomwareCampaignUse'] ?? ''), 'Known') === 0 ? 1 : 0];
            }
        }
        if (count($map) < 100) {
            // a broken or cut-short answer must never clear the flags of the whole catalogue
            Trace::warn('intel', 'kev', 'KEV catalogue looks incomplete', ['count' => count($map)]);
            return 'error';
        }
        $now = Clock::now();
        foreach (array_chunk(array_keys($map), 500) as $chunk) {
            $have = [];
            foreach (Db::rows(Db::table('mod_mcsec_intel')->whereIn('cve', $chunk)->select(['cve', 'kev', 'kev_added', 'kev_ransom'])) as $row) {
                $have[(string) $row->cve] = $row;
            }
            $insert = [];
            foreach ($chunk as $id) {
                $m = $map[$id];
                if (!isset($have[$id])) {
                    $insert[] = ['cve' => $id, 'kev' => 1, 'kev_added' => $m['added'], 'kev_ransom' => $m['ransom'], 'epss' => null, 'epss_at' => 0, 'updated_at' => $now];
                } elseif ((int) $have[$id]->kev !== 1 || (string) $have[$id]->kev_added !== $m['added'] || (int) $have[$id]->kev_ransom !== $m['ransom']) {
                    Db::table('mod_mcsec_intel')->where('cve', $id)->update(['kev' => 1, 'kev_added' => $m['added'], 'kev_ransom' => $m['ransom'], 'updated_at' => $now]);
                }
            }
            if ($insert) {
                Db::table('mod_mcsec_intel')->insert($insert);
            }
        }
        // entries CISA removed from the catalogue
        $flagged = Db::table('mod_mcsec_intel')->where('kev', 1)->pluck('cve');
        $gone = array_values(array_diff(array_map('strval', is_array($flagged) ? $flagged : $flagged->all()), array_keys($map)));
        foreach (array_chunk($gone, 500) as $chunk) {
            Db::table('mod_mcsec_intel')->whereIn('cve', $chunk)->update(['kev' => 0, 'updated_at' => $now]);
        }
        return count($map);
    }

    /** EPSS for CVEs of open findings not looked up in the last 7 days (100 per request, at most 10 requests). */
    public static function refreshEpss(float $deadline): int
    {
        $url = Settings::get('epss_url');
        if (!preg_match('~^https://~i', $url)) {
            return 0;
        }
        $cves = [];
        foreach (Db::rows(Db::table('mod_mcsec_findings')->where('status', 'open')->where('cve', '!=', '')->select(['cve'])->distinct()->limit(5000)) as $r) {
            foreach (self::cves((string) $r->cve) as $c) {
                $cves[$c] = true;
            }
        }
        $facts = self::lookup(array_keys($cves));
        $need = array_values(array_filter(array_keys($cves), fn ($c) => !isset($facts[$c]) || (int) $facts[$c]->epss_at < Clock::now() - 7 * 86400));
        $done = 0;
        foreach (array_slice(array_chunk($need, 100), 0, 10) as $chunk) {
            if (microtime(true) > $deadline) {
                break;
            }
            $r = Http::request('GET', $url . (str_contains($url, '?') ? '&' : '?') . 'cve=' . implode(',', $chunk), [], null, ['timeout' => 20, 'connect' => 8, 'max_bytes' => 2 * 1024 * 1024]);
            if (!$r['ok'] || !is_array($r['json']['data'] ?? null)) {
                Trace::warn('intel', 'epss', 'EPSS not read: HTTP ' . $r['status'] . ' ' . mb_substr((string) $r['error'], 0, 120));
                break;
            }
            $got = [];
            foreach ($r['json']['data'] as $d) {
                $id = strtoupper((string) ($d['cve'] ?? ''));
                if (is_numeric($d['epss'] ?? null)) {
                    $got[$id] = round(max(0.0, min(1.0, (float) $d['epss'])), 5);
                }
            }
            $now = Clock::now();
            $insert = [];
            foreach ($chunk as $id) {
                $epss = $got[$id] ?? null;
                if (isset($facts[$id])) {
                    Db::table('mod_mcsec_intel')->where('cve', $id)->update(['epss' => $epss, 'epss_at' => $now, 'updated_at' => $now]);
                } else {
                    $insert[] = ['cve' => $id, 'kev' => 0, 'kev_added' => '', 'kev_ransom' => 0, 'epss' => $epss, 'epss_at' => $now, 'updated_at' => $now];
                }
                $done++;
            }
            if ($insert) {
                Db::table('mod_mcsec_intel')->insert($insert);
            }
        }
        return $done;
    }

    /**
     * Applies local facts to open findings with a CVE: kev, EPSS and priority; refreshes the score of assets whose
     * KEV state changed and tells each account once about findings that just became "exploited in the wild".
     * @return int findings changed
     */
    public static function apply(float $deadline): int
    {
        $changed = 0;
        $last = 0;
        $assets = [];
        $alerts = [];
        while (microtime(true) < $deadline + 20) {
            $rows = Db::rows(Db::table('mod_mcsec_findings')->where('status', 'open')->where('cve', '!=', '')->where('id', '>', $last)->orderBy('id')->limit(500)
                ->select(['id', 'client_id', 'asset_id', 'title', 'severity', 'location', 'cvss', 'epss', 'kev', 'priority', 'cve']));
            if (!$rows) {
                break;
            }
            $all = [];
            foreach ($rows as $r) {
                $all = array_merge($all, self::cves((string) $r->cve));
            }
            $facts = self::lookup($all);
            foreach ($rows as $r) {
                $last = (int) $r->id;
                $j = self::judge((string) $r->severity, $r->cvss, $r->epss, (string) $r->cve, $facts);
                $oldEpss = $r->epss === null ? null : round((float) $r->epss, 5);
                $newEpss = $j['epss'] === null ? null : round($j['epss'], 5);
                if ($j['kev'] === (int) $r->kev && $j['priority'] === (int) $r->priority && $newEpss === $oldEpss) {
                    continue;
                }
                Db::table('mod_mcsec_findings')->where('id', $r->id)->update(['kev' => $j['kev'], 'epss' => $newEpss, 'priority' => $j['priority']]);
                $changed++;
                if ($j['kev'] !== (int) $r->kev) {
                    $assets[(int) $r->asset_id] = true;
                }
                if ($j['kev'] === 1 && (int) $r->kev === 0) {
                    $alerts[(int) $r->client_id][] = ['id' => (int) $r->id, 'title' => (string) $r->title, 'severity' => (string) $r->severity, 'location' => (string) $r->location, 'cve' => implode(', ', self::cves((string) $r->cve))];
                }
            }
        }
        foreach (array_keys($assets) as $aid) {
            Assets::refreshStats($aid);
        }
        foreach ($alerts as $cid => $list) {
            $ids = array_map(fn ($x) => $x['id'], $list);
            sort($ids);
            Notify::event($cid, 'kev_alert', ['findings' => $list], substr(sha1(implode(',', $ids)), 0, 20));
        }
        return $changed;
    }

    /**
     * Priority for open findings stored before 0.2.0 (priority 0), 500 per worker pass, until none is left.
     */
    public static function backfill(): int
    {
        if (Kv::get('intel:backfilled') === MCSEC_VERSION) {
            return 0;
        }
        $rows = Db::rows(Db::table('mod_mcsec_findings')->where('status', 'open')->where('priority', 0)->orderBy('id')->limit(500)->select(['id', 'severity', 'cvss', 'epss', 'kev', 'cve']));
        if (!$rows) {
            Kv::set('intel:backfilled', MCSEC_VERSION);
            return 0;
        }
        $all = [];
        foreach ($rows as $r) {
            $all = array_merge($all, self::cves((string) $r->cve));
        }
        $facts = $all ? self::lookup($all) : [];
        foreach ($rows as $r) {
            $j = self::judge((string) $r->severity, $r->cvss, $r->epss, (string) $r->cve, $facts);
            Db::table('mod_mcsec_findings')->where('id', $r->id)->update(['priority' => $j['priority'], 'kev' => max((int) $r->kev, $j['kev'])]);
        }
        return count($rows);
    }
}
