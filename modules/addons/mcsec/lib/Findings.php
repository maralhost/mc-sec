<?php

declare(strict_types=1);

namespace McSec;

/**
 * Findings: one row per distinct issue on an asset (fingerprint = asset + source key + location), whatever engine
 * found it, with a lifecycle:
 *  open → fixed           only the system marks fixed: a completed scan of the same profile no longer sees it;
 *  fixed → open           seen again (reopened, counted);
 *  open ⇄ accepted        risk accepted by the customer, with a reason;
 *  open ⇄ false_positive  with a reason.
 * Accepted and false-positive findings stay out of the score and of alerts, but are still updated when seen.
 * Engines hand normalized arrays to ingest() (see Engines\Engine::collect).
 */
final class Findings
{
    public const SEVERITIES = [
        'critical' => ['label' => 'بحرانی', 'tone' => 'crit', 'rank' => 5],
        'high' => ['label' => 'بالا', 'tone' => 'high', 'rank' => 4],
        'medium' => ['label' => 'متوسط', 'tone' => 'med', 'rank' => 3],
        'low' => ['label' => 'پایین', 'tone' => 'low', 'rank' => 2],
        'info' => ['label' => 'اطلاعاتی', 'tone' => 'info', 'rank' => 1],
    ];
    public const STATUS = ['open' => 'باز', 'fixed' => 'رفع‌شده', 'accepted' => 'ریسک پذیرفته', 'false_positive' => 'مثبت کاذب'];

    public static function emptyCounts(): array
    {
        return ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
    }

    public static function severity(string $s): string
    {
        $s = strtolower(trim($s));
        return match ($s) {
            'critical', 'crit', 'urgent' => 'critical',
            'high', 'important' => 'high',
            'medium', 'moderate', 'med', 'warning' => 'medium',
            'low', 'minor' => 'low',
            default => 'info',
        };
    }

    public static function fingerprint(int $assetId, string $key, string $location): string
    {
        $loc = strtolower(trim($location));
        $loc = preg_replace('~^https?://~', '', $loc) ?? $loc;
        $loc = rtrim(preg_replace('~[?#].*$~', '', $loc) ?? $loc, '/');
        return sha1($assetId . '|' . strtolower(trim($key)) . '|' . $loc);
    }

    /**
     * Stores what a scan found. $items: normalized findings
     *   ['key','title','severity','location','description','evidence','solution','refs'=>[],'cve'=>[],'cwe'=>[],'cvss','epss','tags'=>[],'kb']
     * $complete: the scan finished normally, so open findings of this profile it did not see are fixed.
     * @return array{new:int[],reopened:int[],fixed:int[],seen:int}
     */
    public static function ingest(object $scan, object $asset, array $items, bool $complete): array
    {
        $now = Clock::now();
        $out = ['new' => [], 'reopened' => [], 'fixed' => [], 'seen' => 0];
        $seenFps = [];
        foreach ($items as $it) {
            $title = Text::name((string) ($it['title'] ?? ''), 255);
            $key = mb_substr((string) ($it['key'] ?? $title), 0, 160);
            if ($title === '' || $key === '') {
                continue;
            }
            $loc = mb_substr((string) ($it['location'] ?? $asset->value), 0, 500);
            $fp = self::fingerprint((int) $asset->id, $key, $loc);
            if (isset($seenFps[$fp])) {
                continue;
            }
            $seenFps[$fp] = true;
            $out['seen']++;
            $row = [
                'title' => $title, 'severity' => self::severity((string) ($it['severity'] ?? 'info')), 'engine' => (string) $scan->engine, 'profile' => (string) $scan->profile,
                'source_key' => $key, 'kb' => mb_substr((string) ($it['kb'] ?? Kb::match($key, $title)), 0, 64), 'location' => $loc,
                'description' => self::clip($it['description'] ?? '', 4000), 'evidence' => self::clip($it['evidence'] ?? '', 4000), 'solution' => self::clip($it['solution'] ?? '', 4000),
                'refs' => Db::json(array_slice(array_values(array_filter((array) ($it['refs'] ?? []), 'is_string')), 0, 12)),
                'cve' => mb_substr(implode(',', array_slice((array) ($it['cve'] ?? []), 0, 10)), 0, 255), 'cwe' => mb_substr(implode(',', array_slice((array) ($it['cwe'] ?? []), 0, 10)), 0, 255),
                'cvss' => is_numeric($it['cvss'] ?? null) ? round((float) $it['cvss'], 1) : null, 'epss' => is_numeric($it['epss'] ?? null) ? round((float) $it['epss'], 5) : null,
                'tags' => mb_substr(implode(',', array_slice((array) ($it['tags'] ?? []), 0, 12)), 0, 255),
                'last_scan_id' => (int) $scan->id, 'last_seen_at' => $now,
            ];
            $old = Db::table('mod_mcsec_findings')->where('client_id', $asset->client_id)->where('fp', $fp)->first();
            if ($old) {
                if ($old->status === 'fixed') {
                    $row += ['status' => 'open', 'reopened' => (int) $old->reopened + 1, 'fixed_at' => 0, 'fixed_scan_id' => 0, 'status_note' => 'دوباره دیده شد'];
                    $out['reopened'][] = (int) $old->id;
                }
                Db::table('mod_mcsec_findings')->where('id', $old->id)->update($row);
            } else {
                $id = Db::table('mod_mcsec_findings')->insertGetId($row + [
                    'client_id' => (int) $asset->client_id, 'asset_id' => (int) $asset->id, 'fp' => $fp, 'status' => 'open',
                    'first_scan_id' => (int) $scan->id, 'first_seen_at' => $now,
                ]);
                $out['new'][] = (int) $id;
            }
        }
        if ($complete) {
            // what this profile reported before and did not see now is fixed (only for the same asset and profile)
            $gone = Db::table('mod_mcsec_findings')->where('asset_id', $asset->id)->where('profile', (string) $scan->profile)->where('status', 'open')
                ->where('last_scan_id', '!=', (int) $scan->id);
            foreach (Db::rows($gone->select(['id'])) as $g) {
                Db::table('mod_mcsec_findings')->where('id', $g->id)->where('status', 'open')
                    ->update(['status' => 'fixed', 'fixed_at' => $now, 'fixed_scan_id' => (int) $scan->id, 'status_note' => 'در اسکن ' . $scan->id . ' دیگر دیده نشد']);
                $out['fixed'][] = (int) $g->id;
            }
        }
        Assets::refreshStats((int) $asset->id);
        return $out;
    }

    private static function clip($v, int $max): string
    {
        $s = is_array($v) ? implode("\n", array_map('strval', $v)) : (string) $v;
        $s = preg_replace('~[\x00-\x08\x0B\x0C\x0E-\x1F]~', '', $s) ?? '';
        return mb_strlen($s) > $max ? mb_substr($s, 0, $max) . '…' : $s;
    }

    public static function get(int $clientId, int $id): ?object
    {
        return $id > 0 ? Db::table('mod_mcsec_findings')->where('id', $id)->where('client_id', $clientId)->first() : null;
    }

    /** Open findings per severity, for an account (assetId 0) or one asset (clientId 0). */
    public static function openCounts(int $clientId, int $assetId = 0): array
    {
        $q = Db::table('mod_mcsec_findings')->where('status', 'open');
        if ($assetId > 0) {
            $q->where('asset_id', $assetId);
        } else {
            $q->where('client_id', $clientId)->whereIn('asset_id', Db::table('mod_mcsec_assets')->where('client_id', $clientId)->where('status', '!=', 'removed')->select('id'));
        }
        $c = self::emptyCounts();
        foreach (Db::rows($q->selectRaw('severity, COUNT(*) AS n')->groupBy('severity')) as $r) {
            if (isset($c[$r->severity])) {
                $c[$r->severity] = (int) $r->n;
            }
        }
        return $c;
    }

    /**
     * Filtered list for the findings page. $f: status, severity, asset, q, new (days), page
     * @return array{rows:object[],total:int,page:int,pages:int}
     */
    public static function search(int $clientId, array $f, int $per = 25): array
    {
        $q = Db::table('mod_mcsec_findings as f')->join('mod_mcsec_assets as a', 'a.id', '=', 'f.asset_id')
            ->where('f.client_id', $clientId)->where('a.status', '!=', 'removed');
        $status = (string) ($f['status'] ?? 'open');
        if ($status !== 'all' && isset(self::STATUS[$status])) {
            $q->where('f.status', $status);
        }
        if (!empty($f['severity']) && isset(self::SEVERITIES[$f['severity']])) {
            $q->where('f.severity', $f['severity']);
        }
        if ((int) ($f['asset'] ?? 0) > 0) {
            $q->where('f.asset_id', (int) $f['asset']);
        }
        if ((int) ($f['scan'] ?? 0) > 0) {
            $q->where('f.first_scan_id', (int) $f['scan']);
        }
        if ((int) ($f['new'] ?? 0) > 0) {
            $q->where('f.first_seen_at', '>=', Clock::now() - (int) $f['new'] * 86400);
        }
        $term = trim((string) ($f['q'] ?? ''));
        if ($term !== '') {
            $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], mb_substr($term, 0, 80)) . '%';
            $q->where(function ($w) use ($like) {
                $w->where('f.title', 'like', $like)->orWhere('f.location', 'like', $like)->orWhere('f.cve', 'like', $like);
            });
        }
        $total = (clone $q)->count();
        $page = max(1, (int) ($f['page'] ?? 1));
        $pages = max(1, (int) ceil($total / $per));
        $page = min($page, $pages);
        $rank = "CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";
        $rows = Db::rows($q->select(['f.*', 'a.value as asset_value', 'a.label as asset_label'])->orderByRaw($rank . ' DESC')->orderByDesc('f.last_seen_at')
            ->offset(($page - 1) * $per)->limit($per));
        return ['rows' => $rows, 'total' => $total, 'page' => $page, 'pages' => $pages];
    }

    /** Customer changes: accepted / false_positive need a reason; open reopens. 'fixed' is the system's word only. */
    public static function setStatus(array $who, int $id, string $status, string $note): array
    {
        $f = self::get($who['client_id'], $id);
        if (!$f) {
            return ['ok' => false, 'error' => 'این یافته پیدا نشد.'];
        }
        if (!in_array($status, ['open', 'accepted', 'false_positive'], true)) {
            return ['ok' => false, 'error' => 'این وضعیت پذیرفته نیست. «رفع‌شده» را خود سامانه پس از اسکن بعدی ثبت می‌کند.'];
        }
        $note = Text::name($note, 500);
        if ($status !== 'open' && mb_strlen($note) < 5) {
            return ['ok' => false, 'error' => 'دلیل را بنویسید (دست‌کم چند کلمه)، تا بعدها معلوم باشد چرا این تصمیم گرفته شد.'];
        }
        if ($f->status === $status) {
            return ['ok' => true];
        }
        if ($f->status === 'fixed' && $status !== 'open') {
            return ['ok' => false, 'error' => 'این یافته رفع شده است.'];
        }
        Db::table('mod_mcsec_findings')->where('id', $f->id)->update(['status' => $status, 'status_note' => $note, 'status_by' => $who['user_id'], 'status_at' => Clock::now()]);
        Audit::log($who['client_id'], 'finding_status', $f->title, ['id' => $f->id, 'from' => $f->status, 'to' => $status, 'note' => $note], $who['user_id']);
        Assets::refreshStats((int) $f->asset_id);
        return ['ok' => true];
    }

    /** "I fixed it": a free re-test of the profile that found it, at most once a day per finding. */
    public static function retest(array $who, int $id): array
    {
        $f = self::get($who['client_id'], $id);
        if (!$f || $f->status !== 'open') {
            return ['ok' => false, 'error' => 'این یافته باز نیست.'];
        }
        if (!RateLimit::hit('retest:' . $f->id, 1, 86400)) {
            return ['ok' => false, 'error' => 'این یافته امروز یک بار دوباره سنجیده شده است. فردا دوباره امتحان کنید.'];
        }
        if (!RateLimit::hit('retests:' . $who['client_id'], max(1, Settings::int('retest_daily_cap')), 86400)) {
            return ['ok' => false, 'error' => 'سقف بررسی دوباره‌ی رایگان امروز پر شده است. یک اسکن کامل بگیرید یا فردا امتحان کنید.'];
        }
        $asset = Assets::get($who['client_id'], (int) $f->asset_id);
        $profile = $f->profile !== '' ? (string) $f->profile : 'hygiene';
        if (!$asset || !Catalog::get($profile)) {
            return ['ok' => false, 'error' => 'دارایی این یافته دیگر در دسترس نیست.'];
        }
        return Scans::queue($who['client_id'], $asset, $profile, 0, $who['user_id'], ['retest' => (int) $f->id, 'free' => true]);
    }

    /** Severity rank for sorting and thresholds. */
    public static function rank(string $severity): int
    {
        return self::SEVERITIES[$severity]['rank'] ?? 0;
    }

    public static function refs(object $f): array
    {
        $r = json_decode((string) $f->refs, true);
        return is_array($r) ? array_values(array_filter($r, fn ($u) => is_string($u) && preg_match('~^https?://~i', $u))) : [];
    }
}
