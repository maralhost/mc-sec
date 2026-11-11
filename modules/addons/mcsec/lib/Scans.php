<?php

declare(strict_types=1);

namespace McSec;

use McSec\Engines\Builtin;
use McSec\Engines\Engine;
use McSec\Engines\Oasm;
use McSec\Engines\Osmedeus;

/**
 * The scan orchestrator. A scan is queued (credits taken at once, ref scan:<id>), dispatched by the worker to its
 * engine within the global per-engine and per-account concurrency limits, polled until it ends, then its results
 * are collected and stored (Findings, Surface), the customer is notified and the basic report is built.
 * Credits come back automatically when the system (not the customer) is the reason a scan did not finish.
 * Every step on one scan runs under the lock mcsec_scan_<id>, so the worker and the live progress poll never
 * finish the same scan twice.
 */
final class Scans
{
    public const STATUS = ['queued' => 'در صف', 'running' => 'در حال اجرا', 'completed' => 'تمام‌شده', 'failed' => 'ناموفق', 'cancelled' => 'لغوشده'];
    private const MAX_TRIES = 5;

    /** @var array<string,Engine> */
    private static array $engines = [];

    public static function engine(string $key): Engine
    {
        return self::$engines[$key] ??= match ($key) {
            'oasm' => new Oasm(),
            'osmedeus' => new Osmedeus(),
            default => new Builtin(),
        };
    }

    /** Tests replace engines. */
    public static function setEngine(string $key, ?Engine $e): void
    {
        if ($e === null) {
            unset(self::$engines[$key]);
        } else {
            self::$engines[$key] = $e;
        }
    }

    public static function get(int $clientId, int $id): ?object
    {
        return $id > 0 ? Db::table('mod_mcsec_scans')->where('id', $id)->where('client_id', $clientId)->first() : null;
    }

    /**
     * Puts a scan in the queue and takes its credits. $opt: free (retest), retest (finding id), admin (admin id).
     * @return array{ok:bool,error?:string,scan_id?:int,credits?:int,again?:bool}
     */
    public static function queue(int $clientId, object $asset, string $profileKey, int $scheduleId = 0, int $userId = 0, array $opt = []): array
    {
        $profile = Catalog::get($profileKey);
        if (!$profile) {
            return ['ok' => false, 'error' => 'این نوع اسکن در دسترس نیست.'];
        }
        if (Settings::bool('scans_paused') && empty($opt['admin'])) {
            return ['ok' => false, 'error' => 'اسکن‌ها برای نگهداری موقتاً متوقف‌اند. لطفاً کمی بعد امتحان کنید.'];
        }
        if ((int) $asset->client_id !== $clientId || $asset->status !== 'verified') {
            return ['ok' => false, 'error' => 'دارایی «' . $asset->value . '» هنوز تأیید نشده است؛ اسکن فقط پس از تأیید مالکیت ممکن است.'];
        }
        if (!in_array($asset->kind, $profile['kinds'], true)) {
            return ['ok' => false, 'error' => '«' . $profile['label'] . '» برای ' . (Assets::KINDS[$asset->kind] ?? $asset->kind) . ' اجرا نمی‌شود.'];
        }
        $allowed = Catalog::forClient($clientId)[$profileKey]['allowed'] ?? false;
        if (!$allowed && empty($opt['admin'])) {
            return ['ok' => false, 'error' => '«' . $profile['label'] . '» در پلن فعلی شما نیست. برای استفاده، پلن مناسب بگیرید.'];
        }
        if (!self::engine($profile['engine'])->configured()) {
            return ['ok' => false, 'error' => 'موتور این اسکن هنوز راه‌اندازی نشده است. لطفاً بعداً امتحان کنید.'];
        }
        if (Net::blocked((string) $asset->kind, (string) $asset->value) !== '') {
            return ['ok' => false, 'error' => 'این دارایی در فهرست ممنوع است.'];
        }
        $open = Db::table('mod_mcsec_scans')->where('asset_id', $asset->id)->where('profile', $profileKey)->whereIn('status', ['queued', 'running'])->first();
        if ($open) {
            return ['ok' => true, 'scan_id' => (int) $open->id, 'again' => true, 'credits' => 0];
        }
        $dayStart = Clock::now() - 86400;
        if (empty($opt['admin']) && Db::table('mod_mcsec_scans')->where('client_id', $clientId)->where('queued_at', '>', $dayStart)->count() >= max(1, Settings::int('daily_scan_cap'))) {
            return ['ok' => false, 'error' => 'به سقف ' . Text::fa(Settings::int('daily_scan_cap')) . ' اسکن در ۲۴ ساعت رسیده‌اید. فردا دوباره امتحان کنید.'];
        }
        $cost = empty($opt['free']) ? Catalog::cost($profile, $asset) : 0;
        $id = Db::table('mod_mcsec_scans')->insertGetId([
            'client_id' => $clientId, 'asset_id' => (int) $asset->id, 'profile' => $profileKey, 'engine' => $profile['engine'], 'status' => 'queued',
            'credits' => $cost, 'schedule_id' => $scheduleId, 'requested_by' => $userId, 'admin_id' => (int) ($opt['admin'] ?? 0) ?: Auth::masqueradingAdmin(),
            'queued_at' => Clock::now(), 'stage' => 'در صف', 'backend_meta' => Db::json(array_filter(['retest' => (int) ($opt['retest'] ?? 0)])),
        ]);
        if ($cost > 0) {
            $paid = Credits::spend($clientId, $cost, 'scan:' . $id, $profile['label'] . ' — ' . $asset->value, $id);
            if (!$paid['ok']) {
                Db::table('mod_mcsec_scans')->where('id', $id)->delete();
                return ['ok' => false, 'error' => $paid['error'], 'need' => $cost];
            }
        }
        Audit::log($clientId, 'scan_start', $profile['label'] . ' ' . $asset->value, ['scan' => $id, 'credits' => $cost, 'schedule' => $scheduleId], $userId);
        return ['ok' => true, 'scan_id' => $id, 'credits' => $cost];
    }

    /** Customer cancel: a queued scan gets its credits back; a running one is stopped (the work already done is not refunded). */
    public static function cancel(array $who, int $id): array
    {
        $s = self::get($who['client_id'], $id);
        if (!$s || !in_array($s->status, ['queued', 'running'], true)) {
            return ['ok' => false, 'error' => 'این اسکن در حال اجرا یا در صف نیست.'];
        }
        return Lock::with('mcsec_scan_' . $s->id, function () use ($s, $who) {
            $s = Db::table('mod_mcsec_scans')->where('id', $s->id)->first();
            if ($s->status === 'running') {
                $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
                try {
                    self::engine((string) $s->engine)->cancel($s, $asset);
                } catch (\Throwable $e) {
                    Trace::warn('engine', 'cancel', $e->getMessage(), ['scan' => $s->id]);
                }
            }
            $wasQueued = $s->status === 'queued';
            Db::table('mod_mcsec_scans')->where('id', $s->id)->whereIn('status', ['queued', 'running'])
                ->update(['status' => 'cancelled', 'finished_at' => Clock::now(), 'stage' => 'لغو شد']);
            if ($wasQueued && (int) $s->credits > 0) {
                Credits::refund((int) $s->client_id, 'scan:' . $s->id, 'لغو اسکن در صف', (int) $s->id);
            }
            Audit::log((int) $s->client_id, 'scan_cancel', (string) $s->profile, ['scan' => $s->id], $who['user_id']);
            return ['ok' => true, 'refunded' => $wasQueued];
        }, 120) ?? ['ok' => false, 'error' => 'این اسکن همین حالا در حال به‌روزرسانی است؛ چند ثانیه بعد دوباره امتحان کنید.'];
    }

    /** Worker: starts queued scans within the concurrency limits. */
    public static function dispatch(float $deadline): int
    {
        if (Settings::bool('scans_paused')) {
            return 0;
        }
        $started = 0;
        $limits = ['oasm' => max(1, Settings::int('concurrency_oasm')), 'osmedeus' => max(1, Settings::int('concurrency_osm')), 'builtin' => 4];
        $running = [];
        foreach (Db::rows(Db::table('mod_mcsec_scans')->where('status', 'running')->selectRaw('engine, COUNT(*) AS n')->groupBy('engine')) as $r) {
            $running[(string) $r->engine] = (int) $r->n;
        }
        $perClient = max(1, Settings::int('client_concurrency'));
        foreach (Db::rows(Db::table('mod_mcsec_scans')->where('status', 'queued')->orderBy('id')->limit(100)) as $s) {
            if (microtime(true) > $deadline) {
                break;
            }
            $engine = (string) $s->engine;
            if (($running[$engine] ?? 0) >= ($limits[$engine] ?? 1)) {
                continue;
            }
            if (Db::table('mod_mcsec_scans')->where('client_id', $s->client_id)->where('status', 'running')->count() >= $perClient) {
                continue;
            }
            if ((int) $s->tries > 0 && (int) $s->synced_at > Clock::now() - min(3600, 120 * (2 ** (int) $s->tries))) {
                continue; // back-off after a failed start
            }
            $ok = Lock::with('mcsec_scan_' . $s->id, fn () => self::startOne((int) $s->id), 600);
            if ($ok) {
                $started++;
                $running[$engine] = ($running[$engine] ?? 0) + 1;
            }
        }
        return $started;
    }

    private static function startOne(int $id): bool
    {
        $s = Db::table('mod_mcsec_scans')->where('id', $id)->where('status', 'queued')->first();
        if (!$s) {
            return false;
        }
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        $profile = Catalog::get((string) $s->profile) ?? (Catalog::all(true)[$s->profile] ?? null);
        if (!$asset || $asset->status !== 'verified' || !$profile) {
            self::fail($s, 'دارایی دیگر تأییدشده نیست یا نوع اسکن خاموش شد.', true);
            return false;
        }
        try {
            $r = self::engine((string) $s->engine)->start($s, $asset, $profile);
        } catch (\Throwable $e) {
            $r = ['ok' => false, 'error' => $e->getMessage(), 'retry' => true];
            Trace::error('engine', $s->engine . '.start', $e->getMessage(), Trace::exception($e), ['client_id' => (int) $s->client_id]);
        }
        if (!$r['ok']) {
            $tries = (int) $s->tries + 1;
            if (!empty($r['retry']) && $tries < self::MAX_TRIES) {
                Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['tries' => $tries, 'synced_at' => Clock::now(), 'error' => mb_substr((string) $r['error'], 0, 255), 'stage' => 'در صف (تلاش دوباره)']);
            } else {
                $ref = Trace::error('engine', $s->engine . '.start', (string) $r['error'], ['scan' => $s->id], ['client_id' => (int) $s->client_id]);
                self::fail($s, 'موتور اسکن کار را نپذیرفت.', true, $ref);
            }
            return false;
        }
        $meta = array_merge(json_decode((string) $s->backend_meta, true) ?: [], (array) ($r['meta'] ?? []));
        Db::table('mod_mcsec_scans')->where('id', $s->id)->update([
            'status' => 'running', 'backend_ref' => mb_substr((string) ($r['ref'] ?? ''), 0, 128), 'backend_meta' => Db::json($meta),
            'started_at' => Clock::now(), 'synced_at' => 0, 'progress' => (int) ($r['progress'] ?? 1), 'stage' => mb_substr((string) ($r['stage'] ?? 'شروع شد'), 0, 160), 'error' => '', 'tries' => 0,
        ]);
        // the built-in engine already has its result: finish now
        if ($s->engine === 'builtin') {
            self::syncOne($id, false);
        }
        return true;
    }

    /** Worker: polls running scans (each at most once a minute) and finishes the ones that ended. */
    public static function pollRunning(float $deadline): int
    {
        $n = 0;
        foreach (Db::rows(Db::table('mod_mcsec_scans')->where('status', 'running')->where('synced_at', '<', Clock::now() - 50)->orderBy('synced_at')->limit(50)) as $s) {
            if (microtime(true) > $deadline) {
                break;
            }
            Lock::with('mcsec_scan_' . $s->id, fn () => self::syncOne((int) $s->id, false), 600);
            $n++;
        }
        return $n;
    }

    /**
     * Polls one running scan and, when it ended, collects and stores the results. $live: called from the customer's
     * progress poll (short timeouts, skipped while the engine's circuit is open).
     */
    public static function syncOne(int $id, bool $live): ?object
    {
        $s = Db::table('mod_mcsec_scans')->where('id', $id)->first();
        if (!$s || $s->status !== 'running') {
            return $s;
        }
        if ($live && Http::circuitOpen((string) $s->engine)) {
            return $s;
        }
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        $profile = Catalog::all(true)[(string) $s->profile] ?? null;
        if (!$asset || !$profile) {
            self::fail($s, 'دارایی یا نوع اسکن دیگر وجود ندارد.', true);
            return Db::table('mod_mcsec_scans')->where('id', $id)->first();
        }
        if (Clock::now() - (int) $s->started_at > max(1, Settings::int('scan_timeout_hours')) * 3600) {
            try {
                self::engine((string) $s->engine)->cancel($s, $asset);
            } catch (\Throwable $e) {
                // timing out anyway
            }
            self::fail($s, 'اسکن بیش از زمان مجاز طول کشید.', true);
            return Db::table('mod_mcsec_scans')->where('id', $id)->first();
        }
        try {
            $p = self::engine((string) $s->engine)->poll($s, $asset, $profile);
        } catch (\Throwable $e) {
            Trace::warn('engine', $s->engine . '.poll', $e->getMessage(), ['scan' => $s->id]);
            Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['synced_at' => Clock::now()]);
            return $s;
        }
        $upd = ['synced_at' => Clock::now()];
        if (isset($p['progress'])) {
            $upd['progress'] = max((int) $s->progress, min(99, (int) $p['progress']));
        }
        if (!empty($p['stage'])) {
            $upd['stage'] = mb_substr((string) $p['stage'], 0, 160);
        }
        Db::table('mod_mcsec_scans')->where('id', $s->id)->update($upd);
        if ($p['status'] === 'failed') {
            $ref = Trace::error('engine', $s->engine . '.run', (string) ($p['error'] ?? 'failed'), ['scan' => $s->id], ['client_id' => (int) $s->client_id]);
            self::fail($s, 'اسکن در موتور ناموفق شد.', true, $ref);
        } elseif ($p['status'] === 'completed') {
            self::finish(Db::table('mod_mcsec_scans')->where('id', $s->id)->first(), $asset, $profile);
        }
        return Db::table('mod_mcsec_scans')->where('id', $id)->first();
    }

    private static function finish(object $s, object $asset, array $profile): void
    {
        try {
            $res = self::engine((string) $s->engine)->collect($s, $asset, $profile);
        } catch (\Throwable $e) {
            $tries = (int) $s->tries + 1;
            $ref = Trace::error('engine', $s->engine . '.collect', $e->getMessage(), Trace::exception($e), ['client_id' => (int) $s->client_id]);
            if ($tries >= self::MAX_TRIES) {
                self::fail($s, 'نتیجه‌ی اسکن از موتور خوانده نشد.', true, $ref);
            } else {
                Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['tries' => $tries, 'stage' => 'جمع‌آوری نتیجه (تلاش دوباره)']);
            }
            return;
        }
        $findings = array_merge($res['findings'], self::exposureFindings($res['surface']));
        $diff = Findings::ingest($s, $asset, $findings, (bool) $res['complete']);
        $surf = Surface::ingest($s, $asset, $res['surface'], (array) $res['kinds']);
        $counts = Findings::openCounts(0, (int) $asset->id);
        $summary = ['new' => count($diff['new']), 'reopened' => count($diff['reopened']), 'fixed' => count($diff['fixed']), 'seen' => $diff['seen'],
            'open' => $counts, 'surface_new' => count($surf['new']), 'surface_seen' => $surf['seen'], 'surface_gone' => $surf['gone']];
        Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['status' => 'completed', 'finished_at' => Clock::now(), 'progress' => 100, 'stage' => 'تمام شد',
            'summary' => Db::json($summary), 'error' => '']);
        Db::table('mod_mcsec_assets')->where('id', $asset->id)->update(['last_scan_at' => Clock::now()]);
        $s = Db::table('mod_mcsec_scans')->where('id', $s->id)->first();
        try {
            self::announce($s, $asset, $profile, $diff, $surf);
        } catch (\Throwable $e) {
            Trace::error('notify', 'scan', $e->getMessage(), Trace::exception($e));
        }
        if (Settings::bool('ai_auto_scan_report')) {
            Reports::queue((int) $s->client_id, 'scan', ['scan_id' => (int) $s->id, 'asset_id' => (int) $asset->id], false, 0);
        }
    }

    /** Alerts after a scan: the summary, new/reopened findings at or above the person's threshold, new exposure. */
    private static function announce(object $s, object $asset, array $profile, array $diff, array $surf): void
    {
        $clientId = (int) $s->client_id;
        $sum = json_decode((string) $s->summary, true) ?: [];
        $retest = (int) ((json_decode((string) $s->backend_meta, true) ?: [])['retest'] ?? 0);
        Notify::event($clientId, 'scan_completed', ['scan_id' => (int) $s->id, 'asset' => (string) $asset->value, 'profile' => $profile['label'], 'summary' => $sum, 'retest' => $retest], 'scan:' . $s->id);
        $ids = array_merge($diff['new'], $diff['reopened']);
        if ($ids) {
            $rows = Db::rows(Db::table('mod_mcsec_findings')->whereIn('id', $ids)->select(['id', 'title', 'severity', 'location', 'reopened']));
            usort($rows, fn ($a, $b) => Findings::rank($b->severity) <=> Findings::rank($a->severity));
            $list = array_map(fn ($r) => ['id' => (int) $r->id, 'title' => (string) $r->title, 'severity' => (string) $r->severity, 'location' => (string) $r->location, 'reopened' => (int) $r->reopened > 0], $rows);
            Notify::event($clientId, 'new_findings', ['scan_id' => (int) $s->id, 'asset' => (string) $asset->value, 'findings' => $list], 'nf:' . $s->id);
        }
        if ($diff['fixed']) {
            Notify::event($clientId, 'findings_fixed', ['scan_id' => (int) $s->id, 'asset' => (string) $asset->value, 'count' => count($diff['fixed'])], 'fx:' . $s->id);
        }
        $alarm = Surface::alarming($surf['new']);
        if ($alarm) {
            Notify::event($clientId, 'new_exposure', ['scan_id' => (int) $s->id, 'asset' => (string) $asset->value, 'items' => array_slice($alarm, 0, 20)], 'ex:' . $s->id);
        }
    }

    /** Engine-agnostic findings from the surface: risky services reachable from the internet. */
    public static function exposureFindings(array $surface): array
    {
        $names = [21 => 'FTP', 23 => 'Telnet', 445 => 'SMB', 1433 => 'MS SQL Server', 2375 => 'Docker API', 3306 => 'MySQL', 3389 => 'RDP', 5432 => 'PostgreSQL',
            5900 => 'VNC', 6379 => 'Redis', 9200 => 'Elasticsearch', 11211 => 'Memcached', 27017 => 'MongoDB'];
        $out = [];
        foreach ($surface as $it) {
            if (($it['kind'] ?? '') !== 'port') {
                continue;
            }
            $port = (int) preg_replace('~^.*:~', '', (string) $it['value']);
            if (!isset($names[$port])) {
                continue;
            }
            $sev = in_array($port, [2375], true) ? 'critical' : (in_array($port, [21, 11211], true) ? 'medium' : 'high');
            $out[] = ['key' => 'builtin.port.' . $port, 'title' => 'درگاه ' . $names[$port] . ' روی اینترنت باز است', 'severity' => $sev, 'location' => (string) $it['value'],
                'description' => 'سرویس ' . $names[$port] . ' (درگاه ' . $port . ') از اینترنت در دسترس است.', 'evidence' => 'tcp/' . $port . ' open', 'kb' => 'port-exposed', 'tags' => ['exposure']];
        }
        return $out;
    }

    /** Ends a scan as failed; credits back when the system is to blame. */
    public static function fail(object $s, string $why, bool $refund, string $ref = ''): void
    {
        $n = Db::table('mod_mcsec_scans')->where('id', $s->id)->whereIn('status', ['queued', 'running'])
            ->update(['status' => 'failed', 'finished_at' => Clock::now(), 'error' => mb_substr($why, 0, 255), 'error_ref' => $ref, 'stage' => 'ناموفق']);
        if ($n !== 1) {
            return;
        }
        $back = 0;
        if ($refund && (int) $s->credits > 0 && Settings::bool('refund_on_fail')) {
            $back = Credits::refund((int) $s->client_id, 'scan:' . $s->id, 'بازگشت اعتبار اسکن ناموفق', (int) $s->id);
        }
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        Notify::event((int) $s->client_id, 'scan_failed', ['scan_id' => (int) $s->id, 'asset' => (string) ($asset->value ?? ''), 'profile' => (string) (Catalog::all(true)[$s->profile]['label'] ?? $s->profile),
            'error' => $why, 'ref' => $ref, 'refunded' => $back], 'sf:' . $s->id);
    }

    /** @return object[] latest scans of an account (with the asset value) */
    public static function recent(int $clientId, int $limit = 30, int $assetId = 0): array
    {
        $q = Db::table('mod_mcsec_scans as s')->join('mod_mcsec_assets as a', 'a.id', '=', 's.asset_id')->where('s.client_id', $clientId);
        if ($assetId > 0) {
            $q->where('s.asset_id', $assetId);
        }
        return Db::rows($q->select(['s.*', 'a.value as asset_value', 'a.label as asset_label'])->orderByDesc('s.id')->limit($limit));
    }

    public static function activeCount(int $clientId): int
    {
        return Db::table('mod_mcsec_scans')->where('client_id', $clientId)->whereIn('status', ['queued', 'running'])->count();
    }

    public static function summary(object $s): array
    {
        $x = json_decode((string) $s->summary, true);
        return is_array($x) ? $x : [];
    }
}
