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
        if (isset($profile['owner']) && (int) $profile['owner'] !== $clientId) {
            return ['ok' => false, 'error' => 'این نوع اسکن در دسترس نیست.']; // another account's own scan
        }
        if (Settings::bool('scans_paused') && empty($opt['admin'])) {
            return ['ok' => false, 'error' => 'اسکن‌ها برای نگهداری موقتاً متوقف‌اند. لطفاً کمی بعد امتحان کنید.'];
        }
        if ((int) $asset->client_id !== $clientId || $asset->status !== 'verified') {
            return ['ok' => false, 'error' => Lang::t('دارایی «{asset}» هنوز تأیید نشده است؛ اسکن فقط پس از تأیید مالکیت ممکن است.', ['asset' => $asset->value])];
        }
        $via = '';
        if ($asset->kind === 'domain') {
            // one lookup: the domain's IPs against the blocklist, and the CDN in front of it
            $sc = Net::screen('domain', (string) $asset->value);
            Assets::noteCdn($asset, $sc['cdn']);
            if ($sc['blocked'] !== '') {
                return ['ok' => false, 'error' => 'این دارایی در فهرست ممنوع است.'];
            }
            if ($sc['cdn'] !== '' && $profile['engine'] !== 'builtin') {
                // engines that probe ports never touch a CDN's servers; with the real server proven, they scan that
                $origin = Assets::origin($asset);
                $why = self::cdnRefusal($asset, $profile, $sc['cdn'], $origin);
                if ($why !== '') {
                    return ['ok' => false, 'error' => $why, 'cdn' => $sc['cdn']];
                }
                [$via, $asset] = [(string) $asset->value, $origin];
            }
        }
        if (!in_array($asset->kind, $profile['kinds'], true)) {
            return ['ok' => false, 'error' => Lang::t('«{scan}» برای {kind} اجرا نمی‌شود.', ['scan' => Lang::t((string) $profile['label']), 'kind' => Lang::t((string) (Assets::KINDS[$asset->kind] ?? $asset->kind))])];
        }
        $allowed = Catalog::forClient($clientId)[$profileKey]['allowed'] ?? false;
        if (!$allowed && empty($opt['admin'])) {
            // 'plan' tells Schedules why (it used to look for the word in the text, which is now in two languages)
            return ['ok' => false, 'error' => Lang::t('«{scan}» در پلن فعلی شما نیست. برای استفاده، پلن مناسب بگیرید.', ['scan' => Lang::t((string) $profile['label'])]), 'plan' => true];
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
            return ['ok' => false, 'error' => Lang::t('به سقف {n} اسکن در ۲۴ ساعت رسیده‌اید. فردا دوباره امتحان کنید.', ['n' => Text::fa(Settings::int('daily_scan_cap'))])];
        }
        $profile['credits'] = Rules::cost($clientId, (int) $profile['credits']); // the account's rule may lower the price
        $cost = empty($opt['free']) ? Catalog::cost($profile, $asset) : 0;
        // the stage and the ledger line are stored and read later: in the account's own language
        [$stage, $name] = Lang::with(Lang::forClient($clientId), fn () => [Lang::t('در صف'), Lang::t((string) $profile['label'])]);
        $id = Db::table('mod_mcsec_scans')->insertGetId([
            'client_id' => $clientId, 'asset_id' => (int) $asset->id, 'profile' => $profileKey, 'engine' => $profile['engine'], 'status' => 'queued',
            'credits' => $cost, 'schedule_id' => $scheduleId, 'requested_by' => $userId, 'admin_id' => (int) ($opt['admin'] ?? 0) ?: Auth::masqueradingAdmin(),
            'queued_at' => Clock::now(), 'stage' => $stage, 'backend_meta' => Db::json(array_filter(['retest' => (int) ($opt['retest'] ?? 0)])),
        ]);
        if ($cost > 0) {
            $paid = Credits::spend($clientId, $cost, 'scan:' . $id, $name . ' — ' . $asset->value, $id);
            if (!$paid['ok']) {
                Db::table('mod_mcsec_scans')->where('id', $id)->delete();
                return ['ok' => false, 'error' => $paid['error'], 'need' => $cost];
            }
        }
        ScanLog::add((int) $id, $clientId, 'queue', 'در صف قرار گرفت: ' . $profile['label'] . ' روی ' . $asset->value, ['profile' => $profileKey, 'engine' => $profile['engine'], 'credits' => $cost, 'schedule' => $scheduleId, 'user' => $userId]); // i18n-skip
        Audit::log($clientId, 'scan_start', $profile['label'] . ' ' . $asset->value, array_filter(['scan' => $id, 'credits' => $cost, 'schedule' => $scheduleId, 'for' => $via]), $userId);
        return ['ok' => true, 'scan_id' => $id, 'credits' => $cost, 'via' => $via !== '' ? (string) $asset->value : ''];
    }

    /** Why a scan that probes ports cannot run for a domain behind a CDN ('' = it runs on the verified origin server). */
    private static function cdnRefusal(object $asset, array $profile, string $cdn, ?object $origin): string
    {
        // two whole sentences: what stops the scan, then what to do
        $head = Lang::t('«{asset}» پشت CDN ({cdn}) است و «{scan}» روی سرورهای CDN اجرا نمی‌شود.', ['asset' => $asset->value, 'cdn' => Net::cdnLabel($cdn), 'scan' => Lang::t((string) $profile['label'])]) . ' ';
        if (!Settings::bool('cdn_origin_scan')) {
            return $head . Lang::t('برای این دامنه «بررسی سلامت پایه» را بگیرید.');
        }
        if (!in_array('ip', $profile['kinds'], true)) {
            return $head . Lang::t('این نوع اسکن فقط برای دامنه است و روی IP سرور اجرا نمی‌شود؛ «کشف سطح حمله» یا «اسکن آسیب‌پذیری» را بگیرید.');
        }
        if (!$origin) {
            return $head . Lang::t('IP اصلی سرورتان را در صفحه‌ی همین دامنه ثبت کنید تا اسکن روی آن انجام شود.');
        }
        if ($origin->status !== 'verified') {
            return $head . Lang::t('IP اصلی سرور ({ip}) هنوز تأیید نشده است؛ در صفحه‌ی همان IP مالکیتش را تأیید کنید.', ['ip' => $origin->value]);
        }
        return '';
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
            // stored and read later: in the account's own language
            [$stage, $note] = Lang::with(Lang::forClient((int) $s->client_id), fn () => [Lang::t('لغو شد'), Lang::t('لغو اسکن در صف')]);
            Db::table('mod_mcsec_scans')->where('id', $s->id)->whereIn('status', ['queued', 'running'])
                ->update(['status' => 'cancelled', 'finished_at' => Clock::now(), 'stage' => $stage]);
            if ($wasQueued && (int) $s->credits > 0) {
                Credits::refund((int) $s->client_id, 'scan:' . $s->id, $note, (int) $s->id);
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
        // the stage and the error it stores are read by the customer later: written in the account's own language
        return Lang::with(Lang::forClient((int) $s->client_id), fn () => self::startIn($s, $id));
    }

    private static function startIn(object $s, int $id): bool
    {
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        $profile = Catalog::find((string) $s->profile);
        if (!$asset || $asset->status !== 'verified' || !$profile) {
            self::fail($s, Lang::t('دارایی دیگر تأییدشده نیست یا نوع اسکن خاموش شد.'), true);
            return false;
        }
        // the scope may have changed since the scan was queued (a new blocklist rule, the domain moved behind a CDN)
        $sc = Net::screen((string) $asset->kind, (string) $asset->value);
        if ($sc['blocked'] !== '') {
            self::fail($s, Lang::t('این دارایی به فهرست ممنوع افزوده شد و اسکن نمی‌شود.'), true);
            return false;
        }
        if ($sc['cdn'] !== '' && $s->engine !== 'builtin') {
            if ($asset->kind === 'domain') {
                Assets::noteCdn($asset, $sc['cdn']);
            }
            self::fail($s, Lang::t('«{asset}» اکنون پشت CDN ({cdn}) است و اسکن روی سرورهای CDN انجام نمی‌شود.', ['asset' => $asset->value, 'cdn' => Net::cdnLabel($sc['cdn'])]), true);
            return false;
        }
        ScanLog::begin((int) $s->id, (int) $s->client_id, 'start');
        try {
            $r = self::engine((string) $s->engine)->start($s, $asset, $profile);
        } catch (\Throwable $e) {
            $r = ['ok' => false, 'error' => $e->getMessage(), 'retry' => true];
            Trace::error('engine', $s->engine . '.start', $e->getMessage(), Trace::exception($e), ['client_id' => (int) $s->client_id]);
        }
        ScanLog::end(true, $r['ok'] ? 'موتور کار را پذیرفت: ' . (string) ($r['stage'] ?? '') : 'موتور کار را نپذیرفت: ' . mb_substr((string) ($r['error'] ?? ''), 0, 160), ['ref' => (string) ($r['ref'] ?? ''), 'meta' => (array) ($r['meta'] ?? [])], $r['ok'] ? 'info' : 'error'); // i18n-skip
        if (!$r['ok']) {
            $tries = (int) $s->tries + 1;
            if (!empty($r['retry']) && $tries < self::MAX_TRIES) {
                Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['tries' => $tries, 'synced_at' => Clock::now(), 'error' => mb_substr((string) $r['error'], 0, 255), 'stage' => Lang::t('در صف (تلاش دوباره)')]);
            } else {
                $ref = Trace::error('engine', $s->engine . '.start', (string) $r['error'], ['scan' => $s->id], ['client_id' => (int) $s->client_id]);
                self::fail($s, Lang::t('موتور اسکن کار را نپذیرفت.'), true, $ref);
            }
            return false;
        }
        $meta = array_merge(json_decode((string) $s->backend_meta, true) ?: [], (array) ($r['meta'] ?? []));
        Db::table('mod_mcsec_scans')->where('id', $s->id)->update([
            'status' => 'running', 'backend_ref' => mb_substr((string) ($r['ref'] ?? ''), 0, 128), 'backend_meta' => Db::json($meta),
            'started_at' => Clock::now(), 'synced_at' => 0, 'progress' => (int) ($r['progress'] ?? 1), 'stage' => mb_substr((string) ($r['stage'] ?? Lang::t('شروع شد')), 0, 160), 'error' => '', 'tries' => 0,
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
        // the stage and the error it stores are read by the customer later: written in the account's own language
        return Lang::with(Lang::forClient((int) $s->client_id), fn () => self::syncIn($s, $id));
    }

    private static function syncIn(object $s, int $id): ?object
    {
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        $profile = Catalog::find((string) $s->profile);
        if (!$asset || !$profile) {
            self::fail($s, Lang::t('دارایی یا نوع اسکن دیگر وجود ندارد.'), true);
            return Db::table('mod_mcsec_scans')->where('id', $id)->first();
        }
        if (Clock::now() - (int) $s->started_at > max(1, Settings::int('scan_timeout_hours')) * 3600) {
            try {
                self::engine((string) $s->engine)->cancel($s, $asset);
            } catch (\Throwable $e) {
                // timing out anyway
            }
            self::fail($s, Lang::t('اسکن بیش از زمان مجاز طول کشید.'), true);
            return Db::table('mod_mcsec_scans')->where('id', $id)->first();
        }
        ScanLog::begin((int) $s->id, (int) $s->client_id, 'poll');
        try {
            $p = self::engine((string) $s->engine)->poll($s, $asset, $profile);
        } catch (\Throwable $e) {
            ScanLog::end(true, 'پرسیدن وضعیت از موتور خطا داد: ' . mb_substr($e->getMessage(), 0, 160), [], 'warn'); // i18n-skip
            Trace::warn('engine', $s->engine . '.poll', $e->getMessage(), ['scan' => $s->id]);
            Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['synced_at' => Clock::now()]);
            return $s;
        }
        // written only when something changed or a call failed, so a long scan does not fill the journal
        $changed = $p['status'] !== 'running' || (!empty($p['stage']) && (string) $p['stage'] !== (string) $s->stage) || !empty($p['meta']);
        ScanLog::end($changed || ScanLog::failed(), 'وضعیت در موتور: ' . $p['status'] . (!empty($p['stage']) ? ' — ' . $p['stage'] : '') . (!empty($p['error']) ? ' — ' . $p['error'] : ''), array_filter(['meta' => (array) ($p['meta'] ?? [])]), $p['status'] === 'failed' ? 'error' : 'info'); // i18n-skip
        $upd = ['synced_at' => Clock::now()];
        if (!empty($p['meta'])) {
            // the engine learned something it needs later (the run it started after the target's discovery)
            $upd['backend_meta'] = Db::json(array_merge(json_decode((string) $s->backend_meta, true) ?: [], (array) $p['meta']));
        }
        if (isset($p['progress'])) {
            $upd['progress'] = max((int) $s->progress, min(99, (int) $p['progress']));
        }
        if (!empty($p['stage'])) {
            $upd['stage'] = mb_substr((string) $p['stage'], 0, 160);
        }
        Db::table('mod_mcsec_scans')->where('id', $s->id)->update($upd);
        if ($p['status'] === 'failed') {
            $ref = Trace::error('engine', $s->engine . '.run', (string) ($p['error'] ?? 'failed'), ['scan' => $s->id], ['client_id' => (int) $s->client_id]);
            self::fail($s, Lang::t('اسکن در موتور ناموفق شد.'), true, $ref);
        } elseif ($p['status'] === 'completed') {
            self::finish(Db::table('mod_mcsec_scans')->where('id', $s->id)->first(), $asset, $profile);
        }
        return Db::table('mod_mcsec_scans')->where('id', $id)->first();
    }

    /** Collects and stores a finished scan; everything it writes for the customer is in the account's own language. */
    private static function finish(object $s, object $asset, array $profile): void
    {
        Lang::with(Lang::forClient((int) $s->client_id), fn () => self::finishIn($s, $asset, $profile));
    }

    private static function finishIn(object $s, object $asset, array $profile): void
    {
        ScanLog::begin((int) $s->id, (int) $s->client_id, 'collect');
        try {
            $res = self::engine((string) $s->engine)->collect($s, $asset, $profile);
        } catch (\Throwable $e) {
            ScanLog::end(true, 'خواندن نتیجه از موتور خطا داد: ' . mb_substr($e->getMessage(), 0, 160), [], 'error'); // i18n-skip
            $tries = (int) $s->tries + 1;
            $ref = Trace::error('engine', $s->engine . '.collect', $e->getMessage(), Trace::exception($e), ['client_id' => (int) $s->client_id]);
            if ($tries >= self::MAX_TRIES) {
                self::fail($s, Lang::t('نتیجه‌ی اسکن از موتور خوانده نشد.'), true, $ref);
            } else {
                Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['tries' => $tries, 'stage' => Lang::t('جمع‌آوری نتیجه (تلاش دوباره)')]);
            }
            return;
        }
        $findings = array_merge($res['findings'], self::exposureFindings($res['surface']));
        $diff = Findings::ingest($s, $asset, $findings, (bool) $res['complete']);
        $surf = Surface::ingest($s, $asset, $res['surface'], (array) $res['kinds']);
        $counts = Findings::openCounts(0, (int) $asset->id);
        $summary = ['new' => count($diff['new']), 'reopened' => count($diff['reopened']), 'fixed' => count($diff['fixed']), 'seen' => $diff['seen'],
            'open' => $counts, 'surface_new' => count($surf['new']), 'surface_seen' => $surf['seen'], 'surface_gone' => $surf['gone']];
        $partial = mb_substr((string) ($res['partial'] ?? ''), 0, 255);
        if (!empty($res['evidence'])) {
            $summary['evidence'] = (array) $res['evidence']; // what proves the engine really worked (ids, jobs, what it could reach)
        }
        ScanLog::end(true, $partial !== '' ? 'نتیجه خوانده شد، ولی ارزیابی ناقص است: ' . mb_substr($partial, 0, 120) : 'نتیجه خوانده شد: ' . count($res['findings']) . ' یافته از موتور، ' . count($res['surface']) . ' مورد سطح حمله', // i18n-skip
            ['evidence' => (array) ($res['evidence'] ?? []), 'findings_from_engine' => count($res['findings']), 'new' => count($diff['new']), 'surface' => count($res['surface']), 'complete' => (bool) $res['complete']], $partial !== '' ? 'warn' : 'info');
        if ($partial !== '') {
            ScanLog::alert($s, 'incomplete', $partial);
            $summary['partial'] = $partial;
            // a paid scan the target cut off before it saw anything gave the customer nothing: the credits go back
            if ((int) $s->credits > 0 && !$res['findings'] && Settings::bool('refund_on_fail')) {
                $summary['refunded'] = Credits::refund((int) $s->client_id, 'scan:' . $s->id, Lang::t('بازگشت اعتبار اسکن ناقص (هدف پاسخ نداد)'), (int) $s->id);
            }
        }
        Db::table('mod_mcsec_scans')->where('id', $s->id)->update(['status' => 'completed', 'finished_at' => Clock::now(), 'progress' => 100, 'stage' => $partial !== '' ? Lang::t('تمام شد (ارزیابی ناقص)') : Lang::t('تمام شد'),
            'summary' => Db::json($summary), 'error' => '']);
        // engines that judge completeness (built-in) set the asset's "incomplete" mark; others leave it as it is
        Db::table('mod_mcsec_assets')->where('id', $asset->id)->update(['last_scan_at' => Clock::now()] + (array_key_exists('partial', $res) ? ['partial' => $partial] : []));
        if (!empty($res['shots'])) {
            try {
                Shots::save($asset, (array) $res['shots']);
            } catch (\Throwable $e) {
                Trace::warn('engine', 'shot', $e->getMessage(), ['scan' => (int) $s->id]);
            }
        }
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
        Notify::event($clientId, 'scan_completed', ['scan_id' => (int) $s->id, 'asset' => (string) $asset->value, 'profile' => Lang::t((string) $profile['label']), 'summary' => $sum, 'retest' => $retest], 'scan:' . $s->id);
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
            $out[] = ['key' => 'builtin.port.' . $port, 'title' => Lang::t('درگاه {service} روی اینترنت باز است', ['service' => $names[$port]]), 'severity' => $sev, 'location' => (string) $it['value'],
                'description' => Lang::t('سرویس {service} (درگاه {port}) از اینترنت در دسترس است.', ['service' => $names[$port], 'port' => $port]), 'evidence' => 'tcp/' . $port . ' open', 'kb' => 'port-exposed', 'tags' => ['exposure']];
        }
        return $out;
    }

    /** Ends a scan as failed; credits back when the system is to blame. */
    public static function fail(object $s, string $why, bool $refund, string $ref = ''): void
    {
        // $why is shown to the customer; a whole text the dictionary knows is given in the account's own language
        Lang::with(Lang::forClient((int) $s->client_id), fn () => self::failIn($s, Lang::t($why), $refund, $ref));
    }

    private static function failIn(object $s, string $why, bool $refund, string $ref): void
    {
        $n = Db::table('mod_mcsec_scans')->where('id', $s->id)->whereIn('status', ['queued', 'running'])
            ->update(['status' => 'failed', 'finished_at' => Clock::now(), 'error' => mb_substr($why, 0, 255), 'error_ref' => $ref, 'stage' => Lang::t('ناموفق')]);
        if ($n !== 1) {
            return;
        }
        $back = 0;
        if ($refund && (int) $s->credits > 0 && Settings::bool('refund_on_fail')) {
            $back = Credits::refund((int) $s->client_id, 'scan:' . $s->id, Lang::t('بازگشت اعتبار اسکن ناموفق'), (int) $s->id);
        }
        ScanLog::add((int) $s->id, (int) $s->client_id, 'fail', $why . ($ref !== '' ? ' (' . $ref . ')' : ''), ['refunded' => $back, 'was' => (string) $s->status, 'stage' => (string) $s->stage], 'error');
        ScanLog::alert($s, 'failed', $why . ($ref !== '' ? ' کد: ' . $ref : '')); // i18n-skip
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        Notify::event((int) $s->client_id, 'scan_failed', ['scan_id' => (int) $s->id, 'asset' => (string) ($asset->value ?? ''), 'profile' => Lang::t(Catalog::label((string) ($s->profile))),
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
