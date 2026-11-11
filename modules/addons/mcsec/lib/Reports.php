<?php

declare(strict_types=1);

namespace McSec;

/**
 * Reports. Every report is first built deterministically from the database (score, counts, findings with the
 * Persian remediation of the knowledge base, surface, scans) — free, instant, and correct even when the model is
 * down. An AI report adds, on top of that, an executive summary, the key risks, quick wins, a 30-day plan and a
 * tailored fix per finding (cached by finding type, so the same issue is explained once for everyone).
 * Kinds: scan (after a scan), asset (one asset now), account (everything now), periodic (weekly/monthly digest).
 */
final class Reports
{
    public const KINDS = ['scan' => 'گزارش اسکن', 'asset' => 'گزارش دارایی', 'account' => 'گزارش کامل حساب', 'periodic' => 'گزارش دوره‌ای'];
    private const MAX_FINDINGS = 60;
    private const AI_FINDINGS = 20;

    public static function get(int $clientId, int $id): ?object
    {
        return $id > 0 ? Db::table('mod_mcsec_reports')->where('id', $id)->where('client_id', $clientId)->first() : null;
    }

    public static function recent(int $clientId, int $limit = 40): array
    {
        return Db::rows(Db::table('mod_mcsec_reports')->where('client_id', $clientId)->orderByDesc('id')->limit($limit)
            ->select(['id', 'kind', 'scan_id', 'asset_id', 'title', 'status', 'ai', 'credits', 'error', 'created_at', 'ready_at', 'period_from', 'period_to']));
    }

    public static function data(object $r): array
    {
        $d = json_decode((string) $r->data, true);
        return is_array($d) ? $d : [];
    }

    /**
     * Queues a report for the worker. AI reports cost ai_report_cost credits (refunded if the model fails).
     * @return array{ok:bool,error?:string,report_id?:int}
     */
    public static function queue(int $clientId, string $kind, array $scope, bool $ai, int $userId): array
    {
        if (!isset(self::KINDS[$kind])) {
            return ['ok' => false, 'error' => 'نوع گزارش شناخته نشد.'];
        }
        if ($ai && !Ai::configured()) {
            return ['ok' => false, 'error' => 'گزارش هوش مصنوعی فعلاً در دسترس نیست؛ گزارش پایه را بگیرید.'];
        }
        if ($ai && !Plans::limits($clientId)['ai']) {
            return ['ok' => false, 'error' => 'گزارش هوش مصنوعی در پلن شما نیست.'];
        }
        $scanId = (int) ($scope['scan_id'] ?? 0);
        $assetId = (int) ($scope['asset_id'] ?? 0);
        if (!$ai && $kind === 'scan' && Db::table('mod_mcsec_reports')->where('client_id', $clientId)->where('scan_id', $scanId)->where('ai', 0)->exists()) {
            return ['ok' => true, 'report_id' => (int) Db::table('mod_mcsec_reports')->where('client_id', $clientId)->where('scan_id', $scanId)->where('ai', 0)->value('id')];
        }
        if ($userId > 0 && !RateLimit::hit('report:' . $clientId, 20, 86400)) {
            return ['ok' => false, 'error' => 'امروز گزارش‌های زیادی خواسته‌اید. فردا دوباره امتحان کنید.'];
        }
        $title = self::title($clientId, $kind, $scanId, $assetId);
        $id = Db::table('mod_mcsec_reports')->insertGetId(['client_id' => $clientId, 'kind' => $kind, 'scan_id' => $scanId, 'asset_id' => $assetId, 'title' => $title,
            'status' => 'queued', 'ai' => $ai ? 1 : 0, 'requested_by' => $userId, 'created_at' => Clock::now(),
            'period_from' => (int) ($scope['from'] ?? 0), 'period_to' => (int) ($scope['to'] ?? 0)]);
        $cost = $ai ? max(0, Settings::int('ai_report_cost')) : 0;
        if ($cost > 0) {
            $paid = Credits::spend($clientId, $cost, 'report:' . $id, 'گزارش هوش مصنوعی: ' . $title);
            if (!$paid['ok']) {
                Db::table('mod_mcsec_reports')->where('id', $id)->delete();
                return ['ok' => false, 'error' => $paid['error']];
            }
            Db::table('mod_mcsec_reports')->where('id', $id)->update(['credits' => $cost]);
        }
        if ($userId > 0) {
            Audit::log($clientId, 'report_request', $title, ['report' => $id, 'ai' => $ai], $userId);
        }
        return ['ok' => true, 'report_id' => $id];
    }

    private static function title(int $clientId, string $kind, int $scanId, int $assetId): string
    {
        $asset = $assetId > 0 ? Db::table('mod_mcsec_assets')->where('id', $assetId)->first() : null;
        $s = $scanId > 0 ? Db::table('mod_mcsec_scans')->where('id', $scanId)->first() : null;
        return match ($kind) {
            'scan' => (Catalog::all(true)[$s->profile ?? '']['label'] ?? 'اسکن') . ' — ' . ($asset->value ?? ''),
            'asset' => 'وضعیت امنیت ' . ($asset->value ?? ''),
            'periodic' => 'گزارش دوره‌ای امنیت — ' . Text::date(Clock::now(), false),
            default => 'گزارش کامل امنیت — ' . Text::date(Clock::now(), false),
        };
    }

    /** Worker: builds queued reports. */
    public static function process(float $deadline): int
    {
        $n = 0;
        foreach (Db::rows(Db::table('mod_mcsec_reports')->where('status', 'queued')->orderBy('id')->limit(10)) as $r) {
            if (microtime(true) > $deadline) {
                break;
            }
            Lock::with('mcsec_report_' . $r->id, function () use ($r, &$n) {
                self::build((int) $r->id);
                $n++;
            }, 300);
        }
        return $n;
    }

    public static function build(int $id): void
    {
        $r = Db::table('mod_mcsec_reports')->where('id', $id)->where('status', 'queued')->first();
        if (!$r) {
            return;
        }
        try {
            $data = self::compose($r);
            $aiError = '';
            if ((int) $r->ai === 1) {
                $ai = self::enrich($data);
                if ($ai['ok']) {
                    $data['ai'] = $ai['data'];
                } else {
                    $aiError = 'بخش هوش مصنوعی ساخته نشد؛ گزارش پایه آماده است و اعتبارش برگشت.';
                    if ((int) $r->credits > 0) {
                        Credits::refund((int) $r->client_id, 'report:' . $r->id, 'بازگشت اعتبار گزارش هوش مصنوعی', 0);
                    }
                }
            }
            Db::table('mod_mcsec_reports')->where('id', $id)->update(['status' => 'ready', 'data' => Db::json($data), 'ready_at' => Clock::now(), 'error' => $aiError]);
            if ($r->kind !== 'periodic' && (int) $r->requested_by > 0) {
                Notify::event((int) $r->client_id, 'report_ready', ['report_id' => $id, 'title' => (string) $r->title], 'rep:' . $id);
            }
        } catch (\Throwable $e) {
            $ref = Trace::error('worker', 'report.build', $e->getMessage(), Trace::exception($e), ['client_id' => (int) $r->client_id]);
            Db::table('mod_mcsec_reports')->where('id', $id)->update(['status' => 'failed', 'error' => 'ساخت گزارش انجام نشد.' . Trace::forCustomer($ref)]);
            if ((int) $r->credits > 0) {
                Credits::refund((int) $r->client_id, 'report:' . $r->id, 'بازگشت اعتبار گزارش ناموفق', 0);
            }
        }
    }

    /** The deterministic part of every report. */
    public static function compose(object $r): array
    {
        $clientId = (int) $r->client_id;
        $assetIds = [];
        $scan = null;
        if ($r->kind === 'scan') {
            $scan = Db::table('mod_mcsec_scans')->where('id', $r->scan_id)->where('client_id', $clientId)->first();
            $assetIds = $scan ? [(int) $scan->asset_id] : [];
        } elseif ($r->kind === 'asset') {
            $assetIds = [(int) $r->asset_id];
        } else {
            $assetIds = array_map(fn ($a) => (int) $a->id, Assets::forClient($clientId));
        }
        $assets = $assetIds ? Db::rows(Db::table('mod_mcsec_assets')->where('client_id', $clientId)->whereIn('id', $assetIds)) : [];
        $byId = [];
        foreach ($assets as $a) {
            $byId[(int) $a->id] = $a;
        }
        $counts = Findings::emptyCounts();
        $rank = "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";
        $open = $assetIds ? Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $clientId)->whereIn('asset_id', $assetIds)->where('status', 'open')
            ->orderByRaw($rank . ' DESC')->orderByDesc('last_seen_at')->limit(500)) : [];
        foreach ($open as $f) {
            $counts[$f->severity] = ($counts[$f->severity] ?? 0) + 1;
        }
        $findings = [];
        foreach (array_slice($open, 0, self::MAX_FINDINGS) as $f) {
            $kb = Kb::get((string) $f->kb !== '' ? (string) $f->kb : Kb::match((string) $f->source_key, (string) $f->title)) ?? Kb::get('generic');
            $findings[] = [
                'id' => (int) $f->id, 'title' => (string) $f->title, 'severity' => (string) $f->severity, 'asset' => (string) ($byId[(int) $f->asset_id]->value ?? ''),
                'location' => (string) $f->location, 'description' => mb_substr((string) $f->description, 0, 700), 'evidence' => mb_substr((string) $f->evidence, 0, 400),
                'solution' => mb_substr((string) $f->solution, 0, 700), 'cve' => (string) $f->cve, 'cvss' => $f->cvss !== null ? (float) $f->cvss : null,
                'first_seen' => (int) $f->first_seen_at, 'new' => $scan ? (int) $f->first_scan_id === (int) $scan->id : (int) $f->first_seen_at >= (int) $r->period_from && (int) $r->period_from > 0,
                'source_key' => (string) $f->source_key, 'kb' => $kb ? ['title' => $kb['title'], 'why' => $kb['why'], 'steps' => $kb['steps'], 'snippets' => $kb['snippets'] ?? [], 'effort' => $kb['effort'] ?? ''] : null,
            ];
        }
        $from = (int) $r->period_from;
        $to = (int) $r->period_to ?: Clock::now();
        $fixed = $assetIds ? Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $clientId)->whereIn('asset_id', $assetIds)->where('status', 'fixed')
            ->where('fixed_at', '>=', $scan ? (int) $scan->started_at : ($from ?: Clock::now() - 30 * 86400))->limit(50)->select(['id', 'title', 'severity', 'location', 'fixed_at'])) : [];
        $score = $r->kind === 'account' || $r->kind === 'periodic' ? Score::forClient($clientId)['score'] : Score::fromCounts($counts);
        $scans = [];
        if ($r->kind === 'periodic' || $r->kind === 'account') {
            foreach (Db::rows(Db::table('mod_mcsec_scans')->where('client_id', $clientId)->where('finished_at', '>=', $from ?: Clock::now() - 30 * 86400)->where('finished_at', '<=', $to)
                ->orderByDesc('id')->limit(50)) as $s) {
                $scans[] = ['id' => (int) $s->id, 'profile' => (string) (Catalog::all(true)[$s->profile]['label'] ?? $s->profile), 'asset' => (string) ($byId[(int) $s->asset_id]->value ?? ''),
                    'status' => (string) $s->status, 'finished_at' => (int) $s->finished_at];
            }
        }
        $newCount = count(array_filter($findings, fn ($f) => $f['new']));
        return [
            'v' => 1, 'kind' => (string) $r->kind, 'title' => (string) $r->title, 'generated_at' => Clock::now(), 'client' => Whmcs::clientName($clientId),
            'period' => ['from' => $from, 'to' => $to], 'scan' => $scan ? ['id' => (int) $scan->id, 'profile' => (string) (Catalog::all(true)[$scan->profile]['label'] ?? $scan->profile),
                'started_at' => (int) $scan->started_at, 'finished_at' => (int) $scan->finished_at, 'summary' => Scans::summary($scan)] : null,
            'assets' => array_map(fn ($a) => ['id' => (int) $a->id, 'value' => (string) $a->value, 'status' => (string) $a->status, 'score' => (int) $a->score, 'counts' => Assets::counts($a)], $assets),
            'score' => $score, 'score_label' => Score::label($score), 'counts' => $counts, 'open_total' => count($open),
            'findings' => $findings, 'more' => max(0, count($open) - self::MAX_FINDINGS), 'fixed' => array_map(fn ($f) => (array) $f, $fixed),
            'surface' => $assetIds ? self::surfaceSummary($assetIds) : [], 'scans' => $scans,
            'basic_summary' => self::basicSummary($counts, $score, count($fixed), $newCount, $findings),
        ];
    }

    private static function surfaceSummary(array $assetIds): array
    {
        $out = ['counts' => array_fill_keys(array_keys(Surface::KINDS), 0), 'ports' => [], 'tech' => []];
        foreach (Db::rows(Db::table('mod_mcsec_surface')->whereIn('asset_id', $assetIds)->where('gone_at', 0)->orderBy('kind')->limit(800)) as $s) {
            $out['counts'][$s->kind] = ($out['counts'][$s->kind] ?? 0) + 1;
            if ($s->kind === 'port' && count($out['ports']) < 40) {
                $out['ports'][] = (string) $s->value;
            }
            if ($s->kind === 'tech' && count($out['tech']) < 30) {
                $out['tech'][] = (string) $s->value;
            }
        }
        $out['tech'] = array_values(array_unique($out['tech']));
        return $out;
    }

    /** A rule-based executive summary in Persian (what the AI section improves on). @return string[] */
    public static function basicSummary(array $c, int $score, int $fixed, int $new, array $findings): array
    {
        $lines = [];
        if ($score < 0) {
            return ['هنوز اسکنی کامل نشده است؛ پس از اولین اسکن، وضعیت این‌جا خلاصه می‌شود.'];
        }
        $lines[] = 'امتیاز امنیت: ' . Text::fa($score) . ' از ۱۰۰ (' . Score::label($score) . ').';
        $urgent = $c['critical'] + $c['high'];
        if ($urgent > 0) {
            $lines[] = Text::fa($urgent) . ' مشکل بحرانی یا مهم باز است که بهتر است همین هفته رفع شود.';
            $top = array_values(array_filter($findings, fn ($f) => in_array($f['severity'], ['critical', 'high'], true)));
            foreach (array_slice($top, 0, 3) as $f) {
                $lines[] = 'اولویت: ' . $f['title'] . ' (' . $f['location'] . ')';
            }
        } elseif ($c['medium'] > 0) {
            $lines[] = 'مشکل بحرانی باز نیست؛ ' . Text::fa($c['medium']) . ' مورد با اهمیت متوسط مانده که در برنامه‌ی این ماه بگنجانید.';
        } else {
            $lines[] = 'مشکل مهمی باز نیست. اسکن‌های دوره‌ای را ادامه دهید تا تغییرها دیده شوند.';
        }
        if ($new > 0) {
            $lines[] = Text::fa($new) . ' یافته‌ی تازه در این دوره دیده شد.';
        }
        if ($fixed > 0) {
            $lines[] = Text::fa($fixed) . ' مشکل رفع شد؛ آفرین.';
        }
        return $lines;
    }

    /**
     * The AI section: summary, risks, quick wins, a 30-day plan and a fix per finding (from cache when the same type
     * was explained before). @return array{ok:bool,data?:array,error?:string}
     */
    public static function enrich(array $data): array
    {
        $items = [];
        foreach (array_slice($data['findings'], 0, self::AI_FINDINGS) as $f) {
            $items[] = ['id' => $f['id'], 'title' => $f['title'], 'severity' => $f['severity'], 'location' => Ai::mask($f['location']), 'asset' => $f['asset'],
                'description' => Ai::mask(mb_substr($f['description'], 0, 400)), 'evidence' => Ai::mask(mb_substr($f['evidence'], 0, 200)), 'cve' => $f['cve'], 'is_new' => $f['new']];
        }
        $payload = ['report_kind' => $data['kind'], 'score' => $data['score'], 'open_counts' => $data['counts'], 'open_total' => $data['open_total'],
            'fixed_recently' => count($data['fixed']), 'surface' => ['ports' => array_slice($data['surface']['ports'] ?? [], 0, 25), 'technologies' => array_slice($data['surface']['tech'] ?? [], 0, 25)],
            'findings' => $items];
        $user = "Analyse this scan data and write the report.\n<scan_data>\n" . Db::json($payload) . "\n</scan_data>\n"
            . "Return JSON exactly in this shape (all prose in Persian):\n"
            . '{"executive_summary":"3-6 sentences for a business owner","risk_level":"critical|high|medium|low","key_risks":[{"title":"","impact":"","finding_ids":[1]}],'
            . '"quick_wins":["short actionable items that take under an hour"],"plan":[{"when":"این هفته|این ماه|سه ماه آینده","action":""}],'
            . '"findings":[{"id":1,"priority":1,"why":"why it matters here, 1-2 sentences","steps":["concrete step"],"snippet":{"label":"nginx|Apache|WordPress|cPanel|DNS|...","code":""},"verify":"how to check the fix","effort":"e.g. ۱۵ دقیقه","needs_confirmation":false}]}'
            . "\nCover every finding id you were given in \"findings\" (at most " . self::AI_FINDINGS . '); keep snippets short and correct; omit "snippet" when not applicable.';
        $r = Ai::chat(Ai::SYSTEM, $user, true);
        if (!$r['ok'] || !is_array($r['json'])) {
            return ['ok' => false, 'error' => $r['ok'] ? 'invalid JSON' : $r['error']];
        }
        return ['ok' => true, 'data' => self::cleanAi($r['json'], array_column($items, 'id'))];
    }

    /** Keeps only the expected keys and types of the model's answer (it is rendered escaped anyway). */
    private static function cleanAi(array $j, array $ids): array
    {
        $str = fn ($v, int $max = 1200) => mb_substr(is_scalar($v) ? trim((string) $v) : '', 0, $max);
        $out = ['executive_summary' => $str($j['executive_summary'] ?? '', 3000), 'risk_level' => in_array($j['risk_level'] ?? '', ['critical', 'high', 'medium', 'low'], true) ? $j['risk_level'] : '',
            'key_risks' => [], 'quick_wins' => [], 'plan' => [], 'findings' => [], 'model' => Settings::get('ai_model')];
        foreach (array_slice((array) ($j['key_risks'] ?? []), 0, 8) as $k) {
            if (is_array($k)) {
                $out['key_risks'][] = ['title' => $str($k['title'] ?? '', 200), 'impact' => $str($k['impact'] ?? '', 600), 'finding_ids' => array_values(array_intersect(array_map('intval', (array) ($k['finding_ids'] ?? [])), $ids))];
            }
        }
        foreach (array_slice((array) ($j['quick_wins'] ?? []), 0, 8) as $q) {
            if (is_string($q) && trim($q) !== '') {
                $out['quick_wins'][] = $str($q, 300);
            }
        }
        foreach (array_slice((array) ($j['plan'] ?? []), 0, 10) as $p) {
            if (is_array($p)) {
                $out['plan'][] = ['when' => $str($p['when'] ?? '', 40), 'action' => $str($p['action'] ?? '', 400)];
            }
        }
        foreach ((array) ($j['findings'] ?? []) as $f) {
            if (!is_array($f) || !in_array((int) ($f['id'] ?? 0), $ids, true)) {
                continue;
            }
            $snip = is_array($f['snippet'] ?? null) ? ['label' => $str($f['snippet']['label'] ?? '', 40), 'code' => $str($f['snippet']['code'] ?? '', 2000)] : null;
            $out['findings'][(int) $f['id']] = ['priority' => (int) ($f['priority'] ?? 0), 'why' => $str($f['why'] ?? '', 600), 'steps' => array_map(fn ($s) => $str($s, 400), array_slice(array_filter((array) ($f['steps'] ?? []), 'is_string'), 0, 8)),
                'snippet' => $snip && $snip['code'] !== '' ? $snip : null, 'verify' => $str($f['verify'] ?? '', 400), 'effort' => $str($f['effort'] ?? '', 40), 'needs_confirmation' => !empty($f['needs_confirmation'])];
        }
        return $out;
    }

    /**
     * «راهکار با هوش مصنوعی» for one finding, on the customer's request. Cached by finding type for everyone (the
     * location and evidence are not part of the cache key, and not in the cached text). @return array{ok:bool,data?:array,error?:string,cached?:bool}
     */
    public static function aiFix(array $who, int $findingId): array
    {
        $f = Findings::get($who['client_id'], $findingId);
        if (!$f) {
            return ['ok' => false, 'error' => 'این یافته پیدا نشد.'];
        }
        $key = 'fix:' . sha1(strtolower((string) $f->source_key) . '|' . mb_strtolower((string) $f->title) . '|fa');
        $cached = Db::table('mod_mcsec_ai_cache')->where('k', $key)->first();
        if ($cached) {
            Db::table('mod_mcsec_ai_cache')->where('k', $key)->increment('hits');
            return ['ok' => true, 'data' => json_decode((string) $cached->content, true) ?: [], 'cached' => true];
        }
        if (!Ai::configured() || !Plans::limits($who['client_id'])['ai']) {
            return ['ok' => false, 'error' => 'راهکار هوش مصنوعی فعلاً در دسترس نیست؛ راهنمای پایه‌ی همین صفحه را ببینید.'];
        }
        if (!RateLimit::hit('aifix:' . $who['client_id'], 30, 86400)) {
            return ['ok' => false, 'error' => 'امروز درخواست زیادی برای راهکار هوش مصنوعی فرستاده‌اید.'];
        }
        $cost = max(0, Settings::int('ai_fix_cost'));
        $ref = 'aifix:' . $f->id . ':' . Clock::today();
        if ($cost > 0) {
            $paid = Credits::spend($who['client_id'], $cost, $ref, 'راهکار هوش مصنوعی: ' . $f->title);
            if (!$paid['ok']) {
                return ['ok' => false, 'error' => $paid['error']];
            }
        }
        $data = ['title' => (string) $f->title, 'severity' => (string) $f->severity, 'source' => (string) $f->source_key, 'cve' => (string) $f->cve,
            'description' => Ai::mask(mb_substr((string) $f->description, 0, 600)), 'scanner_solution' => Ai::mask(mb_substr((string) $f->solution, 0, 600)), 'technologies' => self::techOf((int) $f->asset_id)];
        $user = "Explain and give the fix for this kind of finding. Do not mention any specific hostname or IP.\n<scan_data>\n" . Db::json($data) . "\n</scan_data>\n"
            . 'Return JSON: {"summary":"one sentence","why":"2-3 sentences","steps":["..."],"snippets":[{"label":"nginx|Apache|WordPress|cPanel|DirectAdmin|IIS|DNS|PHP","code":"..."}],"verify":"how to confirm the fix","effort":"","references":["https://..."]}';
        @set_time_limit(120);
        $r = Ai::chat(Ai::SYSTEM, $user, true, 2500);
        if (!$r['ok'] || !is_array($r['json'])) {
            if ($cost > 0) {
                Credits::refund($who['client_id'], $ref, 'بازگشت اعتبار راهکار هوش مصنوعی');
            }
            return ['ok' => false, 'error' => 'پاسخ هوش مصنوعی دریافت نشد؛ کمی بعد دوباره امتحان کنید.'];
        }
        $j = $r['json'];
        $s = fn ($v, $m = 800) => mb_substr(is_scalar($v) ? trim((string) $v) : '', 0, $m);
        $clean = ['summary' => $s($j['summary'] ?? '', 300), 'why' => $s($j['why'] ?? ''), 'steps' => array_map(fn ($x) => $s($x, 400), array_slice(array_filter((array) ($j['steps'] ?? []), 'is_string'), 0, 10)),
            'snippets' => [], 'verify' => $s($j['verify'] ?? '', 400), 'effort' => $s($j['effort'] ?? '', 40),
            'references' => array_values(array_filter(array_map(fn ($u) => $s($u, 300), (array) ($j['references'] ?? [])), fn ($u) => (bool) preg_match('~^https://~', $u))), 'model' => Settings::get('ai_model')];
        foreach (array_slice((array) ($j['snippets'] ?? []), 0, 5) as $sn) {
            if (is_array($sn) && !empty($sn['code'])) {
                $clean['snippets'][] = ['label' => $s($sn['label'] ?? '', 40), 'code' => $s($sn['code'], 2000)];
            }
        }
        try {
            Db::table('mod_mcsec_ai_cache')->insert(['k' => $key, 'content' => Db::json($clean), 'model' => Settings::get('ai_model'), 'hits' => 1, 'created_at' => Clock::now()]);
        } catch (\Throwable $e) {
            // cached by a parallel request
        }
        return ['ok' => true, 'data' => $clean, 'cached' => false];
    }

    public static function cachedFix(object $f): ?array
    {
        $key = 'fix:' . sha1(strtolower((string) $f->source_key) . '|' . mb_strtolower((string) $f->title) . '|fa');
        $c = Db::table('mod_mcsec_ai_cache')->where('k', $key)->value('content');
        $d = $c ? json_decode((string) $c, true) : null;
        return is_array($d) ? $d : null;
    }

    private static function techOf(int $assetId): array
    {
        $t = Db::table('mod_mcsec_surface')->where('asset_id', $assetId)->where('kind', 'tech')->where('gone_at', 0)->limit(15)->pluck('value');
        return array_values(array_unique(is_array($t) ? $t : $t->all()));
    }

    /** The weekly/monthly digest: a ready periodic report + one 'digest' event. Returns the report id. */
    public static function periodic(int $clientId, int $from, int $to, string $mode): int
    {
        $id = Db::table('mod_mcsec_reports')->insertGetId(['client_id' => $clientId, 'kind' => 'periodic', 'title' => ($mode === 'monthly' ? 'گزارش ماهانه‌ی امنیت — ' : 'گزارش هفتگی امنیت — ') . Text::date($to, false),
            'status' => 'queued', 'ai' => 0, 'created_at' => Clock::now(), 'period_from' => $from, 'period_to' => $to]);
        self::build($id);
        $r = Db::table('mod_mcsec_reports')->where('id', $id)->first();
        if (!$r || $r->status !== 'ready') {
            return 0;
        }
        $d = self::data($r);
        $newIn = Db::table('mod_mcsec_findings')->where('client_id', $clientId)->where('first_seen_at', '>=', $from)->count();
        $fixedIn = Db::table('mod_mcsec_findings')->where('client_id', $clientId)->where('status', 'fixed')->where('fixed_at', '>=', $from)->count();
        $lines = ['امتیاز امنیت: ' . ($d['score'] >= 0 ? Text::fa($d['score']) . ' از ۱۰۰ (' . $d['score_label'] . ')' : 'هنوز اسکنی نشده'),
            'یافته‌ی تازه در این دوره: ' . Text::fa($newIn) . '، رفع‌شده: ' . Text::fa($fixedIn),
            'باز: بحرانی ' . Text::fa($d['counts']['critical']) . '، بالا ' . Text::fa($d['counts']['high']) . '، متوسط ' . Text::fa($d['counts']['medium']) . '، پایین ' . Text::fa($d['counts']['low']),
            'اسکن‌های این دوره: ' . Text::fa(count($d['scans']))];
        Notify::event($clientId, 'digest', ['report_id' => $id, 'title' => (string) $r->title, 'lines' => $lines], 'dg:' . $clientId . ':' . Clock::today());
        return $id;
    }

    public static function purge(): int
    {
        return Db::table('mod_mcsec_reports')->where('kind', 'periodic')->where('created_at', '<', Clock::now() - 400 * 86400)->delete();
    }
}
