<?php

declare(strict_types=1);

namespace McSec;

/**
 * Notifications. Every event becomes an in-panel notice (once per ref) and, by the account's preferences, outbox
 * rows for e-mail (WHMCS SendEmail), Telegram, Bale and a signed webhook. The worker delivers the outbox with
 * retries; nothing is sent from a page load. Alert fatigue rules: findings below the account's threshold only
 * reach the panel and the periodic digest; one alert per scan, not per finding.
 */
final class Notify
{
    /** event => [label, default channels (besides the panel), shown in preferences] */
    public const EVENTS = [
        'new_findings' => ['یافته‌ی تازه یا برگشته', ['email', 'telegram', 'bale', 'webhook']],
        'new_exposure' => ['درگاه یا میزبان تازه روی اینترنت', ['email', 'telegram', 'bale', 'webhook']],
        'scan_completed' => ['پایان اسکن', ['webhook']],
        'scan_failed' => ['اسکن ناموفق', ['email', 'webhook']],
        'findings_fixed' => ['رفع شدن یافته‌ها', ['webhook']],
        'asset_verified' => ['تأیید مالکیت دارایی', ['email']],
        'asset_lapsed' => ['منقضی شدن تأیید', ['email', 'telegram', 'bale', 'webhook']],
        'schedule_paused' => ['توقف زمان‌بندی', ['email', 'telegram', 'bale']],
        'credits_low' => ['کم شدن اعتبار', ['email']],
        'credits_added' => ['افزوده شدن اعتبار', ['email']],
        'report_ready' => ['آماده شدن گزارش', []],
        'request_update' => ['درخواست‌های کارشناس', ['email', 'telegram', 'bale']],
        'digest' => ['گزارش دوره‌ای', ['email', 'telegram', 'bale']],
        'kev_alert' => ['آسیب‌پذیری در حال بهره‌برداری (KEV)', ['email', 'telegram', 'bale', 'webhook']],
        'site_down' => ['از دسترس خارج شدن سایت', ['email', 'telegram', 'bale', 'webhook']],
        'site_up' => ['برگشتن سایت', ['email', 'telegram', 'bale', 'webhook']],
        'ssl_expiring' => ['نزدیک شدن انقضای گواهی SSL', ['email', 'telegram', 'bale', 'webhook']],
        'billing' => ['هدیه، دعوت و شارژ خودکار', ['email']],
        'domain_expiring' => ['نزدیک شدن انقضای دامنه', ['email', 'telegram', 'bale']],
        'threat_alert' => ['تهدید تازه برای فناوری‌های شما', ['email', 'telegram', 'bale', 'webhook']],
    ];
    /** Events that existed before 0.2.0: preferences saved earlier know only these; newer ones get their defaults. */
    private const LEGACY_EVENTS = ['new_findings', 'new_exposure', 'scan_completed', 'scan_failed', 'findings_fixed', 'asset_verified', 'asset_lapsed', 'schedule_paused', 'credits_low', 'credits_added', 'report_ready', 'digest'];
    public const CHANNELS = ['email' => 'ایمیل', 'telegram' => 'تلگرام', 'bale' => 'بله', 'webhook' => 'وب‌هوک'];
    public const DIGEST = ['off' => 'نفرست', 'weekly' => 'هفتگی', 'monthly' => 'ماهانه'];

    public static function defaultPrefs(): array
    {
        $ch = [];
        foreach (self::EVENTS as $ev => [, $def]) {
            foreach ($def as $c) {
                $ch[$c][] = $ev;
            }
        }
        return ['channels' => $ch, 'min_severity' => 'medium', 'digest' => 'weekly'];
    }

    public static function prefs(int $clientId): array
    {
        $acc = Accounts::get($clientId);
        $p = $acc ? json_decode((string) $acc->prefs, true) : null;
        if (!is_array($p)) {
            return self::defaultPrefs();
        }
        $p += self::defaultPrefs();
        // events added after these preferences were saved start with their default channels
        $known = array_map('strval', (array) ($p['known'] ?? self::LEGACY_EVENTS));
        foreach (self::EVENTS as $ev => [, $def]) {
            if (in_array($ev, $known, true)) {
                continue;
            }
            foreach ($def as $c) {
                if (!in_array($ev, (array) ($p['channels'][$c] ?? []), true)) {
                    $p['channels'][$c][] = $ev;
                }
            }
        }
        return $p;
    }

    public static function savePrefs(array $who, array $matrix, string $minSeverity, string $digest): array
    {
        $ch = [];
        foreach (self::CHANNELS as $c => $_) {
            $ch[$c] = array_values(array_intersect(array_keys(self::EVENTS), array_map('strval', (array) ($matrix[$c] ?? []))));
        }
        $p = ['channels' => $ch, 'min_severity' => isset(Findings::SEVERITIES[$minSeverity]) ? $minSeverity : 'medium', 'digest' => isset(self::DIGEST[$digest]) ? $digest : 'weekly', 'known' => array_keys(self::EVENTS)];
        Accounts::update($who['client_id'], ['prefs' => Db::json($p)]);
        Audit::log($who['client_id'], 'notify_save', '', $p, $who['user_id']);
        return ['ok' => true];
    }

    /** Records an event: panel notice + outbox rows, written in the account's own language. Idempotent per ref. */
    public static function event(int $clientId, string $event, array $data, string $ref): void
    {
        try {
            $lang = Lang::forClient($clientId);
        } catch (\Throwable $e) {
            $lang = 'fa';
        }
        Lang::with($lang, fn () => self::record($clientId, $event, $data, $ref));
    }

    private static function record(int $clientId, string $event, array $data, string $ref): void
    {
        try {
            $msg = self::message($event, $data);
            if ($msg === null) {
                return;
            }
            $inserted = false;
            try {
                Db::table('mod_mcsec_notices')->insert(['client_id' => $clientId, 'event' => $event, 'title' => mb_substr($msg['title'], 0, 255), 'body' => implode("\n", $msg['lines']),
                    'link' => $msg['link'], 'tone' => $msg['tone'], 'ref' => substr($event . ':' . $ref, 0, 96), 'created_at' => Clock::now()]);
                $inserted = true;
            } catch (\Throwable $e) {
                // the same ref was already announced
            }
            if (!$inserted) {
                return;
            }
            $prefs = self::prefs($clientId);
            $acc = Accounts::get($clientId);
            if ($event === 'new_findings') {
                // only findings at or above the threshold leave the panel
                $min = Findings::rank((string) $prefs['min_severity']);
                $data['findings'] = array_values(array_filter((array) ($data['findings'] ?? []), fn ($f) => Findings::rank((string) $f['severity']) >= $min));
                if (!$data['findings']) {
                    return;
                }
                $msg = self::message($event, $data) ?? $msg;
            }
            foreach (self::CHANNELS as $channel => $_) {
                if (!in_array($event, (array) ($prefs['channels'][$channel] ?? []), true) || !self::channelReady($channel, $acc)) {
                    continue;
                }
                try {
                    Db::table('mod_mcsec_outbox')->insert(['client_id' => $clientId, 'channel' => $channel, 'event' => $event,
                        'payload' => Db::json(['msg' => $msg, 'data' => $data]), 'status' => 'pending', 'next_try_at' => Clock::now(), 'ref' => substr($channel . ':' . $event . ':' . $ref, 0, 120), 'created_at' => Clock::now()]);
                } catch (\Throwable $e) {
                    // already queued
                }
            }
        } catch (\Throwable $e) {
            Trace::error('notify', 'event.' . $event, $e->getMessage(), Trace::exception($e), ['client_id' => $clientId]);
        }
    }

    public static function channelReady(string $channel, ?object $acc): bool
    {
        return match ($channel) {
            'email' => Settings::bool('email_enabled'),
            'telegram' => $acc && (string) $acc->tg_chat !== '' && Settings::secret('telegram_token') !== '',
            'bale' => $acc && (string) $acc->bale_chat !== '' && Settings::secret('bale_token') !== '',
            'webhook' => $acc && (string) $acc->webhook_url !== '' && Settings::bool('webhook_enabled'),
            default => false,
        };
    }

    /**
     * Title, lines, link and tone of one event, in the current language (event() and the callers run it in the
     * account's own language). @return array{title:string,lines:string[],link:string,tone:string}|null
     */
    public static function message(string $event, array $d): ?array
    {
        $asset = (string) ($d['asset'] ?? '');
        $sev = fn (string $s) => isset(Findings::SEVERITIES[$s]) ? Lang::t(Findings::SEVERITIES[$s]['label']) : $s;
        switch ($event) {
            case 'new_findings':
                $f = (array) ($d['findings'] ?? []);
                if (!$f) {
                    return null;
                }
                $lines = [];
                foreach (array_slice($f, 0, 8) as $x) {
                    $lines[] = '• [' . $sev((string) $x['severity']) . '] ' . $x['title'] . ' — ' . $x['location'] . (!empty($x['reopened']) ? ' ' . Lang::t('(دوباره دیده شد)') : '');
                }
                if (count($f) > 8) {
                    $lines[] = Lang::t('و {n} مورد دیگر.', ['n' => Text::fa(count($f) - 8)]);
                }
                $top = (string) ($f[0]['severity'] ?? 'info');
                return ['title' => Lang::t('{n} یافته‌ی تازه روی {asset}', ['n' => Text::fa(count($f)), 'asset' => $asset]), 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=findings&scan=' . (int) ($d['scan_id'] ?? 0), 'tone' => Findings::rank($top) >= 4 ? 'err' : 'warn'];
            case 'new_exposure':
                $lines = array_map(fn ($i) => '• ' . (isset(Surface::KINDS[$i['kind']]) ? Lang::t(Surface::KINDS[$i['kind']]) : $i['kind']) . ': ' . $i['value'], array_slice((array) ($d['items'] ?? []), 0, 10));
                return ['title' => Lang::t('چیز تازه‌ای از {asset} روی اینترنت دیده شد', ['asset' => $asset]), 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=asset&id=' . self::assetIdFromScan((int) ($d['scan_id'] ?? 0)), 'tone' => 'warn'];
            case 'scan_completed':
                $s = (array) ($d['summary'] ?? []);
                $open = (array) ($s['open'] ?? []);
                $lines = [Lang::t('یافته‌ی تازه: {new}، رفع‌شده: {fixed}، دوباره دیده‌شده: {reopened}', ['new' => Text::fa((int) ($s['new'] ?? 0)), 'fixed' => Text::fa((int) ($s['fixed'] ?? 0)), 'reopened' => Text::fa((int) ($s['reopened'] ?? 0))])];
                $lines[] = Lang::t('باز: بحرانی {critical}، بالا {high}، متوسط {medium}، پایین {low}', ['critical' => Text::fa((int) ($open['critical'] ?? 0)), 'high' => Text::fa((int) ($open['high'] ?? 0)), 'medium' => Text::fa((int) ($open['medium'] ?? 0)), 'low' => Text::fa((int) ($open['low'] ?? 0))]);
                if (!empty($d['retest'])) {
                    $lines[] = Lang::t('این اسکن برای سنجیدن دوباره‌ی یک یافته بود.');
                }
                if (!empty($s['partial'])) {
                    $lines[] = Lang::t('ارزیابی ناقص: {why}', ['why' => $s['partial']]);
                }
                return ['title' => Lang::t('«{profile}» روی {asset} تمام شد', ['profile' => $d['profile'], 'asset' => $asset]), 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=scan&id=' . (int) ($d['scan_id'] ?? 0), 'tone' => 'ok'];
            case 'scan_failed':
                $lines = [(string) ($d['error'] ?? '')];
                if ((int) ($d['refunded'] ?? 0) > 0) {
                    $lines[] = Lang::t('{n} اعتبار به حسابتان برگشت.', ['n' => Text::fa((int) $d['refunded'])]);
                }
                if (!empty($d['ref'])) {
                    $lines[] = Lang::t('کد پیگیری برای پشتیبانی: {ref}', ['ref' => $d['ref']]);
                }
                return ['title' => Lang::t('«{profile}» روی {asset} انجام نشد', ['profile' => $d['profile'], 'asset' => $asset]), 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=scan&id=' . (int) ($d['scan_id'] ?? 0), 'tone' => 'err'];
            case 'findings_fixed':
                return ['title' => Lang::t('{n} یافته روی {asset} رفع شد', ['n' => Text::fa((int) ($d['count'] ?? 0)), 'asset' => $asset]), 'lines' => [Lang::t('در آخرین اسکن دیگر دیده نشدند.')], 'link' => 'index.php?m=mcsec&p=findings&status=fixed', 'tone' => 'ok'];
            case 'asset_verified':
                return ['title' => Lang::t('مالکیت {asset} تأیید شد', ['asset' => $asset]), 'lines' => [Lang::t('حالا می‌توانید اسکن بگیرید یا زمان‌بندی بسازید.')], 'link' => 'index.php?m=mcsec&p=asset&id=' . (int) ($d['asset_id'] ?? 0), 'tone' => 'ok'];
            case 'asset_lapsed':
                return ['title' => Lang::t('تأیید مالکیت {asset} منقضی شد', ['asset' => $asset]), 'lines' => [Lang::t('رکورد یا فایل تأیید دیگر پیدا نمی‌شود؛ زمان‌بندی‌های این دارایی متوقف شد. آن را برگردانید تا دوباره تأیید شود.')], 'link' => 'index.php?m=mcsec&p=asset&id=' . (int) ($d['asset_id'] ?? 0), 'tone' => 'warn'];
            case 'schedule_paused':
                return ['title' => Lang::t('زمان‌بندی «{profile}» متوقف شد', ['profile' => $d['profile']]), 'lines' => [Lang::t('دلیل: {reason}', ['reason' => $d['reason']]), (string) ($d['detail'] ?? '')], 'link' => 'index.php?m=mcsec&p=schedules', 'tone' => 'warn'];
            case 'credits_low':
                return ['title' => Lang::t('اعتبار اسکن شما رو به پایان است'), 'lines' => [Lang::t('مانده: {n} اعتبار. زمان‌بندی‌ها بدون اعتبار متوقف می‌شوند.', ['n' => Text::fa((int) ($d['total'] ?? 0))])], 'link' => 'index.php?m=mcsec&p=credits', 'tone' => 'warn'];
            case 'credits_added':
                return ['title' => Lang::t('{n} اعتبار اسکن افزوده شد', ['n' => Text::fa((int) ($d['credits'] ?? 0))]), 'lines' => !empty($d['note']) ? [(string) $d['note']] : [Lang::t('ممنون از خریدتان.')], 'link' => 'index.php?m=mcsec&p=credits', 'tone' => 'ok'];
            case 'request_update':
                $id = Text::fa((int) ($d['id'] ?? 0));
                $link = 'index.php?m=mcsec&p=support';
                switch ((string) ($d['what'] ?? '')) {
                    case 'quoted':
                        return ['title' => Lang::t('قیمت تست دستی شما اعلام شد (درخواست {id})', ['id' => $id]), 'lines' => [Lang::t('قیمت: {n} اعتبار. آن را در صفحه‌ی «کمک کارشناس» ببینید و تأیید یا رد کنید؛ تا تأیید نکنید چیزی کم نمی‌شود.', ['n' => Text::fa((int) ($d['credits'] ?? 0))])], 'link' => $link, 'tone' => 'warn'];
                    case 'paid':
                        return ['title' => Lang::t('پرداخت درخواست {id} رسید', ['id' => $id]), 'lines' => [Lang::t('کارشناس کار را شروع می‌کند و در تیکت خبرتان می‌کند.')], 'link' => $link, 'tone' => 'ok'];
                    case 'working':
                        return ['title' => Lang::t('کارشناس روی درخواست {id} کار می‌کند', ['id' => $id]), 'lines' => [], 'link' => $link, 'tone' => 'info'];
                    case 'done':
                        return ['title' => Lang::t('درخواست {id} انجام شد', ['id' => $id]), 'lines' => [Lang::t('نتیجه را در تیکت همین درخواست ببینید.')], 'link' => $link, 'tone' => 'ok'];
                    case 'cancelled':
                        return ['title' => Lang::t('درخواست {id} لغو شد', ['id' => $id]), 'lines' => array_values(array_filter([(int) ($d['refunded'] ?? 0) > 0 ? Lang::t('{n} اعتبار به حسابتان برگشت.', ['n' => Text::fa((int) $d['refunded'])]) : '',
                            (int) ($d['invoice'] ?? 0) > 0 ? Lang::t('برای بازگشت مبلغ فاکتور، پشتیبانی با شما هماهنگ می‌کند.') : ''])), 'link' => $link, 'tone' => 'info'];
                }
                return null;
            case 'report_ready':
                return ['title' => Lang::t('گزارش «{title}» آماده است', ['title' => $d['title'] ?? '']), 'lines' => [], 'link' => 'index.php?m=mcsec&p=report&id=' . (int) ($d['report_id'] ?? 0), 'tone' => 'info'];
            case 'kev_alert':
                $f = (array) ($d['findings'] ?? []);
                if (!$f) {
                    return null;
                }
                $lines = [];
                foreach (array_slice($f, 0, 8) as $x) {
                    $lines[] = '• ' . $x['title'] . ' — ' . $x['location'] . ' (' . $x['cve'] . ')';
                }
                $lines[] = Lang::t('سازمان امنیت سایبری آمریکا (CISA) این آسیب‌پذیری را در فهرست «در حال بهره‌برداری فعال» (KEV) گذاشته است: مهاجمان همین حالا از آن استفاده می‌کنند. همین امروز رفعش کنید.');
                return ['title' => count($f) === 1 ? Lang::t('یک آسیب‌پذیری باز شما اکنون در حال بهره‌برداری فعال است') : Lang::t('{n} آسیب‌پذیری باز شما اکنون در حال بهره‌برداری فعال‌اند', ['n' => Text::fa(count($f))]),
                    'lines' => $lines, 'link' => count($f) === 1 ? 'index.php?m=mcsec&p=finding&id=' . (int) $f[0]['id'] : 'index.php?m=mcsec&p=findings', 'tone' => 'err'];
            case 'site_down':
                return ['title' => Lang::t('{asset} از دسترس خارج شد', ['asset' => $asset]),
                    'lines' => [!empty($d['note']) ? Lang::t('دو بررسی پشت سر هم پاسخی نگرفت: {note}.', ['note' => $d['note']]) : Lang::t('دو بررسی پشت سر هم پاسخی نگرفت.'), Lang::t('وقتی دوباره در دسترس شد خبر می‌دهیم.')],
                    'link' => 'index.php?m=mcsec&p=asset&id=' . (int) ($d['asset_id'] ?? 0), 'tone' => 'err'];
            case 'site_up':
                $m = intdiv(max(0, (int) ($d['down_for'] ?? 0)), 60);
                return ['title' => Lang::t('{asset} دوباره در دسترس است', ['asset' => $asset]),
                    'lines' => [$m >= 120 ? Lang::t('حدود {n} ساعت از دسترس خارج بود.', ['n' => Text::fa(intdiv($m, 60))]) : Lang::t('حدود {n} دقیقه از دسترس خارج بود.', ['n' => Text::fa(max(1, $m))])],
                    'link' => 'index.php?m=mcsec&p=asset&id=' . (int) ($d['asset_id'] ?? 0), 'tone' => 'ok'];
            case 'ssl_expiring':
                $days = (int) ($d['days'] ?? 0);
                return ['title' => $days < 0 ? Lang::t('گواهی SSL {asset} منقضی شده است', ['asset' => $asset])
                        : ($days === 0 ? Lang::t('گواهی SSL {asset} امروز منقضی می‌شود', ['asset' => $asset]) : Lang::t('گواهی SSL {asset} {n} روز دیگر منقضی می‌شود', ['asset' => $asset, 'n' => Text::fa($days)])),
                    'lines' => [Lang::t('تاریخ انقضا: {date}', ['date' => Text::ymd((string) ($d['end'] ?? ''))]), $days < 0 ? Lang::t('مرورگرها اکنون برای بازدیدکنندگان هشدار امنیتی نشان می‌دهند.') : Lang::t('اگر تمدید خودکار دارید، بررسی کنید که کار می‌کند؛ وگرنه همین حالا تمدید کنید.')],
                    'link' => 'index.php?m=mcsec&p=asset&id=' . (int) ($d['asset_id'] ?? 0), 'tone' => $days < 0 ? 'err' : 'warn'];
            case 'domain_expiring':
                $days = (int) ($d['days'] ?? 0);
                $dom = (string) ($d['domain'] ?? '');
                return ['title' => $days <= 0 ? Lang::t('دامنه‌ی {domain} امروز منقضی می‌شود', ['domain' => $dom]) : Lang::t('دامنه‌ی {domain} {n} روز دیگر منقضی می‌شود', ['domain' => $dom, 'n' => Text::fa($days)]),
                    'lines' => [Lang::t('تاریخ انقضا: {date}', ['date' => Text::ymd((string) ($d['end'] ?? ''))]), !empty($d['auto']) ? Lang::t('تمدید خودکار روشن است؛ مطمئن شوید فاکتور تمدید پرداخت می‌شود.') : Lang::t('تمدید خودکار این دامنه خاموش است.'),
                        Lang::t('دامنه‌ی منقضی‌شده سایت و ایمیل را از کار می‌اندازد و ممکن است دیگری آن را ثبت کند.')],
                    'link' => 'clientarea.php?action=domains', 'tone' => $days <= 7 ? 'err' : 'warn'];
            case 'threat_alert':
                // product and CVE come from CISA's catalogue; hosts are this account's own assets
                $hosts = array_slice(array_map('strval', (array) ($d['assets'] ?? [])), 0, 5);
                return ['title' => Lang::t('آسیب‌پذیری تازه‌ی {product} در حمله‌های واقعی استفاده می‌شود', ['product' => (string) ($d['product'] ?? '')]),
                    'lines' => array_values(array_filter([(string) ($d['cve'] ?? '') . ((string) ($d['name'] ?? '') !== '' ? ' — ' . (string) $d['name'] : ''),
                        Lang::t('این فناوری روی {hosts} دیده شده است.', ['hosts' => Lang::join($hosts)]),
                        Lang::t('دیده شدن فناوری یعنی نسخه‌ی شما حتماً آسیب‌پذیر نیست. پیشنهاد ما: نرم‌افزار را به‌روز کنید و با «اسکن آسیب‌پذیری» مطمئن شوید.')], 'strlen')),
                    'link' => 'index.php?m=mcsec&p=scans#new', 'tone' => 'warn'];
            case 'billing':
                // text and link are written by this module (Credits, Codes) in the account's language, never by a customer
                return ['title' => (string) ($d['title'] ?? ''), 'lines' => array_map('strval', (array) ($d['lines'] ?? [])), 'link' => (string) ($d['link'] ?? 'index.php?m=mcsec&p=credits'), 'tone' => (string) ($d['tone'] ?? 'info')];
            case 'digest':
                return ['title' => (string) ($d['title'] ?? Lang::t('گزارش دوره‌ای امنیت')), 'lines' => array_map('strval', (array) ($d['lines'] ?? [])), 'link' => 'index.php?m=mcsec&p=report&id=' . (int) ($d['report_id'] ?? 0), 'tone' => 'info'];
        }
        return null;
    }

    private static function assetIdFromScan(int $scanId): int
    {
        return (int) Db::table('mod_mcsec_scans')->where('id', $scanId)->value('asset_id');
    }

    // ── panel notices ──

    public static function unread(int $clientId): int
    {
        return Db::table('mod_mcsec_notices')->where('client_id', $clientId)->where('read_at', 0)->count();
    }

    public static function recent(int $clientId, int $limit = 30): array
    {
        return Db::rows(Db::table('mod_mcsec_notices')->where('client_id', $clientId)->orderByDesc('id')->limit($limit));
    }

    public static function markRead(int $clientId, int $id = 0): int
    {
        $q = Db::table('mod_mcsec_notices')->where('client_id', $clientId)->where('read_at', 0);
        if ($id > 0) {
            $q->where('id', $id);
        }
        return $q->update(['read_at' => Clock::now()]);
    }

    // ── delivery (worker) ──

    public static function deliver(float $deadline): array
    {
        $out = ['sent' => 0, 'failed' => 0];
        foreach (Db::rows(Db::table('mod_mcsec_outbox')->where('status', 'pending')->where('next_try_at', '<=', Clock::now())->orderBy('id')->limit(40)) as $o) {
            if (microtime(true) > $deadline) {
                break;
            }
            $p = json_decode((string) $o->payload, true) ?: [];
            $acc = Accounts::get((int) $o->client_id);
            try {
                // the wrapper of an e-mail is written now, in the language the message itself was written in: the account's
                $r = Lang::with(Lang::forClient((int) $o->client_id), fn () => self::send((string) $o->channel, (int) $o->client_id, $acc, (array) ($p['msg'] ?? []), (string) $o->event, (array) ($p['data'] ?? [])));
            } catch (\Throwable $e) {
                $r = ['ok' => false, 'error' => $e->getMessage(), 'final' => false];
            }
            if ($r['ok']) {
                Db::table('mod_mcsec_outbox')->where('id', $o->id)->update(['status' => 'sent', 'sent_at' => Clock::now(), 'tries' => (int) $o->tries + 1, 'error' => '']);
                $out['sent']++;
                continue;
            }
            $tries = (int) $o->tries + 1;
            $final = !empty($r['final']) || $tries >= 5;
            Db::table('mod_mcsec_outbox')->where('id', $o->id)->update(['status' => $final ? 'failed' : 'pending', 'tries' => $tries,
                'next_try_at' => Clock::now() + [300, 1800, 7200, 43200, 86400][min(4, $tries - 1)], 'error' => mb_substr((string) $r['error'], 0, 255)]);
            if ($final) {
                $out['failed']++;
                Trace::warn('notify', $o->channel, (string) $r['error'], ['outbox' => $o->id], ['client_id' => (int) $o->client_id]);
            }
        }
        return $out;
    }

    /** @return array{ok:bool,error?:string,final?:bool} */
    private static function send(string $channel, int $clientId, ?object $acc, array $msg, string $event, array $data): array
    {
        $url = Whmcs::systemUrl() . ltrim((string) ($msg['link'] ?? ''), '/');
        $text = (string) ($msg['title'] ?? '') . "\n\n" . implode("\n", array_filter((array) ($msg['lines'] ?? []), 'strlen')) . "\n\n" . $url;
        switch ($channel) {
            case 'email':
                $r = Whmcs::sendEmail($clientId, 'MC-Sec | ' . (string) ($msg['title'] ?? ''), self::emailHtml($msg, $url));
                return ['ok' => $r['ok'], 'error' => $r['error'], 'final' => !$r['ok'] && str_contains($r['error'], 'Not Found')];
            case 'telegram':
            case 'bale':
                if (!$acc || ($channel === 'telegram' ? (string) $acc->tg_chat : (string) $acc->bale_chat) === '') {
                    return ['ok' => false, 'error' => 'not linked', 'final' => true];
                }
                return self::bot($channel, 'sendMessage', ['chat_id' => $channel === 'telegram' ? $acc->tg_chat : $acc->bale_chat, 'text' => mb_substr($text, 0, 3800), 'disable_web_page_preview' => true]);
            case 'webhook':
                if (!$acc || (string) $acc->webhook_url === '') {
                    return ['ok' => false, 'error' => 'no webhook', 'final' => true];
                }
                $chk = Net::publicUrl((string) $acc->webhook_url);
                if (!$chk['ok']) {
                    return ['ok' => false, 'error' => (string) $chk['error'], 'final' => true];
                }
                $body = Db::json(['text' => $text, 'event' => $event, 'title' => $msg['title'] ?? '', 'lines' => $msg['lines'] ?? [], 'link' => $url, 'data' => $data, 'client_id' => $clientId, 'sent_at' => gmdate('c', Clock::now())]);
                $sig = hash_hmac('sha256', $body, Crypto::decrypt((string) $acc->webhook_secret));
                $r = Http::request('POST', (string) $acc->webhook_url, ['Content-Type' => 'application/json', 'X-MCSec-Event' => $event, 'X-MCSec-Signature' => 'sha256=' . $sig], $body,
                    ['timeout' => 10, 'connect' => 5, 'resolve' => $chk['resolve'], 'max_bytes' => 65536]);
                return ['ok' => $r['ok'], 'error' => $r['error'] !== '' ? $r['error'] : 'HTTP ' . $r['status'], 'final' => in_array($r['status'], [400, 401, 403, 404, 410], true)];
        }
        return ['ok' => false, 'error' => 'unknown channel', 'final' => true];
    }

    public static function bot(string $which, string $method, array $params): array
    {
        $token = Settings::secret($which === 'telegram' ? 'telegram_token' : 'bale_token');
        if ($token === '') {
            return ['ok' => false, 'error' => 'bot not configured', 'final' => true, 'json' => null];
        }
        $base = $which === 'telegram' ? 'https://api.telegram.org/bot' : 'https://tapi.bale.ai/bot';
        $r = Http::request('POST', $base . $token . '/' . $method, [], $params, ['timeout' => 12, 'connect' => 6]);
        $ok = $r['ok'] && !empty($r['json']['ok']);
        return ['ok' => $ok, 'error' => $ok ? '' : (string) ($r['json']['description'] ?? $r['error'] ?? 'HTTP ' . $r['status']), 'final' => in_array($r['status'], [400, 403], true), 'json' => $r['json']];
    }

    /** Worker: reads bot updates and links chats that sent an account's code ("/start CODE" or the code alone). */
    public static function linkBots(): int
    {
        $n = 0;
        $asked = 0;
        foreach (['telegram', 'bale'] as $which) {
            if (Settings::secret($which === 'telegram' ? 'telegram_token' : 'bale_token') === '') {
                continue;
            }
            $offset = (int) (Kv::get('bot:' . $which . ':offset') ?? '0');
            $r = self::bot($which, 'getUpdates', ['offset' => $offset, 'timeout' => 0, 'limit' => 50]);
            foreach ((array) ($r['json']['result'] ?? []) as $u) {
                $offset = max($offset, (int) ($u['update_id'] ?? 0) + 1);
                $m = $u['message'] ?? null;
                if (!is_array($m) || !isset($m['chat']['id'], $m['text'])) {
                    continue;
                }
                if (preg_match('~^/id\b~i', trim((string) $m['text']))) {
                    self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => 'شناسه‌ی این گفت‌وگو: ' . $m['chat']['id']]); // i18n-skip (no account behind this chat: the admin's own check)
                    continue;
                }
                if (!preg_match('~^(?:/start\s+)?([2-9A-HJ-NP-Z]{8})\s*$~', strtoupper(trim(Text::toAscii((string) $m['text']))), $mm)) {
                    // a question in a chat that is already linked to an account: the assistant answers (never acts) when that is switched on
                    $linked = Settings::bool('assistant_bots') ? Db::table('mod_mcsec_accounts')->where($which === 'telegram' ? 'tg_chat' : 'bale_chat', (string) $m['chat']['id'])->first() : null;
                    if ($linked) {
                        $asked++;
                        // a linked chat is answered in its account's language
                        $answer = Lang::with(Lang::forClient((int) $linked->client_id), fn () => $asked <= 3 ? Assistant::bot((int) $linked->client_id, (string) $m['text'], $which . ':' . (int) ($u['update_id'] ?? 0)) : Lang::t('الان چند پرسش با هم رسیده است. چند دقیقه‌ی دیگر دوباره بپرسید.'));
                        self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => $answer]);
                        continue;
                    }
                    self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => 'برای اتصال، کد ۸ نویسه‌ای را از صفحه‌ی «اعلان‌ها» در بخش امنیت سایبری حساب کاربری‌تان بفرستید.']); // i18n-skip (a chat that is not linked to any account yet)
                    continue;
                }
                $acc = Db::table('mod_mcsec_accounts')->where('link_code', $mm[1])->first();
                if (!$acc) {
                    self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => 'این کد پیدا نشد یا منقضی شده است. کد تازه را از صفحه‌ی اعلان‌ها بردارید.']); // i18n-skip (no account behind this chat)
                    continue;
                }
                Accounts::update((int) $acc->client_id, [$which === 'telegram' ? 'tg_chat' : 'bale_chat' => (string) $m['chat']['id'], 'link_code' => Crypto::code(8)]);
                self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => Lang::with(Lang::forClient((int) $acc->client_id),
                    fn () => Lang::t('اتصال برقرار شد. از این پس اعلان‌های امنیتی حساب «{name}» را این‌جا می‌گیرید.', ['name' => Whmcs::clientName((int) $acc->client_id)]))]);
                $n++;
            }
            Kv::set('bot:' . $which . ':offset', (string) $offset);
        }
        return $n;
    }

    public static function emailHtml(array $msg, string $url): string
    {
        $e = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
        $lines = '';
        foreach ((array) ($msg['lines'] ?? []) as $l) {
            if ($l !== '') {
                $lines .= '<p style="margin:0 0 8px">' . $e($l) . '</p>';
            }
        }
        $color = ['err' => '#b42318', 'warn' => '#b54708', 'ok' => '#067647'][$msg['tone'] ?? ''] ?? '#1d4ed8';
        return '<div ' . Lang::attrs() . ' style="font-family:Tahoma,Arial,sans-serif;line-height:1.9;color:#1f2937;max-width:620px">'
            . '<div style="border-inline-start:4px solid ' . $color . ';padding:4px 12px;margin:0 0 12px"><strong style="font-size:16px">' . $e($msg['title'] ?? '') . '</strong></div>'
            . $lines . '<p style="margin:16px 0"><a href="' . $e($url) . '" style="background:' . $color . ';color:#fff;padding:8px 16px;border-radius:8px;text-decoration:none">' . Lang::t('دیدن در پنل') . '</a></p>'
            . '<p style="font-size:12px;color:#6b7280">' . Lang::t('این پیام از بخش امنیت سایبری مارال کلاد است. تنظیم اعلان‌ها: صفحه‌ی «اعلان‌ها».') . '</p></div>';
    }

    /** Daily: the weekly/monthly digest of each account whose time has come (Tehran time). */
    public static function digests(float $deadline): int
    {
        $tz = new \DateTimeZone('Asia/Tehran');
        $now = (new \DateTimeImmutable('@' . Clock::now()))->setTimezone($tz);
        if ((int) $now->format('G') < Settings::int('digest_hour')) {
            return 0;
        }
        [, , $jd] = Text::jalali((int) $now->format('Y'), (int) $now->format('n'), (int) $now->format('j'));
        $isWeekDay = (int) $now->format('w') === Settings::int('digest_dow');
        $isMonthDay = $jd === 1;
        if (!$isWeekDay && !$isMonthDay) {
            return 0;
        }
        $n = 0;
        $todayStart = $now->setTime(0, 0)->getTimestamp();
        $ids = Db::table('mod_mcsec_accounts')->where('digest_at', '<', $todayStart)->whereIn('client_id', Db::table('mod_mcsec_assets')->where('status', 'verified')->select('client_id'))->limit(300)->pluck('client_id');
        foreach (is_array($ids) ? $ids : $ids->all() as $cid) {
            if (microtime(true) > $deadline) {
                break;
            }
            $cid = (int) $cid;
            $mode = (string) (self::prefs($cid)['digest'] ?? 'weekly');
            if (($mode === 'weekly' && $isWeekDay) || ($mode === 'monthly' && $isMonthDay)) {
                $days = $mode === 'weekly' ? 7 : 31;
                // the digest (report, notice, e-mail) is written in the account's own language
                $rid = (int) Lang::with(Lang::forClient($cid), fn () => Reports::periodic($cid, Clock::now() - $days * 86400, Clock::now(), $mode));
                $n += $rid > 0 ? 1 : 0;
            }
            Accounts::update($cid, ['digest_at' => Clock::now()]);
        }
        return $n;
    }

    public static function purge(): int
    {
        $n = Db::table('mod_mcsec_outbox')->where('created_at', '<', Clock::now() - 60 * 86400)->delete();
        return $n + Db::table('mod_mcsec_notices')->where('created_at', '<', Clock::now() - 180 * 86400)->delete();
    }
}
