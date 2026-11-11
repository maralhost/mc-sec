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
        'digest' => ['گزارش دوره‌ای', ['email', 'telegram', 'bale']],
    ];
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
        return is_array($p) ? $p + self::defaultPrefs() : self::defaultPrefs();
    }

    public static function savePrefs(array $who, array $matrix, string $minSeverity, string $digest): array
    {
        $ch = [];
        foreach (self::CHANNELS as $c => $_) {
            $ch[$c] = array_values(array_intersect(array_keys(self::EVENTS), array_map('strval', (array) ($matrix[$c] ?? []))));
        }
        $p = ['channels' => $ch, 'min_severity' => isset(Findings::SEVERITIES[$minSeverity]) ? $minSeverity : 'medium', 'digest' => isset(self::DIGEST[$digest]) ? $digest : 'weekly'];
        Accounts::update($who['client_id'], ['prefs' => Db::json($p)]);
        Audit::log($who['client_id'], 'notify_save', '', $p, $who['user_id']);
        return ['ok' => true];
    }

    /** Records an event: panel notice + outbox rows. Idempotent per ref. */
    public static function event(int $clientId, string $event, array $data, string $ref): void
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

    /** Persian title, lines, link and tone of one event. @return array{title:string,lines:string[],link:string,tone:string}|null */
    public static function message(string $event, array $d): ?array
    {
        $asset = (string) ($d['asset'] ?? '');
        $sev = fn (string $s) => Findings::SEVERITIES[$s]['label'] ?? $s;
        switch ($event) {
            case 'new_findings':
                $f = (array) ($d['findings'] ?? []);
                if (!$f) {
                    return null;
                }
                $lines = [];
                foreach (array_slice($f, 0, 8) as $x) {
                    $lines[] = '• [' . $sev((string) $x['severity']) . '] ' . $x['title'] . ' — ' . $x['location'] . (!empty($x['reopened']) ? ' (دوباره دیده شد)' : '');
                }
                if (count($f) > 8) {
                    $lines[] = 'و ' . Text::fa(count($f) - 8) . ' مورد دیگر.';
                }
                $top = (string) ($f[0]['severity'] ?? 'info');
                return ['title' => Text::fa(count($f)) . ' یافته‌ی تازه روی ' . $asset, 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=findings&scan=' . (int) ($d['scan_id'] ?? 0), 'tone' => Findings::rank($top) >= 4 ? 'err' : 'warn'];
            case 'new_exposure':
                $lines = array_map(fn ($i) => '• ' . (Surface::KINDS[$i['kind']] ?? $i['kind']) . ': ' . $i['value'], array_slice((array) ($d['items'] ?? []), 0, 10));
                return ['title' => 'چیز تازه‌ای از ' . $asset . ' روی اینترنت دیده شد', 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=asset&id=' . self::assetIdFromScan((int) ($d['scan_id'] ?? 0)), 'tone' => 'warn'];
            case 'scan_completed':
                $s = (array) ($d['summary'] ?? []);
                $open = (array) ($s['open'] ?? []);
                $lines = ['یافته‌ی تازه: ' . Text::fa((int) ($s['new'] ?? 0)) . '، رفع‌شده: ' . Text::fa((int) ($s['fixed'] ?? 0)) . '، دوباره دیده‌شده: ' . Text::fa((int) ($s['reopened'] ?? 0))];
                $lines[] = 'باز: بحرانی ' . Text::fa((int) ($open['critical'] ?? 0)) . '، بالا ' . Text::fa((int) ($open['high'] ?? 0)) . '، متوسط ' . Text::fa((int) ($open['medium'] ?? 0)) . '، پایین ' . Text::fa((int) ($open['low'] ?? 0));
                if (!empty($d['retest'])) {
                    $lines[] = 'این اسکن برای سنجیدن دوباره‌ی یک یافته بود.';
                }
                return ['title' => '«' . $d['profile'] . '» روی ' . $asset . ' تمام شد', 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=scan&id=' . (int) ($d['scan_id'] ?? 0), 'tone' => 'ok'];
            case 'scan_failed':
                $lines = [(string) ($d['error'] ?? '')];
                if ((int) ($d['refunded'] ?? 0) > 0) {
                    $lines[] = Text::fa((int) $d['refunded']) . ' اعتبار به حسابتان برگشت.';
                }
                if (!empty($d['ref'])) {
                    $lines[] = 'کد پیگیری برای پشتیبانی: ' . $d['ref'];
                }
                return ['title' => '«' . $d['profile'] . '» روی ' . $asset . ' انجام نشد', 'lines' => $lines, 'link' => 'index.php?m=mcsec&p=scan&id=' . (int) ($d['scan_id'] ?? 0), 'tone' => 'err'];
            case 'findings_fixed':
                return ['title' => Text::fa((int) ($d['count'] ?? 0)) . ' یافته روی ' . $asset . ' رفع شد', 'lines' => ['در آخرین اسکن دیگر دیده نشدند.'], 'link' => 'index.php?m=mcsec&p=findings&status=fixed', 'tone' => 'ok'];
            case 'asset_verified':
                return ['title' => 'مالکیت ' . $asset . ' تأیید شد', 'lines' => ['حالا می‌توانید اسکن بگیرید یا زمان‌بندی بسازید.'], 'link' => 'index.php?m=mcsec&p=asset&id=' . (int) ($d['asset_id'] ?? 0), 'tone' => 'ok'];
            case 'asset_lapsed':
                return ['title' => 'تأیید مالکیت ' . $asset . ' منقضی شد', 'lines' => ['رکورد یا فایل تأیید دیگر پیدا نمی‌شود؛ زمان‌بندی‌های این دارایی متوقف شد. آن را برگردانید تا دوباره تأیید شود.'], 'link' => 'index.php?m=mcsec&p=asset&id=' . (int) ($d['asset_id'] ?? 0), 'tone' => 'warn'];
            case 'schedule_paused':
                return ['title' => 'زمان‌بندی «' . $d['profile'] . '» متوقف شد', 'lines' => ['دلیل: ' . $d['reason'], (string) ($d['detail'] ?? '')], 'link' => 'index.php?m=mcsec&p=schedules', 'tone' => 'warn'];
            case 'credits_low':
                return ['title' => 'اعتبار اسکن شما رو به پایان است', 'lines' => ['مانده: ' . Text::fa((int) ($d['total'] ?? 0)) . ' اعتبار. زمان‌بندی‌ها بدون اعتبار متوقف می‌شوند.'], 'link' => 'index.php?m=mcsec&p=credits', 'tone' => 'warn'];
            case 'credits_added':
                return ['title' => Text::fa((int) ($d['credits'] ?? 0)) . ' اعتبار اسکن افزوده شد', 'lines' => !empty($d['note']) ? [(string) $d['note']] : ['ممنون از خریدتان.'], 'link' => 'index.php?m=mcsec&p=credits', 'tone' => 'ok'];
            case 'report_ready':
                return ['title' => 'گزارش «' . ($d['title'] ?? '') . '» آماده است', 'lines' => [], 'link' => 'index.php?m=mcsec&p=report&id=' . (int) ($d['report_id'] ?? 0), 'tone' => 'info'];
            case 'digest':
                return ['title' => (string) ($d['title'] ?? 'گزارش دوره‌ای امنیت'), 'lines' => array_map('strval', (array) ($d['lines'] ?? [])), 'link' => 'index.php?m=mcsec&p=report&id=' . (int) ($d['report_id'] ?? 0), 'tone' => 'info'];
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
                $r = self::send((string) $o->channel, (int) $o->client_id, $acc, (array) ($p['msg'] ?? []), (string) $o->event, (array) ($p['data'] ?? []));
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
                if (!preg_match('~^(?:/start\s+)?([2-9A-HJ-NP-Z]{8})\s*$~', strtoupper(trim(Text::toAscii((string) $m['text']))), $mm)) {
                    self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => 'برای اتصال، کد ۸ نویسه‌ای را از صفحه‌ی «اعلان‌ها» در بخش امنیت سایبری حساب کاربری‌تان بفرستید.']);
                    continue;
                }
                $acc = Db::table('mod_mcsec_accounts')->where('link_code', $mm[1])->first();
                if (!$acc) {
                    self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => 'این کد پیدا نشد یا منقضی شده است. کد تازه را از صفحه‌ی اعلان‌ها بردارید.']);
                    continue;
                }
                Accounts::update((int) $acc->client_id, [$which === 'telegram' ? 'tg_chat' : 'bale_chat' => (string) $m['chat']['id'], 'link_code' => Crypto::code(8)]);
                self::bot($which, 'sendMessage', ['chat_id' => $m['chat']['id'], 'text' => 'اتصال برقرار شد. از این پس اعلان‌های امنیتی حساب «' . Whmcs::clientName((int) $acc->client_id) . '» را این‌جا می‌گیرید.']);
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
        return '<div dir="rtl" lang="fa" style="font-family:Tahoma,Arial,sans-serif;line-height:1.9;color:#1f2937;max-width:620px">'
            . '<div style="border-inline-start:4px solid ' . $color . ';padding:4px 12px;margin:0 0 12px"><strong style="font-size:16px">' . $e($msg['title'] ?? '') . '</strong></div>'
            . $lines . '<p style="margin:16px 0"><a href="' . $e($url) . '" style="background:' . $color . ';color:#fff;padding:8px 16px;border-radius:8px;text-decoration:none">دیدن در پنل</a></p>'
            . '<p style="font-size:12px;color:#6b7280">این پیام از بخش امنیت سایبری مارال کلاد است. تنظیم اعلان‌ها: صفحه‌ی «اعلان‌ها».</p></div>';
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
                $rid = Reports::periodic($cid, Clock::now() - $days * 86400, Clock::now(), $mode);
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
