<?php

declare(strict_types=1);

namespace McSec;

/**
 * «درخواست بررسی کارشناس» (0.13.0): a customer asks a person at Maral Cloud to look at a finding, a scan, an
 * ownership proof or their whole account, from inside the security section. One short form; the ticket is opened by
 * WHMCS itself (localAPI OpenTicket, through Whmcs::openTicket) in the department the admin chose, with what the
 * expert needs written by code: the asset, the scan and its number, the finding with its severity and location, the
 * tracking code of a failure. So the customer never has to find «امنیت سایبری» in the list of services of the ticket
 * form (it is only there for accounts with a plan service).
 *
 * - Every id from the browser is read through the account's own getters (Assets::get, Scans::get, Findings::get).
 * - The customer's words are sent as plain text; WHMCS escapes them where it shows the ticket.
 * - A daily cap per account; each request is in the activity log with the ticket's number.
 */
final class Support
{
    public const TOPICS = [
        'finding' => 'کمک برای رفع یک یافته',
        'scan' => 'بررسی نتیجه یا خطای یک اسکن',
        'verify' => 'تأیید مالکیت یک دارایی',
        'review' => 'بررسی امنیتی توسط کارشناس',
        'other' => 'پرسش یا درخواست دیگر',
    ];

    public const DAILY = 6;

    public static function enabled(): bool
    {
        return Settings::bool('support_requests');
    }

    /** What the request is about, read through this account's own records. @return array{asset:?object,scan:?object,finding:?object} */
    public static function refs(int $clientId, int $assetId, int $scanId, int $findingId): array
    {
        $finding = $findingId > 0 ? Findings::get($clientId, $findingId) : null;
        $scan = $scanId > 0 ? Scans::get($clientId, $scanId) : null;
        $assetId = $assetId > 0 ? $assetId : (int) ($finding->asset_id ?? $scan->asset_id ?? 0);
        return ['asset' => $assetId > 0 ? Assets::get($clientId, $assetId) : null, 'scan' => $scan, 'finding' => $finding];
    }

    /** The lines code adds under the customer's message; for Maral Cloud's support staff, so always Persian. */
    public static function context(int $clientId, array $refs): string
    {
        return Lang::with('fa', fn () => self::contextFa($clientId, $refs));
    }

    private static function contextFa(int $clientId, array $refs): string
    {
        // i18n-skip-begin (read by support staff, not by the customer)
        $l = [];
        if ($refs['asset']) {
            $a = $refs['asset'];
            $l[] = 'دارایی: ' . $a->value . ' (' . (Assets::KINDS[(string) $a->kind] ?? $a->kind) . '، ' . ($a->status === 'verified' ? 'تأییدشده' : 'تأییدنشده') . ')';
        }
        if ($refs['scan']) {
            $s = $refs['scan'];
            $l[] = 'اسکن شماره‌ی ' . (int) $s->id . ': ' . Catalog::label((string) $s->profile, (string) $s->profile) . ' — ' . (Scans::STATUS[(string) $s->status] ?? $s->status)
                . (trim((string) $s->error) !== '' ? ' — ' . mb_substr((string) $s->error, 0, 200) : '') . ((string) $s->error_ref !== '' ? ' (کد پیگیری ' . $s->error_ref . ')' : '');
            $partial = trim((string) (Scans::summary($s)['partial'] ?? ''));
            if ($partial !== '') {
                $l[] = 'ارزیابی ناقص: ' . mb_substr($partial, 0, 300);
            }
        }
        if ($refs['finding']) {
            $f = $refs['finding'];
            $l[] = 'یافته شماره‌ی ' . (int) $f->id . ': ' . mb_substr((string) $f->title, 0, 200) . ' — شدت ' . (Findings::SEVERITIES[(string) $f->severity]['label'] ?? $f->severity);
            $l[] = 'محل: ' . mb_substr((string) $f->location, 0, 200) . ((string) $f->cve !== '' ? ' — ' . $f->cve : '');
            $l[] = 'پیوند: ' . Whmcs::systemUrl() . 'index.php?m=mcsec&p=finding&id=' . (int) $f->id;
        }
        $l[] = 'حساب #' . $clientId . ' — فرستاده شده از بخش «' . Settings::menuLabel() . '»';
        return implode("\n", $l);
        // i18n-skip-end
    }

    /**
     * Opens the ticket. @param array{topic:string,text:string,asset:int,scan:int,finding:int} $in
     * @return array{ok:bool,error?:string,tid?:string,id?:int,url?:string}
     */
    public static function open(array $who, array $in): array
    {
        $cid = (int) $who['client_id'];
        if (!self::enabled()) {
            return ['ok' => false, 'error' => 'درخواست بررسی کارشناس فعلاً در دسترس نیست. از بخش پشتیبانی تیکت بزنید.'];
        }
        $topic = isset(self::TOPICS[$in['topic']]) ? $in['topic'] : 'other';
        $text = trim(preg_replace('~[^\P{C}\n\t\x{200C}]+~u', '', (string) $in['text']) ?? '');
        if (mb_strlen($text) < 10) {
            return ['ok' => false, 'error' => 'در یکی دو جمله بنویسید چه کمکی می‌خواهید (دست‌کم ۱۰ نویسه).'];
        }
        if (mb_strlen($text) > 4000) {
            return ['ok' => false, 'error' => 'متن بلند است؛ آن را به ۴۰۰۰ نویسه برسانید. جزئیات فنی را خودمان پیوست می‌کنیم.'];
        }
        if (!RateLimit::hit('support:' . $cid, self::DAILY, 86400)) {
            return ['ok' => false, 'error' => 'امروز چند درخواست فرستاده‌اید. ادامه‌ی گفت‌وگو را در همان تیکت‌ها بنویسید یا فردا درخواست تازه بدهید.'];
        }
        $refs = self::refs($cid, (int) $in['asset'], (int) $in['scan'], (int) $in['finding']);
        $about = $refs['finding'] ? mb_substr((string) $refs['finding']->title, 0, 90) : ($refs['asset'] ? (string) $refs['asset']->value : '');
        // the ticket is read by Maral Cloud's support staff: its subject and context are always Persian
        $subject = Lang::with('fa', fn () => '[' . Settings::menuLabel() . '] ' . self::TOPICS[$topic] . ($about !== '' ? ': ' . $about : ''));
        $dept = Whmcs::supportDept(Settings::int('support_dept'));
        if ($dept <= 0) {
            return ['ok' => false, 'error' => 'دپارتمان پشتیبانی پیدا نشد. از بخش پشتیبانی تیکت بزنید و این را هم بگویید.'];
        }
        $r = Whmcs::openTicket($cid, $dept, mb_substr($subject, 0, 200), $text . "\n\n----------\n" . self::context($cid, $refs), Whmcs::planService($cid));
        if (!$r['ok']) {
            $ref = Trace::error('whmcs', 'support.open', (string) $r['error'], ['topic' => $topic], ['client_id' => $cid]);
            return ['ok' => false, 'error' => Lang::t('تیکت ساخته نشد. کمی بعد دوباره امتحان کنید یا از بخش پشتیبانی تیکت بزنید. کد پیگیری: {ref}', ['ref' => $ref])];
        }
        Audit::log($cid, 'support', '#' . $r['tid'], ['topic' => $topic, 'ticket' => (int) $r['id'], 'asset' => (int) ($refs['asset']->id ?? 0), 'scan' => (int) ($refs['scan']->id ?? 0),
            'finding' => (int) ($refs['finding']->id ?? 0), 'c' => (string) $r['c']], (int) $who['user_id']);
        return ['ok' => true, 'tid' => (string) $r['tid'], 'id' => (int) $r['id'], 'url' => self::url((string) $r['tid'], (string) $r['c'])];
    }

    public static function url(string $tid, string $c): string
    {
        return preg_match('~^[A-Za-z0-9-]{1,32}$~', $tid) && preg_match('~^[A-Za-z0-9]{1,32}$~', $c) ? 'viewticket.php?tid=' . $tid . '&c=' . $c : 'supporttickets.php';
    }

    /** The account's own requests, newest first (from the activity log). @return array<int,array{tid:string,topic:string,at:int,url:string}> */
    public static function recent(int $clientId, int $limit = 8): array
    {
        $out = [];
        foreach (Db::rows(Db::table('mod_mcsec_audit')->where('client_id', $clientId)->where('action', 'support')->orderByDesc('id')->limit($limit)) as $r) {
            $d = Db::decode((string) $r->detail, []);
            $tid = ltrim((string) $r->target, '#');
            $out[] = ['tid' => $tid, 'topic' => self::TOPICS[(string) ($d['topic'] ?? '')] ?? self::TOPICS['other'], 'at' => (int) $r->created_at, 'url' => self::url($tid, (string) ($d['c'] ?? ''))];
        }
        return $out;
    }
}
