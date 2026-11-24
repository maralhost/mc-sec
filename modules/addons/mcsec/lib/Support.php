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
 * - A daily cap per account; each request is a row of Requests (0.15.0) and a line in the activity log.
 * This class makes the ticket; Requests keeps the request, its price and its state.
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

    /** The customer's words, cleaned and measured. @return array{ok:bool,error?:string,text?:string} */
    public static function check(int $clientId, string $text): array
    {
        if (!self::enabled()) {
            return ['ok' => false, 'error' => 'درخواست بررسی کارشناس فعلاً در دسترس نیست. از بخش پشتیبانی تیکت بزنید.'];
        }
        $text = trim(preg_replace('~[^\P{C}\n\t\x{200C}]+~u', '', $text) ?? '');
        if (mb_strlen($text) < 10) {
            return ['ok' => false, 'error' => 'در یکی دو جمله بنویسید چه کمکی می‌خواهید (دست‌کم ۱۰ نویسه).'];
        }
        if (mb_strlen($text) > 4000) {
            return ['ok' => false, 'error' => 'متن بلند است؛ آن را به ۴۰۰۰ نویسه برسانید. جزئیات فنی را خودمان پیوست می‌کنیم.'];
        }
        return ['ok' => true, 'text' => $text];
    }

    /**
     * Opens the ticket of a request (Requests::create). $subject and $lines are written by code in Persian; $text is
     * the customer's own. @return array{ok:bool,error:string,id:int,tid:string,c:string}
     */
    public static function open(array $who, string $subject, string $text, array $refs, array $lines = []): array
    {
        $cid = (int) $who['client_id'];
        $about = $refs['finding'] ? mb_substr((string) $refs['finding']->title, 0, 90) : ($refs['asset'] ? (string) $refs['asset']->value : '');
        // the ticket is read by Maral Cloud's support staff: its subject and context are always Persian
        $subject = Lang::with('fa', fn () => '[' . Settings::menuLabel() . '] ' . $subject . ($about !== '' ? ': ' . $about : ''));
        $dept = Whmcs::supportDept(Settings::int('support_dept'));
        if ($dept <= 0) {
            return ['ok' => false, 'error' => Lang::t('دپارتمان پشتیبانی پیدا نشد. از بخش پشتیبانی تیکت بزنید و این را هم بگویید.'), 'id' => 0, 'tid' => '', 'c' => ''];
        }
        $r = Whmcs::openTicket($cid, $dept, mb_substr($subject, 0, 200), $text . "\n\n----------\n" . ($lines ? implode("\n", $lines) . "\n" : '') . self::context($cid, $refs), Whmcs::planService($cid));
        if (!$r['ok']) {
            $ref = Trace::error('whmcs', 'support.open', (string) $r['error'], [], ['client_id' => $cid]);
            return ['ok' => false, 'error' => Lang::t('تیکت ساخته نشد. کمی بعد دوباره امتحان کنید یا از بخش پشتیبانی تیکت بزنید. کد پیگیری: {ref}', ['ref' => $ref]), 'id' => 0, 'tid' => '', 'c' => ''];
        }
        return ['ok' => true, 'error' => '', 'id' => (int) $r['id'], 'tid' => (string) $r['tid'], 'c' => (string) $r['c']];
    }

    public static function url(string $tid, string $c): string
    {
        return preg_match('~^[A-Za-z0-9-]{1,32}$~', $tid) && preg_match('~^[A-Za-z0-9]{1,32}$~', $c) ? 'viewticket.php?tid=' . $tid . '&c=' . $c : 'supporttickets.php';
    }

}
