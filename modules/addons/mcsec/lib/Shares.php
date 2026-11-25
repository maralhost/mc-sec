<?php

declare(strict_types=1);

namespace McSec;

/**
 * Things an account chose to show to people who have no login (mod_mcsec_shares), each behind a long random token:
 *  - report: a read-only link to one ready report, always with an expiry (1, 7 or 30 days), optionally with a
 *    password (only its hash is kept), withdrawn with one click. The public page shows that report and nothing else.
 *  - badge: a small picture for the customer's own site, «پایش امنیتی · مارال کلاد» with the date of the last
 *    completed scan of one verified domain. It never says "secure", and it turns grey when the last scan is old.
 * Both are off until the admin turns them on (report_share, site_badge). Making one is a POST with a nonce by someone
 * who may manage the account; opening one changes nothing.
 */
final class Shares
{
    public const DAYS = [1, 7, 30];
    private const MAX_PER_REPORT = 5;
    /** A badge is "fresh" while the last completed scan of the asset is younger than this. */
    public const FRESH = 35 * 86400;

    public static function url(string $token): string
    {
        return rtrim(Whmcs::systemUrl(), '/') . '/index.php?m=mcsec&p=shared&t=' . $token;
    }

    public static function badgeUrl(string $token): string
    {
        return rtrim(Whmcs::systemUrl(), '/') . '/index.php?m=mcsec&p=badge&t=' . $token;
    }

    private static function token(): string
    {
        return bin2hex(random_bytes(24));
    }

    /** @return array{ok:bool,error?:string,token?:string} */
    public static function create(array $who, int $reportId, int $days, string $password): array
    {
        if (!Settings::bool('report_share')) {
            return ['ok' => false, 'error' => 'پیوند اشتراکی گزارش روشن نیست.'];
        }
        $cid = (int) $who['client_id'];
        $r = Reports::get($cid, $reportId);
        if (!$r || $r->status !== 'ready') {
            return ['ok' => false, 'error' => 'این گزارش پیدا نشد یا هنوز آماده نیست.'];
        }
        if (!in_array($days, self::DAYS, true)) {
            return ['ok' => false, 'error' => 'مدت پیوند را از فهرست انتخاب کنید.'];
        }
        if ($password !== '' && (mb_strlen($password) < 6 || mb_strlen($password) > 72)) {
            return ['ok' => false, 'error' => 'رمز پیوند باید دست‌کم ۶ نویسه باشد (یا خالی بماند).'];
        }
        if (count(self::forReport($cid, $reportId)) >= self::MAX_PER_REPORT) {
            return ['ok' => false, 'error' => 'این گزارش پنج پیوند فعال دارد. اول یکی را بردارید.'];
        }
        $token = self::token();
        Db::table('mod_mcsec_shares')->insert(['client_id' => $cid, 'kind' => 'report', 'ref_id' => (int) $r->id, 'token' => $token,
            'pass' => $password !== '' ? (string) password_hash($password, PASSWORD_DEFAULT) : '', 'expires_at' => Clock::now() + $days * 86400,
            'created_by' => (int) $who['user_id'], 'created_at' => Clock::now()]);
        Audit::log($cid, 'report_share', (string) $r->title, ['report' => (int) $r->id, 'days' => $days, 'password' => $password !== ''], (int) $who['user_id']);
        return ['ok' => true, 'token' => $token];
    }

    public static function revoke(array $who, int $id): array
    {
        $n = Db::table('mod_mcsec_shares')->where('id', $id)->where('client_id', (int) $who['client_id'])->where('revoked_at', 0)->update(['revoked_at' => Clock::now()]);
        if ($n > 0) {
            Audit::log((int) $who['client_id'], 'report_unshare', '', ['share' => $id], (int) $who['user_id']);
        }
        return $n > 0 ? ['ok' => true] : ['ok' => false, 'error' => 'این پیوند پیدا نشد.'];
    }

    /** Links of one report that still open. @return object[] */
    public static function forReport(int $clientId, int $reportId): array
    {
        return Db::rows(Db::table('mod_mcsec_shares')->where('client_id', $clientId)->where('kind', 'report')->where('ref_id', $reportId)
            ->where('revoked_at', 0)->where('expires_at', '>', Clock::now())->orderByDesc('id'));
    }

    private static function find(string $token, string $kind): ?object
    {
        if (!preg_match('~^[a-f0-9]{48}$~', $token)) {
            return null;
        }
        $s = Db::table('mod_mcsec_shares')->where('token', $token)->where('kind', $kind)->where('revoked_at', 0)->first();
        return $s && hash_equals((string) $s->token, $token) && ((int) $s->expires_at === 0 || (int) $s->expires_at > Clock::now()) ? $s : null;
    }

    /**
     * What a visitor with this token gets. state: none (no such link, expired, withdrawn, feature off), password
     * (it has one and none was given), wrong, limited (too many tries), ok (with the report).
     * @return array{state:string,report?:object,share?:object}
     */
    public static function open(string $token, ?string $password): array
    {
        $s = Settings::bool('report_share') && Settings::bool('enabled') ? self::find($token, 'report') : null;
        $r = $s ? Reports::get((int) $s->client_id, (int) $s->ref_id) : null;
        if (!$s || !$r || $r->status !== 'ready') {
            return ['state' => 'none'];
        }
        if ((string) $s->pass !== '') {
            if ($password === null || $password === '') {
                return ['state' => 'password', 'share' => $s];
            }
            if (!RateLimit::hit('share:' . (int) $s->id, 10, 3600)) {
                return ['state' => 'limited', 'share' => $s];
            }
            if (!password_verify($password, (string) $s->pass)) {
                return ['state' => 'wrong', 'share' => $s];
            }
        }
        return ['state' => 'ok', 'report' => $r, 'share' => $s];
    }

    // ── the badge ──

    public static function badgeOf(int $clientId, int $assetId): ?object
    {
        return Db::table('mod_mcsec_shares')->where('client_id', $clientId)->where('kind', 'badge')->where('ref_id', $assetId)->where('revoked_at', 0)->first();
    }

    /** Turns the badge of one verified domain of this account on (a new token) or off. */
    public static function badge(array $who, int $assetId, bool $on): array
    {
        if (!Settings::bool('site_badge')) {
            return ['ok' => false, 'error' => 'نشان پایش امنیتی روشن نیست.'];
        }
        $cid = (int) $who['client_id'];
        $a = Assets::get($cid, $assetId);
        if (!$a || $a->kind !== 'domain' || $a->status !== 'verified') {
            return ['ok' => false, 'error' => 'نشان فقط برای دامنه‌ی تأییدشده‌ی همین حساب ساخته می‌شود.'];
        }
        $old = self::badgeOf($cid, $assetId);
        if (!$on) {
            if ($old) {
                Db::table('mod_mcsec_shares')->where('id', (int) $old->id)->where('client_id', $cid)->update(['revoked_at' => Clock::now()]);
                Audit::log($cid, 'site_badge', (string) $a->value, ['on' => false], (int) $who['user_id']);
            }
            return ['ok' => true];
        }
        if (!$old) {
            Db::table('mod_mcsec_shares')->insert(['client_id' => $cid, 'kind' => 'badge', 'ref_id' => (int) $a->id, 'token' => self::token(), 'pass' => '',
                'expires_at' => 0, 'created_by' => (int) $who['user_id'], 'created_at' => Clock::now()]);
            Audit::log($cid, 'site_badge', (string) $a->value, ['on' => true], (int) $who['user_id']);
        }
        return ['ok' => true];
    }

    /**
     * The picture for a badge token, or null. Made here from fixed words and one date; nothing a scanned site or a
     * customer wrote goes into it. When the domain is no longer verified, or its last completed scan is old, the
     * badge says the check is not current (and is grey): it is a statement about monitoring, never about being safe.
     */
    public static function badgeSvg(string $token, string $lang = 'fa'): ?string
    {
        $s = Settings::bool('site_badge') && Settings::bool('enabled') ? self::find($token, 'badge') : null;
        $a = $s ? Db::table('mod_mcsec_assets')->where('id', (int) $s->ref_id)->where('client_id', (int) $s->client_id)->first() : null;
        if (!$s || !$a || $a->status === 'removed') {
            return null;
        }
        $last = $a->status === 'verified' ? (int) Db::table('mod_mcsec_scans')->where('asset_id', (int) $a->id)->where('status', 'completed')->max('finished_at') : 0;
        $fresh = $last > Clock::now() - self::FRESH;
        return Lang::with($lang === 'en' ? 'en' : 'fa', function () use ($fresh, $last) {
            $rtl = Lang::rtl();
            $l1 = Lang::t('پایش امنیتی · مارال کلاد');
            $l2 = $fresh ? Lang::t('آخرین بررسی: {date}', ['date' => Text::date($last, false)]) : Lang::t('بررسی به‌روز نیست');
            $bg = $fresh ? '#0b1f3a' : '#64748b';
            $ac = $fresh ? '#38bdf8' : '#cbd5e1';
            $tx = $rtl ? 'x="176" text-anchor="start" direction="rtl"' : 'x="44" text-anchor="start"';
            $ix = $rtl ? 184 : 10;
            $font = 'font-family="Tahoma,Vazirmatn,Segoe UI,Arial,sans-serif"';
            return '<svg xmlns="http://www.w3.org/2000/svg" width="220" height="48" viewBox="0 0 220 48" role="img" aria-label="' . Text::e($l1 . ' — ' . $l2) . '">'
                . '<rect width="220" height="48" rx="8" fill="' . $bg . '"/>'
                . '<g transform="translate(' . $ix . ',10)" fill="none" stroke="' . $ac . '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 1 3 5v8c0 6 4 11 10 14 6-3 10-8 10-14V5z"/>'
                . ($fresh ? '<path d="m8 14 4 4 7-8"/>' : '<path d="M13 9v6M13 20v.5"/>') . '</g>'
                . '<text ' . $tx . ' y="21" ' . $font . ' font-size="12.5" font-weight="bold" fill="#fff">' . Text::e($l1) . '</text>'
                . '<text ' . $tx . ' y="38" ' . $font . ' font-size="11" fill="' . $ac . '">' . Text::e($l2) . '</text></svg>';
        });
    }
}
