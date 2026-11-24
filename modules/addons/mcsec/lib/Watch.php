<?php

declare(strict_types=1);

namespace McSec;

/**
 * Things MC-Sec knows from WHMCS's own data, with no scan and no network (0.10.0, each behind its own switch):
 * - domain_watch: a domain registered in this WHMCS that expires soon is announced at 30, 7 and 1 days.
 * - service_box: a small "security of this site" box on the hosting service page (built here, shown by a hook).
 */
final class Watch
{
    /** Daily: accounts that use the workspace hear about their domains that expire within 30 days, once per band. */
    public static function domains(): int
    {
        if (!Settings::bool('domain_watch')) {
            return 0;
        }
        $rows = Whmcs::expiringDomains(30);
        if (!$rows) {
            return 0;
        }
        // only accounts that opened the security workspace and may see it (two batched reads)
        $ids = array_values(array_unique(array_map(fn ($r) => (int) $r->userid, $rows)));
        $using = [];
        foreach (array_chunk($ids, 500) as $chunk) {
            foreach (Db::rows(Db::table('mod_mcsec_accounts')->whereIn('client_id', $chunk)->select(['client_id'])) as $a) {
                $using[] = (int) $a->client_id;
            }
        }
        $allowed = array_flip(Access::allowedIds($using));
        $today = strtotime(Clock::today() . ' 00:00:00 UTC');
        $n = 0;
        foreach ($rows as $r) {
            $cid = (int) $r->userid;
            $end = strtotime((string) $r->expirydate . ' 00:00:00 UTC');
            if (!isset($allowed[$cid]) || $end === false) {
                continue;
            }
            $days = (int) floor(($end - $today) / 86400);
            if ($days < 0 || $days > 30) {
                continue;
            }
            $band = $days <= 1 ? 1 : ($days <= 7 ? 7 : 30);
            Notify::event($cid, 'domain_expiring', ['domain' => strtolower((string) $r->domain), 'days' => $days, 'end' => (string) $r->expirydate, 'auto' => (int) ($r->donotrenew ?? 0) === 0],
                $cid . ':' . substr(sha1(strtolower((string) $r->domain)), 0, 12) . ':' . $r->expirydate . ':' . $band);
            $n++;
        }
        return $n;
    }

    /**
     * The box on a hosting service's page: what MC-Sec knows about this site and one link. Database only (it runs
     * inside a page hook). Everything is escaped; inline styles only, so no theme file is touched.
     */
    public static function serviceBox(int $clientId, string $domain): string
    {
        $domain = strtolower(trim($domain));
        if (!Settings::bool('service_box') || $domain === '' || isset(Net::parse($domain)['error'])) {
            return '';
        }
        $e = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $a = Db::table('mod_mcsec_assets')->where('client_id', $clientId)->where('value', $domain)->where('status', '!=', 'removed')->first();
        $name = '<bdi dir="ltr">' . $e($domain) . '</bdi>';
        if (!$a) {
            $text = Lang::t('امنیت {site} هنوز بررسی نشده است. «بررسی سلامت پایه» رایگان است و کمتر از دو دقیقه طول می‌کشد.', ['site' => $name]);
            $href = 'index.php?m=mcsec&p=assets&add=' . rawurlencode($domain) . '#add';
            $btn = Lang::t('افزودن و بررسی');
            $tone = '#1d4ed8';
        } elseif ($a->status !== 'verified') {
            $text = Lang::t('برای بررسی امنیت {site} یک قدم مانده است: تأیید مالکیت.', ['site' => $name]);
            $href = 'index.php?m=mcsec&p=asset&id=' . (int) $a->id;
            $btn = Lang::t('تأیید مالکیت');
            $tone = '#b45309';
        } elseif ((int) $a->last_scan_at === 0 || (int) $a->score < 0) {
            $text = Lang::t('{site} آماده‌ی بررسی است؛ هنوز اسکنی گرفته نشده.', ['site' => $name]);
            $href = 'index.php?m=mcsec&p=asset&id=' . (int) $a->id;
            $btn = Lang::t('گرفتن اولین اسکن');
            $tone = '#1d4ed8';
        } else {
            $c = Assets::counts($a);
            $urgent = (int) $c['critical'] + (int) $c['high'];
            $text = Lang::t('امتیاز امنیت {site}: <strong>{score}</strong> از ۱۰۰ ({label}).', ['site' => $name, 'score' => $e(Text::fa((int) $a->score)), 'label' => $e(Lang::t(Score::label((int) $a->score)))]) . ' '
                . ($urgent > 0 ? Lang::t('{n} مشکل بحرانی یا مهم باز است.', ['n' => $e(Text::fa($urgent))]) : Lang::t('مشکل بحرانی یا مهمی باز نیست.'))
                . ' <span style="opacity:.75">' . Lang::t('آخرین بررسی: {date}', ['date' => $e(Text::date((int) $a->last_scan_at, false))]) . '</span>';
            $href = 'index.php?m=mcsec&p=asset&id=' . (int) $a->id;
            $btn = Lang::t('دیدن جزئیات');
            $tone = $urgent > 0 ? '#b91c1c' : '#15803d';
        }
        return '<div class="mcs-svc" ' . Lang::attrs() . ' style="margin:12px 0;padding:12px 16px;border:1px solid rgba(127,140,160,.35);border-inline-start:4px solid ' . $tone . ';border-radius:10px;line-height:1.9;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:space-between">'
            . '<div><strong>' . $e(Settings::menuLabel()) . '</strong><br>' . $text . '</div><a class="btn btn-default btn-sm" href="' . $e($href) . '">' . $e($btn) . '</a></div>';
    }
}
