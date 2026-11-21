<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Assets;
use McSec\Catalog;
use McSec\Clock;
use McSec\Db;
use McSec\Findings;
use McSec\Kb;
use McSec\Monitor;
use McSec\Schedules;
use McSec\Score;
use McSec\Settings;
use McSec\Shots;
use McSec\Text;

/**
 * The overview in two views over the same data, chosen by each person (Kv 'view:<client>:<user>'):
 *  - simple (default): one Persian sentence that says how things are, the three jobs to do first, and a card per
 *    site with its picture, availability and certificate; written for a site owner who is not technical;
 *  - advanced: the numbers in a strip, one table row per asset (open findings as squares, score, availability, last
 *    scan, ports, technologies, certificate), certificates and findings per tool; for people who run many assets.
 * Neither is a cut-down version of the other. Everything is read from MC-Sec's own tables: no network here.
 */
final class HomeViews
{
    private static function e($s): string
    {
        return Ui::e($s);
    }

    /** Each person of an account keeps their own view (Kv, no expiry). */
    public static function mode(array $who): string
    {
        return \McSec\Kv::get('view:' . (int) $who['client_id'] . ':' . (int) $who['user_id']) === 'advanced' ? 'advanced' : 'simple';
    }

    /** The simple/advanced switch: two POST buttons (it changes a preference), usable without JavaScript. */
    public static function switcher(array $ctx, string $mode): string
    {
        $btn = fn (string $m, string $label) => $m === $mode
            ? '<span class="mcs-view-on" aria-current="true">' . self::e($label) . '</span>'
            : Ui::form($ctx, 'home', 'view_mode', '<input type="hidden" name="view" value="' . $m . '"><button type="submit" class="mcs-view-btn">' . self::e($label) . '</button>', '', 'mcs-inline');
        return '<div class="mcs-viewswitch" role="group" aria-label="نمای صفحه">' . $btn('simple', 'ساده') . $btn('advanced', 'پیشرفته') . '</div>';
    }

    public static function body(array $ctx, array $assets, array $verified, array $score, array $counts): string
    {
        $cid = (int) $ctx['who']['client_id'];
        $mode = self::mode($ctx['who']);
        Views::$pageActions = self::switcher($ctx, $mode);
        $d = self::data($cid, $verified);
        return $mode === 'advanced' ? self::advanced($ctx, $assets, $verified, $score, $counts, $d) : self::simple($ctx, $assets, $verified, $score, $counts, $d);
    }

    /** Everything both views need, with a fixed number of queries whatever the number of assets. */
    private static function data(int $cid, array $verified): array
    {
        $rank = "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";
        $top = Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'open')->whereIn('severity', ['critical', 'high', 'medium'])
            ->orderByDesc('priority')->orderByRaw($rank . ' DESC')->orderByDesc('last_seen_at')->limit(20));
        // one line per issue: the same port on the same IP reached through two assets is one job
        $seen = [];
        $top = array_values(array_filter($top, function ($f) use (&$seen) {
            $k = $f->source_key . '|' . $f->location;
            return isset($seen[$k]) ? false : ($seen[$k] = true);
        }));
        $surface = [];
        foreach (Db::rows(Db::table('mod_mcsec_surface')->where('client_id', $cid)->where('gone_at', 0)->whereIn('kind', ['port', 'tech', 'cert'])->orderBy('value')->limit(3000)->select(['asset_id', 'kind', 'value', 'meta'])) as $s) {
            $surface[(int) $s->asset_id][(string) $s->kind][] = $s;
        }
        $certs = [];
        foreach ($verified as $a) {
            $end = (string) ($a->mon_cert_end ?? '');
            $issuer = '';
            foreach ($surface[(int) $a->id]['cert'] ?? [] as $c) {
                $m = json_decode((string) $c->meta, true) ?: [];
                if ($end === '' && preg_match('~^\d{4}-\d{2}-\d{2}~', (string) ($m['not_after'] ?? ''))) {
                    $end = substr((string) $m['not_after'], 0, 10);
                }
                $issuer = $issuer !== '' ? $issuer : (string) ($m['issuer'] ?? '');
            }
            if ($end !== '') {
                $certs[(int) $a->id] = ['end' => $end, 'days' => (int) floor((strtotime($end . ' 23:59:59 UTC') - Clock::now()) / 86400), 'issuer' => $issuer];
            }
        }
        $week = Clock::now() - 7 * 86400;
        $feed = Db::rows(Db::table('mod_mcsec_notices')->where('client_id', $cid)->where('created_at', '>=', Clock::now() - 14 * 86400)
            ->whereIn('event', ['new_findings', 'findings_fixed', 'new_exposure', 'site_down', 'site_up', 'ssl_expiring', 'kev_alert', 'asset_lapsed', 'asset_verified'])->orderByDesc('id')->limit(6));
        return ['top' => $top, 'surface' => $surface, 'certs' => $certs, 'feed' => $feed, 'shots' => Shots::forClient($cid),
            'new' => Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('first_seen_at', '>=', $week)->count(),
            'fixed' => Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'fixed')->where('fixed_at', '>=', $week)->count()];
    }

    /** One plain sentence for the whole account, most serious thing first. */
    public static function sentence(array $score, array $counts, int $down, int $verified): string
    {
        if ($verified === 0) {
            return 'هنوز دارایی تأییدشده‌ای ندارید.';
        }
        if ($score['score'] < 0) {
            return 'هنوز اسکنی نگرفته‌اید؛ با یک بررسی رایگان شروع کنید.';
        }
        $urgent = (int) $counts['critical'] + (int) $counts['high'];
        $parts = [];
        if ($urgent > 0) {
            $parts[] = $urgent === 1 ? 'یک کار فوری دارید' : Text::fa($urgent) . ' کار فوری دارید';
        }
        if ($down > 0) {
            $parts[] = ($down === 1 ? 'یکی از سایت‌ها' : Text::fa($down) . ' سایت') . ($parts ? ' هم' : '') . ' از دسترس خارج است';
        }
        if ($parts) {
            return implode('؛ ', $parts) . '.';
        }
        if ((int) $counts['medium'] > 0) {
            return 'مشکل فوری ندارید. ' . Text::fa((int) $counts['medium']) . ' مورد متوسط هست که بهتر است سر فرصت رفع شود.';
        }
        return 'همه‌چیز خوب است؛ مشکل مهمی باز نیست.';
    }

    private static function actions(array $top, int $limit, string $title): string
    {
        if (!$top) {
            return '';
        }
        $items = '';
        foreach (array_slice($top, 0, $limit) as $f) {
            $kb = Kb::get((string) $f->kb);
            $items .= '<li><span class="mcs-act-sev">' . Ui::sev((string) $f->severity) . '</span><span class="mcs-act-text"><a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '"><strong>' . self::e($f->title) . '</strong></a>'
                . '<span class="mcs-act-meta">' . Ui::ltr($f->location) . ((int) ($f->kev ?? 0) === 1 ? ' · ' . Ui::chip('در حال بهره‌برداری', 'err') : '') . ($kb && !empty($kb['effort']) ? ' · ' . self::e($kb['effort']) : '') . '</span></span>'
                . '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '">چطور رفع کنم؟</a></li>';
        }
        return Ui::card('<ul class="mcs-acts">' . $items . '</ul>', $title, 'check', count($top) > $limit ? '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings">همه‌ی یافته‌ها</a>' : '');
    }

    private static function feed(array $feed, int $new, int $fixed): string
    {
        $tone = ['err' => 'var(--t-err)', 'warn' => 'var(--sev-h-ic)', 'ok' => 'var(--t-ok)', 'info' => 'var(--t-muted)'];
        $items = '';
        foreach ($feed as $n) {
            $link = preg_match('~^index\.php\?m=mcsec~', (string) $n->link) ? (string) $n->link : '';
            $items .= '<li style="--d:' . ($tone[(string) $n->tone] ?? $tone['info']) . '"><time>' . self::e(Views::when((int) $n->created_at)) . '</time>'
                . ($link !== '' ? '<a href="' . self::e($link) . '">' . self::e($n->title) . '</a>' : self::e($n->title)) . '</li>';
        }
        $sum = '<p class="mcs-small mcs-muted">هفت روز اخیر: ' . self::e(Text::fa($new)) . ' یافته‌ی تازه، ' . self::e(Text::fa($fixed)) . ' رفع‌شده.</p>';
        return Ui::card(($items !== '' ? '<ul class="mcs-feed">' . $items . '</ul>' : '<p class="mcs-muted">در دو هفته‌ی اخیر تغییری ثبت نشده است.</p>') . $sum, 'چه چیزی عوض شد؟', 'activity',
            '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=notify">همه</a>');
    }

    private static function sslChip(?array $c): string
    {
        if ($c === null) {
            return '';
        }
        return $c['days'] < 0 ? Ui::chip('SSL منقضی', 'err') : Ui::chip('SSL: ' . Text::fa($c['days']) . ' روز', $c['days'] <= max(1, Settings::int('monitor_ssl_days')) ? 'warn' : 'ok');
    }

    private static function simple(array $ctx, array $assets, array $verified, array $score, array $counts, array $d): string
    {
        $cid = (int) $ctx['who']['client_id'];
        $down = count(array_filter($verified, fn ($a) => ($m = Monitor::status($a)) !== null && $m[1] === 'err'));
        $trend = Score::trend($cid, 60);
        $delta = '';
        if (count($trend) >= 2 && $score['score'] >= 0) {
            $x = $score['score'] - (int) $trend[max(0, count($trend) - 8)]['score'];
            $delta = $x === 0 ? 'امتیاز نسبت به هفته‌ی پیش تغییری نکرده است.' : 'امتیاز از هفته‌ی پیش ' . Text::fa(abs($x)) . ' واحد ' . ($x > 0 ? 'بالا رفته' : 'پایین آمده') . ' است.';
        }
        $partial = $score['partial'] > 0 ? ' ' . Ui::chip('ارزیابی ناقص', 'warn') . ' ' . self::e(Text::fa($score['partial']) . ' دارایی کامل سنجیده نشد.') : '';
        $out = '<div class="mcs-card mcs-hero">' . Ui::gauge($score['score'], '', $score['partial'] > 0 && $score['score'] >= 0)
            . '<div class="mcs-hero-say"><strong>' . self::e(self::sentence($score, $counts, $down, count($verified))) . '</strong><p class="mcs-muted">' . self::e($delta) . $partial . '</p>'
            . '<details class="mcs-how"><summary>امتیاز چطور حساب می‌شود؟</summary><p>از ۱۰۰ شروع می‌شود و هر یافته‌ی باز به اندازه‌ی اهمیتش کم می‌کند. یک یافته‌ی بحرانیِ باز، یا آسیب‌پذیری‌ای که مهاجمان همین حالا از آن استفاده می‌کنند (فهرست KEV)، امتیاز را حداکثر ۴۹ و یک یافته‌ی مهم حداکثر ۷۹ نگه می‌دارد، تا مشکل جدی پشت چند مورد سالم پنهان نماند.</p>'
            . '<p>اگر فایروال یا خطای سایت جلوی بخشی از بررسی را بگیرد، اسکن «ارزیابی ناقص» است، نه «سالم»؛ یافته‌هایی که این بار سنجیده نشدند باز می‌مانند.</p></details></div>'
            . (count($trend) >= 2 ? '<div class="mcs-hero-trend">' . Ui::spark($trend, 220, 48) . '<span class="mcs-small mcs-muted">روند ۶۰ روز</span></div>' : '') . '</div>';
        $acts = self::actions($d['top'], 3, 'اول این‌ها را انجام دهید');
        if ($acts === '' && $score['score'] >= 0) {
            $acts = Ui::card(Ui::emptyState('shield-check', 'مشکل مهمی باز نیست', 'آفرین. با زمان‌بندی هفتگی، اگر چیزی تغییر کرد خبرتان می‌کنیم.', !Schedules::forClient($cid) && $ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=schedules">زمان‌بندی بسازید</a>' : ''));
        }
        $out .= $acts;
        if ($verified) {
            $cards = '';
            foreach (array_slice($verified, 0, 12) as $a) {
                $c = Assets::counts($a);
                $urgent = (int) $c['critical'] + (int) $c['high'];
                $mon = Monitor::status($a);
                $isDown = $mon !== null && $mon[1] === 'err';
                $shot = isset($d['shots'][(int) $a->id])
                    ? '<img src="index.php?m=mcsec&amp;p=shot&amp;id=' . (int) $a->id . '&amp;t=' . (int) $d['shots'][(int) $a->id] . '" alt="" loading="lazy" width="320" height="180">'
                    : '<span class="mcs-site-noshot">' . Ui::ico($a->kind === 'domain' ? 'globe' : 'server') . '</span>';
                $chips = ($mon !== null ? Ui::chip($mon[0], $mon[1]) : '') . self::sslChip($d['certs'][(int) $a->id] ?? null)
                    . ((int) $a->last_scan_at === 0 ? Ui::chip('اسکن نشده', 'muted') : ($urgent > 0 ? Ui::chip(Text::fa($urgent) . ' فوری', 'err') : Ui::chip('بی کار فوری', 'ok')))
                    . (trim((string) ($a->partial ?? '')) !== '' ? Ui::chip('ناقص', 'warn') : '');
                $cards .= '<a class="mcs-site' . ($isDown ? ' is-down' : '') . '" href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '"><span class="mcs-site-shot">' . $shot . '</span>'
                    . '<span class="mcs-site-body">' . Ui::ltr($a->value, 'mcs-site-name') . '<span class="mcs-site-chips">' . $chips . '</span></span></a>';
            }
            $more = count($verified) > 12 ? '<p class="mcs-small"><a href="index.php?m=mcsec&amp;p=assets">' . self::e(Text::fa(count($verified) - 12)) . ' دارایی دیگر</a></p>' : '';
            $out .= '<div class="mcs-sites-head"><h3>سایت‌ها و سرورهای شما</h3><a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=assets">مدیریت</a></div><div class="mcs-sites">' . $cards . '</div>' . $more;
        }
        return $out . self::feed($d['feed'], $d['new'], $d['fixed']);
    }

    private static function advanced(array $ctx, array $assets, array $verified, array $score, array $counts, array $d): string
    {
        $cid = (int) $ctx['who']['client_id'];
        $monitored = array_values(array_filter(array_map(fn ($a) => Monitor::status($a), $verified)));
        $up = count(array_filter($monitored, fn ($m) => $m[1] !== 'err'));
        $nearest = null;
        foreach ($verified as $a) {
            $c = $d['certs'][(int) $a->id] ?? null;
            if ($c !== null && ($nearest === null || $c['days'] < $nearest[0]['days'])) {
                $nearest = [$c, $a];
            }
        }
        $trend = Score::trend($cid, 60);
        $dx = count($trend) >= 2 && $score['score'] >= 0 ? $score['score'] - (int) $trend[max(0, count($trend) - 8)]['score'] : 0;
        $stat = fn (string $label, string $big, string $small) => '<div><span>' . self::e($label) . '</span><strong>' . $big . '</strong> <small>' . $small . '</small></div>';
        $out = '<div class="mcs-stats">'
            . $stat('امتیاز امنیت', $score['score'] < 0 ? '—' : self::e(Text::fa($score['score'])), self::e($score['label']) . ($dx !== 0 ? ' · ' . self::e(Text::fa(abs($dx)) . ($dx > 0 ? '+' : '−') . ' در هفته') : '') . ($score['partial'] > 0 ? ' · ' . Ui::chip('ناقص', 'warn') : ''))
            . $stat('کار فوری', self::e(Text::fa((int) $counts['critical'] + (int) $counts['high'])), self::e(Text::fa((int) $counts['critical']) . ' بحرانی، ' . Text::fa((int) $counts['high']) . ' بالا'))
            . $stat('در دسترس', $monitored ? self::e(Text::fa($up) . ' از ' . Text::fa(count($monitored))) : '—', $monitored ? ($up < count($monitored) ? self::e(Text::fa(count($monitored) - $up) . ' سایت خارج است') : 'همه در دسترس‌اند') : 'پایش روشن نیست')
            . $stat('نزدیک‌ترین انقضای SSL', $nearest ? ($nearest[0]['days'] < 0 ? 'منقضی' : self::e(Text::fa($nearest[0]['days']) . ' روز')) : '—', $nearest ? Ui::ltr($nearest[1]->value) : 'گواهی‌ای دیده نشده')
            . '</div>';
        $rows = '';
        foreach ($verified as $a) {
            $c = Assets::counts($a);
            $dots = '';
            $n = 0;
            foreach (['critical' => 'c', 'high' => 'h', 'medium' => 'm', 'low' => 'l'] as $sev => $cls) {
                for ($i = 0; $i < min((int) $c[$sev], 12 - $n); $i++, $n++) {
                    $dots .= '<i class="' . $cls . '"></i>';
                }
            }
            $open = (int) $c['critical'] + (int) $c['high'] + (int) $c['medium'] + (int) $c['low'];
            $label = Text::fa((int) $c['critical']) . ' بحرانی، ' . Text::fa((int) $c['high']) . ' بالا، ' . Text::fa((int) $c['medium']) . ' متوسط، ' . Text::fa((int) $c['low']) . ' پایین';
            $find = $open > 0 ? '<a class="mcs-dots" href="index.php?m=mcsec&amp;p=findings&amp;asset=' . (int) $a->id . '" title="' . self::e($label) . '" aria-label="' . self::e($label) . '">' . $dots . ($open > $n ? '<small>+' . self::e(Text::fa($open - $n)) . '</small>' : '') . '</a>'
                : '<span class="mcs-muted mcs-small">' . ((int) $a->last_scan_at > 0 ? 'بی یافته' : 'اسکن نشده') . '</span>';
            $sc = (int) $a->last_scan_at > 0 ? (int) $a->score : -1;
            $tone = Score::tone($sc);
            $scoreCell = $sc < 0 ? '—' : '<span class="mcs-scorebar mcs-tone-' . $tone . '"><strong>' . self::e(Text::fa($sc)) . '</strong><span><i style="width:' . $sc . '%"></i></span></span>' . (trim((string) ($a->partial ?? '')) !== '' ? ' ' . Ui::chip('ناقص', 'warn') : '');
            $mon = Monitor::status($a);
            $ports = array_slice(array_values(array_unique(array_map(fn ($p) => (string) preg_replace('~^.*:~', '', (string) $p->value), $d['surface'][(int) $a->id]['port'] ?? []))), 0, 5);
            sort($ports, SORT_NUMERIC);
            $tech = array_slice(array_values(array_unique(array_map(fn ($t) => (string) $t->value, $d['surface'][(int) $a->id]['tech'] ?? []))), 0, 3);
            $cert = $d['certs'][(int) $a->id] ?? null;
            $kind = (Assets::KINDS[$a->kind] ?? $a->kind) . ((string) ($a->cdn ?? '') !== '' ? ' · پشت CDN' : '');
            $rows .= '<tr>' . Ui::td('دارایی', '<a href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '">' . Ui::ltr($a->value) . '</a><small class="mcs-muted">' . self::e($kind) . '</small>')
                . Ui::td('یافته‌های باز', $find) . Ui::td('امتیاز', $scoreCell)
                . Ui::td('در دسترس بودن', $mon !== null ? Ui::chip($mon[0], $mon[1]) : '<span class="mcs-muted">—</span>')
                . Ui::td('آخرین اسکن', (int) $a->last_scan_at > 0 ? self::e(Views::when((int) $a->last_scan_at)) : '<span class="mcs-muted">—</span>')
                . Ui::td('درگاه‌ها', $ports ? Ui::ltr(implode(', ', $ports)) : '<span class="mcs-muted">—</span>')
                . Ui::td('فناوری', $tech ? '<span class="mcs-small" dir="ltr">' . self::e(implode(', ', $tech)) . '</span>' : '<span class="mcs-muted">—</span>')
                . Ui::td('گواهی', $cert ? self::sslChip($cert) : '<span class="mcs-muted">—</span>')
                . '</tr>';
        }
        $out .= Ui::card('<div class="mcs-assetmap">' . Ui::table(['دارایی', 'یافته‌های باز', 'امتیاز', 'در دسترس بودن', 'آخرین اسکن', 'درگاه‌ها', 'فناوری', 'گواهی'], $rows) . '</div>'
            . '<p class="mcs-small mcs-muted">هر مربع یک یافته‌ی باز است و رنگش شدت آن: <span class="mcs-dots"><i class="c"></i></span> بحرانی، <span class="mcs-dots"><i class="h"></i></span> بالا، <span class="mcs-dots"><i class="m"></i></span> متوسط، <span class="mcs-dots"><i class="l"></i></span> پایین.</p>',
            'دارایی‌های شما', 'globe', ($ctx['manage'] ? '<a class="btn btn-primary btn-sm" href="index.php?m=mcsec&amp;p=scans#new">اسکن تازه</a> ' : '') . '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=assets">مدیریت</a>');
        $acts = self::actions($d['top'], 5, 'اول این‌ها را انجام دهید');
        $out .= '<div class="mcs-grid21">' . ($acts !== '' ? $acts : Ui::card(Ui::emptyState('shield-check', 'مشکل مهمی باز نیست', 'یافته‌ی بحرانی، بالا یا متوسطِ بازی ندارید.'))) . self::feed($d['feed'], $d['new'], $d['fixed']) . '</div>';

        // certificates, soonest first
        $certRows = '';
        $byDays = $d['certs'];
        uasort($byDays, fn ($x, $y) => $x['days'] <=> $y['days']);
        $names = [];
        foreach ($verified as $a) {
            $names[(int) $a->id] = (string) $a->value;
        }
        foreach (array_slice($byDays, 0, 10, true) as $aid => $c) {
            $certRows .= '<tr>' . Ui::td('دارایی', Ui::ltr($names[$aid] ?? '')) . Ui::td('صادرکننده', '<span dir="ltr">' . self::e($c['issuer'] !== '' ? $c['issuer'] : '—') . '</span>') . Ui::td('تا', self::e(Text::ymd($c['end']))) . Ui::td('مانده', self::sslChip($c)) . '</tr>';
        }
        // open findings per tool
        $tools = [];
        foreach (Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'open')->whereIn('asset_id', array_map(fn ($a) => (int) $a->id, $verified) ?: [0])->limit(3000)->select(['engine', 'tags', 'severity'])) as $f) {
            $tools[self::toolOf((string) $f->engine, (string) $f->tags)][(string) $f->severity] = ($tools[self::toolOf((string) $f->engine, (string) $f->tags)][(string) $f->severity] ?? 0) + 1;
        }
        ksort($tools);
        $toolRows = '';
        foreach ($tools as $name => $c) {
            $toolRows .= '<tr>' . Ui::td('ابزار', self::e($name));
            foreach (['critical', 'high', 'medium', 'low', 'info'] as $sev) {
                $toolRows .= Ui::td(Findings::SEVERITIES[$sev]['label'], self::e(Text::fa((int) ($c[$sev] ?? 0))));
            }
            $toolRows .= '</tr>';
        }
        return $out . '<div class="mcs-grid2">'
            . Ui::card($certRows !== '' ? Ui::table(['دارایی', 'صادرکننده', 'تا', 'مانده'], $certRows) : '<p class="mcs-muted">هنوز گواهی‌ای دیده نشده است.</p>', 'گواهی‌های SSL', 'lock')
            . Ui::card($toolRows !== '' ? Ui::table(['ابزار', 'بحرانی', 'بالا', 'متوسط', 'پایین', 'اطلاعاتی'], $toolRows) : '<p class="mcs-muted">یافته‌ی بازی نیست.</p>', 'یافته‌های باز به تفکیک ابزار', 'bug') . '</div>';
    }

    /** The tool behind a finding, for the per-tool table: the built-in check, or the OASM tool named in its tags. */
    public static function toolOf(string $engine, string $tags): string
    {
        if ($engine === 'builtin') {
            return 'بررسی پایه';
        }
        foreach (array_reverse(array_map('trim', explode(',', strtolower($tags)))) as $t) {
            if (isset(Catalog::TOOLS[$t])) {
                return Catalog::TOOLS[$t]['label'];
            }
        }
        return Catalog::engineLabel($engine);
    }
}
