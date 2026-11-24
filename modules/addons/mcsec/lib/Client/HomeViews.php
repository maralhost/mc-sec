<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Assets;
use McSec\Catalog;
use McSec\Clock;
use McSec\Db;
use McSec\Findings;
use McSec\Kb;
use McSec\Lang;
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
 * Both start with the same top (0.13.0): a dark console with the score and a radar of the assets, six number tiles,
 * what the scanners are doing now, and three pictures (open findings, new against fixed, the score's trend).
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
        return '<div class="mcs-viewswitch" role="group" aria-label="' . self::e(Lang::t('نمای صفحه')) . '">' . $btn('simple', 'ساده') . $btn('advanced', 'پیشرفته') . '</div>';
    }

    public static function body(array $ctx, array $assets, array $verified, array $score, array $counts): string
    {
        $cid = (int) $ctx['who']['client_id'];
        $mode = self::mode($ctx['who']);
        Views::$pageActions = self::switcher($ctx, $mode);
        $d = self::data($cid, $verified);
        $trend = Score::trend($cid, 60);
        // the same top for both views: the console, the numbers, what is running now, and three pictures
        $out = self::console($ctx, $verified, $score, $counts, $d, $trend) . self::tiles($assets, $verified, $counts, $d) . self::live($ctx, $d)
            . '<div class="mcs-grid3 mcs-charts">'
            . Ui::card(Charts::donut($counts, 'index.php?m=mcsec&p=findings'), 'یافته‌های باز', 'bug', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings">' . Lang::t('همه') . '</a>')
            . Ui::card(Charts::days($d['days'], $d['dayNew'], $d['dayFixed']), 'تازه و رفع‌شده', 'activity')
            . Ui::card('<div class="mcs-tone-' . Score::tone($score['score']) . ' mcs-areawrap">' . Charts::area($trend, max(0, (int) $score['score'])) . '</div>', 'روند امتیاز', 'shield-check') . '</div>';
        return $out . ($mode === 'advanced' ? self::advanced($ctx, $assets, $verified, $score, $counts, $d) : self::simple($ctx, $assets, $verified, $score, $counts, $d));
    }

    /** The dark console at the top: the score, one sentence, what is watching, and the radar of the assets. */
    private static function console(array $ctx, array $verified, array $score, array $counts, array $d, array $trend): string
    {
        $down = count(array_filter($verified, fn ($a) => ($m = Monitor::status($a)) !== null && $m[1] === 'err'));
        $delta = '';
        if (count($trend) >= 2 && $score['score'] >= 0) {
            $x = $score['score'] - (int) $trend[max(0, count($trend) - 8)]['score'];
            $delta = $x === 0 ? Lang::t('امتیاز نسبت به هفته‌ی پیش تغییری نکرده است.')
                : ($x > 0 ? Lang::t('امتیاز از هفته‌ی پیش {n} واحد بالا رفته است.', ['n' => Text::fa(abs($x))]) : Lang::t('امتیاز از هفته‌ی پیش {n} واحد پایین آمده است.', ['n' => Text::fa(abs($x))]));
        }
        $partial = $score['partial'] > 0 ? ' ' . Ui::chip('ارزیابی ناقص', 'warn') . ' ' . self::e(Lang::t('{n} دارایی کامل سنجیده نشد.', ['n' => Text::fa($score['partial'])])) : '';
        $monitored = count(array_filter($verified, fn ($a) => Monitor::status($a) !== null));
        $lastScan = max(array_map(fn ($a) => (int) $a->last_scan_at, $verified) ?: [0]);
        $facts = '<li class="' . ($monitored > 0 ? 'is-on' : '') . '"><i aria-hidden="true"></i>' . self::e($monitored > 0 ? Lang::t('پایش {n} دارایی روشن است', ['n' => Text::fa($monitored)]) : 'پایش در دسترس بودن روشن نیست') . '</li>'
            . '<li>' . Ui::ico('clock') . self::e($lastScan > 0 ? Lang::t('آخرین اسکن: {when}', ['when' => Views::when($lastScan)]) : 'هنوز اسکنی نشده') . '</li>'
            . '<li>' . Ui::ico('calendar') . ($d['next'] > 0 ? self::e(Lang::t('اسکن خودکار بعدی: {when}', ['when' => Text::date($d['next'])])) :'<a href="index.php?m=mcsec&amp;p=schedules">' . self::e('اسکن خودکار ندارید؛ بسازید') . '</a>') . '</li>';
        $blips = [];
        foreach ($verified as $a) {
            $mon = Monitor::status($a);
            $sc = (int) $a->last_scan_at > 0 ? (int) $a->score : -1;
            $blips[] = ['name' => (string) $a->value, 'score' => $sc, 'tone' => $mon !== null && $mon[1] === 'err' ? 'err' : ($sc < 0 ? 'none' : Score::tone($sc))];
        }
        $btns = ($ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=scans#new">' . Ui::ico('play') . Lang::t('اسکن تازه') . '</a>' : '')
            . '<a class="btn btn-default mcs-btn-ghost" href="index.php?m=mcsec&amp;p=findings">' . Ui::ico('bug') . Lang::t('یافته‌ها') . '</a>'
            . SupportViews::link('', 'کمک کارشناس', 'btn btn-default mcs-btn-ghost');
        return '<section class="mcs-console" aria-label="' . self::e(Lang::t('وضعیت امنیت')) . '">' . Ui::gauge($score['score'], '', $score['partial'] > 0 && $score['score'] >= 0)
            . '<div class="mcs-console-say"><p class="mcs-console-kicker">' . Ui::ico('shield-check') . Lang::t('مرکز پایش امنیت') . '</p><strong>' . self::e(self::sentence($score, $counts, $down, count($verified))) . '</strong>'
            . '<p class="mcs-console-sub">' . self::e($delta) . $partial . '</p><ul class="mcs-console-facts">' . $facts . '</ul><div class="mcs-actions">' . $btns . '</div>'
            . '<details class="mcs-how"><summary>' . Lang::t('امتیاز چطور حساب می‌شود؟') . '</summary><p>' . Lang::t('از ۱۰۰ شروع می‌شود و هر یافته‌ی باز به اندازه‌ی اهمیتش کم می‌کند. یک یافته‌ی بحرانیِ باز، یا آسیب‌پذیری‌ای که مهاجمان همین حالا از آن استفاده می‌کنند (فهرست KEV)، امتیاز را حداکثر ۴۹ و یک یافته‌ی مهم حداکثر ۷۹ نگه می‌دارد، تا مشکل جدی پشت چند مورد سالم پنهان نماند.') . '</p>'
            . '<p>' . Lang::t('اگر فایروال یا خطای سایت جلوی بخشی از بررسی را بگیرد، اسکن «ارزیابی ناقص» است، نه «سالم»؛ یافته‌هایی که این بار سنجیده نشدند باز می‌مانند.') . '</p></details></div>'
            . Charts::radar($blips) . '</section>';
    }

    /** Six numbers, each a way into its page. */
    private static function tiles(array $assets, array $verified, array $counts, array $d): string
    {
        $monitored = array_values(array_filter(array_map(fn ($a) => Monitor::status($a), $verified)));
        $up = count(array_filter($monitored, fn ($m) => $m[1] !== 'err'));
        $nearest = null;
        foreach ($verified as $a) {
            $c = $d['certs'][(int) $a->id] ?? null;
            if ($c !== null && ($nearest === null || $c['days'] < $nearest[0]['days'])) {
                $nearest = [$c, $a];
            }
        }
        $urgent = (int) $counts['critical'] + (int) $counts['high'];
        $sc = $d['surfaceCounts'];
        $tile = fn (string $icon, string $label, string $big, string $small, string $href, string $tone = '') => '<a class="mcs-tile' . ($tone !== '' ? ' mcs-tile-' . $tone : '') . '" href="' . self::e($href) . '">'
            . '<span class="mcs-tile-ico">' . Ui::ico($icon) . '</span><span class="mcs-tile-label">' . self::e($label) . '</span><strong>' . $big . '</strong><small>' . $small . '</small></a>';
        return '<div class="mcs-tiles">'
            . $tile('globe', 'دارایی‌ها', self::e(Text::fa(count($verified))), self::e(count($assets) > count($verified) ? Lang::t('{n} در انتظار تأیید', ['n' => Text::fa(count($assets) - count($verified))]) : 'همه تأییدشده'), 'index.php?m=mcsec&p=assets', count($assets) > count($verified) ? 'warn' : '')
            . $tile('alert', 'کار فوری', self::e(Text::fa($urgent)), self::e(Lang::t('{critical} بحرانی، {high} بالا', ['critical' => Text::fa((int) $counts['critical']), 'high' => Text::fa((int) $counts['high'])])), 'index.php?m=mcsec&p=findings', $urgent > 0 ? 'err' : 'ok')
            . $tile('layers', 'سطح حمله', self::e(Text::fa((int) $sc['host'] + (int) $sc['port'])), self::e(Lang::t('{hosts} میزبان، {ports} درگاه، {techs} فناوری', ['hosts' => Text::fa((int) $sc['host']), 'ports' => Text::fa((int) $sc['port']), 'techs' => Text::fa((int) $sc['tech'])])), 'index.php?m=mcsec&p=assets')
            . $tile('heart', 'در دسترس', $monitored ? self::e(Lang::t('{up} از {all}', ['up' => Text::fa($up), 'all' => Text::fa(count($monitored))])) : '—', $monitored ? ($up < count($monitored) ? self::e(Lang::t('{n} سایت خارج است', ['n' => Text::fa(count($monitored) - $up)])) : Lang::t('همه در دسترس‌اند')) : Lang::t('پایش روشن نیست'), 'index.php?m=mcsec&p=assets', $monitored && $up < count($monitored) ? 'err' : '')
            . $tile('lock', 'انقضای SSL', $nearest ? ($nearest[0]['days'] < 0 ? Lang::t('منقضی') : self::e(Lang::t('{n} روز', ['n' => Text::fa($nearest[0]['days'])]))) : '—', $nearest ? Ui::ltr($nearest[1]->value) : Lang::t('گواهی‌ای دیده نشده'),
                $nearest ? 'index.php?m=mcsec&p=asset&id=' . (int) $nearest[1]->id : 'index.php?m=mcsec&p=assets', $nearest && $nearest[0]['days'] <= max(1, Settings::int('monitor_ssl_days')) ? 'warn' : '')
            . $tile('radar', 'اسکن‌های این ماه', self::e(Text::fa($d['scans30'])), self::e($d['running'] > 0 ? Lang::t('{n} در جریان', ['n' => Text::fa($d['running'])]) : 'اسکنی در جریان نیست'), 'index.php?m=mcsec&p=scans', $d['running'] > 0 ? 'run' : '')
            . '</div>';
    }

    /** What the scanners are doing now (each running scan with its path), then the latest finished ones. */
    private static function live(array $ctx, array $d): string
    {
        if (!$d['scans']) {
            return '';
        }
        $rows = '';
        $any = false;
        foreach ($d['scans'] as $s) {
            $live = in_array($s->status, ['queued', 'running'], true);
            $any = $any || $live;
            $profile = Catalog::find((string) $s->profile) ?? ['label' => (string) $s->profile];
            $head = '<a class="mcs-op-name" href="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $s->id . '"><strong>' . self::e($profile['label']) . '</strong> ' . Ui::ltr($s->asset_value) . '</a>';
            if ($live) {
                [$steps, $active, $state] = ScanViews::path($s, $profile);
                $rows .= '<li class="mcs-op is-live" data-mcs-progress="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $s->id . '&amp;progress=1"><div class="mcs-op-head">' . $head . ScanViews::statusChip($s) . '</div>'
                    . Ui::progress((int) $s->progress, $s->status === 'queued' ? 'در صف؛ به‌زودی شروع می‌شود' : (string) $s->stage, $s->status === 'running') . Charts::pipeline($steps, $active, $state) . '</li>';
            } else {
                $sum = \McSec\Scans::summary($s);
                $note = $s->status === 'completed' ? Lang::t('{new} تازه · {fixed} رفع‌شده', ['new' => Text::fa((int) ($sum['new'] ?? 0)), 'fixed' => Text::fa((int) ($sum['fixed'] ?? 0))]) : '';
                $rows .= '<li class="mcs-op"><div class="mcs-op-head">' . $head . ScanViews::statusChip($s) . '</div><p class="mcs-small mcs-muted">' . self::e(Views::when((int) ($s->finished_at ?: $s->queued_at)) . ($note !== '' ? ' · ' . $note : '')) . '</p></li>';
            }
        }
        return Ui::card('<ul class="mcs-ops">' . $rows . '</ul>', $any ? 'اسکنرها همین حالا' : 'آخرین اسکن‌ها', 'radar',
            ($ctx['manage'] ? '<a class="btn btn-primary btn-sm" href="index.php?m=mcsec&amp;p=scans#new">' . Ui::ico('play') . Lang::t('اسکن تازه') . '</a> ' : '') . '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=scans">' . Lang::t('همه') . '</a>', $any ? 'mcs-livecard' : '');
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
        // 14 days of new and fixed findings, by local day
        $from = Clock::now() - 13 * 86400;
        $days = [];
        for ($i = 13; $i >= 0; $i--) {
            $days[] = date('Y-m-d', Clock::now() - $i * 86400);
        }
        $dayNew = [];
        $dayFixed = [];
        foreach (Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('first_seen_at', '>=', $from - 86400)->limit(5000)->select(['first_seen_at'])) as $f) {
            $k = date('Y-m-d', (int) $f->first_seen_at);
            $dayNew[$k] = ($dayNew[$k] ?? 0) + 1;
        }
        foreach (Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'fixed')->where('fixed_at', '>=', $from - 86400)->limit(5000)->select(['fixed_at'])) as $f) {
            $k = date('Y-m-d', (int) $f->fixed_at);
            $dayFixed[$k] = ($dayFixed[$k] ?? 0) + 1;
        }
        $scans = \McSec\Scans::recent($cid, 20);
        $liveScans = array_values(array_filter($scans, fn ($s) => in_array($s->status, ['queued', 'running'], true)));
        $shown = $liveScans ? array_slice($liveScans, 0, 4) : array_slice($scans, 0, 3);
        $next = 0;
        foreach (Schedules::forClient($cid) as $sch) {
            if ((string) $sch->status === 'active' && (int) $sch->next_run_at > 0 && ($next === 0 || (int) $sch->next_run_at < $next)) {
                $next = (int) $sch->next_run_at;
            }
        }
        $feed = Db::rows(Db::table('mod_mcsec_notices')->where('client_id', $cid)->where('created_at', '>=', Clock::now() - 14 * 86400)
            ->whereIn('event', ['new_findings', 'findings_fixed', 'new_exposure', 'site_down', 'site_up', 'ssl_expiring', 'kev_alert', 'asset_lapsed', 'asset_verified'])->orderByDesc('id')->limit(6));
        return ['top' => $top, 'surface' => $surface, 'certs' => $certs, 'feed' => $feed, 'shots' => Shots::forClient($cid),
            'days' => $days, 'dayNew' => $dayNew, 'dayFixed' => $dayFixed, 'scans' => $shown, 'running' => count($liveScans), 'next' => $next, 'surfaceCounts' => \McSec\Surface::counts($cid),
            'scans30' => Db::table('mod_mcsec_scans')->where('client_id', $cid)->where('queued_at', '>=', Clock::now() - 30 * 86400)->count(),
            'new' => Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('first_seen_at', '>=', $week)->count(),
            'fixed' => Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'fixed')->where('fixed_at', '>=', $week)->count()];
    }

    /** One plain sentence for the whole account, most serious thing first. */
    public static function sentence(array $score, array $counts, int $down, int $verified): string
    {
        if ($verified === 0) {
            return Lang::t('هنوز دارایی تأییدشده‌ای ندارید.');
        }
        if ($score['score'] < 0) {
            return Lang::t('هنوز اسکنی نگرفته‌اید؛ با یک بررسی رایگان شروع کنید.');
        }
        $urgent = (int) $counts['critical'] + (int) $counts['high'];
        $parts = [];
        if ($urgent > 0) {
            $parts[] = $urgent === 1 ? Lang::t('یک کار فوری دارید') : Lang::t('{n} کار فوری دارید', ['n' => Text::fa($urgent)]);
        }
        if ($down > 0) {
            // said after an urgent job it reads "… too", so each case is a sentence of its own
            $parts[] = $down === 1
                ? ($parts ? Lang::t('یکی از سایت‌ها هم از دسترس خارج است') : Lang::t('یکی از سایت‌ها از دسترس خارج است'))
                : ($parts ? Lang::t('{n} سایت هم از دسترس خارج است', ['n' => Text::fa($down)]) : Lang::t('{n} سایت از دسترس خارج است', ['n' => Text::fa($down)]));
        }
        if ($parts) {
            return count($parts) > 1 ? Lang::t('{a}؛ {b}.', ['a' => $parts[0], 'b' => $parts[1]]) : $parts[0] . '.';
        }
        if ((int) $counts['medium'] > 0) {
            return Lang::t('مشکل فوری ندارید. {n} مورد متوسط هست که بهتر است سر فرصت رفع شود.', ['n' => Text::fa((int) $counts['medium'])]);
        }
        return Lang::t('همه‌چیز خوب است؛ مشکل مهمی باز نیست.');
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
                . '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '">' . Lang::t('چطور رفع کنم؟') . '</a></li>';
        }
        return Ui::card('<ul class="mcs-acts">' . $items . '</ul>', $title, 'check', count($top) > $limit ? '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings">' . Lang::t('همه‌ی یافته‌ها') . '</a>' : '');
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
        $sum = '<p class="mcs-small mcs-muted">' . Lang::t('هفت روز اخیر: {new} یافته‌ی تازه، {fixed} رفع‌شده.', ['new' => self::e(Text::fa($new)), 'fixed' => self::e(Text::fa($fixed))]) . '</p>';
        return Ui::card(($items !== '' ? '<ul class="mcs-feed">' . $items . '</ul>' : '<p class="mcs-muted">' . Lang::t('در دو هفته‌ی اخیر تغییری ثبت نشده است.') . '</p>') . $sum, 'چه چیزی عوض شد؟', 'activity',
            '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=notify">' . Lang::t('همه') . '</a>');
    }

    private static function sslChip(?array $c): string
    {
        if ($c === null) {
            return '';
        }
        return $c['days'] < 0 ? Ui::chip('SSL منقضی', 'err') : Ui::chip(Lang::t('SSL: {n} روز', ['n' => Text::fa($c['days'])]),$c['days'] <= max(1, Settings::int('monitor_ssl_days')) ? 'warn' : 'ok');
    }

    private static function simple(array $ctx, array $assets, array $verified, array $score, array $counts, array $d): string
    {
        $cid = (int) $ctx['who']['client_id'];
        $out = '';
        $acts = self::actions($d['top'], 3, 'اول این‌ها را انجام دهید');
        if ($acts === '' && $score['score'] >= 0) {
            $acts = Ui::card(Ui::emptyState('shield-check', 'مشکل مهمی باز نیست', Lang::t('آفرین. با زمان‌بندی هفتگی، اگر چیزی تغییر کرد خبرتان می‌کنیم.'), !Schedules::forClient($cid) && $ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=schedules">' . Lang::t('زمان‌بندی بسازید') . '</a>' : ''));
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
                    . ((int) $a->last_scan_at === 0 ? Ui::chip('اسکن نشده', 'muted') : ($urgent > 0 ? Ui::chip(Lang::t('{n} فوری', ['n' => Text::fa($urgent)]), 'err') : Ui::chip('بی کار فوری', 'ok')))
                    . (trim((string) ($a->partial ?? '')) !== '' ? Ui::chip('ناقص', 'warn') : '');
                $cards .= '<a class="mcs-site' . ($isDown ? ' is-down' : '') . '" href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '"><span class="mcs-site-shot">' . $shot . '</span>'
                    . '<span class="mcs-site-body">' . Ui::ltr($a->value, 'mcs-site-name') . '<span class="mcs-site-chips">' . $chips . '</span></span></a>';
            }
            $more = count($verified) > 12 ? '<p class="mcs-small"><a href="index.php?m=mcsec&amp;p=assets">' . Lang::t('{n} دارایی دیگر', ['n' => self::e(Text::fa(count($verified) - 12))]) . '</a></p>' : '';
            $out .= '<div class="mcs-sites-head"><h3>' . Lang::t('سایت‌ها و سرورهای شما') . '</h3><a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=assets">' . Lang::t('مدیریت') . '</a></div><div class="mcs-sites">' . $cards . '</div>' . $more;
        }
        return $out . self::feed($d['feed'], $d['new'], $d['fixed']);
    }

    private static function advanced(array $ctx, array $assets, array $verified, array $score, array $counts, array $d): string
    {
        $cid = (int) $ctx['who']['client_id'];
        // the attack surface: what the scanners see from outside, by kind, with the commonest ports and technologies
        $ports = [];
        $techs = [];
        foreach ($d['surface'] as $byKind) {
            foreach ($byKind['port'] ?? [] as $p) {
                $n = (string) preg_replace('~^.*:~', '', (string) $p->value);
                $ports[$n] = ($ports[$n] ?? 0) + 1;
            }
            foreach ($byKind['tech'] ?? [] as $t) {
                $techs[(string) $t->value] = ($techs[(string) $t->value] ?? 0) + 1;
            }
        }
        arsort($ports);
        arsort($techs);
        $bars = [];
        foreach (\McSec\Surface::KINDS as $k => $label) {
            $bars[] = [$label, (int) ($d['surfaceCounts'][$k] ?? 0)];
        }
        $tags = fn (array $list) => implode(' ', array_map(fn ($name, $n) => '<span class="mcs-tag" dir="ltr">' . self::e($name) . ($n > 1 ? ' <small>×' . $n . '</small>' : '') . '</span>', array_keys($list), $list));
        $out = Ui::card('<div class="mcs-surfacemap"><div>' . Charts::hbars($bars) . '</div><div><p class="mcs-small mcs-muted">' . Lang::t('درگاه‌های باز پرتکرار') . '</p><p>' . ($ports ? $tags(array_slice($ports, 0, 12, true)) : '<span class="mcs-muted">—</span>') . '</p>'
            . '<p class="mcs-small mcs-muted">' . Lang::t('فناوری‌های دیده‌شده') . '</p><p>' . ($techs ? $tags(array_slice($techs, 0, 14, true)) : '<span class="mcs-muted">—</span>') . '</p></div></div>', 'سطح حمله از بیرون', 'layers');
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
            $label = Lang::t('{critical} بحرانی، {high} بالا، {medium} متوسط، {low} پایین', ['critical' => Text::fa((int) $c['critical']), 'high' => Text::fa((int) $c['high']), 'medium' => Text::fa((int) $c['medium']), 'low' => Text::fa((int) $c['low'])]);
            $find = $open > 0 ? '<a class="mcs-dots" href="index.php?m=mcsec&amp;p=findings&amp;asset=' . (int) $a->id . '" title="' . self::e($label) . '" aria-label="' . self::e($label) . '">' . $dots . ($open > $n ? '<small>+' . self::e(Text::fa($open - $n)) . '</small>' : '') . '</a>'
                : '<span class="mcs-muted mcs-small">' . ((int) $a->last_scan_at > 0 ? Lang::t('بی یافته') : Lang::t('اسکن نشده')) . '</span>';
            $sc = (int) $a->last_scan_at > 0 ? (int) $a->score : -1;
            $tone = Score::tone($sc);
            $scoreCell = $sc < 0 ? '—' : '<span class="mcs-scorebar mcs-tone-' . $tone . '"><strong>' . self::e(Text::fa($sc)) . '</strong><span><i style="width:' . $sc . '%"></i></span></span>' . (trim((string) ($a->partial ?? '')) !== '' ? ' ' . Ui::chip('ناقص', 'warn') : '');
            $mon = Monitor::status($a);
            $ports = array_slice(array_values(array_unique(array_map(fn ($p) => (string) preg_replace('~^.*:~', '', (string) $p->value), $d['surface'][(int) $a->id]['port'] ?? []))), 0, 5);
            sort($ports, SORT_NUMERIC);
            $tech = array_slice(array_values(array_unique(array_map(fn ($t) => (string) $t->value, $d['surface'][(int) $a->id]['tech'] ?? []))), 0, 3);
            $cert = $d['certs'][(int) $a->id] ?? null;
            $kind = Lang::t((string) (Assets::KINDS[$a->kind] ?? $a->kind));
            $kind = (string) ($a->cdn ?? '') !== '' ? Lang::t('{kind} · پشت CDN', ['kind' => $kind]) : $kind;
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
            . '<p class="mcs-small mcs-muted">' . Lang::t('هر مربع یک یافته‌ی باز است و رنگش شدت آن: <span class="mcs-dots"><i class="c"></i></span> بحرانی، <span class="mcs-dots"><i class="h"></i></span> بالا، <span class="mcs-dots"><i class="m"></i></span> متوسط، <span class="mcs-dots"><i class="l"></i></span> پایین.') . '</p>',
            'دارایی‌های شما', 'globe', ($ctx['manage'] ? '<a class="btn btn-primary btn-sm" href="index.php?m=mcsec&amp;p=scans#new">' . Lang::t('اسکن تازه') . '</a> ' : '') . '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=assets">' . Lang::t('مدیریت') . '</a>');
        $acts = self::actions($d['top'], 5, 'اول این‌ها را انجام دهید');
        $out .= '<div class="mcs-grid21">' . ($acts !== '' ? $acts : Ui::card(Ui::emptyState('shield-check', 'مشکل مهمی باز نیست', Lang::t('یافته‌ی بحرانی، بالا یا متوسطِ بازی ندارید.')))) . self::feed($d['feed'], $d['new'], $d['fixed']) . '</div>';

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
            . Ui::card($certRows !== '' ? Ui::table(['دارایی', 'صادرکننده', 'تا', 'مانده'], $certRows) : '<p class="mcs-muted">' . Lang::t('هنوز گواهی‌ای دیده نشده است.') . '</p>', 'گواهی‌های SSL', 'lock')
            . Ui::card($toolRows !== '' ? Ui::table(['ابزار', 'بحرانی', 'بالا', 'متوسط', 'پایین', 'اطلاعاتی'], $toolRows) : '<p class="mcs-muted">' . Lang::t('یافته‌ی بازی نیست.') . '</p>', 'یافته‌های باز به تفکیک ابزار', 'bug') . '</div>';
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
