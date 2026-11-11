<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Assets;
use McSec\Audit;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Findings;
use McSec\Kb;
use McSec\Notify;
use McSec\Scans;
use McSec\Schedules;
use McSec\Score;
use McSec\Settings;
use McSec\Surface;
use McSec\Text;

/**
 * Client pages of MC-Sec: Persian, right to left, on Lagom2's variables (dark mode follows the theme). A Cloudflare-
 * style shell: a side menu, a top bar (where you are, credits, notices bell, full screen) and a page head. Every page
 * starts with «این بخش چه کار می‌کند؟», has one main action, and says why something is not possible.
 * Page bodies live in AssetViews, ScanViews, FindingViews, ReportViews and AccountViews; the blocks in Ui.
 */
final class Views
{
    private const PAGES = ['home' => 'نمای کلی', 'assets' => 'دارایی‌ها', 'asset' => 'دارایی', 'scans' => 'اسکن‌ها', 'scan' => 'اسکن', 'findings' => 'یافته‌ها',
        'finding' => 'یافته', 'reports' => 'گزارش‌ها', 'report' => 'گزارش', 'schedules' => 'زمان‌بندی‌ها', 'notify' => 'اعلان‌ها', 'credits' => 'اعتبار و پلن', 'activity' => 'فعالیت‌ها'];

    private const DESC = ['home' => 'وضعیت امنیت سایت‌ها و سرورهایتان، آنچه تغییر کرده و مهم‌ترین کار بعدی.', 'assets' => 'دامنه‌ها و IPهایی که بررسی می‌شوند؛ فقط دارایی تأییدشده اسکن می‌شود.',
        'scans' => 'اسکن تازه بگیرید و تاریخچه‌ی اسکن‌ها را ببینید.', 'findings' => 'مشکل‌های پیدا شده، از مهم‌ترین، با راه رفع هر کدام.',
        'reports' => 'گزارش‌های پایه و هوش مصنوعی برای خودتان، مدیرتان یا تیم فنی.', 'schedules' => 'اسکن خودکار روزانه، هفتگی یا ماهانه؛ تغییرها را خبر می‌دهیم.',
        'notify' => 'خبرها و این‌که از چه راهی و برای چه چیزهایی خبرتان کنیم.', 'credits' => 'مانده‌ی اعتبار اسکن، پلن، خرید بسته و ریز تراکنش‌ها.', 'activity' => 'هر کاری که در این بخش انجام شده است.'];

    private const MENU = [
        '' => ['', [['home', 'home']]],
        'surface' => ['محدوده', [['assets', 'globe'], ['scans', 'radar'], ['schedules', 'calendar']]],
        'results' => ['نتیجه', [['findings', 'bug'], ['reports', 'file']]],
        'account' => ['حساب', [['notify', 'bell'], ['credits', 'coins'], ['activity', 'activity']]],
    ];

    /** The last view built by wrap(), for a pjax swap. */
    public static string $view = '';

    public static function full(): bool
    {
        return ($_COOKIE['mcs_full'] ?? '') === '1';
    }

    public static function title(string $p): string
    {
        return $p === 'home' ? Settings::menuLabel() : (self::PAGES[$p] ?? Settings::menuLabel());
    }

    private static function e($s): string
    {
        return Ui::e($s);
    }

    private static function side(array $ctx, string $active): string
    {
        $cid = $ctx['who']['client_id'];
        $unread = Notify::unread($cid);
        $c = Findings::openCounts($cid);
        $urgent = $c['critical'] + $c['high'];
        $pending = Db::table('mod_mcsec_assets')->where('client_id', $cid)->whereIn('status', ['pending', 'lapsed'])->count();
        $running = Scans::activeCount($cid);
        $nav = '';
        $parent = ['asset' => 'assets', 'scan' => 'scans', 'finding' => 'findings', 'report' => 'reports'];
        foreach (self::MENU as [$title, $items]) {
            $links = '';
            foreach ($items as [$p, $icon]) {
                $on = $p === $active || ($parent[$active] ?? '') === $p;
                $count = match (true) {
                    $p === 'findings' && $urgent > 0 => '<span class="mcs-badge" aria-label="' . self::e(Text::fa($urgent) . ' مورد بحرانی یا مهم') . '">' . Text::fa($urgent) . '</span>',
                    $p === 'assets' && $pending > 0 => '<span class="mcs-badge mcs-badge-warn" aria-label="' . self::e(Text::fa($pending) . ' در انتظار تأیید') . '">' . Text::fa($pending) . '</span>',
                    $p === 'scans' && $running > 0 => '<span class="mcs-badge mcs-badge-run" aria-label="' . self::e(Text::fa($running) . ' اسکن در جریان') . '">' . Text::fa($running) . '</span>',
                    $p === 'notify' && $unread > 0 => '<span class="mcs-badge" data-mcs-count="unread">' . Text::fa($unread) . '</span>',
                    default => '',
                };
                $links .= '<a class="mcs-side-link' . ($on ? ' active' : '') . '" href="index.php?m=mcsec&amp;p=' . $p . '"' . ($on ? ' aria-current="page"' : '') . '>'
                    . Ui::ico($icon) . '<span>' . self::e(self::PAGES[$p]) . '</span>' . $count . '</a>';
            }
            $nav .= '<div class="mcs-side-group">' . ($title !== '' ? '<p class="mcs-side-h">' . self::e($title) . '</p>' : '') . $links . '</div>';
        }
        $top = '<div class="mcs-side-brand"><span class="mcs-side-logo">' . Ui::ico('shield-check') . '</span><div><strong>' . self::e(Settings::menuLabel()) . '</strong><span>مارال کلاد</span></div></div>';
        return '<aside class="mcs-side" id="mcs-side" aria-label="' . self::e(Settings::menuLabel()) . '">' . $top . '<nav class="mcs-side-nav">' . $nav . '</nav>'
            . '<a class="mcs-side-exit" href="clientarea.php">' . Ui::ico('chevron') . '<span>بازگشت به ناحیه‌ی کاربری</span></a></aside>';
    }

    private static function topbar(array $ctx, string $active, string $crumbTitle): string
    {
        $cid = $ctx['who']['client_id'];
        $bal = Credits::balance($cid);
        $unread = Notify::unread($cid);
        $parent = ['asset' => 'assets', 'scan' => 'scans', 'finding' => 'findings', 'report' => 'reports'];
        $crumb = '<a href="index.php?m=mcsec">' . self::e(Settings::menuLabel()) . '</a>';
        if (isset($parent[$active])) {
            $crumb .= Ui::ico('chevron') . '<a href="index.php?m=mcsec&amp;p=' . $parent[$active] . '">' . self::e(self::PAGES[$parent[$active]]) . '</a>';
        }
        if ($active !== 'home') {
            $crumb .= Ui::ico('chevron') . '<span>' . ($crumbTitle !== '' ? $crumbTitle : self::e(self::title($active))) . '</span>';
        }
        $credits = '<a class="mcs-credit-chip' . ($bal['total'] <= max(0, Settings::int('low_credit_alert')) ? ' is-low' : '') . '" href="index.php?m=mcsec&amp;p=credits" title="مانده‌ی اعتبار اسکن">'
            . Ui::ico('coins') . '<span>اعتبار: <strong>' . self::e(Text::fa($bal['total'])) . '</strong></span></a>';
        $bell = '<a class="mcs-icon-btn" href="index.php?m=mcsec&amp;p=notify" aria-label="' . self::e('اعلان‌ها' . ($unread > 0 ? '، ' . Text::fa($unread) . ' خبر تازه' : '')) . '">' . Ui::ico('bell')
            . ($unread > 0 ? '<span class="mcs-badge" data-mcs-count="unread">' . Text::fa($unread) . '</span>' : '') . '</a>';
        $full = '<button type="button" class="mcs-icon-btn" data-mcs-full aria-pressed="' . (self::full() ? 'true' : 'false') . '" hidden title="تمام‌صفحه">' . Ui::ico('expand') . '<span class="mcs-sr">تمام‌صفحه</span></button>';
        return '<div class="mcs-topbar"><button type="button" class="mcs-icon-btn mcs-menu-btn" data-mcs-menu aria-controls="mcs-side" aria-expanded="false" hidden>' . Ui::ico('menu')
            . '<span class="mcs-sr">منو</span></button><nav class="mcs-crumb" aria-label="مسیر">' . $crumb . '</nav><div class="mcs-topbar-actions">' . $credits . $bell . $full . '</div></div>';
    }

    /** Set by a page that has its own title (an asset's value, a finding's title). HTML, already escaped. */
    public static string $pageTitle = '';
    public static string $pageActions = '';

    private static function pageHead(string $active): string
    {
        $title = self::$pageTitle !== '' ? self::$pageTitle : self::e(self::title($active));
        $desc = self::DESC[$active] ?? '';
        return '<div class="mcs-pagehead"><div><h2>' . $title . '</h2>' . ($desc !== '' ? '<p>' . self::e($desc) . '</p>' : '') . '</div>'
            . (self::$pageActions !== '' ? '<div class="mcs-actions">' . self::$pageActions . '</div>' : '') . '</div>';
    }

    private static function wrap(array $ctx, string $active, string $body): string
    {
        self::$view = '<div class="mcs-shell">' . self::side($ctx, $active) . '<main class="mcs-main"><div class="mcs-loadbar" aria-hidden="true"></div>' . self::topbar($ctx, $active, self::$pageTitle)
            . '<div class="mcs-page" data-mcs-page="' . self::e($active) . '">' . self::pageHead($active) . $body . '</div></main></div>';
        return self::root(self::$view, true);
    }

    private static function root(string $view, bool $script): string
    {
        return '<div class="mcs' . (self::full() ? ' mcs-full' : '') . '" dir="rtl" lang="fa">' . Ui::sprite() . '<style>' . self::asset('client.css') . '</style>'
            . '<div class="mcs-view" data-mcs-view>' . $view . '</div><div class="mcs-toast" data-mcs-toast role="status" aria-live="polite" hidden></div></div>'
            . ($script ? '<script>' . str_replace('</', '<\/', self::asset('client.js')) . '</script>' : '');
    }

    private static function asset(string $file): string
    {
        static $cache = [];
        return $cache[$file] ??= (string) @file_get_contents(__DIR__ . '/' . $file);
    }

    public static function render(string $p, array $ctx, string $flash): string
    {
        Ui::$nonce = null;
        self::$pageTitle = '';
        self::$pageActions = '';
        $body = Ui::flash($flash) . match ($p) {
            'assets' => AssetViews::list($ctx),
            'asset' => AssetViews::detail($ctx),
            'scans' => ScanViews::list($ctx),
            'scan' => ScanViews::detail($ctx),
            'schedules' => ScanViews::schedules($ctx),
            'findings' => FindingViews::list($ctx),
            'finding' => FindingViews::detail($ctx),
            'reports' => ReportViews::list($ctx),
            'report' => ReportViews::detail($ctx),
            'notify' => AccountViews::notify($ctx),
            'credits' => AccountViews::credits($ctx),
            'activity' => AccountViews::activity($ctx),
            default => self::home($ctx),
        };
        return self::wrap($ctx, $p, $body);
    }

    public static function closed(array $who): string
    {
        $msg = 'بخش امنیت سایبری هنوز برای حساب شما باز نشده است. اگر می‌خواهید از آن استفاده کنید، به پشتیبانی مارال کلاد پیام بدهید.';
        self::$view = Ui::alert('info', self::e($msg), 'info');
        return self::root(self::$view, false);
    }

    /** A "not found" body inside the shell (a wrong or foreign id in the address). */
    public static function missing(string $what, string $back, string $backLabel): string
    {
        return Ui::emptyState('search', $what . ' پیدا نشد', 'شاید حذف شده باشد یا مال حساب دیگری باشد.', '<a class="btn btn-default" href="' . self::e($back) . '">' . self::e($backLabel) . '</a>');
    }

    // ── overview ──

    private static function home(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $assets = Assets::forClient($cid);
        $verified = array_values(array_filter($assets, fn ($a) => $a->status === 'verified'));
        $score = Score::forClient($cid);
        $counts = Findings::openCounts($cid);
        $out = Ui::guide('<p>این‌جا در یک نگاه می‌بینید وضعیت امنیت سایت‌ها و سرورهایتان چطور است، از اسکن‌های اخیر چه چیزی تغییر کرده و مهم‌ترین کاری که الان باید انجام دهید چیست.</p>'
            . '<p>روال کار سه گام است: <strong>دارایی</strong> (دامنه یا IP) را بیفزایید، <strong>مالکیت</strong> را تأیید کنید (سرویس‌های خود مارال کلاد خودکار تأیید می‌شوند)، و <strong>اسکن</strong> بگیرید. بعد با زمان‌بندی، تغییرها را خودکار خبر می‌دهیم.</p>', !$verified);

        $checklist = self::checklist($ctx, $assets, $verified);
        if ($checklist !== '') {
            $out .= $checklist;
        }
        if (!$assets) {
            return $out;
        }
        // running scans banner
        foreach (Db::rows(Db::table('mod_mcsec_scans as s')->join('mod_mcsec_assets as a', 'a.id', '=', 's.asset_id')->where('s.client_id', $cid)->whereIn('s.status', ['queued', 'running'])
            ->select(['s.id', 's.status', 's.progress', 's.profile', 'a.value'])->limit(3)) as $s) {
            $out .= Ui::alert('info', 'اسکن «' . self::e(\McSec\Catalog::all(true)[$s->profile]['label'] ?? $s->profile) . '» روی ' . Ui::ltr($s->value) . ' '
                . ($s->status === 'queued' ? 'در صف است' : 'در حال اجراست (' . self::e(Text::fa((int) $s->progress)) . '٪)') . '. <a href="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $s->id . '">دیدن پیشرفت</a>', 'radar');
        }
        // row 1: score, open findings, changes in 7 days
        $week = Clock::now() - 7 * 86400;
        $new = Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('first_seen_at', '>=', $week)->count();
        $fixed = Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'fixed')->where('fixed_at', '>=', $week)->count();
        $reopened = Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'open')->where('reopened', '>', 0)->where('last_seen_at', '>=', $week)->count();
        $trend = Score::trend($cid, 60);
        $delta = '';
        if (count($trend) >= 2 && $score['score'] >= 0) {
            $d = $score['score'] - (int) $trend[max(0, count($trend) - 8)]['score'];
            $delta = $d === 0 ? 'بی‌تغییر نسبت به هفته‌ی پیش' : ($d > 0 ? Text::fa($d) . '+ از هفته‌ی پیش' : Text::fa(abs($d)) . '− از هفته‌ی پیش');
        }
        $scoreCard = Ui::card(Ui::gauge($score['score'], $score['score'] < 0 ? 'اولین اسکن را بگیرید تا امتیاز ساخته شود.' : self::e($delta))
            . '<details class="mcs-how"><summary>امتیاز چطور حساب می‌شود؟</summary><p>از ۱۰۰ شروع می‌شود و هر یافته‌ی باز به اندازه‌ی اهمیتش کم می‌کند. یک یافته‌ی بحرانیِ باز امتیاز را حداکثر ۴۹ و یک یافته‌ی مهم حداکثر ۷۹ نگه می‌دارد، تا مشکل جدی پشت چند مورد سالم پنهان نماند.</p></details>',
            'امتیاز امنیت', 'shield-check', '', 'mcs-scorecard');
        $openCard = Ui::card(Ui::sevCounts($counts, 'index.php?m=mcsec&p=findings') . '<p class="mcs-small mcs-muted">' . self::e(Text::fa(array_sum($counts))) . ' یافته‌ی باز در ' . self::e(Text::fa(count($verified))) . ' دارایی تأییدشده</p>',
            'یافته‌های باز', 'bug', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings">همه</a>');
        $diffCard = Ui::card('<ul class="mcs-diff"><li><strong>' . self::e(Text::fa($new)) . '</strong><span>تازه</span></li><li class="is-ok"><strong>' . self::e(Text::fa($fixed)) . '</strong><span>رفع‌شده</span></li>'
            . '<li class="is-warn"><strong>' . self::e(Text::fa($reopened)) . '</strong><span>دوباره دیده‌شده</span></li></ul>' . ($new > 0 ? '<a class="mcs-small" href="index.php?m=mcsec&amp;p=findings&amp;new=7">دیدن یافته‌های تازه</a>' : ''),
            'هفت روز اخیر', 'activity');
        $out .= '<div class="mcs-grid3">' . $scoreCard . $openCard . $diffCard . '</div>';

        // row 2: what to do now
        $rank = "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";
        $top = Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('status', 'open')->whereIn('severity', ['critical', 'high', 'medium'])
            ->orderByRaw($rank . ' DESC')->orderByDesc('last_seen_at')->limit(20));
        // one line per issue: the same port on the same IP reached through two assets is one job
        $seen = [];
        $top = array_slice(array_values(array_filter($top, function ($f) use (&$seen) {
            $k = $f->source_key . '|' . $f->location;
            if (isset($seen[$k])) {
                return false;
            }
            return $seen[$k] = true;
        })), 0, 5);
        if ($top) {
            $items = '';
            foreach ($top as $f) {
                $kb = Kb::get((string) $f->kb) ?? null;
                $items .= '<li><a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '">' . Ui::sev((string) $f->severity) . '<span class="mcs-todo-title">' . self::e($f->title) . '</span></a>'
                    . '<span class="mcs-todo-meta">' . Ui::ltr($f->location) . ($kb && !empty($kb['effort']) ? ' · ' . self::e($kb['effort']) : '') . '</span></li>';
            }
            $out .= Ui::card('<ol class="mcs-todo">' . $items . '</ol>', 'مهم‌ترین کارهای الان', 'check', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings">همه‌ی یافته‌ها</a>');
        } elseif ($score['score'] >= 0) {
            $out .= Ui::card(Ui::emptyState('shield-check', 'مشکل مهمی باز نیست', 'آفرین. با زمان‌بندی هفتگی، اگر چیزی تغییر کرد خبرتان می‌کنیم.', !Schedules::forClient($cid) && $ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=schedules">زمان‌بندی بسازید</a>' : ''));
        }

        // row 3: trend + assets + certificates
        $certs = self::expiringCerts($cid);
        $assetSummary = '<ul class="mcs-statlist"><li><span>تأییدشده</span><strong>' . self::e(Text::fa(count($verified))) . '</strong></li>'
            . '<li><span>در انتظار تأیید</span><strong>' . self::e(Text::fa(count(array_filter($assets, fn ($a) => $a->status === 'pending')))) . '</strong></li>'
            . '<li><span>تأیید منقضی</span><strong>' . self::e(Text::fa(count(array_filter($assets, fn ($a) => $a->status === 'lapsed')))) . '</strong></li></ul>' . $certs;
        $next = Db::table('mod_mcsec_schedules')->where('client_id', $cid)->where('status', 'active')->where('next_run_at', '>', 0)->orderBy('next_run_at')->first();
        $trendCard = Ui::card(Ui::spark($trend) . '<p class="mcs-small mcs-muted">' . ($next ? 'اسکن خودکار بعدی: ' . self::e(Text::date((int) $next->next_run_at)) : 'زمان‌بندی فعالی ندارید.') . '</p>', 'روند امتیاز', 'activity');
        $out .= '<div class="mcs-grid2">' . $trendCard . Ui::card($assetSummary, 'دارایی‌ها', 'globe', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=assets">مدیریت</a>') . '</div>';
        return $out;
    }

    /** The first-run checklist (hidden once everything is done). */
    private static function checklist(array $ctx, array $assets, array $verified): string
    {
        $cid = $ctx['who']['client_id'];
        $acc = Accounts::get($cid);
        $steps = [
            ['افزودن اولین دارایی', (bool) $assets, 'index.php?m=mcsec&p=assets#add'],
            ['تأیید مالکیت', (bool) $verified, 'index.php?m=mcsec&p=assets'],
            ['اولین اسکن', Db::table('mod_mcsec_scans')->where('client_id', $cid)->where('status', 'completed')->exists(), 'index.php?m=mcsec&p=scans'],
            ['اتصال بله، تلگرام یا وب‌هوک', $acc && ((string) $acc->bale_chat !== '' || (string) $acc->tg_chat !== '' || (string) $acc->webhook_url !== ''), 'index.php?m=mcsec&p=notify#channels'],
            ['زمان‌بندی خودکار', Db::table('mod_mcsec_schedules')->where('client_id', $cid)->exists(), 'index.php?m=mcsec&p=schedules'],
        ];
        $done = count(array_filter($steps, fn ($s) => $s[1]));
        if ($done === count($steps)) {
            return '';
        }
        $items = '';
        $nextShown = false;
        foreach ($steps as $i => [$label, $ok, $href]) {
            $isNext = !$ok && !$nextShown;
            $nextShown = $nextShown || $isNext;
            $items .= '<li class="' . ($ok ? 'is-done' : ($isNext ? 'is-next' : '')) . '"><span class="mcs-step-n" aria-hidden="true">' . ($ok ? Ui::ico('check') : self::e(Text::fa($i + 1))) . '</span>'
                . ($ok ? '<span>' . self::e($label) . '</span><span class="mcs-sr">انجام شد</span>' : '<a href="' . self::e($href) . '">' . self::e($label) . '</a>') . '</li>';
        }
        return Ui::card(Ui::meter($done, count($steps), self::e(Text::fa($done) . ' از ' . Text::fa(count($steps)) . ' گام')) . '<ol class="mcs-steps">' . $items . '</ol>', 'شروع کار', 'list', '', 'mcs-onboard');
    }

    /** Certificates that expire within 30 days (from the surface data). */
    private static function expiringCerts(int $clientId): string
    {
        $soon = [];
        foreach (Db::rows(Db::table('mod_mcsec_surface')->where('client_id', $clientId)->where('kind', 'cert')->where('gone_at', 0)->limit(300)) as $c) {
            $na = (string) (Surface::meta($c)['not_after'] ?? '');
            $t = $na !== '' ? strtotime($na) : false;
            if ($t && $t < Clock::now() + 30 * 86400) {
                $soon[] = ['host' => (string) $c->value, 'at' => $t];
            }
        }
        if (!$soon) {
            return '';
        }
        usort($soon, fn ($a, $b) => $a['at'] <=> $b['at']);
        $h = '<p class="mcs-small"><strong>گواهی‌های رو به انقضا</strong></p><ul class="mcs-plain">';
        foreach (array_slice($soon, 0, 5) as $s) {
            $days = (int) floor(($s['at'] - Clock::now()) / 86400);
            $h .= '<li>' . Ui::ltr($s['host']) . ' — ' . self::e($days < 0 ? 'منقضی شده' : Text::fa($days) . ' روز مانده') . '</li>';
        }
        return $h . '</ul>';
    }

    /** "۳ دقیقه پیش" or the date for older times. */
    public static function when(int $ts): string
    {
        if ($ts <= 0) {
            return '—';
        }
        return Clock::now() - $ts < 2 * 86400 ? Text::ago($ts) : Text::date($ts);
    }
}
