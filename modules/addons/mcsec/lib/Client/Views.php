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
use McSec\Lang;
use McSec\Monitor;
use McSec\Net;
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
        'finding' => 'یافته', 'reports' => 'گزارش‌ها', 'report' => 'گزارش', 'schedules' => 'زمان‌بندی‌ها', 'recipes' => 'اسکن سفارشی', 'assistant' => 'دستیار امنیت', 'support' => 'کمک کارشناس', 'notify' => 'اعلان‌ها', 'credits' => 'اعتبار و پلن', 'activity' => 'فعالیت‌ها'];

    private const DESC = ['home' => 'وضعیت امنیت سایت‌ها و سرورهایتان، آنچه تغییر کرده و مهم‌ترین کار بعدی.', 'assets' => 'دامنه‌ها و IPهایی که بررسی می‌شوند؛ فقط دارایی تأییدشده اسکن می‌شود.',
        'scans' => 'اسکن تازه بگیرید و تاریخچه‌ی اسکن‌ها را ببینید.', 'findings' => 'مشکل‌های پیدا شده، از مهم‌ترین، با راه رفع هر کدام.',
        'reports' => 'گزارش‌های پایه و هوش مصنوعی برای خودتان، مدیرتان یا تیم فنی.', 'schedules' => 'اسکن خودکار روزانه، هفتگی یا ماهانه؛ تغییرها را خبر می‌دهیم.', 'recipes' => 'حالت پیشرفته: از ابزارهای اسکن، اسکن خودتان را بسازید و ذخیره کنید.',
        'assistant' => 'بپرسید یا بگویید چه کاری می‌خواهید؛ دستیار از داده‌ی همین حساب جواب می‌دهد و کار را برای تأیید شما آماده می‌کند.',
        'support' => 'از کارشناسان امنیت مارال کلاد بخواهید یافته، اسکن یا دارایی شما را بررسی کنند.',
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
        $menu = self::MENU;
        if (\McSec\Recipes::allowed($cid)) {
            $menu['surface'][1][] = ['recipes', 'layers'];
        }
        if (\McSec\Assistant::allowed($cid)) {
            $menu[''][1][] = ['assistant', 'sparkle'];
        }
        if (\McSec\Support::enabled()) {
            $menu['results'][1][] = ['support', 'lifebuoy'];
        }
        foreach ($menu as [$title, $items]) {
            $links = '';
            foreach ($items as [$p, $icon]) {
                $on = $p === $active || ($parent[$active] ?? '') === $p;
                $count = match (true) {
                    $p === 'findings' && $urgent > 0 => '<span class="mcs-badge" aria-label="' . self::e(Lang::t('{n} مورد بحرانی یا مهم', ['n' => Text::fa($urgent)])) . '">' . Text::fa($urgent) . '</span>',
                    $p === 'assets' && $pending > 0 => '<span class="mcs-badge mcs-badge-warn" aria-label="' . self::e(Lang::t('{n} در انتظار تأیید', ['n' => Text::fa($pending)])) . '">' . Text::fa($pending) . '</span>',
                    $p === 'scans' && $running > 0 => '<span class="mcs-badge mcs-badge-run" aria-label="' . self::e(Lang::t('{n} اسکن در جریان', ['n' => Text::fa($running)])) . '">' . Text::fa($running) . '</span>',
                    $p === 'notify' && $unread > 0 => '<span class="mcs-badge" data-mcs-count="unread">' . Text::fa($unread) . '</span>',
                    default => '',
                };
                $links .= '<a class="mcs-side-link' . ($on ? ' active' : '') . '" href="index.php?m=mcsec&amp;p=' . $p . '"' . ($on ? ' aria-current="page"' : '') . '>'
                    . Ui::ico($icon) . '<span>' . self::e(self::PAGES[$p]) . '</span>' . $count . '</a>';
            }
            $nav .= '<div class="mcs-side-group">' . ($title !== '' ? '<p class="mcs-side-h">' . self::e($title) . '</p>' : '') . $links . '</div>';
        }
        $top = '<div class="mcs-side-brand"><span class="mcs-side-logo">' . Ui::ico('shield-check') . '</span><div><strong>' . self::e(Settings::menuLabel()) . '</strong><span>' . Lang::t('مارال کلاد') . '</span></div></div>';
        return '<aside class="mcs-side" id="mcs-side" aria-label="' . self::e(Settings::menuLabel()) . '">' . $top . '<nav class="mcs-side-nav">' . $nav . '</nav>'
            . '<a class="mcs-side-exit" href="clientarea.php">' . Ui::ico('chevron') . '<span>' . Lang::t('بازگشت به ناحیه‌ی کاربری') . '</span></a></aside>';
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
        $credits = '<a class="mcs-credit-chip' . ($bal['total'] <= max(0, Settings::int('low_credit_alert')) ? ' is-low' : '') . '" href="index.php?m=mcsec&amp;p=credits" title="' . Lang::t('مانده‌ی اعتبار اسکن') . '">'
            . Ui::ico('coins') . '<span>' . Lang::t('اعتبار: <strong>{n}</strong>', ['n' => self::e(Text::fa($bal['total']))]) . '</span></a>';
        $bell = '<a class="mcs-icon-btn" href="index.php?m=mcsec&amp;p=notify" aria-label="' . self::e($unread > 0 ? Lang::t('اعلان‌ها، {n} خبر تازه', ['n' => Text::fa($unread)]) : Lang::t('اعلان‌ها')) . '">' . Ui::ico('bell')
            . ($unread > 0 ? '<span class="mcs-badge" data-mcs-count="unread">' . Text::fa($unread) . '</span>' : '') . '</a>';
        $full = '<button type="button" class="mcs-icon-btn" data-mcs-full aria-pressed="' . (self::full() ? 'true' : 'false') . '" hidden title="' . Lang::t('تمام‌صفحه') . '">' . Ui::ico('expand') . '<span class="mcs-sr">' . Lang::t('تمام‌صفحه') . '</span></button>';
        return '<div class="mcs-topbar"><nav class="mcs-crumb" aria-label="' . Lang::t('مسیر') . '">' . $crumb . '</nav><div class="mcs-topbar-actions">' . $credits . $bell . $full . '</div></div>';
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
        Charts::$rtl = \McSec\Lang::rtl();
        return '<div class="mcs' . (self::full() ? ' mcs-full' : '') . '" ' . \McSec\Lang::attrs() . ' data-mcs-lang="' . \McSec\Lang::code() . '">' . Ui::sprite() . '<style>' . self::asset('client.css') . '</style>'
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
        Charts::$rtl = \McSec\Lang::rtl(); // before any page draws: time runs the way the page reads
        self::$pageTitle = '';
        self::$pageActions = '';
        $body = Ui::flash($flash) . match ($p) {
            'assets' => AssetViews::list($ctx),
            'asset' => AssetViews::detail($ctx),
            'scans' => ScanViews::list($ctx),
            'scan' => ScanViews::detail($ctx),
            'schedules' => ScanViews::schedules($ctx),
            'recipes' => ScanViews::recipes($ctx),
            'assistant' => AssistantViews::page($ctx),
            'support' => SupportViews::page($ctx),
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

    /**
     * The public "about this scanner" page (no login): what MC-Sec is, how it behaves, its User-Agent and IPs, and
     * whom to write to so a domain or IP is never scanned again. The User-Agent of every request links here.
     */
    public static function scanner(): string
    {
        $ips = array_values(array_filter(array_map('trim', preg_split('~[ \t\r\n,]+~', Settings::get('scanner_ips')) ?: []), fn ($ip) => filter_var($ip, FILTER_VALIDATE_IP) !== false || Net::ipRange($ip) !== null));
        $abuse = trim(Settings::get('abuse_email'));
        $abuse = filter_var($abuse, FILTER_VALIDATE_EMAIL) ? $abuse : '';
        $contact = $abuse !== '' ? Lang::t('به {email} بنویسید', ['email' => '<a href="mailto:' . self::e($abuse) . '" dir="ltr">' . self::e($abuse) . '</a>']) : Lang::t('از راه <a href="contact.php">فرم تماس</a> همین سایت به ما خبر دهید');
        $body = '<div class="mcs-page mcs-public"><div class="mcs-pagehead"><div><h2>' . Lang::t('درباره‌ی اسکنر امنیتی مارال کلاد') . '</h2><p>' . Lang::t('اگر در لاگ سرور یا فایروال خود درخواست‌هایی با شناسه‌ی MC-Sec دیده‌اید، این صفحه برای شماست.') . '</p></div></div>'
            . Ui::card(Lang::t('<p>«امنیت سایبری» بخشی از ناحیه‌ی کاربری مارال کلاد است که مشتریان با آن سایت‌ها و سرورهای خودشان را از نظر امنیتی می‌سنجند. هر مشتری <strong>فقط دارایی‌ای را اسکن می‌کند که مالکیتش را ثابت کرده است</strong>: با رکورد DNS، فایلی روی همان سایت، یا سرویسی که خودش در مارال کلاد دارد. دامنه‌ها و IPهای فهرست ممنوع (از جمله نشانی‌های دولتی، نظامی و آموزشی) هرگز اسکن نمی‌شوند و سرورهای CDN درگاه‌کاوی نمی‌شوند.</p>')
                . Lang::t('<ul><li>بررسی‌ها غیرتهاجمی‌اند: هیچ رمزی حدس زده نمی‌شود، از هیچ آسیب‌پذیری‌ای بهره‌برداری نمی‌شود و شمار درخواست‌ها کم است.</li><li>پایش در دسترس بودن، اگر روشن باشد، هر چند دقیقه فقط صفحه‌ی اول سایت را یک بار باز می‌کند.</li></ul>'), 'این درخواست‌ها از کجاست؟', 'shield')
            . Ui::card(Ui::facts(['شناسه‌ی مرورگر (User-Agent)' => Ui::code(\McSec\Http::ua(), '', false), 'IPهای اسکنر' => $ips ? implode(' ', array_map(fn ($ip) => Ui::ltr($ip, 'mcs-tag'), $ips)) : '<span class="mcs-muted">' . Lang::t('اعلام نشده') . '</span>'])
                . '<p class="mcs-small mcs-muted">' . Lang::t('اگر مشتری مارال کلاد هستید و فایروال یا WAF جلوی بررسی را می‌گیرد (اسکن «ناقص» می‌شود)، همین IPها یا شناسه را مجاز کنید.') . '</p>', 'شناسه و نشانی‌ها', 'info')
            . Ui::card('<p>' . Lang::t('اگر این دامنه یا IP مال شماست و اجازه‌ی اسکن نداده‌اید، {contact}: نشانی دامنه یا IP، زمان تقریبی و اگر می‌شود بخشی از لاگ. بررسی می‌کنیم و آن را در فهرست ممنوع می‌گذاریم تا دیگر اسکن نشود.', ['contact' => $contact]) . '</p>', 'توقف اسکن یا گزارش سوءاستفاده', 'alert')
            . '</div>';
        self::$view = $body;
        return self::root($body, false);
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
        return Ui::emptyState('search', Lang::t('{what} پیدا نشد', ['what' => Lang::t($what)]), Lang::t('شاید حذف شده باشد یا مال حساب دیگری باشد.'), '<a class="btn btn-default" href="' . self::e($back) . '">' . self::e($backLabel) . '</a>');
    }

    // ── overview ──

    private static function home(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $assets = Assets::forClient($cid);
        $verified = array_values(array_filter($assets, fn ($a) => $a->status === 'verified'));
        $score = Score::forClient($cid);
        $counts = Findings::openCounts($cid);
        $out = Ui::guide(Lang::t('<p>این‌جا در یک نگاه می‌بینید وضعیت امنیت سایت‌ها و سرورهایتان چطور است، از اسکن‌های اخیر چه چیزی تغییر کرده و مهم‌ترین کاری که الان باید انجام دهید چیست.</p>')
            . Lang::t('<p>روال کار سه گام است: <strong>دارایی</strong> (دامنه یا IP) را بیفزایید، <strong>مالکیت</strong> را تأیید کنید (سرویس‌های خود مارال کلاد خودکار تأیید می‌شوند)، و <strong>اسکن</strong> بگیرید. بعد با زمان‌بندی، تغییرها را خودکار خبر می‌دهیم.</p>'), !$verified);

        $checklist = self::checklist($ctx, $assets, $verified);
        if ($checklist !== '') {
            $out .= $checklist;
        }
        if (!$assets) {
            return $out;
        }
        // sites the light monitoring sees as down
        foreach ($verified as $a) {
            $m = Monitor::status($a);
            if ($m !== null && $m[1] === 'err') {
                $out .= Ui::alert('danger', Lang::t('{asset} از دسترس خارج است ({why}).', ['asset' => Ui::ltr($a->value), 'why' => Ui::plain($m[2])]) . ' <a href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '">' . Lang::t('جزئیات') . '</a>', 'alert');
            }
        }
        return $out . HomeViews::body($ctx, $assets, $verified, $score, $counts);
    }

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
                . ($ok ? '<span>' . self::e($label) . '</span><span class="mcs-sr">' . Lang::t('انجام شد') . '</span>' : '<a href="' . self::e($href) . '">' . self::e($label) . '</a>') . '</li>';
        }
        return Ui::card(Ui::meter($done, count($steps), self::e(Lang::t('{n} از {total} گام', ['n' => Text::fa($done), 'total' => Text::fa(count($steps))]))) . '<ol class="mcs-steps">' . $items . '</ol>', 'شروع کار', 'list', '', 'mcs-onboard');
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
        $h = '<p class="mcs-small"><strong>' . Lang::t('گواهی‌های رو به انقضا') . '</strong></p><ul class="mcs-plain">';
        foreach (array_slice($soon, 0, 5) as $s) {
            $days = (int) floor(($s['at'] - Clock::now()) / 86400);
            $h .= '<li>' . Ui::ltr($s['host']) . ' — ' . self::e($days < 0 ? Lang::t('منقضی شده') : Lang::t('{n} روز مانده', ['n' => Text::fa($days)])) . '</li>';
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
