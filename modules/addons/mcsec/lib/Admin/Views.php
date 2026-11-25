<?php

declare(strict_types=1);

namespace McSec\Admin;

use McSec\Auth;
use McSec\Catalog;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Findings;
use McSec\Scans;
use McSec\Settings;
use McSec\Text;
use McSec\Trace;
use McSec\Verify;
use McSec\Whmcs;

/** Admin pages (Persian, RTL), scoped under .mcsa. Every page has «راهنمای این صفحه»; every setting an ⓘ text and default. */
final class Views
{
    public static string $link = 'addonmodules.php?module=mcsec';
    /** Text settings that hold rule lists (domains, IPs, URLs): left-to-right, taller boxes. */
    private const LTR_LISTS = ['blocklist', 'cdn_list', 'reputation_lists', 'scanner_ips'];

    private static function e($s): string
    {
        return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function url(string $page, string $extra = ''): string
    {
        return self::$link . '&mcsa=' . $page . $extra;
    }

    private static function form(string $page, string $act, string $body, string $confirm = ''): string
    {
        return '<form method="post" action="' . self::e(self::url($page)) . '"' . ($confirm !== '' ? ' onsubmit="return confirm(' . self::e(json_encode($confirm, JSON_UNESCAPED_UNICODE)) . ')"' : '') . '>'
            . '<input type="hidden" name="mcsa_csrf" value="' . self::e(Auth::csrf()) . '"><input type="hidden" name="mcsa_act" value="' . self::e($act) . '">' . $body . '</form>';
    }

    private static function box(string $title, string $body, string $help = ''): string
    {
        return '<section class="mcsa-box"><h3>' . self::e($title) . '</h3>' . ($help !== '' ? '<p class="mcsa-help">' . $help . '</p>' : '') . $body . '</section>';
    }

    private static function guide(string $html): string
    {
        return '<details class="mcsa-guide"><summary>راهنمای این صفحه</summary><div>' . $html . '</div></details>';
    }

    private static function flash(string $f): string
    {
        if ($f === '') {
            return '';
        }
        [$k, $m] = array_pad(explode(':', $f, 2), 2, '');
        return '<div class="alert alert-' . ($k === 'ok' ? 'success' : 'danger') . '">' . nl2br(self::e($m), false) . '</div>';
    }

    /** Pages grouped the way MC-Care groups its tabs: a few tabs in the dark bar, the pages of the open tab under it. */
    private const GROUPS = [
        'نمای کلی' => ['overview'],
        'عملیات' => ['assets', 'scans', 'requests'],
        'فروش و اعتبار' => ['pricing', 'credits', 'codes', 'revenue'],
        'راه‌اندازی' => ['setup', 'report', 'settings'],
        'سامانه' => ['log', 'changelog'],
    ];

    private const SUBS = ['revenue' => 'فروش بسته‌ها، اعتبار فروخته و مصرف‌شده، و پرخریدترین حساب‌ها.', 'overview' => 'شمار کلی استفاده، سلامت موتورها و پرمصرف‌ترین حساب‌ها.', 'setup' => 'اتصال به موتور اسکن، هوش مصنوعی و ربات‌های اعلان.', 'pricing' => 'نوع‌های اسکن، هزینه‌ی هر کدام، بسته‌های اعتبار و پلن‌ها.',
        'credits' => 'قیمت ویژه‌ی یک گروه یا یک حساب، اعطای دستی اعتبار و دفتر تراکنش‌ها.', 'codes' => 'کدهای اعتبار و تخفیف، هدیه، دعوت و شارژ خودکار.', 'assets' => 'دارایی‌های مشتریان و تأیید دستی مالکیت.',
        'scans' => 'اسکن‌های در صف، در حال اجرا و تمام‌شده.', 'requests' => 'درخواست‌های مشتریان از کارشناس: پرسش، بررسی و رفع عیب، و تست دستی با اعلام قیمت.', 'report' => 'ظاهر گزارش PDF: لوگو، نام، رنگ، فونت و بخش‌ها.', 'settings' => 'هر قابلیتی که روی مشتری اثر دارد پیش‌فرض خاموش است.', 'log' => 'خطاها و هشدارهای سامانه با کد پیگیری.', 'changelog' => 'هر نسخه چه چیزی را عوض کرده است.'];

    /**
     * The shell shared with MC-Care (its «style B»): a dark bar with the brand and the tabs, the pages of the open tab
     * under it, a soft grey page, white cards with a grey header strip, dark primary buttons. Only CSS and markup
     * under .mcsa; no script, no font file, nothing loaded from outside.
     */
    public static function render(string $page, string $flash): string
    {
        $tabs = '';
        $pills = '';
        $waiting = \McSec\Requests::waiting();
        $hot = (Settings::bool('ops_alerts') ? count(\McSec\ScanLog::attention(1, 50)) : 0) + $waiting;
        foreach (self::GROUPS as $label => $pages) {
            $on = in_array($page, $pages, true);
            $badge = $hot > 0 && in_array('scans', $pages, true) ? ' <span class="mcsa-count" title="اسکن‌های ۲۴ ساعت اخیر که نیاز به بررسی دارند و درخواست‌های منتظر تیم">' . self::e(Text::fa($hot)) . '</span>' : '';
            $tabs .= '<li' . ($on ? ' class="active"' : '') . '><a href="' . self::e(self::url(in_array('scans', $pages, true) && $hot > 0 ? ($waiting > 0 ? 'requests' : 'scans') : $pages[0])) . '"' . ($on ? ' aria-current="true"' : '') . '>' . self::e($label) . $badge . '</a></li>';
            if ($on && count($pages) > 1) {
                foreach ($pages as $p) {
                    $pills .= '<li' . ($p === $page ? ' class="active"' : '') . '><a href="' . self::e(self::url($p)) . '"' . ($p === $page ? ' aria-current="page"' : '') . '>' . self::e(Controller::PAGES[$p]) . '</a></li>';
                }
            }
        }
        $tier = Auth::adminTier();
        $body = match ($page) {
            'setup' => self::setup(),
            'pricing' => self::pricing(),
            'credits' => self::credits(),
            'codes' => self::codes(),
            'revenue' => self::revenue(),
            'assets' => self::assets(),
            'scans' => self::scans(),
            'settings' => self::settings(),
            'report' => self::report(),
            'requests' => self::requests(),
            'log' => self::log(),
            'changelog' => self::changelog(),
            default => self::overview(),
        };
        $warn = !Settings::bool('enabled') ? '<div class="alert alert-info">MC-Sec برای مشتری‌ها خاموش است. پس از راه‌اندازی موتورها و آزمودن روی چند حساب آزمایشی، در «تنظیمات» روشنش کنید.</div>' : '';
        $notes = $warn . self::flash($flash);
        $title = Controller::PAGES[$page] ?? Controller::PAGES['overview'];
        return '<div class="mcsa" id="mcsa-root" dir="rtl" lang="fa"><style>' . self::css() . '</style>'
            . '<div class="mcsa-shell"><div class="mcsa-topbar"><a class="mcsa-brand" href="' . self::e(self::url('overview')) . '"><span class="mcsa-logo" aria-hidden="true">MC</span><b>MC-Sec</b></a>'
            . '<ul class="mcsa-tabs">' . $tabs . '</ul><span class="mcsa-ver">نسخه‌ی <bdi dir="ltr">' . self::e(MCSEC_VERSION) . '</bdi> · سطح شما: ' . self::e($tier) . '</span></div>'
            . ($pills !== '' ? '<ul class="mcsa-pills">' . $pills . '</ul>' : '') . '</div>'
            . ($notes !== '' ? '<div class="mcsa-flashwrap">' . $notes . '</div>' : '')
            . '<div class="mcsa-body"><div class="mcsa-head"><h2>' . self::e($title) . '</h2><div class="sub">' . self::e(self::SUBS[$page] ?? '') . '</div></div>' . $body . '</div></div>';
    }

    private static function overview(): string
    {
        $now = Clock::now();
        $k = [
            'حساب‌های فعال' => Db::table('mod_mcsec_accounts')->count(),
            'دارایی تأییدشده' => Db::table('mod_mcsec_assets')->where('status', 'verified')->count(),
            'در انتظار تأیید' => Db::table('mod_mcsec_assets')->where('status', 'pending')->count(),
            'اسکن ۲۴ ساعت' => Db::table('mod_mcsec_scans')->where('queued_at', '>', $now - 86400)->count(),
            'در حال اجرا / صف' => Db::table('mod_mcsec_scans')->where('status', 'running')->count() . ' / ' . Db::table('mod_mcsec_scans')->where('status', 'queued')->count(),
            'ناموفق ۷ روز' => Db::table('mod_mcsec_scans')->where('status', 'failed')->where('finished_at', '>', $now - 7 * 86400)->count(),
            'اعتبار مصرف‌شده ۳۰ روز' => -(int) Db::table('mod_mcsec_ledger')->where('kind', 'spend')->where('created_at', '>', $now - 30 * 86400)->sum('delta'),
            'اعتبار فروخته‌شده ۳۰ روز' => (int) Db::table('mod_mcsec_ledger')->where('kind', 'topup')->where('created_at', '>', $now - 30 * 86400)->sum('delta'),
            'یافته‌ی باز بحرانی/بالا' => Db::table('mod_mcsec_findings')->where('status', 'open')->whereIn('severity', ['critical', 'high'])->count(),
        ];
        $kpis = '<div class="mcsa-kpis">';
        foreach ($k as $l => $v) {
            $kpis .= '<div><span>' . self::e($l) . '</span><strong>' . self::e(is_int($v) ? Text::fa($v) : Text::fa((string) $v)) . '</strong></div>';
        }
        $kpis .= '</div>';
        $health = '<ul class="mcsa-health">';
        foreach (['builtin' => 'بررسی داخلی', 'oasm' => 'OASM', 'osmedeus' => 'Osmedeus', 'ai' => 'هوش مصنوعی'] as $e => $l) {
            $h = json_decode(Settings::get('health_' . $e), true);
            $state = is_array($h) ? ($h['ok'] ? '<b class="ok">سالم</b>' : '<b class="err">مشکل</b>') . ' — ' . self::e($h['message'] ?? '') . ' <small>(' . self::e(Text::ago((int) ($h['at'] ?? 0))) . ')</small>' : '<span class="mcsa-muted">آزموده نشده</span>';
            $health .= '<li><strong>' . self::e($l) . ':</strong> ' . $state . '</li>';
        }
        $health .= '</ul>';
        $w = (int) Settings::get('last_worker_at');
        $worker = $w > 0 ? 'آخرین اجرای کار پس‌زمینه: ' . self::e(Text::ago($w)) . ($w < $now - 900 ? ' — <b class="err">بیش از ۱۵ دقیقه پیش؛ cron سیستم WHMCS را بررسی کنید.</b>' : '') : '<b class="err">کار پس‌زمینه هنوز اجرا نشده است (cron WHMCS).</b>';
        $top = Db::rows(Db::table('mod_mcsec_scans')->where('queued_at', '>', $now - 30 * 86400)->selectRaw('client_id, COUNT(*) AS n, SUM(credits) AS c')->groupBy('client_id')->orderByDesc('n')->limit(10));
        $names = Whmcs::clientNames(array_map(fn ($r) => (int) $r->client_id, $top));
        $rows = '';
        foreach ($top as $r) {
            $rows .= '<tr><td><a href="clientssummary.php?userid=' . (int) $r->client_id . '">#' . (int) $r->client_id . ' ' . self::e($names[(int) $r->client_id] ?? '') . '</a></td><td>' . self::e(Text::fa((int) $r->n)) . '</td><td>' . self::e(Text::fa((int) $r->c)) . '</td></tr>';
        }
        return self::guide('<p>شمار کلی استفاده، سلامت موتورها و پرمصرف‌ترین حساب‌ها. سلامت هر موتور را در «راه‌اندازی موتورها» با دکمه‌ی «آزمودن» تازه کنید.</p>')
            . $kpis . self::attention(5) . self::box('سلامت', $health . '<p>' . $worker . '</p>' . self::form('overview', 'run_worker', '<button class="btn btn-default">اجرای کار پس‌زمینه همین حالا</button>'))
            . self::box('پرمصرف‌ترین حساب‌ها (۳۰ روز)', $rows !== '' ? '<table class="table"><thead><tr><th>حساب</th><th>اسکن</th><th>اعتبار</th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">هنوز اسکنی نیست.</p>');
    }

    /** Fields of settings in one group, generated from Settings::DEFS (label, ⓘ help, default). */
    private static function fields(string $group, array $only = []): string
    {
        $h = '';
        foreach (Settings::DEFS as $k => [$def, $type, $g, $label, $help]) {
            if ($g !== $group || ($only && !in_array($k, $only, true))) {
                continue;
            }
            $id = 'mcsa-' . $k;
            $val = Settings::get($k);
            $control = match ($type) {
                'bool' => '<input type="hidden" name="has_' . $k . '" value="1"><label class="mcsa-switch"><input type="checkbox" id="' . $id . '" name="set_' . $k . '" value="1"' . ($val === '1' ? ' checked' : '') . '> روشن</label>',
                'secret' => '<input class="form-control" type="password" autocomplete="new-password" id="' . $id . '" name="set_' . $k . '" placeholder="' . ($val !== '' ? '•••••• (ذخیره شده؛ خالی بگذارید تا بماند)' : 'تنظیم نشده') . '" dir="ltr">'
                    . ($val !== '' ? '<label class="mcsa-inline"><input type="checkbox" name="clear_' . $k . '" value="1"> پاک شود</label>' : ''),
                'text', 'json' => '<textarea class="form-control" id="' . $id . '" name="set_' . $k . '" rows="' . ($type === 'json' ? 5 : (in_array($k, self::LTR_LISTS, true) ? 8 : 3)) . '" dir="' . ($type === 'json' || in_array($k, self::LTR_LISTS, true) ? 'ltr' : 'auto') . '">' . self::e($val) . '</textarea>',
                default => '<input class="form-control" id="' . $id . '" name="set_' . $k . '" value="' . self::e($val) . '" dir="' . (in_array($type, ['int', 'csv'], true) || str_ends_with($k, '_url') || str_contains($k, 'email') || str_contains($k, 'model') || in_array($k, ['pdf_color', 'pdf_accent', 'pdf_font', 'pdf_page'], true) ? 'ltr' : 'auto') . '">',
            };
            $h .= '<div class="mcsa-field"><label for="' . $id . '">' . self::e($label) . ' <span class="mcsa-i" tabindex="0" role="note" title="' . self::e($help . ($type !== 'secret' && $def !== '' && strlen($def) < 60 ? ' پیش‌فرض: ' . $def : '')) . '">?</span></label>' . $control
                . ($help !== '' ? '<small>' . self::e($help) . '</small>' : '') . '</div>';
        }
        return $h;
    }

    private static function setup(): string
    {
        $test = fn (string $e, string $l) => self::form('setup', 'test_engine', '<input type="hidden" name="engine" value="' . $e . '"><button class="btn btn-default btn-sm">آزمودن ' . self::e($l) . '</button>');
        $ip = (string) ($_SERVER['SERVER_ADDR'] ?? '');
        return self::guide('<ol><li><strong>OASM:</strong> نشانی و یک کاربر <em>admin</em> را بدهید. MC-Sec برای هر حساب مشتری یک کاربر و یک فضای کار جدا در OASM می‌سازد (هر کاربر OASM حداکثر ۵ فضا دارد). برای اسکن آسیب‌پذیری، OASM باید worker با Nuclei داشته باشد.</li>'
            . '<li><strong>Osmedeus:</strong> نشانی (مثلاً <code dir="ltr">http://IP:8811</code>) و ترجیحاً کلید API (<code dir="ltr">osmedeus config view server.auth_api_key</code>). فایروال سرور Osmedeus باید IP سرور WHMCS' . ($ip !== '' ? ' (<code dir="ltr">' . self::e($ip) . '</code>)' : '') . ' را بپذیرد. Osmedeus v5 فقط HTTP دارد؛ پشت TLS یا تونل بگذارید.</li>'
            . '<li><strong>هوش مصنوعی:</strong> هر سرویس سازگار با OpenAI (OpenAI، New API مارال، OpenRouter). اگر خاموش باشد، گزارش‌ها با پایگاه دانش فارسی داخلی ساخته می‌شوند.</li>'
            . '<li><strong>اعلان:</strong> ربات بله (درون ایران در دسترس) و/یا تلگرام. مشتری با کد ۸ نویسه‌ای در صفحه‌ی «اعلان‌ها» وصل می‌شود.</li></ol><p>هر بخش را ذخیره و بعد «آزمودن» را بزنید.</p>')
            . self::box('OASM', self::form('setup', 'save_engines', self::fields('engines', ['oasm_url', 'oasm_email', 'oasm_password', 'oasm_verify_tls', 'oasm_user_domain']) . '<button class="btn btn-primary">ذخیره</button>') . $test('oasm', 'OASM'))
            . self::box('Osmedeus', self::form('setup', 'save_engines', self::fields('engines', ['osm_url', 'osm_api_key', 'osm_username', 'osm_password', 'osm_verify_tls']) . '<button class="btn btn-primary">ذخیره</button>') . $test('osmedeus', 'Osmedeus'))
            . self::box('ابزارهای کلیددار OASM (Acunetix، WPScan) و تنظیم ابزارها', self::form('setup', 'save_engines', self::fields('engines', ['acunetix_url', 'acunetix_key', 'acunetix_verify_tls', 'wpscan_token', 'tool_configs']) . '<button class="btn btn-primary">ذخیره</button>')
                . '<p class="mcsa-help">کلیدها در فضای کار هر مشتری در OASM به‌عنوان پروفایل ابزار گذاشته می‌شوند و با تغییرشان، در اسکن بعدی هر مشتری به‌روز می‌شوند. پس از گذاشتن کلید، نوع اسکن مربوط را در «قیمت و پلن» روشن کنید.</p>')
            . self::box('بررسی‌های داخلی', '<p>روی همین سرور WHMCS اجرا می‌شوند (DNS، TLS، هدرها، چند درگاه پرخطر روی IPهای خود مشتری). اگر فایروال خروجی دارید، درگاه‌های ۸۰ و ۴۴۳ و درگاه‌های «بررسی پایه» باید باز باشند.</p>' . $test('builtin', 'بررسی داخلی'))
            . self::box('هوش مصنوعی', self::form('setup', 'save_settings', self::fields('ai') . '<button class="btn btn-primary">ذخیره</button>') . $test('ai', 'مدل'))
            . self::box('اعلان‌ها', self::form('setup', 'save_settings', self::fields('notify') . '<button class="btn btn-primary">ذخیره</button>') . $test('bots', 'ربات‌ها'));
    }

    private static function pricing(): string
    {
        $rows = '';
        foreach (Catalog::all(true) as $k => $p) {
            $risk = Catalog::risk($p);
            $rows .= '<tr><td><code dir="ltr">' . self::e($k) . '</code><br><small>' . self::e((Catalog::CATEGORIES[$p['cat'] ?? 'custom'][0] ?? '') . ' · ' . Catalog::engineLabel($p['engine']))
                . (!empty($p['tools']) ? ': <bdi dir="ltr">' . self::e(implode(' → ', $p['tools'])) . '</bdi> · ' . self::e(Catalog::RISK[$risk] ?? '') : '') . '</small></td>'
                . '<td><input class="form-control" name="pl[' . $k . ']" value="' . self::e($p['label']) . '"></td>'
                . '<td><input class="form-control" name="pc[' . $k . ']" value="' . (int) $p['credits'] . '" dir="ltr" style="max-width:90px"></td>'
                . '<td>' . (isset($p['workflow']) ? '<input class="form-control" name="pw[' . $k . ']" value="' . self::e($p['workflow']) . '" dir="ltr" style="max-width:150px">' : '—') . '</td>'
                . '<td><label><input type="checkbox" name="pf[' . $k . ']" value="1"' . ($p['free'] ? ' checked' : '') . '> بی‌پلن</label></td>'
                . '<td><label><input type="checkbox" name="pe[' . $k . ']" value="1"' . ($p['enabled'] ? ' checked' : '') . '> روشن</label></td></tr>';
        }
        $prof = self::form('pricing', 'save_profiles', '<table class="table"><thead><tr><th>کلید</th><th>نام برای مشتری</th><th>اعتبار هر دارایی</th><th>workflow (Osmedeus)</th><th>در دسترس</th><th>وضعیت</th></tr></thead><tbody>' . $rows . '</tbody></table><button class="btn btn-primary">ذخیره</button>');
        $packRows = '';
        $packs = array_values(Credits::packs());
        for ($i = 0; $i < max(3, count($packs) + 1); $i++) {
            $p = $packs[$i] ?? ['key' => '', 'credits' => '', 'price' => '', 'label' => ''];
            $packRows .= '<tr><td><input class="form-control" name="pk_key[]" value="' . self::e($p['key']) . '" dir="ltr" placeholder="p100"></td><td><input class="form-control" name="pk_credits[]" value="' . self::e($p['credits']) . '" dir="ltr"></td>'
                . '<td><input class="form-control" name="pk_price[]" value="' . self::e($p['price'] === '' ? '' : (string) $p['price']) . '" dir="ltr"></td><td><input class="form-control" name="pk_label[]" value="' . self::e($p['label']) . '"></td></tr>';
        }
        $packsForm = self::form('pricing', 'save_packs', '<table class="table"><thead><tr><th>کلید</th><th>اعتبار</th><th>قیمت (ارز پیش‌فرض)</th><th>نام</th></tr></thead><tbody>' . $packRows . '</tbody></table><button class="btn btn-primary">ذخیره</button>');
        $plans = '';
        foreach (Whmcs::planProducts() as $pr) {
            $n = Db::table('mod_mcsec_plans')->where('product_id', $pr->id)->where('status', 'active')->count();
            $plans .= '<li><a href="configproducts.php?action=edit&id=' . (int) $pr->id . '">' . self::e($pr->name) . '</a> — ' . self::e(Text::fa($n)) . ' سرویس فعال</li>';
        }
        return self::guide('<p><strong>مدل قیمت:</strong> پلن‌ها (محصول WHMCS با ماژول سرور «MC-Sec») سقف دارایی، اعتبار ماهانه، نوع‌های اسکن و کوتاه‌ترین فاصله‌ی زمان‌بندی را می‌دهند؛ هر اسکن به اندازه‌ی عمقش اعتبار مصرف می‌کند؛ بسته‌های اعتبار با فاکتور WHMCS فروخته می‌شوند؛ قیمت ویژه‌ی یک گروه یا یک حساب در «قاعده‌ها و اعطا» و کدهای تخفیف، هدیه و دعوت در «کدها» است.</p>'
            . '<p>هزینه‌ی هر نوع اسکن برای یک دامنه یا IP است؛ بازه‌ی IP به ازای هر ۱۶ آدرس. نوعی که «بی‌پلن» نیست فقط برای مشتری‌های دارای پلنی است که آن را دارد.</p>'
            . '<p><strong>ساختن پلن:</strong> Setup › Products › محصول تازه، تب Module Settings، ماژول «MC-Sec — پلن امنیت سایبری»، و اعتبار ماهانه، سقف دارایی، نوع‌ها و گزارش هوش مصنوعی را بگذارید. تمدید هر ماه اعتبار ماه را یک بار می‌دهد.</p>')
            . self::box('نوع‌های اسکن و هزینه', $prof) . self::box('نوع اسکن سفارشی از ابزارهای OASM', self::customProfiles()) . self::box('بسته‌های خرید اعتبار', $packsForm)
            . self::box('هزینه‌های دیگر', self::form('pricing', 'save_settings', self::fields('credits', ['ai_report_cost', 'ai_fix_cost', 'welcome_credits', 'low_credit_alert', 'refund_on_fail', 'invoice_due_days']) . '<button class="btn btn-primary">ذخیره</button>'))
            . self::box('پلن‌ها (محصول‌های ماژول MC-Sec)', $plans !== '' ? '<ul>' . $plans . '</ul>' : '<p class="mcsa-muted">هنوز محصولی با ماژول MC-Sec نساخته‌اید.</p>');
    }

    /** Build a scan type from OASM tools: no code needed when OASM gains a tool MC-Sec knows (Catalog::TOOLS). */
    private static function customProfiles(): string
    {
        $tools = '';
        foreach (Catalog::TOOLS as $name => $t) {
            $tools .= '<tr><td><code dir="ltr">' . self::e($name) . '</code></td><td>' . self::e($t['what']) . '</td><td>' . self::e(Catalog::RISK[$t['risk']]) . '</td><td>'
                . self::e(implode('، ', array_map(fn ($k) => \McSec\Assets::KINDS[$k] ?? $k, $t['kinds']))) . '</td><td>' . (isset($t['needs']) ? (Settings::secret($t['needs']) !== '' ? '<b class="ok">کلید دارد</b>' : '<b class="err">کلید می‌خواهد</b>') : '—') . '</td></tr>';
        }
        $list = '';
        foreach (Catalog::custom() as $k => $p) {
            $list .= '<li><code dir="ltr">' . self::e($k) . '</code> — ' . self::e($p['label']) . ' <small class="mcsa-muted"><bdi dir="ltr">' . self::e(implode(' → ', $p['tools'])) . '</bdi></small> '
                . self::form('pricing', 'delete_custom', '<input type="hidden" name="cp_key" value="' . self::e($k) . '"><button class="btn btn-default btn-xs">برداشتن</button>', 'این نوع اسکن برداشته شود؟') . '</li>';
        }
        $form = self::form('pricing', 'save_custom', '<div class="mcsa-row"><div class="mcsa-field"><label for="mcsa-cpk">کلید</label><input class="form-control" id="mcsa-cpk" name="cp_key" dir="ltr" placeholder="web_full" required><small>لاتین کوچک؛ «c_» خودکار جلویش می‌آید. کلید موجود را بازنویسی می‌کند.</small></div>'
            . '<div class="mcsa-field"><label for="mcsa-cpl">نام برای مشتری</label><input class="form-control" id="mcsa-cpl" name="cp_label" required></div>'
            . '<div class="mcsa-field"><label for="mcsa-cpt">ابزارها، به ترتیب اجرا</label><input class="form-control" id="mcsa-cpt" name="cp_tools" dir="ltr" placeholder="katana,nuclei,zap" required><small>با ویرگول. هر ابزار پس از ابزار قبلی اجرا می‌شود.</small></div>'
            . '<div class="mcsa-field"><label for="mcsa-cpc">اعتبار هر دارایی</label><input class="form-control" id="mcsa-cpc" name="cp_credits" dir="ltr" value="10"></div></div>'
            . '<div class="mcsa-field"><label for="mcsa-cpd">توضیح برای مشتری</label><input class="form-control" id="mcsa-cpd" name="cp_desc" maxlength="300"></div>'
            . '<label class="mcsa-inline"><input type="checkbox" name="cp_free" value="1"> بی‌پلن هم در دسترس</label> <label class="mcsa-inline"><input type="checkbox" name="cp_enabled" value="1"> روشن</label> <button class="btn btn-primary">ذخیره‌ی نوع اسکن</button>');
        return '<p class="mcsa-help">نوع اسکن تازه را از ابزارهای زیر بسازید. MC-Sec ابزار را در فضای کار هر مشتری خودکار نصب می‌کند و با تنظیم ملایم خودش اجرا می‌کند. ابزار «پرفشار» درخواست زیادی به هدف می‌فرستد؛ آن را فقط برای پلن‌های حرفه‌ای بگذارید. قانون‌های مالکیت، فهرست ممنوع و CDN برای همه‌ی نوع‌ها یکی است.</p>'
            . '<table class="table"><thead><tr><th>ابزار</th><th>کار</th><th>فشار</th><th>نوع دارایی</th><th>کلید</th></tr></thead><tbody>' . $tools . '</tbody></table>'
            . ($list !== '' ? '<p><strong>نوع‌های سفارشی فعلی</strong> (قیمت و روشن بودنشان در جدول بالا):</p><ul>' . $list . '</ul>' : '') . $form;
    }

    private static function credits(): string
    {
        $groups = Whmcs::groups();
        $rules = \McSec\Rules::all();
        $names = Whmcs::clientNames(array_map(fn ($r) => $r->scope === 'client' ? (int) $r->target : 0, $rules));
        $rows = '';
        foreach ($rules as $r) {
            $who = $r->scope === 'client' ? 'حساب #' . (int) $r->target . ' ' . ($names[(int) $r->target] ?? '') : 'گروه «' . ($groups[(int) $r->target] ?? '#' . (int) $r->target) . '»';
            $ended = (int) $r->ends_at > 0 && (int) $r->ends_at <= Clock::now();
            $rows .= '<tr' . ($ended ? ' class="mcsa-muted"' : '') . '><td>' . self::e($who) . ($r->note !== '' ? '<br><small>' . self::e($r->note) . '</small>' : '') . '</td><td>' . self::e(Text::fa((int) $r->monthly)) . '</td><td>' . self::e((int) $r->max_assets > 0 ? Text::fa((int) $r->max_assets) : '—') . '</td>'
                . '<td>' . self::e((int) $r->discount > 0 ? Text::fa((int) $r->discount) . '٪' : '—') . '</td><td>' . self::e((int) $r->spend_pct < 100 ? Text::fa((int) $r->spend_pct) . '٪ قیمت عادی' : 'عادی') . '</td>'
                . '<td>' . ($r->profiles !== '' ? '<code dir="ltr">' . self::e($r->profiles) . '</code>' : '—') . '</td><td>' . self::e((int) $r->ends_at > 0 ? ($ended ? 'تمام شد: ' : 'تا ') . Text::date((int) $r->ends_at, false) : 'بی‌پایان') . '</td>'
                . '<td>' . (Auth::adminCan('settings') ? self::form('credits', 'disable_rule', '<input type="hidden" name="rule_id" value="' . (int) $r->id . '"><button class="btn btn-default btn-xs">برداشتن</button>', 'این قاعده برداشته شود؟') : '') . '</td></tr>';
        }
        $opts = '<option value="0">—</option>';
        foreach ($groups as $gid => $gn) {
            $opts .= '<option value="' . (int) $gid . '">' . self::e($gn) . '</option>';
        }
        $add = self::form('credits', 'save_rule', '<div class="mcsa-row">'
            . '<div class="mcsa-field"><label for="mcsa-rl-g">گروه مشتری</label><select class="form-control" id="mcsa-rl-g" name="rl_group">' . $opts . '</select></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-c">یا شماره‌ی حساب</label><input class="form-control" id="mcsa-rl-c" name="rl_client" dir="ltr"><small>اگر پر شود، قاعده فقط برای همین حساب است.</small></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-m">اعتبار ماهانه‌ی رایگان <span class="mcsa-i" tabindex="0" role="note" title="اول هر ماه شمسی پر می‌شود و به ماه بعد نمی‌رود. پیش‌فرض: ۰.">?</span></label><input class="form-control" id="mcsa-rl-m" name="rl_monthly" dir="ltr" value="0"></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-a">سقف دارایی <span class="mcsa-i" tabindex="0" role="note" title="۰ یعنی همان سقف پلن یا سقف بی‌پلن. پیش‌فرض: ۰.">?</span></label><input class="form-control" id="mcsa-rl-a" name="rl_assets" dir="ltr" value="0"></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-d">تخفیف بسته‌ها (٪) <span class="mcsa-i" tabindex="0" role="note" title="۰ تا ۹۰. با کد تخفیف جمع نمی‌شود: مشتری بهترینِ یکی را می‌گیرد. پیش‌فرض: ۰.">?</span></label><input class="form-control" id="mcsa-rl-d" name="rl_discount" dir="ltr" value="0"></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-p">هزینه‌ی اسکن (٪ قیمت عادی) <span class="mcsa-i" tabindex="0" role="note" title="۱۰۰ یعنی قیمت عادی، ۵۰ یعنی نصف، ۰ یعنی رایگان. فقط کم می‌کند. پیش‌فرض: ۱۰۰.">?</span></label><input class="form-control" id="mcsa-rl-p" name="rl_spend" dir="ltr" value="100"></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-o">نوع‌های اسکن باز بی‌پلن <span class="mcsa-i" tabindex="0" role="note" title="کلید نوع‌های اسکن با ویرگول، مثل vuln,web. کلیدها در «قیمت و پلن» هستند. پیش‌فرض: هیچ.">?</span></label><input class="form-control" id="mcsa-rl-o" name="rl_profiles" dir="ltr" placeholder="vuln,web"></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-t">مدت (روز) <span class="mcsa-i" tabindex="0" role="note" title="پس از این چند روز قاعده خودکار تمام می‌شود. ۰ یعنی بی‌پایان. پیش‌فرض: ۰.">?</span></label><input class="form-control" id="mcsa-rl-t" name="rl_days" dir="ltr" value="0"></div>'
            . '<div class="mcsa-field"><label for="mcsa-rl-n">یادداشت (فقط مدیر می‌بیند)</label><input class="form-control" id="mcsa-rl-n" name="rl_note" maxlength="160"></div>'
            . '</div><button class="btn btn-primary">ذخیره‌ی قاعده</button>');
        $grant = self::form('credits', 'grant', '<div class="mcsa-row"><div class="mcsa-field"><label>شماره‌ی حساب مشتری</label><input class="form-control" name="grant_client" dir="ltr" required></div>'
            . '<div class="mcsa-field"><label>تعداد اعتبار</label><input class="form-control" name="grant_amount" dir="ltr" required></div>'
            . '<div class="mcsa-field"><label>نوع</label><select class="form-control" name="grant_bucket"><option value="paid">بی‌انقضا</option><option value="monthly">ماهانه (تا آخر ماه)</option></select></div>'
            . '<div class="mcsa-field"><label>شرح (مشتری می‌بیند)</label><input class="form-control" name="grant_note" placeholder="مثلاً جبران قطعی"></div></div><button class="btn btn-primary">افزودن اعتبار</button>', 'این اعتبار افزوده شود؟');
        $ledger = '';
        $last = Db::rows(Db::table('mod_mcsec_ledger')->whereIn('kind', ['grant', 'topup', 'refund', 'group', 'plan', 'code', 'gift', 'invite'])->orderByDesc('id')->limit(40));
        $names = Whmcs::clientNames(array_map(fn ($r) => (int) $r->client_id, $last));
        foreach ($last as $l) {
            $ledger .= '<tr><td>' . self::e(Text::date((int) $l->created_at)) . '</td><td>#' . (int) $l->client_id . ' ' . self::e($names[(int) $l->client_id] ?? '') . '</td><td>' . self::e(Credits::KINDS[$l->kind] ?? $l->kind) . '</td><td dir="ltr">' . (int) $l->delta . '</td><td>' . self::e($l->note) . '</td></tr>';
        }
        return self::guide('<p><strong>قاعده</strong> می‌گوید یک گروه مشتری WHMCS (مثلاً «همکاران» یا «VIP») یا یک حساب خاص چه قیمتی می‌گیرد: اعتبار ماهانه‌ی رایگان، سقف دارایی، تخفیف بسته‌ها، هزینه‌ی کمتر اسکن و نوع‌های اسکن باز بی‌پلن.</p>'
            . '<p>برای هر مشتری <strong>فقط یک قاعده</strong> اثر دارد: قاعده‌ی خود حساب بر قاعده‌ی گروهش مقدم است. قاعده‌ی تازه برای همان گروه یا حساب جای قبلی را می‌گیرد. تخفیف قاعده با کد تخفیف جمع نمی‌شود؛ مشتری بهترینِ یکی را می‌گیرد.</p>'
            . '<p><strong>اعطای تکی:</strong> برای جبران یا هدیه؛ مشتری خبر می‌گیرد و در تراکنش‌هایش می‌بیند.</p>')
            . self::box('قاعده‌های فعال', $rows !== '' ? '<table class="table"><thead><tr><th>برای</th><th>اعتبار ماهانه</th><th>سقف دارایی</th><th>تخفیف بسته</th><th>هزینه‌ی اسکن</th><th>نوع‌های باز</th><th>مدت</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">هنوز قاعده‌ای نیست: همه قیمت عادی می‌گیرند.</p>')
            . self::box('قاعده‌ی تازه', $add) . self::box('افزودن اعتبار به یک حساب', $grant)
            . self::box('آخرین افزوده‌ها و بازگشت‌ها', $ledger !== '' ? '<table class="table"><thead><tr><th>تاریخ</th><th>حساب</th><th>نوع</th><th>مقدار</th><th>شرح</th></tr></thead><tbody>' . $ledger . '</tbody></table>' : '<p class="mcsa-muted">چیزی نیست.</p>');
    }

    /** Campaign codes, and the switches of gifts, invites and auto top-up. */
    private static function codes(): string
    {
        $groups = Whmcs::groups();
        $list = Db::rows(Db::table('mod_mcsec_codes')->whereIn('kind', \McSec\Codes::ADMIN_KINDS)->orderByDesc('id')->limit(100));
        $rows = '';
        foreach ($list as $c) {
            $what = match ((string) $c->kind) {
                'credit' => Text::fa((int) $c->value) . ' اعتبار' . ($c->bucket === 'monthly' ? ' (تا پایان ماه)' : ' (بی‌انقضا)'),
                'discount' => Text::fa((int) $c->value) . '٪ تخفیف بسته',
                default => Text::fa((int) $c->value) . '٪ اعتبار بیشتر',
            };
            $only = (int) $c->client_id > 0 ? 'حساب #' . (int) $c->client_id : ((int) $c->group_id > 0 ? 'گروه «' . ($groups[(int) $c->group_id] ?? '#' . (int) $c->group_id) . '»' : 'همه');
            $ended = (int) $c->enabled !== 1 || ((int) $c->expires_at > 0 && (int) $c->expires_at <= Clock::now());
            $rows .= '<tr' . ($ended ? ' class="mcsa-muted"' : '') . '><td><code dir="ltr">' . self::e($c->code) . '</code>' . ($c->note !== '' ? '<br><small>' . self::e($c->note) . '</small>' : '') . '</td><td>' . self::e($what) . '</td><td>' . self::e($only) . '</td>'
                . '<td>' . self::e(Text::fa((int) $c->used) . ((int) $c->max_uses > 0 ? ' از ' . Text::fa((int) $c->max_uses) : '')) . '</td>'
                . '<td>' . self::e((int) $c->enabled !== 1 ? 'خاموش' : ((int) $c->expires_at > 0 ? ($ended ? 'تمام شد: ' : 'تا ') . Text::date((int) $c->expires_at, false) : 'بی‌پایان')) . '</td>'
                . '<td>' . ((int) $c->enabled === 1 && Auth::adminCan('settings') ? self::form('codes', 'disable_code', '<input type="hidden" name="code_id" value="' . (int) $c->id . '"><button class="btn btn-default btn-xs">خاموش</button>', 'این کد خاموش شود؟') : '') . '</td></tr>';
        }
        $opts = '<option value="0">همه</option>';
        foreach ($groups as $gid => $gn) {
            $opts .= '<option value="' . (int) $gid . '">' . self::e($gn) . '</option>';
        }
        $add = self::form('codes', 'save_code', '<div class="mcsa-row">'
            . '<div class="mcsa-field"><label for="mcsa-cd-k">نوع</label><select class="form-control" id="mcsa-cd-k" name="cd_kind"><option value="bonus">اعتبار بیشتر روی بسته (٪) — درآمد کم نمی‌شود</option><option value="discount">تخفیف بسته (٪)</option><option value="credit">اعتبار رایگان (تعداد)</option></select></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-v">مقدار <span class="mcsa-i" tabindex="0" role="note" title="برای اعتبار رایگان: تعداد اعتبار. برای تخفیف: درصد (۱ تا ۹۰). برای اعتبار بیشتر: درصد (۱ تا ۳۰۰).">?</span></label><input class="form-control" id="mcsa-cd-v" name="cd_value" dir="ltr" required></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-c">کد <span class="mcsa-i" tabindex="0" role="note" title="حروف لاتین بزرگ، رقم و خط تیره، مثل YALDA1405. خالی: خودکار ساخته می‌شود.">?</span></label><input class="form-control" id="mcsa-cd-c" name="cd_code" dir="ltr" maxlength="24" placeholder="YALDA1405"></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-b">اعتبار رایگان تا کی؟ <span class="mcsa-i" tabindex="0" role="note" title="فقط برای نوع «اعتبار رایگان». پیش‌فرض: بی‌انقضا.">?</span></label><select class="form-control" id="mcsa-cd-b" name="cd_bucket"><option value="paid">بی‌انقضا</option><option value="monthly">تا پایان همان ماه شمسی</option></select></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-m">سقف تعداد استفاده <span class="mcsa-i" tabindex="0" role="note" title="چند حساب می‌توانند از این کد استفاده کنند. ۰ یعنی بی‌سقف. هر حساب فقط یک بار. پیش‌فرض: ۰.">?</span></label><input class="form-control" id="mcsa-cd-m" name="cd_max" dir="ltr" value="0"></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-d">مهلت (روز) <span class="mcsa-i" tabindex="0" role="note" title="پس از این چند روز کد دیگر پذیرفته نمی‌شود. ۰ یعنی بی‌پایان. پیش‌فرض: ۰.">?</span></label><input class="form-control" id="mcsa-cd-d" name="cd_days" dir="ltr" value="0"></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-g">فقط برای گروه</label><select class="form-control" id="mcsa-cd-g" name="cd_group">' . $opts . '</select></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-u">فقط برای حساب شماره‌ی</label><input class="form-control" id="mcsa-cd-u" name="cd_client" dir="ltr" placeholder="خالی = همه"></div>'
            . '<div class="mcsa-field"><label for="mcsa-cd-n">یادداشت (فقط مدیر می‌بیند)</label><input class="form-control" id="mcsa-cd-n" name="cd_note" maxlength="160" placeholder="مثلاً کمپین یلدا"></div>'
            . '</div><button class="btn btn-primary">ساختن کد</button>');
        $now = Clock::now();
        $stat = [
            'هدیه‌های فروخته‌شده' => Db::table('mod_mcsec_codes')->where('kind', 'gift')->count(),
            'هدیه‌ی منتظر استفاده' => Db::table('mod_mcsec_codes')->where('kind', 'gift')->where('used', 0)->count(),
            'دعوت‌شده‌ها (۳۰ روز)' => Db::table('mod_mcsec_accounts')->where('invited_at', '>', $now - 30 * 86400)->count(),
            'جایزه‌ی دعوت (۳۰ روز)' => (int) Db::table('mod_mcsec_ledger')->where('kind', 'invite')->where('created_at', '>', $now - 30 * 86400)->sum('delta'),
            'اعتبار داده‌شده با کد (۳۰ روز)' => (int) Db::table('mod_mcsec_ledger')->where('kind', 'code')->where('created_at', '>', $now - 30 * 86400)->sum('delta'),
            'حساب با شارژ خودکار' => Db::table('mod_mcsec_accounts')->where('auto_pack', '!=', '')->count(),
        ];
        $kpis = '<div class="mcsa-kpis">';
        foreach ($stat as $l => $v) {
            $kpis .= '<div><span>' . self::e($l) . '</span><strong>' . self::e(Text::fa((int) $v)) . '</strong></div>';
        }
        $kpis .= '</div>';
        return self::guide('<p>مشتری فقط <strong>یک جا</strong> کد وارد می‌کند: کادر «کد دارید؟» در صفحه‌ی اعتبار. کد کمپین، کد هدیه و کد دعوت همه همان‌جا پذیرفته می‌شوند.</p>'
            . '<ul><li><strong>اعتبار بیشتر روی بسته:</strong> همان قیمت، اعتبار بیشتر. پیشنهاد ما برای کمپین‌ها، چون درآمد کم نمی‌شود.</li><li><strong>تخفیف بسته:</strong> درصدی از قیمت بسته‌ی بعدی کم می‌شود.</li><li><strong>اعتبار رایگان:</strong> همان لحظه به کیف می‌آید.</li></ul>'
            . '<p>هر کد برای هر حساب یک بار کار می‌کند. تخفیف‌ها جمع نمی‌شوند: بین قاعده‌ی حساب و کد، بهترینِ یکی. کد تخفیف <strong>پلن‌ها</strong> را در Promotions خود WHMCS بسازید و پورسانت نقدی را با Affiliates.</p>'
            . '<p>کدهای هدیه و دعوت را سامانه خودش می‌سازد؛ این‌جا فقط روشن و خاموش می‌شوند.</p>')
            . $kpis . self::box('کد تازه', $add)
            . self::box('کدهای کمپین', $rows !== '' ? '<table class="table"><thead><tr><th>کد</th><th>اثر</th><th>برای</th><th>استفاده</th><th>مهلت</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">هنوز کدی نساخته‌اید.</p>')
            . self::box('هدیه، دعوت و شارژ خودکار', self::form('codes', 'save_settings', self::fields('billing') . '<button class="btn btn-primary">ذخیره</button>'));
    }

    /** «درآمد و مصرف»: what was sold and what was used, in 30-day steps. Reading only; every number is a sum from our own tables. */
    private static function revenue(): string
    {
        $now = Clock::now();
        $step = 30 * 86400;
        $period = function (int $i) use ($now, $step): array {
            [$from, $to] = [$now - ($i + 1) * $step, $now - $i * $step];
            $paid = Db::table('mod_mcsec_topups')->where('status', 'paid')->where('paid_at', '>', $from)->where('paid_at', '<=', $to);
            $led = fn (string $kind) => (int) Db::table('mod_mcsec_ledger')->where('kind', $kind)->where('created_at', '>', $from)->where('created_at', '<=', $to)->sum('delta');
            $manual = Db::table('mod_mcsec_requests')->where('kind', 'manual')->where('accepted_at', '>', $from)->where('accepted_at', '<=', $to);
            return ['from' => $from, 'to' => $to, 'invoices' => (int) (clone $paid)->count(), 'amount' => (float) (clone $paid)->sum('amount'), 'sold' => (int) (clone $paid)->sum('credits'),
                'spent' => -$led('spend'), 'refunded' => $led('refund'), 'manual' => (int) (clone $manual)->count(), 'manual_amount' => (float) (clone $manual)->sum('amount')];
        };
        $p = array_map($period, range(0, 5));
        $delta = $p[1]['amount'] > 0 ? (int) round(100 * ($p[0]['amount'] - $p[1]['amount']) / $p[1]['amount']) : null;
        $pending = Db::table('mod_mcsec_topups')->where('status', 'pending')->where('created_at', '>', $now - $step);
        $k = [
            'فروش بسته، ۳۰ روز' => Text::money($p[0]['amount']) . ($delta !== null ? ' (' . ($delta >= 0 ? '+' : '') . Text::fa($delta) . '٪)' : ''),
            'فاکتور پرداخت‌شده، ۳۰ روز' => Text::fa($p[0]['invoices']),
            'اعتبار فروخته / مصرف‌شده' => Text::fa($p[0]['sold']) . ' / ' . Text::fa($p[0]['spent']),
            'اعتبار برگشتی، ۳۰ روز' => Text::fa($p[0]['refunded']),
            'فاکتور باز بسته‌ها' => Text::fa((int) (clone $pending)->count()) . ' — ' . Text::money((float) (clone $pending)->sum('amount')),
            'اعتبار خریده‌ی مصرف‌نشده' => Text::fa((int) Db::table('mod_mcsec_wallets')->sum('paid')),
        ];
        $kpis = '<div class="mcsa-kpis">';
        foreach ($k as $l => $v) {
            $kpis .= '<div><span>' . self::e($l) . '</span><strong>' . self::e($v) . '</strong></div>';
        }
        $kpis .= '</div>';
        $rows = '';
        foreach ($p as $x) {
            $rows .= '<tr><td>' . self::e(Text::date($x['from'], false)) . ' تا ' . self::e(Text::date($x['to'], false)) . '</td><td>' . self::e(Text::fa($x['invoices'])) . '</td><td>' . self::e(Text::money($x['amount'])) . '</td><td>' . self::e(Text::fa($x['sold']))
                . '</td><td>' . self::e(Text::fa($x['spent'])) . '</td><td>' . self::e(Text::fa($x['refunded'])) . '</td><td>' . self::e(Text::fa($x['manual'])) . ($x['manual_amount'] > 0 ? ' — ' . self::e(Text::money($x['manual_amount'])) : '') . '</td></tr>';
        }
        $types = '';
        foreach (Db::rows(Db::table('mod_mcsec_scans')->where('queued_at', '>', $now - $step)->selectRaw('profile, COUNT(*) AS n, SUM(credits) AS c')->groupBy('profile')->orderByDesc('c')->limit(15)) as $t) {
            $types .= '<tr><td>' . self::e(\McSec\Catalog::label((string) $t->profile)) . '</td><td>' . self::e(Text::fa((int) $t->n)) . '</td><td>' . self::e(Text::fa((int) $t->c)) . '</td></tr>';
        }
        $top = Db::rows(Db::table('mod_mcsec_topups')->where('status', 'paid')->where('paid_at', '>', $now - 3 * $step)->selectRaw('client_id, COUNT(*) AS n, SUM(amount) AS a, SUM(credits) AS c')->groupBy('client_id')->orderByDesc('a')->limit(10));
        $names = Whmcs::clientNames(array_map(fn ($x) => (int) $x->client_id, $top));
        $buyers = '';
        foreach ($top as $x) {
            $buyers .= '<tr><td><a href="clientssummary.php?userid=' . (int) $x->client_id . '">#' . (int) $x->client_id . ' ' . self::e($names[(int) $x->client_id] ?? '') . '</a></td><td>' . self::e(Text::fa((int) $x->n)) . '</td><td>' . self::e(Text::money((float) $x->a)) . '</td><td>' . self::e(Text::fa((int) $x->c)) . '</td></tr>';
        }
        $none = '<p class="mcsa-muted">در این بازه چیزی نیست.</p>';
        return self::guide('<p>این صفحه فقط می‌خواند: فروش بسته‌های اعتبار (فاکتورهای پرداخت‌شده‌ی WHMCS که این ماژول ساخته)، اعتباری که فروخته و مصرف شده، و تست‌های دستی پذیرفته‌شده. هر ردیف جدول یک بازه‌ی ۳۰ روزه است، از تازه‌ترین.</p>'
            . '<ul><li><strong>اعتبار خریده‌ی مصرف‌نشده</strong> بدهی شماست: اعتباری که پولش گرفته شده و هنوز اسکنی با آن اجرا نشده.</li><li>درآمد پلن‌ها (محصول‌های WHMCS) این‌جا نیست؛ آن را در گزارش‌های خود WHMCS ببینید.</li><li>مبلغ‌ها به ارز پیش‌فرض WHMCS است.</li></ul>')
            . $kpis . self::box('شش بازه‌ی ۳۰ روزه', '<table class="table"><thead><tr><th>بازه</th><th>فاکتور پرداخت‌شده</th><th>مبلغ</th><th>اعتبار فروخته</th><th>اعتبار مصرف‌شده</th><th>اعتبار برگشتی</th><th>تست دستی پذیرفته</th></tr></thead><tbody>' . $rows . '</tbody></table>')
            . self::box('مصرف بر اساس نوع اسکن (۳۰ روز)', $types !== '' ? '<table class="table"><thead><tr><th>نوع اسکن</th><th>اسکن</th><th>اعتبار</th></tr></thead><tbody>' . $types . '</tbody></table>' : $none)
            . self::box('پرخریدترین حساب‌ها (۹۰ روز)', $buyers !== '' ? '<table class="table"><thead><tr><th>حساب</th><th>خرید</th><th>مبلغ</th><th>اعتبار</th></tr></thead><tbody>' . $buyers . '</tbody></table>' : $none);
    }

    private static function assets(): string
    {
        $q = trim(Text::toAscii((string) ($_GET['q'] ?? '')));
        $query = Db::table('mod_mcsec_assets')->where('status', '!=', 'removed');
        if ($q !== '') {
            ctype_digit($q) ? $query->where('client_id', (int) $q) : $query->where('value', 'like', '%' . str_replace(['%', '_'], ['\\%', '\\_'], mb_substr($q, 0, 80)) . '%');
        } else {
            $query->whereIn('status', ['pending', 'lapsed']);
        }
        $list = Db::rows($query->orderByDesc('id')->limit(100));
        $names = Whmcs::clientNames(array_map(fn ($a) => (int) $a->client_id, $list));
        $rows = '';
        foreach ($list as $a) {
            $approve = $a->status !== 'verified' && Auth::adminCan('ops') ? self::form('assets', 'approve_asset', '<input type="hidden" name="asset_id" value="' . (int) $a->id . '"><input class="form-control input-sm" name="approve_note" placeholder="دلیل (مثلاً مدرک در تیکت ۱۲۳)" style="max-width:220px;display:inline-block">'
                . ' <button class="btn btn-default btn-sm">تأیید دستی</button>', 'مالکیت این دارایی را دستی تأیید می‌کنید؟') : '';
            $rows .= '<tr><td dir="ltr">' . self::e($a->value) . '</td><td><a href="clientssummary.php?userid=' . (int) $a->client_id . '">#' . (int) $a->client_id . ' ' . self::e($names[(int) $a->client_id] ?? '') . '</a></td>'
                . '<td>' . self::e(\McSec\Assets::STATUS[$a->status] ?? $a->status) . ($a->method !== '' ? ' (' . self::e(Verify::METHODS[$a->method] ?? $a->method) . ')' : '') . '</td><td><small>' . self::e($a->check_note) . '</small></td><td>' . $approve . '</td></tr>';
        }
        return self::guide('<p>بی‌جستجو، دارایی‌های در انتظار تأیید و منقضی دیده می‌شوند. با شماره‌ی حساب یا بخشی از دامنه جستجو کنید.</p><p><strong>تأیید دستی</strong> فقط وقتی که مالکیت را با مدرک (مثلاً تیکت با نامه‌ی رسمی یا دسترسی سرور) سنجیده‌اید؛ دلیلش در دفتر ثبت می‌شود. دارایی‌های ممنوع در «تنظیمات» (فهرست ممنوع) هستند.</p>')
            . '<form method="get" class="mcsa-search"><input type="hidden" name="module" value="mcsec"><input type="hidden" name="mcsa" value="assets"><input class="form-control" name="q" value="' . self::e($q) . '" placeholder="شماره‌ی حساب یا دامنه" dir="ltr"><button class="btn btn-default">جستجو</button></form>'
            . self::box($q !== '' ? 'نتیجه‌ی جستجو' : 'در انتظار تأیید یا منقضی', $rows !== '' ? '<table class="table"><thead><tr><th>دارایی</th><th>حساب</th><th>وضعیت</th><th>آخرین بررسی</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">چیزی نیست.</p>');
    }

    /** Scans of the last week that failed or finished incomplete, each with a link to its journal. */
    private static function attention(int $limit): string
    {
        $list = Settings::bool('ops_alerts') ? \McSec\ScanLog::attention(7, $limit) : [];
        if (!$list) {
            return '';
        }
        $rows = '';
        foreach ($list as $s) {
            $why = $s->status === 'failed' ? (string) $s->error . ' ' . (string) $s->error_ref : (string) (Scans::summary($s)['partial'] ?? '');
            $rows .= '<tr><td><a href="' . self::e(self::url('scans', '&scan=' . (int) $s->id)) . '">اسکن ' . self::e(Text::fa((int) $s->id)) . '</a></td><td>#' . (int) $s->client_id . '</td><td dir="ltr">' . self::e($s->value) . '</td><td>' . self::e(Catalog::label((string) $s->profile)) . '</td>'
                . '<td><span class="mcsa-tag ' . ($s->status === 'failed' ? 'mcsa-tag-fix' : 'mcsa-tag-ops') . '">' . ($s->status === 'failed' ? 'ناموفق' : 'ناقص') . '</span> ' . self::e(mb_substr($why, 0, 140)) . '</td><td>' . self::e(Text::ago((int) $s->finished_at)) . '</td></tr>';
        }
        return self::box('اسکن‌های نیازمند بررسی (۷ روز)', '<table class="table"><thead><tr><th>اسکن</th><th>حساب</th><th>دارایی</th><th>نوع</th><th>چه شد</th><th>زمان</th></tr></thead><tbody>' . $rows . '</tbody></table>',
            'اسکنی که ناموفق شد، یا تمام شد ولی مدرکی از کار واقعی موتور نبود (ارزیابی ناقص). روی شماره‌ی اسکن بزنید تا ببینید ماژول از موتور چه خواست و چه جواب گرفت.');
    }

    /** Everything known about one scan: where it lives in the engine, the proof of work, and its journal. */
    private static function scanDetail(int $id): string
    {
        $s = Db::table('mod_mcsec_scans as s')->join('mod_mcsec_assets as a', 'a.id', '=', 's.asset_id')->where('s.id', $id)->select(['s.*', 'a.value'])->first();
        $back = '<p><a href="' . self::e(self::url('scans')) . '">→ بازگشت به صف اسکن</a></p>';
        if (!$s) {
            return $back . '<div class="alert alert-danger">اسکنی با این شماره پیدا نشد.</div>';
        }
        $sum = Scans::summary($s);
        $ev = (array) ($sum['evidence'] ?? []);
        $meta = json_decode((string) $s->backend_meta, true) ?: [];
        $acc = \McSec\Accounts::get((int) $s->client_id);
        $dl = fn (array $rows) => '<table class="table mcsa-facts"><tbody>' . implode('', array_map(fn ($k, $x) => $x === '' ? '' : '<tr><th>' . self::e($k) . '</th><td>' . $x . '</td></tr>', array_keys($rows), $rows)) . '</tbody></table>';
        $ltr = fn ($x) => (string) $x === '' ? '' : '<bdi dir="ltr">' . self::e($x) . '</bdi>';
        $t = fn ($ts) => (int) $ts > 0 ? self::e(Text::date((int) $ts)) : '';
        $partial = (string) ($sum['partial'] ?? '');
        $state = self::e(Scans::STATUS[(string) $s->status] ?? (string) $s->status) . ($partial !== '' ? ' <span class="mcsa-tag mcsa-tag-ops">ارزیابی ناقص</span>' : '') . ' — ' . self::e((string) $s->stage);
        $out = $back . ($partial !== '' ? '<div class="alert alert-warning"><strong>چرا ناقص؟</strong> ' . self::e($partial) . '</div>' : '')
            . ($s->status === 'failed' ? '<div class="alert alert-danger"><strong>چرا ناموفق؟</strong> ' . self::e((string) $s->error) . ((string) $s->error_ref !== '' ? ' — کد پیگیری: ' . $ltr($s->error_ref) : '') . '</div>' : '')
            . self::box('اسکن شماره‌ی ' . Text::fa((int) $s->id), $dl(['حساب' => '<a href="clientssummary.php?userid=' . (int) $s->client_id . '">#' . (int) $s->client_id . ' ' . self::e(Whmcs::clientName((int) $s->client_id)) . '</a>',
                'دارایی' => $ltr($s->value), 'نوع اسکن' => self::e(Catalog::label((string) $s->profile, (string) $s->profile)) . ' (' . self::e(Catalog::engineLabel((string) $s->engine)) . ')', 'وضعیت' => $state,
                'در صف' => $t($s->queued_at), 'شروع' => $t($s->started_at), 'پایان' => $t($s->finished_at), 'اعتبار' => self::e(Text::fa((int) $s->credits)) . (isset($sum['refunded']) ? ' — ' . self::e(Text::fa((int) $sum['refunded'])) . ' برگشت' : ''),
                'نتیجه' => isset($sum['seen']) ? self::e(Text::fa((int) $sum['seen']) . ' یافته دیده شد، ' . Text::fa((int) ($sum['new'] ?? 0)) . ' تازه، ' . Text::fa((int) ($sum['fixed'] ?? 0)) . ' رفع‌شده؛ ' . Text::fa((int) ($sum['surface_seen'] ?? 0)) . ' مورد سطح حمله') : '']));
        if ($s->engine === 'oasm') {
            $ws = (string) ($ev['workspace'] ?? $meta['ws'] ?? ($acc->oasm_workspace ?? ''));
            $jobs = '';
            foreach ((array) ($ev['jobs_by_status'] ?? []) as $st => $n) {
                $jobs .= self::e(Text::fa((int) $n)) . ' ' . self::e($st) . '، ';
            }
            $out .= self::box('این اسکن در OASM کجاست؟', $dl(['فضای کار' => $ltr('mcsec-c' . (int) $s->client_id) . ' ' . $ltr($ws), 'کاربر مالک فضای کار' => $ltr((string) ($acc->oasm_user ?? '')),
                'هدف (target)' => $ltr((string) $s->backend_ref), 'پروژه (pipeline)' => $ltr((string) ($ev['project'] ?? $meta['project'] ?? '')), 'اجرا (run)' => $ltr((string) ($ev['run'] ?? $meta['run'] ?? '')),
                'ابزارها' => $ltr(implode(' → ', (array) ($meta['tools'] ?? []))), 'وضعیت اجرا در OASM' => $ltr((string) ($ev['run_status'] ?? '')),
                'کارهای اجراشده (jobs)' => array_key_exists('jobs', $ev) ? ($ev['jobs'] === null ? 'خوانده نشد' : self::e(Text::fa((int) $ev['jobs'])) . ($jobs !== '' ? ' (' . rtrim($jobs, '، ') . ')' : '')) : '',
                'آنچه اسکنر دید' => array_key_exists('services', $ev) ? self::e(Text::fa((int) $ev['hosts']) . ' میزبان، ' . Text::fa((int) $ev['services']) . ' سرویس (درگاه باز)') : '']),
                'MC-Sec برای هر حساب مشتری یک کاربر و یک فضای کار جدا در OASM می‌سازد. این فضای کار مال همان کاربر است، پس وقتی با حساب مدیر وارد کنسول OASM می‌شوید در فهرست فضاهای کار خودتان دیده نمی‌شود؛ در بخش مدیریت (Admin › Workspaces) با نام بالا پیدا می‌شود.');
        }
        $steps = ['queue' => 'صف', 'start' => 'شروع', 'poll' => 'پیگیری', 'collect' => 'خواندن نتیجه', 'fail' => 'ناموفق', 'alert' => 'هشدار مدیر'];
        $rows = '';
        foreach (\McSec\ScanLog::of((int) $s->id) as $e) {
            $d = json_decode((string) $e->detail, true);
            $calls = '';
            foreach ((array) ($d['calls'] ?? []) as $c) {
                $bad = (int) $c['status'] === 0 || (int) $c['status'] >= 400;
                $calls .= '<tr' . ($bad ? ' class="lvl-error"' : '') . '><td dir="ltr">' . self::e($c['m']) . '</td><td dir="ltr">' . self::e($c['path']) . '</td><td dir="ltr">' . self::e((string) $c['status']) . '</td><td dir="ltr">' . self::e((string) $c['ms']) . ' ms</td><td dir="ltr">' . self::e((string) ($c['answer'] ?? '')) . '</td></tr>';
            }
            unset($d['calls']);
            $more = ($calls !== '' ? '<details><summary>' . self::e(Text::fa(substr_count($calls, '<tr')) . ' درخواست به موتور') . '</summary><table class="table"><tbody>' . $calls . '</tbody></table></details>' : '')
                . ($d ? '<details><summary>جزئیات</summary><pre dir="ltr">' . self::e(json_encode($d, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre></details>' : '');
            $lvl = in_array((string) $e->level, ['error', 'warn'], true) ? ' class="lvl-' . ($e->level === 'error' ? 'error' : 'warn') . '"' : '';
            $rows .= '<tr' . $lvl . '><td>' . self::e(Text::date((int) $e->created_at)) . '</td><td>' . self::e($steps[(string) $e->step] ?? (string) $e->step) . '</td><td>' . self::e((string) $e->message) . $more . '</td></tr>';
        }
        return $out . self::box('لاگ این اسکن', $rows !== '' ? '<table class="table mcsa-log"><thead><tr><th>زمان</th><th>گام</th><th>چه شد</th></tr></thead><tbody>' . $rows . '</tbody></table>'
            : '<p class="mcsa-muted">برای این اسکن لاگی نیست (پیش از نسخه‌ی ۰٫۱۲٫۰ گرفته شده یا لاگش پس از ' . self::e(Text::fa(\McSec\ScanLog::KEEP_DAYS)) . ' روز پاک شده است).</p>',
            'هر ردیف یک گام است: آنچه ماژول از موتور خواست، کد پاسخ هر درخواست و زمانش. بدنه‌ی درخواست‌ها و هیچ رمزی این‌جا نگه داشته نمی‌شود.');
    }

    private static function scans(): string
    {
        $one = (int) Text::toAscii((string) ($_GET['scan'] ?? '0'));
        if ($one > 0) {
            return self::scanDetail($one);
        }
        $out = self::guide('<p>صف و اسکن‌های در حال اجرا و ناموفق. «توقف» اعتبار را برمی‌گرداند؛ «دوباره» برای اسکن ناموفق یک اسکن رایگان تازه می‌سازد. علت خطا با کد پیگیری در «گزارش فنی» است.</p>');
        $out .= '<form method="get" action="addonmodules.php" class="mcsa-search"><input type="hidden" name="module" value="mcsec"><input type="hidden" name="mcsa" value="scans">'
            . '<input class="form-control" name="scan" dir="ltr" inputmode="numeric" placeholder="شماره‌ی اسکن" aria-label="شماره‌ی اسکن"><button class="btn btn-default">دیدن لاگ اسکن</button></form>';
        $out .= self::attention(20);
        foreach (['running' => 'در حال اجرا', 'queued' => 'در صف', 'failed' => 'ناموفق (۷ روز)', 'completed' => 'تمام‌شده (۳۰ تای آخر)'] as $st => $label) {
            $q = Db::table('mod_mcsec_scans as s')->join('mod_mcsec_assets as a', 'a.id', '=', 's.asset_id')->where('s.status', $st);
            if ($st === 'failed') {
                $q->where('s.finished_at', '>', Clock::now() - 7 * 86400);
            }
            $list = Db::rows($q->select(['s.*', 'a.value'])->orderByDesc('s.id')->limit($st === 'completed' ? 30 : 60));
            $rows = '';
            foreach ($list as $s) {
                $btn = $st === 'completed' ? '' : (Auth::adminCan('ops') ? ($st === 'failed'
                    ? self::form('scans', 'retry_scan', '<input type="hidden" name="scan_id" value="' . (int) $s->id . '"><button class="btn btn-default btn-sm">دوباره</button>')
                    : self::form('scans', 'cancel_scan', '<input type="hidden" name="scan_id" value="' . (int) $s->id . '"><button class="btn btn-default btn-sm">توقف</button>', 'این اسکن متوقف شود؟')) : '');
                $sm = $st === 'completed' ? Scans::summary($s) : [];
                $rows .= '<tr><td><a href="' . self::e(self::url('scans', '&scan=' . (int) $s->id)) . '" title="لاگ و جزئیات این اسکن">' . (int) $s->id . '</a></td><td>#' . (int) $s->client_id . '</td><td dir="ltr">' . self::e($s->value) . '</td><td>' . self::e(Catalog::label((string) ($s->profile))) . ' <small>(' . self::e($s->engine) . ')</small></td>'
                    . '<td>' . ($st === 'completed' && isset($sm['partial']) ? '<span class="mcsa-tag mcsa-tag-ops">ناقص</span> ' : '') . self::e($st === 'failed' ? $s->error . ' ' . $s->error_ref : ($st === 'completed' ? Text::fa((int) ($sm['seen'] ?? 0)) . ' یافته' : Text::fa((int) $s->progress) . '٪ ' . $s->stage)) . '</td><td>' . self::e(Text::ago((int) ($s->started_at ?: $s->queued_at))) . '</td><td>' . $btn . '</td></tr>';
            }
            $out .= self::box($label . ' (' . Text::fa(count($list)) . ')', $rows !== '' ? '<table class="table"><thead><tr><th>#</th><th>حساب</th><th>دارایی</th><th>اسکن</th><th>وضعیت</th><th>زمان</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">چیزی نیست.</p>');
        }
        return $out;
    }

    /**
     * «درخواست‌های کارشناس»: every request a customer sent (question, paid fix, manual test) with its ticket. Anyone
     * who can open the panel sees them; the ops tier writes a price, moves the state and cancels (credits go back).
     */
    private static function requests(): string
    {
        $filter = in_array($_GET['show'] ?? '', ['open', 'closed', 'all'], true) ? (string) $_GET['show'] : 'open';
        $list = \McSec\Requests::all($filter, 150);
        $names = Whmcs::clientNames(array_map(fn ($r) => (int) $r->client_id, $list));
        $assets = [];
        foreach (array_chunk(array_values(array_unique(array_filter(array_map(fn ($r) => (int) $r->asset_id, $list)))), 500) as $chunk) {
            foreach (Db::rows(Db::table('mod_mcsec_assets')->whereIn('id', $chunk)->select(['id', 'value'])) as $a) {
                $assets[(int) $a->id] = (string) $a->value;
            }
        }
        $can = Auth::adminCan('ops');
        $tone = ['new' => 'fix', 'quoted' => 'chg', 'paying' => 'chg', 'invoiced' => 'chg', 'accepted' => 'fix', 'working' => 'ops', 'done' => 'ok'];
        $rows = '';
        foreach ($list as $r) {
            $id = (int) $r->id;
            $st = (string) $r->status;
            $cur = Whmcs::currency((int) (Whmcs::client((int) $r->client_id)->currency ?? 0));
            $money = (float) $r->amount > 0 ? Text::money((float) $r->amount, $cur) : '';
            $price = (int) $r->credits > 0 ? Text::fa((int) $r->credits) . ' اعتبار' . ($money !== '' ? ' / ' . $money : '') : ($r->kind === 'manual' ? 'اعلام نشده' : 'رایگان');
            $paid = match ((string) $r->paid_with) {
                'credits' => 'از اعتبار' . ((int) $r->refunded > 0 ? ' (' . Text::fa((int) $r->refunded) . ' برگشت)' : ''),
                'invoice' => 'با فاکتور',
                default => $st === 'invoiced' ? 'منتظر فاکتور' : '—',
            };
            $acts = '';
            if ($can) {
                if ($r->kind === 'manual' && in_array($st, ['new', 'quoted'], true)) {
                    $acts .= self::form('requests', 'request_quote', '<input type="hidden" name="id" value="' . $id . '"><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 16px">'
                        . '<div class="mcsa-field"><label for="mcsa-qc-' . $id . '">قیمت (اعتبار)</label><input class="form-control" id="mcsa-qc-' . $id . '" name="credits" dir="ltr" inputmode="numeric" value="' . ((int) $r->credits ?: '') . '" required><small>اگر مشتری این‌قدر اعتبار داشته باشد، با تأییدش کم می‌شود.</small></div>'
                        . '<div class="mcsa-field"><label for="mcsa-qa-' . $id . '">مبلغ فاکتور (' . self::e((string) ($cur->code ?? '')) . ')</label><input class="form-control" id="mcsa-qa-' . $id . '" name="amount" dir="ltr" inputmode="decimal" value="' . ((float) $r->amount > 0 ? self::e(rtrim(rtrim(number_format((float) $r->amount, 2, '.', ''), '0'), '.')) : '') . '"><small>اگر اعتبار مشتری کافی نباشد، با تأییدش فاکتوری به این مبلغ ساخته می‌شود. خالی یا ۰: فقط با اعتبار.</small></div></div>'
                        . '<div class="mcsa-field"><label for="mcsa-qn-' . $id . '">این قیمت چه چیزی را پوشش می‌دهد؟ (مشتری می‌بیند)</label><textarea class="form-control" id="mcsa-qn-' . $id . '" name="note" rows="3" dir="auto">' . self::e((string) $r->quote_note) . '</textarea></div>'
                        . '<button class="btn btn-primary">' . ($st === 'quoted' ? 'اعلام دوباره‌ی قیمت' : 'اعلام قیمت به مشتری') . '</button>');
                }
                $btn = fn (string $to, string $label, string $confirm = '') => self::form('requests', 'request_status', '<input type="hidden" name="id" value="' . $id . '"><input type="hidden" name="to" value="' . $to . '"><button class="btn btn-default btn-sm">' . self::e($label) . '</button>', $confirm);
                $started = $r->kind === 'manual' ? in_array($st, ['accepted'], true) : in_array($st, ['new', 'accepted'], true);
                $acts .= '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">' . ($started ? $btn('working', 'شروع کار') : '')
                    . ($started || $st === 'working' ? $btn('done', 'انجام شد') : '')
                    . (in_array($st, ['new', 'quoted', 'invoiced', 'accepted', 'working'], true) ? $btn('cancelled', 'لغو', 'این درخواست لغو شود؟' . ((string) $r->paid_with === 'credits' ? ' اعتبار مشتری برمی‌گردد.' : ((string) $r->paid_with === 'invoice' ? ' مبلغ فاکتور خودکار برنمی‌گردد؛ در WHMCS رسیدگی کنید.' : ''))) : '') . '</div>';
            }
            $ticket = (int) $r->ticket_id > 0 ? '<a href="supporttickets.php?action=view&amp;id=' . (int) $r->ticket_id . '" target="_blank" rel="noopener" dir="ltr">#' . self::e((string) $r->ticket_tid) . '</a>' : '—';
            $rows .= '<tr><td>' . self::e(Text::fa($id)) . '</td><td>' . self::e(\McSec\Requests::KINDS[(string) $r->kind] ?? $r->kind) . '<br><small class="mcsa-muted">' . self::e(\McSec\Support::TOPICS[(string) $r->topic] ?? '') . '</small></td>'
                . '<td><a href="clientssummary.php?userid=' . (int) $r->client_id . '">' . self::e($names[(int) $r->client_id] ?? '#' . (int) $r->client_id) . '</a>' . (isset($assets[(int) $r->asset_id]) ? '<br><small dir="ltr">' . self::e($assets[(int) $r->asset_id]) . '</small>' : '') . '</td>'
                . '<td><span class="mcsa-tag' . (isset($tone[$st]) ? ' mcsa-tag-' . $tone[$st] : '') . '">' . self::e(\McSec\Requests::STATUS[$st === 'paying' ? 'quoted' : $st] ?? $st) . '</span></td><td>' . self::e($price) . '<br><small class="mcsa-muted">' . self::e($paid) . '</small></td>'
                . '<td>' . $ticket . '</td><td>' . self::e(Text::date((int) $r->created_at)) . '</td></tr>'
                . '<tr><td colspan="7"><details' . (in_array($st, ['new', 'accepted'], true) ? ' open' : '') . '><summary>متن درخواست و کارها</summary><p dir="auto" style="white-space:pre-wrap">' . self::e((string) $r->text) . '</p>'
                . ((int) $r->scan_id > 0 ? '<p><a href="' . self::e(self::url('scans', '&scan=' . (int) $r->scan_id)) . '">لاگ اسکن ' . self::e(Text::fa((int) $r->scan_id)) . '</a></p>' : '')
                . ((int) $r->invoice_id > 0 ? '<p><a href="invoices.php?action=edit&amp;id=' . (int) $r->invoice_id . '" target="_blank" rel="noopener">فاکتور ' . self::e(Text::fa((int) $r->invoice_id)) . '</a></p>' : '')
                . (trim((string) $r->admin_note) !== '' ? '<p class="mcsa-muted" dir="auto">' . self::e((string) $r->admin_note) . '</p>' : '') . $acts . '</details></td></tr>';
        }
        $tabs = '';
        foreach (['open' => 'باز', 'closed' => 'بسته', 'all' => 'همه'] as $k => $l) {
            $tabs .= '<a class="btn btn-' . ($k === $filter ? 'primary' : 'default') . ' btn-sm" href="' . self::e(self::url('requests', '&show=' . $k)) . '">' . $l . '</a> ';
        }
        $on = array_filter(['پرسش رایگان' => Settings::bool('support_requests'), 'بررسی و رفع عیب (' . Text::fa(Settings::int('expert_fix_cost')) . ' اعتبار)' => Settings::bool('support_requests') && Settings::bool('expert_fix'), 'تست دستی با اعلام قیمت' => Settings::bool('support_requests') && Settings::bool('expert_manual')]);
        return self::guide('<p>هر درخواستی که مشتری از صفحه‌ی «کمک کارشناس» می‌فرستد این‌جا می‌آید و یک تیکت WHMCS هم برایش ساخته می‌شود؛ گفت‌وگو با مشتری در همان تیکت است و وضعیت و پول این‌جا.</p>'
                . '<ul><li><strong>پرسش و راهنمایی:</strong> رایگان. پس از پاسخ در تیکت، «انجام شد» را بزنید.</li>'
                . '<li><strong>بررسی و رفع عیب:</strong> هزینه‌ی ثابت هنگام ثبت از اعتبار مشتری کم شده است. اگر نمی‌شود انجامش داد «لغو» بزنید تا اعتبار برگردد.</li>'
                . '<li><strong>تست دستی:</strong> اول قیمت را اعلام کنید (اعتبار، و مبلغ فاکتور برای مشتری‌ای که اعتبار کافی ندارد). مشتری در پنل خودش تأیید یا رد می‌کند. با تأیید، اعتبار کم یا فاکتور ساخته می‌شود؛ پس از پرداخت، وضعیت «تأیید و پرداخت شد» می‌شود و می‌توانید «شروع کار» بزنید.</li></ul>'
                . '<p>دیدن این صفحه برای هر مدیری که پنل MC-Sec را می‌بیند ممکن است؛ اعلام قیمت، تغییر وضعیت و لغو سطح «ops» می‌خواهد (تنظیم «سطح نقش‌های مدیر»). روشن و خاموش کردن هر نوع درخواست و هزینه‌ی رفع عیب در «تنظیمات» ← «پشتیبانی» است.</p>')
            . '<p class="mcsa-muted">' . ($on ? 'روشن برای مشتری: ' . self::e(implode('، ', array_keys($on))) . '.' : 'درخواست کارشناس برای مشتری خاموش است.') . (!$can ? ' نقش شما فقط اجازه‌ی دیدن دارد.' : '') . '</p><p>' . $tabs . '</p>'
            . self::box('درخواست‌ها', $rows !== '' ? '<table class="table"><thead><tr><th>#</th><th>نوع</th><th>حساب و دارایی</th><th>وضعیت</th><th>قیمت و پرداخت</th><th>تیکت</th><th>زمان</th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">درخواستی در این فهرست نیست.</p>');
    }

    /** «قالب گزارش»: the look of the PDF report (logo, name, colours, font, parts), with a sample to look at. */
    private static function report(): string
    {
        $upload = function (string $key, string $label, string $accept, string $help): string {
            $info = \McSec\Blobs::info($key);
            $has = $info ? '<p class="mcsa-muted">ذخیره‌شده: ' . self::e(Text::fa((int) ceil($info['size'] / 1024)) . ' کیلوبایت، ' . Text::date($info['updated_at'])) . '</p>' : '<p class="mcsa-muted">چیزی بارگذاری نشده است.</p>';
            $form = '<form method="post" enctype="multipart/form-data" action="' . self::e(self::url('report')) . '"><input type="hidden" name="mcsa_csrf" value="' . self::e(Auth::csrf()) . '"><input type="hidden" name="mcsa_act" value="upload_blob">'
                . '<input type="hidden" name="blob" value="' . self::e($key) . '"><div class="mcsa-field"><label for="mcsa-up-' . self::e($key) . '">' . self::e($label) . '</label>'
                . '<div class="mcsa-search"><input class="form-control" type="file" id="mcsa-up-' . self::e($key) . '" name="file" accept="' . self::e($accept) . '" required><button class="btn btn-default">بارگذاری</button></div><small>' . self::e($help) . '</small></div></form>';
            return $form . $has . ($info ? self::form('report', 'remove_blob', '<input type="hidden" name="blob" value="' . self::e($key) . '"><button class="btn btn-default btn-sm">برداشتن</button>', 'این فایل برداشته شود؟') : '');
        };
        $can = \McSec\Pdf::available();
        $logo = \McSec\Blobs::get('pdf_logo');
        $font = \McSec\Pdf::customFont();
        $using = \McSec\Pdf::font();
        $state = !$can ? '<div class="alert alert-info">روی این سرور کتابخانه‌ی TCPDF یا فونت مناسب پیدا نشد؛ PDF ساخته نمی‌شود و مشتری فقط دکمه‌ی «چاپ» مرورگر را دارد. (WHMCS معمولاً هر دو را دارد.)</div>'
            : '<p><a class="btn btn-primary" target="_blank" rel="noopener" href="' . self::e(self::url('report', '&sample=fa')) . '">نمونه‌ی PDF (فارسی)</a> <a class="btn btn-default" target="_blank" rel="noopener" href="' . self::e(self::url('report', '&sample=en')) . '">نمونه‌ی PDF (انگلیسی)</a></p>'
                . '<p class="mcsa-muted">نمونه با داده‌ی ساختگی و همین تنظیم‌های ذخیره‌شده ساخته می‌شود. فونت فعلی: <span dir="ltr">' . self::e($using === 'mcsfont' ? 'فونت بارگذاری‌شده' : $using) . '</span></p>';
        return self::guide('<p>ظاهر فایل PDF گزارش‌ها این‌جا تنظیم می‌شود و روی همه‌ی گزارش‌ها (پایه، هوش مصنوعی و دوره‌ای) اثر دارد. گزارش‌های قبلی هم با قالب تازه دانلود می‌شوند، چون PDF هنگام دانلود ساخته می‌شود.</p>'
                . '<ol><li>لوگو را بارگذاری کنید (PNG با زمینه‌ی شفاف بهتر است؛ روی جلدِ تیره می‌نشیند، پس لوگوی روشن یا سفید انتخاب کنید).</li><li>نام، رنگ‌ها و بخش‌ها را تنظیم و ذخیره کنید.</li><li>با «نمونه‌ی PDF» نتیجه را ببینید.</li></ol>'
                . '<p>فونت: پیش‌فرض DejaVu Sans خود WHMCS است. اگر فونت دیگری می‌خواهید، فایل TTF آن را بارگذاری کنید. فایل در پایگاه داده می‌ماند، نه در پوشه‌ی ماژول و نه در بسته‌ی نصب. فونت باید «شکل‌های چسبان» حروف فارسی را داشته باشد؛ اگر نداشته باشد پذیرفته نمی‌شود.</p>')
            . self::box('نمونه', $state)
            . self::box('لوگو', ($logo ? '<p><img alt="لوگوی فعلی" style="max-height:64px;max-width:260px;background:#0b1f3a;padding:8px;border-radius:6px" src="data:' . self::e($logo['mime']) . ';base64,' . base64_encode($logo['bytes']) . '"></p>' : '')
                . $upload('pdf_logo', 'فایل لوگو', 'image/png,image/jpeg', 'PNG یا JPEG، حداکثر ۴۰۰ کیلوبایت. روی جلد و گوشه‌ی سربرگ هر صفحه می‌آید. بدون لوگو، «نام روی گزارش» نوشته می‌شود.'))
            . self::box('نام، رنگ و بخش‌ها', self::form('report', 'save_settings', self::fields('report') . '<button class="btn btn-primary">ذخیره</button>'))
            . self::box('فونت دلخواه', ($font['error'] !== '' ? '<div class="alert alert-danger">' . self::e($font['error']) . '</div>' : '')
                . $upload('pdf_font', 'فونت متن (TTF)', '.ttf,font/ttf', 'فایل TTF، حداکثر ۳ مگابایت. پس از بارگذاری، اگر «فونت» روی auto باشد همین فونت به کار می‌رود.')
                . '<hr>' . $upload('pdf_font_bold', 'فونت ضخیم (TTF، اختیاری)', '.ttf,font/ttf', 'وزن Bold همان فونت برای عنوان‌ها. بدون آن، عنوان‌ها با همان وزن معمولی نوشته می‌شوند.'));
    }

    private static function settings(): string
    {
        $out = self::guide('<p>هر قابلیتی که روی مشتری اثر دارد پیش‌فرض خاموش است. روال پیشنهادی: «چه کسانی» = list با چند حساب آزمایشی ← آزمودن ← groups یا all.</p>');
        foreach (['general' => 'عمومی و دسترسی', 'scope' => 'محدوده‌ی اسکن: فهرست ممنوع و CDN', 'scans' => 'ظرفیت و اسکن', 'checks' => 'فهرست سیاه، پایش و اولویت آسیب‌پذیری‌ها',
            'support' => 'پشتیبانی، پیشنهاد خدمت و صفحه‌ی «درباره‌ی اسکنر»', 'advanced' => 'حالت پیشرفته: اسکن سفارشی مشتری', 'assistant' => 'دستیار امنیت (گفت‌وگوی هوش مصنوعی)', 'extras' => 'قابلیت‌های تکمیلی (هر کدام یک کلید)', 'credits' => 'اعتبار', 'billing' => 'هدیه، دعوت و شارژ خودکار', 'system' => 'سامانه'] as $g => $l) {
            $out .= self::box($l, self::form('settings', 'save_settings', self::fields($g) . '<button class="btn btn-primary">ذخیره</button>')
                . ($g === 'checks' ? self::intelStatus() : '')
                . ($g === 'scope' ? '<hr>' . self::form('settings', 'scope_test', '<div class="mcsa-field"><label for="mcsa-scope-t">این دامنه یا IP اسکن می‌شود؟</label>'
                    . '<div class="mcsa-search"><input class="form-control" id="mcsa-scope-t" name="target" dir="ltr" placeholder="shop.example.com یا 203.0.113.10"><button class="btn btn-default">بسنج</button></div>'
                    . '<small>با قاعده‌های ذخیره‌شده‌ی بالا می‌سنجد: IPهای دامنه، قاعده‌ی ممنوعی که به آن می‌خورد و CDN جلوی آن. چیزی را تغییر نمی‌دهد.</small></div>') : ''));
        }
        return $out;
    }

    /** Last KEV/EPSS refresh and how many monitored sites are down, under the "checks" settings. */
    private static function intelStatus(): string
    {
        $i = json_decode(Settings::get('intel_last'), true);
        $line = is_array($i) ? 'آخرین به‌روزرسانی KEV/EPSS: ' . Text::ago((int) ($i['at'] ?? 0)) . ' — KEV: ' . (is_numeric($i['kev'] ?? null) ? Text::fa((int) $i['kev']) . ' CVE' : 'خطا (گزارش فنی را ببینید)')
            . '، EPSS تازه: ' . Text::fa((int) ($i['epss'] ?? 0)) . '، یافته‌ی به‌روزشده: ' . Text::fa((int) ($i['findings'] ?? 0)) : 'KEV/EPSS هنوز گرفته نشده است (پس از روشن کردن، در اجرای بعدی کار پس‌زمینه).';
        $down = Settings::bool('monitor_enabled') ? Db::table('mod_mcsec_assets')->where('mon_status', 'down')->where('status', 'verified')->count() : 0;
        return '<p class="mcsa-muted">' . self::e($line) . (Settings::bool('monitor_enabled') ? ' · ' . self::e('سایت‌های از دسترس خارج: ' . Text::fa($down)) : '') . '</p>';
    }

    private static function log(): string
    {
        $ref = strtoupper(trim((string) ($_GET['ref'] ?? '')));
        $q = Db::table('mod_mcsec_log');
        if ($ref !== '') {
            $q->where('ref', $ref);
        }
        $rows = '';
        foreach (Db::rows($q->orderByDesc('id')->limit(150)) as $l) {
            $rows .= '<tr class="lvl-' . self::e($l->level) . '"><td dir="ltr">' . self::e($l->ref) . '</td><td>' . self::e(Text::date((int) $l->created_at)) . '</td><td>' . self::e(Trace::AREAS[$l->area] ?? $l->area) . '</td><td dir="ltr">' . self::e($l->action) . '</td>'
                . '<td>' . ((int) $l->client_id > 0 ? '#' . (int) $l->client_id : '') . '</td><td dir="auto">' . self::e($l->message) . ($l->detail ? '<details><summary>جزئیات</summary><pre dir="ltr">' . self::e($l->detail) . '</pre></details>' : '') . '</td></tr>';
        }
        return self::guide('<p>هر خطای موتور، هوش مصنوعی، اعلان یا WHMCS با کد پیگیری (<code dir="ltr">MS-XXXXXX</code>) که مشتری هم می‌بیند. رمزها و کلیدها هرگز ثبت نمی‌شوند.</p>')
            . '<form method="get" class="mcsa-search"><input type="hidden" name="module" value="mcsec"><input type="hidden" name="mcsa" value="log"><input class="form-control" name="ref" value="' . self::e($ref) . '" placeholder="MS-XXXXXX" dir="ltr"><button class="btn btn-default">جستجو</button></form>'
            . self::box('گزارش فنی', $rows !== '' ? '<table class="table mcsa-log"><thead><tr><th>کد</th><th>زمان</th><th>بخش</th><th>کار</th><th>حساب</th><th>پیام</th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">چیزی ثبت نشده است.</p>');
    }

    /** Versions and what each changed (changelog.php), newest first; the installed version is marked. */
    public static function changes(): array
    {
        $file = dirname(__DIR__, 2) . '/changelog.php';
        $log = is_file($file) ? include $file : [];
        return is_array($log) ? $log : [];
    }

    private static function changelog(): string
    {
        $kinds = ['new' => ['تازه', 'ok'], 'change' => ['تغییر', 'chg'], 'fix' => ['رفع', 'fix'], 'ops' => ['برای مدیر', 'ops']];
        $out = self::guide('<p>هر نسخه چه چیزی آورد. «تازه» قابلیت نو است، «تغییر» رفتاری که عوض شده، «رفع» اشکالی که درست شده، و «برای مدیر» کاری که پس از نصب باید انجام دهید یا بدانید. نسخه‌ی نصب‌شده علامت دارد.</p>');
        $log = self::changes();
        if (!$log) {
            return $out . self::box('تغییرات نسخه‌ها', '<p class="mcsa-muted">فایل تغییرات پیدا نشد.</p>');
        }
        foreach ($log as $ver => $v) {
            $items = '';
            foreach ((array) ($v['items'] ?? []) as $it) {
                [$label, $cls] = $kinds[(string) ($it[0] ?? '')] ?? ['تغییر', 'chg'];
                $items .= '<li><span class="mcsa-tag mcsa-tag-' . $cls . '">' . self::e($label) . '</span> ' . self::e((string) ($it[1] ?? '')) . '</li>';
            }
            $here = (string) $ver === MCSEC_VERSION ? ' <span class="mcsa-tag mcsa-tag-ok">نصب‌شده</span>' : '';
            $out .= '<div class="mcsa-box"><h3><bdi dir="ltr">' . self::e($ver) . '</bdi> — ' . self::e((string) ($v['title'] ?? '')) . $here
                . ' <small class="mcsa-muted">' . self::e(Text::ymd((string) ($v['date'] ?? ''))) . '</small></h3><ul class="mcsa-changes">' . $items . '</ul></div>';
        }
        return $out;
    }

    private static function css(): string
    {
        // the look of MC-Care's admin pages (style B), on MC-Sec's own class names
        return '.mcsa{--ink:#101828;--mu:#475467;--ln:#E4E7EC;--hd:#F2F4F7;--p:#101828;--g:#137A43;--y:#8A5A00;--r:#B42318;'
            . 'font-family:"Vazirmatn FD",Vazirmatn,Tahoma,"Segoe UI",sans-serif;color:var(--ink);font-size:13.5px;line-height:1.75;background:#F6F7F9;border-radius:10px;padding:0 0 28px}'
            . '.mcsa *{box-sizing:border-box}.mcsa [hidden]{display:none!important}.mcsa code,.mcsa kbd,.mcsa [dir=ltr]{font-family:Tahoma,"Segoe UI",Consolas,sans-serif}'
            . '.mcsa a{color:#0B5FDB;text-decoration:none}.mcsa a:hover,.mcsa a:focus{color:#0847A6}'
            . '.mcsa h2{font-size:19px;font-weight:700;margin:0;line-height:1.5}.mcsa h3{font-size:13.5px;font-weight:700}.mcsa h4{font-size:14px;font-weight:600}'
            . '.mcsa-topbar{display:flex;flex-wrap:wrap;align-items:center;gap:6px 18px;padding:8px 20px;background:#101828;color:#fff;border-radius:10px 10px 0 0}'
            . '.mcsa a.mcsa-brand,.mcsa a.mcsa-brand:hover,.mcsa a.mcsa-brand:focus{display:inline-flex;align-items:center;gap:8px;color:#fff;font-size:15px}'
            . '.mcsa-logo{display:inline-flex;width:28px;height:28px;border-radius:7px;background:#fff;color:#101828;align-items:center;justify-content:center;font-size:11px;font-weight:700}'
            . '.mcsa-tabs{display:flex;flex-wrap:wrap;gap:2px;list-style:none;margin:0;padding:0;flex:1 1 auto}'
            . '.mcsa .mcsa-tabs a,.mcsa .mcsa-tabs a:hover,.mcsa .mcsa-tabs a:focus{display:inline-flex;align-items:center;min-height:38px;padding:0 12px;border-radius:8px;color:#D0D5DD;background:transparent}'
            . '.mcsa .mcsa-tabs a:hover{background:#1D2939;color:#fff}.mcsa .mcsa-tabs li.active a,.mcsa .mcsa-tabs li.active a:hover{background:#344054;color:#fff;font-weight:600}'
            . '.mcsa-ver{color:#98A2B3;font-size:12px;white-space:nowrap}'
            . '.mcsa-pills{display:flex;flex-wrap:wrap;gap:0 20px;list-style:none;margin:0;padding:0 20px;background:#fff;border-bottom:1px solid var(--ln)}'
            . '.mcsa .mcsa-pills a,.mcsa .mcsa-pills a:hover,.mcsa .mcsa-pills a:focus{display:inline-block;padding:9px 0;border-bottom:2px solid transparent;color:var(--mu)}'
            . '.mcsa .mcsa-pills a:hover{color:var(--ink)}.mcsa .mcsa-pills li.active a{border-bottom-color:var(--ink);color:var(--ink);font-weight:600}'
            . '.mcsa-flashwrap{padding:12px 20px 0}.mcsa-flashwrap>*{margin-bottom:8px}.mcsa-flashwrap>*:last-child{margin-bottom:0}'
            . '.mcsa-body{padding:14px 20px 0}.mcsa-head{margin:0 0 12px}.mcsa-head .sub{color:var(--mu);font-size:13px;max-width:860px}'
            . '.mcsa-box{background:#fff;border:1px solid var(--ln);border-radius:10px;padding:12px 14px;margin:0 0 14px}'
            . '.mcsa-box>h3{margin:-12px -14px 12px;padding:8px 14px;background:var(--hd);border-bottom:1px solid var(--ln);border-radius:9px 9px 0 0;line-height:1.75}'
            . '.mcsa-help,.mcsa-muted{color:var(--mu);font-size:12.5px}'
            . '.mcsa-guide{background:#E8F0FE;color:#0847A6;border-radius:8px;padding:8px 14px;margin:0 0 14px}.mcsa-guide summary{cursor:pointer;font-weight:600}.mcsa-guide>div{color:var(--ink);margin-top:6px}'
            . '.mcsa-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:0;background:#fff;border:1px solid var(--ln);border-radius:10px;overflow:hidden;margin:0 0 14px}'
            . '.mcsa-kpis div{padding:10px 16px;box-shadow:-1px 0 0 var(--ln),0 1px 0 var(--ln)}.mcsa-kpis span{display:block;color:var(--mu);font-size:12.5px}.mcsa-kpis strong{font-size:21px;line-height:1.5;font-weight:700}'
            . '.mcsa-field{margin:0 0 12px}.mcsa-field label{display:block;font-weight:600;margin:0 0 5px;font-size:13.5px}.mcsa-field small{display:block;color:var(--mu);font-size:12.5px;margin-top:3px}'
            . '.mcsa-i{display:inline-flex;width:18px;height:18px;border-radius:50%;background:#E3E8F0;color:#3A4456;font-size:11.5px;font-weight:700;align-items:center;justify-content:center;cursor:help;margin:0 4px;vertical-align:middle;line-height:1}'
            . '.mcsa-i:hover,.mcsa-i:focus{background:var(--p);color:#fff;outline:none}.mcsa-i:focus-visible{box-shadow:0 0 0 3px #9CC0FA}'
            . '.mcsa-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:4px 12px}'
            . '.mcsa-switch,.mcsa-inline{font-weight:400!important;display:inline-flex!important;gap:6px;align-items:center;margin-inline-start:8px}'
            . '.mcsa .ok{color:var(--g)}.mcsa .err{color:var(--r)}.mcsa-health{list-style:none;padding:0;margin:0 0 8px}.mcsa-health li{padding:5px 0;border-bottom:1px solid var(--hd)}.mcsa-health li:last-child{border-bottom:0}'
            . '.mcsa-search{display:flex;gap:6px;margin:0 0 12px;max-width:520px}'
            . '.mcsa .form-control{border:1px solid #D0D5DD;border-radius:8px;box-shadow:none;min-height:36px;font-family:inherit;color:var(--ink)}.mcsa .form-control:focus{border-color:var(--p);box-shadow:0 0 0 3px #E4E7EC}.mcsa textarea.form-control{line-height:1.85}'
            . '.mcsa .btn{border-radius:8px;min-height:34px;font-family:inherit;display:inline-flex;align-items:center;gap:5px;justify-content:center}.mcsa .btn.btn-sm{min-height:32px;padding:4px 12px;font-size:13px}'
            . '.mcsa .btn-default{background:#fff;border-color:#D0D5DD;color:var(--ink)}.mcsa .btn-default:hover,.mcsa .btn-default:focus{border-color:var(--p);color:var(--ink);background:#fff}'
            . '.mcsa .btn-primary{background:var(--p);border-color:var(--p);color:#fff}.mcsa .btn-primary:hover,.mcsa .btn-primary:focus{background:#344054;border-color:#344054;color:#fff}'
            . '.mcsa .btn:focus-visible,.mcsa a:focus-visible{outline:3px solid #9CC0FA;outline-offset:1px}'
            . '.mcsa .alert{border:0;border-radius:8px;padding:8px 14px;margin:0 0 14px}.mcsa .alert-success{background:#E6F4EC;color:#137A43}.mcsa .alert-danger{background:#FDECEA;color:#B42318}.mcsa .alert-info{background:#E8F0FE;color:#0847A6}.mcsa .alert-warning{background:#FFF4DC;color:#8A5A00}'
            . '.mcsa .table{background:#fff;margin-bottom:0;width:100%}.mcsa table td,.mcsa table th{text-align:right;vertical-align:middle}'
            . '.mcsa .table>thead>tr>th{background:var(--hd);color:#344054;font-weight:600;font-size:12px;padding:7px 10px;border-bottom:0}.mcsa .table>tbody>tr>td{padding:7px 10px;border-top:1px solid var(--hd)}.mcsa .table>tbody>tr:hover{background:#F9FAFB}'
            . '.mcsa-log pre{max-height:240px;overflow:auto;font-size:12px;text-align:left;border-radius:8px}.mcsa-log tr.lvl-error td:first-child{border-inline-start:3px solid var(--r)}'
            . '.mcsa form{margin:0 0 8px}.mcsa textarea[dir=ltr],.mcsa input[dir=ltr]{text-align:left;font-family:Consolas,monospace}.mcsa hr{border:0;border-top:1px solid var(--ln);margin:12px 0}'
            . '.mcsa-changes{list-style:none;padding:0;margin:0}.mcsa-changes li{padding:6px 0;border-bottom:1px solid var(--hd)}.mcsa-changes li:last-child{border:0}'
            . '.mcsa-tag{display:inline-block;min-width:4.6rem;text-align:center;font-size:11.5px;font-weight:600;border-radius:6px;padding:1px 9px;margin-inline-end:6px;background:#EEF1F6;color:#4A5466}'
            . '.mcsa-tag-ok{background:#E6F4EC;color:#137A43}.mcsa-tag-fix{background:#FDECEA;color:#B42318}.mcsa-tag-chg{background:#E8F0FE;color:#0847A6}.mcsa-tag-ops{background:#FFF4DC;color:#8A5A00}'
            . '.mcsa-count{display:inline-block;min-width:20px;padding:0 6px;border-radius:10px;background:#F97066;color:#101828;font-size:11px;text-align:center;font-weight:700;margin-inline-start:6px}'
            . '.mcsa-facts th{width:190px;color:var(--mu);font-weight:600;background:transparent!important}.mcsa-log tr.lvl-warn td:first-child{border-inline-start:3px solid var(--y)}.mcsa details>summary{cursor:pointer;color:#0B5FDB}'
            . '@media(max-width:700px){.mcsa-topbar,.mcsa-pills,.mcsa-body,.mcsa-flashwrap{padding-inline:12px}.mcsa-ver{display:none}}';
    }
}
