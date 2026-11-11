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

    public static function render(string $page, string $flash): string
    {
        $nav = '<nav class="mcsa-nav">';
        foreach (Controller::PAGES as $p => $l) {
            $nav .= '<a href="' . self::e(self::url($p)) . '"' . ($p === $page ? ' class="active"' : '') . '>' . self::e($l) . '</a>';
        }
        $nav .= '</nav>';
        $tier = Auth::adminTier();
        $body = match ($page) {
            'setup' => self::setup(),
            'pricing' => self::pricing(),
            'credits' => self::credits(),
            'assets' => self::assets(),
            'scans' => self::scans(),
            'settings' => self::settings(),
            'log' => self::log(),
            default => self::overview(),
        };
        $warn = !Settings::bool('enabled') ? '<div class="alert alert-info">MC-Sec برای مشتری‌ها خاموش است. پس از راه‌اندازی موتورها و آزمودن روی چند حساب آزمایشی، در «تنظیمات» روشنش کنید.</div>' : '';
        return '<div class="mcsa" dir="rtl" lang="fa"><style>' . self::css() . '</style><header class="mcsa-head"><h2>MC-Sec — امنیت سایبری <small>نسخه‌ی ' . self::e(MCSEC_VERSION) . ' · سطح شما: ' . self::e($tier) . '</small></h2></header>'
            . $nav . $warn . self::flash($flash) . $body . '</div>';
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
            . $kpis . self::box('سلامت', $health . '<p>' . $worker . '</p>' . self::form('overview', 'run_worker', '<button class="btn btn-default">اجرای کار پس‌زمینه همین حالا</button>'))
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
                'text', 'json' => '<textarea class="form-control" id="' . $id . '" name="set_' . $k . '" rows="' . ($type === 'json' ? 5 : 3) . '" dir="' . ($type === 'json' || $k === 'blocklist' ? 'ltr' : 'auto') . '">' . self::e($val) . '</textarea>',
                default => '<input class="form-control" id="' . $id . '" name="set_' . $k . '" value="' . self::e($val) . '" dir="' . (in_array($type, ['int', 'csv'], true) || str_ends_with($k, '_url') || str_contains($k, 'email') || str_contains($k, 'model') ? 'ltr' : 'auto') . '">',
            };
            $h .= '<div class="mcsa-field"><label for="' . $id . '">' . self::e($label) . ' <span class="mcsa-i" title="' . self::e($help . ($type !== 'secret' && $def !== '' && strlen($def) < 60 ? ' پیش‌فرض: ' . $def : '')) . '">ⓘ</span></label>' . $control
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
            . self::box('بررسی‌های داخلی', '<p>روی همین سرور WHMCS اجرا می‌شوند (DNS، TLS، هدرها، چند درگاه پرخطر روی IPهای خود مشتری). اگر فایروال خروجی دارید، درگاه‌های ۸۰ و ۴۴۳ و درگاه‌های «بررسی پایه» باید باز باشند.</p>' . $test('builtin', 'بررسی داخلی'))
            . self::box('هوش مصنوعی', self::form('setup', 'save_settings', self::fields('ai') . '<button class="btn btn-primary">ذخیره</button>') . $test('ai', 'مدل'))
            . self::box('اعلان‌ها', self::form('setup', 'save_settings', self::fields('notify') . '<button class="btn btn-primary">ذخیره</button>') . $test('bots', 'ربات‌ها'));
    }

    private static function pricing(): string
    {
        $rows = '';
        foreach (Catalog::all(true) as $k => $p) {
            $rows .= '<tr><td><code dir="ltr">' . self::e($k) . '</code><br><small>' . self::e(Catalog::engineLabel($p['engine'])) . '</small></td>'
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
        return self::guide('<p><strong>مدل قیمت:</strong> پلن‌ها (محصول WHMCS با ماژول سرور «MC-Sec») سقف دارایی، اعتبار ماهانه، نوع‌های اسکن و کوتاه‌ترین فاصله‌ی زمان‌بندی را می‌دهند؛ هر اسکن به اندازه‌ی عمقش اعتبار مصرف می‌کند؛ بسته‌های اعتبار با فاکتور WHMCS فروخته می‌شوند؛ گروه‌های مشتری می‌توانند اعتبار ماهانه‌ی رایگان بگیرند.</p>'
            . '<p>هزینه‌ی هر نوع اسکن برای یک دامنه یا IP است؛ بازه‌ی IP به ازای هر ۱۶ آدرس. نوعی که «بی‌پلن» نیست فقط برای مشتری‌های دارای پلنی است که آن را دارد.</p>'
            . '<p><strong>ساختن پلن:</strong> Setup › Products › محصول تازه، تب Module Settings، ماژول «MC-Sec — پلن امنیت سایبری»، و اعتبار ماهانه، سقف دارایی، نوع‌ها و گزارش هوش مصنوعی را بگذارید. تمدید هر ماه اعتبار ماه را یک بار می‌دهد.</p>')
            . self::box('نوع‌های اسکن و هزینه', $prof) . self::box('بسته‌های خرید اعتبار', $packsForm)
            . self::box('هزینه‌های دیگر', self::form('pricing', 'save_settings', self::fields('credits', ['ai_report_cost', 'ai_fix_cost', 'welcome_credits', 'low_credit_alert', 'refund_on_fail', 'invoice_due_days']) . '<button class="btn btn-primary">ذخیره</button>'))
            . self::box('پلن‌ها (محصول‌های ماژول MC-Sec)', $plans !== '' ? '<ul>' . $plans . '</ul>' : '<p class="mcsa-muted">هنوز محصولی با ماژول MC-Sec نساخته‌اید.</p>');
    }

    private static function credits(): string
    {
        $groups = Whmcs::groups();
        $rules = Settings::json('group_rules');
        $rows = '';
        for ($i = 0; $i < count($rules) + 2; $i++) {
            $r = $rules[$i] ?? ['group' => 0, 'monthly' => '', 'max_assets' => ''];
            $opts = '<option value="0">—</option>';
            foreach ($groups as $gid => $gn) {
                $opts .= '<option value="' . $gid . '"' . ((int) $r['group'] === $gid ? ' selected' : '') . '>' . self::e($gn) . '</option>';
            }
            $rows .= '<tr><td><select class="form-control" name="gr_group[]">' . $opts . '</select></td><td><input class="form-control" name="gr_monthly[]" value="' . self::e($r['monthly']) . '" dir="ltr"></td>'
                . '<td><input class="form-control" name="gr_assets[]" value="' . self::e($r['max_assets']) . '" dir="ltr"></td></tr>';
        }
        $groupsForm = self::form('credits', 'save_groups', '<table class="table"><thead><tr><th>گروه مشتری</th><th>اعتبار ماهانه‌ی رایگان</th><th>سقف دارایی</th></tr></thead><tbody>' . $rows . '</tbody></table><button class="btn btn-primary">ذخیره</button>');
        $grant = self::form('credits', 'grant', '<div class="mcsa-row"><div class="mcsa-field"><label>شماره‌ی حساب مشتری</label><input class="form-control" name="grant_client" dir="ltr" required></div>'
            . '<div class="mcsa-field"><label>تعداد اعتبار</label><input class="form-control" name="grant_amount" dir="ltr" required></div>'
            . '<div class="mcsa-field"><label>نوع</label><select class="form-control" name="grant_bucket"><option value="paid">بی‌انقضا</option><option value="monthly">ماهانه (تا آخر ماه)</option></select></div>'
            . '<div class="mcsa-field"><label>شرح (مشتری می‌بیند)</label><input class="form-control" name="grant_note" placeholder="مثلاً جبران قطعی"></div></div><button class="btn btn-primary">افزودن اعتبار</button>', 'این اعتبار افزوده شود؟');
        $ledger = '';
        $last = Db::rows(Db::table('mod_mcsec_ledger')->whereIn('kind', ['grant', 'topup', 'refund', 'group', 'plan'])->orderByDesc('id')->limit(40));
        $names = Whmcs::clientNames(array_map(fn ($r) => (int) $r->client_id, $last));
        foreach ($last as $l) {
            $ledger .= '<tr><td>' . self::e(Text::date((int) $l->created_at)) . '</td><td>#' . (int) $l->client_id . ' ' . self::e($names[(int) $l->client_id] ?? '') . '</td><td>' . self::e(Credits::KINDS[$l->kind] ?? $l->kind) . '</td><td dir="ltr">' . (int) $l->delta . '</td><td>' . self::e($l->note) . '</td></tr>';
        }
        return self::guide('<p><strong>اعتبار رایگان گروه:</strong> برای هر گروه مشتری WHMCS (مثلاً «همکاران» یا «VIP») اعتبار ماهانه بگذارید؛ اول هر ماه شمسی پر می‌شود و به ماه بعد نمی‌رود. سقف دارایی گروه هم این‌جاست.</p><p><strong>اعطای تکی:</strong> برای جبران یا هدیه؛ مشتری خبر می‌گیرد و در تراکنش‌هایش می‌بیند.</p>')
            . self::box('اعتبار رایگان گروه‌ها', $groupsForm) . self::box('افزودن اعتبار به یک حساب', $grant)
            . self::box('آخرین افزوده‌ها و بازگشت‌ها', $ledger !== '' ? '<table class="table"><thead><tr><th>تاریخ</th><th>حساب</th><th>نوع</th><th>مقدار</th><th>شرح</th></tr></thead><tbody>' . $ledger . '</tbody></table>' : '<p class="mcsa-muted">چیزی نیست.</p>');
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

    private static function scans(): string
    {
        $out = self::guide('<p>صف و اسکن‌های در حال اجرا و ناموفق. «توقف» اعتبار را برمی‌گرداند؛ «دوباره» برای اسکن ناموفق یک اسکن رایگان تازه می‌سازد. علت خطا با کد پیگیری در «گزارش فنی» است.</p>');
        foreach (['running' => 'در حال اجرا', 'queued' => 'در صف', 'failed' => 'ناموفق (۷ روز)'] as $st => $label) {
            $q = Db::table('mod_mcsec_scans as s')->join('mod_mcsec_assets as a', 'a.id', '=', 's.asset_id')->where('s.status', $st);
            if ($st === 'failed') {
                $q->where('s.finished_at', '>', Clock::now() - 7 * 86400);
            }
            $list = Db::rows($q->select(['s.*', 'a.value'])->orderByDesc('s.id')->limit(60));
            $rows = '';
            foreach ($list as $s) {
                $btn = Auth::adminCan('ops') ? ($st === 'failed'
                    ? self::form('scans', 'retry_scan', '<input type="hidden" name="scan_id" value="' . (int) $s->id . '"><button class="btn btn-default btn-sm">دوباره</button>')
                    : self::form('scans', 'cancel_scan', '<input type="hidden" name="scan_id" value="' . (int) $s->id . '"><button class="btn btn-default btn-sm">توقف</button>', 'این اسکن متوقف شود؟')) : '';
                $rows .= '<tr><td>' . (int) $s->id . '</td><td>#' . (int) $s->client_id . '</td><td dir="ltr">' . self::e($s->value) . '</td><td>' . self::e(Catalog::all(true)[$s->profile]['label'] ?? $s->profile) . ' <small>(' . self::e($s->engine) . ')</small></td>'
                    . '<td>' . self::e($st === 'failed' ? $s->error . ' ' . $s->error_ref : Text::fa((int) $s->progress) . '٪ ' . $s->stage) . '</td><td>' . self::e(Text::ago((int) ($s->started_at ?: $s->queued_at))) . '</td><td>' . $btn . '</td></tr>';
            }
            $out .= self::box($label . ' (' . Text::fa(count($list)) . ')', $rows !== '' ? '<table class="table"><thead><tr><th>#</th><th>حساب</th><th>دارایی</th><th>اسکن</th><th>وضعیت</th><th>زمان</th><th></th></tr></thead><tbody>' . $rows . '</tbody></table>' : '<p class="mcsa-muted">چیزی نیست.</p>');
        }
        return $out;
    }

    private static function settings(): string
    {
        $out = self::guide('<p>هر قابلیتی که روی مشتری اثر دارد پیش‌فرض خاموش است. روال پیشنهادی: «چه کسانی» = list با چند حساب آزمایشی ← آزمودن ← groups یا all.</p>');
        foreach (['general' => 'عمومی و دسترسی', 'scans' => 'ظرفیت و اسکن', 'credits' => 'اعتبار', 'system' => 'سامانه'] as $g => $l) {
            $out .= self::box($l, self::form('settings', 'save_settings', self::fields($g) . '<button class="btn btn-primary">ذخیره</button>'));
        }
        return $out;
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

    private static function css(): string
    {
        return '.mcsa{font-family:Tahoma,var(--font-family-base,sans-serif);line-height:1.8;max-width:1300px}.mcsa *{box-sizing:border-box}.mcsa-head h2{margin:0 0 .5rem;font-size:1.35rem}.mcsa-head small{font-size:.8rem;color:#64748b;font-weight:400}'
            . '.mcsa-nav{display:flex;flex-wrap:wrap;gap:.25rem;margin:0 0 1rem;padding:.3rem;background:#f1f5f9;border-radius:10px}.mcsa-nav a{padding:.35rem .8rem;border-radius:8px;color:#334155;text-decoration:none}.mcsa-nav a.active{background:#fff;font-weight:700;box-shadow:0 1px 3px rgba(0,0,0,.1)}'
            . '.mcsa-box{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1rem 1.2rem;margin:0 0 1rem}.mcsa-box h3{margin:0 0 .75rem;font-size:1.05rem}.mcsa-help,.mcsa-muted{color:#64748b}'
            . '.mcsa-guide{background:#e0f2fe;border-radius:10px;padding:.5rem 1rem;margin:0 0 1rem}.mcsa-guide summary{cursor:pointer;font-weight:700;color:#075985}'
            . '.mcsa-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:.6rem;margin:0 0 1rem}.mcsa-kpis div{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:.7rem 1rem}.mcsa-kpis span{display:block;color:#64748b;font-size:.85rem}.mcsa-kpis strong{font-size:1.35rem}'
            . '.mcsa-field{margin:0 0 .8rem}.mcsa-field label{display:block;font-weight:700;margin:0 0 .2rem}.mcsa-field small{display:block;color:#64748b;font-size:.8rem}.mcsa-i{cursor:help;color:#2563eb}.mcsa-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.75rem}'
            . '.mcsa-switch,.mcsa-inline{font-weight:400!important;display:inline-flex!important;gap:.35rem;align-items:center;margin-inline-start:.5rem}.mcsa .ok{color:#15803d}.mcsa .err{color:#b91c1c}.mcsa-health{list-style:none;padding:0}.mcsa-health li{padding:.25rem 0}'
            . '.mcsa-search{display:flex;gap:.5rem;margin:0 0 1rem;max-width:520px}.mcsa table td,.mcsa table th{text-align:right;vertical-align:middle}.mcsa-log pre{max-height:240px;overflow:auto;font-size:.75rem;text-align:left}.mcsa-log tr.lvl-error td:first-child{border-inline-start:3px solid #b91c1c}'
            . '.mcsa form{margin:0 0 .5rem}.mcsa textarea[dir=ltr],.mcsa input[dir=ltr]{text-align:left;font-family:monospace}';
    }
}
