<?php

declare(strict_types=1);

namespace McSec;

/**
 * Module settings (mod_mcsec_settings). Every setting has a Persian label, an explanation and a default, so the
 * admin page can show ⓘ for each one. Secrets (type secret) are stored encrypted (Crypto) and never shown back.
 * Everything that changes what customers see starts off (enabled = 0, access_mode = list: a trial on a few clients).
 */
final class Settings
{
    /** @var array<string,string>|null */
    private static ?array $cache = null;

    /**
     * key => [default, type, group, label, help]
     * types: bool, int, string, text, secret, json, csv
     */
    public const DEFS = [
        // general
        'enabled' => ['0', 'bool', 'general', 'روشن برای مشتری‌ها', 'تا روشن نشود، منو و صفحه‌ها به هیچ مشتری‌ای نشان داده نمی‌شود. مدیر همیشه صفحه‌ها را می‌بیند. پیش‌فرض: خاموش.'],
        'access_mode' => ['list', 'string', 'general', 'چه کسانی', 'list: فقط حساب‌های فهرست «حساب‌های آزمایشی» (برای آزمایش). groups: فقط گروه‌های مشتری انتخاب‌شده. all: همه‌ی مشتری‌ها. پیش‌فرض: list.'],
        'access_clients' => ['', 'csv', 'general', 'حساب‌های آزمایشی', 'شماره‌ی حساب مشتری‌ها، جداشده با ویرگول. فقط وقتی «چه کسانی» = list است.'],
        'access_groups' => ['', 'csv', 'general', 'گروه‌های مشتری مجاز', 'شناسه‌ی گروه‌های مشتری WHMCS، جداشده با ویرگول. فقط وقتی «چه کسانی» = groups است.'],
        'menu_label' => ['امنیت سایبری', 'string', 'general', 'نام منو', 'نامی که مشتری در منوی ناحیه‌ی کاربری می‌بیند.'],
        'masq_actions' => ['0', 'bool', 'general', 'کار با «ورود به‌جای مشتری»', 'اگر روشن باشد مدیری که با Login as Owner آمده می‌تواند اسکن بگیرد یا تنظیم را عوض کند (شناسه‌ی مدیر ثبت می‌شود). پیش‌فرض: فقط دیدن.'],
        'terms_text' => ['با شروع اسکن تأیید می‌کنم که مالک این دارایی هستم یا از مالک اجازه‌ی کتبی دارم، و می‌دانم اسکن ممکن است بار کوتاهی روی سرویس بگذارد.', 'text', 'general', 'متن رضایت اسکن', 'پیش از اولین اسکن هر حساب نشان داده و تأیید آن ثبت می‌شود.'],
        'max_assets_free' => ['3', 'int', 'general', 'سقف دارایی بدون پلن', 'چند دارایی تأییدشده یک حساب بدون پلن و بدون قاعده‌ی گروه می‌تواند داشته باشد.'],
        'blocklist' => ["*.gov.ir\n*.mil.ir\n*.sch.ir\nlocalhost", 'text', 'general', 'دارایی‌های ممنوع', 'هر خط یک دامنه یا الگو (*.example.com) یا IP/CIDR که هرگز افزوده یا اسکن نمی‌شود، حتی با تأیید.'],
        'allow_private_ips' => ['0', 'bool', 'general', 'IP خصوصی', 'اجازه‌ی افزودن IPهای خصوصی، loopback و رزروشده. پیش‌فرض خاموش (جلوی اسکن شبکه‌ی داخلی مارال را می‌گیرد).'],
        'verify_recheck_days' => ['30', 'int', 'general', 'بازبینی تأیید (روز)', 'هر چند روز رکورد DNS، فایل یا متای تأیید دوباره سنجیده شود. اگر سه بار پشت سر هم نبود، دارایی «منقضی» و زمان‌بندی‌هایش متوقف می‌شود.'],
        'verify_pending_days' => ['7', 'int', 'general', 'پیگیری خودکار تأیید (روز)', 'تا چند روز پس از افزودن، کار پس‌زمینه خودش تأیید را هر چند دقیقه می‌سنجد تا مشتری لازم نباشد منتظر بماند.'],
        'ownership_autoverify' => ['1', 'bool', 'general', 'تأیید خودکار سرویس‌های مارال', 'دامنه یا IPی که همین حساب در WHMCS دارد (دامنه‌ی ثبت‌شده، دامنه‌ی سرویس هاست، IP اختصاصی سرور) بی‌گام اضافه تأیید می‌شود.'],

        // credits and pricing
        'welcome_credits' => ['10', 'int', 'credits', 'اعتبار خوش‌آمد', 'یک بار، هنگام ساخته شدن فضای امنیت هر حساب، به اعتبار خریداری‌شده (بی‌انقضا) افزوده می‌شود. ۰ یعنی هیچ.'],
        'group_rules' => ['[]', 'json', 'credits', 'اعتبار رایگان گروه‌ها', 'برای هر گروه مشتری: اعتبار ماهانه‌ی رایگان (اول هر ماه شمسی پر می‌شود و جمع نمی‌شود) و سقف دارایی.'],
        'credit_packs' => ['[{"key":"p50","credits":50,"price":5000000,"label":"بسته‌ی ۵۰ اعتبار"},{"key":"p200","credits":200,"price":17000000,"label":"بسته‌ی ۲۰۰ اعتبار"},{"key":"p1000","credits":1000,"price":70000000,"label":"بسته‌ی ۱۰۰۰ اعتبار"}]', 'json', 'credits', 'بسته‌های خرید اعتبار', 'مبلغ به واحد پول پیش‌فرض WHMCS. خرید با فاکتور WHMCS انجام می‌شود و پس از پرداخت، اعتبار خودکار افزوده می‌شود.'],
        'low_credit_alert' => ['5', 'int', 'credits', 'هشدار کمبود اعتبار', 'وقتی مانده‌ی کل اعتبار به این عدد یا کمتر رسید، یک بار خبر داده می‌شود.'],
        'refund_on_fail' => ['1', 'bool', 'credits', 'بازگشت اعتبار اسکن ناموفق', 'اگر اسکن به‌خاطر خطای سامانه (نه مشتری) تمام نشد، اعتبارش خودکار برمی‌گردد.'],
        'ai_report_cost' => ['2', 'int', 'credits', 'هزینه‌ی گزارش هوش مصنوعی', 'اعتبار هر گزارش هوش مصنوعی. گزارش پایه (بی هوش مصنوعی) رایگان است.'],
        'ai_fix_cost' => ['0', 'int', 'credits', 'هزینه‌ی «راهکار با هوش مصنوعی»', 'اعتبار هر درخواست راهکار برای یک یافته. پاسخ‌ها کش می‌شوند و یافته‌ی یکسان برای همه یک بار هزینه دارد.'],
        'invoice_due_days' => ['3', 'int', 'credits', 'مهلت فاکتور خرید اعتبار', 'سررسید فاکتور بسته‌ی اعتبار (روز).'],

        // scan catalogue and capacity
        'profiles' => ['{}', 'json', 'scans', 'تنظیم نوع‌های اسکن', 'روشن/خاموش، هزینه‌ی اعتبار و workflow هر نوع اسکن. هر چه این‌جا نیست، پیش‌فرض کد است.'],
        'scans_paused' => ['0', 'bool', 'scans', 'توقف همه‌ی اسکن‌ها', 'کلید اضطراری: اسکن تازه پذیرفته و از صف شروع نمی‌شود (مثلاً هنگام شکایت از ترافیک اسکن یا تعمیر موتورها). اسکن‌های در حال اجرا ادامه می‌یابند.'],
        'retest_daily_cap' => ['10', 'int', 'scans', 'سقف بررسی دوباره‌ی رایگان در روز', '«رفع کردم، دوباره بسنج» هر حساب در ۲۴ ساعت.'],
        'concurrency_oasm' => ['3', 'int', 'scans', 'اسکن همزمان OASM', 'بیشترین اسکن در حال اجرا روی OASM برای همه‌ی مشتری‌ها.'],
        'concurrency_osm' => ['2', 'int', 'scans', 'اسکن همزمان Osmedeus', 'بیشترین اسکن در حال اجرا روی Osmedeus برای همه‌ی مشتری‌ها.'],
        'client_concurrency' => ['2', 'int', 'scans', 'اسکن همزمان هر حساب', 'یک حساب بیش از این تعداد اسکن در حال اجرا ندارد؛ بقیه در صف می‌مانند.'],
        'scan_timeout_hours' => ['12', 'int', 'scans', 'سقف زمان اسکن (ساعت)', 'اسکنی که بیش از این طول بکشد ناموفق ثبت می‌شود و اعتبارش برمی‌گردد.'],
        'daily_scan_cap' => ['20', 'int', 'scans', 'سقف اسکن روزانه‌ی هر حساب', 'جلوی سوءاستفاده را می‌گیرد، حتی اگر اعتبار کافی باشد.'],
        'live_sync' => ['1', 'bool', 'scans', 'به‌روزرسانی زنده‌ی پیشرفت', 'وقتی مشتری صفحه‌ی اسکن را باز دارد، وضعیت با درخواست کوتاه (حداکثر ۴ ثانیه) از موتور خوانده شود. خاموش: فقط کار پس‌زمینه هر ۵ دقیقه.'],
        'builtin_ports' => ['21,22,23,25,110,143,445,1433,2375,3306,3389,5432,5900,6379,9200,11211,27017', 'csv', 'scans', 'درگاه‌های بررسی پایه', 'درگاه‌های پرخطری که بررسی سلامت پایه باز بودنشان را می‌سنجد.'],

        // engines
        'oasm_url' => ['', 'string', 'engines', 'آدرس OASM', 'مثل https://oasm.example.com (بدون /api).'],
        'oasm_email' => ['', 'string', 'engines', 'حساب سرویس OASM', 'ایمیل کاربر مدیر OASM که فضای کار هر مشتری با آن ساخته می‌شود.'],
        'oasm_password' => ['', 'secret', 'engines', 'رمز حساب سرویس OASM', 'رمزنگاری‌شده ذخیره می‌شود و دوباره نمایش داده نمی‌شود.'],
        'oasm_verify_tls' => ['1', 'bool', 'engines', 'بررسی گواهی OASM', 'خاموش فقط برای staging با گواهی خودامضا.'],
        'oasm_user_domain' => ['mcsec.invalid', 'string', 'engines', 'دامنه‌ی کاربرهای OASM', 'هر حساب مشتری یک کاربر جدا در OASM می‌گیرد (mcsec-c<شماره>@این‌دامنه) چون هر کاربر OASM حداکثر ۵ فضای کار دارد. ایمیلی به این نشانی‌ها فرستاده نمی‌شود.'],
        'osm_url' => ['', 'string', 'engines', 'آدرس Osmedeus', 'مثل http://10.0.0.5:8811'],
        'osm_username' => ['osmedeus', 'string', 'engines', 'نام کاربری Osmedeus', ''],
        'osm_password' => ['', 'secret', 'engines', 'رمز Osmedeus', 'رمزنگاری‌شده ذخیره می‌شود.'],
        'osm_api_key' => ['', 'secret', 'engines', 'کلید API Osmedeus', 'اگر سرور Osmedeus کلید API دارد، به‌جای نام کاربری و رمز به کار می‌رود.'],
        'osm_verify_tls' => ['1', 'bool', 'engines', 'بررسی گواهی Osmedeus', ''],

        // AI
        'ai_enabled' => ['0', 'bool', 'ai', 'گزارش هوش مصنوعی', 'روشن: گزارش‌ها و «راهکار با هوش مصنوعی» از مدل ساخته می‌شوند. خاموش: گزارش پایه با پایگاه دانش داخلی (فارسی) ساخته می‌شود.'],
        'ai_base_url' => ['https://api.openai.com/v1', 'string', 'ai', 'آدرس سرویس (سازگار با OpenAI)', 'OpenAI یا هر درگاه سازگار (New API مارال، OpenRouter، Azure). با /v1 تمام شود.'],
        'ai_key' => ['', 'secret', 'ai', 'کلید API', 'رمزنگاری‌شده ذخیره می‌شود.'],
        'ai_model' => ['gpt-4.1-mini', 'string', 'ai', 'مدل', 'نام مدل در همان سرویس.'],
        'ai_max_tokens' => ['6000', 'int', 'ai', 'سقف توکن خروجی', ''],
        'ai_timeout' => ['90', 'int', 'ai', 'مهلت پاسخ (ثانیه)', 'گزارش‌ها در کار پس‌زمینه ساخته می‌شوند؛ مشتری منتظر نمی‌ماند.'],
        'ai_auto_scan_report' => ['1', 'bool', 'ai', 'گزارش خودکار پس از اسکن', 'پس از هر اسکن موفق، گزارش پایه خودکار ساخته شود (رایگان).'],
        'ai_mask_pii' => ['1', 'bool', 'ai', 'پوشاندن داده‌ی شخصی', 'ایمیل، شماره تلفن و توکن‌ها پیش از فرستادن به مدل پوشانده شوند.'],

        // notifications
        'email_enabled' => ['1', 'bool', 'notify', 'ایمیل', 'اعلان با ایمیل WHMCS (پیام سفارشی general) فرستاده شود.'],
        'telegram_token' => ['', 'secret', 'notify', 'توکن ربات تلگرام', 'خالی یعنی تلگرام خاموش.'],
        'telegram_bot' => ['', 'string', 'notify', 'نام ربات تلگرام', 'بدون @؛ برای پیوند «اتصال تلگرام» مشتری.'],
        'bale_token' => ['', 'secret', 'notify', 'توکن ربات بله', 'خالی یعنی بله خاموش.'],
        'bale_bot' => ['', 'string', 'notify', 'نام ربات بله', 'بدون @.'],
        'webhook_enabled' => ['1', 'bool', 'notify', 'وب‌هوک مشتری', 'مشتری می‌تواند آدرس وب‌هوک (Slack، Mattermost، سامانه‌ی خودش) بدهد. هر پیام با HMAC امضا می‌شود.'],
        'digest_dow' => ['6', 'int', 'notify', 'روز گزارش هفتگی', '۰ یکشنبه … ۶ شنبه (به وقت تهران).'],
        'digest_hour' => ['9', 'int', 'notify', 'ساعت گزارش دوره‌ای', 'ساعت تهران.'],

        // system
        'log_days' => ['90', 'int', 'system', 'نگه‌داری گزارش فنی (روز)', ''],
        'role_map' => ['1:settings', 'csv', 'system', 'سطح نقش‌های مدیر', 'roleid:tier، tier یکی از view، ops، settings. نقش بی نگاشت فقط می‌بیند.'],
    ];

    public static function get(string $key): string
    {
        self::load();
        if (array_key_exists($key, self::$cache)) {
            return self::$cache[$key];
        }
        return (string) (self::DEFS[$key][0] ?? '');
    }

    public static function set(string $key, string $value): void
    {
        self::load();
        $exists = Db::table('mod_mcsec_settings')->where('k', $key)->exists();
        if ($exists) {
            Db::table('mod_mcsec_settings')->where('k', $key)->update(['v' => $value]);
        } else {
            Db::table('mod_mcsec_settings')->insert(['k' => $key, 'v' => $value]);
        }
        self::$cache[$key] = $value;
    }

    public static function bool(string $key): bool
    {
        return self::get($key) === '1';
    }

    public static function int(string $key): int
    {
        return (int) self::get($key);
    }

    /** @return string[] */
    public static function csv(string $key): array
    {
        return array_values(array_filter(array_map('trim', explode(',', Text::toAscii(self::get($key)))), 'strlen'));
    }

    /** @return int[] */
    public static function ints(string $key): array
    {
        return array_values(array_filter(array_map('intval', self::csv($key))));
    }

    public static function json(string $key): array
    {
        $v = json_decode(self::get($key), true);
        return is_array($v) ? $v : (json_decode((string) (self::DEFS[$key][0] ?? '[]'), true) ?: []);
    }

    public static function secret(string $key): string
    {
        $v = self::get($key);
        return $v === '' ? '' : Crypto::decrypt($v);
    }

    public static function setSecret(string $key, string $plain): void
    {
        self::set($key, $plain === '' ? '' : Crypto::encrypt($plain));
    }

    public static function menuLabel(): string
    {
        $l = Text::name(self::get('menu_label'), 40);
        return $l !== '' ? $l : 'امنیت سایبری';
    }

    /** Tests and the admin save: forget the per-request cache. */
    public static function forget(): void
    {
        self::$cache = null;
    }

    private static function load(): void
    {
        if (self::$cache !== null) {
            return;
        }
        self::$cache = [];
        try {
            foreach (Db::rows(Db::table('mod_mcsec_settings')) as $r) {
                self::$cache[(string) $r->k] = (string) $r->v;
            }
        } catch (\Throwable $e) {
            // before install: defaults only
        }
    }
}
