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
        // scope: what may never be scanned, CDNs
        'blocklist' => ["*.gov.ir\n*.mil.ir\n*.sch.ir\nlocalhost", 'text', 'scope', 'دارایی‌های ممنوع', 'هر خط یک قاعده؛ هر چه با آن جور شود هرگز افزوده یا اسکن نمی‌شود، حتی با تأیید. دامنه (example.com یا *.gov.ir: خودش و همه‌ی زیردامنه‌هایش)، الگوی ستاره‌دار (*bank*: هر دامنه‌ای که bank دارد)، IP، CIDR یا بازه (5.6.7.10-5.6.7.50؛ IPv6 هم). دامنه‌ای که IPش در یکی از این قاعده‌های IP بیفتد هم ممنوع است. یادداشت را پس از # بنویسید. قاعده‌ی تازه روی اسکن‌های در صف هم اثر دارد.'],
        'allow_private_ips' => ['0', 'bool', 'scope', 'IP خصوصی', 'اجازه‌ی افزودن IPهای خصوصی، loopback و رزروشده. پیش‌فرض خاموش (جلوی اسکن شبکه‌ی داخلی مارال را می‌گیرد).'],
        'cdn_list' => [
            "# Cloudflare — cloudflare.com/ips (1405-08-21)\ncloudflare 173.245.48.0/20\ncloudflare 103.21.244.0/22\ncloudflare 103.22.200.0/22\ncloudflare 103.31.4.0/22\ncloudflare 141.101.64.0/18\ncloudflare 108.162.192.0/18\ncloudflare 190.93.240.0/20\ncloudflare 188.114.96.0/20\ncloudflare 197.234.240.0/22\ncloudflare 198.41.128.0/17\ncloudflare 162.158.0.0/15\ncloudflare 104.16.0.0/13\ncloudflare 104.24.0.0/14\ncloudflare 172.64.0.0/13\ncloudflare 131.0.72.0/22\ncloudflare 2400:cb00::/32\ncloudflare 2606:4700::/32\ncloudflare 2803:f800::/32\ncloudflare 2405:b500::/32\ncloudflare 2405:8100::/32\ncloudflare 2a06:98c0::/29\ncloudflare 2c0f:f248::/32\ncloudflare cdn.cloudflare.net\n"
            . "# ArvanCloud — arvancloud.ir/en/ips.txt (1405-08-21)\narvancloud 185.143.232.0/22\narvancloud 188.229.116.16/30\narvancloud 94.101.182.0/27\narvancloud 2.144.3.128/28\narvancloud 37.32.16.0/27\narvancloud 37.32.17.0/27\narvancloud 37.32.18.0/27\narvancloud 37.32.19.0/27\narvancloud 185.215.232.0/22\narvancloud 178.131.120.48/28\narvancloud 94.101.183.0/28\narvancloud 78.157.36.112/28\narvancloud 95.38.61.80/28\narvancloud 193.24.119.0/29\n"
            . "# MizbanCloud — RIPE IR-ABRMIZBAN\nmizbancloud 185.226.140.0/22\n"
            . "# CNAME of other CDNs\ncloudfront cloudfront.net\nakamai akamaiedge.net\nakamai edgekey.net\nakamai edgesuite.net\nfastly fastly.net\nazure-cdn azureedge.net",
            'text', 'scope', 'سرورهای CDN',
            'هر خط: نام CDN و یک IP، CIDR، بازه یا پسوند CNAME. دامنه‌ای که IPش در این فهرست باشد یا CNAMEش به این نام‌ها برسد «پشت CDN» است: سرورهای CDN هرگز درگاه‌کاوی نمی‌شوند و IP آن‌ها دارایی پذیرفته نمی‌شود. فهرست پیش‌فرض از منبع رسمی Cloudflare و ابر آروان در آبان ۱۴۰۵ است؛ هر چند ماه به‌روزش کنید.',
        ],
        'cdn_origin_scan' => ['0', 'bool', 'scope', 'اسکن سرور اصلی دامنه‌های پشت CDN', 'روشن: مشتری در صفحه‌ی دامنه‌ی پشت CDN، IP اصلی سرورش را ثبت می‌کند و پس از تأیید مالکیت آن IP، کشف سطح حمله و اسکن آسیب‌پذیری روی همان IP اجرا می‌شود. خاموش: این دامنه‌ها فقط بررسی سلامت پایه می‌گیرند (همان چیزی که بازدیدکننده از پشت CDN می‌بیند). پیش‌فرض: خاموش.'],
        'verify_recheck_days' => ['30', 'int', 'general', 'بازبینی تأیید (روز)', 'هر چند روز رکورد DNS، فایل یا متای تأیید دوباره سنجیده شود. اگر سه بار پشت سر هم نبود، دارایی «منقضی» و زمان‌بندی‌هایش متوقف می‌شود.'],
        'verify_pending_days' => ['7', 'int', 'general', 'پیگیری خودکار تأیید (روز)', 'تا چند روز پس از افزودن، کار پس‌زمینه خودش تأیید را هر چند دقیقه می‌سنجد تا مشتری لازم نباشد منتظر بماند.'],
        'ownership_autoverify' => ['1', 'bool', 'general', 'تأیید خودکار سرویس‌های مارال', 'دامنه یا IPی که همین حساب در WHMCS دارد (دامنه‌ی ثبت‌شده، دامنه‌ی سرویس هاست، IP اختصاصی سرور) بی‌گام اضافه تأیید می‌شود.'],

        // credits and pricing
        'welcome_credits' => ['10', 'int', 'credits', 'اعتبار خوش‌آمد', 'یک بار، هنگام ساخته شدن فضای امنیت هر حساب، به اعتبار خریداری‌شده (بی‌انقضا) افزوده می‌شود. ۰ یعنی هیچ.'],
        'group_rules' => ['[]', 'json', 'legacy', 'اعتبار رایگان گروه‌ها (پیش از ۰٫۷)', 'از ۰٫۷٫۰ در صفحه‌ی «قاعده‌ها» است؛ هنگام به‌روزرسانی خودکار منتقل می‌شود.'],
        'credit_packs' => ['[{"key":"p50","credits":50,"price":5000000,"label":"بسته‌ی ۵۰ اعتبار"},{"key":"p200","credits":200,"price":17000000,"label":"بسته‌ی ۲۰۰ اعتبار"},{"key":"p1000","credits":1000,"price":70000000,"label":"بسته‌ی ۱۰۰۰ اعتبار"}]', 'json', 'credits', 'بسته‌های خرید اعتبار', 'مبلغ به واحد پول پیش‌فرض WHMCS. خرید با فاکتور WHMCS انجام می‌شود و پس از پرداخت، اعتبار خودکار افزوده می‌شود.'],
        'low_credit_alert' => ['5', 'int', 'credits', 'هشدار کمبود اعتبار', 'وقتی مانده‌ی کل اعتبار به این عدد یا کمتر رسید، یک بار خبر داده می‌شود.'],
        'refund_on_fail' => ['1', 'bool', 'credits', 'بازگشت اعتبار اسکن ناموفق', 'اگر اسکن به‌خاطر خطای سامانه (نه مشتری) تمام نشد، اعتبارش خودکار برمی‌گردد.'],
        'ai_report_cost' => ['2', 'int', 'credits', 'هزینه‌ی گزارش هوش مصنوعی', 'اعتبار هر گزارش هوش مصنوعی. گزارش پایه (بی هوش مصنوعی) رایگان است.'],
        'ai_fix_cost' => ['0', 'int', 'credits', 'هزینه‌ی «راهکار با هوش مصنوعی»', 'اعتبار هر درخواست راهکار برای یک یافته. پاسخ‌ها کش می‌شوند و یافته‌ی یکسان برای همه یک بار هزینه دارد.'],
        'invoice_due_days' => ['3', 'int', 'credits', 'مهلت فاکتور خرید اعتبار', 'سررسید فاکتور بسته‌ی اعتبار (روز).'],

        // codes, gifts, invites, auto top-up (all off until the admin turns them on)
        'gift_enabled' => ['0', 'bool', 'billing', 'هدیه برای دوستان', 'روشن: کنار هر بسته دکمه‌ی «هدیه به دوست» می‌آید. مشتری فاکتور را می‌پردازد و یک کد هدیه می‌گیرد؛ دوستش کد را در «کد دارید؟» وارد می‌کند. کدی که یک سال استفاده نشود به اعتبار خریدار برمی‌گردد. پیش‌فرض: خاموش.'],
        'invite_enabled' => ['0', 'bool', 'billing', 'دعوت از دوستان', 'روشن: هر حساب یک کد و پیوند دعوت دارد. جایزه فقط اعتبار اسکن است. پیش‌فرض: خاموش.'],
        'invite_new_credits' => ['10', 'int', 'billing', 'اعتبار هدیه‌ی دعوت‌شده', 'اعتباری که حساب تازه با وارد کردن کد دعوت می‌گیرد (یک بار، تا ۳۰ روز پس از شروع و پیش از اولین خرید).'],
        'invite_reward_verify' => ['5', 'int', 'billing', 'جایزه‌ی دعوت‌کننده: تأیید اولین دارایی', 'وقتی دعوت‌شده مالکیت اولین دارایی‌اش را تأیید کرد. ۰ یعنی هیچ.'],
        'invite_reward_buy' => ['30', 'int', 'billing', 'جایزه‌ی دعوت‌کننده: اولین خرید', 'وقتی دعوت‌شده اولین بسته‌ی اعتبارش را پرداخت کرد. کمتر از اعتبار کوچک‌ترین بسته بگذارید تا خرید ساختگی به‌صرفه نباشد. ۰ یعنی هیچ.'],
        'invite_month_cap' => ['10', 'int', 'billing', 'سقف دعوت در ۳۰ روز', 'هر حساب در ۳۰ روز حداکثر این تعداد دعوت‌شده‌ی تازه می‌تواند داشته باشد (جلوی سوءاستفاده).'],
        'auto_topup_enabled' => ['0', 'bool', 'billing', 'شارژ خودکار', 'روشن: مشتری می‌تواند بخواهد وقتی اعتبارش کم شد فاکتور بسته‌ی انتخابی‌اش خودکار ساخته شود. چیزی خودکار کسر نمی‌شود؛ فقط فاکتور ساخته و خبر داده می‌شود. پیش‌فرض: خاموش.'],
        'auto_topup_month_cap' => ['2', 'int', 'billing', 'سقف فاکتور خودکار در ۳۰ روز', 'برای هر حساب. تا فاکتور خودکار قبلی پرداخت یا لغو نشود، فاکتور تازه ساخته نمی‌شود.'],

        // advanced mode: customers build their own scans from allowed tools
        'advanced_enabled' => ['0', 'bool', 'advanced', 'اسکن سفارشی مشتری', 'روشن: مشتری در صفحه‌ی «اسکن سفارشی» از ابزارهای مجاز، اسکن خودش را می‌سازد، ذخیره می‌کند و مثل هر اسکن دیگر اجرا یا زمان‌بندی می‌کند. قانون‌های مالکیت، فهرست ممنوع و CDN همان است. پیش‌فرض: خاموش.'],
        'advanced_plan_only' => ['1', 'bool', 'advanced', 'فقط برای حساب‌های دارای پلن', 'روشن: فقط حسابی که پلن فعال دارد اسکن سفارشی می‌سازد. خاموش: همه‌ی حساب‌هایی که بخش را می‌بینند. پیش‌فرض: روشن.'],
        'advanced_tools' => ['nuclei,katana,zap,nmap', 'csv', 'advanced', 'ابزارهای مجاز', 'نام ابزارها با ویرگول، از: gau, katana, ffuf, dirsearch, arjun, nmap, nuclei, zap, wpscan, acunetix. ابزار «پرفشار» (ffuf، dirsearch، arjun، acunetix) درخواست زیادی به هدف می‌فرستد؛ با احتیاط اضافه کنید. ابزار کلیددار فقط وقتی دیده می‌شود که کلیدش در «راه‌اندازی موتورها» باشد.'],
        'advanced_tool_costs' => ['{}', 'json', 'advanced', 'هزینه‌ی هر ابزار (اعتبار)', 'هزینه‌ی اسکن سفارشی = جمع هزینه‌ی ابزارهایش برای هر دارایی. پیش‌فرض‌ها: gau 2، katana 4، arjun 4، nmap 4، nuclei 6، zap 6، ffuf 6، dirsearch 6، wpscan 6، acunetix 60. برای تغییر: {"nuclei":8}.'],
        'advanced_max' => ['10', 'int', 'advanced', 'سقف اسکن سفارشی هر حساب', 'هر حساب چند اسکن سفارشی ذخیره‌شده می‌تواند داشته باشد.'],

        // the assistant: a Persian chat that answers from the account's data and prepares work the customer confirms
        'assistant_enabled' => ['0', 'bool', 'assistant', 'دستیار امنیت', 'کلید اصلی. روشن: حساب‌هایی که پایین مشخص می‌کنید صفحه‌ی «دستیار امنیت» را می‌بینند: گفت‌وگوی فارسی که از داده‌ی همان حساب جواب می‌دهد و کارها را آماده می‌کند. مدل و کلید همان «هوش مصنوعی» در «راه‌اندازی موتورها» است. پیش‌فرض: خاموش.'],
        'assistant_all' => ['0', 'bool', 'assistant', 'برای همه‌ی حساب‌ها', 'روشن: هر حسابی که بخش امنیت را می‌بیند دستیار را هم دارد. خاموش: فقط گروه‌ها و حساب‌های دو فهرست پایین. پیش‌فرض: خاموش.'],
        'assistant_groups' => ['', 'csv', 'assistant', 'گروه‌های مشتری دارای دستیار', 'شناسه‌ی گروه‌های مشتری WHMCS، جداشده با ویرگول.'],
        'assistant_clients' => ['', 'csv', 'assistant', 'حساب‌های دارای دستیار', 'شماره‌ی حساب مشتری‌ها، جداشده با ویرگول (برای آزمایش یا مشتری خاص).'],
        'assistant_off' => ['', 'csv', 'assistant', 'حساب‌های بی دستیار', 'شماره‌ی حساب‌هایی که دستیار برایشان خاموش بماند، حتی اگر گروهشان یا «همه» روشن باشد.'],
        'assistant_actions' => ['1', 'bool', 'assistant', 'دستیار کار هم انجام دهد', 'روشن: دستیار می‌تواند افزودن دارایی، بررسی مالکیت، اسکن، زمان‌بندی، تغییر وضعیت یافته و گزارش را آماده کند؛ هر کار فقط پس از «تأیید و انجام» مشتری و از همان قاعده‌های صفحه‌ها (مالکیت، فهرست ممنوع، پلن، اعتبار) اجرا می‌شود. خاموش: فقط جواب می‌دهد. پیش‌فرض: روشن.'],
        'assistant_cost' => ['0', 'int', 'assistant', 'هزینه‌ی هر پیام (اعتبار)', 'اعتباری که هر پیام مشتری به دستیار کم می‌کند؛ اگر دستیار جواب ندهد برمی‌گردد. ۰ = رایگان. کارهایی که دستیار آماده می‌کند هزینه‌ی خودشان را دارند.'],
        'assistant_daily' => ['30', 'int', 'assistant', 'سقف پیام روزانه‌ی هر حساب', 'هر حساب در یک روز چند پیام می‌تواند بفرستد (سقف هزینه‌ی مدل).'],

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

        'nuclei_rate' => ['10', 'int', 'scans', 'درخواست در ثانیه (nuclei، katana، ffuf)', 'سقف درخواست‌های ابزارهای اسکن به هر هدف. پیش‌فرض خود OASM ۱۵۰ است که فایروال و محافظ وب هدف را وادار به مسدود کردن اسکنر می‌کند. ۱ تا ۱۵۰. تغییر این چهار تنظیم از اسکن بعدی هر دارایی اثر دارد.'],
        'nuclei_concurrency' => ['5', 'int', 'scans', 'nuclei: الگوی همزمان', 'چند الگو همزمان اجرا شود. ۱ تا ۵۰.'],
        'nuclei_exclude_tags' => ['dos,fuzz,intrusive', 'csv', 'scans', 'nuclei: برچسب‌های کنارگذاشته', 'الگوهایی با این برچسب‌ها اجرا نمی‌شوند (پرفشار یا مخرب).'],
        'nuclei_interactsh' => ['0', 'bool', 'scans', 'nuclei: کشف خارج از باند (interactsh)', 'روشن: برای یافتن SSRF و RCE کور، هدف وادار می‌شود به سرور عمومی interactsh وصل شود. پیش‌فرض خاموش.'],

        // extra checks, light monitoring and vulnerability intelligence
        'reputation_lists' => [
            "# هر خط: domain یا ip، نام zone، و نام فهرست\nip bl.spamcop.net SpamCop\n# Spamhaus برای استفاده‌ی تجاری کلید رایگان یا پولی DQS می‌خواهد (spamhaus.com/dqs):\n# domain KEY.dbl.dq.spamhaus.net Spamhaus DBL\n# ip KEY.zen.dq.spamhaus.net Spamhaus ZEN\n# domain multi.surbl.org SURBL",
            'text', 'checks', 'فهرست‌های سیاه (DNSBL)',
            'بررسی سلامت پایه نام دامنه و IPهای خود مشتری را در این فهرست‌ها می‌پرسد (یک پرس‌وجوی DNS برای هر فهرست). دامنه‌ای که در فهرست بدافزار یا فیشینگ باشد یافته‌ی «بحرانی» می‌گیرد. هر خط: domain یا ip، zone و نام. پاسخ‌های «پرس‌وجو رد شد» (مثل 127.255.255.254 در Spamhaus) نادیده گرفته می‌شوند. شرایط استفاده‌ی هر فهرست را بخوانید؛ Spamhaus و SURBL برای کار تجاری کلید یا اشتراک می‌خواهند. خالی یعنی خاموش.',
        ],
        'monitor_enabled' => ['0', 'bool', 'checks', 'پایش در دسترس بودن و SSL', 'روشن: دامنه‌های تأییدشده‌ی مشتری‌ها هر چند دقیقه یک بار باز می‌شوند (یک درخواست GET به صفحه‌ی اول) و گواهی SSL روزی یک بار سنجیده می‌شود. از دسترس خارج شدن (دو بار پشت سر هم)، برگشتن و نزدیک شدن انقضای گواهی خبر داده می‌شود. رایگان است و اعتبار مصرف نمی‌کند. پیش‌فرض: خاموش.'],
        'monitor_minutes' => ['30', 'int', 'checks', 'فاصله‌ی پایش (دقیقه)', 'هر دامنه هر چند دقیقه یک بار سنجیده شود. کمتر از ۵ پذیرفته نمی‌شود (کار پس‌زمینه هر ۵ دقیقه اجرا می‌شود).'],
        'monitor_ssl_days' => ['14', 'int', 'checks', 'هشدار انقضای SSL (روز)', 'وقتی تا انقضای گواهی این تعداد روز یا کمتر مانده باشد، یک بار خبر داده می‌شود.'],
        'intel_enabled' => ['0', 'bool', 'checks', 'اولویت با KEV و EPSS', 'روشن: کار پس‌زمینه روزی یک بار فهرست آسیب‌پذیری‌های در حال بهره‌برداری (CISA KEV) و احتمال بهره‌برداری (FIRST EPSS) را برای CVEهای یافته‌های باز می‌گیرد. یافته‌ی KEV برچسب «در حال بهره‌برداری» می‌گیرد، امتیاز دارایی را مثل یافته‌ی بحرانی به ۴۹ محدود می‌کند و یک بار خبر داده می‌شود. فقط شناسه‌ی CVE فرستاده می‌شود، نه داده‌ی مشتری. پیش‌فرض: خاموش.'],
        'kev_url' => ['https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json', 'string', 'checks', 'نشانی فهرست KEV', 'نسخه‌ی GitHub خود CISA. نشانی اصلی cisa.gov از بیرون آمریکا گاهی 403 می‌دهد.'],
        'epss_url' => ['https://api.first.org/data/v1/epss', 'string', 'checks', 'نشانی API EPSS', 'API رایگان FIRST؛ هر بار تا ۱۰۰ CVE پرسیده می‌شود.'],

        // support, offers and the public scanner page
        'support_dept' => ['0', 'int', 'support', 'دپارتمان تیکت «کمک از پشتیبانی»', 'شناسه‌ی دپارتمان پشتیبانی WHMCS. اگر بیشتر از ۰ باشد، صفحه‌ی هر یافته پیوند «از پشتیبانی کمک بخواهید» دارد که فرم تیکت همان دپارتمان را با عنوان و خلاصه‌ی یافته باز می‌کند (مشتری خودش می‌فرستد). ۰ یعنی پنهان.'],
        'offers' => ['', 'text', 'support', 'پیشنهاد خدمت کنار راهکار', 'هر خط: کلید راهکار | متن | نشانی. مثلاً «tls-expiring | گواهی SSL با تمدید خودکار از مارال کلاد | https://maral.cloud/ssl». روی صفحه‌ی یافته‌ای که همان راهکار را دارد، یک کادر کوچک «راه آسان‌تر» نشان داده می‌شود. خالی یعنی هیچ.'],
        'abuse_email' => ['', 'string', 'support', 'ایمیل گزارش سوءاستفاده (abuse)', 'روی صفحه‌ی عمومی «درباره‌ی اسکنر» برای صاحبان سایت‌هایی که اسکن را دیده‌اند نمایش داده می‌شود.'],
        'scanner_ips' => ['', 'text', 'support', 'IPهای اسکنر', 'IP سرور WHMCS و کارگرهای OASM و Osmedeus، هر خط یکی. روی صفحه‌ی «درباره‌ی اسکنر» می‌آید تا مشتری بتواند آن‌ها را در فایروال یا WAF خودش مجاز کند.'],

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
        'acunetix_url' => ['', 'string', 'engines', 'آدرس Acunetix', 'مثل https://acunetix.example.com:3443 . کارگرهای OASM باید به آن دسترسی داشته باشند.'],
        'acunetix_key' => ['', 'secret', 'engines', 'کلید API Acunetix', 'از Profile › API Key در Acunetix. رمزنگاری‌شده ذخیره می‌شود و در فضای کار هر مشتری در OASM به‌عنوان پروفایل ابزار گذاشته می‌شود. تا خالی است «اسکن حرفه‌ای» اجرا نمی‌شود.'],
        'acunetix_verify_tls' => ['1', 'bool', 'engines', 'بررسی گواهی Acunetix', 'خاموش برای گواهی خودامضای پیش‌فرض Acunetix.'],
        'wpscan_token' => ['', 'secret', 'engines', 'توکن WPScan', 'از wpscan.com (استفاده‌ی تجاری لایسنس پولی می‌خواهد). تا خالی است «اسکن وردپرس» اجرا نمی‌شود.'],
        'tool_configs' => ['{}', 'json', 'engines', 'تنظیم پیشرفته‌ی ابزارها', 'JSON: برای هر ابزار، کلیدهایی که می‌خواهید از پیش‌فرض ملایم MC-Sec عوض شود؛ مثلاً {"zap":{"maxSpiderDuration":10},"katana":{"depth":4}}. نام کلیدها همان طرح‌واره‌ی ابزار در OASM است. رمزها و نشانی‌ها این‌جا پذیرفته نمی‌شوند. خالی: {}'],
        'custom_profiles' => ['[]', 'json', 'scans', 'نوع‌های اسکن سفارشی', 'در صفحه‌ی «قیمت و پلن» ساخته می‌شوند.'],

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
