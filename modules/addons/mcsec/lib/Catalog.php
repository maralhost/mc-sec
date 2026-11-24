<?php

declare(strict_types=1);

namespace McSec;

/**
 * The scan products customers choose from. Each profile names its engine, the asset kinds it accepts, its credit
 * cost per asset and, for OASM, the tools of its pipeline in order (a profile is data: a tool OASM gains needs no
 * new code, only a line in TOOLS and a profile). Admins override enabled/credits/workflow/label in the setting
 * `profiles` and add their own profiles in `custom_profiles`; anything else comes from DEFAULTS.
 * `free` = available without a plan. `cat` = the group a customer finds it under (CATEGORIES); `options` = named,
 * gentler settings of a tool for this profile (the same mechanism as a customer's own scan: Recipes::apply only ever
 * lowers a rate, a depth or a list). BUNDLES are ready-made picks of several profiles for one click.
 * Since 0.16.0 the catalogue is wide (both engines, every tool they have) but the page that offers it stays short:
 * three bundles first, everything else by category behind one click.
 * OASM is the product engine. The two Osmedeus profiles (recon, deep) are off by default since 0.3.0: its tools overlap
 * OASM's, and two engines reporting the same issue made duplicate findings. An admin can still turn them on.
 */
final class Catalog
{
    /**
     * OASM connector tools MC-Sec may put in a pipeline. category and input are OASM's own (GET /api/tools, read live
     * on 0.12.1); kinds = asset kinds the tool accepts; risk: passive (asks third parties only), light (a polite
     * crawl or template scan), heavy (many requests, brute force or an active scanner); needs = a secret setting the
     * tool cannot run without.
     */
    public const TOOLS = [
        'nuclei' => ['label' => 'Nuclei', 'category' => 'vulnerabilities', 'input' => ['host', 'web'], 'kinds' => ['domain', 'ip', 'cidr'], 'risk' => 'light', 'what' => 'آسیب‌پذیری‌های شناخته‌شده و پیکربندی نادرست'],
        'zap' => ['label' => 'ZAP', 'category' => 'vulnerabilities', 'input' => ['web', 'host'], 'kinds' => ['domain', 'ip', 'cidr'], 'risk' => 'light', 'what' => 'آزمون وب (حالت baseline: خزیدن و بررسی منفعل)'],
        'katana' => ['label' => 'Katana', 'category' => 'url_discovery', 'input' => ['host'], 'kinds' => ['domain'], 'risk' => 'light', 'what' => 'خزیدن سایت و یافتن صفحه‌ها'],
        'gau' => ['label' => 'gau', 'category' => 'url_discovery', 'input' => ['host'], 'kinds' => ['domain'], 'risk' => 'passive', 'what' => 'نشانی‌های قدیمی از آرشیوهای عمومی'],
        'nmap' => ['label' => 'Nmap', 'category' => 'ports_scanner', 'input' => ['host'], 'kinds' => ['ip', 'cidr'], 'risk' => 'heavy', 'what' => 'سرویس‌ها و درگاه‌ها'],
        'ffuf' => ['label' => 'ffuf', 'category' => 'url_discovery', 'input' => ['web', 'host'], 'kinds' => ['domain', 'ip'], 'risk' => 'heavy', 'what' => 'کشف پوشه و فایل پنهان'],
        'dirsearch' => ['label' => 'dirsearch', 'category' => 'url_discovery', 'input' => ['web', 'host'], 'kinds' => ['domain', 'ip'], 'risk' => 'heavy', 'what' => 'کشف پوشه و فایل پنهان'],
        'arjun' => ['label' => 'Arjun', 'category' => 'url_discovery', 'input' => ['url', 'web'], 'kinds' => ['domain', 'ip'], 'risk' => 'heavy', 'what' => 'کشف پارامترهای پنهان'],
        'wpscan' => ['label' => 'WPScan', 'category' => 'vulnerabilities', 'input' => ['web', 'host'], 'kinds' => ['domain'], 'risk' => 'light', 'what' => 'وردپرس: هسته، افزونه‌ها و قالب‌ها', 'needs' => 'wpscan_token'],
        'acunetix' => ['label' => 'Acunetix', 'category' => 'vulnerabilities', 'input' => ['web', 'host'], 'kinds' => ['domain', 'ip'], 'risk' => 'heavy', 'what' => 'اسکنر تجاری وب', 'needs' => 'acunetix_key'],
        // in OASM's connector manifest, not yet run by us on staging: their profiles ship switched off
        'nikto' => ['label' => 'Nikto', 'category' => 'vulnerabilities', 'input' => ['web', 'host'], 'kinds' => ['domain', 'ip'], 'risk' => 'heavy', 'what' => 'پیکربندی نادرست و فایل‌های خطرناک وب‌سرور'],
        'rustscan' => ['label' => 'RustScan', 'category' => 'ports_scanner', 'input' => ['host'], 'kinds' => ['ip', 'cidr'], 'risk' => 'heavy', 'what' => 'همه‌ی ۶۵ هزار درگاه، سریع'],
    ];
    public const RISK = ['passive' => 'منفعل', 'light' => 'سبک', 'heavy' => 'پرفشار'];

    /** The groups of the scan chooser, in order: key => [name, one line that says when to pick it, icon]. */
    public const CATEGORIES = [
        'start' => ['شروع سریع', 'یک نگاه رایگان و بی‌خطر به وضعیت کلی.', 'heart'],
        'discover' => ['شناسایی و سطح حمله', 'چه چیزهایی از شما روی اینترنت دیده می‌شود؟', 'radar'],
        'vuln' => ['آسیب‌پذیری', 'ضعف‌های شناخته‌شده‌ای که مهاجم دنبالشان می‌گردد.', 'bug'],
        'web' => ['وب‌سایت و برنامه‌ی وب', 'صفحه‌ها، فرم‌ها، پوشه‌های پنهان و سامانه‌ی مدیریت محتوا.', 'globe'],
        'server' => ['سرور و شبکه', 'درگاه‌ها و سرویس‌های باز روی IPهای خودتان.', 'server'],
        'full' => ['ارزیابی کامل', 'چند ابزار پشت سر هم، برای پیش از راه‌اندازی یا ممیزی.', 'layers'],
        'custom' => ['اسکن‌های ویژه', 'ترکیب‌هایی که برای شما ساخته شده است.', 'sparkle'],
    ];

    /**
     * Ready-made picks: key => [name, what it is for, profiles in the order they run]. A bundle costs the sum of its
     * profiles (no price of its own), and a profile that is switched off, not in the account's plan or not for the
     * kind of the chosen asset is simply left out.
     */
    public const BUNDLES = [
        'b_quick' => ['نگاه سریع', 'رایگان و چند دقیقه‌ای: گواهی، هدرها، ایمیل و درگاه‌های پرخطر.', ['hygiene']],
        'b_standard' => ['بررسی استاندارد', 'پیشنهاد ما برای بیشتر سایت‌ها: سلامت پایه، هر چه از شما روی اینترنت دیده می‌شود، و آسیب‌پذیری‌های شناخته‌شده.', ['hygiene', 'surface', 'vuln']],
        'b_full' => ['بررسی کامل', 'همه‌ی استاندارد، به‌اضافه‌ی خزیدن و آزمون صفحه‌به‌صفحه‌ی سایت و سرویس‌های سرور.', ['hygiene', 'surface', 'vuln', 'web', 'services']],
    ];
    public const DEFAULTS = [
        'hygiene' => [
            'cat' => 'start', 'label' => 'بررسی سلامت پایه', 'engine' => 'builtin', 'credits' => 0, 'kinds' => ['domain', 'ip'], 'free' => true, 'enabled' => true,
            'eta' => 'کمتر از ۲ دقیقه', 'depth' => 1, 'icon' => 'heart',
            'desc' => 'گواهی SSL و TLS، رفتن خودکار به HTTPS، هدرهای امنیتی و کوکی‌ها، SPF و DMARC، رکورد CAA و درگاه‌های پرخطرِ باز. سریع و بی‌خطر.',
        ],
        'surface' => [
            'cat' => 'discover', 'label' => 'کشف سطح حمله', 'engine' => 'oasm', 'credits' => 2, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => true, 'enabled' => true,
            'eta' => '۱۰ تا ۴۰ دقیقه', 'depth' => 2, 'icon' => 'radar',
            'desc' => 'زیردامنه‌ها، IPها، درگاه‌ها و سرویس‌های باز، فناوری‌ها و گواهی‌ها را پیدا می‌کند و تغییرشان را از اسکن قبلی نشان می‌دهد.',
        ],
        'vuln' => [
            'cat' => 'vuln', 'label' => 'اسکن آسیب‌پذیری', 'engine' => 'oasm', 'tools' => ['nuclei'], 'credits' => 6, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => true, 'enabled' => true,
            'eta' => '۲۰ دقیقه تا ۲ ساعت', 'depth' => 3, 'icon' => 'bug',
            'desc' => 'با هزاران الگوی Nuclei آسیب‌پذیری‌های شناخته‌شده (CVE)، پیکربندی نادرست، پنل‌ها و فایل‌های حساسِ در دسترس را می‌سنجد.',
        ],
        'web' => [
            'cat' => 'web', 'label' => 'اسکن عمیق وب', 'engine' => 'oasm', 'tools' => ['katana', 'zap'], 'credits' => 10, 'kinds' => ['domain'], 'free' => true, 'enabled' => true,
            'eta' => '۲۰ تا ۶۰ دقیقه', 'depth' => 3, 'icon' => 'globe',
            'desc' => 'سایت را صفحه‌به‌صفحه می‌خزد و با ZAP مشکل‌های رایج وب (هدرها، کوکی‌ها، فرم‌ها، نشت اطلاعات) را در همه‌ی صفحه‌ها می‌سنجد. بی حمله‌ی فعال.',
        ],
        'urls' => [
            'cat' => 'discover', 'label' => 'نشانی‌های قدیمی و لورفته', 'engine' => 'oasm', 'tools' => ['gau'], 'credits' => 2, 'kinds' => ['domain'], 'free' => true, 'enabled' => false,
            'eta' => '۵ تا ۲۰ دقیقه', 'depth' => 1, 'icon' => 'link',
            'desc' => 'نشانی‌هایی از سایت شما که در آرشیوهای عمومی اینترنت مانده‌اند (پنل‌های قدیمی، فایل‌های پشتیبان، مسیرهای فراموش‌شده). هیچ درخواستی به سایت شما نمی‌فرستد.',
        ],
        'services' => [
            'cat' => 'server', 'label' => 'سرویس‌ها و درگاه‌های سرور', 'engine' => 'oasm', 'tools' => ['nmap'], 'credits' => 4, 'kinds' => ['ip', 'cidr'], 'free' => true, 'enabled' => true,
            'eta' => '۱۰ تا ۳۰ دقیقه', 'depth' => 2, 'icon' => 'server',
            'desc' => 'هزار درگاه رایج سرور شما را با Nmap می‌سنجد و سرویس پشت هر کدام را نشان می‌دهد. فقط برای IPهای خودتان.',
        ],
        'wordpress' => [
            'cat' => 'web', 'label' => 'اسکن وردپرس', 'engine' => 'oasm', 'tools' => ['wpscan'], 'credits' => 6, 'kinds' => ['domain'], 'free' => true, 'enabled' => false,
            'eta' => '۱۰ تا ۳۰ دقیقه', 'depth' => 3, 'icon' => 'bug',
            'desc' => 'نسخه‌ی وردپرس، افزونه‌ها و قالب‌ها و آسیب‌پذیری‌های شناخته‌شده‌ی هر کدام.',
        ],
        'pro' => [
            'cat' => 'full', 'label' => 'اسکن حرفه‌ای (Acunetix)', 'engine' => 'oasm', 'tools' => ['acunetix'], 'credits' => 60, 'kinds' => ['domain', 'ip'], 'free' => false, 'enabled' => false,
            'eta' => '۱ تا ۶ ساعت', 'depth' => 4, 'icon' => 'layers',
            'desc' => 'اسکن کامل وب با موتور تجاری Acunetix: تزریق SQL، XSS و صدها آزمون فعال دیگر. درخواست زیادی به سایت می‌فرستد؛ برای پیش از راه‌اندازی یا ممیزی.',
        ],
        'recon' => [
            'cat' => 'discover', 'label' => 'شناسایی سریع', 'engine' => 'osmedeus', 'workflow' => 'fast', 'credits' => 8, 'kinds' => ['domain'], 'free' => false, 'enabled' => false,
            'eta' => '۲۰ تا ۶۰ دقیقه', 'depth' => 2, 'icon' => 'search',
            'desc' => 'شناسایی گسترده‌ی زیردامنه‌ها، سرویس‌های وب، اسکرین‌شات و فناوری‌ها با Osmedeus.',
        ],
        'deep' => [
            'cat' => 'full', 'label' => 'ارزیابی عمیق', 'engine' => 'osmedeus', 'workflow' => 'general', 'credits' => 30, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => false, 'enabled' => false,
            'eta' => '۲ تا ۸ ساعت', 'depth' => 4, 'icon' => 'layers',
            'desc' => 'همه‌ی مراحل: شناسایی، اسکن درگاه، کشف محتوا، آسیب‌پذیری وب و گزارش کامل. برای پیش از راه‌اندازی یا ممیزی.',
        ],

        // 0.16.0 ── more ways to use the same tools. On by default only when every tool is one we already run and the
        // profile is no heavier than what was on before; the rest wait for the admin in «قیمت و پلن».
        'vuln_quick' => [
            'cat' => 'vuln', 'label' => 'آسیب‌پذیری‌های جدی (سریع)', 'engine' => 'oasm', 'tools' => ['nuclei'], 'options' => ['nuclei' => ['severity' => ['high', 'critical']]],
            'credits' => 3, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => true, 'enabled' => true, 'eta' => '۱۰ تا ۴۰ دقیقه', 'depth' => 2, 'icon' => 'alert',
            'desc' => 'همان اسکن آسیب‌پذیری، ولی فقط الگوهای با شدت بالا و بحرانی: سریع‌تر و ارزان‌تر، برای بررسی‌های پرتکرار.',
        ],
        'web_quick' => [
            'cat' => 'web', 'label' => 'اسکن سریع وب', 'engine' => 'oasm', 'tools' => ['katana', 'zap'], 'options' => ['katana' => ['depth' => 1]],
            'credits' => 5, 'kinds' => ['domain'], 'free' => true, 'enabled' => true, 'eta' => '۱۰ تا ۲۵ دقیقه', 'depth' => 2, 'icon' => 'globe',
            'desc' => 'صفحه‌ی اول و پیوندهایش را می‌خزد و با ZAP می‌سنجد. برای سایت‌های کوچک یا بررسی پس از هر تغییر.',
        ],
        'services_quick' => [
            'cat' => 'server', 'label' => 'درگاه‌های رایج سرور (سریع)', 'engine' => 'oasm', 'tools' => ['nmap'], 'options' => ['nmap' => ['topPorts' => 100]],
            'credits' => 2, 'kinds' => ['ip', 'cidr'], 'free' => true, 'enabled' => true, 'eta' => '۵ تا ۱۵ دقیقه', 'depth' => 1, 'icon' => 'server',
            'desc' => 'صد درگاه پرکاربرد سرور شما و سرویس پشت هر کدام. فقط برای IPهای خودتان.',
        ],
        'full_web' => [
            'cat' => 'full', 'label' => 'ارزیابی کامل وب‌سایت', 'engine' => 'oasm', 'tools' => ['katana', 'nuclei', 'zap'],
            'credits' => 14, 'kinds' => ['domain'], 'free' => true, 'enabled' => true, 'eta' => '۴۰ دقیقه تا ۳ ساعت', 'depth' => 4, 'icon' => 'layers',
            'desc' => 'یک بار سایت را می‌خزد و همه‌ی صفحه‌های پیداشده را هم با الگوهای Nuclei و هم با ZAP می‌سنجد. کامل‌ترین اسکن بی حمله‌ی فعال.',
        ],
        'content' => [
            'cat' => 'web', 'label' => 'کشف پوشه و فایل پنهان', 'engine' => 'oasm', 'tools' => ['ffuf'],
            'credits' => 5, 'kinds' => ['domain', 'ip'], 'free' => true, 'enabled' => false, 'eta' => '۱۰ تا ۳۰ دقیقه', 'depth' => 3, 'icon' => 'search',
            'desc' => 'نام‌های رایج پوشه و فایل را روی سایت می‌آزماید تا پنل مدیریت، فایل پشتیبان و مسیر فراموش‌شده پیدا شود. درخواست زیادی می‌فرستد.',
        ],
        'content_deep' => [
            'cat' => 'web', 'label' => 'کشف محتوای پنهان (عمیق)', 'engine' => 'oasm', 'tools' => ['dirsearch', 'arjun'],
            'credits' => 8, 'kinds' => ['domain', 'ip'], 'free' => false, 'enabled' => false, 'eta' => '۳۰ دقیقه تا ۲ ساعت', 'depth' => 4, 'icon' => 'search',
            'desc' => 'فهرست بزرگ‌تری از مسیرها و پسوندها، و بعد پارامترهای پنهان صفحه‌ها. برای ممیزی؛ روی سرور ضعیف اجرا نکنید.',
        ],
        'webserver' => [
            'cat' => 'web', 'label' => 'پیکربندی وب‌سرور (Nikto)', 'engine' => 'oasm', 'tools' => ['nikto'],
            'credits' => 5, 'kinds' => ['domain', 'ip'], 'free' => true, 'enabled' => false, 'eta' => '۱۵ تا ۴۵ دقیقه', 'depth' => 3, 'icon' => 'server',
            'desc' => 'هزاران فایل، اسکریپت و تنظیم خطرناک شناخته‌شده‌ی وب‌سرور و نسخه‌های قدیمی نرم‌افزار را می‌سنجد.',
        ],
        'wordpress_full' => [
            'cat' => 'web', 'label' => 'وردپرس کامل', 'engine' => 'oasm', 'tools' => ['wpscan', 'nuclei'],
            'credits' => 10, 'kinds' => ['domain'], 'free' => true, 'enabled' => false, 'eta' => '۳۰ تا ۹۰ دقیقه', 'depth' => 3, 'icon' => 'bug',
            'desc' => 'هسته، افزونه‌ها و قالب‌های وردپرس با WPScan، و بعد آسیب‌پذیری‌های شناخته‌شده با الگوهای Nuclei.',
        ],
        'ports_all' => [
            'cat' => 'server', 'label' => 'همه‌ی درگاه‌های سرور', 'engine' => 'oasm', 'tools' => ['rustscan', 'nmap'],
            'credits' => 8, 'kinds' => ['ip', 'cidr'], 'free' => false, 'enabled' => false, 'eta' => '۲۰ دقیقه تا ۲ ساعت', 'depth' => 4, 'icon' => 'server',
            'desc' => 'هر ۶۵ هزار درگاه را می‌سنجد و سرویس پشت درگاه‌های باز را می‌شناسد؛ برای پیدا کردن سرویسی که روی درگاه غیرمعمول مانده است.',
        ],
        'server_full' => [
            'cat' => 'full', 'label' => 'ارزیابی کامل سرور', 'engine' => 'oasm', 'tools' => ['nmap', 'nuclei'],
            'credits' => 9, 'kinds' => ['ip', 'cidr'], 'free' => true, 'enabled' => false, 'eta' => '۳۰ دقیقه تا ۲ ساعت', 'depth' => 3, 'icon' => 'layers',
            'desc' => 'هزار درگاه رایج و سرویس‌هایشان، و بعد آسیب‌پذیری‌های شناخته‌شده روی همان سرور.',
        ],
        'osm_lite' => [
            'cat' => 'discover', 'label' => 'شناسایی دامنه (سبک)', 'engine' => 'osmedeus', 'workflow' => 'domain-lite', 'credits' => 6, 'kinds' => ['domain'], 'free' => false, 'enabled' => false,
            'eta' => '۱۵ تا ۴۵ دقیقه', 'depth' => 2, 'icon' => 'search',
            'desc' => 'زیردامنه‌ها، سرویس‌های وب زنده و فناوری‌ها با Osmedeus؛ سبک‌ترین جریان آن.',
        ],
        'osm_standard' => [
            'cat' => 'discover', 'label' => 'شناسایی دامنه (استاندارد)', 'engine' => 'osmedeus', 'workflow' => 'domain-standard', 'credits' => 15, 'kinds' => ['domain'], 'free' => false, 'enabled' => false,
            'eta' => '۱ تا ۳ ساعت', 'depth' => 3, 'icon' => 'search',
            'desc' => 'شناسایی کامل دامنه با Osmedeus: زیردامنه‌ها از منابع بیشتر، درگاه‌ها، اسکرین‌شات و نشانی‌های آرشیوی.',
        ],
        'osm_extensive' => [
            'cat' => 'full', 'label' => 'ارزیابی گسترده‌ی دامنه', 'engine' => 'osmedeus', 'workflow' => 'domain-extensive', 'credits' => 45, 'kinds' => ['domain'], 'free' => false, 'enabled' => false,
            'eta' => '۴ تا ۱۲ ساعت', 'depth' => 4, 'icon' => 'layers',
            'desc' => 'سنگین‌ترین جریان Osmedeus روی یک دامنه: همه‌ی مرحله‌های شناسایی، کشف محتوا و آسیب‌پذیری روی همه‌ی زیردامنه‌ها.',
        ],
        'osm_cidr' => [
            'cat' => 'server', 'label' => 'شناسایی بازه‌ی IP', 'engine' => 'osmedeus', 'workflow' => 'cidr', 'credits' => 12, 'kinds' => ['cidr'], 'free' => false, 'enabled' => false,
            'eta' => '۳۰ دقیقه تا ۳ ساعت', 'depth' => 3, 'icon' => 'server',
            'desc' => 'میزبان‌های زنده، درگاه‌ها و سرویس‌های وب یک بازه‌ی IP با Osmedeus.',
        ],
        'osm_web' => [
            'cat' => 'web', 'label' => 'تحلیل یک سایت (Osmedeus)', 'engine' => 'osmedeus', 'workflow' => 'web-analysis', 'credits' => 10, 'kinds' => ['domain'], 'free' => false, 'enabled' => false,
            'eta' => '۳۰ تا ۹۰ دقیقه', 'depth' => 3, 'icon' => 'globe',
            'desc' => 'فقط همین یک سایت: خزیدن، کشف محتوا و آسیب‌پذیری وب، بی سر زدن به زیردامنه‌های دیگر.',
        ],
    ];

    /**
     * Profiles an admin built from OASM tools (setting custom_profiles). Each is checked again here: a known key
     * shape, known tools, and only asset kinds every one of its tools accepts.
     * @return array<string,array>
     */
    public static function custom(): array
    {
        $out = [];
        foreach (Settings::json('custom_profiles') as $c) {
            if (!is_array($c)) {
                continue;
            }
            $key = strtolower((string) ($c['key'] ?? ''));
            $tools = array_values(array_unique(array_filter(array_map('strval', (array) ($c['tools'] ?? [])), fn ($t) => isset(self::TOOLS[$t]))));
            if (!preg_match('~^c_[a-z0-9_]{2,24}$~', $key) || isset(self::DEFAULTS[$key]) || !$tools || count($tools) > 6) {
                continue;
            }
            $kinds = ['domain', 'ip', 'cidr'];
            foreach ($tools as $t) {
                $kinds = array_values(array_intersect($kinds, self::TOOLS[$t]['kinds']));
            }
            if (!$kinds) {
                continue;
            }
            $label = Text::name((string) ($c['label'] ?? ''), 80);
            $p = [
                'label' => $label !== '' ? $label : $key, 'engine' => 'oasm', 'tools' => $tools, 'credits' => max(0, (int) ($c['credits'] ?? 0)), 'kinds' => $kinds,
                'free' => !empty($c['free']), 'enabled' => !empty($c['enabled']), 'eta' => 'بسته به ابزارها', 'depth' => 3, 'icon' => 'layers', 'custom' => true, 'cat' => 'custom',
                'desc' => Text::name((string) ($c['desc'] ?? ''), 300),
            ];
            $p['depth'] = self::risk($p) === 'heavy' ? 4 : 3;
            if ($p['desc'] === '') {
                $p['desc'] = Lang::t('ابزارها: {tools}', ['tools' => Lang::join(array_map(fn ($t) => self::TOOLS[$t]['label'], $tools))]);
            }
            $out[$key] = $p;
        }
        return $out;
    }

    /** The heaviest risk class among a profile's tools ('' for profiles without tools). */
    public static function risk(array $profile): string
    {
        $risk = '';
        foreach ((array) ($profile['tools'] ?? []) as $t) {
            $r = self::TOOLS[$t]['risk'] ?? 'heavy';
            $risk = $r === 'heavy' || $risk === 'heavy' ? 'heavy' : ($r === 'light' || $risk === 'light' ? 'light' : 'passive');
        }
        return $risk;
    }

    /** @return array<string,array> enabled profiles (with overrides), in display order */
    public static function all(bool $includeDisabled = false): array
    {
        $over = Settings::json('profiles');
        $out = [];
        foreach (self::DEFAULTS + self::custom() as $key => $p) {
            $o = is_array($over[$key] ?? null) ? $over[$key] : [];
            foreach (['enabled' => 'bool', 'credits' => 'int', 'workflow' => 'string', 'label' => 'string', 'free' => 'bool'] as $f => $type) {
                if (array_key_exists($f, $o) && $o[$f] !== '' && $o[$f] !== null) {
                    $p[$f] = match ($type) {
                        'bool' => (bool) $o[$f],
                        'int' => max(0, (int) $o[$f]),
                        default => Text::name((string) $o[$f], 80),
                    };
                }
            }
            $p['key'] = $key;
            if ($p['enabled'] || $includeDisabled) {
                $out[$key] = $p;
            }
        }
        return $out;
    }

    /** A profile that can start a scan now (a customer's own scan, key u<id>, included). */
    public static function get(string $key): ?array
    {
        if (Recipes::idOf($key) > 0) {
            $p = Recipes::find($key);
            return $p && $p['enabled'] ? $p : null;
        }
        return self::all()[$key] ?? null;
    }

    /** Any profile a scan may have been made with: switched-off ones and removed customer scans too. */
    public static function find(string $key): ?array
    {
        return Recipes::idOf($key) > 0 ? Recipes::find($key) : (self::all(true)[$key] ?? null);
    }

    /** The name of a scan type in the current language (a name the admin or the customer wrote stays as written). */
    public static function label(string $key, string $default = ''): string
    {
        return Lang::t((string) (self::find($key)['label'] ?? ($default !== '' ? $default : $key)));
    }

    public static function engineLabel(string $engine): string
    {
        return ['builtin' => Lang::t('بررسی داخلی'), 'oasm' => 'OASM', 'osmedeus' => 'Osmedeus'][$engine] ?? $engine;
    }

    /** Profiles this account may run now (plan or free), for an asset kind ('' = any). */
    public static function forClient(int $clientId, string $kind = ''): array
    {
        $lim = Plans::limits($clientId);
        $out = [];
        foreach (self::all() as $k => $p) {
            if ($kind !== '' && !in_array($kind, $p['kinds'], true)) {
                continue;
            }
            $p['allowed'] = $p['free'] || in_array($k, $lim['open'], true) || ($lim['profiles'] !== null && in_array($k, $lim['profiles'], true));
            $p['full'] = (int) $p['credits'];
            $p['credits'] = Rules::cost($clientId, (int) $p['credits']); // what this account pays
            $out[$k] = $p;
        }
        // advanced mode: the account's own scans, and nobody else's
        if (Recipes::allowed($clientId)) {
            foreach (Recipes::forClient($clientId) as $row) {
                $p = Recipes::profile($row);
                if (!$p['enabled'] || ($kind !== '' && !in_array($kind, $p['kinds'], true))) {
                    continue;
                }
                $p['allowed'] = true;
                $p['full'] = (int) $p['credits'];
                $p['credits'] = Rules::cost($clientId, (int) $p['credits']);
                $out[$p['key']] = $p;
            }
        }
        return $out;
    }

    /**
     * The profiles of a list grouped for the chooser: category key => [key => profile], in the order of CATEGORIES;
     * a category with nothing in it is left out. A customer's own scans (u<id>) go under 'custom'.
     * @return array<string,array<string,array>>
     */
    public static function grouped(array $profiles): array
    {
        $out = array_fill_keys(array_keys(self::CATEGORIES), []);
        foreach ($profiles as $k => $p) {
            $cat = (string) ($p['cat'] ?? 'custom');
            $out[isset(self::CATEGORIES[$cat]) ? $cat : 'custom'][$k] = $p;
        }
        return array_filter($out);
    }

    /**
     * The bundles this account can use: each with the profiles of it that are on, allowed and runnable, and what they
     * cost together. A bundle left with fewer than its first profile is not offered.
     * @param array<string,array> $profiles Catalog::forClient() @return array<string,array{label:string,desc:string,profiles:string[],credits:int}>
     */
    public static function bundles(array $profiles): array
    {
        $out = [];
        foreach (self::BUNDLES as $key => [$label, $desc, $list]) {
            $have = array_values(array_filter($list, fn ($k) => isset($profiles[$k]) && !empty($profiles[$k]['allowed']) && Scans::engine((string) $profiles[$k]['engine'])->configured()));
            if (!$have || count($have) < min(2, count($list))) {
                continue;
            }
            $out[$key] = ['label' => $label, 'desc' => $desc, 'profiles' => $have, 'credits' => array_sum(array_map(fn ($k) => (int) $profiles[$k]['credits'], $have))];
        }
        // two bundles that came out the same (a small catalogue) are one choice, not two
        $seen = [];
        return array_filter($out, function ($b) use (&$seen) {
            $sig = implode(',', $b['profiles']);
            return isset($seen[$sig]) ? false : ($seen[$sig] = true);
        });
    }

    /** The profile keys a form asked for: ticked profiles plus the profiles of ticked bundles, once each, in catalogue order. @return string[] */
    public static function chosen(array $profiles, array $keys, array $bundleKeys): array
    {
        $want = array_fill_keys(array_map('strval', $keys), true);
        $bundles = self::bundles($profiles);
        foreach ($bundleKeys as $b) {
            foreach ($bundles[(string) $b]['profiles'] ?? [] as $k) {
                $want[$k] = true;
            }
        }
        return array_values(array_filter(array_keys($profiles), fn ($k) => isset($want[(string) $k])));
    }

    /** The credit cost of one profile on one asset (a CIDR costs per /28 block, at least 1×). */
    public static function cost(array $profile, object $asset): int
    {
        $base = (int) $profile['credits'];
        if ($asset->kind === 'cidr') {
            $bits = (int) explode('/', (string) $asset->value)[1];
            $blocks = max(1, intdiv(1 << (32 - $bits), 16));
            return $base * $blocks;
        }
        return $base;
    }
}
