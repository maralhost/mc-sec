<?php

declare(strict_types=1);

namespace McSec;

/**
 * The scan products customers choose from. Each profile names its engine, the asset kinds it accepts, its credit
 * cost per asset and, for OASM, the tools of its pipeline in order (a profile is data: a tool OASM gains needs no
 * new code, only a line in TOOLS and a profile). Admins override enabled/credits/workflow/label in the setting
 * `profiles` and add their own profiles in `custom_profiles`; anything else comes from DEFAULTS.
 * `free` = available without a plan.
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
    ];
    public const RISK = ['passive' => 'منفعل', 'light' => 'سبک', 'heavy' => 'پرفشار'];

    public const DEFAULTS = [
        'hygiene' => [
            'label' => 'بررسی سلامت پایه', 'engine' => 'builtin', 'credits' => 0, 'kinds' => ['domain', 'ip'], 'free' => true, 'enabled' => true,
            'eta' => 'کمتر از ۲ دقیقه', 'depth' => 1, 'icon' => 'heart',
            'desc' => 'گواهی SSL و TLS، رفتن خودکار به HTTPS، هدرهای امنیتی و کوکی‌ها، SPF و DMARC، رکورد CAA و درگاه‌های پرخطرِ باز. سریع و بی‌خطر.',
        ],
        'surface' => [
            'label' => 'کشف سطح حمله', 'engine' => 'oasm', 'credits' => 2, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => true, 'enabled' => true,
            'eta' => '۱۰ تا ۴۰ دقیقه', 'depth' => 2, 'icon' => 'radar',
            'desc' => 'زیردامنه‌ها، IPها، درگاه‌ها و سرویس‌های باز، فناوری‌ها و گواهی‌ها را پیدا می‌کند و تغییرشان را از اسکن قبلی نشان می‌دهد.',
        ],
        'vuln' => [
            'label' => 'اسکن آسیب‌پذیری', 'engine' => 'oasm', 'tools' => ['nuclei'], 'credits' => 6, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => true, 'enabled' => true,
            'eta' => '۲۰ دقیقه تا ۲ ساعت', 'depth' => 3, 'icon' => 'bug',
            'desc' => 'با هزاران الگوی Nuclei آسیب‌پذیری‌های شناخته‌شده (CVE)، پیکربندی نادرست، پنل‌ها و فایل‌های حساسِ در دسترس را می‌سنجد.',
        ],
        'web' => [
            'label' => 'اسکن عمیق وب', 'engine' => 'oasm', 'tools' => ['katana', 'zap'], 'credits' => 10, 'kinds' => ['domain'], 'free' => true, 'enabled' => true,
            'eta' => '۲۰ تا ۶۰ دقیقه', 'depth' => 3, 'icon' => 'globe',
            'desc' => 'سایت را صفحه‌به‌صفحه می‌خزد و با ZAP مشکل‌های رایج وب (هدرها، کوکی‌ها، فرم‌ها، نشت اطلاعات) را در همه‌ی صفحه‌ها می‌سنجد. بی حمله‌ی فعال.',
        ],
        'urls' => [
            'label' => 'نشانی‌های قدیمی و لورفته', 'engine' => 'oasm', 'tools' => ['gau'], 'credits' => 2, 'kinds' => ['domain'], 'free' => true, 'enabled' => false,
            'eta' => '۵ تا ۲۰ دقیقه', 'depth' => 1, 'icon' => 'link',
            'desc' => 'نشانی‌هایی از سایت شما که در آرشیوهای عمومی اینترنت مانده‌اند (پنل‌های قدیمی، فایل‌های پشتیبان، مسیرهای فراموش‌شده). هیچ درخواستی به سایت شما نمی‌فرستد.',
        ],
        'services' => [
            'label' => 'سرویس‌ها و درگاه‌های سرور', 'engine' => 'oasm', 'tools' => ['nmap'], 'credits' => 4, 'kinds' => ['ip', 'cidr'], 'free' => true, 'enabled' => true,
            'eta' => '۱۰ تا ۳۰ دقیقه', 'depth' => 2, 'icon' => 'server',
            'desc' => 'هزار درگاه رایج سرور شما را با Nmap می‌سنجد و سرویس پشت هر کدام را نشان می‌دهد. فقط برای IPهای خودتان.',
        ],
        'wordpress' => [
            'label' => 'اسکن وردپرس', 'engine' => 'oasm', 'tools' => ['wpscan'], 'credits' => 6, 'kinds' => ['domain'], 'free' => true, 'enabled' => false,
            'eta' => '۱۰ تا ۳۰ دقیقه', 'depth' => 3, 'icon' => 'bug',
            'desc' => 'نسخه‌ی وردپرس، افزونه‌ها و قالب‌ها و آسیب‌پذیری‌های شناخته‌شده‌ی هر کدام.',
        ],
        'pro' => [
            'label' => 'اسکن حرفه‌ای (Acunetix)', 'engine' => 'oasm', 'tools' => ['acunetix'], 'credits' => 60, 'kinds' => ['domain', 'ip'], 'free' => false, 'enabled' => false,
            'eta' => '۱ تا ۶ ساعت', 'depth' => 4, 'icon' => 'layers',
            'desc' => 'اسکن کامل وب با موتور تجاری Acunetix: تزریق SQL، XSS و صدها آزمون فعال دیگر. درخواست زیادی به سایت می‌فرستد؛ برای پیش از راه‌اندازی یا ممیزی.',
        ],
        'recon' => [
            'label' => 'شناسایی سریع', 'engine' => 'osmedeus', 'workflow' => 'fast', 'credits' => 8, 'kinds' => ['domain'], 'free' => false, 'enabled' => false,
            'eta' => '۲۰ تا ۶۰ دقیقه', 'depth' => 2, 'icon' => 'search',
            'desc' => 'شناسایی گسترده‌ی زیردامنه‌ها، سرویس‌های وب، اسکرین‌شات و فناوری‌ها با Osmedeus.',
        ],
        'deep' => [
            'label' => 'ارزیابی عمیق', 'engine' => 'osmedeus', 'workflow' => 'general', 'credits' => 30, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => false, 'enabled' => false,
            'eta' => '۲ تا ۸ ساعت', 'depth' => 4, 'icon' => 'layers',
            'desc' => 'همه‌ی مراحل: شناسایی، اسکن درگاه، کشف محتوا، آسیب‌پذیری وب و گزارش کامل. برای پیش از راه‌اندازی یا ممیزی.',
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
                'free' => !empty($c['free']), 'enabled' => !empty($c['enabled']), 'eta' => 'بسته به ابزارها', 'depth' => 3, 'icon' => 'layers', 'custom' => true,
                'desc' => Text::name((string) ($c['desc'] ?? ''), 300),
            ];
            $p['depth'] = self::risk($p) === 'heavy' ? 4 : 3;
            if ($p['desc'] === '') {
                $p['desc'] = 'ابزارها: ' . implode('، ', array_map(fn ($t) => self::TOOLS[$t]['label'], $tools));
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

    public static function get(string $key): ?array
    {
        return self::all()[$key] ?? null;
    }

    public static function engineLabel(string $engine): string
    {
        return ['builtin' => 'بررسی داخلی', 'oasm' => 'OASM', 'osmedeus' => 'Osmedeus'][$engine] ?? $engine;
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
            $p['allowed'] = $lim['profiles'] === null ? (bool) $p['free'] : in_array($k, $lim['profiles'], true) || $p['free'];
            $out[$k] = $p;
        }
        return $out;
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
