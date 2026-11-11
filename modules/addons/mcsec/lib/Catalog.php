<?php

declare(strict_types=1);

namespace McSec;

/**
 * The scan products customers choose from. Each profile names its engine, the asset kinds it accepts, its credit
 * cost per asset and (for Osmedeus) the workflow. Admins override enabled/credits/workflow/label in the setting
 * `profiles`; anything not overridden comes from DEFAULTS. `free` = available without a plan.
 */
final class Catalog
{
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
            'label' => 'اسکن آسیب‌پذیری', 'engine' => 'oasm', 'credits' => 6, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => true, 'enabled' => true,
            'eta' => '۲۰ دقیقه تا ۲ ساعت', 'depth' => 3, 'icon' => 'bug',
            'desc' => 'با هزاران الگوی Nuclei آسیب‌پذیری‌های شناخته‌شده (CVE)، پیکربندی نادرست، پنل‌ها و فایل‌های حساسِ در دسترس را می‌سنجد.',
        ],
        'recon' => [
            'label' => 'شناسایی سریع', 'engine' => 'osmedeus', 'workflow' => 'fast', 'credits' => 8, 'kinds' => ['domain'], 'free' => false, 'enabled' => true,
            'eta' => '۲۰ تا ۶۰ دقیقه', 'depth' => 2, 'icon' => 'search',
            'desc' => 'شناسایی گسترده‌ی زیردامنه‌ها، سرویس‌های وب، اسکرین‌شات و فناوری‌ها با Osmedeus.',
        ],
        'deep' => [
            'label' => 'ارزیابی عمیق', 'engine' => 'osmedeus', 'workflow' => 'general', 'credits' => 30, 'kinds' => ['domain', 'ip', 'cidr'], 'free' => false, 'enabled' => true,
            'eta' => '۲ تا ۸ ساعت', 'depth' => 4, 'icon' => 'layers',
            'desc' => 'همه‌ی مراحل: شناسایی، اسکن درگاه، کشف محتوا، آسیب‌پذیری وب و گزارش کامل. برای پیش از راه‌اندازی یا ممیزی.',
        ],
    ];

    /** @return array<string,array> enabled profiles (with overrides), in display order */
    public static function all(bool $includeDisabled = false): array
    {
        $over = Settings::json('profiles');
        $out = [];
        foreach (self::DEFAULTS as $key => $p) {
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
