<?php

declare(strict_types=1);

namespace McSec;

/**
 * Where the open findings of a report fall in two well-known lists: OWASP Top 10 (2021) and the controls of
 * ISO/IEC 27001:2022 Annex A. A fixed table from the knowledge-base key of each finding (never from a model), so a
 * manager or an auditor can read the report in their own vocabulary.
 *
 * It is a mapping, not a certificate: an empty row only says the automated, outside-in scans saw nothing there.
 * The report says so next to the table.
 */
final class Compliance
{
    public const OWASP = [
        'A01' => 'کنترل دسترسی شکسته', 'A02' => 'خطاهای رمزنگاری', 'A03' => 'تزریق', 'A04' => 'طراحی ناامن', 'A05' => 'پیکربندی امنیتی نادرست',
        'A06' => 'اجزای آسیب‌پذیر و قدیمی', 'A07' => 'خطاهای شناسایی و احراز هویت', 'A08' => 'خطاهای یکپارچگی نرم‌افزار و داده',
        'A09' => 'خطاهای ثبت رویداد و پایش', 'A10' => 'جعل درخواست سمت سرور (SSRF)',
    ];

    public const ISO = [
        'A.8.5' => 'احراز هویت امن', 'A.8.8' => 'مدیریت آسیب‌پذیری‌های فنی', 'A.8.9' => 'مدیریت پیکربندی', 'A.8.12' => 'جلوگیری از نشت داده',
        'A.8.20' => 'امنیت شبکه', 'A.8.24' => 'استفاده از رمزنگاری', 'A.8.26' => 'الزامات امنیتی برنامه',
    ];

    /** kb key => [OWASP category, ISO control]; a key that is not here is counted as «نگاشت‌نشده». */
    private const MAP = [
        'tls-expired' => ['A02', 'A.8.24'], 'tls-expiring' => ['A02', 'A.8.24'], 'tls-hostname' => ['A02', 'A.8.24'], 'tls-self-signed' => ['A02', 'A.8.24'],
        'tls-old-protocol' => ['A02', 'A.8.24'], 'weak-cipher' => ['A02', 'A.8.24'], 'web-no-https' => ['A02', 'A.8.24'], 'web-no-redirect' => ['A02', 'A.8.24'],
        'hdr-hsts' => ['A02', 'A.8.24'], 'mixed-content' => ['A02', 'A.8.24'], 'ftp-plaintext' => ['A02', 'A.8.24'],
        'hdr-csp' => ['A05', 'A.8.9'], 'hdr-frame' => ['A05', 'A.8.9'], 'hdr-nosniff' => ['A05', 'A.8.9'], 'hdr-version' => ['A05', 'A.8.9'], 'cookie-flags' => ['A05', 'A.8.9'],
        'web-listing' => ['A05', 'A.8.9'], 'web-server-status' => ['A05', 'A.8.9'], 'http-methods' => ['A05', 'A.8.9'], 'cors-misconfig' => ['A05', 'A.8.9'],
        'security-txt' => ['A05', 'A.8.9'], 'waf-missing' => ['A05', 'A.8.9'], 'dns-zone-transfer' => ['A05', 'A.8.9'], 'dnssec-missing' => ['A05', 'A.8.9'],
        'dns-caa' => ['A05', 'A.8.9'], 'mail-spf' => ['A05', 'A.8.9'], 'mail-dmarc' => ['A05', 'A.8.9'], 'smtp-open-relay' => ['A05', 'A.8.9'],
        'exposed-panel' => ['A05', 'A.8.9'], 'subdomain-takeover' => ['A05', 'A.8.9'],
        'web-git' => ['A05', 'A.8.12'], 'web-env' => ['A05', 'A.8.12'], 'exposed-backup' => ['A05', 'A.8.12'], 'exposed-config' => ['A05', 'A.8.12'], 'info-disclosure' => ['A01', 'A.8.12'],
        'port-exposed' => ['A05', 'A.8.20'], 'weak-ssh' => ['A05', 'A.8.20'],
        'cve-patch' => ['A06', 'A.8.8'], 'outdated-software' => ['A06', 'A.8.8'], 'wordpress-core-outdated' => ['A06', 'A.8.8'], 'wordpress-plugin-vuln' => ['A06', 'A.8.8'],
        'default-credentials' => ['A07', 'A.8.5'],
        'open-redirect' => ['A01', 'A.8.26'], 'xss' => ['A03', 'A.8.26'], 'sqli' => ['A03', 'A.8.26'], 'lfi-rce' => ['A03', 'A.8.26'], 'ssrf' => ['A10', 'A.8.26'],
    ];

    /** @return array{0:string,1:string}|null */
    public static function of(string $kb): ?array
    {
        return self::MAP[$kb] ?? null;
    }

    /**
     * @param array<int,array{kbk?:string,severity?:string}> $findings open findings (each with its kb key)
     * @return array{owasp:array<string,array{n:int,severity:string}>,iso:array<string,array{n:int,severity:string}>,unmapped:int,total:int}
     */
    public static function summary(array $findings): array
    {
        $out = ['owasp' => [], 'iso' => [], 'unmapped' => 0, 'total' => count($findings)];
        foreach (array_keys(self::OWASP) as $k) {
            $out['owasp'][$k] = ['n' => 0, 'severity' => ''];
        }
        foreach ($findings as $f) {
            $m = self::of((string) ($f['kbk'] ?? ''));
            if ($m === null) {
                $out['unmapped']++;
                continue;
            }
            $sev = (string) ($f['severity'] ?? 'info');
            foreach (['owasp' => $m[0], 'iso' => $m[1]] as $list => $code) {
                $row = $out[$list][$code] ?? ['n' => 0, 'severity' => ''];
                $row['n']++;
                $row['severity'] = Findings::rank($sev) > Findings::rank($row['severity']) ? $sev : $row['severity'];
                $out[$list][$code] = $row;
            }
        }
        ksort($out['iso'], SORT_NATURAL);
        return $out;
    }

    /** The line every table of this mapping carries. */
    public static function note(): string
    {
        return Lang::t('این جدول یک نگاشت است، نه گواهی انطباق: فقط نشان می‌دهد یافته‌های اسکن خودکار (از بیرون) در کدام بند می‌افتند. ردیف خالی یعنی اسکن خودکار در آن بند چیزی ندید، نه این‌که آن بند رعایت شده است.');
    }
}
