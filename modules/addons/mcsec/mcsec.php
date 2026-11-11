<?php
/**
 * MC-Sec — WHMCS addon: a cyber-security workspace for Maral Cloud customers.
 * Assets (domains, subdomains, IPs) with ownership verification, scans on OASM and Osmedeus plus built-in
 * checks, findings with remediation, AI reports, schedules, notifications and a scan-credit wallet.
 * Design: docs/DESIGN.md. Rules: CLAUDE.md.
 */

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/bootstrap.php';

function mcsec_config(): array
{
    return [
        'name' => 'MC-Sec (امنیت سایبری)',
        'description' => 'فضای کار امنیت سایبری برای مشتریان: دارایی و تأیید مالکیت، اسکن (OASM، Osmedeus و بررسی‌های داخلی)، یافته و راهکار، گزارش هوش مصنوعی، زمان‌بندی، اعلان و اعتبار اسکن. تنظیمات در صفحه‌ی خود ماژول است.',
        'author' => 'Maral Cloud',
        'language' => 'farsi',
        'version' => MCSEC_VERSION,
        'fields' => [],
    ];
}

function mcsec_activate(): array
{
    try {
        \McSec\Installer::install();
        \McSec\Settings::set('schema_version', MCSEC_VERSION);
        return ['status' => 'success', 'description' => 'MC-Sec نصب شد. برای راه‌اندازی، صفحه‌ی ماژول را باز کنید. قابلیت برای مشتری‌ها تا روشن کردن در تنظیمات خاموش است.'];
    } catch (\Throwable $e) {
        return ['status' => 'error', 'description' => 'نصب MC-Sec انجام نشد: ' . $e->getMessage()];
    }
}

/** Keeps every table and row: deactivation never deletes data. */
function mcsec_deactivate(): array
{
    return ['status' => 'success', 'description' => 'MC-Sec غیرفعال شد. داده‌ها نگه داشته شده‌اند.'];
}

/** $vars['version'] is the previously installed version. Additive only. */
function mcsec_upgrade($vars): void
{
    \McSec\Installer::install();
    \McSec\Settings::set('schema_version', MCSEC_VERSION);
}

function mcsec_output($vars): void
{
    try {
        if (\McSec\Settings::get('schema_version') !== MCSEC_VERSION) {
            \McSec\Installer::install();
            \McSec\Settings::set('schema_version', MCSEC_VERSION);
        }
        echo \McSec\Admin\Controller::handle((string) ($vars['modulelink'] ?? 'addonmodules.php?module=mcsec'));
    } catch (\Throwable $e) {
        \McSec\Trace::error('admin', 'page', $e->getMessage(), \McSec\Trace::exception($e));
        echo '<div class="alert alert-danger">خطای داخلی MC-Sec. کد پیگیری در «گزارش فنی» ماژول ثبت شد.</div>';
    }
}

function mcsec_clientarea($vars): array
{
    try {
        return \McSec\Client\Controller::handle();
    } catch (\Throwable $e) {
        $code = \McSec\Trace::error('client', 'page', $e->getMessage(), \McSec\Trace::exception($e));
        return [
            'pagetitle' => 'امنیت سایبری',
            'breadcrumb' => ['index.php?m=mcsec' => 'امنیت سایبری'],
            'templatefile' => 'templates/page',
            'requirelogin' => true,
            'vars' => ['mcsec_html' => '<div class="mcs" dir="rtl" lang="fa"><div class="alert alert-danger">خطایی رخ داد؛ لطفاً دوباره امتحان کنید. اگر تکرار شد، این کد را به پشتیبانی بدهید: <bdi>' . htmlspecialchars($code, ENT_QUOTES) . '</bdi></div></div>'],
        ];
    }
}
