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
        // i18n-skip-begin (the admin's module list and activation messages)
        'name' => 'MC-Sec (امنیت سایبری)',
        'description' => 'فضای کار امنیت سایبری برای مشتریان: دارایی و تأیید مالکیت، اسکن (OASM، Osmedeus و بررسی‌های داخلی)، یافته و راهکار، گزارش هوش مصنوعی، زمان‌بندی، اعلان و اعتبار اسکن. تنظیمات در صفحه‌ی خود ماژول است.',
        // i18n-skip-end
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
        return ['status' => 'success', 'description' => 'MC-Sec نصب شد. برای راه‌اندازی، صفحه‌ی ماژول را باز کنید. قابلیت برای مشتری‌ها تا روشن کردن در تنظیمات خاموش است.']; // i18n-skip
    } catch (\Throwable $e) {
        return ['status' => 'error', 'description' => 'نصب MC-Sec انجام نشد: ' . $e->getMessage()]; // i18n-skip
    }
}

/** Keeps every table and row: deactivation never deletes data. */
function mcsec_deactivate(): array
{
    return ['status' => 'success', 'description' => 'MC-Sec غیرفعال شد. داده‌ها نگه داشته شده‌اند.']; // i18n-skip
}

/** $vars['version'] is the previously installed version. Additive only. */
function mcsec_upgrade($vars): void
{
    \McSec\Installer::install();
}

function mcsec_output($vars): void
{
    try {
        \McSec\Installer::ensure();
        echo \McSec\Admin\Controller::handle((string) ($vars['modulelink'] ?? 'addonmodules.php?module=mcsec'));
    } catch (\Throwable $e) {
        \McSec\Trace::error('admin', 'page', $e->getMessage(), \McSec\Trace::exception($e));
        echo '<div class="alert alert-danger">خطای داخلی MC-Sec. کد پیگیری در «گزارش فنی» ماژول ثبت شد.</div>'; // i18n-skip
    }
}

function mcsec_clientarea($vars): array
{
    try {
        return \McSec\Client\Controller::handle();
    } catch (\Throwable $e) {
        $code = \McSec\Trace::error('client', 'page', $e->getMessage(), \McSec\Trace::exception($e));
        return [
            'pagetitle' => \McSec\Lang::t('امنیت سایبری'),
            'breadcrumb' => ['index.php?m=mcsec' => \McSec\Lang::t('امنیت سایبری')],
            'templatefile' => 'templates/page',
            'requirelogin' => true,
            'vars' => ['mcsec_html' => '<div class="mcs" ' . \McSec\Lang::attrs() . '><div class="alert alert-danger">'
                . \McSec\Lang::t('خطایی رخ داد؛ لطفاً دوباره امتحان کنید. اگر تکرار شد، این کد را به پشتیبانی بدهید: {code}', ['code' => '<bdi>' . htmlspecialchars($code, ENT_QUOTES) . '</bdi>']) . '</div></div>'],
        ];
    }
}
