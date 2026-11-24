<?php
/**
 * MC-Sec plans — WHMCS provisioning module. A plan is an ordinary WHMCS product on this module; WHMCS bills it,
 * and these functions keep the plan's entitlements (monthly credits, asset cap, scan types, shortest schedule interval,
 * AI reports) in the addon's table through McSec\Plans. Needs the MC-Sec addon (modules/addons/mcsec) installed.
 * No server, no remote calls: every function is database-only and idempotent (renewals never double the credits).
 */

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

$mcsecBoot = __DIR__ . '/../../addons/mcsec/bootstrap.php';
if (is_file($mcsecBoot)) {
    require_once $mcsecBoot;
}

function mcsecplan_MetaData(): array
{
    return [
        'DisplayName' => 'MC-Sec — پلن امنیت سایبری', // i18n-skip (admin's product setup)
        'APIVersion' => '1.1',
        'RequiresServer' => false,
    ];
}

function mcsecplan_ConfigOptions(): array
{
    $profiles = defined('MCSEC_VERSION') ? implode(', ', array_keys(\McSec\Catalog::DEFAULTS)) : 'hygiene, surface, vuln, recon, deep';
    // i18n-skip-begin (the admin's product options)
    return [
        'monthly_credits' => ['FriendlyName' => 'اعتبار ماهانه', 'Type' => 'text', 'Size' => '6', 'Default' => '150', 'Description' => 'هر ماه شمسی به اعتبار ماهانه‌ی مشتری افزوده می‌شود (جمع نمی‌شود).'],
        'max_assets' => ['FriendlyName' => 'سقف دارایی', 'Type' => 'text', 'Size' => '6', 'Default' => '3', 'Description' => 'بیشترین دارایی (دامنه یا IP) در حساب.'],
        'profiles' => ['FriendlyName' => 'نوع‌های اسکن', 'Type' => 'text', 'Size' => '40', 'Default' => '', 'Description' => 'جداشده با ویرگول، از: ' . $profiles . '. خالی = همه.'],
        'min_interval_h' => ['FriendlyName' => 'کوتاه‌ترین فاصله‌ی زمان‌بندی', 'Type' => 'dropdown', 'Options' => '24,168,720', 'Default' => '168', 'Description' => 'ساعت: ۲۴ روزانه، ۱۶۸ هفتگی، ۷۲۰ ماهانه.'],
        'ai_reports' => ['FriendlyName' => 'گزارش هوش مصنوعی', 'Type' => 'yesno', 'Description' => 'گزارش و راهکار هوش مصنوعی در این پلن هست.'],
    ];
    // i18n-skip-end
}

/** The product's options from $params (configoption1..5 in the order above). */
function mcsecplan_cfg(array $params): array
{
    return [
        'monthly_credits' => (int) ($params['configoption1'] ?? 0),
        'max_assets' => (int) ($params['configoption2'] ?? 0),
        'profiles' => (string) ($params['configoption3'] ?? ''),
        'min_interval_h' => (int) ($params['configoption4'] ?? 168),
        'ai_reports' => in_array(strtolower((string) ($params['configoption5'] ?? '')), ['on', 'yes', '1'], true),
    ];
}

function mcsecplan_apply(array $params, string $status): string
{
    if (!defined('MCSEC_VERSION')) {
        return 'افزونه‌ی MC-Sec (modules/addons/mcsec) نصب نیست.'; // i18n-skip (module command result, for the admin)
    }
    try {
        \McSec\Installer::ensure();
        $serviceId = (int) ($params['serviceid'] ?? 0);
        if ($status === 'active') {
            $name = (string) ($params['model']->product->name ?? $params['configoptions']['name'] ?? ('Plan #' . (int) ($params['pid'] ?? 0)));
            \McSec\Plans::activate($serviceId, (int) ($params['userid'] ?? $params['clientsdetails']['userid'] ?? 0), (int) ($params['pid'] ?? 0), $name, mcsecplan_cfg($params));
        } else {
            \McSec\Plans::setStatus($serviceId, $status);
        }
        return 'success';
    } catch (\Throwable $e) {
        \McSec\Trace::error('plan', $status, $e->getMessage(), \McSec\Trace::exception($e));
        return 'خطای MC-Sec: ' . $e->getMessage(); // i18n-skip
    }
}

function mcsecplan_CreateAccount(array $params): string
{
    return mcsecplan_apply($params, 'active');
}

function mcsecplan_SuspendAccount(array $params): string
{
    return mcsecplan_apply($params, 'suspended');
}

function mcsecplan_UnsuspendAccount(array $params): string
{
    return mcsecplan_apply($params, 'active');
}

function mcsecplan_TerminateAccount(array $params): string
{
    return mcsecplan_apply($params, 'terminated');
}

function mcsecplan_ChangePackage(array $params): string
{
    return mcsecplan_apply($params, 'active');
}

/** Paid renewal: entitlements refreshed; this month's credits are granted once (the ledger ref is per month). */
function mcsecplan_Renew(array $params): string
{
    return mcsecplan_apply($params, 'active');
}

/** The service page shows a way into the workspace (an HTML string is a valid ClientArea output). */
function mcsecplan_ClientArea(array $params): string
{
    return '<div ' . (defined('MCSEC_VERSION') ? \McSec\Lang::attrs() : 'dir="rtl" lang="fa"') . ' style="padding:12px 0"><a class="btn btn-primary" href="index.php?m=mcsec">' . mcsecplan_t('ورود به فضای امنیت سایبری') . '</a></div>';
}

/** A customer's text in their language; Persian when the addon (and so the dictionary) is not installed. */
function mcsecplan_t(string $fa): string
{
    return defined('MCSEC_VERSION') ? \McSec\Lang::t($fa) : $fa;
}

function mcsecplan_ClientAreaCustomButtonArray(): array
{
    return [mcsecplan_t('ورود به فضای امنیت') => 'open'];
}

function mcsecplan_open(array $params): string
{
    header('Location: index.php?m=mcsec');
    exit;
}
