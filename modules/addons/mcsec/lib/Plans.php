<?php

declare(strict_types=1);

namespace McSec;

/**
 * Plans are ordinary WHMCS products on the `mcsecplan` provisioning module (modules/servers/mcsecplan; its own name,
 * because PHP function names are case-insensitive and mcsec_ClientArea would clash with the addon's mcsec_clientarea). WHMCS bills them;
 * the provisioning functions call these methods, which keep one row per service in mod_mcsec_plans. Limits of an
 * account = the best of: free tier, its client group's rule, and every active plan.
 */
final class Plans
{
    /** Called from CreateAccount / Unsuspend / ChangePackage / Renew. $cfg = product config options. */
    public static function activate(int $serviceId, int $clientId, int $productId, string $name, array $cfg): void
    {
        $row = [
            'client_id' => $clientId, 'product_id' => $productId, 'name' => mb_substr($name, 0, 120), 'status' => 'active',
            'monthly_credits' => max(0, (int) ($cfg['monthly_credits'] ?? 0)), 'max_assets' => max(0, (int) ($cfg['max_assets'] ?? 0)),
            'profiles' => implode(',', array_filter(array_map('trim', explode(',', (string) ($cfg['profiles'] ?? ''))))),
            'min_interval_h' => max(1, (int) ($cfg['min_interval_h'] ?? 24)), 'ai_reports' => !empty($cfg['ai_reports']) ? 1 : 0, 'updated_at' => Clock::now(),
        ];
        if (Db::table('mod_mcsec_plans')->where('service_id', $serviceId)->exists()) {
            Db::table('mod_mcsec_plans')->where('service_id', $serviceId)->update($row);
        } else {
            Db::table('mod_mcsec_plans')->insert($row + ['service_id' => $serviceId]);
        }
        Accounts::ensure($clientId);
        // this month's credits now (the ref makes it once per service per month, also across renewals)
        if ($row['monthly_credits'] > 0) {
            Credits::credit($clientId, $row['monthly_credits'], 'monthly', 'plan', 'plan:' . $serviceId . ':' . Credits::period(), 'اعتبار ماهانه‌ی پلن ' . $row['name']);
        }
        self::resumeSchedules($clientId);
    }

    public static function setStatus(int $serviceId, string $status): void
    {
        Db::table('mod_mcsec_plans')->where('service_id', $serviceId)->update(['status' => $status, 'updated_at' => Clock::now()]);
    }

    /** @return object[] */
    public static function active(int $clientId): array
    {
        return Db::rows(Db::table('mod_mcsec_plans')->where('client_id', $clientId)->where('status', 'active'));
    }

    /**
     * @return array{max_assets:int,profiles:?array,min_interval_h:int,ai:bool,monthly:int,plans:string[]}
     * profiles null = no plan (free profiles only)
     */
    public static function limits(int $clientId): array
    {
        $max = Settings::int('max_assets_free');
        $monthly = 0;
        $rule = Credits::groupRule(Whmcs::groupOf($clientId));
        if ($rule) {
            $max = max($max, $rule['max_assets']);
            $monthly += $rule['monthly'];
        }
        $profiles = null;
        $interval = 168; // without a plan: at most weekly schedules
        $ai = Settings::bool('ai_enabled');
        $names = [];
        foreach (self::active($clientId) as $p) {
            $names[] = (string) $p->name;
            $max = max($max, (int) $p->max_assets);
            $monthly += (int) $p->monthly_credits;
            $interval = min($interval, max(1, (int) $p->min_interval_h));
            $list = trim((string) $p->profiles) === '' ? array_keys(Catalog::all()) : explode(',', (string) $p->profiles);
            $profiles = array_values(array_unique(array_merge($profiles ?? [], $list)));
        }
        return ['max_assets' => $max, 'profiles' => $profiles, 'min_interval_h' => $interval, 'ai' => $ai, 'monthly' => $monthly, 'plans' => $names];
    }

    /** Schedules paused for a missing plan or credits come back when a plan starts. */
    private static function resumeSchedules(int $clientId): void
    {
        Db::table('mod_mcsec_schedules')->where('client_id', $clientId)->where('status', 'paused')->whereIn('pause_reason', ['credits', 'plan'])
            ->update(['status' => 'active', 'pause_reason' => '']);
    }
}
