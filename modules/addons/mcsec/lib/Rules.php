<?php

declare(strict_types=1);

namespace McSec;

/**
 * Who gets which price (mod_mcsec_rules): one rule for a WHMCS client group or for one account, optionally with an
 * end date. A rule gives free monthly credits, a higher asset limit, a discount on credit packs, a lower credit cost
 * of scans and AI (spend_pct) and scan types open without a plan.
 * Exactly one rule applies to an account, so nothing ever stacks: the account's own rule wins over its group's rule,
 * and of several the newest. See skill mcsec-billing-safety.
 */
final class Rules
{
    public const NONE = ['id' => 0, 'scope' => '', 'monthly' => 0, 'max_assets' => 0, 'discount' => 0, 'spend_pct' => 100, 'profiles' => [], 'ends_at' => 0];

    /** @var array<int,array> */
    private static array $cache = [];

    /** The rule of an account now. @return array{id:int,scope:string,monthly:int,max_assets:int,discount:int,spend_pct:int,profiles:string[],ends_at:int} */
    public static function of(int $clientId): array
    {
        if (isset(self::$cache[$clientId])) {
            return self::$cache[$clientId];
        }
        $group = Whmcs::groupOf($clientId);
        $now = Clock::now();
        $rows = Db::rows(Db::table('mod_mcsec_rules')->where('enabled', 1)->where('starts_at', '<=', $now)
            ->where(fn ($q) => $q->where('ends_at', 0)->orWhere('ends_at', '>', $now))
            ->where(function ($q) use ($clientId, $group) {
                $q->where(fn ($w) => $w->where('scope', 'client')->where('target', $clientId));
                if ($group > 0) {
                    $q->orWhere(fn ($w) => $w->where('scope', 'group')->where('target', $group));
                }
            })->orderByDesc('id'));
        $pick = null;
        foreach ($rows as $r) {
            if ($r->scope === 'client') {
                $pick = $r;
                break;
            }
            $pick ??= $r;
        }
        return self::$cache[$clientId] = $pick ? [
            'id' => (int) $pick->id, 'scope' => (string) $pick->scope, 'monthly' => max(0, (int) $pick->monthly), 'max_assets' => max(0, (int) $pick->max_assets),
            'discount' => max(0, min(90, (int) $pick->discount)), 'spend_pct' => max(0, min(100, (int) $pick->spend_pct)),
            'profiles' => array_values(array_filter(array_map('trim', explode(',', (string) $pick->profiles)), 'strlen')), 'ends_at' => (int) $pick->ends_at,
        ] : self::NONE;
    }

    /** The credit cost of something for this account (rounded up; a rule can lower a price, never raise it). */
    public static function cost(int $clientId, int $cost): int
    {
        $pct = self::of($clientId)['spend_pct'];
        return $cost <= 0 || $pct >= 100 ? max(0, $cost) : (int) ceil($cost * $pct / 100);
    }

    /** @return array{ok:bool,error?:string,id?:int} */
    public static function save(array $in, int $adminId = 0): array
    {
        $scope = ($in['scope'] ?? '') === 'client' ? 'client' : 'group';
        $target = (int) ($in['target'] ?? 0);
        if ($target <= 0 || ($scope === 'client' ? !Whmcs::client($target) : !isset(Whmcs::groups()[$target]))) {
            return ['ok' => false, 'error' => $scope === 'client' ? 'حسابی با این شماره پیدا نشد.' : 'گروه مشتری را انتخاب کنید.']; // i18n-skip (rules are made in the admin panel only)
        }
        $known = array_keys(Catalog::all(true));
        $profiles = array_values(array_intersect(array_filter(array_map('trim', explode(',', strtolower(Text::toAscii((string) ($in['profiles'] ?? ''))))), 'strlen'), $known));
        $days = max(0, (int) ($in['days'] ?? 0));
        $row = [
            'scope' => $scope, 'target' => $target, 'monthly' => max(0, min(1000000, (int) ($in['monthly'] ?? 0))), 'max_assets' => max(0, min(100000, (int) ($in['max_assets'] ?? 0))),
            'discount' => max(0, min(90, (int) ($in['discount'] ?? 0))), 'spend_pct' => max(0, min(100, (int) ($in['spend_pct'] ?? 100))),
            'profiles' => mb_substr(implode(',', $profiles), 0, 255), 'starts_at' => Clock::now(), 'ends_at' => $days > 0 ? Clock::now() + $days * 86400 : 0,
            'note' => Text::name((string) ($in['note'] ?? ''), 160), 'enabled' => 1, 'admin_id' => $adminId, 'created_at' => Clock::now(),
        ];
        // one live rule per group or account: the new one replaces the old (kept, switched off, for the record)
        Db::table('mod_mcsec_rules')->where('scope', $scope)->where('target', $target)->where('enabled', 1)->update(['enabled' => 0]);
        $id = (int) Db::table('mod_mcsec_rules')->insertGetId($row);
        self::forget();
        Audit::log($scope === 'client' ? $target : 0, 'rule', $scope . ' ' . $target, $row);
        return ['ok' => true, 'id' => $id];
    }

    public static function disable(int $id): bool
    {
        $n = Db::table('mod_mcsec_rules')->where('id', $id)->where('enabled', 1)->update(['enabled' => 0]);
        self::forget();
        if ($n > 0) {
            Audit::log(0, 'rule', 'off ' . $id);
        }
        return $n > 0;
    }

    /** Live rules, newest first. @return object[] */
    public static function all(): array
    {
        return Db::rows(Db::table('mod_mcsec_rules')->where('enabled', 1)->orderByDesc('id')->limit(300));
    }

    public static function forget(): void
    {
        self::$cache = [];
    }
}
