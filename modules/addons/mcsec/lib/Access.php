<?php

declare(strict_types=1);

namespace McSec;

/**
 * Whether a client account may use MC-Sec at all: the feature switch plus the access mode (a trial list of accounts,
 * chosen client groups, or everyone). Admins behind "Login as Owner" always see it, so support can look first.
 */
final class Access
{
    public static function clientAllowed(int $clientId, bool $masq = false): bool
    {
        if ($masq) {
            return true;
        }
        if (!Settings::bool('enabled')) {
            return false;
        }
        $c = Whmcs::client($clientId);
        if (!$c || (string) $c->status === 'Closed') {
            return false;
        }
        return self::modeAllows($clientId, (int) $c->groupid);
    }

    /** clientAllowed() for many accounts with one batched read (worker loops). @param int[] $ids @return int[] */
    public static function allowedIds(array $ids): array
    {
        if (!Settings::bool('enabled') || !$ids) {
            return [];
        }
        $out = [];
        foreach (Whmcs::clientFlags($ids) as $id => $c) {
            if ((string) $c->status !== 'Closed' && self::modeAllows((int) $id, (int) $c->groupid)) {
                $out[] = (int) $id;
            }
        }
        return $out;
    }

    private static function modeAllows(int $clientId, int $groupId): bool
    {
        return match (Settings::get('access_mode')) {
            'all' => true,
            'groups' => in_array($groupId, Settings::ints('access_groups'), true),
            default => in_array($clientId, Settings::ints('access_clients'), true),
        };
    }
}
