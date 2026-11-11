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
        return match (Settings::get('access_mode')) {
            'all' => true,
            'groups' => in_array((int) $c->groupid, Settings::ints('access_groups'), true),
            default => in_array($clientId, Settings::ints('access_clients'), true),
        };
    }
}
