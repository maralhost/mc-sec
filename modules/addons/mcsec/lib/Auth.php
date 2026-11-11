<?php

declare(strict_types=1);

namespace McSec;

/**
 * Who is asking. The person comes only from the WHMCS session (CurrentUser), never from input.
 * Client side: the account owner can do everything; another user of the account needs WHMCS permission
 * 'products' to see the section, 'manageproducts' to act (assets, scans, schedules, settings) and 'invoices' to buy
 * credit. Admin tiers: view < ops < settings, mapped from WHMCS admin role ids (setting role_map).
 */
final class Auth
{
    /** Tests inject the session here: ['client_id','user_id','owner','perms','masq']. */
    public static ?array $testClient = null;
    public static ?array $testAdmin = null;

    private const TIERS = ['view' => 1, 'ops' => 2, 'settings' => 3];

    /** @return array{client_id:int,user_id:int,owner:bool,perms:string[],masq:bool}|null */
    public static function client(): ?array
    {
        if (self::$testClient !== null) {
            return self::$testClient + ['owner' => false, 'perms' => [], 'masq' => false];
        }
        try {
            $cu = new \WHMCS\Authentication\CurrentUser();
            $client = $cu->client();
            $user = $cu->user();
            if (!$client || !$user) {
                return null;
            }
            $clientId = (int) $client->id;
            $userId = (int) $user->id;
            $link = Whmcs::link($userId, $clientId);
            if ($link === null) {
                return null;
            }
            return ['client_id' => $clientId, 'user_id' => $userId, 'owner' => $link['owner'], 'perms' => $link['perms'],
                'masq' => (bool) $cu->isMasqueradingAdmin()];
        } catch (\Throwable $e) {
            return null;
        }
    }

    public static function canView(array $who): bool
    {
        return $who['owner'] || in_array('products', $who['perms'], true) || in_array('manageproducts', $who['perms'], true);
    }

    public static function canManage(array $who): bool
    {
        return $who['owner'] || in_array('manageproducts', $who['perms'], true);
    }

    public static function canBuy(array $who): bool
    {
        return $who['owner'] || in_array('invoices', $who['perms'], true);
    }

    /** The admin id behind "Login as Owner", or 0. */
    public static function masqueradingAdmin(): int
    {
        if (self::$testClient !== null) {
            return !empty(self::$testClient['masq']) ? (int) (self::$testClient['admin_id'] ?? 1) : 0;
        }
        return !empty($_SESSION['adminid']) && !empty($_SESSION['uid']) ? (int) $_SESSION['adminid'] : 0;
    }

    /** Whether a client-area session may change anything (an admin behind "Login as Owner" only views unless allowed). */
    public static function mayAct(array $who): bool
    {
        return !$who['masq'] || Settings::bool('masq_actions');
    }

    public static function adminId(): int
    {
        if (self::$testAdmin !== null) {
            return (int) self::$testAdmin['id'];
        }
        return (int) ($_SESSION['adminid'] ?? 0);
    }

    public static function adminTier(): string
    {
        if (self::$testAdmin !== null) {
            return (string) self::$testAdmin['tier'];
        }
        $id = self::adminId();
        if ($id <= 0) {
            return '';
        }
        try {
            $role = (int) Db::table('tbladmins')->where('id', $id)->value('roleid');
        } catch (\Throwable $e) {
            return 'view';
        }
        foreach (Settings::csv('role_map') ?: ['1:settings'] as $pair) {
            [$rid, $tier] = array_pad(explode(':', $pair, 2), 2, '');
            if ((int) $rid === $role && isset(self::TIERS[$tier])) {
                return $tier;
            }
        }
        return 'view';
    }

    public static function adminCan(string $tier): bool
    {
        return (self::TIERS[self::adminTier()] ?? 0) >= (self::TIERS[$tier] ?? 99);
    }

    /** The module's own session CSRF token (admin and client forms). */
    public static function csrf(): string
    {
        if (empty($_SESSION['mcsec_csrf'])) {
            $_SESSION['mcsec_csrf'] = bin2hex(random_bytes(16));
        }
        return (string) $_SESSION['mcsec_csrf'];
    }

    public static function checkCsrf(?string $given): bool
    {
        return is_string($given) && !empty($_SESSION['mcsec_csrf']) && hash_equals((string) $_SESSION['mcsec_csrf'], $given);
    }

    /** WHMCS client-area token ({$token}); check_token() prints HTML on failure, so compare directly. */
    public static function checkWhmcsToken(?string $given): bool
    {
        if (self::$testClient !== null) {
            return $given === 'whmcs-token';
        }
        if (!is_string($given) || $given === '') {
            return false;
        }
        try {
            $expected = function_exists('generate_token') ? (string) generate_token('plain') : '';
            return $expected !== '' && hash_equals($expected, $given);
        } catch (\Throwable $e) {
            return false;
        }
    }
}
