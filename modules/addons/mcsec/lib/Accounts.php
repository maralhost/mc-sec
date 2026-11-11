<?php

declare(strict_types=1);

namespace McSec;

/**
 * The security workspace of one WHMCS client account (mod_mcsec_accounts): its verification token, backend
 * workspace ids, notification settings and one-time flags (welcome credits, terms accepted). Created on the first
 * visit; the welcome credits are granted exactly once (ledger ref welcome:<client>).
 */
final class Accounts
{
    /** @var array<int,object> */
    private static array $cache = [];

    public static function get(int $clientId): ?object
    {
        if (!isset(self::$cache[$clientId])) {
            $r = Db::table('mod_mcsec_accounts')->where('client_id', $clientId)->first();
            if (!$r) {
                return null;
            }
            self::$cache[$clientId] = $r;
        }
        return self::$cache[$clientId];
    }

    public static function ensure(int $clientId): object
    {
        $a = self::get($clientId);
        if ($a) {
            return $a;
        }
        try {
            Db::table('mod_mcsec_accounts')->insert([
                'client_id' => $clientId, 'verify_token' => Crypto::token(12), 'prefs' => Db::json(Notify::defaultPrefs()),
                'link_code' => Crypto::code(8), 'created_at' => Clock::now(), 'updated_at' => Clock::now(),
            ]);
        } catch (\Throwable $e) {
            // created by a parallel request
        }
        self::forget($clientId);
        $a = self::get($clientId);
        if ($a && (int) $a->welcome_at === 0) {
            $n = Settings::int('welcome_credits');
            if ($n > 0) {
                Credits::credit($clientId, $n, 'paid', 'welcome', 'welcome:' . $clientId, 'اعتبار خوش‌آمد');
            }
            Db::table('mod_mcsec_accounts')->where('client_id', $clientId)->where('welcome_at', 0)->update(['welcome_at' => Clock::now()]);
            self::forget($clientId);
            $a = self::get($clientId);
        }
        return $a;
    }

    public static function update(int $clientId, array $fields): void
    {
        $fields['updated_at'] = Clock::now();
        Db::table('mod_mcsec_accounts')->where('client_id', $clientId)->update($fields);
        self::forget($clientId);
    }

    /** The TXT/meta/file value that proves control: mcsec-verify=<token>. */
    public static function proof(object $account): string
    {
        return 'mcsec-verify=' . $account->verify_token;
    }

    public static function forget(?int $clientId = null): void
    {
        if ($clientId === null) {
            self::$cache = [];
        } else {
            unset(self::$cache[$clientId]);
        }
    }
}
