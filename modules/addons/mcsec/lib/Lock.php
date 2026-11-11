<?php

declare(strict_types=1);

namespace McSec;

use WHMCS\Database\Capsule;

/**
 * Named, non-blocking locks shared by every PHP process (same as MC-AI).
 * MySQL/MariaDB: GET_LOCK(name, 0), released automatically if the process dies.
 * Other drivers (the SQLite test harness): a row in mod_mcsec_locks with an expiry.
 */
final class Lock
{
    /** @var array<string, true> */
    private static array $held = [];
    private static ?string $owner = null;

    public static function acquire(string $name, int $ttl = 120): bool
    {
        $name = substr($name, 0, 64);
        if (isset(self::$held[$name])) {
            return false;
        }
        if (Db::driver() === 'mysql') {
            $r = Capsule::selectOne('SELECT GET_LOCK(?, 0) AS l', [$name]);
            $ok = (int) ($r->l ?? 0) === 1;
        } else {
            $now = Clock::now();
            $owner = self::owner();
            $ok = Db::table('mod_mcsec_locks')->where('name', $name)->where('locked_until', '<', $now)
                ->update(['owner' => $owner, 'locked_until' => $now + $ttl]) === 1;
            if (!$ok) {
                try {
                    Db::table('mod_mcsec_locks')->insert(['name' => $name, 'owner' => $owner, 'locked_until' => $now + $ttl]);
                    $ok = true;
                } catch (\Throwable $e) {
                    $ok = false;
                }
            }
        }
        if ($ok) {
            self::$held[$name] = true;
        }
        return $ok;
    }

    public static function release(string $name): void
    {
        $name = substr($name, 0, 64);
        if (!isset(self::$held[$name])) {
            return;
        }
        unset(self::$held[$name]);
        try {
            if (Db::driver() === 'mysql') {
                Capsule::select('SELECT RELEASE_LOCK(?)', [$name]);
            } else {
                Db::table('mod_mcsec_locks')->where('name', $name)->where('owner', self::owner())->update(['locked_until' => 0]);
            }
        } catch (\Throwable $e) {
            // expiry frees it
        }
    }

    /** Runs $fn while holding $name; returns null without running when the lock is busy. */
    public static function with(string $name, callable $fn, int $ttl = 120)
    {
        if (!self::acquire($name, $ttl)) {
            return null;
        }
        try {
            return $fn();
        } finally {
            self::release($name);
        }
    }

    private static function owner(): string
    {
        return self::$owner ??= getmypid() . '-' . bin2hex(random_bytes(6));
    }
}
