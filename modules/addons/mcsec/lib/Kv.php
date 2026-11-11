<?php

declare(strict_types=1);

namespace McSec;

/** Small key-value store with expiry (mod_mcsec_kv): engine sessions, circuit breakers, health, short caches. */
final class Kv
{
    public static function get(string $k, ?string $default = null): ?string
    {
        $r = Db::table('mod_mcsec_kv')->where('k', substr($k, 0, 96))->first();
        if (!$r || ((int) $r->expires_at > 0 && (int) $r->expires_at < Clock::now())) {
            return $default;
        }
        return (string) $r->v;
    }

    public static function set(string $k, string $v, int $ttl = 0): void
    {
        $k = substr($k, 0, 96);
        $exp = $ttl > 0 ? Clock::now() + $ttl : 0;
        if (Db::table('mod_mcsec_kv')->where('k', $k)->update(['v' => $v, 'expires_at' => $exp]) === 0
            && !Db::table('mod_mcsec_kv')->where('k', $k)->exists()) {
            try {
                Db::table('mod_mcsec_kv')->insert(['k' => $k, 'v' => $v, 'expires_at' => $exp]);
            } catch (\Throwable $e) {
                Db::table('mod_mcsec_kv')->where('k', $k)->update(['v' => $v, 'expires_at' => $exp]);
            }
        }
    }

    public static function forget(string $k): void
    {
        Db::table('mod_mcsec_kv')->where('k', substr($k, 0, 96))->delete();
    }

    public static function json(string $k): array
    {
        $v = self::get($k);
        $d = $v === null ? null : json_decode($v, true);
        return is_array($d) ? $d : [];
    }

    public static function setJson(string $k, array $v, int $ttl = 0): void
    {
        self::set($k, Db::json($v), $ttl);
    }

    public static function purge(): int
    {
        return Db::table('mod_mcsec_kv')->where('expires_at', '>', 0)->where('expires_at', '<', Clock::now())->delete();
    }
}
