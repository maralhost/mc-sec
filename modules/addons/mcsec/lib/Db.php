<?php

declare(strict_types=1);

namespace McSec;

use WHMCS\Database\Capsule;

/**
 * Small helpers around WHMCS Capsule (Illuminate query builder).
 * Rows come back as stdClass, whatever PDO fetch mode WHMCS set.
 * WHMCS tables (tbl*) are only read here; every WHMCS write goes through Whmcs (localAPI).
 */
final class Db
{
    public static function table(string $name): \Illuminate\Database\Query\Builder
    {
        return Capsule::table($name);
    }

    public static function driver(): string
    {
        return Capsule::connection()->getDriverName();
    }

    /** Runs $fn in one transaction and returns its result. */
    public static function tx(callable $fn)
    {
        return Capsule::connection()->transaction($fn);
    }

    /** Rows as a plain array of stdClass. */
    public static function rows($query): array
    {
        $r = $query->get();
        return is_array($r) ? $r : $r->all();
    }

    public static function json($value): string
    {
        return (string) json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    public static function decode(?string $json, $default = [])
    {
        if ($json === null || $json === '') {
            return $default;
        }
        $v = json_decode($json, true);
        return $v === null ? $default : $v;
    }

    /** Whether a WHMCS table has a column (WHMCS versions differ); cached per request. */
    public static function hasColumn(string $table, string $column): bool
    {
        static $seen = [];
        $k = $table . '.' . $column;
        if (!array_key_exists($k, $seen)) {
            try {
                $seen[$k] = Capsule::schema()->hasColumn($table, $column);
            } catch (\Throwable $e) {
                $seen[$k] = false;
            }
        }
        return $seen[$k];
    }

    /** WHMCS core configuration value (tblconfiguration), read only. */
    public static function whmcsSetting(string $name, string $default = ''): string
    {
        try {
            $v = Capsule::table('tblconfiguration')->where('setting', $name)->value('value');
        } catch (\Throwable $e) {
            return $default;
        }
        return $v === null ? $default : (string) $v;
    }

    /** Module log line in WHMCS's activity log. Never pass secrets here. */
    public static function log(string $message): void
    {
        try {
            if (function_exists('logActivity')) {
                logActivity('MC-Sec: ' . mb_substr($message, 0, 900));
            }
        } catch (\Throwable $e) {
            // logging must never break a request
        }
    }
}
