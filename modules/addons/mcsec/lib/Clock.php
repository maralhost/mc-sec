<?php

declare(strict_types=1);

namespace McSec;

/**
 * Module time. Every module timestamp is a Unix epoch integer (UTC), so the server, PHP and
 * WHMCS cron timezones can never shift a deadline. Tests freeze or move the clock.
 */
final class Clock
{
    public static ?int $fixed = null;

    public static function now(): int
    {
        return self::$fixed ?? time();
    }

    /** Today in Tehran as Y-m-d (WHMCS due dates are plain dates). */
    public static function today(int $plusDays = 0): string
    {
        return (new \DateTimeImmutable('@' . (self::now() + $plusDays * 86400)))->setTimezone(new \DateTimeZone('Asia/Tehran'))->format('Y-m-d');
    }
}
