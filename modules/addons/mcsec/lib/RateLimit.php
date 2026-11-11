<?php

declare(strict_types=1);

namespace McSec;

/** Fixed-window counters per key (mod_mcsec_hits), e.g. invites per organization per hour. */
final class RateLimit
{
    /** Counts one hit; false when the limit for this window is already reached. */
    public static function hit(string $key, int $limit, int $window): bool
    {
        if ($limit <= 0) {
            return true;
        }
        $key = substr($key, 0, 96);
        $now = Clock::now();
        $start = $now - ($now % max(1, $window));
        $row = Db::table('mod_mcsec_hits')->where('k', $key)->first();
        if (!$row) {
            try {
                Db::table('mod_mcsec_hits')->insert(['k' => $key, 'window_start' => $start, 'n' => 1]);
                return true;
            } catch (\Throwable $e) {
                $row = Db::table('mod_mcsec_hits')->where('k', $key)->first();
            }
        }
        if ((int) $row->window_start !== $start) {
            Db::table('mod_mcsec_hits')->where('k', $key)->update(['window_start' => $start, 'n' => 1]);
            return true;
        }
        return Db::table('mod_mcsec_hits')->where('k', $key)->where('window_start', $start)->where('n', '<', $limit)->increment('n') === 1;
    }

    public static function purge(): void
    {
        Db::table('mod_mcsec_hits')->where('window_start', '<', Clock::now() - 2 * 86400)->delete();
    }
}
