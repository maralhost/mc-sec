<?php

declare(strict_types=1);

namespace McSec;

/**
 * One-time form nonces (mod_mcsec_nonces). A nonce belongs to one user, one client account and one
 * purpose; consuming it is a single atomic UPDATE, so a double click or a resubmitted form never passes twice.
 */
final class Nonce
{
    public static function issue(int $userId, int $clientId, string $purpose, int $ttl = 7200): string
    {
        $nonce = bin2hex(random_bytes(16));
        Db::table('mod_mcsec_nonces')->insert([
            'nonce' => $nonce, 'user_id' => $userId, 'client_id' => $clientId, 'purpose' => substr($purpose, 0, 32),
            'used_at' => 0, 'expires_at' => Clock::now() + $ttl,
        ]);
        return $nonce;
    }

    /** True exactly once for a valid, unexpired nonce of this user, account and purpose. */
    public static function consume(string $nonce, int $userId, int $clientId, string $purpose): bool
    {
        if (!preg_match('~^[a-f0-9]{32}$~', $nonce)) {
            return false;
        }
        $now = Clock::now();
        return Db::table('mod_mcsec_nonces')->where('nonce', $nonce)->where('user_id', $userId)->where('client_id', $clientId)
            ->where('purpose', substr($purpose, 0, 32))->where('used_at', 0)->where('expires_at', '>=', $now)
            ->update(['used_at' => $now]) === 1;
    }

    public static function purge(): void
    {
        Db::table('mod_mcsec_nonces')->where('expires_at', '<', Clock::now() - 86400)->delete();
    }
}
