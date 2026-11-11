<?php

declare(strict_types=1);

namespace McSec;

/**
 * Secrets at rest (backend passwords, AI key, bot tokens, engine session cookies). Inside WHMCS: its own
 * encrypt()/decrypt() (key = cc_encryption_hash in configuration.php, never in the database). Outside WHMCS
 * (tests): AES-256-GCM with a per-installation key. A value that cannot be decrypted reads as ''.
 */
final class Crypto
{
    private const PREFIX = 'mcs1:';

    public static function encrypt(string $plain): string
    {
        if (function_exists('encrypt') && !self::testing()) {
            return self::PREFIX . 'w:' . (string) encrypt($plain);
        }
        $iv = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plain, 'aes-256-gcm', self::localKey(), OPENSSL_RAW_DATA, $iv, $tag);
        return self::PREFIX . 'g:' . base64_encode($iv . $tag . $ct);
    }

    public static function decrypt(string $stored): string
    {
        if (!str_starts_with($stored, self::PREFIX)) {
            return '';
        }
        $body = substr($stored, strlen(self::PREFIX));
        try {
            if (str_starts_with($body, 'w:')) {
                return function_exists('decrypt') ? (string) decrypt(substr($body, 2)) : '';
            }
            if (str_starts_with($body, 'g:')) {
                $raw = base64_decode(substr($body, 2), true);
                if ($raw === false || strlen($raw) < 29) {
                    return '';
                }
                $out = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', self::localKey(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
                return $out === false ? '' : $out;
            }
        } catch (\Throwable $e) {
            return '';
        }
        return '';
    }

    /** Random token for verification records, webhook secrets and link codes. */
    public static function token(int $bytes = 16): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /** Short human code (Telegram/Bale linking): no 0/O, 1/I. */
    public static function code(int $len = 8): string
    {
        $a = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
        $s = '';
        for ($i = 0; $i < $len; $i++) {
            $s .= $a[random_int(0, strlen($a) - 1)];
        }
        return $s;
    }

    private static function testing(): bool
    {
        return defined('MCSEC_TESTING');
    }

    private static function localKey(): string
    {
        static $key = null;
        if ($key === null) {
            $k = '';
            try {
                $k = (string) Db::table('mod_mcsec_settings')->where('k', 'local_key')->value('v');
                if ($k === '') {
                    $k = bin2hex(random_bytes(32));
                    Db::table('mod_mcsec_settings')->insert(['k' => 'local_key', 'v' => $k]);
                }
            } catch (\Throwable $e) {
                $k = hash('sha256', __DIR__);
            }
            $key = hash('sha256', $k, true);
        }
        return $key;
    }
}
