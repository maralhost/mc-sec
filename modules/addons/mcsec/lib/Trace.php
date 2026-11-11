<?php

declare(strict_types=1);

namespace McSec;

/**
 * The technical log: every failed backend call (OASM, Osmedeus, AI), hook error, worker failure and credit movement,
 * with a short reference code. The customer sees only the code («کد پیگیری: MS-7K2Q9X»); support finds the whole
 * story under the same code in the admin «گزارش فنی» page. Errors also go to WHMCS's Activity Log with the code.
 * Never stores a secret: details pass through scrub() and long texts are cut.
 */
final class Trace
{
    public const LEVELS = ['info' => 'اطلاع', 'warn' => 'هشدار', 'error' => 'خطا'];
    public const AREAS = [
        'whmcs' => 'فراخوانی WHMCS', 'hook' => 'هوک', 'worker' => 'کار پس‌زمینه', 'credit' => 'اعتبار', 'engine' => 'موتور اسکن',
        'verify' => 'تأیید مالکیت', 'ai' => 'هوش مصنوعی', 'notify' => 'اعلان', 'client' => 'ناحیه‌ی کاربری', 'admin' => 'پنل مدیر', 'plan' => 'پلن',
    ];

    /** Who the current request is about (the client controller sets it once it knows the person). */
    public static array $ctx = [];

    /** No 0/O, 1/I/L: a code read over the phone is never ambiguous. */
    private const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

    private const SECRET_KEYS = '~pass|secret|token|api[_-]?key|authorization|cookie|session|private|credential|bearer~i';

    public static function ref(): string
    {
        $s = '';
        for ($i = 0; $i < 6; $i++) {
            $s .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
        }
        return 'MS-' . $s;
    }

    public static function error(string $area, string $action, string $message, array $detail = [], array $ctx = []): string
    {
        return self::write('error', $area, $action, $message, $detail, $ctx);
    }

    public static function warn(string $area, string $action, string $message, array $detail = [], array $ctx = []): string
    {
        return self::write('warn', $area, $action, $message, $detail, $ctx);
    }

    public static function info(string $area, string $action, string $message, array $detail = [], array $ctx = []): string
    {
        return self::write('info', $area, $action, $message, $detail, $ctx);
    }

    /** The detail of an exception, for the log (class, message, where). */
    public static function exception(\Throwable $e): array
    {
        return ['exception' => get_class($e), 'message' => mb_substr($e->getMessage(), 0, 500), 'at' => basename($e->getFile()) . ':' . $e->getLine()];
    }

    /** Replaces the value of any key that looks like a secret, at any depth. */
    public static function scrub(array $data): array
    {
        $out = [];
        foreach ($data as $k => $v) {
            if (is_string($k) && preg_match(self::SECRET_KEYS, $k)) {
                $out[$k] = '[hidden]';
            } elseif (is_array($v)) {
                $out[$k] = self::scrub($v);
            } else {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    private static function write(string $level, string $area, string $action, string $message, array $detail, array $ctx): string
    {
        $ref = self::ref();
        $c = $ctx + self::$ctx;
        $message = mb_substr(trim($message), 0, 250);
        try {
            Db::table('mod_mcsec_log')->insert([
                'ref' => $ref,
                'level' => $level,
                'area' => substr($area, 0, 16),
                'action' => substr($action, 0, 64),
                'client_id' => (int) ($c['client_id'] ?? 0),
                'user_id' => (int) ($c['user_id'] ?? 0),
                'admin_id' => (int) ($c['admin_id'] ?? Auth::masqueradingAdmin()),
                'message' => $message,
                'detail' => $detail ? Db::json(self::clip(self::scrub($detail))) : null,
                'ip' => substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45),
                'created_at' => Clock::now(),
            ]);
        } catch (\Throwable $e) {
            // the log must never break the request; the Activity Log line below still says what happened
        }
        if ($level !== 'info') {
            Db::log($ref . ' ' . $area . ' ' . $action . ': ' . $message);
        }
        return $ref;
    }

    /** Long texts (a backend answer) are cut, so one row never grows without bound. */
    private static function clip(array $data, int $depth = 0): array
    {
        $out = [];
        foreach ($data as $k => $v) {
            if (is_array($v)) {
                $out[$k] = $depth < 4 ? self::clip($v, $depth + 1) : '[…]';
            } elseif (is_string($v)) {
                $out[$k] = mb_strlen($v) > 400 ? mb_substr($v, 0, 400) . '…' : $v;
            } else {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    /** «کد پیگیری» sentence for the customer. */
    public static function forCustomer(string $ref): string
    {
        return $ref !== '' ? ' کد پیگیری: ' . $ref : '';
    }

    /** Nightly: keeps the last log_days days (at least 30). */
    public static function purge(): int
    {
        $days = max(30, Settings::int('log_days'));
        return Db::table('mod_mcsec_log')->where('created_at', '<', Clock::now() - $days * 86400)->delete();
    }
}
