<?php

declare(strict_types=1);

namespace McSec;

/** Persian text helpers: escaping, digits, money and Jalali dates for display (same rules as MC-AI). */
final class Text
{
    private const FA = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
    private const AR = ['٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩'];
    public const MONTHS = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];

    public static function e($s): string
    {
        return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function fa($s): string
    {
        return str_replace(range(0, 9), self::FA, (string) $s);
    }

    /** Persian/Arabic digits and separators to ASCII, for parsing user input. */
    public static function toAscii(string $s): string
    {
        $s = str_replace(self::FA, range(0, 9), $s);
        $s = str_replace(self::AR, range(0, 9), $s);
        return str_replace(['٫', '٬', '،'], ['.', '', ''], $s);
    }

    /** 1234567 → "۱٬۲۳۴٬۵۶۷" */
    public static function num(int $n): string
    {
        $neg = $n < 0;
        $groups = array_reverse(array_map('strrev', str_split(strrev((string) abs($n)), 3)));
        return ($neg ? '−' : '') . self::fa(implode('٬', $groups));
    }

    /**
     * An amount in a client's WHMCS currency, e.g. "۱٬۲۰۰٬۰۰۰ ریال". Whole units only: the founder's
     * production currency is IRR without decimals; other currencies show two decimals.
     */
    public static function money(float $amount, ?object $currency = null): string
    {
        $code = strtoupper((string) ($currency->code ?? 'IRR'));
        if (in_array($code, ['IRR', 'IRT', 'TOMAN'], true) || (int) ($currency->format ?? 0) === 4) {
            $s = self::num((int) round($amount));
        } else {
            $c = (int) round($amount * 100);
            $s = self::num(intdiv($c, 100)) . '٫' . self::fa(str_pad((string) abs($c % 100), 2, '0', STR_PAD_LEFT));
        }
        $prefix = trim((string) ($currency->prefix ?? ''));
        $suffix = trim((string) ($currency->suffix ?? ''));
        if ($prefix === '' && $suffix === '') {
            $suffix = $code === 'IRR' ? 'ریال' : $code;
        }
        return trim(($prefix !== '' ? $prefix . ' ' : '') . $s . ($suffix !== '' ? ' ' . $suffix : ''));
    }

    /** @return array{0:int,1:int,2:int} */
    public static function jalali(int $gy, int $gm, int $gd): array
    {
        $gdm = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        $gy2 = $gm > 2 ? $gy + 1 : $gy;
        $days = 355666 + (365 * $gy) + intdiv($gy2 + 3, 4) - intdiv($gy2 + 99, 100) + intdiv($gy2 + 399, 400) + $gd + $gdm[$gm - 1];
        $jy = -1595 + (33 * intdiv($days, 12053));
        $days %= 12053;
        $jy += 4 * intdiv($days, 1461);
        $days %= 1461;
        if ($days > 365) {
            $jy += intdiv($days - 1, 365);
            $days = ($days - 1) % 365;
        }
        if ($days < 186) {
            $jm = 1 + intdiv($days, 31);
            $jd = 1 + ($days % 31);
        } else {
            $jm = 7 + intdiv($days - 186, 30);
            $jd = 1 + (($days - 186) % 30);
        }
        return [$jy, $jm, $jd];
    }

    /** Epoch → "۱۵ آبان ۱۴۰۵، ۱۸:۳۰" in Tehran time (the customers' clock). */
    public static function date(int $ts, bool $withTime = true): string
    {
        if ($ts <= 0) {
            return '—';
        }
        $d = (new \DateTimeImmutable('@' . $ts))->setTimezone(new \DateTimeZone('Asia/Tehran'));
        [$y, $m, $day] = self::jalali((int) $d->format('Y'), (int) $d->format('n'), (int) $d->format('j'));
        $s = self::fa($day) . ' ' . self::MONTHS[$m - 1] . ' ' . self::fa($y);
        return $withTime ? $s . '، ' . self::fa($d->format('H:i')) : $s;
    }

    /** A WHMCS date ("2026-11-06") → "۱۵ آبان ۱۴۰۵"; empty and zero dates → "—". */
    public static function ymd(?string $date): string
    {
        if ($date === null || $date === '' || str_starts_with($date, '0000')) {
            return '—';
        }
        $p = explode('-', substr($date, 0, 10));
        if (count($p) !== 3) {
            return '—';
        }
        [$y, $m, $d] = self::jalali((int) $p[0], (int) $p[1], (int) $p[2]);
        return self::fa($d) . ' ' . self::MONTHS[$m - 1] . ' ' . self::fa($y);
    }

    /** "۳ دقیقه پیش" */
    public static function ago(int $ts): string
    {
        if ($ts <= 0) {
            return 'هرگز';
        }
        $d = max(0, Clock::now() - $ts);
        if ($d < 60) {
            return 'همین حالا';
        }
        if ($d < 3600) {
            return self::fa(intdiv($d, 60)) . ' دقیقه پیش';
        }
        if ($d < 86400) {
            return self::fa(intdiv($d, 3600)) . ' ساعت پیش';
        }
        return self::fa(intdiv($d, 86400)) . ' روز پیش';
    }

    /** Trims and collapses spaces of a short name (workspace, organization); Persian-safe, Arabic ي and ك become ی and ک. */
    public static function name(string $s, int $max = 80): string
    {
        $s = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s) ?? '';
        $s = preg_replace('/\s+/u', ' ', $s) ?? '';
        $s = preg_replace('/^\s+|\s+$/u', '', $s) ?? '';
        return mb_substr(self::letters($s), 0, $max);
    }

    /** Arabic Yeh, Alef Maksura and Kaf (typed on an Arabic keyboard) as the Persian letters, so the same name is the same text. */
    public static function letters(string $s): string
    {
        return strtr($s, ['ي' => 'ی', 'ى' => 'ی', 'ك' => 'ک']);
    }

    /** Persian alphabet: آ comes first; پ، چ، ژ and گ sit where a Persian reader expects them, not after ی as in Unicode. */
    private const ALPHABET = ['آ', 'ا', 'ب', 'پ', 'ت', 'ث', 'ج', 'چ', 'ح', 'خ', 'د', 'ذ', 'ر', 'ز', 'ژ', 'س', 'ش', 'ص', 'ض', 'ط', 'ظ', 'ع', 'غ', 'ف', 'ق', 'ک', 'گ', 'ل', 'م', 'ن', 'و', 'ه', 'ی'];

    /**
     * A key that sorts names in Persian alphabetical order with strcmp (the database's unicode_ci order does not):
     * digits and Latin letters first, then the Persian alphabet; the zero-width non-joiner and spaces are ignored.
     */
    public static function sortKey(string $s): string
    {
        static $map = null;
        if ($map === null) {
            $map = ['أ' => "\x02\x41", 'إ' => "\x02\x41", 'ؤ' => "\x02\x5e", 'ئ' => "\x02\x60", 'ة' => "\x02\x5f"];
            foreach (self::ALPHABET as $i => $ch) {
                $map[$ch] = "\x02" . chr(0x40 + $i);
            }
        }
        $s = mb_strtolower(self::letters(self::toAscii($s)));
        $key = '';
        foreach (preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
            if ($ch === "\u{200C}" || $ch === ' ') {
                continue;
            }
            $key .= $map[$ch] ?? ("\x01" . $ch);
        }
        return $key;
    }

    /** Sorts rows (objects or arrays) by a name field in Persian order, then by id, keeping keys when asked. */
    public static function sortByName(array $rows, string $field = 'name', bool $keepKeys = false): array
    {
        $get = fn ($r, string $f) => (string) (is_array($r) ? ($r[$f] ?? '') : ($r->$f ?? ''));
        $cmp = fn ($a, $b) => [self::sortKey($get($a, $field)), (int) $get($a, 'id')] <=> [self::sortKey($get($b, $field)), (int) $get($b, 'id')];
        $keepKeys ? uasort($rows, $cmp) : usort($rows, $cmp);
        return $rows;
    }
}
