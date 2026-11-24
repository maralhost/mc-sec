<?php

declare(strict_types=1);

namespace McSec;

/**
 * Persian and English for everything a customer sees (0.13.0). The module is written in Persian; the Persian text
 * itself is the key, and lang/en/*.php hold its English (each file returns [Persian => English]).
 *
 * - Lang::t('… {n} …', ['n' => $x]) for a sentence built from parts: in Persian the placeholders are filled in the
 *   Persian text, in English in the translation, so each language keeps its own word order.
 * - Text::e() (and so Ui::e() and every block that escapes a label) translates a whole string that is in the
 *   dictionary by itself, so labels from constants, table heads, chips and plain messages need no call.
 * - A text that has no English yet is shown in Persian: never an empty place, never a key.
 * - Digits, dates, "ago" and money follow the language in Text (Latin digits and Gregorian dates in English).
 *
 * Which language: the visitor's WHMCS language in the client area (session, then the account's own, then the
 * system's); the account's language for anything written in the background (notices, e-mails, reports, findings).
 * 'farsi' / 'persian' is Persian; every other WHMCS language gets English. The admin panel is Persian.
 */
final class Lang
{
    /** Tests and previews: 'fa' or 'en'. */
    public static ?string $force = null;

    private static ?string $cur = null;
    /** @var array<string,string>|null */
    private static ?array $dict = null;

    public static function code(): string
    {
        if (self::$force !== null) {
            return self::$force;
        }
        return self::$cur ??= self::detect();
    }

    public static function fa(): bool
    {
        return self::code() === 'fa';
    }

    public static function rtl(): bool
    {
        return self::code() === 'fa';
    }

    public static function dir(): string
    {
        return self::rtl() ? 'rtl' : 'ltr';
    }

    /** dir and lang attributes for a root element. */
    public static function attrs(): string
    {
        return 'dir="' . self::dir() . '" lang="' . self::code() . '"';
    }

    public static function set(?string $code): void
    {
        self::$cur = $code === null ? null : ($code === 'fa' ? 'fa' : 'en');
    }

    /** Runs $fn in a language (the account's, for background work), then puts the old one back. */
    public static function with(string $code, callable $fn)
    {
        [$oldCur, $oldForce] = [self::$cur, self::$force];
        self::$force = null;
        self::$cur = $code === 'fa' ? 'fa' : 'en';
        try {
            return $fn();
        } finally {
            self::$cur = $oldCur;
            self::$force = $oldForce;
        }
    }

    /** A WHMCS language name ('farsi', 'english', …) as ours. */
    public static function fromName(string $name): string
    {
        $n = strtolower(trim($name));
        return $n === '' ? '' : (in_array($n, ['farsi', 'persian', 'fa'], true) ? 'fa' : 'en');
    }

    /** The language an account reads: its own in WHMCS, else the system's. */
    public static function forClient(int $clientId): string
    {
        $c = self::fromName(Whmcs::clientLanguage($clientId));
        return $c !== '' ? $c : self::system();
    }

    public static function system(): string
    {
        $c = self::fromName(Db::whmcsSetting('Language'));
        return $c !== '' ? $c : 'fa';
    }

    private static function detect(): string
    {
        try {
            // admin pages are Persian
            if (defined('ADMINAREA') && ADMINAREA) {
                return 'fa';
            }
            $s = self::fromName((string) ($_SESSION['Language'] ?? ''));
            if ($s !== '') {
                return $s;
            }
            $cid = (int) ($_SESSION['uid'] ?? 0);
            if ($cid > 0) {
                return self::forClient($cid);
            }
            return self::system();
        } catch (\Throwable $e) {
            return 'fa';
        }
    }

    /** @return array<string,string> */
    private static function dict(): array
    {
        if (self::$dict === null) {
            self::$dict = [];
            foreach (glob(MCSEC_DIR . '/lang/en/*.php') ?: [] as $f) {
                $d = include $f;
                if (is_array($d)) {
                    self::$dict += $d;
                }
            }
        }
        return self::$dict;
    }

    /** The text in the current language; {name} placeholders are filled from $vars. */
    public static function t(string $fa, array $vars = []): string
    {
        $s = self::code() === 'fa' ? $fa : (self::dict()[$fa] ?? $fa);
        if ($vars) {
            $map = [];
            foreach ($vars as $k => $v) {
                $map['{' . $k . '}'] = (string) $v;
            }
            $s = strtr($s, $map);
        }
        return $s;
    }

    /** For Text::e(): the English of a whole string when there is one; anything else comes back untouched. */
    public static function whole(string $s): string
    {
        if (self::code() === 'fa' || $s === '' || !preg_match('~[\x{0600}-\x{06FF}]~u', $s)) {
            return $s;
        }
        return self::dict()[$s] ?? $s;
    }

    /** True when the dictionary has this exact text. */
    public static function has(string $fa): bool
    {
        return isset(self::dict()[$fa]);
    }

    /** "a، b، c" or "a, b, c". */
    public static function join(array $items): string
    {
        return implode(self::fa() ? '، ' : ', ', $items);
    }

    /** The whole dictionary (tools and tests). @return array<string,string> */
    public static function all(): array
    {
        return self::dict();
    }
}
