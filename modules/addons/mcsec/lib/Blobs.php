<?php

declare(strict_types=1);

namespace McSec;

/**
 * Small files an admin uploads for the report template (0.14.0): the logo and, when wanted, a font. They live in the
 * database (mod_mcsec_blobs, base64), never in the module's folder, in git or in the release package, so a licensed
 * font (Ray) can be used on the server without ever being shipped (rule 5), and a read-only module folder is fine.
 * Only the fixed keys of KINDS are accepted; what a file is, is decided from its own bytes, never from its name or
 * the type the browser sent.
 */
final class Blobs
{
    /** key => [what it must be, largest size in bytes] */
    public const KINDS = [
        'pdf_logo' => ['image', 400 * 1024],
        'pdf_font' => ['font', 3 * 1024 * 1024],
        'pdf_font_bold' => ['font', 3 * 1024 * 1024],
    ];

    /** 'image/png', 'image/jpeg' or 'font/ttf' from the bytes themselves; '' for anything else. */
    public static function sniff(string $bytes): string
    {
        if (str_starts_with($bytes, "\x89PNG\r\n\x1a\n")) {
            return 'image/png';
        }
        if (str_starts_with($bytes, "\xFF\xD8\xFF")) {
            return 'image/jpeg';
        }
        // TrueType outlines only: TCPDF cannot embed CFF (OTTO) fonts
        if (str_starts_with($bytes, "\x00\x01\x00\x00") || str_starts_with($bytes, 'true')) {
            return 'font/ttf';
        }
        return '';
    }

    /** A PNG whose chunks are all there, each with a right checksum, up to IEND: the PDF library reads it chunk by chunk. */
    private static function pngWhole(string $b): bool
    {
        $at = 8;
        $len = strlen($b);
        for ($i = 0; $i < 5000 && $at + 12 <= $len; $i++) {
            $n = unpack('N', substr($b, $at, 4))[1];
            $type = substr($b, $at + 4, 4);
            if ($n > $len || $at + 12 + $n > $len || unpack('N', substr($b, $at + 8 + $n, 4))[1] !== crc32($type . substr($b, $at + 8, $n))) {
                return false;
            }
            if ($type === 'IEND') {
                return true;
            }
            $at += 12 + $n;
        }
        return false;
    }

    /** @return array{ok:bool,error?:string,mime?:string} */
    public static function put(string $key, string $bytes): array
    {
        if (!isset(self::KINDS[$key])) {
            return ['ok' => false, 'error' => 'این فایل شناخته نشد.'];
        }
        [$want, $max] = self::KINDS[$key];
        if ($bytes === '') {
            return ['ok' => false, 'error' => 'فایلی انتخاب نشده یا خالی است.'];
        }
        if (strlen($bytes) > $max) {
            return ['ok' => false, 'error' => 'فایل بزرگ است؛ حداکثر ' . Text::fa((int) round($max / 1024)) . ' کیلوبایت پذیرفته می‌شود.'];
        }
        $mime = self::sniff($bytes);
        if ($want === 'image' && !in_array($mime, ['image/png', 'image/jpeg'], true)) {
            return ['ok' => false, 'error' => 'لوگو باید PNG یا JPEG باشد (SVG و GIF پذیرفته نمی‌شود).'];
        }
        if ($want === 'image') {
            $info = @getimagesizefromstring($bytes);
            if (!$info || $info[0] < 16 || $info[1] < 16 || $info[0] > 4000 || $info[1] > 4000 || ($mime === 'image/png' && !self::pngWhole($bytes))) {
                return ['ok' => false, 'error' => 'تصویر خوانده نشد یا اندازه‌اش مناسب نیست (از ۱۶ تا ۴۰۰۰ پیکسل).'];
            }
        }
        if ($want === 'font' && $mime !== 'font/ttf') {
            return ['ok' => false, 'error' => 'فونت باید فایل TTF (TrueType) باشد. فایل OTF و WOFF پذیرفته نمی‌شود.'];
        }
        $row = ['mime' => $mime, 'size' => strlen($bytes), 'sha' => sha1($bytes), 'bytes' => base64_encode($bytes), 'updated_at' => Clock::now()];
        if (Db::table('mod_mcsec_blobs')->where('k', $key)->exists()) {
            Db::table('mod_mcsec_blobs')->where('k', $key)->update($row);
        } else {
            Db::table('mod_mcsec_blobs')->insert(['k' => $key] + $row);
        }
        unset(self::$cache[$key]);
        return ['ok' => true, 'mime' => $mime];
    }

    /** @var array<string,?array> */
    private static array $cache = [];

    /** @return array{mime:string,bytes:string,sha:string,size:int}|null */
    public static function get(string $key): ?array
    {
        if (!isset(self::KINDS[$key])) {
            return null;
        }
        if (!array_key_exists($key, self::$cache)) {
            try {
                $r = Db::table('mod_mcsec_blobs')->where('k', $key)->first();
            } catch (\Throwable $e) {
                $r = null;
            }
            $bytes = $r ? (string) base64_decode((string) $r->bytes, true) : '';
            self::$cache[$key] = $r && $bytes !== '' ? ['mime' => (string) $r->mime, 'bytes' => $bytes, 'sha' => (string) $r->sha, 'size' => (int) $r->size] : null;
        }
        return self::$cache[$key];
    }

    /** Size and time of what is stored, without loading the bytes. @return array{mime:string,size:int,updated_at:int}|null */
    public static function info(string $key): ?array
    {
        try {
            $r = Db::table('mod_mcsec_blobs')->where('k', $key)->first(['mime', 'size', 'updated_at']);
        } catch (\Throwable $e) {
            return null;
        }
        return $r ? ['mime' => (string) $r->mime, 'size' => (int) $r->size, 'updated_at' => (int) $r->updated_at] : null;
    }

    public static function remove(string $key): void
    {
        if (isset(self::KINDS[$key])) {
            Db::table('mod_mcsec_blobs')->where('k', $key)->delete();
            unset(self::$cache[$key]);
        }
    }

    public static function forget(): void
    {
        self::$cache = [];
    }
}
