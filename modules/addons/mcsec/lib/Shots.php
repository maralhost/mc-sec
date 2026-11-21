<?php

declare(strict_types=1);

namespace McSec;

/**
 * One screenshot per asset, taken by OASM during discovery and copied here by the worker (OASM's own links are signed
 * and expire in 48 hours, and its storage is not meant to be reached by customers' browsers). Kept in the database as
 * base64 (about 100 KB each on staging): WHMCS module folders are not reliably writable.
 * The picture is pixels of a customer's site, so it is treated as untrusted: only JPEG or PNG by their own magic
 * bytes, a size cap, and served with nosniff from an authenticated route that checks the account (Controller).
 */
final class Shots
{
    private const MAX = 700000;

    /**
     * Picks the best shot a scan saw (the asset's own host on 443, then 80, then any) and stores it.
     * @param array<int,array{host:string,port:int,path:string}> $shots paths under the OASM base URL
     */
    public static function save(object $asset, array $shots): bool
    {
        $best = null;
        $rank = -1;
        foreach ($shots as $s) {
            $path = (string) ($s['path'] ?? '');
            // only OASM's own storage route, relative: never a URL a scanned site could have planted
            if (!preg_match('~^/api/storage/[A-Za-z0-9/_.-]+\?[\x21-\x7E]+$~', $path) || str_contains($path, '..')) {
                continue;
            }
            $own = strtolower((string) ($s['host'] ?? '')) === strtolower((string) $asset->value);
            $r = ($own ? 10 : 0) + ((int) ($s['port'] ?? 0) === 443 ? 2 : ((int) ($s['port'] ?? 0) === 80 ? 1 : 0));
            if ($r > $rank) {
                [$best, $rank] = [$s, $r];
            }
        }
        $base = rtrim(Settings::get('oasm_url'), '/');
        if ($best === null || !preg_match('~^https?://~i', $base)) {
            return false;
        }
        $r = Http::request('GET', $base . $best['path'], ['Accept' => 'image/*'], null, ['timeout' => 15, 'connect' => 6, 'max_bytes' => self::MAX + 1, 'verify' => Settings::bool('oasm_verify_tls')]);
        $img = (string) $r['body'];
        $mime = self::mime($img);
        if ($r['status'] !== 200 || $mime === '' || strlen($img) > self::MAX) {
            return false;
        }
        $row = ['client_id' => (int) $asset->client_id, 'host' => mb_substr((string) $best['host'], 0, 255), 'mime' => $mime, 'data' => base64_encode($img), 'taken_at' => Clock::now()];
        if (Db::table('mod_mcsec_shots')->where('asset_id', $asset->id)->update($row) === 0 && !Db::table('mod_mcsec_shots')->where('asset_id', $asset->id)->exists()) {
            Db::table('mod_mcsec_shots')->insert($row + ['asset_id' => (int) $asset->id]);
        }
        return true;
    }

    /** image/jpeg or image/png by the file's own first bytes ('' = neither). */
    public static function mime(string $bytes): string
    {
        return match (true) {
            str_starts_with($bytes, "\xFF\xD8\xFF") => 'image/jpeg',
            str_starts_with($bytes, "\x89PNG\r\n\x1A\n") => 'image/png',
            default => '',
        };
    }

    /** The picture of one asset of this account: ['mime','bytes','taken_at'] or null. */
    public static function get(int $clientId, int $assetId): ?array
    {
        $r = $assetId > 0 ? Db::table('mod_mcsec_shots')->where('asset_id', $assetId)->where('client_id', $clientId)->first() : null;
        $bytes = $r ? (string) base64_decode((string) $r->data, true) : '';
        return $r && self::mime($bytes) === (string) $r->mime ? ['mime' => (string) $r->mime, 'bytes' => $bytes, 'taken_at' => (int) $r->taken_at] : null;
    }

    /** @return array<int,int> asset id => taken_at, for the assets of an account that have a picture */
    public static function forClient(int $clientId): array
    {
        $out = [];
        foreach (Db::rows(Db::table('mod_mcsec_shots')->where('client_id', $clientId)->select(['asset_id', 'taken_at'])) as $r) {
            $out[(int) $r->asset_id] = (int) $r->taken_at;
        }
        return $out;
    }

    public static function forget(int $assetId): void
    {
        Db::table('mod_mcsec_shots')->where('asset_id', $assetId)->delete();
    }
}
