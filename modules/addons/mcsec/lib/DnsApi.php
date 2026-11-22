<?php

declare(strict_types=1);

namespace McSec;

/**
 * «تأیید خودکار» for a domain whose DNS is at a provider with an API (switch verify_dns_api): the customer pastes a
 * token of their own DNS panel once, and the proof record (TXT _mcsec-verify) is created for them.
 *
 * - Creating the record proves NOTHING by itself: anyone can add any domain as an inactive zone in their own
 *   provider account. Ownership is still decided only by Verify::check reading the public DNS. This class only saves
 *   the customer the trip to their DNS panel.
 * - The token is used in this one request and thrown away: never stored, never logged, never shown back.
 * - Only fixed provider addresses are called (no customer-supplied URL), in the customer's explicit POST.
 */
final class DnsApi
{
    /** key => [name, where the customer makes the token] */
    public const PROVIDERS = [
        'cloudflare' => ['Cloudflare', 'در Cloudflare: My Profile ← API Tokens ← Create Token ← قالب «Edit zone DNS» و فقط همین دامنه را انتخاب کنید.'],
        'arvan' => ['آروان‌کلاد', 'در آروان‌کلاد: تنظیمات حساب ← کلید API (Machine User) با دسترسی به DNS همین دامنه.'],
    ];

    /** Providers the admin switched on, in the order of PROVIDERS. @return string[] */
    public static function enabled(): array
    {
        if (!Settings::bool('verify_dns_api')) {
            return [];
        }
        return array_values(array_intersect(array_keys(self::PROVIDERS), Settings::csv('verify_dns_providers')));
    }

    /**
     * Creates the TXT proof for $domain at the provider with the customer's token.
     * @return array{ok:bool,error:string}
     */
    public static function addProof(string $provider, string $token, string $domain, string $proof): array
    {
        $no = fn (string $e): array => ['ok' => false, 'error' => $e];
        if (!in_array($provider, self::enabled(), true)) {
            return $no('این پنل DNS پشتیبانی نمی‌شود.');
        }
        $token = trim((string) preg_replace('~^(?:bearer|apikey)\s+~i', '', trim($token)));
        if (!preg_match('~^[A-Za-z0-9_.\-]{20,200}$~', $token)) {
            return $no('توکن را کامل و بی فاصله بچسبانید.');
        }
        $domain = strtolower($domain);
        $apex = Net::apex($domain);
        $name = self::PROVIDERS[$provider][0];
        try {
            $r = $provider === 'cloudflare' ? self::cloudflare($token, $domain, $apex, $proof) : self::arvan($token, $domain, $apex, $proof);
        } catch (\Throwable $e) {
            Trace::warn('verify', 'dnsapi.' . $provider, $e->getMessage(), ['domain' => $domain]);
            return $no('به ' . $name . ' وصل نشدیم. کمی بعد دوباره امتحان کنید یا رکورد را دستی بسازید.');
        }
        if ($r === 'ok') {
            return ['ok' => true, 'error' => ''];
        }
        return $no(match ($r) {
            'auth' => $name . ' این توکن را نپذیرفت یا توکن به DNS این دامنه دسترسی ندارد. توکن را با دسترسی «ویرایش DNS» همین دامنه بسازید.',
            'zone' => 'دامنه‌ی ' . $apex . ' در این حساب ' . $name . ' پیدا نشد. اگر DNS دامنه جای دیگری است، رکورد را دستی بسازید.',
            'net' => 'به ' . $name . ' وصل نشدیم. کمی بعد دوباره امتحان کنید یا رکورد را دستی بسازید.',
            default => $name . ' رکورد را نساخت. می‌توانید رکورد را دستی بسازید.',
        });
    }

    /** @return string ok | auth | zone | net | fail */
    private static function cloudflare(string $token, string $domain, string $apex, string $proof): string
    {
        $h = ['Authorization' => 'Bearer ' . $token];
        $opt = ['timeout' => 15, 'connect' => 6, 'max_bytes' => 262144];
        $z = Http::request('GET', 'https://api.cloudflare.com/client/v4/zones?name=' . rawurlencode($apex), $h, null, $opt);
        if ($z['status'] === 0) {
            return 'net';
        }
        if (in_array($z['status'], [400, 401, 403], true)) {
            return 'auth';
        }
        $zone = (string) ($z['json']['result'][0]['id'] ?? '');
        if (!$z['ok'] || !preg_match('~^[a-f0-9]{32}$~', $zone)) {
            return 'zone';
        }
        $r = Http::request('POST', 'https://api.cloudflare.com/client/v4/zones/' . $zone . '/dns_records', $h,
            ['type' => 'TXT', 'name' => '_mcsec-verify.' . $domain, 'content' => $proof, 'ttl' => 120, 'comment' => 'MC-Sec ownership proof'], $opt);
        if ($r['status'] === 0) {
            return 'net';
        }
        if ($r['ok'] && !empty($r['json']['success'])) {
            return 'ok';
        }
        // the same record is already there (an earlier try): that is what we wanted
        foreach ((array) ($r['json']['errors'] ?? []) as $e) {
            if (in_array((int) ($e['code'] ?? 0), [81057, 81058], true)) {
                return 'ok';
            }
        }
        return in_array($r['status'], [401, 403], true) ? 'auth' : 'fail';
    }

    /** @return string ok | auth | zone | net | fail */
    private static function arvan(string $token, string $domain, string $apex, string $proof): string
    {
        $sub = $domain === $apex ? '' : substr($domain, 0, -strlen('.' . $apex));
        $r = Http::request('POST', 'https://napi.arvancloud.ir/cdn/4.0/domains/' . rawurlencode($apex) . '/dns-records', ['Authorization' => 'Apikey ' . $token],
            ['type' => 'txt', 'name' => '_mcsec-verify' . ($sub !== '' ? '.' . $sub : ''), 'value' => ['text' => $proof], 'ttl' => 120, 'cloud' => false], ['timeout' => 15, 'connect' => 6, 'max_bytes' => 262144]);
        if ($r['status'] === 0) {
            return 'net';
        }
        if ($r['ok']) {
            return 'ok';
        }
        if (in_array($r['status'], [401, 403], true)) {
            return 'auth';
        }
        if ($r['status'] === 404) {
            return 'zone';
        }
        // 422 with "already exists": the record from an earlier try
        return $r['status'] === 422 && preg_match('~exist|تکرار|موجود~iu', (string) $r['body']) ? 'ok' : 'fail';
    }
}
