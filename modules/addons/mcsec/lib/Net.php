<?php

declare(strict_types=1);

namespace McSec;

/**
 * Targets and the network: parsing what a customer types (a URL, a domain, an IP, a CIDR) into one normal form,
 * the registrable domain (apex) and its parents, public-IP checks, the blocklist, DNS lookups (mockable) and the
 * SSRF guard for customer-supplied URLs (webhooks).
 */
final class Net
{
    /** Tests: fn(string $name, string $type): array of records like dns_get_record (null = use the real resolver). */
    public static $resolver = null;

    /** Second-level public suffixes we meet often (Iran first). Not the full PSL: enough to find an apex. */
    private const MULTI_SUFFIX = [
        'co.ir', 'ac.ir', 'org.ir', 'net.ir', 'gov.ir', 'id.ir', 'sch.ir', 'mil.ir', 'ایران.ir',
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'com.tr', 'gen.tr', 'org.tr',
        'com.br', 'com.cn', 'com.hk', 'co.jp', 'co.in', 'co.za', 'com.sa', 'com.ae', 'co.ae', 'com.iq', 'com.af',
    ];

    /**
     * What a customer typed → ['kind' => domain|ip|cidr, 'value' => normal form] or ['error' => Persian text].
     * Accepts "https://Shop.Example.com/path", "example.com.", "1.2.3.4", "1.2.3.0/24", IPv6.
     */
    public static function parse(string $input): array
    {
        $s = trim(Text::toAscii($input));
        $s = preg_replace('~\s+~u', '', $s) ?? '';
        if ($s === '') {
            return ['error' => 'خالی است.'];
        }
        if (preg_match('~^[a-z][a-z0-9+.-]*://~i', $s)) {
            $host = parse_url($s, PHP_URL_HOST);
            if (!is_string($host) || $host === '') {
                return ['error' => 'نشانی را نشناختیم. فقط دامنه یا IP را بنویسید، مثل example.com'];
            }
            $s = trim($host, '[]');
        } else {
            $s = preg_replace('~[/?#].*$~', '', $s) ?? $s; // "example.com/path"
            if (preg_match('~^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$~', trim($input), $m)) {
                $s = $m[1] . '/' . $m[2];
            }
        }
        // CIDR (IPv4 /24–/32, the range OASM accepts)
        if (preg_match('~^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$~', $s, $m)) {
            $bits = (int) $m[2];
            if (!filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $bits < 24 || $bits > 32) {
                return ['error' => 'بازه‌ی IP باید IPv4 با پیشوند ۲۴ تا ۳۲ باشد، مثل 203.0.113.0/28'];
            }
            $net = long2ip(ip2long($m[1]) & (-1 << (32 - $bits)));
            return $bits === 32 ? ['kind' => 'ip', 'value' => $net] : ['kind' => 'cidr', 'value' => $net . '/' . $bits];
        }
        // host:port → host
        if (substr_count($s, ':') === 1 && preg_match('~^([^:]+):\d+$~', $s, $m)) {
            $s = $m[1];
        }
        if (filter_var($s, FILTER_VALIDATE_IP)) {
            return ['kind' => 'ip', 'value' => strtolower((string) inet_ntop((string) inet_pton($s)))];
        }
        $s = rtrim(mb_strtolower($s), '.');
        if (str_starts_with($s, '*.')) {
            return ['error' => 'الگوی ستاره‌دار لازم نیست: دامنه‌ی اصلی (' . substr($s, 2) . ') را بیفزایید؛ زیردامنه‌هایش خودکار در محدوده‌اند.'];
        }
        if (preg_match('~[^\x00-\x7F]~', $s)) {
            if (!function_exists('idn_to_ascii')) {
                return ['error' => 'دامنه‌ی حروف فارسی را به شکل punycode (xn--) بنویسید.'];
            }
            $a = idn_to_ascii($s, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (!is_string($a) || $a === '') {
                return ['error' => 'این دامنه درست نیست.'];
            }
            $s = $a;
        }
        if (strlen($s) > 253 || !preg_match('~^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$~', $s)) {
            return ['error' => 'این دامنه درست نیست. نمونه‌ی درست: shop.example.com'];
        }
        return ['kind' => 'domain', 'value' => $s];
    }

    /** The registrable domain: shop.example.co.ir → example.co.ir */
    public static function apex(string $domain): string
    {
        $parts = explode('.', strtolower($domain));
        $n = count($parts);
        if ($n <= 2) {
            return $domain;
        }
        $last2 = $parts[$n - 2] . '.' . $parts[$n - 1];
        $take = in_array($last2, self::MULTI_SUFFIX, true) ? 3 : 2;
        return implode('.', array_slice($parts, -$take));
    }

    /** example.com, shop.example.com for a.shop.example.com (nearest last), never past the apex. @return string[] */
    public static function parents(string $domain): array
    {
        $apex = self::apex($domain);
        $out = [];
        $d = $domain;
        while ($d !== $apex && str_contains($d, '.')) {
            $d = substr($d, strpos($d, '.') + 1);
            $out[] = $d;
            if ($d === $apex) {
                break;
            }
        }
        return $out;
    }

    /** Whether $sub is $domain itself or one of its subdomains. */
    public static function within(string $sub, string $domain): bool
    {
        return $sub === $domain || str_ends_with($sub, '.' . $domain);
    }

    public static function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $l = ip2long($ip);
            foreach ([['100.64.0.0', 10], ['198.18.0.0', 15], ['192.0.0.0', 24], ['192.0.2.0', 24], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['0.0.0.0', 8]] as [$n, $b]) {
                if (($l & (-1 << (32 - $b))) === (ip2long($n) & (-1 << (32 - $b)))) {
                    return false;
                }
            }
        } else {
            $low = strtolower($ip);
            if (str_starts_with($low, 'fc') || str_starts_with($low, 'fd') || str_starts_with($low, 'fe80') || str_starts_with($low, '2001:db8')) {
                return false;
            }
        }
        return true;
    }

    /** Whether an IP falls inside a CIDR (IPv4). */
    public static function inCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }
        [$net, $bits] = explode('/', $cidr, 2);
        $l = ip2long($ip);
        $n = ip2long($net);
        if ($l === false || $n === false) {
            return false;
        }
        $mask = -1 << (32 - (int) $bits);
        return ($l & $mask) === ($n & $mask);
    }

    /** The first blocklist line a target matches ('' = allowed). Lines: domain, *.domain, IP or CIDR. */
    public static function blocked(string $kind, string $value, ?string $list = null): string
    {
        foreach (preg_split('~\R~', $list ?? Settings::get('blocklist')) ?: [] as $line) {
            $p = strtolower(trim(Text::toAscii($line)));
            if ($p === '' || str_starts_with($p, '#')) {
                continue;
            }
            if ($kind === 'domain') {
                $d = ltrim($p, '*.');
                if ($d !== '' && !preg_match('~^[\d./]+$~', $d) && self::within($value, $d)) {
                    return $p;
                }
            } elseif (preg_match('~^[\d.]+(/\d+)?$~', $p)) {
                $ip = $kind === 'cidr' ? explode('/', $value)[0] : $value;
                if (self::inCidr($ip, $p)) {
                    return $p;
                }
            }
        }
        return '';
    }

    /** DNS records of one type as dns_get_record returns them; [] on failure. */
    public static function dns(string $name, string $type): array
    {
        if (self::$resolver !== null) {
            return (array) (self::$resolver)($name, $type);
        }
        $map = ['A' => DNS_A, 'AAAA' => DNS_AAAA, 'TXT' => DNS_TXT, 'MX' => DNS_MX, 'CNAME' => DNS_CNAME, 'NS' => DNS_NS, 'CAA' => defined('DNS_CAA') ? DNS_CAA : DNS_ANY, 'PTR' => DNS_PTR];
        if (!isset($map[$type])) {
            return [];
        }
        try {
            $r = @dns_get_record($name, $map[$type]);
            return is_array($r) ? $r : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** TXT strings of a name (multi-part records joined). @return string[] */
    public static function txt(string $name): array
    {
        $out = [];
        foreach (self::dns($name, 'TXT') as $r) {
            if (isset($r['entries']) && is_array($r['entries'])) {
                $out[] = implode('', $r['entries']);
            } elseif (isset($r['txt'])) {
                $out[] = (string) $r['txt'];
            }
        }
        return $out;
    }

    /** IPv4 and IPv6 addresses a name resolves to. @return string[] */
    public static function ips(string $name): array
    {
        $out = [];
        foreach (self::dns($name, 'A') as $r) {
            if (!empty($r['ip'])) {
                $out[] = (string) $r['ip'];
            }
        }
        foreach (self::dns($name, 'AAAA') as $r) {
            if (!empty($r['ipv6'])) {
                $out[] = strtolower((string) $r['ipv6']);
            }
        }
        return array_values(array_unique($out));
    }

    /** Reverse DNS of an IPv4 address ('' when none). */
    public static function ptr(string $ip): string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return '';
        }
        $name = implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        foreach (self::dns($name, 'PTR') as $r) {
            if (!empty($r['target'])) {
                return rtrim(strtolower((string) $r['target']), '.');
            }
        }
        return '';
    }

    /**
     * SSRF guard for a customer-supplied URL: http(s) only, no credentials, standard ports, and every address the
     * host resolves to must be public. Returns ['ok'=>true,'resolve'=>'host:port:ip'] to pin curl to the checked IP.
     */
    public static function publicUrl(string $url): array
    {
        $p = parse_url($url);
        if (!is_array($p) || !in_array(strtolower((string) ($p['scheme'] ?? '')), ['http', 'https'], true) || empty($p['host'])) {
            return ['ok' => false, 'error' => 'نشانی باید با https:// شروع شود.'];
        }
        if (isset($p['user']) || isset($p['pass'])) {
            return ['ok' => false, 'error' => 'نشانی نباید نام کاربری یا رمز داشته باشد.'];
        }
        $scheme = strtolower((string) $p['scheme']);
        $port = (int) ($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        if (!in_array($port, [80, 443, 8080, 8443], true)) {
            return ['ok' => false, 'error' => 'فقط درگاه‌های ۸۰، ۴۴۳، ۸۰۸۰ و ۸۴۴۳ پذیرفته می‌شوند.'];
        }
        $host = strtolower(trim((string) $p['host'], '[]'));
        $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : self::ips($host);
        if (!$ips) {
            return ['ok' => false, 'error' => 'نام این نشانی پیدا نشد (DNS).'];
        }
        foreach ($ips as $ip) {
            if (!self::isPublicIp($ip)) {
                return ['ok' => false, 'error' => 'نشانی به شبکه‌ی داخلی اشاره می‌کند و پذیرفته نمی‌شود.'];
            }
        }
        return ['ok' => true, 'resolve' => $host . ':' . $port . ':' . $ips[0], 'host' => $host];
    }
}
