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

    /** Whether an IP (v4 or v6) falls inside a CIDR, a range "a-b" or equals an IP. */
    public static function inCidr(string $ip, string $cidr): bool
    {
        $a = self::ipRange($ip);
        $b = self::ipRange($cidr);
        return $a !== null && $b !== null && self::overlaps($a, $b);
    }

    /**
     * An IP, a CIDR (IPv4 or IPv6) or a range "a-b" → [first, last] as packed addresses of one family; null if it is
     * none of these. Packed addresses of the same family compare correctly with strcmp.
     * @return array{0:string,1:string}|null
     */
    public static function ipRange(string $rule): ?array
    {
        $rule = trim($rule);
        if (str_contains($rule, '-')) {
            [$x, $y] = array_map('trim', explode('-', $rule, 2));
            $a = filter_var($x, FILTER_VALIDATE_IP) ? inet_pton($x) : false;
            $b = filter_var($y, FILTER_VALIDATE_IP) ? inet_pton($y) : false;
            if ($a === false || $b === false || strlen($a) !== strlen($b)) {
                return null;
            }
            return strcmp($a, $b) <= 0 ? [$a, $b] : [$b, $a];
        }
        $bits = null;
        if (str_contains($rule, '/')) {
            [$rule, $b] = explode('/', $rule, 2);
            if (!ctype_digit($b)) {
                return null;
            }
            $bits = (int) $b;
        }
        if (!filter_var($rule, FILTER_VALIDATE_IP)) {
            return null;
        }
        $p = (string) inet_pton($rule);
        $len = strlen($p) * 8;
        $bits = $bits ?? $len;
        if ($bits > $len) {
            return null;
        }
        $first = '';
        $last = '';
        for ($i = 0; $i < strlen($p); $i++) {
            $keep = max(0, min(8, $bits - $i * 8));
            $mask = $keep === 0 ? 0 : (0xFF << (8 - $keep)) & 0xFF;
            $first .= chr(ord($p[$i]) & $mask);
            $last .= chr((ord($p[$i]) & $mask) | (~$mask & 0xFF));
        }
        return [$first, $last];
    }

    /** @param array{0:string,1:string} $a @param array{0:string,1:string} $b */
    private static function overlaps(array $a, array $b): bool
    {
        return strlen($a[0]) === strlen($b[0]) && strcmp($a[0], $b[1]) <= 0 && strcmp($b[0], $a[1]) <= 0;
    }

    /** The meaningful lines of a list setting: Persian digits made Latin, "# note" cut off, lower case. @return string[] */
    public static function lines(string $list): array
    {
        $out = [];
        foreach (preg_split('~\r\n|\r|\n~', $list) ?: [] as $line) {
            $p = strtolower(trim(preg_replace('~\s#.*$~', '', Text::toAscii($line)) ?? ''));
            if ($p !== '' && !str_starts_with($p, '#')) {
                $out[] = $p;
            }
        }
        return $out;
    }

    /**
     * The blocklist rule that forbids this target ('' = allowed). Rules, one per line ("# note" allowed):
     *   example.com, *.gov.ir          the domain and all its subdomains
     *   *bank*, shop*.example.com      a pattern, * = any letters (here: every domain that contains "bank")
     *   5.6.7.8, 5.6.7.0/24, 5.6.7.10-5.6.7.50, 2001:db8::/32   an IP, a CIDR or a range (IPv4 or IPv6)
     * A domain is also forbidden when one of its IPs ($resolved) falls in an IP rule (someone pointing a domain at a
     * forbidden address), and an asset range when it overlaps one.
     * @param string[]|null $resolved the domain's current IPs (null = not looked up)
     */
    public static function blocked(string $kind, string $value, ?string $list = null, ?array $resolved = null): string
    {
        $value = strtolower($value);
        $mine = $kind === 'domain' ? null : self::ipRange($value);
        foreach (self::lines($list ?? Settings::get('blocklist')) as $p) {
            $range = self::ipRange($p);
            if ($range !== null) {
                if ($mine !== null && self::overlaps($mine, $range)) {
                    return $p;
                }
                foreach ($kind === 'domain' ? (array) $resolved : [] as $ip) {
                    $r = self::ipRange((string) $ip);
                    if ($r !== null && self::overlaps($r, $range)) {
                        return $p . ' (' . $ip . ')';
                    }
                }
                continue;
            }
            if ($kind !== 'domain' || preg_match('~[^a-z0-9.*_-]~', $p)) {
                continue;
            }
            $d = str_starts_with($p, '*.') ? substr($p, 2) : $p;
            if (!str_contains($d, '*')) {
                if ($d !== '' && self::within($value, $d)) {
                    return $p;
                }
            } elseif (preg_match('~^' . str_replace('\*', '[a-z0-9._-]*', preg_quote($p, '~')) . '$~', $value)) {
                return $p;
            }
        }
        return '';
    }

    /** Display names of the CDN keys used in cdn_list (an unknown key is shown as written). */
    private const CDN_LABELS = ['cloudflare' => 'Cloudflare', 'arvancloud' => 'ابر آروان', 'mizbancloud' => 'میزبان‌کلاد', 'cloudfront' => 'Amazon CloudFront',
        'akamai' => 'Akamai', 'fastly' => 'Fastly', 'azure-cdn' => 'Azure CDN', 'cdn' => 'CDN'];

    public static function cdnLabel(string $key): string
    {
        return self::CDN_LABELS[strtolower($key)] ?? $key;
    }

    /** @var array{0:string,1:array}|null parsed cdn_list, cached per request by its text */
    private static ?array $cdnCache = null;

    /** @return array<int,array{name:string,range?:array{0:string,1:string},suffix?:string}> */
    private static function cdnRules(): array
    {
        $text = Settings::get('cdn_list');
        if (self::$cdnCache !== null && self::$cdnCache[0] === $text) {
            return self::$cdnCache[1];
        }
        $rules = [];
        foreach (self::lines($text) as $line) {
            $parts = preg_split('~\s+~', $line) ?: [];
            [$name, $target] = count($parts) >= 2 ? [$parts[0], $parts[1]] : ['cdn', $parts[0]];
            $range = self::ipRange($target);
            if ($range !== null) {
                $rules[] = ['name' => $name, 'range' => $range];
            } elseif (preg_match('~^\.?[a-z0-9-]+(\.[a-z0-9-]+)+$~', $target)) {
                $rules[] = ['name' => $name, 'suffix' => ltrim($target, '.')];
            }
        }
        self::$cdnCache = [$text, $rules];
        return $rules;
    }

    /**
     * The CDN in front of a target ('' = none): an IP or range inside a listed CDN range, a domain whose address is
     * one, or whose CNAME chain reaches a listed CDN name (CloudFront, Akamai…). CDN edges are never port-scanned.
     * @param string[]|null $ips the domain's IPs if already looked up
     */
    public static function cdnOf(string $kind, string $value, ?array $ips = null): string
    {
        $rules = self::cdnRules();
        if (!$rules) {
            return '';
        }
        foreach ($kind === 'domain' ? ($ips ?? self::ips($value)) : [$value] as $ip) {
            $r = self::ipRange((string) $ip);
            foreach ($r === null ? [] : $rules as $rule) {
                if (isset($rule['range']) && self::overlaps($r, $rule['range'])) {
                    return $rule['name'];
                }
            }
        }
        if ($kind !== 'domain') {
            return '';
        }
        $name = strtolower($value);
        for ($hop = 0; $hop < 4; $hop++) {
            $target = strtolower(rtrim((string) (self::dns($name, 'CNAME')[0]['target'] ?? ''), '.'));
            if ($target === '' || $target === $name) {
                break;
            }
            foreach ($rules as $rule) {
                if (isset($rule['suffix']) && self::within($target, $rule['suffix'])) {
                    return $rule['name'];
                }
            }
            $name = $target;
        }
        return '';
    }

    /**
     * What the scope rules need to know about a target, with one DNS lookup: its IPs, the blocklist rule it hits and
     * the CDN in front of it. Network: only from the worker or an explicit POST.
     * @return array{ips:string[],blocked:string,cdn:string}
     */
    public static function screen(string $kind, string $value): array
    {
        $ips = $kind === 'domain' ? self::ips($value) : [];
        return ['ips' => $ips, 'blocked' => self::blocked($kind, $value, null, $ips), 'cdn' => self::cdnOf($kind, $value, $kind === 'domain' ? $ips : null)];
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
