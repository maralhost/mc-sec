<?php

declare(strict_types=1);

namespace McSec;

/**
 * The way out to customers' sites. When the admin sets «مسیر خروجی» (egress_proxies: one or more SOCKS5 proxies,
 * each a named location), every connection this module makes to a customer's own site or server (ownership proof by
 * file or meta, the origin-server test, the built-in check with its certificate and port probes, monitoring, the
 * customer's webhook) leaves through one of them, so the address of the WHMCS server never appears in a customer's
 * logs.
 *
 *  - Fail closed: while the setting is filled, nothing of the above is ever sent directly. A mistyped or dead proxy
 *    means the check fails; it does not fall back to the server's own address.
 *  - Several locations: they are tried in order. A location that cannot reach the target (the proxy is down, or the
 *    site is filtered in that country) is followed by the next one; a site counts as unreachable only when no
 *    location reaches it.
 *  - Names are resolved here and the proxy is given the address already checked (plain SOCKS5, never "socks5h"), so
 *    the SSRF guard and the pinning to a vetted IP stay exactly as they are without a proxy.
 * Calls to our own engines and vendors (OASM, the AI model, the messengers, the DNS panels) are not customers' sites
 * and do not go through it.
 */
final class Egress
{
    private const MAX = 5;

    /** Tests: fn(array $loc, string $ip, int $port): resource|false|'proxy_down' */
    public static $dial = null;

    private static ?array $parsed = null;

    public static function forget(): void
    {
        self::$parsed = null;
    }

    public static function on(): bool
    {
        return trim(Settings::secret('egress_proxies')) !== '';
    }

    /**
     * The locations as written by the admin: "name=socks5://user:pass@host:1080", separated by commas, spaces or
     * new lines. @return array{ok:array<int,array{name:string,host:string,port:int,user:string,pass:string}>,bad:int}
     */
    public static function parse(): array
    {
        $raw = trim(Settings::secret('egress_proxies'));
        if (self::$parsed !== null && self::$parsed['raw'] === $raw) {
            return self::$parsed;
        }
        $ok = [];
        $bad = 0;
        foreach (array_slice(array_values(array_filter(preg_split('~[\s,]+~', $raw) ?: [], 'strlen')), 0, self::MAX) as $i => $item) {
            $name = (string) ($i + 1);
            if (preg_match('~^([\p{L}\p{N}_-]{1,24})=(.+)$~u', $item, $m)) {
                [$name, $item] = [$m[1], $m[2]];
            }
            $u = parse_url($item);
            $host = is_array($u) ? trim((string) ($u['host'] ?? ''), '[]') : '';
            if (!is_array($u) || !in_array(strtolower((string) ($u['scheme'] ?? '')), ['socks5', 'socks5h'], true) || $host === '' || (int) ($u['port'] ?? 0) < 1) {
                $bad++;
                continue;
            }
            $ok[] = ['name' => $name, 'host' => $host, 'port' => (int) $u['port'], 'user' => rawurldecode((string) ($u['user'] ?? '')), 'pass' => rawurldecode((string) ($u['pass'] ?? ''))];
        }
        return self::$parsed = ['raw' => $raw, 'ok' => $ok, 'bad' => $bad];
    }

    /** Locations to try, those seen dead a moment ago last. Empty while the setting is filled but unusable (then nothing is sent). */
    public static function route(int $skip = 0): array
    {
        $locs = self::parse()['ok'];
        usort($locs, fn ($a, $b) => (int) (Kv::get(self::downKey($a)) === '1') <=> (int) (Kv::get(self::downKey($b)) === '1'));
        return array_slice($locs, max(0, $skip));
    }

    /** @return string[] */
    public static function names(): array
    {
        return array_map(fn ($l) => $l['name'], self::parse()['ok']);
    }

    private static function downKey(array $loc): string
    {
        return 'egress:down:' . substr(sha1($loc['host'] . ':' . $loc['port']), 0, 16);
    }

    /** curl options that send one request through one location. */
    public static function curl(array $loc): array
    {
        $o = [CURLOPT_PROXY => (str_contains($loc['host'], ':') ? '[' . $loc['host'] . ']' : $loc['host']) . ':' . $loc['port'], CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5];
        if ($loc['user'] !== '') {
            $o[CURLOPT_PROXYUSERPWD] = $loc['user'] . ':' . $loc['pass'];
        }
        return $o;
    }

    /**
     * A TCP connection to a target for the raw probes (certificate, ports): direct while no way out is set, otherwise
     * through the locations in turn. @return resource|null
     */
    public static function connect(string $ip, int $port, float $timeout, ?string &$via = null)
    {
        $via = '';
        if (!self::on()) {
            $target = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $ip . ']' : $ip;
            $s = @stream_socket_client('tcp://' . $target . ':' . $port, $en, $es, $timeout);
            return $s ?: null;
        }
        foreach (self::route() as $loc) {
            $s = self::$dial !== null ? (self::$dial)($loc, $ip, $port) : self::socks($loc, $ip, $port, $timeout);
            if ($s === 'proxy_down') {
                Kv::set(self::downKey($loc), '1', 60);
                continue;
            }
            if ($s) {
                $via = $loc['name'];
                return $s;
            }
        }
        return null;
    }

    /** One SOCKS5 CONNECT (RFC 1928, with user/password of RFC 1929 when given). @return resource|false|string */
    private static function socks(array $loc, string $ip, int $port, float $timeout)
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        $host = str_contains($loc['host'], ':') ? '[' . $loc['host'] . ']' : $loc['host'];
        $s = @stream_socket_client('tcp://' . $host . ':' . $loc['port'], $en, $es, min(5.0, $timeout));
        if (!$s) {
            return 'proxy_down';
        }
        stream_set_timeout($s, (int) max(1, ceil($timeout)));
        $read = function (int $n) use ($s): string {
            $buf = '';
            while (strlen($buf) < $n && !feof($s)) {
                $chunk = fread($s, $n - strlen($buf));
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $buf .= $chunk;
            }
            return $buf;
        };
        $auth = $loc['user'] !== '';
        fwrite($s, $auth ? "\x05\x02\x00\x02" : "\x05\x01\x00");
        $r = $read(2);
        if (strlen($r) !== 2 || $r[0] !== "\x05" || $r[1] === "\xFF") {
            fclose($s);
            return 'proxy_down';
        }
        if ($r[1] === "\x02") {
            fwrite($s, "\x01" . chr(min(255, strlen($loc['user']))) . substr($loc['user'], 0, 255) . chr(min(255, strlen($loc['pass']))) . substr($loc['pass'], 0, 255));
            $a = $read(2);
            if (strlen($a) !== 2 || $a[1] !== "\x00") {
                fclose($s);
                return 'proxy_down';
            }
        }
        fwrite($s, "\x05\x01\x00" . (strlen($bin) === 4 ? "\x01" : "\x04") . $bin . pack('n', $port));
        $h = $read(4);
        if (strlen($h) !== 4 || $h[1] !== "\x00") {
            fclose($s);
            return false; // the proxy answered: this target is not reachable from there
        }
        $read(($h[3] === "\x01" ? 4 : ($h[3] === "\x04" ? 16 : ord($read(1)))) + 2);
        return $s;
    }

    /** Is at least one location's proxy answering? (cached for half a minute) */
    public static function alive(): bool
    {
        if (!self::on()) {
            return true;
        }
        if (self::$dial !== null) {
            return self::route() !== [];
        }
        $k = 'egress:alive';
        $c = Kv::get($k);
        if ($c !== null) {
            return $c === '1';
        }
        $ok = false;
        foreach (self::route() as $loc) {
            $s = @stream_socket_client('tcp://' . (str_contains($loc['host'], ':') ? '[' . $loc['host'] . ']' : $loc['host']) . ':' . $loc['port'], $en, $es, 4);
            if ($s) {
                fclose($s);
                $ok = true;
                break;
            }
            Kv::set(self::downKey($loc), '1', 60);
        }
        Kv::set($k, $ok ? '1' : '0', 30);
        return $ok;
    }

    /**
     * The admin's «آزمودن مسیر خروجی»: through each location, one TLS-port connection to this WHMCS's own address
     * (never to a customer). @return array<int,array{name:string,ok:bool}> and the number of unreadable entries in 'bad'
     */
    public static function test(): array
    {
        $host = (string) parse_url(Whmcs::systemUrl(), PHP_URL_HOST);
        $ip = $host !== '' ? (filter_var($host, FILTER_VALIDATE_IP) ? $host : (Net::ips($host)[0] ?? '')) : '';
        $out = ['rows' => [], 'bad' => self::parse()['bad'], 'target' => $host];
        foreach (self::parse()['ok'] as $loc) {
            $s = $ip === '' ? false : (self::$dial !== null ? (self::$dial)($loc, $ip, 443) : self::socks($loc, $ip, 443, 6.0));
            $out['rows'][] = ['name' => $loc['name'], 'ok' => is_resource($s), 'proxy' => $s !== 'proxy_down'];
            if (is_resource($s)) {
                fclose($s);
            }
        }
        return $out;
    }
}
