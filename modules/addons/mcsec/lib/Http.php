<?php

declare(strict_types=1);

namespace McSec;

/**
 * Outgoing HTTP (curl): backends, AI, bots, customer webhooks and the built-in checks. Short timeouts, a body size
 * cap, no redirects unless asked, and for customer-supplied URLs an SSRF guard (Net::publicUrl) that pins the
 * resolved public IP. Tests replace the transport with Http::$mock.
 * Never called from a page-load hook (skill whmcs-addon §2): only from the worker, an explicit POST, or the
 * JSON progress poll behind a circuit breaker.
 */
final class Http
{
    /** Tests: fn(string $method, string $url, array $headers, ?string $body, array $opt): array|null (null = no match) */
    public static $mock = null;

    /**
     * @param array<string,string> $headers
     * @param array|string|null $body array = JSON
     * @param array{timeout?:int,connect?:int,verify?:bool,max_bytes?:int,follow?:bool,resolve?:string,cookie?:string,ua?:string} $opt
     * @return array{ok:bool,status:int,body:string,json:?array,headers:array<string,string[]>,error:string,ms:int,url:string}
     */
    public static function request(string $method, string $url, array $headers = [], $body = null, array $opt = []): array
    {
        $start = microtime(true);
        if (is_array($body)) {
            $body = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $headers += ['Content-Type' => 'application/json'];
        }
        $headers += ['Accept' => 'application/json'];
        if (self::$mock !== null) {
            $r = (self::$mock)($method, $url, $headers, $body, $opt);
            if (is_array($r)) {
                $r += ['status' => 200, 'body' => '', 'headers' => [], 'error' => ''];
                $r['ok'] = $r['error'] === '' && $r['status'] >= 200 && $r['status'] < 300;
                $r['json'] = self::decode((string) $r['body']);
                $r['ms'] = 1;
                $r['url'] = $url;
                return $r;
            }
        }
        if (!function_exists('curl_init')) {
            return self::fail($url, 'curl extension is missing', $start);
        }
        $ch = curl_init();
        $respHeaders = [];
        $buf = '';
        $max = (int) ($opt['max_bytes'] ?? 8 * 1024 * 1024);
        $h = [];
        foreach ($headers as $k => $v) {
            $h[] = $k . ': ' . $v;
        }
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $h,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => (bool) ($opt['follow'] ?? false),
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_CONNECTTIMEOUT => (int) ($opt['connect'] ?? 5),
            CURLOPT_TIMEOUT => (int) ($opt['timeout'] ?? 15),
            CURLOPT_SSL_VERIFYPEER => (bool) ($opt['verify'] ?? true),
            CURLOPT_SSL_VERIFYHOST => ($opt['verify'] ?? true) ? 2 : 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_USERAGENT => (string) ($opt['ua'] ?? 'MC-Sec/' . (defined('MCSEC_VERSION') ? MCSEC_VERSION : 'dev') . ' (+Maral Cloud security scanner)'),
            CURLOPT_ENCODING => '',
            CURLOPT_HEADERFUNCTION => function ($ch, string $line) use (&$respHeaders) {
                $p = strpos($line, ':');
                if ($p !== false) {
                    $respHeaders[strtolower(trim(substr($line, 0, $p)))][] = trim(substr($line, $p + 1));
                } elseif (preg_match('~^HTTP/~', $line)) {
                    $respHeaders = []; // a redirect starts a new header block
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$buf, $max) {
                if (strlen($buf) + strlen($chunk) > $max) {
                    $buf .= substr($chunk, 0, max(0, $max - strlen($buf)));
                    return 0; // stop: body cap reached
                }
                $buf .= $chunk;
                return strlen($chunk);
            },
        ]);
        if (!empty($opt['resolve'])) {
            curl_setopt($ch, CURLOPT_RESOLVE, [(string) $opt['resolve']]);
        }
        if (!empty($opt['cookie'])) {
            curl_setopt($ch, CURLOPT_COOKIE, (string) $opt['cookie']);
        }
        if ($body !== null && $body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = $ok === false ? curl_error($ch) : '';
        $final = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);
        if ($err !== '' && $status > 0 && strlen($buf) >= $max) {
            $err = ''; // we stopped reading on purpose
        }
        return [
            'ok' => $err === '' && $status >= 200 && $status < 300,
            'status' => $status,
            'body' => $buf,
            'json' => self::decode($buf),
            'headers' => $respHeaders,
            'error' => $err,
            'ms' => (int) round((microtime(true) - $start) * 1000),
            'url' => $final !== '' ? $final : $url,
        ];
    }

    /** Cookies set by a response, as "name=value; name2=value2" (engine sessions). */
    public static function cookies(array $resp): string
    {
        $out = [];
        foreach ($resp['headers']['set-cookie'] ?? [] as $line) {
            $pair = trim(explode(';', $line, 2)[0]);
            if (str_contains($pair, '=')) {
                [$n, $v] = explode('=', $pair, 2);
                $out[trim($n)] = trim($n) . '=' . trim($v);
            }
        }
        return implode('; ', $out);
    }

    private static function decode(string $body): ?array
    {
        if ($body === '' || ($body[0] !== '{' && $body[0] !== '[')) {
            $t = ltrim($body);
            if ($t === '' || ($t[0] !== '{' && $t[0] !== '[')) {
                return null;
            }
            $body = $t;
        }
        $j = json_decode($body, true);
        return is_array($j) ? $j : null;
    }

    private static function fail(string $url, string $err, float $start): array
    {
        return ['ok' => false, 'status' => 0, 'body' => '', 'json' => null, 'headers' => [], 'error' => $err, 'ms' => (int) round((microtime(true) - $start) * 1000), 'url' => $url];
    }

    /**
     * Circuit breaker per name: after $fails failures inside $window seconds the circuit opens for $cool seconds;
     * callers skip the call (and the page stays fast) while it is open.
     */
    public static function circuitOpen(string $name): bool
    {
        $s = Kv::json('cb:' . $name);
        return (int) ($s['open_until'] ?? 0) > Clock::now();
    }

    public static function circuitRecord(string $name, bool $success, int $fails = 4, int $window = 300, int $cool = 180): void
    {
        $s = Kv::json('cb:' . $name);
        if ($success) {
            if ($s) {
                Kv::setJson('cb:' . $name, ['n' => 0, 'since' => 0, 'open_until' => 0], 3600);
            }
            return;
        }
        $now = Clock::now();
        if ((int) ($s['since'] ?? 0) < $now - $window) {
            $s = ['n' => 0, 'since' => $now, 'open_until' => 0];
        }
        $s['n'] = (int) ($s['n'] ?? 0) + 1;
        if ($s['n'] >= $fails) {
            $s['open_until'] = $now + $cool;
            $s['n'] = 0;
            $s['since'] = $now;
        }
        Kv::setJson('cb:' . $name, $s, 3600);
    }
}
