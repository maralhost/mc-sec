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
        if (empty($opt['egress']) || !Egress::on()) {
            return self::send($method, $url, $headers, $body, $opt);
        }
        // a request to a customer's own site while a way out is set: through the locations in turn, never directly
        $last = null;
        foreach (Egress::route((int) ($opt['skip'] ?? 0)) as $loc) {
            $r = self::send($method, $url, $headers, $body, ['proxy' => $loc] + $opt);
            $r['via'] = $loc['name'];
            if ((int) $r['status'] > 0) {
                return $r;
            }
            $last = $r;
        }
        return $last ?? self::fail($url, 'no usable egress proxy; nothing was sent directly', microtime(true)) + ['via' => ''];
    }

    private static function send(string $method, string $url, array $headers = [], $body = null, array $opt = []): array
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
            CURLOPT_USERAGENT => (string) ($opt['ua'] ?? self::ua()),
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
        if (!empty($opt['proxy'])) {
            curl_setopt_array($ch, Egress::curl((array) $opt['proxy']));
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

    /**
     * One fixed User-Agent for every request MC-Sec sends, with the public "about this scanner" page, so a site owner
     * who sees it in a log can find out who scanned and how to allow or stop it (polite scanning).
     */
    public static function ua(): string
    {
        static $ua = null;
        if ($ua === null) {
            $base = '';
            try {
                $base = Whmcs::systemUrl();
            } catch (\Throwable $e) {
                $base = '';
            }
            $ua = 'MC-Sec/' . (defined('MCSEC_VERSION') ? MCSEC_VERSION : 'dev') . ' (+' . (preg_match('~^https?://~i', $base) ? rtrim($base, '/') . '/index.php?m=mcsec&p=scanner' : 'Maral Cloud security scanner') . ')';
        }
        return $ua;
    }

    /**
     * Several GETs at once (light monitoring): only the status and time matter, the body is read up to 16 KB.
     * No redirects, no certificate checks (an expired certificate is reported by the certificate check, not as "down").
     * @param array<int|string,array{url:string,resolve?:string}> $reqs
     * @return array<int|string,array{ok:bool,status:int,error:string,ms:int}>
     */
    public static function multi(array $reqs, int $timeout = 10, bool $egress = false): array
    {
        $out = [];
        $egress = $egress && Egress::on();
        $first = $egress ? (Egress::route()[0] ?? null) : null;
        if ($egress && $first === null) {
            foreach ($reqs as $k => $r) {
                $out[$k] = ['ok' => false, 'status' => 0, 'error' => 'no usable egress proxy; nothing was sent directly', 'ms' => 0];
            }
            return $out;
        }
        if (self::$mock !== null || !function_exists('curl_multi_init')) {
            foreach ($reqs as $k => $r) {
                if ($egress) {
                    $x = self::request('GET', $r['url'], ['Accept' => 'text/html,*/*;q=0.8'], null, ['timeout' => $timeout, 'connect' => min(5, $timeout), 'verify' => false, 'max_bytes' => 16384, 'resolve' => $r['resolve'] ?? '', 'egress' => true]);
                    $out[$k] = ['ok' => $x['status'] > 0, 'status' => (int) $x['status'], 'error' => (string) $x['error'], 'ms' => (int) $x['ms'], 'via' => (string) ($x['via'] ?? '')];
                    continue;
                }
                $x = self::request('GET', $r['url'], ['Accept' => 'text/html,*/*;q=0.8'], null, ['timeout' => $timeout, 'connect' => min(5, $timeout), 'verify' => false, 'max_bytes' => 16384] + $r);
                $out[$k] = ['ok' => $x['status'] > 0, 'status' => (int) $x['status'], 'error' => (string) $x['error'], 'ms' => (int) $x['ms']];
            }
            return $out;
        }
        $mh = curl_multi_init();
        $handles = [];
        foreach ($reqs as $k => $r) {
            $ch = curl_init();
            $got = 0;
            curl_setopt_array($ch, [
                CURLOPT_URL => $r['url'], CURLOPT_HTTPGET => true, CURLOPT_HTTPHEADER => ['Accept: text/html,*/*;q=0.8'], CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => min(5, $timeout), CURLOPT_TIMEOUT => $timeout, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_USERAGENT => self::ua(), CURLOPT_ENCODING => '',
                CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$got) {
                    $got += strlen($chunk);
                    return $got > 16384 ? 0 : strlen($chunk);
                },
            ]);
            if (!empty($r['resolve'])) {
                curl_setopt($ch, CURLOPT_RESOLVE, [(string) $r['resolve']]);
            }
            if ($first !== null) {
                curl_setopt_array($ch, Egress::curl($first));
            }
            curl_multi_add_handle($mh, $ch);
            $handles[$k] = [$ch, microtime(true)];
        }
        $running = 0;
        do {
            $st = curl_multi_exec($mh, $running);
            if ($running > 0) {
                curl_multi_select($mh, 1.0);
            }
        } while ($running > 0 && $st === CURLM_OK);
        // per-transfer result codes (curl_error() is empty for handles run by curl_multi)
        $codes = [];
        while (($info = curl_multi_info_read($mh)) !== false) {
            $codes[spl_object_id($info['handle'])] = (int) $info['result'];
        }
        foreach ($handles as $k => [$ch, $t0]) {
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $code = $codes[spl_object_id($ch)] ?? 0;
            $err = $status > 0 ? '' : ($code !== 0 ? curl_strerror($code) : (curl_error($ch) !== '' ? curl_error($ch) : 'no answer'));
            $out[$k] = ['ok' => $status > 0, 'status' => $status, 'error' => $err, 'ms' => (int) round((float) curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000)];
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);
        if ($first !== null && count(Egress::route()) > 1) {
            // what the first location could not reach is asked from the others, one by one: unreachable only when none reaches it
            foreach ($out as $k => $x) {
                if (!$x['ok']) {
                    $y = self::request('GET', $reqs[$k]['url'], ['Accept' => 'text/html,*/*;q=0.8'], null, ['timeout' => $timeout, 'connect' => min(5, $timeout), 'verify' => false, 'max_bytes' => 16384, 'resolve' => $reqs[$k]['resolve'] ?? '', 'egress' => true, 'skip' => 1]);
                    if ((int) $y['status'] > 0) {
                        $out[$k] = ['ok' => true, 'status' => (int) $y['status'], 'error' => '', 'ms' => (int) $y['ms'], 'via' => (string) ($y['via'] ?? '')];
                    }
                }
            }
        }
        return $out;
    }

    /**
     * The same small GETs from several egress locations at once (monitoring that wants to know from where a site
     * answers). Never direct: every transfer carries one location's proxy.
     * @param array<int|string,array{url:string,resolve?:string}> $reqs
     * @param array<int,array{name:string,host:string,port:int,user:string,pass:string}> $locs
     * @return array<int|string,array<string,array{ok:bool,status:int,error:string,ms:int}>> request key => location name => result
     */
    public static function multiVia(array $reqs, int $timeout, array $locs): array
    {
        $out = [];
        if (!$locs) {
            return $out;
        }
        if (self::$mock !== null || !function_exists('curl_multi_init')) {
            foreach ($reqs as $k => $r) {
                foreach ($locs as $loc) {
                    $x = self::send('GET', $r['url'], ['Accept' => 'text/html,*/*;q=0.8'], null, ['timeout' => $timeout, 'connect' => min(5, $timeout), 'verify' => false, 'max_bytes' => 16384, 'resolve' => $r['resolve'] ?? '', 'egress' => true, 'proxy' => $loc]);
                    $out[$k][$loc['name']] = ['ok' => $x['status'] > 0, 'status' => (int) $x['status'], 'error' => (string) $x['error'], 'ms' => (int) $x['ms']];
                }
            }
            return $out;
        }
        $mh = curl_multi_init();
        $handles = [];
        foreach ($reqs as $k => $r) {
            foreach ($locs as $loc) {
                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL => $r['url'], CURLOPT_HTTPGET => true, CURLOPT_HTTPHEADER => ['Accept: text/html,*/*;q=0.8'], CURLOPT_FOLLOWLOCATION => false, CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_CONNECTTIMEOUT => min(5, $timeout), CURLOPT_TIMEOUT => $timeout, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_RANGE => '0-16383',
                    CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS, CURLOPT_USERAGENT => self::ua(), CURLOPT_ENCODING => '',
                ] + Egress::curl($loc));
                if (!empty($r['resolve'])) {
                    curl_setopt($ch, CURLOPT_RESOLVE, [(string) $r['resolve']]);
                }
                curl_multi_add_handle($mh, $ch);
                $handles[] = [$ch, $k, $loc['name']];
            }
        }
        $running = 0;
        do {
            $st = curl_multi_exec($mh, $running);
            if ($running > 0) {
                curl_multi_select($mh, 1.0);
            }
        } while ($running > 0 && $st === CURLM_OK);
        $codes = [];
        while (($info = curl_multi_info_read($mh)) !== false) {
            $codes[spl_object_id($info['handle'])] = (int) $info['result'];
        }
        foreach ($handles as [$ch, $k, $name]) {
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $code = $codes[spl_object_id($ch)] ?? 0;
            $out[$k][$name] = ['ok' => $status > 0, 'status' => $status, 'error' => $status > 0 ? '' : ($code !== 0 ? curl_strerror($code) : 'no answer'), 'ms' => (int) round((float) curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000)];
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);
        return $out;
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
