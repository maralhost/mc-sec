<?php

declare(strict_types=1);

namespace McSec\Engines;

use McSec\Db;
use McSec\Http;
use McSec\Net;
use McSec\Settings;

/**
 * Built-in hygiene checks, run by the worker itself (no backend): DNS, TLS certificate and protocol, HTTPS redirect,
 * security headers, cookie flags, information leaks in headers, a few well-known exposed files, e-mail spoofing
 * protection (SPF, DMARC), CAA, and high-risk ports reachable from the internet. Gentle: a handful of requests
 * per asset, short timeouts, never an exploit. Every finding carries a kb key with the Persian fix (Kb).
 */
final class Builtin implements Engine
{
    /** Tests: fn(string $ip, int[] $ports): int[] open ports */
    public static $portProbe = null;
    /** Tests: fn(string $host): ?array cert info ['days'=>int,'issuer'=>string,'cn'=>string,'san'=>[],'valid_host'=>bool,'proto'=>string] */
    public static $certProbe = null;

    private const PORT_RISK = [
        21 => ['medium', 'FTP'], 23 => ['high', 'Telnet'], 25 => ['info', 'SMTP'], 110 => ['low', 'POP3'], 143 => ['low', 'IMAP'], 445 => ['high', 'SMB'],
        1433 => ['high', 'MS SQL Server'], 2375 => ['critical', 'Docker API'], 3306 => ['high', 'MySQL'], 3389 => ['high', 'RDP'], 5432 => ['high', 'PostgreSQL'],
        5900 => ['high', 'VNC'], 6379 => ['high', 'Redis'], 9200 => ['high', 'Elasticsearch'], 11211 => ['medium', 'Memcached'], 27017 => ['high', 'MongoDB'], 22 => ['info', 'SSH'],
    ];

    public function key(): string
    {
        return 'builtin';
    }

    public function configured(): bool
    {
        return true;
    }

    public function start(object $scan, object $asset, array $profile): array
    {
        $res = $this->run((string) $asset->kind, (string) $asset->value, self::portScopeFor($asset));
        return ['ok' => true, 'ref' => 'builtin-' . $scan->id, 'meta' => ['result' => $res], 'progress' => 100, 'stage' => 'تمام شد'];
    }

    public function poll(object $scan, object $asset, array $profile): array
    {
        return ['status' => 'completed', 'progress' => 100, 'stage' => 'تمام شد'];
    }

    public function collect(object $scan, object $asset, array $profile): array
    {
        $meta = json_decode((string) $scan->backend_meta, true);
        $res = is_array($meta['result'] ?? null) ? $meta['result'] : ['findings' => [], 'surface' => []];
        return ['findings' => $res['findings'], 'surface' => $res['surface'], 'kinds' => [], 'complete' => true];
    }

    public function cancel(object $scan, object $asset): bool
    {
        return true;
    }

    public function health(): array
    {
        return ['ok' => function_exists('curl_init') && function_exists('stream_socket_client'), 'message' => 'بررسی‌های داخلی روی همین سرور WHMCS اجرا می‌شوند.'];
    }

    /**
     * IPs whose ports this account may probe: its verified IP assets and the IPs of its own Maral services. A domain on
     * shared hosting or behind a CDN resolves to an IP shared with others: its ports are never probed.
     * @return string[]|null null = no limit (an IP asset: the verified IP itself)
     */
    public static function portScopeFor(object $asset): ?array
    {
        if ($asset->kind !== 'domain') {
            return null;
        }
        $ips = \McSec\Whmcs::ownedIps((int) $asset->client_id);
        foreach (Db::rows(Db::table('mod_mcsec_assets')->where('client_id', $asset->client_id)->where('kind', 'ip')->where('status', 'verified')->select(['value'])) as $r) {
            $ips[] = strtolower((string) $r->value);
        }
        return array_values(array_unique($ips));
    }

    /** @param string[]|null $portScope see portScopeFor() @return array{findings:array,surface:array} */
    public function run(string $kind, string $value, ?array $portScope = null): array
    {
        $f = [];
        $s = [];
        $host = $value;
        $ips = $kind === 'ip' ? [$value] : Net::ips($value);
        if ($kind === 'domain') {
            if (!$ips) {
                $f[] = $this->finding('dns.no_address', 'دامنه به هیچ IPی اشاره نمی‌کند', 'info', $host, 'رکورد A یا AAAA برای این نام پیدا نشد؛ بقیه‌ی بررسی‌های وب انجام نشد.', '', 'dns-no-address');
                return ['findings' => array_merge($f, $this->email($value)), 'surface' => $s];
            }
            foreach ($ips as $ip) {
                $s[] = ['kind' => 'host', 'value' => $ip, 'meta' => ['from' => $host]];
            }
        }
        $publicIps = array_values(array_filter($ips, fn ($ip) => Net::isPublicIp($ip) || Settings::bool('allow_private_ips')));

        // web: HTTPS, certificate, redirect, headers, cookies, leaks, exposed files
        $https = $this->get('https://' . $this->urlHost($host) . '/', $publicIps[0] ?? '', $host, true);
        $http = $this->get('http://' . $this->urlHost($host) . '/', $publicIps[0] ?? '', $host, false);
        if ($https !== null || $http !== null) {
            $cert = $this->cert($host, $publicIps[0] ?? $host);
            if ($cert !== null) {
                $s[] = ['kind' => 'cert', 'value' => $host . ':443', 'meta' => $cert];
                if ($cert['days'] < 0) {
                    $f[] = $this->finding('tls.expired', 'گواهی SSL منقضی شده است', 'high', $host . ':443', 'گواهی از ' . abs($cert['days']) . ' روز پیش منقضی شده و مرورگرها هشدار امنیتی نشان می‌دهند.', 'expires in ' . $cert['days'] . ' days; issuer: ' . $cert['issuer'], 'tls-expired');
                } elseif ($cert['days'] < 14) {
                    $f[] = $this->finding('tls.expiring', 'گواهی SSL به‌زودی منقضی می‌شود', 'medium', $host . ':443', 'فقط ' . $cert['days'] . ' روز تا انقضای گواهی مانده است.', 'expires in ' . $cert['days'] . ' days', 'tls-expiring');
                } elseif ($cert['days'] < 30) {
                    $f[] = $this->finding('tls.expiring', 'گواهی SSL کمتر از یک ماه اعتبار دارد', 'low', $host . ':443', $cert['days'] . ' روز تا انقضای گواهی مانده است. اگر تمدید خودکار ندارید، برنامه‌ریزی کنید.', 'expires in ' . $cert['days'] . ' days', 'tls-expiring');
                }
                if ($kind === 'domain' && !$cert['valid_host']) {
                    $f[] = $this->finding('tls.hostname', 'گواهی SSL برای این نام صادر نشده است', 'high', $host . ':443', 'نام‌های گواهی (' . implode(', ', array_slice($cert['san'], 0, 5)) . ') با این دامنه یکی نیست.', 'CN=' . $cert['cn'], 'tls-hostname');
                }
                if ($cert['self_signed'] ?? false) {
                    $f[] = $this->finding('tls.self_signed', 'گواهی SSL خودامضا است', 'medium', $host . ':443', 'مرورگرها به گواهی خودامضا اعتماد نمی‌کنند.', 'issuer=' . $cert['issuer'], 'tls-self-signed');
                }
                if (in_array($cert['proto'] ?? '', ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3'], true)) {
                    $f[] = $this->finding('tls.old_protocol', 'نسخه‌ی قدیمی TLS پذیرفته می‌شود', 'medium', $host . ':443', 'سرور با ' . $cert['proto'] . ' وصل می‌شود که دیگر امن شمرده نمی‌شود.', 'negotiated ' . $cert['proto'], 'tls-old-protocol');
                }
            } elseif ($https === null && $http !== null) {
                $f[] = $this->finding('web.no_https', 'سایت HTTPS ندارد', 'high', 'http://' . $host, 'سایت فقط با HTTP بی‌رمز باز می‌شود؛ رمز ورود و اطلاعات کاربران در مسیر خوانده می‌شود.', '', 'web-no-https');
            }
            if ($http !== null && $https !== null && !$this->redirectsToHttps($http)) {
                $f[] = $this->finding('web.no_redirect', 'نسخه‌ی HTTP به HTTPS هدایت نمی‌شود', 'low', 'http://' . $host, 'بازدیدکننده‌ای که http:// را باز کند، روی اتصال بی‌رمز می‌ماند.', 'HTTP ' . $http['status'], 'web-no-redirect');
            }
            $main = $https ?? $http;
            $f = array_merge($f, $this->headers($main, $host, $https !== null));
            foreach (['server', 'x-powered-by'] as $h) {
                foreach ($main['headers'][$h] ?? [] as $v) {
                    $s[] = ['kind' => 'tech', 'value' => mb_substr($v, 0, 120), 'meta' => ['header' => $h, 'host' => $host]];
                }
            }
            $f = array_merge($f, $this->exposedFiles(($https !== null ? 'https://' : 'http://') . $this->urlHost($host), $publicIps[0] ?? '', $host, $https !== null));
        }

        // ports (first public address only: a gentle check, not a port scan), and only on an address this account owns
        if ($publicIps && $portScope !== null && !in_array(strtolower($publicIps[0]), $portScope, true)) {
            $publicIps = [];
        }
        if ($publicIps) {
            $ports = array_map('intval', Settings::csv('builtin_ports'));
            $open = $this->ports($publicIps[0], $ports);
            foreach ($open as $p) {
                $s[] = ['kind' => 'port', 'value' => $publicIps[0] . ':' . $p, 'meta' => ['service' => self::PORT_RISK[$p][1] ?? '']];
                [$sev, $name] = self::PORT_RISK[$p] ?? ['low', 'port ' . $p];
                if ($sev !== 'info') {
                    $f[] = $this->finding('port.' . $p, 'درگاه ' . $name . ' روی اینترنت باز است', $sev, $publicIps[0] . ':' . $p,
                        'سرویس ' . $name . ' (درگاه ' . $p . ') از همه‌جای اینترنت در دسترس است و هدف حمله‌ی حدس رمز یا آسیب‌پذیری‌های شناخته‌شده قرار می‌گیرد.', 'tcp/' . $p . ' open', 'port-exposed');
                }
            }
        }
        if ($kind === 'domain' && Net::apex($value) === $value) {
            $f = array_merge($f, $this->email($value));
            if (!Net::dns($value, 'CAA')) {
                $f[] = $this->finding('dns.no_caa', 'رکورد CAA تعریف نشده است', 'info', $value, 'بدون CAA هر مرجع صدور گواهی می‌تواند برای این دامنه گواهی صادر کند.', '', 'dns-caa');
            }
        }
        return ['findings' => $f, 'surface' => $s];
    }

    private function finding(string $key, string $title, string $sev, string $loc, string $desc, string $evidence, string $kb): array
    {
        return ['key' => 'builtin.' . $key, 'title' => $title, 'severity' => $sev, 'location' => $loc, 'description' => $desc, 'evidence' => $evidence, 'kb' => $kb, 'tags' => ['hygiene']];
    }

    private function urlHost(string $host): string
    {
        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $host . ']' : $host;
    }

    /** One GET pinned to the checked public IP; null when nothing answers. */
    private function get(string $url, string $ip, string $host, bool $tls): ?array
    {
        $port = $tls ? 443 : 80;
        $opt = ['timeout' => 10, 'connect' => 5, 'verify' => false, 'max_bytes' => 300000, 'follow' => false];
        if ($ip !== '' && !filter_var($host, FILTER_VALIDATE_IP)) {
            $opt['resolve'] = $host . ':' . $port . ':' . $ip;
        }
        $r = Http::request('GET', $url, ['Accept' => 'text/html,*/*;q=0.8'], null, $opt);
        return $r['status'] > 0 ? $r : null;
    }

    private function redirectsToHttps(array $r): bool
    {
        $loc = (string) ($r['headers']['location'][0] ?? '');
        return $r['status'] >= 300 && $r['status'] < 400 && str_starts_with(strtolower($loc), 'https://');
    }

    private function headers(array $r, string $host, bool $tls): array
    {
        $h = $r['headers'];
        $loc = ($tls ? 'https://' : 'http://') . $host . '/';
        $f = [];
        if ($r['status'] >= 300 && $r['status'] < 400) {
            return $f; // a redirect page: headers belong to the final page, judged on the next scan of that host
        }
        if ($tls && empty($h['strict-transport-security'])) {
            $f[] = $this->finding('hdr.hsts', 'هدر HSTS تنظیم نشده است', 'low', $loc, 'بدون HSTS مرورگر ممکن است اولین اتصال را بی‌رمز برقرار کند (حمله‌ی SSL stripping).', '', 'hdr-hsts');
        }
        $csp = strtolower(implode(';', $h['content-security-policy'] ?? []));
        if ($csp === '') {
            $f[] = $this->finding('hdr.csp', 'سیاست امنیت محتوا (CSP) تنظیم نشده است', 'low', $loc, 'CSP اثر حمله‌های XSS و تزریق اسکریپت را محدود می‌کند.', '', 'hdr-csp');
        }
        if (empty($h['x-frame-options']) && !str_contains($csp, 'frame-ancestors')) {
            $f[] = $this->finding('hdr.frame', 'محافظت در برابر Clickjacking نیست', 'low', $loc, 'سایت را می‌توان در iframe سایت دیگری نشاند و کاربر را به کلیک ناخواسته کشاند.', '', 'hdr-frame');
        }
        if (strtolower((string) ($h['x-content-type-options'][0] ?? '')) !== 'nosniff') {
            $f[] = $this->finding('hdr.nosniff', 'هدر X-Content-Type-Options تنظیم نشده است', 'info', $loc, 'مرورگر ممکن است نوع فایل را حدس بزند و فایل بارگذاری‌شده را اجرا کند.', '', 'hdr-nosniff');
        }
        foreach (['server' => 'web server', 'x-powered-by' => 'framework'] as $name => $what) {
            $v = (string) ($h[$name][0] ?? '');
            if ($v !== '' && preg_match('~\d+\.\d+~', $v)) {
                $f[] = $this->finding('hdr.version.' . $name, 'نسخه‌ی نرم‌افزار در هدر ' . $name . ' دیده می‌شود', 'low', $loc, 'نسخه‌ی دقیق به مهاجم کمک می‌کند آسیب‌پذیری‌های همان نسخه را پیدا کند.', $name . ': ' . mb_substr($v, 0, 120), 'hdr-version');
            }
        }
        foreach ($h['set-cookie'] ?? [] as $c) {
            $lc = strtolower($c);
            $name = trim(explode('=', $c, 2)[0]);
            if (preg_match('~sess|auth|token|login|sid~i', $name) && ((!str_contains($lc, 'secure') && $tls) || !str_contains($lc, 'httponly'))) {
                $f[] = $this->finding('cookie.flags.' . strtolower($name), 'کوکی نشست بدون Secure یا HttpOnly', 'medium', $loc, 'کوکی «' . $name . '» بدون پرچم‌های Secure و HttpOnly فرستاده می‌شود و در خطر سرقت است.', mb_substr($c, 0, 160), 'cookie-flags');
            }
        }
        if (preg_match('~<title>\s*Index of /~i', (string) $r['body'])) {
            $f[] = $this->finding('web.listing', 'فهرست فایل‌های پوشه نمایش داده می‌شود', 'medium', $loc, 'Directory listing روشن است و فایل‌های پوشه را به همه نشان می‌دهد.', 'Index of /', 'web-listing');
        }
        return $f;
    }

    private function exposedFiles(string $base, string $ip, string $host, bool $tls): array
    {
        $f = [];
        $checks = [
            ['/.git/HEAD', '~^ref:\s*refs/~m', 'web.git', 'پوشه‌ی .git روی سایت در دسترس است', 'high', 'کل کد منبع، تاریخچه و گاهی رمزها از روی پوشه‌ی .git قابل بازسازی است.', 'web-git'],
            ['/.env', '~^(APP_KEY|DB_PASSWORD|DB_HOST|SECRET_KEY|AWS_SECRET|MAIL_PASSWORD)\s*=~m', 'web.env', 'فایل .env روی سایت در دسترس است', 'critical', 'این فایل معمولاً رمز پایگاه داده و کلیدهای سرویس‌ها را دارد.', 'web-env'],
            ['/server-status', '~Apache Server Status~i', 'web.server_status', 'صفحه‌ی server-status آپاچی عمومی است', 'medium', 'این صفحه درخواست‌های جاری، IP بازدیدکننده‌ها و مسیرهای داخلی را نشان می‌دهد.', 'web-server-status'],
        ];
        foreach ($checks as [$path, $re, $key, $title, $sev, $desc, $kb]) {
            $r = $this->get($base . $path, $ip, $host, $tls);
            if ($r !== null && $r['status'] === 200 && preg_match($re, substr((string) $r['body'], 0, 20000))) {
                $f[] = $this->finding($key, $title, $sev, $base . $path, $desc, 'HTTP 200 ' . $path, $kb);
            }
        }
        return $f;
    }

    private function email(string $domain): array
    {
        $f = [];
        $spf = array_values(array_filter(Net::txt($domain), fn ($t) => stripos(trim($t, '"'), 'v=spf1') === 0));
        if (!$spf) {
            $f[] = $this->finding('mail.spf_missing', 'رکورد SPF تعریف نشده است', 'medium', $domain, 'هر کسی می‌تواند ایمیلی به نام این دامنه بفرستد و گیرنده نمی‌تواند جعلی بودنش را بفهمد.', '', 'mail-spf');
        } elseif (preg_match('/[+?]all\b/i', $spf[0]) || !preg_match('/[-~]all\b|redirect=/i', $spf[0])) {
            $f[] = $this->finding('mail.spf_weak', 'رکورد SPF جلوی جعل را نمی‌گیرد', 'medium', $domain, 'SPF با ‎+all یا ‎?all یا بی پایان all، فرستنده‌های دیگر را رد نمی‌کند.', mb_substr($spf[0], 0, 200), 'mail-spf');
        }
        $dmarc = array_values(array_filter(Net::txt('_dmarc.' . $domain), fn ($t) => stripos(trim($t, '"'), 'v=DMARC1') === 0));
        if (!$dmarc) {
            $f[] = $this->finding('mail.dmarc_missing', 'رکورد DMARC تعریف نشده است', 'medium', $domain, 'بدون DMARC، سرویس‌های ایمیل سیاستی برای رد ایمیل‌های جعلی به نام شما ندارند و گزارشی هم نمی‌گیرید.', '', 'mail-dmarc');
        } elseif (preg_match('~\bp\s*=\s*none~i', $dmarc[0])) {
            $f[] = $this->finding('mail.dmarc_none', 'سیاست DMARC فقط نظارتی است (p=none)', 'low', $domain, 'ایمیل‌های جعلی گزارش می‌شوند ولی رد نمی‌شوند.', mb_substr($dmarc[0], 0, 200), 'mail-dmarc');
        }
        return $f;
    }

    /** Certificate facts from a TLS handshake (no verification, so expired or self-signed ones are still read). */
    private function cert(string $host, string $connectTo): ?array
    {
        if (self::$certProbe !== null) {
            return (self::$certProbe)($host);
        }
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $host]]);
        $target = filter_var($connectTo, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $connectTo . ']' : $connectTo;
        $fp = @stream_socket_client('ssl://' . $target . ':443', $errno, $errstr, 6, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) {
            return null;
        }
        $meta = stream_get_meta_data($fp);
        $params = stream_context_get_params($fp);
        fclose($fp);
        $raw = $params['options']['ssl']['peer_certificate'] ?? null;
        $info = $raw ? openssl_x509_parse($raw) : false;
        if (!$info) {
            return null;
        }
        $san = [];
        foreach (explode(',', (string) ($info['extensions']['subjectAltName'] ?? '')) as $e) {
            $e = trim($e);
            if (str_starts_with($e, 'DNS:')) {
                $san[] = strtolower(substr($e, 4));
            }
        }
        $cn = strtolower((string) ($info['subject']['CN'] ?? ''));
        $names = $san ?: [$cn];
        $valid = false;
        foreach ($names as $n) {
            if ($n === strtolower($host) || (str_starts_with($n, '*.') && substr_count($host, '.') === substr_count($n, '.') && str_ends_with(strtolower($host), substr($n, 1)))) {
                $valid = true;
            }
        }
        $issuer = (string) ($info['issuer']['O'] ?? $info['issuer']['CN'] ?? '');
        return [
            'days' => (int) floor(((int) $info['validTo_time_t'] - time()) / 86400), 'not_after' => date('Y-m-d', (int) $info['validTo_time_t']),
            'issuer' => mb_substr($issuer, 0, 120), 'cn' => $cn, 'san' => array_slice($san, 0, 20), 'valid_host' => $valid,
            'self_signed' => ($info['issuer'] ?? null) == ($info['subject'] ?? null), 'proto' => (string) ($meta['crypto']['protocol'] ?? ''),
        ];
    }

    /** Parallel TCP connects with a 3 s overall budget. @return int[] open ports */
    private function ports(string $ip, array $ports): array
    {
        if (self::$portProbe !== null) {
            return (self::$portProbe)($ip, $ports);
        }
        $socks = [];
        $target = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $ip . ']' : $ip;
        foreach (array_unique($ports) as $p) {
            if ($p <= 0 || $p > 65535) {
                continue;
            }
            $s = @stream_socket_client('tcp://' . $target . ':' . $p, $en, $es, 3, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT);
            if ($s) {
                stream_set_blocking($s, false);
                $socks[$p] = $s;
            }
        }
        $open = [];
        $deadline = microtime(true) + 3.0;
        while ($socks && microtime(true) < $deadline) {
            $w = array_values($socks);
            $r = null;
            $e = null;
            $n = @stream_select($r, $w, $e, 0, 250000);
            if ($n === false) {
                break;
            }
            foreach ($socks as $p => $s) {
                if (in_array($s, $w, true)) {
                    // writable: connected, unless the peer refused (no remote name then)
                    if (@stream_socket_get_name($s, true) !== false) {
                        $open[] = $p;
                    }
                    fclose($s);
                    unset($socks[$p]);
                }
            }
        }
        foreach ($socks as $s) {
            fclose($s);
        }
        sort($open);
        return $open;
    }
}
