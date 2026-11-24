<?php

declare(strict_types=1);

namespace McSec\Engines;

use McSec\Db;
use McSec\Http;
use McSec\Lang;
use McSec\Net;
use McSec\Settings;

/**
 * Built-in hygiene checks, run by the worker itself (no backend): DNS, TLS certificate and protocol, HTTPS redirect,
 * security headers, cookie flags, information leaks in headers, a few well-known exposed files, e-mail spoofing
 * protection (SPF, DMARC), CAA, high-risk ports reachable from the internet, DNS blocklists (reputation_lists) and
 * dangling CNAMEs that let others take a subdomain over. Gentle: a handful of requests per asset, short timeouts,
 * never an exploit. Every finding carries a kb key with the Persian fix (Kb).
 * When the web part could not be judged (no answer, a WAF block, a server error) the result says so in 'partial':
 * the scan is an incomplete assessment, never "healthy", and findings it could not see stay open.
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
        $res = $this->run((string) $asset->kind, (string) $asset->value, self::portScopeFor($asset), self::subdomainsOf($asset));
        return ['ok' => true, 'ref' => 'builtin-' . $scan->id, 'meta' => ['result' => $res], 'progress' => 100, 'stage' => Lang::t('تمام شد')];
    }

    public function poll(object $scan, object $asset, array $profile): array
    {
        return ['status' => 'completed', 'progress' => 100, 'stage' => Lang::t('تمام شد')];
    }

    public function collect(object $scan, object $asset, array $profile): array
    {
        $meta = json_decode((string) $scan->backend_meta, true);
        $res = is_array($meta['result'] ?? null) ? $meta['result'] : ['findings' => [], 'surface' => []];
        $partial = (string) ($res['partial'] ?? '');
        return ['findings' => $res['findings'], 'surface' => $res['surface'], 'kinds' => [], 'complete' => $partial === '', 'partial' => $partial];
    }

    public function cancel(object $scan, object $asset): bool
    {
        return true;
    }

    public function health(): array
    {
        return ['ok' => function_exists('curl_init') && function_exists('stream_socket_client'), 'message' => 'بررسی‌های داخلی روی همین سرور WHMCS اجرا می‌شوند.']; // i18n-skip (admin setup page)
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

    /**
     * Subdomains seen under a domain asset by earlier discovery scans (still present), for the dangling-CNAME check.
     * @return string[]
     */
    public static function subdomainsOf(object $asset, int $max = 25): array
    {
        if ($asset->kind !== 'domain') {
            return [];
        }
        $out = [];
        $rows = Db::rows(Db::table('mod_mcsec_surface')->where('asset_id', $asset->id)->where('kind', 'host')->where('gone_at', 0)->orderByDesc('last_seen_at')->limit(200)->select(['value']));
        foreach ($rows as $r) {
            $v = strtolower(trim((string) $r->value));
            if ($v !== $asset->value && !filter_var($v, FILTER_VALIDATE_IP) && Net::within($v, (string) $asset->value) && !Net::blocked('domain', $v)) {
                $out[$v] = true;
            }
            if (count($out) >= $max) {
                break;
            }
        }
        return array_keys($out);
    }

    /**
     * @param string[]|null $portScope see portScopeFor()
     * @param string[] $subdomains discovered names under this domain, checked for dangling CNAMEs only (DNS, no HTTP)
     * @return array{findings:array,surface:array,partial:string} partial: why the web part was not judged ('' = complete)
     */
    public function run(string $kind, string $value, ?array $portScope = null, array $subdomains = []): array
    {
        $f = [];
        $s = [];
        $host = $value;
        $ips = $kind === 'ip' ? [$value] : Net::ips($value);
        $chain = $kind === 'domain' ? self::cnameChain($value) : [];
        foreach ($subdomains as $sub) {
            $f = array_merge($f, $this->takeover((string) $sub, self::cnameChain((string) $sub), null));
        }
        if ($kind === 'domain') {
            if (!$ips) {
                $tk = $this->takeover($value, $chain, null);
                if (!$tk) {
                    $f[] = $this->finding('dns.no_address', Lang::t('دامنه به هیچ IPی اشاره نمی‌کند'), 'info', $host, Lang::t('رکورد A یا AAAA برای این نام پیدا نشد؛ بقیه‌ی بررسی‌های وب انجام نشد.'), '', 'dns-no-address');
                }
                return ['findings' => array_merge($f, $tk, $this->email($value), $this->reputation($value, [])), 'surface' => $s, 'partial' => ''];
            }
            foreach ($ips as $ip) {
                $s[] = ['kind' => 'host', 'value' => $ip, 'meta' => ['from' => $host]];
            }
        }
        $publicIps = array_values(array_filter($ips, fn ($ip) => Net::isPublicIp($ip) || Settings::bool('allow_private_ips')));
        $owned = $portScope === null ? $publicIps : array_values(array_filter($publicIps, fn ($ip) => in_array(strtolower($ip), $portScope, true)));
        $partial = '';

        // web: HTTPS, certificate, redirect, headers, cookies, leaks, exposed files
        $https = $this->get('https://' . $this->urlHost($host) . '/', $publicIps[0] ?? '', $host, true);
        $http = $this->get('http://' . $this->urlHost($host) . '/', $publicIps[0] ?? '', $host, false);
        if ($kind === 'domain') {
            $f = array_merge($f, $this->takeover($value, $chain, $https ?? $http));
        }
        if ($https === null && $http === null && $publicIps) {
            $partial = Lang::t('سایت به درخواست‌های بررسی (HTTP و HTTPS) پاسخ نداد؛ بررسی‌های وب انجام نشد.');
        }
        if ($https !== null || $http !== null) {
            $cert = $this->cert($host, $publicIps[0] ?? $host);
            if ($cert !== null) {
                $s[] = ['kind' => 'cert', 'value' => $host . ':443', 'meta' => $cert];
                if ($cert['days'] < 0) {
                    $f[] = $this->finding('tls.expired', Lang::t('گواهی SSL منقضی شده است'), 'high', $host . ':443', Lang::t('گواهی از {n} روز پیش منقضی شده و مرورگرها هشدار امنیتی نشان می‌دهند.', ['n' => abs($cert['days'])]), 'expires in ' . $cert['days'] . ' days; issuer: ' . $cert['issuer'], 'tls-expired');
                } elseif ($cert['days'] < 14) {
                    $f[] = $this->finding('tls.expiring', Lang::t('گواهی SSL به‌زودی منقضی می‌شود'), 'medium', $host . ':443', Lang::t('فقط {n} روز تا انقضای گواهی مانده است.', ['n' => $cert['days']]), 'expires in ' . $cert['days'] . ' days', 'tls-expiring');
                } elseif ($cert['days'] < 30) {
                    $f[] = $this->finding('tls.expiring', Lang::t('گواهی SSL کمتر از یک ماه اعتبار دارد'), 'low', $host . ':443', Lang::t('{n} روز تا انقضای گواهی مانده است. اگر تمدید خودکار ندارید، برنامه‌ریزی کنید.', ['n' => $cert['days']]), 'expires in ' . $cert['days'] . ' days', 'tls-expiring');
                }
                if ($kind === 'domain' && !$cert['valid_host']) {
                    $f[] = $this->finding('tls.hostname', Lang::t('گواهی SSL برای این نام صادر نشده است'), 'high', $host . ':443', Lang::t('نام‌های گواهی ({names}) با این دامنه یکی نیست.', ['names' => implode(', ', array_slice($cert['san'], 0, 5))]), 'CN=' . $cert['cn'], 'tls-hostname');
                }
                if ($cert['self_signed'] ?? false) {
                    $f[] = $this->finding('tls.self_signed', Lang::t('گواهی SSL خودامضا است'), 'medium', $host . ':443', Lang::t('مرورگرها به گواهی خودامضا اعتماد نمی‌کنند.'), 'issuer=' . $cert['issuer'], 'tls-self-signed');
                }
                if (in_array($cert['proto'] ?? '', ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3'], true)) {
                    $f[] = $this->finding('tls.old_protocol', Lang::t('نسخه‌ی قدیمی TLS پذیرفته می‌شود'), 'medium', $host . ':443', Lang::t('سرور با {proto} وصل می‌شود که دیگر امن شمرده نمی‌شود.', ['proto' => $cert['proto']]), 'negotiated ' . $cert['proto'], 'tls-old-protocol');
                }
            } elseif ($https === null && $http !== null) {
                $f[] = $this->finding('web.no_https', Lang::t('سایت HTTPS ندارد'), 'high', 'http://' . $host, Lang::t('سایت فقط با HTTP بی‌رمز باز می‌شود؛ رمز ورود و اطلاعات کاربران در مسیر خوانده می‌شود.'), '', 'web-no-https');
            }
            if ($http !== null && $https !== null && !$this->redirectsToHttps($http)) {
                $f[] = $this->finding('web.no_redirect', Lang::t('نسخه‌ی HTTP به HTTPS هدایت نمی‌شود'), 'low', 'http://' . $host, Lang::t('بازدیدکننده‌ای که http:// را باز کند، روی اتصال بی‌رمز می‌ماند.'), 'HTTP ' . $http['status'], 'web-no-redirect');
            }
            $main = $https ?? $http;
            $st = (int) $main['status'];
            foreach (['server', 'x-powered-by'] as $h) {
                foreach ($main['headers'][$h] ?? [] as $v) {
                    $s[] = ['kind' => 'tech', 'value' => mb_substr($v, 0, 120), 'meta' => ['header' => $h, 'host' => $host]];
                }
            }
            if ($st === 403 || $st === 429) {
                // a WAF, a rate limit or an IP block answered instead of the site: its headers say nothing about the site
                $partial = Lang::t('فایروال یا محدودیت نرخ جلوی بررسی را گرفت (HTTP {code})؛ هدرها و فایل‌های لورفته سنجیده نشدند. IP اسکنر را در فایروال یا WAF خود مجاز کنید و دوباره بسنجید.', ['code' => $st]);
            } elseif ($st >= 500) {
                $partial = Lang::t('سایت هنگام بررسی خطای سرور داد (HTTP {code})؛ هدرها و فایل‌های لورفته سنجیده نشدند.', ['code' => $st]);
            } else {
                $f = array_merge($f, $this->headers($main, $host, $https !== null));
                $f = array_merge($f, $this->exposedFiles(($https !== null ? 'https://' : 'http://') . $this->urlHost($host), $publicIps[0] ?? '', $host, $https !== null));
            }
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
                    $f[] = $this->finding('port.' . $p, Lang::t('درگاه {name} روی اینترنت باز است', ['name' => $name]), $sev, $publicIps[0] . ':' . $p,
                        Lang::t('سرویس {name} (درگاه {port}) از همه‌جای اینترنت در دسترس است و هدف حمله‌ی حدس رمز یا آسیب‌پذیری‌های شناخته‌شده قرار می‌گیرد.', ['name' => $name, 'port' => $p]), 'tcp/' . $p . ' open', 'port-exposed');
                }
            }
        }
        if ($kind === 'domain' && Net::apex($value) === $value) {
            $f = array_merge($f, $this->email($value));
            if (!Net::dns($value, 'CAA')) {
                $f[] = $this->finding('dns.no_caa', Lang::t('رکورد CAA تعریف نشده است'), 'info', $value, Lang::t('بدون CAA هر مرجع صدور گواهی می‌تواند برای این دامنه گواهی صادر کند.'), '', 'dns-caa');
            }
        }
        $f = array_merge($f, $this->reputation($kind === 'domain' ? $value : '', $owned));
        return ['findings' => $f, 'surface' => $s, 'partial' => $partial];
    }

    /**
     * Services where an unclaimed name can be registered by anyone, so a CNAME left pointing at them hands the
     * subdomain to whoever claims it (EdOverflow/can-i-take-over-xyz, "vulnerable" entries). CNAME suffix =>
     * [service, text its "nothing here" page shows]; '' = judged only by a CNAME target that no longer resolves.
     */
    private const TAKEOVER = [
        'github.io' => ['GitHub Pages', "There isn't a GitHub Pages site here"],
        'herokuapp.com' => ['Heroku', 'No such app'],
        'herokudns.com' => ['Heroku', 'No such app'],
        's3.amazonaws.com' => ['Amazon S3', 'NoSuchBucket'],
        'amazonaws.com' => ['Amazon S3', 'NoSuchBucket'],
        'elasticbeanstalk.com' => ['AWS Elastic Beanstalk', ''],
        'cloudapp.net' => ['Microsoft Azure', ''],
        'cloudapp.azure.com' => ['Microsoft Azure', ''],
        'azurewebsites.net' => ['Microsoft Azure', ''],
        'blob.core.windows.net' => ['Microsoft Azure', ''],
        'trafficmanager.net' => ['Microsoft Azure', ''],
        'azure-api.net' => ['Microsoft Azure', ''],
        'azurefd.net' => ['Microsoft Azure', ''],
        'azureedge.net' => ['Microsoft Azure', ''],
        'bitbucket.io' => ['Bitbucket', 'Repository not found'],
        'pantheonsite.io' => ['Pantheon', 'The gods are wise'],
        'surge.sh' => ['Surge.sh', 'project not found'],
        'helpscoutdocs.com' => ['Help Scout', 'No settings were found for this company'],
        'readme.io' => ['ReadMe', 'Project doesnt exist... yet!'],
        'myshopify.com' => ['Shopify', 'Sorry, this shop is currently unavailable'],
        'domains.tumblr.com' => ['Tumblr', "Whatever you were looking for doesn't currently exist at this address"],
        'agilecrm.com' => ['Agile CRM', 'Sorry, this page is no longer available'],
        'fly.dev' => ['Fly.io', ''],
    ];

    /** CNAME targets of a name, in order (at most 5 hops). @return string[] */
    public static function cnameChain(string $name): array
    {
        $out = [];
        $n = strtolower($name);
        for ($hop = 0; $hop < 5; $hop++) {
            $t = strtolower(rtrim((string) (Net::dns($n, 'CNAME')[0]['target'] ?? ''), '.'));
            if ($t === '' || $t === $n || in_array($t, $out, true)) {
                break;
            }
            $out[] = $t;
            $n = $t;
        }
        return $out;
    }

    /**
     * A CNAME whose target no longer exists (dangling), or that points at a service showing its "unclaimed" page:
     * anyone could claim the name there and serve content under this domain.
     * @param string[] $chain cnameChain() of $name
     */
    private function takeover(string $name, array $chain, ?array $page): array
    {
        if (!$chain) {
            return [];
        }
        $last = (string) end($chain);
        $service = null;
        foreach ($chain as $t) {
            foreach (self::TAKEOVER as $suffix => $def) {
                if (Net::within($t, $suffix)) {
                    $service = $def;
                    break 2;
                }
            }
        }
        $path = $name . ' → ' . implode(' → ', $chain);
        if (!Net::ips($last)) {
            if ($service !== null) {
                return [$this->finding('dns.takeover', Lang::t('خطر تصاحب زیردامنه ({service})', ['service' => $service[0]]), 'high', $name,
                    Lang::t('این نام با CNAME به {service} اشاره می‌کند ولی آن منبع دیگر وجود ندارد. هر کسی می‌تواند همین نام را در {service} برای خودش بسازد و زیر نام دامنه‌ی شما محتوا نشان دهد.', ['service' => $service[0]]),
                    $path . ' (no A/AAAA)', 'subdomain-takeover')];
            }
            return [$this->finding('dns.dangling', Lang::t('رکورد CNAME به نامی اشاره می‌کند که وجود ندارد'), 'medium', $name,
                Lang::t('مقصد این رکورد پاسخی ندارد. اگر مقصد سرویسی است که دیگری بتواند همان نام را در آن بگیرد، زیردامنه‌ی شما تصاحب می‌شود؛ رکوردی را که استفاده نمی‌شود پاک کنید.'),
                $path . ' (no A/AAAA)', 'subdomain-takeover')];
        }
        if ($service !== null && $service[1] !== '' && $page !== null && str_contains(substr((string) $page['body'], 0, 50000), $service[1])) {
            return [$this->finding('dns.takeover', Lang::t('خطر تصاحب زیردامنه ({service})', ['service' => $service[0]]), 'high', $name,
                Lang::t('این نام به {service} اشاره می‌کند ولی آن‌جا صفحه‌ی «چیزی این‌جا نیست» نشان داده می‌شود؛ یعنی منبع شما در آن سرویس حذف شده و دیگری می‌تواند آن را بگیرد.', ['service' => $service[0]]),
                $path . '; page: "' . $service[1] . '"', 'subdomain-takeover')];
        }
        return [];
    }

    /**
     * DNS blocklists (setting reputation_lists): the domain name, and only the IPs this account owns (a shared
     * hosting IP on a spam list is the hosting company's matter, not the customer's).
     * @param string[] $ips public IPs owned by the account
     */
    private function reputation(string $domain, array $ips): array
    {
        $f = [];
        foreach (self::reputationLists() as [$type, $zone, $name]) {
            $targets = $type === 'domain'
                ? ($domain === '' ? [] : array_values(array_unique([$domain, Net::apex($domain)])))
                : array_values(array_filter($ips, fn ($ip) => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false));
            foreach ($targets as $t) {
                $q = $type === 'domain' ? $t . '.' . $zone : implode('.', array_reverse(explode('.', $t))) . '.' . $zone;
                $answers = array_values(array_filter(Net::ips($q), fn ($a) => str_starts_with($a, '127.')));
                $sev = self::listedSeverity($type, $zone, $answers);
                if ($sev === '') {
                    continue;
                }
                $f[] = $type === 'domain'
                    ? $this->finding('rep.domain.' . $zone, Lang::t('دامنه در فهرست سیاه {list} است', ['list' => $name]), $sev, $t,
                        $sev === 'critical' ? Lang::t('این دامنه در فهرست دامنه‌های بدافزار یا فیشینگ است: احتمالاً سایت آلوده شده یا برای فریب کاربران به کار رفته است. مرورگرها، ایمیل‌ها و سامانه‌های امنیتی آن را مسدود می‌کنند.')
                            : Lang::t('این دامنه در فهرست سیاه است و ایمیل‌ها و پیوندهایش ممکن است مسدود شوند.'), implode(', ', $answers) . ' @ ' . $zone, 'blocklisted')
                    : $this->finding('rep.ip.' . $zone, Lang::t('IP سرور در فهرست سیاه {list} است', ['list' => $name]), $sev, $t,
                        Lang::t('این IP به‌عنوان فرستنده‌ی هرزنامه یا دستگاه آلوده ثبت شده است؛ ایمیل‌های این سرور احتمالاً رد می‌شوند و ممکن است سرور آلوده باشد.'), implode(', ', $answers) . ' @ ' . $zone, 'blocklisted');
            }
        }
        return $f;
    }

    /** @return array<int,array{0:string,1:string,2:string}> [type, zone, name] */
    public static function reputationLists(): array
    {
        $out = [];
        foreach (preg_split('~\r\n|\r|\n~', Settings::get('reputation_lists')) ?: [] as $line) {
            $line = trim((string) preg_replace('~#.*$~', '', $line));
            $p = preg_split('~[ \t]+~', $line, 3) ?: [];
            if (count($p) < 2 || !in_array(strtolower($p[0]), ['domain', 'ip'], true) || !preg_match('~^[a-z0-9-]+(\.[a-z0-9-]+)+$~i', $p[1])) {
                continue;
            }
            $out[] = [strtolower($p[0]), strtolower($p[1]), trim((string) ($p[2] ?? '')) !== '' ? trim((string) $p[2]) : strtolower($p[1])];
        }
        return $out;
    }

    /**
     * Severity of a blocklist answer, '' = not listed or the list refused to answer. Spamhaus: 127.255.255.x are
     * errors (public resolver, quota), 127.0.0.10/11 the PBL policy list (not an incident); DBL 127.0.1.4–6 and
     * 127.0.1.104–106 are phishing, malware and botnet domains. SURBL/URIBL: 127.0.0.1 means "query blocked".
     * @param string[] $answers
     */
    public static function listedSeverity(string $type, string $zone, array $answers): string
    {
        $real = [];
        foreach ($answers as $a) {
            if (str_starts_with($a, '127.255.255.') || $a === '127.0.0.1' || (str_contains($zone, 'spamhaus') && in_array($a, ['127.0.0.10', '127.0.0.11'], true))) {
                continue;
            }
            $real[] = $a;
        }
        if (!$real) {
            return '';
        }
        if ($type === 'domain') {
            return array_intersect($real, ['127.0.1.4', '127.0.1.5', '127.0.1.6', '127.0.1.104', '127.0.1.105', '127.0.1.106']) ? 'critical' : 'high';
        }
        return array_intersect($real, ['127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7']) ? 'high' : 'medium';
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
            $f[] = $this->finding('hdr.hsts', Lang::t('هدر HSTS تنظیم نشده است'), 'low', $loc, Lang::t('بدون HSTS مرورگر ممکن است اولین اتصال را بی‌رمز برقرار کند (حمله‌ی SSL stripping).'), '', 'hdr-hsts');
        }
        $csp = strtolower(implode(';', $h['content-security-policy'] ?? []));
        if ($csp === '') {
            $f[] = $this->finding('hdr.csp', Lang::t('سیاست امنیت محتوا (CSP) تنظیم نشده است'), 'low', $loc, Lang::t('CSP اثر حمله‌های XSS و تزریق اسکریپت را محدود می‌کند.'), '', 'hdr-csp');
        }
        if (empty($h['x-frame-options']) && !str_contains($csp, 'frame-ancestors')) {
            $f[] = $this->finding('hdr.frame', Lang::t('محافظت در برابر Clickjacking نیست'), 'low', $loc, Lang::t('سایت را می‌توان در iframe سایت دیگری نشاند و کاربر را به کلیک ناخواسته کشاند.'), '', 'hdr-frame');
        }
        if (strtolower((string) ($h['x-content-type-options'][0] ?? '')) !== 'nosniff') {
            $f[] = $this->finding('hdr.nosniff', Lang::t('هدر X-Content-Type-Options تنظیم نشده است'), 'info', $loc, Lang::t('مرورگر ممکن است نوع فایل را حدس بزند و فایل بارگذاری‌شده را اجرا کند.'), '', 'hdr-nosniff');
        }
        foreach (['server' => 'web server', 'x-powered-by' => 'framework'] as $name => $what) {
            $v = (string) ($h[$name][0] ?? '');
            if ($v !== '' && preg_match('~\d+\.\d+~', $v)) {
                $f[] = $this->finding('hdr.version.' . $name, Lang::t('نسخه‌ی نرم‌افزار در هدر {header} دیده می‌شود', ['header' => $name]), 'low', $loc, Lang::t('نسخه‌ی دقیق به مهاجم کمک می‌کند آسیب‌پذیری‌های همان نسخه را پیدا کند.'), $name . ': ' . mb_substr($v, 0, 120), 'hdr-version');
            }
        }
        foreach ($h['set-cookie'] ?? [] as $c) {
            $lc = strtolower($c);
            $name = trim(explode('=', $c, 2)[0]);
            if (preg_match('~sess|auth|token|login|sid~i', $name) && ((!str_contains($lc, 'secure') && $tls) || !str_contains($lc, 'httponly'))) {
                $f[] = $this->finding('cookie.flags.' . strtolower($name), Lang::t('کوکی نشست بدون Secure یا HttpOnly'), 'medium', $loc, Lang::t('کوکی «{name}» بدون پرچم‌های Secure و HttpOnly فرستاده می‌شود و در خطر سرقت است.', ['name' => $name]), mb_substr($c, 0, 160), 'cookie-flags');
            }
        }
        if (preg_match('~<title>\s*Index of /~i', (string) $r['body'])) {
            $f[] = $this->finding('web.listing', Lang::t('فهرست فایل‌های پوشه نمایش داده می‌شود'), 'medium', $loc, Lang::t('Directory listing روشن است و فایل‌های پوشه را به همه نشان می‌دهد.'), 'Index of /', 'web-listing');
        }
        return $f;
    }

    private function exposedFiles(string $base, string $ip, string $host, bool $tls): array
    {
        $f = [];
        $checks = [
            ['/.git/HEAD', '~^ref:\s*refs/~m', 'web.git', Lang::t('پوشه‌ی .git روی سایت در دسترس است'), 'high', Lang::t('کل کد منبع، تاریخچه و گاهی رمزها از روی پوشه‌ی .git قابل بازسازی است.'), 'web-git'],
            ['/.env', '~^(APP_KEY|DB_PASSWORD|DB_HOST|SECRET_KEY|AWS_SECRET|MAIL_PASSWORD)\s*=~m', 'web.env', Lang::t('فایل .env روی سایت در دسترس است'), 'critical', Lang::t('این فایل معمولاً رمز پایگاه داده و کلیدهای سرویس‌ها را دارد.'), 'web-env'],
            ['/server-status', '~Apache Server Status~i', 'web.server_status', Lang::t('صفحه‌ی server-status آپاچی عمومی است'), 'medium', Lang::t('این صفحه درخواست‌های جاری، IP بازدیدکننده‌ها و مسیرهای داخلی را نشان می‌دهد.'), 'web-server-status'],
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
            $f[] = $this->finding('mail.spf_missing', Lang::t('رکورد SPF تعریف نشده است'), 'medium', $domain, Lang::t('هر کسی می‌تواند ایمیلی به نام این دامنه بفرستد و گیرنده نمی‌تواند جعلی بودنش را بفهمد.'), '', 'mail-spf');
        } elseif (preg_match('/[+?]all\b/i', $spf[0]) || !preg_match('/[-~]all\b|redirect=/i', $spf[0])) {
            $f[] = $this->finding('mail.spf_weak', Lang::t('رکورد SPF جلوی جعل را نمی‌گیرد'), 'medium', $domain, Lang::t('SPF با ‎+all یا ‎?all یا بی پایان all، فرستنده‌های دیگر را رد نمی‌کند.'), mb_substr($spf[0], 0, 200), 'mail-spf');
        }
        $dmarc = array_values(array_filter(Net::txt('_dmarc.' . $domain), fn ($t) => stripos(trim($t, '"'), 'v=DMARC1') === 0));
        if (!$dmarc) {
            $f[] = $this->finding('mail.dmarc_missing', Lang::t('رکورد DMARC تعریف نشده است'), 'medium', $domain, Lang::t('بدون DMARC، سرویس‌های ایمیل سیاستی برای رد ایمیل‌های جعلی به نام شما ندارند و گزارشی هم نمی‌گیرید.'), '', 'mail-dmarc');
        } elseif (preg_match('~\bp\s*=\s*none~i', $dmarc[0])) {
            $f[] = $this->finding('mail.dmarc_none', Lang::t('سیاست DMARC فقط نظارتی است (p=none)'), 'low', $domain, Lang::t('ایمیل‌های جعلی گزارش می‌شوند ولی رد نمی‌شوند.'), mb_substr($dmarc[0], 0, 200), 'mail-dmarc');
        }
        return $f;
    }

    /** cert() for other parts (light monitoring). */
    public static function certInfo(string $host, string $connectTo): ?array
    {
        return (new self())->cert($host, $connectTo);
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
