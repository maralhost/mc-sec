<?php

declare(strict_types=1);

namespace McSec;

/**
 * Proof of ownership before anything is scanned (the legal and ethical line of the product).
 *
 * Instant (database only, at add time and by the worker):
 *  - whmcs:  the domain (or a parent of it) is a registered domain or hosting service of this account, or the IP is a
 *            dedicated/assigned IP of its active services;
 *  - parent: a parent domain of this asset is verified on the same account (a verified domain covers subdomains).
 * Network checks (the «بررسی کن» button, rate limited, and the worker every few minutes while pending):
 *  - dns:  TXT record "mcsec-verify=<token>" on _mcsec-verify.<domain> (its own name, so an SPF record on @ is never
 *          touched by mistake) or on <domain> itself;
 *  - file: http(s)://<host>/.well-known/mcsec-verify.txt contains the proof;
 *  - meta: <meta name="mcsec-verification" content="<token>"> on the home page;
 *  - ptr:  an IP whose reverse DNS is a host inside a verified domain of the account, and that host resolves back.
 * Verified assets are re-checked every verify_recheck_days; three failures in a row → lapsed (schedules pause).
 */
final class Verify
{
    public const METHODS = ['dns' => 'رکورد DNS', 'file' => 'فایل روی سایت', 'meta' => 'تگ متا', 'whmcs' => 'سرویس مارال', 'parent' => 'دامنه‌ی اصلی تأییدشده', 'ptr' => 'DNS معکوس', 'admin' => 'تأیید مدیر'];
    public const FILE_PATH = '/.well-known/mcsec-verify.txt';
    /** Methods that prove control of the whole DNS zone, so subdomains inherit them. */
    public const ZONE_METHODS = ['dns', 'whmcs', 'admin', 'parent'];

    /** Database-only verification (WHMCS ownership, verified parent). */
    public static function instant(object $asset): bool
    {
        $m = self::instantMethod($asset);
        if ($m === '') {
            return false;
        }
        self::markVerified($asset, $m, $m === 'whmcs' ? 'این دارایی از سرویس‌های همین حساب در مارال کلاد است.' : 'دامنه‌ی اصلی آن تأیید شده است.');
        return true;
    }

    public static function instantMethod(object $asset): string
    {
        $clientId = (int) $asset->client_id;
        if ($asset->kind === 'domain') {
            $chain = array_merge([(string) $asset->value], Net::parents((string) $asset->value));
            // only a proof of DNS-level control covers subdomains: a file or meta tag proves one website, not the zone
            $parentVerified = Db::table('mod_mcsec_assets')->where('client_id', $clientId)->where('status', 'verified')->where('kind', 'domain')
                ->whereIn('method', self::ZONE_METHODS)->whereIn('value', array_slice($chain, 1))->exists();
            if ($parentVerified) {
                return 'parent';
            }
            if (Settings::bool('ownership_autoverify') && array_intersect($chain, Whmcs::ownedDomains($clientId))) {
                return 'whmcs';
            }
        } elseif ($asset->kind === 'ip' && Settings::bool('ownership_autoverify')) {
            if (in_array(strtolower((string) $asset->value), Whmcs::ownedIps($clientId), true)) {
                return 'whmcs';
            }
        }
        return '';
    }

    /**
     * Network check now (button or worker). @return array{ok:bool,method:string,note:string}
     */
    public static function check(object $asset): array
    {
        if (self::instantMethod($asset) !== '') {
            self::instant($asset);
            return ['ok' => true, 'method' => self::instantMethod($asset), 'note' => ''];
        }
        $acc = Accounts::ensure((int) $asset->client_id);
        $proof = Accounts::proof($acc);
        $notes = [];
        if ($asset->kind === 'domain') {
            foreach (['dns', 'file', 'meta'] as $m) {
                $r = self::{'try' . ucfirst($m)}((string) $asset->value, $proof, (string) $acc->verify_token);
                if ($r['ok']) {
                    return self::found($asset, $m);
                }
                $notes[] = $r['note'];
            }
        } elseif ($asset->kind === 'ip') {
            $r = self::tryFile((string) $asset->value, $proof, (string) $acc->verify_token);
            if ($r['ok']) {
                return self::found($asset, 'file');
            }
            $notes[] = $r['note'];
            $r = self::tryPtr($asset);
            if ($r['ok']) {
                return self::found($asset, 'ptr');
            }
            $notes[] = $r['note'];
        } else {
            $notes[] = 'بازه‌ی IP با روش خودکار تأیید نمی‌شود؛ از «درخواست تأیید دستی» استفاده کنید یا IPها را تک‌تک بیفزایید.';
        }
        $note = mb_substr(implode(' ', array_filter($notes)), 0, 250);
        Db::table('mod_mcsec_assets')->where('id', $asset->id)->update(['checked_at' => Clock::now(), 'check_note' => $note]);
        return ['ok' => false, 'method' => '', 'note' => $note];
    }

    private static function found(object $asset, string $method): array
    {
        self::markVerified($asset, $method);
        return ['ok' => true, 'method' => $method, 'note' => ''];
    }

    /** @return array{ok:bool,note:string} */
    public static function tryDns(string $domain, string $proof, string $token): array
    {
        $found = [];
        foreach (['_mcsec-verify.' . $domain, $domain] as $name) {
            foreach (Net::txt($name) as $txt) {
                $txt = trim($txt, " \"\t");
                if (hash_equals($proof, $txt)) {
                    return ['ok' => true, 'note' => ''];
                }
                if (str_starts_with($txt, 'mcsec-verify=')) {
                    $found[] = $txt;
                }
            }
        }
        return ['ok' => false, 'note' => $found ? 'رکورد TXT پیدا شد ولی مقدارش با کد این حساب یکی نیست.' : 'رکورد TXT هنوز دیده نمی‌شود (ممکن است تا چند ساعت طول بکشد).'];
    }

    public static function tryFile(string $host, string $proof, string $token): array
    {
        foreach (['https', 'http'] as $scheme) {
            $r = self::fetch($scheme . '://' . self::hostForUrl($host) . self::FILE_PATH, 4096);
            if ($r === null) {
                continue;
            }
            if ($r['status'] === 200 && str_contains($r['body'], $proof)) {
                return ['ok' => true, 'note' => ''];
            }
            if ($r['status'] === 200) {
                return ['ok' => false, 'note' => 'فایل تأیید باز شد ولی کد درست در آن نیست.'];
            }
        }
        return ['ok' => false, 'note' => 'فایل تأیید روی سایت پیدا نشد.'];
    }

    public static function tryMeta(string $domain, string $proof, string $token): array
    {
        foreach (['https', 'http'] as $scheme) {
            $r = self::fetch($scheme . '://' . $domain . '/', 262144);
            if ($r === null || $r['status'] !== 200) {
                continue;
            }
            if (preg_match_all('~<meta\s[^>]*name\s*=\s*["\']mcsec-verification["\'][^>]*>~i', $r['body'], $mm)) {
                foreach ($mm[0] as $tag) {
                    if (preg_match('~content\s*=\s*["\']([^"\']+)["\']~i', $tag, $c) && (hash_equals($token, trim($c[1])) || hash_equals($proof, trim($c[1])))) {
                        return ['ok' => true, 'note' => ''];
                    }
                }
                return ['ok' => false, 'note' => 'تگ متا هست ولی مقدارش درست نیست.'];
            }
            return ['ok' => false, 'note' => 'تگ متا در صفحه‌ی اصلی پیدا نشد.'];
        }
        return ['ok' => false, 'note' => 'صفحه‌ی اصلی سایت باز نشد.'];
    }

    public static function tryPtr(object $asset): array
    {
        $host = Net::ptr((string) $asset->value);
        if ($host === '') {
            return ['ok' => false, 'note' => 'DNS معکوس (PTR) برای این IP تعریف نشده است.'];
        }
        $domains = Db::table('mod_mcsec_assets')->where('client_id', $asset->client_id)->where('status', 'verified')->where('kind', 'domain')->pluck('value');
        $domains = is_array($domains) ? $domains : $domains->all();
        foreach ($domains as $d) {
            if (Net::within($host, (string) $d) && in_array((string) $asset->value, Net::ips($host), true)) {
                return ['ok' => true, 'note' => ''];
            }
        }
        return ['ok' => false, 'note' => 'DNS معکوس این IP (' . $host . ') زیر هیچ دامنه‌ی تأییدشده‌ی شما نیست.'];
    }

    /** A GET to the customer's own host, pinned to a public IP (no SSRF into our network). */
    private static function fetch(string $url, int $max): ?array
    {
        $chk = Net::publicUrl($url);
        if (!$chk['ok']) {
            if (!Settings::bool('allow_private_ips')) {
                return null;
            }
            $chk = ['resolve' => ''];
        }
        $r = Http::request('GET', $url, ['Accept' => 'text/plain, text/html;q=0.9, */*;q=0.5'], null,
            ['timeout' => 8, 'connect' => 4, 'verify' => false, 'max_bytes' => $max, 'resolve' => $chk['resolve'] ?? '']);
        return $r['error'] !== '' && $r['status'] === 0 ? null : $r;
    }

    private static function hostForUrl(string $host): string
    {
        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $host . ']' : $host;
    }

    public static function markVerified(object $asset, string $method, string $note = ''): void
    {
        $was = (string) $asset->status;
        Db::table('mod_mcsec_assets')->where('id', $asset->id)->update([
            'status' => 'verified', 'method' => $method, 'verified_at' => $was === 'verified' ? (int) $asset->verified_at : Clock::now(),
            'checked_at' => Clock::now(), 'next_check_at' => Clock::now() + max(1, Settings::int('verify_recheck_days')) * 86400, 'fails' => 0, 'check_note' => $note,
        ]);
        if ($was !== 'verified') {
            Audit::log((int) $asset->client_id, 'asset_verified', (string) $asset->value, ['method' => $method]);
            Notify::event((int) $asset->client_id, 'asset_verified', ['asset' => (string) $asset->value, 'asset_id' => (int) $asset->id, 'method' => $method], 'verified:' . $asset->id . ':' . Clock::now());
            // its pending subdomains inherit the proof now
            if ($asset->kind === 'domain' && in_array($method, self::ZONE_METHODS, true)) {
                foreach (Db::rows(Db::table('mod_mcsec_assets')->where('client_id', $asset->client_id)->where('kind', 'domain')->whereIn('status', ['pending', 'lapsed'])) as $child) {
                    if ($child->id !== $asset->id && Net::within((string) $child->value, (string) $asset->value)) {
                        self::markVerified($child, 'parent', 'دامنه‌ی اصلی آن تأیید شده است.');
                    }
                }
            }
            Db::table('mod_mcsec_schedules')->where('client_id', $asset->client_id)->where('asset_id', $asset->id)->where('status', 'paused')->where('pause_reason', 'verify')
                ->update(['status' => 'active', 'pause_reason' => '']);
            // «start the scan once verified», chosen when the asset was added: queued now, so nobody has to come back
            $auto = (string) ($asset->autoscan ?? '');
            if ($auto !== '' && Db::table('mod_mcsec_assets')->where('id', $asset->id)->where('autoscan', $auto)->update(['autoscan' => '']) === 1) {
                $fresh = Db::table('mod_mcsec_assets')->where('id', $asset->id)->first();
                $r = Scans::queue((int) $asset->client_id, $fresh, $auto, 0, (int) $asset->created_by);
                if (!$r['ok']) {
                    Notify::event((int) $asset->client_id, 'scan_failed', ['asset' => (string) $asset->value, 'profile' => $auto, 'error' => $r['error']], 'autoscan:' . $asset->id);
                }
            }
        }
    }

    /** Admin approval for what cannot be proven automatically (a CIDR, a server without web). */
    public static function adminApprove(int $assetId, string $note): bool
    {
        $a = Db::table('mod_mcsec_assets')->where('id', $assetId)->where('status', '!=', 'removed')->first();
        if (!$a) {
            return false;
        }
        self::markVerified($a, 'admin', $note !== '' ? $note : 'با بررسی پشتیبانی تأیید شد.');
        Audit::log((int) $a->client_id, 'admin_verify', (string) $a->value, ['note' => $note]);
        return true;
    }

    /**
     * Worker: pending assets (checked often during the first hour, then hourly, for verify_pending_days) and verified
     * ones due for their periodic re-check. Network calls, so bounded by a time budget.
     */
    public static function due(int $budgetSeconds = 20): array
    {
        $deadline = microtime(true) + $budgetSeconds;
        $now = Clock::now();
        $out = ['verified' => 0, 'lapsed' => 0, 'checked' => 0];
        $pending = Db::rows(Db::table('mod_mcsec_assets')->where('status', 'pending')->where('next_check_at', '<=', $now)
            ->where('created_at', '>', $now - max(1, Settings::int('verify_pending_days')) * 86400)->orderBy('next_check_at')->limit(30));
        foreach ($pending as $a) {
            if (microtime(true) > $deadline) {
                break;
            }
            $r = self::check($a);
            $out['checked']++;
            if ($r['ok']) {
                $out['verified']++;
            } else {
                $age = $now - (int) $a->created_at;
                Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['next_check_at' => $now + ($age < 3600 ? 300 : 3600)]);
            }
        }
        $recheck = Db::rows(Db::table('mod_mcsec_assets')->where('status', 'verified')->where('next_check_at', '<=', $now)->orderBy('next_check_at')->limit(30));
        foreach ($recheck as $a) {
            if (microtime(true) > $deadline) {
                break;
            }
            $out['checked']++;
            if (in_array($a->method, ['whmcs', 'parent'], true)) {
                $ok = self::instantMethod($a) !== '';
            } elseif ($a->method === 'admin') {
                $ok = true;
            } else {
                $ok = self::check($a)['ok'];
            }
            if ($ok) {
                Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['next_check_at' => $now + max(1, Settings::int('verify_recheck_days')) * 86400, 'fails' => 0, 'checked_at' => $now]);
                continue;
            }
            $fails = (int) $a->fails + 1;
            if ($fails >= 3) {
                Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['status' => 'lapsed', 'fails' => $fails, 'checked_at' => $now, 'next_check_at' => $now + 3600]);
                Db::table('mod_mcsec_schedules')->where('asset_id', $a->id)->where('status', 'active')->update(['status' => 'paused', 'pause_reason' => 'verify']);
                Audit::log((int) $a->client_id, 'asset_lapsed', (string) $a->value);
                Notify::event((int) $a->client_id, 'asset_lapsed', ['asset' => (string) $a->value, 'asset_id' => (int) $a->id], 'lapsed:' . $a->id . ':' . $now);
                $out['lapsed']++;
            } else {
                Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['fails' => $fails, 'checked_at' => $now, 'next_check_at' => $now + 86400]);
            }
        }
        // lapsed assets keep being tried hourly, so a fixed record brings them back
        foreach (Db::rows(Db::table('mod_mcsec_assets')->where('status', 'lapsed')->where('next_check_at', '<=', $now)->limit(10)) as $a) {
            if (microtime(true) > $deadline) {
                break;
            }
            if (!self::check($a)['ok']) {
                Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['next_check_at' => $now + 3600]);
            }
        }
        return $out;
    }
}
