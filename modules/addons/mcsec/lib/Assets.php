<?php

declare(strict_types=1);

namespace McSec;

/**
 * A customer's assets: domains (a verified domain covers its subdomains), single IPs and small IPv4 ranges.
 * Every id that comes from the browser is checked against the session's client (get()). Nothing is scanned until
 * the asset is verified (Verify). Removing is soft (status removed) so findings and reports keep their history.
 */
final class Assets
{
    public const STATUS = ['pending' => 'در انتظار تأیید', 'verified' => 'تأییدشده', 'lapsed' => 'تأیید منقضی', 'blocked' => 'مسدود', 'removed' => 'حذف‌شده'];
    public const KINDS = ['domain' => 'دامنه', 'ip' => 'IP', 'cidr' => 'بازه‌ی IP'];
    public const BULK_MAX = 100;

    public static function get(int $clientId, int $id): ?object
    {
        if ($id <= 0) {
            return null;
        }
        return Db::table('mod_mcsec_assets')->where('id', $id)->where('client_id', $clientId)->where('status', '!=', 'removed')->first();
    }

    /** @return object[] */
    public static function forClient(int $clientId, string $status = ''): array
    {
        $q = Db::table('mod_mcsec_assets')->where('client_id', $clientId)->where('status', '!=', 'removed');
        if ($status !== '') {
            $q->where('status', $status);
        }
        $rows = Db::rows($q->orderBy('value'));
        // group a domain's subdomains right after it
        usort($rows, fn ($a, $b) => [self::sortKey($a), $a->id] <=> [self::sortKey($b), $b->id]);
        return $rows;
    }

    private static function sortKey(object $a): string
    {
        if ($a->kind !== 'domain') {
            return 'zz|' . $a->value;
        }
        $apex = Net::apex((string) $a->value);
        return $apex . '|' . ($a->value === $apex ? '' : (string) $a->value);
    }

    public static function count(int $clientId): int
    {
        return Db::table('mod_mcsec_assets')->where('client_id', $clientId)->whereIn('status', ['pending', 'verified', 'lapsed'])->count();
    }

    /**
     * Adds one asset. @return array{ok:bool,error?:string,id?:int,verified?:bool,value?:string}
     */
    public static function add(array $who, string $input, string $label = '', string $autoscan = '', bool $screen = true): array
    {
        $clientId = $who['client_id'];
        if ($autoscan !== '' && !(Catalog::forClient($clientId)[$autoscan]['allowed'] ?? false)) {
            $autoscan = '';
        }
        $t = Net::parse($input);
        if (isset($t['error'])) {
            return ['ok' => false, 'error' => $t['error'], 'value' => trim($input)];
        }
        [$kind, $value] = [$t['kind'], $t['value']];
        // a single domain is looked up now (its IPs against the blocklist, the CDN in front); a bulk list later
        $sc = $kind === 'domain' && $screen ? Net::screen($kind, $value) : ['ips' => null, 'blocked' => Net::blocked($kind, $value), 'cdn' => $kind === 'domain' ? '' : Net::cdnOf($kind, $value)];
        if ($sc['blocked'] !== '') {
            return ['ok' => false, 'error' => Lang::t('این دارایی در فهرست ممنوع است و اسکن نمی‌شود ({why}).', ['why' => $sc['blocked']]), 'value' => $value];
        }
        if ($kind !== 'domain' && !Settings::bool('allow_private_ips')) {
            $ip = $kind === 'cidr' ? explode('/', $value)[0] : $value;
            if (!Net::isPublicIp($ip)) {
                return ['ok' => false, 'error' => 'IP خصوصی یا رزروشده پذیرفته نمی‌شود؛ فقط IP عمومی.', 'value' => $value];
            }
        }
        if ($kind !== 'domain' && $sc['cdn'] !== '') {
            return ['ok' => false, 'error' => Lang::t('این IP از سرورهای CDN ({cdn}) است، نه سرور شما، و اسکن نمی‌شود. خود دامنه را بیفزایید؛ برای اسکن سرور، IP اصلی سرورتان را وارد کنید.', ['cdn' => Net::cdnLabel($sc['cdn'])]), 'value' => $value];
        }
        if (Db::table('mod_mcsec_assets')->where('client_id', $clientId)->where('value', $value)->where('status', '!=', 'removed')->exists()) {
            return ['ok' => false, 'error' => 'این دارایی از قبل در فهرست شماست.', 'value' => $value];
        }
        $lim = Plans::limits($clientId);
        if (self::count($clientId) >= $lim['max_assets']) {
            return ['ok' => false, 'error' => Lang::t('به سقف {n} دارایی رسیده‌اید. دارایی بی‌استفاده را حذف کنید یا پلن بالاتری بگیرید.', ['n' => Text::fa($lim['max_assets'])]), 'value' => $value];
        }
        $id = Db::table('mod_mcsec_assets')->insertGetId([
            'client_id' => $clientId, 'kind' => $kind, 'value' => $value, 'label' => Text::name($label, 120), 'status' => 'pending',
            'next_check_at' => Clock::now() + 120, 'created_by' => $who['user_id'], 'created_at' => Clock::now(),
            'autoscan' => in_array($kind, Catalog::get($autoscan)['kinds'] ?? [], true) ? $autoscan : '',
            'cdn' => mb_substr($sc['cdn'], 0, 40), 'cdn_checked_at' => $kind === 'domain' && $screen ? Clock::now() : 0,
        ]);
        Audit::log($clientId, 'asset_add', $value, [], $who['user_id']);
        $asset = Db::table('mod_mcsec_assets')->where('id', $id)->first();
        $verified = Verify::instant($asset);
        return ['ok' => true, 'id' => $id, 'verified' => $verified, 'value' => $value];
    }

    /**
     * Many at once (one per line, or separated by comma/space). Stops at BULK_MAX lines.
     * @return array{added:array,failed:array,verified:int}
     */
    public static function bulk(array $who, string $text, string $autoscan = ''): array
    {
        $items = preg_split('~[\s,;،]+~u', Text::toAscii($text)) ?: []; // i18n-skip
        $items = array_values(array_unique(array_filter(array_map('trim', $items), 'strlen')));
        $out = ['added' => [], 'failed' => [], 'verified' => 0];
        foreach (array_slice($items, 0, self::BULK_MAX) as $item) {
            $r = self::add($who, $item, '', $autoscan, false); // no DNS for a hundred lines in one request: the worker notes CDNs
            if ($r['ok']) {
                $out['added'][] = $r['value'];
                $out['verified'] += $r['verified'] ? 1 : 0;
            } else {
                $out['failed'][] = ($r['value'] ?? $item) . ': ' . Lang::t((string) $r['error']);
            }
        }
        if (count($items) > self::BULK_MAX) {
            $out['failed'][] = Lang::t('فقط {n} مورد اول افزوده شد؛ بقیه را در نوبت بعد بفرستید.', ['n' => Text::fa(self::BULK_MAX)]);
        }
        return $out;
    }

    public static function remove(array $who, int $id): array
    {
        $a = self::get($who['client_id'], $id);
        if (!$a) {
            return ['ok' => false, 'error' => 'این دارایی پیدا نشد.'];
        }
        Db::tx(function () use ($a) {
            Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['status' => 'removed', 'removed_at' => Clock::now()]);
            Shots::forget((int) $a->id);
            Db::table('mod_mcsec_schedules')->where('client_id', $a->client_id)->where('asset_id', $a->id)->delete();
            Db::table('mod_mcsec_scans')->where('asset_id', $a->id)->where('status', 'queued')->update(['status' => 'cancelled', 'finished_at' => Clock::now(), 'error' => 'دارایی حذف شد']);
        });
        foreach (Db::rows(Db::table('mod_mcsec_scans')->where('asset_id', $a->id)->where('status', 'queued')->where('credits', '>', 0)) as $s) {
            Credits::refund((int) $a->client_id, 'scan:' . $s->id, 'لغو اسکن (حذف دارایی)', (int) $s->id);
        }
        // a removed server is no longer the origin of a CDN domain
        Db::table('mod_mcsec_assets')->where('client_id', $a->client_id)->where('origin_id', $a->id)->update(['origin_id' => 0]);
        Audit::log((int) $a->client_id, 'asset_remove', (string) $a->value, [], $who['user_id']);
        return ['ok' => true];
    }

    /** The IP asset of the real server behind a CDN domain (pending or verified; null = none). */
    public static function origin(object $asset): ?object
    {
        if ((int) ($asset->origin_id ?? 0) <= 0) {
            return null;
        }
        return Db::table('mod_mcsec_assets')->where('id', (int) $asset->origin_id)->where('client_id', (int) $asset->client_id)->where('kind', 'ip')
            ->where('status', '!=', 'removed')->first();
    }

    /**
     * The customer names the real server behind a CDN domain ('' unlinks it). The IP is (or becomes) an IP asset with
     * its own ownership proof; once verified, the scans that probe ports run on it instead of the CDN's servers.
     * @return array{ok:bool,error?:string,id?:int,verified?:bool,value?:string,unlinked?:bool}
     */
    public static function setOrigin(array $who, int $id, string $input, bool $skipTls = false): array
    {
        $a = self::get($who['client_id'], $id);
        if (!$a || $a->kind !== 'domain') {
            return ['ok' => false, 'error' => 'این دامنه پیدا نشد.'];
        }
        if (!Settings::bool('cdn_origin_scan')) {
            return ['ok' => false, 'error' => 'اسکن سرور اصلی دامنه‌های پشت CDN فعلاً فعال نیست.'];
        }
        if (trim($input) === '') {
            Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['origin_id' => 0, 'origin_ok_at' => 0, 'origin_tls_skip' => 0, 'origin_note' => '']);
            Audit::log((int) $a->client_id, 'origin_unlink', (string) $a->value, [], $who['user_id']);
            return ['ok' => true, 'unlinked' => true];
        }
        $t = Net::parse($input);
        if (isset($t['error']) || $t['kind'] !== 'ip') {
            return ['ok' => false, 'error' => 'IP اصلی سرور را مثل 203.0.113.10 بنویسید: یک IP، نه دامنه یا بازه.'];
        }
        $ip = Db::table('mod_mcsec_assets')->where('client_id', $a->client_id)->where('kind', 'ip')->where('value', $t['value'])->where('status', '!=', 'removed')->first();
        if ($ip) {
            if (Net::cdnOf('ip', (string) $ip->value) !== '') {
                return ['ok' => false, 'error' => 'این IP از سرورهای CDN است، نه سرور شما.'];
            }
            [$ipId, $verified] = [(int) $ip->id, $ip->status === 'verified'];
        } else {
            $r = self::add($who, $t['value'], Lang::t('سرور اصلی {domain}', ['domain' => (string) $a->value]));
            if (!$r['ok']) {
                return $r;
            }
            [$ipId, $verified] = [(int) $r['id'], (bool) $r['verified']];
        }
        Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['origin_id' => $ipId, 'origin_tls_skip' => $skipTls ? 1 : 0, 'origin_ok_at' => 0, 'origin_note' => '']);
        Audit::log((int) $a->client_id, 'origin_set', $a->value . ' → ' . $t['value'], ['tls_skip' => $skipTls], $who['user_id']);
        // is the site really on that server? asked of the server itself, now, in this POST
        $test = self::testOrigin(self::get((int) $a->client_id, (int) $a->id));
        return ['ok' => true, 'id' => $ipId, 'verified' => $verified, 'value' => $t['value'], 'direct' => $test['ok'], 'note' => $test['note']];
    }

    /**
     * Asks the origin server whether it serves this site (Verify::onServer) and keeps the answer on the domain.
     * Network: only from an explicit POST or the worker. @return array{ok:bool,note:string}
     */
    public static function testOrigin(?object $a, ?bool $skipTls = null): array
    {
        $origin = $a ? self::origin($a) : null;
        if (!$a || $a->kind !== 'domain' || !$origin || !Settings::bool('cdn_origin_scan')) {
            return ['ok' => false, 'note' => Lang::t('برای این دامنه سرور اصلی ثبت نشده است.')];
        }
        if ($a->status !== 'verified') {
            return ['ok' => false, 'note' => Lang::t('اول مالکیت خود دامنه را تأیید کنید.')];
        }
        $skip = $skipTls ?? ((int) ($a->origin_tls_skip ?? 0) === 1);
        $acc = Accounts::ensure((int) $a->client_id);
        $r = Verify::onServer((string) $a->value, (string) $origin->value, $skip, Accounts::proof($acc), (string) $acc->verify_token);
        Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['origin_ok_at' => $r['ok'] ? Clock::now() : 0, 'origin_tls_skip' => $skip ? 1 : 0, 'origin_note' => mb_substr($r['note'], 0, 255)]);
        return ['ok' => $r['ok'], 'note' => $r['note']];
    }

    /**
     * The direct route of a domain: its origin server's IP, when the site was shown to be on it, and whether that
     * server's certificate is ignored. null when there is none (requests then go the public way, through the CDN).
     * $recheck (the worker, right before using it): the test is run again, so a server that changed hands is dropped.
     * @return array{ip:string,tls_skip:bool}|null
     */
    public static function direct(object $a, bool $recheck = false): ?array
    {
        if ($a->kind !== 'domain' || (int) ($a->origin_ok_at ?? 0) <= 0 || !Settings::bool('cdn_origin_scan')) {
            return null;
        }
        $origin = self::origin($a);
        if (!$origin) {
            return null;
        }
        if ($recheck && !self::testOrigin($a)['ok']) {
            return null;
        }
        return ['ip' => (string) $origin->value, 'tls_skip' => (int) ($a->origin_tls_skip ?? 0) === 1];
    }

    public static function noteCdn(object $asset, string $cdn): void
    {
        Db::table('mod_mcsec_assets')->where('id', $asset->id)->update(['cdn' => mb_substr($cdn, 0, 40), 'cdn_checked_at' => Clock::now()]);
    }

    /** Worker: notes which domains sit behind a CDN (at most a day old), so pages can say so without a lookup. */
    public static function detectCdn(float $deadline, int $max = 50): int
    {
        $n = 0;
        $rows = Db::rows(Db::table('mod_mcsec_assets')->where('kind', 'domain')->whereIn('status', ['pending', 'verified', 'lapsed'])
            ->where('cdn_checked_at', '<', Clock::now() - 86400)->orderBy('cdn_checked_at')->limit($max));
        foreach ($rows as $a) {
            if (microtime(true) > $deadline) {
                break;
            }
            self::noteCdn($a, Net::cdnOf('domain', (string) $a->value));
            $n++;
        }
        return $n;
    }

    public static function setLabel(array $who, int $id, string $label, string $tags): array
    {
        $a = self::get($who['client_id'], $id);
        if (!$a) {
            return ['ok' => false, 'error' => 'این دارایی پیدا نشد.'];
        }
        $tagList = array_slice(array_values(array_unique(array_filter(array_map(fn ($t) => Text::name($t, 24), preg_split('~[,،]~u', $tags) ?: [])))), 0, 8); // i18n-skip
        Db::table('mod_mcsec_assets')->where('id', $a->id)->update(['label' => Text::name($label, 120), 'tags' => implode(',', $tagList)]);
        return ['ok' => true];
    }

    /** Open findings per severity and the score of one asset, cached on the row (after each scan and status change). */
    public static function refreshStats(int $assetId): void
    {
        $counts = Findings::openCounts(0, $assetId);
        Db::table('mod_mcsec_assets')->where('id', $assetId)->update(['counts' => Db::json($counts), 'score' => Score::fromCounts($counts)]);
    }

    public static function counts(object $a): array
    {
        $c = json_decode((string) $a->counts, true);
        return is_array($c) ? $c + Findings::emptyCounts() : Findings::emptyCounts();
    }

    /** The display name of an asset: its label, else its value. */
    public static function name(object $a): string
    {
        return trim((string) $a->label) !== '' ? (string) $a->label : (string) $a->value;
    }
}
