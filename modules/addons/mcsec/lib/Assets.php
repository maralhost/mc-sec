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
    public static function add(array $who, string $input, string $label = '', string $autoscan = ''): array
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
        $block = Net::blocked($kind, $value);
        if ($block !== '') {
            return ['ok' => false, 'error' => 'این دارایی در فهرست ممنوع است و اسکن نمی‌شود (' . $block . ').', 'value' => $value];
        }
        if ($kind !== 'domain' && !Settings::bool('allow_private_ips')) {
            $ip = $kind === 'cidr' ? explode('/', $value)[0] : $value;
            if (!Net::isPublicIp($ip)) {
                return ['ok' => false, 'error' => 'IP خصوصی یا رزروشده پذیرفته نمی‌شود؛ فقط IP عمومی.', 'value' => $value];
            }
        }
        if (Db::table('mod_mcsec_assets')->where('client_id', $clientId)->where('value', $value)->where('status', '!=', 'removed')->exists()) {
            return ['ok' => false, 'error' => 'این دارایی از قبل در فهرست شماست.', 'value' => $value];
        }
        $lim = Plans::limits($clientId);
        if (self::count($clientId) >= $lim['max_assets']) {
            return ['ok' => false, 'error' => 'به سقف ' . Text::fa($lim['max_assets']) . ' دارایی رسیده‌اید. دارایی بی‌استفاده را حذف کنید یا پلن بالاتری بگیرید.', 'value' => $value];
        }
        $id = Db::table('mod_mcsec_assets')->insertGetId([
            'client_id' => $clientId, 'kind' => $kind, 'value' => $value, 'label' => Text::name($label, 120), 'status' => 'pending',
            'next_check_at' => Clock::now() + 120, 'created_by' => $who['user_id'], 'created_at' => Clock::now(),
            'autoscan' => in_array($kind, Catalog::get($autoscan)['kinds'] ?? [], true) ? $autoscan : '',
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
        $items = preg_split('~[\s,;،]+~u', Text::toAscii($text)) ?: [];
        $items = array_values(array_unique(array_filter(array_map('trim', $items), 'strlen')));
        $out = ['added' => [], 'failed' => [], 'verified' => 0];
        foreach (array_slice($items, 0, self::BULK_MAX) as $item) {
            $r = self::add($who, $item, '', $autoscan);
            if ($r['ok']) {
                $out['added'][] = $r['value'];
                $out['verified'] += $r['verified'] ? 1 : 0;
            } else {
                $out['failed'][] = ($r['value'] ?? $item) . ': ' . $r['error'];
            }
        }
        if (count($items) > self::BULK_MAX) {
            $out['failed'][] = 'فقط ' . Text::fa(self::BULK_MAX) . ' مورد اول افزوده شد؛ بقیه را در نوبت بعد بفرستید.';
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
            Db::table('mod_mcsec_schedules')->where('client_id', $a->client_id)->where('asset_id', $a->id)->delete();
            Db::table('mod_mcsec_scans')->where('asset_id', $a->id)->where('status', 'queued')->update(['status' => 'cancelled', 'finished_at' => Clock::now(), 'error' => 'دارایی حذف شد']);
        });
        foreach (Db::rows(Db::table('mod_mcsec_scans')->where('asset_id', $a->id)->where('status', 'queued')->where('credits', '>', 0)) as $s) {
            Credits::refund((int) $a->client_id, 'scan:' . $s->id, 'لغو اسکن (حذف دارایی)', (int) $s->id);
        }
        Audit::log((int) $a->client_id, 'asset_remove', (string) $a->value, [], $who['user_id']);
        return ['ok' => true];
    }

    public static function setLabel(array $who, int $id, string $label, string $tags): array
    {
        $a = self::get($who['client_id'], $id);
        if (!$a) {
            return ['ok' => false, 'error' => 'این دارایی پیدا نشد.'];
        }
        $tagList = array_slice(array_values(array_unique(array_filter(array_map(fn ($t) => Text::name($t, 24), preg_split('~[,،]~u', $tags) ?: [])))), 0, 8);
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
