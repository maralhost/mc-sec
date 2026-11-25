<?php

declare(strict_types=1);

namespace McSec;

/**
 * The discovered attack surface of an asset: hosts (subdomains, IPs), open ports and services, technologies,
 * TLS certificates and URLs. Each item remembers when it was first and last seen, so a scan can say what is new
 * ("a new port 3306 is open") and what went away. Engines hand ['kind','value','meta'] items to ingest().
 */
final class Surface
{
    public const KINDS = ['host' => 'میزبان', 'port' => 'درگاه و سرویس', 'tech' => 'فناوری', 'cert' => 'گواهی', 'url' => 'نشانی', 'dns' => 'رکورد DNS', 'ip' => 'نشانی IP'];

    /** Ports whose sudden appearance deserves an alert on its own. */
    public const RISKY_PORTS = [21, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017];

    /**
     * @param string[] $kinds the kinds this scan fully covers (items of these kinds it did not see are marked gone)
     * @return array{new:array,gone:int,seen:int}
     */
    public static function ingest(object $scan, object $asset, array $items, array $kinds): array
    {
        $now = Clock::now();
        $out = ['new' => [], 'gone' => 0, 'seen' => 0];
        $seen = [];
        foreach ($items as $it) {
            $kind = (string) ($it['kind'] ?? '');
            $value = mb_substr(trim((string) ($it['value'] ?? '')), 0, 255);
            if (!isset(self::KINDS[$kind]) || $value === '' || isset($seen[$kind . '|' . $value])) {
                continue;
            }
            $seen[$kind . '|' . $value] = true;
            $out['seen']++;
            $meta = Db::json(array_slice((array) ($it['meta'] ?? []), 0, 20));
            $old = Db::table('mod_mcsec_surface')->where('asset_id', $asset->id)->where('kind', $kind)->where('value', $value)->first();
            if ($old) {
                Db::table('mod_mcsec_surface')->where('id', $old->id)->update(['meta' => $meta, 'last_seen_at' => $now, 'gone_at' => 0]);
                continue;
            }
            Db::table('mod_mcsec_surface')->insert(['client_id' => (int) $asset->client_id, 'asset_id' => (int) $asset->id, 'kind' => $kind, 'value' => $value,
                'meta' => $meta, 'first_scan_id' => (int) $scan->id, 'first_seen_at' => $now, 'last_seen_at' => $now]);
            // the very first scan of an asset is the baseline, not "new"
            if (Db::table('mod_mcsec_scans')->where('asset_id', $asset->id)->where('status', 'completed')->where('id', '<', $scan->id)->exists()) {
                $out['new'][] = ['kind' => $kind, 'value' => $value];
            }
        }
        if ($kinds) {
            $out['gone'] = Db::table('mod_mcsec_surface')->where('asset_id', $asset->id)->whereIn('kind', $kinds)->where('gone_at', 0)
                ->where('last_seen_at', '<', $now)->update(['gone_at' => $now]);
        }
        return $out;
    }

    public const MUTE_NOTE = 'میزبان کنار گذاشته شد (مال این حساب نیست)';

    /** Hosts of an asset the customer set aside, lowercased. @return string[] */
    public static function muted(int $assetId): array
    {
        $v = Db::table('mod_mcsec_surface')->where('asset_id', $assetId)->where('kind', 'host')->where('muted', '>', 0)->pluck('value');
        return array_map(fn ($x) => strtolower((string) $x), is_array($v) ? $v : $v->all());
    }

    /**
     * Sets a discovered host aside, or brings it back (switch host_mute). The host is switched off in OASM so it is
     * no longer scanned (this is the explicit POST that may call the engine); here its findings stop being recorded
     * and its open ones are marked «ریسک پذیرفته» with a fixed note. The asset's own name cannot be set aside.
     * @return array{ok:bool,error?:string,engine?:bool}
     */
    public static function mute(array $who, int $id, bool $on): array
    {
        $cid = (int) $who['client_id'];
        $row = $id > 0 ? Db::table('mod_mcsec_surface')->where('id', $id)->where('client_id', $cid)->where('kind', 'host')->first() : null;
        $asset = $row ? Assets::get($cid, (int) $row->asset_id) : null;
        if (!Settings::bool('host_mute') || !$row || !$asset) {
            return ['ok' => false, 'error' => 'این میزبان پیدا نشد.'];
        }
        $host = strtolower((string) $row->value);
        if ($host === strtolower((string) $asset->value)) {
            return ['ok' => false, 'error' => 'این خود دارایی است. اگر نمی‌خواهید بررسی شود، دارایی را حذف کنید.'];
        }
        $engine = true;
        if ((string) $asset->oasm_target !== '') {
            try {
                $engine = (new Engines\Oasm())->toggleHost($asset, $host, !$on);
            } catch (\Throwable $e) {
                Trace::warn('engine', 'oasm.toggle', $e->getMessage(), ['asset' => (int) $asset->id], ['client_id' => $cid]);
                $engine = false;
            }
        }
        Db::table('mod_mcsec_surface')->where('id', (int) $row->id)->update(['muted' => $on ? ($engine ? 1 : 2) : 0]);
        $q = Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('asset_id', (int) $asset->id)->where('status', $on ? 'open' : 'accepted');
        if (!$on) {
            $q->where('status_note', self::MUTE_NOTE);
        }
        foreach (Db::rows($q->select(['id', 'location'])->limit(2000)) as $f) {
            if (Findings::hostOf((string) $f->location) === $host) {
                Db::table('mod_mcsec_findings')->where('id', (int) $f->id)->where('client_id', $cid)->update($on
                    ? ['status' => 'accepted', 'status_note' => self::MUTE_NOTE, 'status_by' => (int) $who['user_id'], 'status_at' => Clock::now()]
                    : ['status' => 'open', 'status_note' => '', 'status_by' => (int) $who['user_id'], 'status_at' => Clock::now()]);
            }
        }
        Assets::refreshStats((int) $asset->id);
        Audit::log($cid, 'host_mute', $host, ['on' => $on, 'asset' => (int) $asset->id, 'engine' => $engine], (int) $who['user_id']);
        return ['ok' => true, 'engine' => $engine];
    }

    /** @return array<string,object[]> current (not gone) items of an asset by kind */
    public static function forAsset(int $assetId, int $limit = 500): array
    {
        $out = [];
        foreach (Db::rows(Db::table('mod_mcsec_surface')->where('asset_id', $assetId)->where('gone_at', 0)->orderBy('kind')->orderBy('value')->limit($limit)) as $r) {
            $out[(string) $r->kind][] = $r;
        }
        return $out;
    }

    /** @return array<string,int> */
    public static function counts(int $clientId): array
    {
        $c = array_fill_keys(array_keys(self::KINDS), 0);
        foreach (Db::rows(Db::table('mod_mcsec_surface')->where('client_id', $clientId)->where('gone_at', 0)->selectRaw('kind, COUNT(*) AS n')->groupBy('kind')) as $r) {
            $c[(string) $r->kind] = (int) $r->n;
        }
        return $c;
    }

    public static function meta(object $r): array
    {
        $m = json_decode((string) $r->meta, true);
        return is_array($m) ? $m : [];
    }

    /** New items worth an alert by themselves: risky ports and new hosts. */
    public static function alarming(array $new): array
    {
        return array_values(array_filter($new, function ($n) {
            if ($n['kind'] === 'host') {
                return true;
            }
            if ($n['kind'] === 'port') {
                $port = (int) preg_replace('~^.*:~', '', (string) $n['value']);
                return in_array($port, self::RISKY_PORTS, true);
            }
            return false;
        }));
    }
}
