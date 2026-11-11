<?php

declare(strict_types=1);

namespace McSec;

/**
 * The security score (0–100) with a word, never a letter grade alone: penalties per open finding, with caps so a
 * single critical issue can never hide behind many clean checks (one open critical → at most 49, a high → at most 79;
 * the SSL Labs way). The account score is the mean of its scanned assets, under the same caps.
 */
final class Score
{
    private const PENALTY = ['critical' => 25, 'high' => 10, 'medium' => 4, 'low' => 1, 'info' => 0];

    public static function fromCounts(array $c): int
    {
        $p = 0;
        foreach (self::PENALTY as $sev => $w) {
            $n = (int) ($c[$sev] ?? 0);
            // diminishing: the 10th low finding matters less than the first
            $p += $w * ($n <= 3 ? $n : 3 + sqrt($n - 3));
        }
        $s = (int) max(0, round(100 - $p));
        if ((int) ($c['critical'] ?? 0) > 0) {
            $s = min($s, 49);
        } elseif ((int) ($c['high'] ?? 0) > 0) {
            $s = min($s, 79);
        }
        return $s;
    }

    /** @return array{score:int,label:string,tone:string,scanned:int} score -1 = nothing scanned yet */
    public static function forClient(int $clientId): array
    {
        $scores = [];
        $crit = false;
        $high = false;
        foreach (Assets::forClient($clientId) as $a) {
            if ((int) $a->last_scan_at === 0 || (int) $a->score < 0) {
                continue;
            }
            $scores[] = (int) $a->score;
            $c = Assets::counts($a);
            $crit = $crit || $c['critical'] > 0;
            $high = $high || $c['high'] > 0;
        }
        if (!$scores) {
            return ['score' => -1, 'label' => 'هنوز اسکنی نشده', 'tone' => 'none', 'scanned' => 0];
        }
        $s = (int) round(array_sum($scores) / count($scores));
        $s = $crit ? min($s, 49) : ($high ? min($s, 79) : $s);
        return ['score' => $s, 'label' => self::label($s), 'tone' => self::tone($s), 'scanned' => count($scores)];
    }

    public static function label(int $s): string
    {
        return match (true) {
            $s < 0 => 'بی‌اسکن',
            $s >= 90 => 'عالی',
            $s >= 75 => 'خوب',
            $s >= 50 => 'نیاز به توجه',
            $s >= 25 => 'پرخطر',
            default => 'بحرانی',
        };
    }

    public static function tone(int $s): string
    {
        return match (true) {
            $s < 0 => 'none',
            $s >= 90 => 'ok',
            $s >= 75 => 'good',
            $s >= 50 => 'warn',
            default => 'err',
        };
    }

    /** Daily snapshot per account for the trend chart (the worker, once a day). */
    public static function snapshot(): int
    {
        $day = Clock::today();
        $n = 0;
        $ids = Db::table('mod_mcsec_assets')->where('status', 'verified')->where('last_scan_at', '>', 0)->distinct()->pluck('client_id');
        foreach (is_array($ids) ? $ids : $ids->all() as $cid) {
            $s = self::forClient((int) $cid);
            if ($s['score'] < 0 || Db::table('mod_mcsec_snapshots')->where('client_id', $cid)->where('day', $day)->exists()) {
                continue;
            }
            Db::table('mod_mcsec_snapshots')->insert(['client_id' => (int) $cid, 'day' => $day, 'score' => $s['score'], 'counts' => Db::json(Findings::openCounts((int) $cid))]);
            $n++;
        }
        return $n;
    }

    /** @return array<int,array{day:string,score:int}> last $days snapshots, oldest first */
    public static function trend(int $clientId, int $days = 90): array
    {
        $since = Clock::today(-$days);
        $rows = Db::rows(Db::table('mod_mcsec_snapshots')->where('client_id', $clientId)->where('day', '>=', $since)->orderBy('day'));
        return array_map(fn ($r) => ['day' => (string) $r->day, 'score' => (int) $r->score], $rows);
    }
}
