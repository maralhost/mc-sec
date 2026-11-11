<?php

declare(strict_types=1);

namespace McSec;

/**
 * Periodic scans: daily, weekly (a weekday) or monthly (a day of the Jalali month), at an hour in Tehran time.
 * One schedule covers one asset or every verified asset of the account (asset_id 0, so new assets join by
 * themselves). The worker queues due runs through Scans::queue (credits are taken then); without credits the
 * schedule pauses and the customer is told; a lapsed verification pauses it too. The plan sets the shortest interval.
 */
final class Schedules
{
    public const FREQ = ['daily' => ['label' => 'روزانه', 'hours' => 24], 'weekly' => ['label' => 'هفتگی', 'hours' => 168], 'monthly' => ['label' => 'ماهانه', 'hours' => 720]];
    public const DOW = [6 => 'شنبه', 0 => 'یکشنبه', 1 => 'دوشنبه', 2 => 'سه‌شنبه', 3 => 'چهارشنبه', 4 => 'پنجشنبه', 5 => 'جمعه'];
    public const PAUSE = ['credits' => 'اعتبار کافی نبود', 'verify' => 'تأیید مالکیت منقضی شد', 'plan' => 'نوع اسکن در پلن نیست', 'user' => 'متوقف‌شده به دست شما', 'asset' => 'دارایی در دسترس نیست'];
    public const MAX_PER_CLIENT = 20;

    public static function get(int $clientId, int $id): ?object
    {
        return $id > 0 ? Db::table('mod_mcsec_schedules')->where('id', $id)->where('client_id', $clientId)->first() : null;
    }

    /** @return object[] */
    public static function forClient(int $clientId): array
    {
        return Db::rows(Db::table('mod_mcsec_schedules')->where('client_id', $clientId)->orderBy('next_run_at'));
    }

    /**
     * Creates or updates one schedule. $d: id, asset (0 = all), profile, freq, dow, dom, hour.
     * @return array{ok:bool,error?:string,id?:int}
     */
    public static function save(array $who, array $d): array
    {
        $clientId = $who['client_id'];
        $freq = (string) ($d['freq'] ?? '');
        if (!isset(self::FREQ[$freq])) {
            return ['ok' => false, 'error' => 'تکرار را انتخاب کنید.'];
        }
        $profileKey = (string) ($d['profile'] ?? '');
        $p = Catalog::forClient($clientId)[$profileKey] ?? null;
        if (!$p || !$p['allowed']) {
            return ['ok' => false, 'error' => 'این نوع اسکن برای زمان‌بندی در پلن شما نیست.'];
        }
        $lim = Plans::limits($clientId);
        if (self::FREQ[$freq]['hours'] < $lim['min_interval_h']) {
            $allowed = array_keys(array_filter(self::FREQ, fn ($f) => $f['hours'] >= $lim['min_interval_h']));
            return ['ok' => false, 'error' => 'در پلن فعلی کوتاه‌ترین فاصله‌ی اسکن ' . implode(' یا ', array_map(fn ($k) => self::FREQ[$k]['label'], $allowed)) . ' است.'];
        }
        $assetId = (int) ($d['asset'] ?? 0);
        if ($assetId > 0) {
            $a = Assets::get($clientId, $assetId);
            if (!$a) {
                return ['ok' => false, 'error' => 'این دارایی پیدا نشد.'];
            }
            if (!in_array($a->kind, $p['kinds'], true)) {
                return ['ok' => false, 'error' => '«' . $p['label'] . '» برای این نوع دارایی اجرا نمی‌شود.'];
            }
        }
        $row = [
            'asset_id' => $assetId, 'profile' => $profileKey, 'freq' => $freq,
            'dow' => max(0, min(6, (int) ($d['dow'] ?? 6))), 'dom' => max(1, min(28, (int) ($d['dom'] ?? 1))), 'hour' => max(0, min(23, (int) ($d['hour'] ?? 3))),
        ];
        $id = (int) ($d['id'] ?? 0);
        if ($id > 0) {
            $old = self::get($clientId, $id);
            if (!$old) {
                return ['ok' => false, 'error' => 'این زمان‌بندی پیدا نشد.'];
            }
            $row['next_run_at'] = self::nextRun($row + ['id' => $id], Clock::now());
            Db::table('mod_mcsec_schedules')->where('id', $id)->update($row);
        } else {
            if (Db::table('mod_mcsec_schedules')->where('client_id', $clientId)->count() >= self::MAX_PER_CLIENT) {
                return ['ok' => false, 'error' => 'حداکثر ' . Text::fa(self::MAX_PER_CLIENT) . ' زمان‌بندی دارید.'];
            }
            $dup = Db::table('mod_mcsec_schedules')->where('client_id', $clientId)->where('asset_id', $assetId)->where('profile', $profileKey)->exists();
            if ($dup) {
                return ['ok' => false, 'error' => 'برای همین دارایی و همین نوع اسکن از قبل زمان‌بندی دارید؛ همان را ویرایش کنید.'];
            }
            $id = Db::table('mod_mcsec_schedules')->insertGetId($row + ['client_id' => $clientId, 'status' => 'active', 'created_by' => $who['user_id'], 'created_at' => Clock::now(), 'next_run_at' => 0]);
            Db::table('mod_mcsec_schedules')->where('id', $id)->update(['next_run_at' => self::nextRun($row + ['id' => $id], Clock::now())]);
        }
        Audit::log($clientId, 'schedule_save', $profileKey . ' ' . $freq, ['id' => $id, 'asset' => $assetId], $who['user_id']);
        return ['ok' => true, 'id' => $id];
    }

    public static function setActive(array $who, int $id, bool $active): array
    {
        $s = self::get($who['client_id'], $id);
        if (!$s) {
            return ['ok' => false, 'error' => 'این زمان‌بندی پیدا نشد.'];
        }
        Db::table('mod_mcsec_schedules')->where('id', $id)->update($active
            ? ['status' => 'active', 'pause_reason' => '', 'next_run_at' => self::nextRun((array) $s, Clock::now())]
            : ['status' => 'paused', 'pause_reason' => 'user']);
        return ['ok' => true];
    }

    public static function delete(array $who, int $id): array
    {
        $s = self::get($who['client_id'], $id);
        if (!$s) {
            return ['ok' => false, 'error' => 'این زمان‌بندی پیدا نشد.'];
        }
        Db::table('mod_mcsec_schedules')->where('id', $id)->where('client_id', $who['client_id'])->delete();
        Audit::log($who['client_id'], 'schedule_delete', (string) $s->profile, ['id' => $id], $who['user_id']);
        return ['ok' => true];
    }

    /** The next run after $after (epoch), in Tehran time; minutes spread by id so runs do not all start at :00. */
    public static function nextRun(array $s, int $after): int
    {
        $tz = new \DateTimeZone('Asia/Tehran');
        $hour = (int) ($s['hour'] ?? 3);
        $minute = ((int) ($s['id'] ?? 0) * 7) % 50;
        $now = (new \DateTimeImmutable('@' . $after))->setTimezone($tz);
        switch ($s['freq'] ?? 'weekly') {
            case 'daily':
                $c = $now->setTime($hour, $minute);
                if ($c->getTimestamp() <= $after) {
                    $c = $c->modify('+1 day');
                }
                return $c->getTimestamp();
            case 'monthly':
                [$jy, $jm] = Text::jalali((int) $now->format('Y'), (int) $now->format('n'), (int) $now->format('j'));
                $dom = max(1, min(28, (int) ($s['dom'] ?? 1)));
                for ($i = 0; $i < 3; $i++) {
                    [$gy, $gm, $gd] = self::toGregorian($jy, $jm, $dom);
                    $c = (new \DateTimeImmutable('now', $tz))->setDate($gy, $gm, $gd)->setTime($hour, $minute);
                    if ($c->getTimestamp() > $after) {
                        return $c->getTimestamp();
                    }
                    $jm++;
                    if ($jm > 12) {
                        $jm = 1;
                        $jy++;
                    }
                }
                return $after + 30 * 86400;
            default: // weekly
                $dow = max(0, min(6, (int) ($s['dow'] ?? 6)));
                $c = $now->setTime($hour, $minute);
                $diff = ($dow - (int) $c->format('w') + 7) % 7;
                $c = $c->modify('+' . $diff . ' day');
                if ($c->getTimestamp() <= $after) {
                    $c = $c->modify('+7 day');
                }
                return $c->getTimestamp();
        }
    }

    /** Jalali → Gregorian. @return array{0:int,1:int,2:int} */
    public static function toGregorian(int $jy, int $jm, int $jd): array
    {
        $jy += 1595;
        $days = -355668 + (365 * $jy) + (intdiv($jy, 33) * 8) + intdiv(($jy % 33) + 3, 4) + $jd + ($jm < 7 ? ($jm - 1) * 31 : (($jm - 7) * 30) + 186);
        $gy = 400 * intdiv($days, 146097);
        $days %= 146097;
        if ($days > 36524) {
            $gy += 100 * intdiv(--$days, 36524);
            $days %= 36524;
            if ($days >= 365) {
                $days++;
            }
        }
        $gy += 4 * intdiv($days, 1461);
        $days %= 1461;
        if ($days > 365) {
            $gy += intdiv($days - 1, 365);
            $days = ($days - 1) % 365;
        }
        $gd = $days + 1;
        $leap = ($gy % 4 === 0 && $gy % 100 !== 0) || ($gy % 400 === 0);
        $months = [0, 31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for ($gm = 1; $gm <= 12 && $gd > $months[$gm]; $gm++) {
            $gd -= $months[$gm];
        }
        return [$gy, $gm, $gd];
    }

    /** Worker: queues every due run. */
    public static function due(float $deadline): array
    {
        $out = ['queued' => 0, 'paused' => 0];
        $now = Clock::now();
        foreach (Db::rows(Db::table('mod_mcsec_schedules')->where('status', 'active')->where('next_run_at', '>', 0)->where('next_run_at', '<=', $now)->orderBy('next_run_at')->limit(50)) as $s) {
            if (microtime(true) > $deadline) {
                break;
            }
            // claim this run first (a parallel worker skips it)
            $next = self::nextRun((array) $s, max($now, (int) $s->next_run_at));
            if (Db::table('mod_mcsec_schedules')->where('id', $s->id)->where('next_run_at', $s->next_run_at)->update(['next_run_at' => $next, 'last_run_at' => $now, 'runs' => (int) $s->runs + 1]) !== 1) {
                continue;
            }
            if (!Access::clientAllowed((int) $s->client_id)) {
                continue;
            }
            $assets = (int) $s->asset_id > 0
                ? array_filter([Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->where('client_id', $s->client_id)->where('status', '!=', 'removed')->first()])
                : Assets::forClient((int) $s->client_id, 'verified');
            $profile = Catalog::get((string) $s->profile);
            if (!$profile) {
                self::pause($s, 'plan');
                $out['paused']++;
                continue;
            }
            if (!$assets) {
                if ((int) $s->asset_id > 0) {
                    self::pause($s, 'asset');
                    $out['paused']++;
                }
                continue;
            }
            foreach ($assets as $a) {
                if (!in_array($a->kind, $profile['kinds'], true)) {
                    continue;
                }
                if ($a->status !== 'verified') {
                    if ((int) $s->asset_id > 0) {
                        self::pause($s, 'verify');
                        $out['paused']++;
                    }
                    continue;
                }
                $r = Scans::queue((int) $s->client_id, $a, (string) $s->profile, (int) $s->id, 0);
                if ($r['ok']) {
                    $out['queued'] += empty($r['again']) ? 1 : 0;
                } elseif (isset($r['need'])) {
                    self::pause($s, 'credits', $r['error']);
                    $out['paused']++;
                    break;
                } elseif (str_contains((string) $r['error'], 'پلن')) {
                    self::pause($s, 'plan', $r['error']);
                    $out['paused']++;
                    break;
                }
            }
        }
        return $out;
    }

    private static function pause(object $s, string $reason, string $detail = ''): void
    {
        Db::table('mod_mcsec_schedules')->where('id', $s->id)->update(['status' => 'paused', 'pause_reason' => $reason]);
        Notify::event((int) $s->client_id, 'schedule_paused', ['schedule_id' => (int) $s->id, 'profile' => (string) (Catalog::all(true)[$s->profile]['label'] ?? $s->profile),
            'reason' => self::PAUSE[$reason] ?? $reason, 'detail' => $detail], 'sp:' . $s->id . ':' . Clock::today());
    }

    public static function describe(object $s): string
    {
        $h = Text::fa(sprintf('%02d:%02d', (int) $s->hour, ((int) $s->id * 7) % 50));
        return match ((string) $s->freq) {
            'daily' => 'هر روز ساعت ' . $h,
            'monthly' => 'روز ' . Text::fa((int) $s->dom) . ' هر ماه، ساعت ' . $h,
            default => 'هر ' . (self::DOW[(int) $s->dow] ?? '') . ' ساعت ' . $h,
        };
    }
}
