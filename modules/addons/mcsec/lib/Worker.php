<?php

declare(strict_types=1);

namespace McSec;

/**
 * Background work, from WHMCS's own cron (no extra cron line): AfterCronJob (about every 5 minutes) runs the locked
 * pass below within a time budget; DailyCronJob the nightly upkeep. Each step is independent, so one failing step
 * never stops the others (skill whmcs-addon §2). Network calls (engines, verification, AI, bots) happen only here,
 * in an explicit customer POST, or in the live progress poll behind a circuit breaker.
 */
final class Worker
{
    /** @return array<string,mixed>|null null when another pass holds the lock */
    public static function run(int $budgetSeconds = 45): ?array
    {
        if (Settings::get('schema_version') !== MCSEC_VERSION) {
            Installer::install();
            Settings::set('schema_version', MCSEC_VERSION);
        }
        return Lock::with('mcsec_worker', function () use ($budgetSeconds) {
            @set_time_limit($budgetSeconds + 120);
            $deadline = microtime(true) + $budgetSeconds;
            $report = ['at' => Clock::now()];
            $steps = [
                'topups' => fn () => Credits::reconcileTopups(),
                'poll' => fn () => Scans::pollRunning($deadline),
                'dispatch' => fn () => Scans::dispatch($deadline),
                'schedules' => fn () => Schedules::due($deadline),
                'verify' => fn () => Verify::due((int) max(5, min(20, $deadline - microtime(true)))),
                'reports' => fn () => Reports::process($deadline),
                'digests' => fn () => self::every('digests', 1800) ? Notify::digests($deadline) : 'skip',
                'deliver' => fn () => Notify::deliver($deadline + 10),
                'bots' => fn () => self::every('bots', 120) ? Notify::linkBots() : 'skip',
            ];
            foreach ($steps as $name => $fn) {
                try {
                    $report[$name] = $fn();
                } catch (\Throwable $e) {
                    $report[$name] = 'error';
                    Trace::error('worker', $name, $e->getMessage(), Trace::exception($e));
                }
            }
            Settings::set('last_worker_at', (string) Clock::now());
            Settings::set('last_worker_report', Db::json($report));
            return $report;
        }, 900);
    }

    /** True at most once per $seconds for a step (steps that need not run every pass). */
    private static function every(string $step, int $seconds): bool
    {
        $k = 'every:' . $step;
        if (Kv::get($k) !== null) {
            return false;
        }
        Kv::set($k, '1', $seconds);
        return true;
    }

    public static function daily(): array
    {
        $out = [];
        $steps = [
            'snapshot' => fn () => Score::snapshot(),
            'low_credit' => fn () => Credits::lowAlerts(),
            'log' => fn () => Trace::purge(),
            'audit' => fn () => Audit::purge(),
            'nonces' => fn () => Nonce::purge(),
            'hits' => fn () => RateLimit::purge(),
            'kv' => fn () => Kv::purge(),
            'notices' => fn () => Notify::purge(),
            'reports' => fn () => Reports::purge(),
        ];
        foreach ($steps as $step => $fn) {
            try {
                $out[$step] = $fn();
            } catch (\Throwable $e) {
                $out[$step] = 'error';
                Trace::error('worker', 'daily.' . $step, $e->getMessage(), Trace::exception($e));
            }
        }
        Settings::set('last_daily_at', (string) Clock::now());
        return $out;
    }
}
