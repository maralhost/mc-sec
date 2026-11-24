<?php

declare(strict_types=1);

namespace McSec;

/**
 * The journal of one scan (0.12.0): what MC-Sec asked the engine, what the engine answered, and what proof there is
 * that work was really done. An admin opens it from «صف اسکن» with the scan's number, so "it says finished but
 * nothing is in OASM" can be answered from facts: the workspace and its owner, target, project, run, the jobs of the
 * run, and every HTTP call with its status.
 *
 * - Engine calls are gathered per step (start, poll, collect) and written as one row. A poll that changed nothing and
 *   failed nowhere is not written, so a long scan does not fill the table.
 * - Nothing secret is stored: paths and status codes, a short piece of an error answer, and details through
 *   Trace::scrub. Request bodies are never kept.
 * - Problems an admin should hear about are rows with step 'alert'; the worker sends the new ones to the admin's Bale
 *   or Telegram chat when one is set (Ops alerts), and the overview lists them.
 */
final class ScanLog
{
    private const MAX_EVENTS = 80;
    public const KEEP_DAYS = 60;

    private static int $scan = 0;
    private static int $client = 0;
    private static string $step = '';
    /** @var array<int,array> */
    private static array $calls = [];

    /** From here until end(), engine calls belong to this scan's step. */
    public static function begin(int $scanId, int $clientId, string $step): void
    {
        self::$scan = $scanId;
        self::$client = $clientId;
        self::$step = $step;
        self::$calls = [];
    }

    /** One engine HTTP call (called by the engine's own call()). */
    public static function call(string $method, string $path, array $r): void
    {
        if (self::$scan <= 0 || count(self::$calls) >= 60) {
            return;
        }
        $status = (int) ($r['status'] ?? 0);
        $row = ['m' => $method, 'path' => mb_substr($path, 0, 180), 'status' => $status, 'ms' => (int) ($r['ms'] ?? 0)];
        if ($status === 0 || $status >= 400) {
            $row['answer'] = mb_substr(trim((string) ($r['error'] ?? '') . ' ' . preg_replace('~\s+~', ' ', (string) ($r['body'] ?? ''))), 0, 200);
        }
        self::$calls[] = $row;
    }

    /** True when a call of the current step failed (so a quiet poll is still worth a row). */
    public static function failed(): bool
    {
        foreach (self::$calls as $c) {
            if ($c['status'] === 0 || $c['status'] >= 400) {
                return true;
            }
        }
        return false;
    }

    /** Ends the step; with $write it becomes one row holding the step's calls. */
    public static function end(bool $write, string $message = '', array $detail = [], string $level = 'info'): void
    {
        [$scan, $client, $step, $calls] = [self::$scan, self::$client, self::$step, self::$calls];
        self::$scan = 0;
        self::$calls = [];
        if ($write && $scan > 0) {
            self::add($scan, $client, $step, $message, $detail + ($calls ? ['calls' => $calls] : []), $level);
        }
    }

    public static function add(int $scanId, int $clientId, string $step, string $message, array $detail = [], string $level = 'info'): void
    {
        try {
            if ($scanId <= 0 || Db::table('mod_mcsec_scan_events')->where('scan_id', $scanId)->count() >= self::MAX_EVENTS) {
                return;
            }
            Db::table('mod_mcsec_scan_events')->insert(['scan_id' => $scanId, 'client_id' => $clientId, 'step' => mb_substr($step, 0, 16), 'level' => mb_substr($level, 0, 8),
                'message' => mb_substr($message, 0, 255), 'detail' => $detail ? mb_substr(Db::json(Trace::scrub($detail)), 0, 12000) : null, 'created_at' => Clock::now()]);
        } catch (\Throwable $e) {
            // the journal must never break a scan
        }
    }

    /** @return object[] oldest first */
    public static function of(int $scanId): array
    {
        return Db::rows(Db::table('mod_mcsec_scan_events')->where('scan_id', $scanId)->orderBy('id')->limit(self::MAX_EVENTS + 20));
    }

    /**
     * Something about a scan an admin should look at (it failed, it finished without proof of work, it was cut off).
     * Kept as a journal row (once per scan and kind) and sent to the admin's chat by the worker.
     */
    public static function alert(object $scan, string $kind, string $message): void
    {
        try {
            if (Db::table('mod_mcsec_scan_events')->where('scan_id', (int) $scan->id)->where('step', 'alert')->where('message', 'like', $kind . ':%')->exists()) {
                return;
            }
            Db::table('mod_mcsec_scan_events')->insert(['scan_id' => (int) $scan->id, 'client_id' => (int) $scan->client_id, 'step' => 'alert', 'level' => 'new',
                'message' => mb_substr($kind . ': ' . $message, 0, 255), 'detail' => null, 'created_at' => Clock::now()]);
        } catch (\Throwable $e) {
            // never break a scan
        }
    }

    /** Worker: sends alerts not sent yet to the admin's chats (settings ops_alert_bale / ops_alert_telegram). @return int sent */
    public static function deliverAlerts(): int
    {
        $chats = array_filter(['bale' => trim(Settings::get('ops_alert_bale')), 'telegram' => trim(Settings::get('ops_alert_telegram'))], fn ($c) => preg_match('~^-?\d{3,20}$~', $c) === 1);
        $rows = Db::rows(Db::table('mod_mcsec_scan_events')->where('step', 'alert')->where('level', 'new')->orderBy('id')->limit(10));
        $sent = 0;
        foreach ($rows as $r) {
            // with no chat set, or alerts switched off, the row is only marked: the panel still lists it
            Db::table('mod_mcsec_scan_events')->where('id', (int) $r->id)->where('level', 'new')->update(['level' => 'seen']);
            if (!$chats || !Settings::bool('ops_alerts')) {
                continue;
            }
            $scan = Db::table('mod_mcsec_scans as s')->join('mod_mcsec_assets as a', 'a.id', '=', 's.asset_id')->where('s.id', (int) $r->scan_id)->select(['s.id', 's.client_id', 's.profile', 'a.value'])->first();
            $text = "MC-Sec | اسکن شماره‌ی " . (int) $r->scan_id . " نیاز به بررسی دارد\n" . ($scan ? Catalog::label((string) $scan->profile, (string) $scan->profile) . ' روی ' . $scan->value . ' (حساب #' . (int) $scan->client_id . ")\n" : '')
                . preg_replace('~^[a-z_]+:\s*~', '', (string) $r->message) . "\n\nجزئیات: پنل مدیر ← MC-Sec ← عملیات ← صف اسکن ← اسکن " . (int) $r->scan_id;
            foreach ($chats as $which => $chat) {
                if (Notify::bot($which, 'sendMessage', ['chat_id' => $chat, 'text' => $text])['ok']) {
                    $sent++;
                }
            }
        }
        return $sent;
    }

    /** Scans of the last $days days an admin should look at: failed, or finished incomplete. @return object[] */
    public static function attention(int $days = 7, int $limit = 20): array
    {
        return Db::rows(Db::table('mod_mcsec_scans as s')->join('mod_mcsec_assets as a', 'a.id', '=', 's.asset_id')->where('s.finished_at', '>', Clock::now() - $days * 86400)
            ->where(fn ($q) => $q->where('s.status', 'failed')->orWhere(fn ($w) => $w->where('s.status', 'completed')->where('s.summary', 'like', '%"partial"%')))
            ->select(['s.*', 'a.value'])->orderByDesc('s.id')->limit($limit));
    }

    public static function purge(): int
    {
        return Db::table('mod_mcsec_scan_events')->where('created_at', '<', Clock::now() - self::KEEP_DAYS * 86400)->delete();
    }
}
