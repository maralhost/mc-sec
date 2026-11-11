<?php

declare(strict_types=1);

namespace McSec;

/**
 * Who did what (mod_mcsec_audit): adding and removing assets, verification, scans, finding status changes,
 * schedules, credit grants by admins and settings changes. Shown to the customer as their activity log and to admins.
 */
final class Audit
{
    public const ACTIONS = [
        'asset_add' => 'افزودن دارایی', 'asset_remove' => 'حذف دارایی', 'asset_verified' => 'تأیید مالکیت', 'asset_lapsed' => 'منقضی شدن تأیید',
        'scan_start' => 'شروع اسکن', 'scan_cancel' => 'لغو اسکن', 'finding_status' => 'تغییر وضعیت یافته', 'schedule_save' => 'زمان‌بندی',
        'schedule_delete' => 'حذف زمان‌بندی', 'report_request' => 'درخواست گزارش', 'notify_save' => 'تنظیم اعلان', 'topup' => 'خرید اعتبار',
        'grant' => 'اعتبار مدیر', 'terms' => 'پذیرش شرایط اسکن', 'settings' => 'تنظیمات ماژول', 'admin_verify' => 'تأیید دستی مدیر',
    ];

    public static function log(int $clientId, string $action, string $target = '', array $detail = [], int $userId = 0): void
    {
        try {
            Db::table('mod_mcsec_audit')->insert([
                'client_id' => $clientId, 'user_id' => $userId, 'admin_id' => Auth::adminId() ?: Auth::masqueradingAdmin(),
                'action' => substr($action, 0, 48), 'target' => mb_substr($target, 0, 160), 'detail' => $detail ? Db::json(Trace::scrub($detail)) : null,
                'ip' => substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45), 'created_at' => Clock::now(),
            ]);
        } catch (\Throwable $e) {
            Db::log('audit write failed: ' . $e->getMessage());
        }
    }

    public static function recent(int $clientId, int $limit = 50): array
    {
        return Db::rows(Db::table('mod_mcsec_audit')->where('client_id', $clientId)->orderByDesc('id')->limit($limit));
    }

    public static function purge(): int
    {
        return Db::table('mod_mcsec_audit')->where('created_at', '<', Clock::now() - 730 * 86400)->delete();
    }
}
