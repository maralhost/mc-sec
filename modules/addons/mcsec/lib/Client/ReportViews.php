<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Ai;
use McSec\Assets;
use McSec\Findings;
use McSec\Plans;
use McSec\Reports;
use McSec\Settings;
use McSec\Surface;
use McSec\Text;

/** Reports: list and request, and one report as a printable document (browser print → PDF). */
final class ReportViews
{
    private static function e($s): string
    {
        return Ui::e($s);
    }

    public static function list(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $list = Reports::recent($cid);
        $aiOk = Ai::configured() && Plans::limits($cid)['ai'];
        $out = Ui::guide('<p>گزارش پایه پس از هر اسکن خودکار و رایگان ساخته می‌شود: امتیاز، یافته‌ها از مهم‌ترین، و راه رفع هر کدام. <strong>گزارش هوش مصنوعی</strong> روی همان داده، خلاصه‌ی مدیریتی، ریسک‌های اصلی، کارهای سریع و برنامه‌ی ۳۰ روزه و راهکار اختصاصی هر یافته را می‌نویسد.</p>'
            . '<p>هر گزارش را می‌توانید چاپ یا با «چاپ ← ذخیره به PDF» مرورگر نگه دارید و برای مدیر یا تیم فنی بفرستید. گزارش هفتگی یا ماهانه را در «اعلان‌ها» تنظیم کنید.</p>', !$list);
        if ($ctx['manage']) {
            $assets = [];
            foreach (Assets::forClient($cid, 'verified') as $a) {
                $assets[(string) $a->id] = (string) $a->value;
            }
            $cost = Settings::int('ai_report_cost');
            $body = '<div class="mcs-form-row">' . Ui::field('mcs-rk', 'دامنه‌ی گزارش', Ui::select('kind', ['account' => 'همه‌ی دارایی‌ها', 'asset' => 'یک دارایی'], 'account', 'mcs-rk'))
                . ($assets ? Ui::field('mcs-ra', 'دارایی (برای «یک دارایی»)', Ui::select('asset', $assets, (string) array_key_first($assets), 'mcs-ra')) : '') . '</div>'
                . ($aiOk ? Ui::toggle('ai', true, 'با هوش مصنوعی' . ($cost > 0 ? ' (' . Text::fa($cost) . ' اعتبار)' : ''), 'خلاصه‌ی مدیریتی، ریسک‌ها، کارهای سریع و راهکار اختصاصی. اگر ساخته نشود، اعتبارش برمی‌گردد.') : '<p class="mcs-help">گزارش هوش مصنوعی در پلن فعلی شما نیست؛ گزارش پایه ساخته می‌شود.</p>')
                . '<button type="submit" class="btn btn-primary">' . Ui::ico('file') . 'ساختن گزارش</button>';
            $out .= Ui::card(Ui::form($ctx, 'reports', 'report_create', $body), 'گزارش تازه', 'plus');
        }
        if (!$list) {
            return $out . Ui::emptyState('file', 'هنوز گزارشی نیست', 'پس از اولین اسکن، گزارش پایه خودکار این‌جا می‌آید.');
        }
        $rows = '';
        foreach ($list as $r) {
            $st = match ($r->status) {
                'ready' => Ui::chip('آماده', 'ok'),
                'failed' => Ui::chip('ناموفق', 'err'),
                default => Ui::chip('در حال ساخت', 'run'),
            };
            $rows .= '<tr>' . Ui::td('گزارش', '<a href="index.php?m=mcsec&amp;p=report&amp;id=' . (int) $r->id . '" dir="auto">' . self::e($r->title) . '</a>')
                . Ui::td('نوع', self::e(Reports::KINDS[$r->kind] ?? $r->kind) . ((int) $r->ai ? ' ' . Ui::chip('هوش مصنوعی', 'info') : ''))
                . Ui::td('وضعیت', $st) . Ui::td('تاریخ', self::e(Text::date((int) $r->created_at))) . '</tr>';
        }
        return $out . Ui::card(Ui::table(['گزارش', 'نوع', 'وضعیت', 'تاریخ'], $rows), 'گزارش‌های شما', 'file');
    }

    public static function detail(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $r = Reports::get($cid, (int) Text::toAscii((string) ($_GET['id'] ?? '0')));
        if (!$r) {
            return Views::missing('این گزارش', 'index.php?m=mcsec&p=reports', 'بازگشت به گزارش‌ها');
        }
        Views::$pageTitle = self::e($r->title);
        if ($r->status === 'queued') {
            return Ui::card('<div data-mcs-reload="8">' . Ui::progress(30, 'گزارش در حال ساخت است' . ((int) $r->ai ? '؛ بخش هوش مصنوعی ممکن است چند دقیقه طول بکشد' : ''), true)
                . '<p class="mcs-help">لازم نیست منتظر بمانید؛ وقتی آماده شد در «اعلان‌ها» خبرتان می‌کنیم.</p><noscript><p><a href="index.php?m=mcsec&amp;p=report&amp;id=' . (int) $r->id . '">تازه کردن</a></p></noscript></div>', 'در حال ساخت', 'clock');
        }
        if ($r->status === 'failed') {
            return Ui::alert('danger', self::e($r->error), 'alert');
        }
        $d = Reports::data($r);
        Views::$pageActions = '<button type="button" class="btn btn-default" data-mcs-print hidden>' . Ui::ico('printer') . 'چاپ یا PDF</button>';
        $out = $r->error !== '' ? Ui::alert('warning', self::e($r->error), 'alert') : '';
        $out .= '<article class="mcs-report">';
        $out .= '<header class="mcs-report-head"><div><p class="mcs-muted mcs-small">' . self::e(Reports::KINDS[$d['kind']] ?? '') . ' — ' . self::e($d['client'] ?? '') . '</p><h3 dir="auto">' . self::e($d['title'] ?? '') . '</h3>'
            . '<p class="mcs-small mcs-muted">ساخته‌شده: ' . self::e(Text::date((int) ($d['generated_at'] ?? 0)))
            . ((int) ($d['period']['from'] ?? 0) > 0 ? ' — دوره: ' . self::e(Text::date((int) $d['period']['from'], false) . ' تا ' . Text::date((int) $d['period']['to'], false)) : '') . '</p></div>'
            . Ui::gauge((int) ($d['score'] ?? -1)) . '</header>';
        $ai = is_array($d['ai'] ?? null) ? $d['ai'] : null;
        // summary
        $sum = $ai && $ai['executive_summary'] !== '' ? Ui::para($ai['executive_summary']) : '<ul>' . implode('', array_map(fn ($l) => '<li>' . self::e($l) . '</li>', (array) ($d['basic_summary'] ?? []))) . '</ul>';
        $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico($ai ? 'sparkle' : 'info') . 'خلاصه</h4>' . $sum . Ui::sevCounts((array) ($d['counts'] ?? [])) . '</section>';
        if ($ai) {
            if ($ai['key_risks']) {
                $h = '<ul class="mcs-risks">';
                foreach ($ai['key_risks'] as $k) {
                    $h .= '<li><strong dir="auto">' . self::e($k['title']) . '</strong><p dir="auto">' . self::e($k['impact']) . '</p></li>';
                }
                $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('alert') . 'ریسک‌های اصلی</h4>' . $h . '</ul></section>';
            }
            if ($ai['quick_wins']) {
                $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('check') . 'کارهای سریع (کمتر از یک ساعت)</h4><ul>' . implode('', array_map(fn ($q) => '<li dir="auto">' . self::e($q) . '</li>', $ai['quick_wins'])) . '</ul></section>';
            }
            if ($ai['plan']) {
                $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('calendar') . 'برنامه‌ی پیشنهادی</h4><ol>' . implode('', array_map(fn ($p) => '<li dir="auto"><strong>' . self::e($p['when']) . ':</strong> ' . self::e($p['action']) . '</li>', $ai['plan'])) . '</ol></section>';
            }
        }
        // findings with fixes
        $fs = (array) ($d['findings'] ?? []);
        if ($fs) {
            $h = '';
            foreach ($fs as $i => $f) {
                $af = $ai['findings'][$f['id']] ?? null;
                $fix = '';
                if ($af) {
                    $fix = ($af['why'] !== '' ? '<p class="mcs-why" dir="auto">' . self::e($af['why']) . '</p>' : '') . '<ol class="mcs-fix-steps">' . implode('', array_map(fn ($s) => '<li dir="auto">' . self::e($s) . '</li>', $af['steps'])) . '</ol>'
                        . ($af['snippet'] ? Ui::code((string) $af['snippet']['code'], (string) $af['snippet']['label']) : '') . ($af['verify'] !== '' ? '<p class="mcs-small" dir="auto"><strong>سنجش رفع:</strong> ' . self::e($af['verify']) . '</p>' : '')
                        . ($af['needs_confirmation'] ? '<p class="mcs-small mcs-muted">این مورد پیش از اقدام باید تأیید شود (شاید مثبت کاذب باشد).</p>' : '');
                } elseif (!empty($f['kb'])) {
                    $fix = '<p class="mcs-why">' . self::e($f['kb']['why']) . '</p><ol class="mcs-fix-steps">' . implode('', array_map(fn ($s) => '<li>' . self::e($s) . '</li>', (array) $f['kb']['steps'])) . '</ol>'
                        . (!empty($f['kb']['snippets'][0]) ? Ui::code((string) $f['kb']['snippets'][0]['code'], (string) $f['kb']['snippets'][0]['label']) : '');
                }
                $h .= '<li class="mcs-report-finding"><div class="mcs-report-finding-head">' . Ui::sev($f['severity']) . '<a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f['id'] . '" dir="auto">' . self::e($f['title']) . '</a>'
                    . ($f['new'] ? ' ' . Ui::chip('تازه', 'warn') : '') . '</div><p class="mcs-small">' . Ui::ltr($f['location']) . ($af && $af['effort'] !== '' ? ' · ' . self::e($af['effort']) : (!empty($f['kb']['effort']) ? ' · ' . self::e($f['kb']['effort']) : '')) . '</p>' . $fix . '</li>';
            }
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('bug') . 'یافته‌ها و راه رفع</h4><ol class="mcs-report-findings">' . $h . '</ol>'
                . ((int) ($d['more'] ?? 0) > 0 ? '<p class="mcs-muted">و ' . self::e(Text::fa((int) $d['more'])) . ' یافته‌ی کم‌اهمیت‌تر در صفحه‌ی «یافته‌ها».</p>' : '') . '</section>';
        } else {
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('shield-check') . 'یافته‌ها</h4><p>یافته‌ی بازی نیست.</p></section>';
        }
        if (!empty($d['fixed'])) {
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('check') . 'رفع‌شده‌ها</h4><ul>' . implode('', array_map(fn ($f) => '<li>' . self::e($f['title']) . ' — ' . Ui::ltr($f['location']) . '</li>', array_slice($d['fixed'], 0, 30))) . '</ul></section>';
        }
        $sf = (array) ($d['surface'] ?? []);
        if (!empty($sf['counts']) && array_sum($sf['counts']) > 0) {
            $h = '<ul class="mcs-surface-sum">';
            foreach (Surface::KINDS as $k => $l) {
                if (!empty($sf['counts'][$k])) {
                    $h .= '<li><strong>' . self::e(Text::fa((int) $sf['counts'][$k])) . '</strong><span>' . self::e($l) . '</span></li>';
                }
            }
            $h .= '</ul>' . (!empty($sf['ports']) ? '<p class="mcs-small"><strong>درگاه‌های باز:</strong> ' . implode(' ', array_map(fn ($p) => Ui::ltr($p, 'mcs-tag'), array_slice($sf['ports'], 0, 30))) . '</p>' : '')
                . (!empty($sf['tech']) ? '<p class="mcs-small"><strong>فناوری‌ها:</strong> ' . implode(' ', array_map(fn ($p) => Ui::ltr($p, 'mcs-tag'), array_slice($sf['tech'], 0, 30))) . '</p>' : '');
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('radar') . 'سطح حمله</h4>' . $h . '</section>';
        }
        if (!empty($d['scans'])) {
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('clock') . 'اسکن‌های این دوره</h4><ul>' . implode('', array_map(fn ($s) => '<li>' . self::e($s['profile']) . ' — ' . Ui::ltr($s['asset']) . ' — ' . self::e(\McSec\Scans::STATUS[$s['status']] ?? $s['status']) . ' — ' . self::e(Text::date((int) $s['finished_at'])) . '</li>', $d['scans'])) . '</ul></section>';
        }
        $out .= '<footer class="mcs-report-foot"><p>این گزارش از داده‌ی اسکن‌های خودکار ساخته شده و جای تست نفوذ دستی را نمی‌گیرد.' . ($ai ? ' بخش‌های هوش مصنوعی با مدل ' . Ui::ltr($ai['model'] ?? '') . ' نوشته شده‌اند؛ پیش از اجرای دستورها آن‌ها را بخوانید.' : '') . '</p><p>بخش امنیت سایبری مارال کلاد</p></footer>';
        return $out . '</article>';
    }
}
