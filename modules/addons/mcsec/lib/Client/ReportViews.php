<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Ai;
use McSec\Assets;
use McSec\Findings;
use McSec\Lang;
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
        $out = Ui::guide(Lang::t('<p>گزارش پایه پس از هر اسکن خودکار و رایگان ساخته می‌شود: امتیاز، یافته‌ها از مهم‌ترین، و راه رفع هر کدام. <strong>گزارش هوش مصنوعی</strong> روی همان داده، خلاصه‌ی مدیریتی، ریسک‌های اصلی، کارهای سریع و برنامه‌ی ۳۰ روزه و راهکار اختصاصی هر یافته را می‌نویسد.</p>')
            . Lang::t('<p>هر گزارش را می‌توانید چاپ یا با «چاپ ← ذخیره به PDF» مرورگر نگه دارید و برای مدیر یا تیم فنی بفرستید. گزارش هفتگی یا ماهانه را در «اعلان‌ها» تنظیم کنید.</p>'), !$list);
        if ($ctx['manage']) {
            // one choice, not two: «all assets» or one of them. (Until 0.16.1 a second list chose between "all" and
            // "one asset" and stayed on "all" while people picked an asset in the first: they got the whole account.)
            $scope = ['0' => Lang::t('همه‌ی دارایی‌ها')];
            foreach (Assets::forClient($cid, 'verified') as $a) {
                $scope[(string) (int) $a->id] = (string) $a->value;
            }
            $pre = (string) (int) Text::toAscii((string) ($_POST['asset'] ?? $_GET['asset'] ?? '0'));
            $cost = \McSec\Rules::cost($cid, Settings::int('ai_report_cost'));
            $body = '<div class="mcs-form-row">' . Ui::field('mcs-ra', 'گزارش برای', Ui::select('asset', $scope, isset($scope[$pre]) ? $pre : '0', 'mcs-ra'), Lang::t('یک دارایی را انتخاب کنید تا گزارش فقط همان را داشته باشد.')) . '</div>'
                . ($aiOk ? Ui::toggle('ai', true, $cost > 0 ? Lang::t('با هوش مصنوعی ({n} اعتبار)', ['n' => Text::fa($cost)]) : 'با هوش مصنوعی', Lang::t('خلاصه‌ی مدیریتی، ریسک‌ها، کارهای سریع و راهکار اختصاصی. اگر ساخته نشود، اعتبارش برمی‌گردد.')) : '<p class="mcs-help">' . Lang::t('گزارش هوش مصنوعی در پلن فعلی شما نیست؛ گزارش پایه ساخته می‌شود.') . '</p>')
                . '<button type="submit" class="btn btn-primary">' . Ui::ico('file') . Lang::t('ساختن گزارش') . '</button>';
            $out .= Ui::card(Ui::form($ctx, 'reports', 'report_create', $body), 'گزارش تازه', 'plus');
            if (\McSec\Pdf::ownAllowed($cid) && \McSec\Pdf::available()) {
                // for an agency: its own name on the PDF it hands to its customer
                $acc = \McSec\Accounts::get($cid);
                $out .= Ui::drawer(Lang::t('نام شرکت شما روی PDF گزارش'), '<p>' . Lang::t('اگر گزارش را برای مشتری خودتان می‌فرستید، نام و خط تماس شرکت شما جای نام ما روی جلد، سربرگ و پابرگ PDF می‌آید. خالی بگذارید تا قالب پیش‌فرض بماند.') . '</p>'
                    . Ui::form($ctx, 'reports', 'brand_save', '<div class="mcs-form-row">'
                        . Ui::field('mcs-bn', 'نام شرکت', '<input class="form-control" id="mcs-bn" name="brand_name" maxlength="60" dir="auto" value="' . self::e((string) ($acc->brand_name ?? '')) . '">')
                        . Ui::field('mcs-bc', 'خط تماس', '<input class="form-control" id="mcs-bc" name="brand_contact" maxlength="160" dir="auto" value="' . self::e((string) ($acc->brand_contact ?? '')) . '">', Lang::t('مثلاً نشانی سایت یا تلفن؛ روی جلد می‌آید.'))
                        . '</div><button type="submit" class="btn btn-default">' . Lang::t('ذخیره') . '</button>'), (string) ($acc->brand_name ?? '') !== '', 'file', 'brand');
            }
        }
        if (!$list) {
            return $out . Ui::emptyState('file', 'هنوز گزارشی نیست', Lang::t('پس از اولین اسکن، گزارش پایه خودکار این‌جا می‌آید.'));
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
            return Ui::card('<div data-mcs-reload="8">' . Ui::progress(30, (int) $r->ai ? 'گزارش در حال ساخت است؛ بخش هوش مصنوعی ممکن است چند دقیقه طول بکشد' : 'گزارش در حال ساخت است', true)
                . '<p class="mcs-help">' . Lang::t('لازم نیست منتظر بمانید؛ وقتی آماده شد در «اعلان‌ها» خبرتان می‌کنیم.') . '</p><noscript><p><a href="index.php?m=mcsec&amp;p=report&amp;id=' . (int) $r->id . '">' . Lang::t('تازه کردن') . '</a></p></noscript></div>', 'در حال ساخت', 'clock');
        }
        if ($r->status === 'failed') {
            return Ui::alert('danger', self::e($r->error), 'alert');
        }
        $d = Reports::data($r);
        Views::$pageActions = (\McSec\Pdf::available() ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=report&amp;id=' . (int) $r->id . '&amp;pdf=1" download>' . Ui::ico('file') . Lang::t('دانلود PDF') . '</a> ' : '')
            . '<button type="button" class="btn btn-default" data-mcs-print hidden>' . Ui::ico('printer') . (\McSec\Pdf::available() ? Lang::t('چاپ') : Lang::t('چاپ یا PDF')) . '</button>';
        return self::article($r, $d, false) . self::shareCard($ctx, $r);
    }

    /** The report itself. $public: for a visitor without a login (a shared link): nothing in it leads into the account. */
    public static function article(object $r, array $d, bool $public): string
    {
        $out = !$public && $r->error !== '' ? Ui::alert('warning', self::e($r->error), 'alert') : '';
        $out .= '<article class="mcs-report">';
        $out .= '<header class="mcs-report-head"><div><p class="mcs-muted mcs-small">' . self::e(Reports::KINDS[$d['kind']] ?? '') . ' — ' . self::e($d['client'] ?? '') . '</p><h3 dir="auto">' . self::e($d['title'] ?? '') . '</h3>'
            . '<p class="mcs-small mcs-muted">' . Lang::t('ساخته‌شده: {date}', ['date' => self::e(Text::date((int) ($d['generated_at'] ?? 0)))])
            . ((int) ($d['period']['from'] ?? 0) > 0 ? ' — ' . Lang::t('دوره: {from} تا {to}', ['from' => self::e(Text::date((int) $d['period']['from'], false)), 'to' => self::e(Text::date((int) $d['period']['to'], false))]) : '') . '</p></div>'
            . Ui::gauge((int) ($d['score'] ?? -1)) . '</header>';
        $ai = is_array($d['ai'] ?? null) ? $d['ai'] : null;
        // summary
        $sum = $ai && $ai['executive_summary'] !== '' ? Ui::para($ai['executive_summary']) : '<ul>' . implode('', array_map(fn ($l) => '<li>' . self::e($l) . '</li>', (array) ($d['basic_summary'] ?? []))) . '</ul>';
        $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico($ai ? 'sparkle' : 'info') . Lang::t('خلاصه') . '</h4>' . $sum . Ui::sevCounts((array) ($d['counts'] ?? [])) . '</section>';
        if ($ai) {
            if ($ai['key_risks']) {
                $h = '<ul class="mcs-risks">';
                foreach ($ai['key_risks'] as $k) {
                    $h .= '<li><strong dir="auto">' . self::e($k['title']) . '</strong><p dir="auto">' . self::e($k['impact']) . '</p></li>';
                }
                $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('alert') . Lang::t('ریسک‌های اصلی') . '</h4>' . $h . '</ul></section>';
            }
            if ($ai['quick_wins']) {
                $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('check') . Lang::t('کارهای سریع (کمتر از یک ساعت)') . '</h4><ul>' . implode('', array_map(fn ($q) => '<li dir="auto">' . self::e($q) . '</li>', $ai['quick_wins'])) . '</ul></section>';
            }
            if ($ai['plan']) {
                $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('calendar') . Lang::t('برنامه‌ی پیشنهادی') . '</h4><ol>' . implode('', array_map(fn ($p) => '<li dir="auto"><strong>' . self::e($p['when']) . ':</strong> ' . self::e($p['action']) . '</li>', $ai['plan'])) . '</ol></section>';
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
                        . ($af['snippet'] ? Ui::code((string) $af['snippet']['code'], (string) $af['snippet']['label']) : '') . ($af['verify'] !== '' ? '<p class="mcs-small" dir="auto"><strong>' . Lang::t('سنجش رفع:') . '</strong> ' . self::e($af['verify']) . '</p>' : '')
                        . ($af['needs_confirmation'] ? '<p class="mcs-small mcs-muted">' . Lang::t('این مورد پیش از اقدام باید تأیید شود (شاید مثبت کاذب باشد).') . '</p>' : '');
                } elseif (!empty($f['kb'])) {
                    $fix = '<p class="mcs-why">' . self::e($f['kb']['why']) . '</p><ol class="mcs-fix-steps">' . implode('', array_map(fn ($s) => '<li>' . self::e($s) . '</li>', (array) $f['kb']['steps'])) . '</ol>'
                        . (!empty($f['kb']['snippets'][0]) ? Ui::code((string) $f['kb']['snippets'][0]['code'], (string) $f['kb']['snippets'][0]['label']) : '');
                }
                $h .= '<li class="mcs-report-finding"><div class="mcs-report-finding-head">' . Ui::sev($f['severity']) . ($public ? '<strong dir="auto">' . self::e($f['title']) . '</strong>' : '<a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f['id'] . '" dir="auto">' . self::e($f['title']) . '</a>')
                    . ($f['new'] ? ' ' . Ui::chip('تازه', 'warn') : '') . '</div><p class="mcs-small">' . Ui::ltr($f['location']) . ($af && $af['effort'] !== '' ? ' · ' . self::e($af['effort']) : (!empty($f['kb']['effort']) ? ' · ' . self::e($f['kb']['effort']) : '')) . '</p>' . $fix . '</li>';
            }
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('bug') . Lang::t('یافته‌ها و راه رفع') . '</h4><ol class="mcs-report-findings">' . $h . '</ol>'
                . ((int) ($d['more'] ?? 0) > 0 ? '<p class="mcs-muted">' . Lang::t('و {n} یافته‌ی کم‌اهمیت‌تر در صفحه‌ی «یافته‌ها».', ['n' => self::e(Text::fa((int) $d['more']))]) . '</p>' : '') . '</section>';
        } else {
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('shield-check') . Lang::t('یافته‌ها') . '</h4><p>' . Lang::t('یافته‌ی بازی نیست.') . '</p></section>';
        }
        if (!empty($d['fixed'])) {
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('check') . Lang::t('رفع‌شده‌ها') . '</h4><ul>' . implode('', array_map(fn ($f) => '<li>' . self::e($f['title']) . ' — ' . Ui::ltr($f['location']) . '</li>', array_slice($d['fixed'], 0, 30))) . '</ul></section>';
        }
        $sf = (array) ($d['surface'] ?? []);
        if (!empty($sf['counts']) && array_sum($sf['counts']) > 0) {
            $h = '<ul class="mcs-surface-sum">';
            foreach (Surface::KINDS as $k => $l) {
                if (!empty($sf['counts'][$k])) {
                    $h .= '<li><strong>' . self::e(Text::fa((int) $sf['counts'][$k])) . '</strong><span>' . self::e($l) . '</span></li>';
                }
            }
            $h .= '</ul>' . (!empty($sf['ports']) ? '<p class="mcs-small"><strong>' . Lang::t('درگاه‌های باز:') . '</strong> ' . implode(' ', array_map(fn ($p) => Ui::ltr($p, 'mcs-tag'), array_slice($sf['ports'], 0, 30))) . '</p>' : '')
                . (!empty($sf['tech']) ? '<p class="mcs-small"><strong>' . Lang::t('فناوری‌ها:') . '</strong> ' . implode(' ', array_map(fn ($p) => Ui::ltr($p, 'mcs-tag'), array_slice($sf['tech'], 0, 30))) . '</p>' : '');
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('radar') . Lang::t('سطح حمله') . '</h4>' . $h . '</section>';
        }
        $out .= self::compliance($d);
        if (!empty($d['scans'])) {
            $out .= '<section class="mcs-report-sec"><h4>' . Ui::ico('clock') . Lang::t('اسکن‌های این دوره') . '</h4><ul>' . implode('', array_map(fn ($s) => '<li>' . self::e($s['profile']) . ' — ' . Ui::ltr($s['asset']) . ' — ' . self::e(\McSec\Scans::STATUS[$s['status']] ?? $s['status']) . ' — ' . self::e(Text::date((int) $s['finished_at'])) . '</li>', $d['scans'])) . '</ul></section>';
        }
        $out .= '<footer class="mcs-report-foot"><p>' . Lang::t('این گزارش از داده‌ی اسکن‌های خودکار ساخته شده و جای تست نفوذ دستی را نمی‌گیرد.') . ($ai ? ' ' . Lang::t('بخش‌های هوش مصنوعی با مدل {model} نوشته شده‌اند؛ پیش از اجرای دستورها آن‌ها را بخوانید.', ['model' => Ui::ltr($ai['model'] ?? '')]) : '') . '</p><p>' . Lang::t('بخش امنیت سایبری مارال کلاد') . '</p></footer>';
        return $out . '</article>';
    }

    /** Where the open findings fall in OWASP Top 10 and ISO 27001 (Compliance): a mapping, and it says so. */
    private static function compliance(array $d): string
    {
        $c = is_array($d['compliance'] ?? null) ? $d['compliance'] : null;
        if (!$c || empty($c['owasp'])) {
            return '';
        }
        $row = fn (string $code, string $title, array $x) => '<tr>' . Ui::td('بند', Ui::ltr($code)) . Ui::td('عنوان', self::e($title))
            . Ui::td('یافته‌ی باز', (int) ($x['n'] ?? 0) > 0 ? '<strong>' . self::e(Text::fa((int) $x['n'])) . '</strong>' : '<span class="mcs-muted">' . Lang::t('دیده نشد') . '</span>')
            . Ui::td('بالاترین شدت', (string) ($x['severity'] ?? '') !== '' ? Ui::sev((string) $x['severity']) : '') . '</tr>';
        $ow = '';
        foreach (\McSec\Compliance::OWASP as $k => $title) {
            $ow .= $row($k, $title, (array) ($c['owasp'][$k] ?? []));
        }
        $iso = '';
        foreach ((array) ($c['iso'] ?? []) as $k => $x) {
            $iso .= isset(\McSec\Compliance::ISO[$k]) ? $row((string) $k, \McSec\Compliance::ISO[$k], (array) $x) : '';
        }
        $head = ['بند', 'عنوان', 'یافته‌ی باز', 'بالاترین شدت'];
        return '<section class="mcs-report-sec"><h4>' . Ui::ico('layers') . Lang::t('نگاشت به استانداردها') . '</h4>'
            . '<p class="mcs-small"><strong dir="ltr">OWASP Top 10 (2021)</strong></p>' . Ui::table($head, $ow)
            . ($iso !== '' ? '<p class="mcs-small"><strong dir="ltr">ISO/IEC 27001:2022 — Annex A</strong></p>' . Ui::table($head, $iso) : '')
            . ((int) ($c['unmapped'] ?? 0) > 0 ? '<p class="mcs-small mcs-muted">' . Lang::t('{n} یافته در این دو فهرست جایی ندارد.', ['n' => self::e(Text::fa((int) $c['unmapped']))]) . '</p>' : '')
            . '<p class="mcs-small mcs-muted">' . self::e(\McSec\Compliance::note()) . '</p></section>';
    }

    /** «پیوند فقط‌خواندنی»: the links of this report that still open, and a short form for a new one. */
    private static function shareCard(array $ctx, object $r): string
    {
        if (!Settings::bool('report_share') || !$ctx['manage'] || $r->status !== 'ready') {
            return '';
        }
        $cid = (int) $ctx['who']['client_id'];
        $q = '&amp;id=' . (int) $r->id;
        $list = '';
        foreach (\McSec\Shares::forReport($cid, (int) $r->id) as $s) {
            $list .= '<li class="mcs-share">' . Ui::code(\McSec\Shares::url((string) $s->token), '', false)
                . '<span class="mcs-small mcs-muted">' . self::e(Lang::t('تا {date} باز است', ['date' => Text::date((int) $s->expires_at)])) . ((string) $s->pass !== '' ? ' ' . Ui::chip('با رمز', 'info') : ' ' . Ui::chip('بی رمز', 'muted')) . '</span>'
                . Ui::form($ctx, 'report', 'report_unshare', '<input type="hidden" name="share" value="' . (int) $s->id . '"><button type="submit" class="btn btn-default btn-sm">' . Ui::ico('x') . Lang::t('برداشتن') . '</button>',
                    'این پیوند برداشته شود؟ هر کس آن را دارد دیگر گزارش را نمی‌بیند.', 'mcs-inline', false, $q) . '</li>';
        }
        $days = [];
        foreach (\McSec\Shares::DAYS as $n) {
            $days[(string) $n] = Lang::t('{n} روز', ['n' => Text::fa($n)]);
        }
        $form = Ui::form($ctx, 'report', 'report_share', '<input type="hidden" name="report" value="' . (int) $r->id . '"><div class="mcs-form-row">'
            . Ui::field('mcs-sd', 'تا کی باز باشد', Ui::select('days', $days, '7', 'mcs-sd'))
            . Ui::field('mcs-sp', 'رمز (اختیاری)', '<input class="form-control" id="mcs-sp" type="password" name="password" maxlength="72" autocomplete="new-password" dir="ltr">', Lang::t('اگر بگذارید، بازکننده باید آن را بداند. رمز را از راه دیگری به او بدهید.'))
            . '</div><button type="submit" class="btn btn-default">' . Ui::ico('link') . Lang::t('ساختن پیوند') . '</button>', '', '', false, $q);
        return Ui::drawer(Lang::t('فرستادن برای کسی که حساب ندارد (پیوند فقط‌خواندنی)'), '<p>' . Lang::t('هر کس این پیوند را داشته باشد همین گزارش را می‌بیند، بدون ورود و بدون دسترسی به هیچ جای دیگر حساب شما. پیوند پس از مدتی که انتخاب می‌کنید خودش بسته می‌شود.') . '</p>'
            . ($list !== '' ? '<ul class="mcs-plain mcs-shares">' . $list . '</ul>' : '') . $form, $list !== '', 'link', 'share');
    }

    /** The page a shared link opens (no login): the report, a password box, or «در دسترس نیست». */
    public static function shared(array $st, string $token): string
    {
        $state = (string) ($st['state'] ?? 'none');
        if ($state === 'ok') {
            $r = $st['report'];
            return '<div class="mcs-pagehead"><div><h2 dir="auto">' . self::e($r->title) . '</h2><p class="mcs-small mcs-muted">' . self::e(Lang::t('این گزارش با یک پیوند فقط‌خواندنی به شما نشان داده می‌شود؛ پیوند تا {date} باز است.', ['date' => Text::date((int) $st['share']->expires_at)])) . '</p></div></div>'
                . self::article($r, Reports::data($r), true);
        }
        if ($state === 'none') {
            return Ui::card(Ui::emptyState('lock', 'این پیوند در دسترس نیست', Lang::t('پیوند منقضی شده، برداشته شده یا نشانی آن کامل نیست. از کسی که آن را فرستاده پیوند تازه بخواهید.')));
        }
        $msg = $state === 'wrong' ? Ui::alert('danger', Lang::t('رمز درست نیست.'), 'alert') : ($state === 'limited' ? Ui::alert('warning', Lang::t('تلاش‌های زیادی شد. یک ساعت دیگر دوباره امتحان کنید.'), 'alert') : '');
        return Ui::card($msg . '<form method="post" action="index.php?m=mcsec&amp;p=shared&amp;t=' . self::e($token) . '" novalidate>'
            . Ui::field('mcs-pw', 'رمز این گزارش', '<input class="form-control" id="mcs-pw" type="password" name="pw" maxlength="72" autocomplete="off" dir="ltr" required>', Lang::t('فرستنده‌ی پیوند رمز را به شما داده است.'))
            . '<button type="submit" class="btn btn-primary">' . Lang::t('دیدن گزارش') . '</button></form>', 'این گزارش رمز دارد', 'lock');
    }
}
