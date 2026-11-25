<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Assets;
use McSec\Catalog;
use McSec\Db;
use McSec\Findings;
use McSec\Lang;
use McSec\Monitor;
use McSec\Net;
use McSec\Plans;
use McSec\Scans;
use McSec\Score;
use McSec\Settings;
use McSec\Surface;
use McSec\Text;
use McSec\Verify;

/** Assets: the list with one smart input (one target or a whole list), the verification wizard and the asset page. */
final class AssetViews
{
    private static function e($s): string
    {
        return Ui::e($s);
    }

    public static function statusChip(object $a): string
    {
        $tone = ['pending' => 'warn', 'verified' => 'ok', 'lapsed' => 'err', 'blocked' => 'muted'][$a->status] ?? 'muted';
        $label = Assets::STATUS[$a->status] ?? $a->status;
        if ($a->status === 'verified' && in_array($a->method, ['whmcs', 'parent'], true)) {
            $label = $a->method === 'whmcs' ? 'تأیید خودکار (مارال)' : 'تأیید با دامنه‌ی اصلی';
        }
        return Ui::chip($label, $tone);
    }

    public static function list(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $assets = Assets::forClient($cid);
        $lim = Plans::limits($cid);
        $out = Ui::guide(Lang::t('<p>دامنه‌ها، زیردامنه‌ها و IPهایی که می‌خواهید بررسی شوند این‌جا هستند. <strong>فقط دارایی‌ای اسکن می‌شود که مالکیتش تأیید شده باشد</strong>؛ این قانون از سایت شما و دیگران محافظت می‌کند.</p>')
            . Lang::t('<ul><li>دامنه‌ها و IPهای سرویس‌های خودتان در مارال کلاد خودکار تأیید می‌شوند.</li><li>با تأیید یک دامنه، همه‌ی زیردامنه‌هایش هم تأییدشده‌اند.</li><li>می‌توانید یک‌جا فهرستی از دامنه‌ها را بچسبانید (هر خط یکی).</li></ul>'), !$assets);
        if (isset($_GET['removed'])) {
            $out .= Ui::alert('success', Lang::t('دارایی حذف شد. یافته‌ها و گزارش‌های قبلی‌اش در تاریخچه می‌مانند.'), 'check');
        }
        if ($ctx['manage']) {
            $out .= self::addForm($ctx, !$assets, count($assets), $lim['max_assets']);
        }
        if (!$assets) {
            return $out . Ui::emptyState('globe', 'هنوز دارایی‌ای اضافه نکرده‌اید', Lang::t('دامنه‌ی سایتتان را در کادر بالا بنویسید تا اولین بررسی امنیتی را انجام دهیم.'));
        }
        $f = (string) ($_GET['status'] ?? '');
        $shown = $f !== '' && isset(Assets::STATUS[$f]) ? array_values(array_filter($assets, fn ($a) => $a->status === $f)) : $assets;
        $seg = ['index.php?m=mcsec&p=assets' => Lang::t('همه ({n})', ['n' => Text::fa(count($assets))])];
        foreach (['verified', 'pending', 'lapsed'] as $s) {
            $n = count(array_filter($assets, fn ($a) => $a->status === $s));
            if ($n > 0) {
                $seg['index.php?m=mcsec&p=assets&status=' . $s] = self::e(Assets::STATUS[$s]) . ' (' . Text::fa($n) . ')';
            }
        }
        $schedules = [];
        foreach (Db::rows(Db::table('mod_mcsec_schedules')->where('client_id', $cid)->where('status', 'active')) as $s) {
            $schedules[(int) $s->asset_id][] = \McSec\Schedules::FREQ[$s->freq]['label'] ?? $s->freq;
        }
        $rows = '';
        foreach ($shown as $a) {
            $isSub = $a->kind === 'domain' && Net::apex((string) $a->value) !== $a->value;
            $sched = array_merge($schedules[(int) $a->id] ?? [], $a->status === 'verified' ? ($schedules[0] ?? []) : []);
            $rows .= '<tr>' . Ui::td('دارایی', '<a class="mcs-asset-link' . ($isSub ? ' is-sub' : '') . '" href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '">'
                    . Ui::ico($a->kind === 'domain' ? 'globe' : 'server') . Ui::ltr($a->value) . '</a>' . (trim((string) $a->label) !== '' ? '<small class="mcs-muted">' . self::e($a->label) . '</small>' : ''))
                . Ui::td('وضعیت', self::statusChip($a) . ((string) ($a->cdn ?? '') !== '' ? ' ' . Ui::chip('پشت CDN', 'muted') : '')
                    . (trim((string) ($a->partial ?? '')) !== '' && $a->status === 'verified' ? ' <span title="' . self::e((string) $a->partial) . '">' . Ui::chip('ارزیابی ناقص', 'warn') . '</span>' : '')
                    . ((($m = Monitor::status($a)) !== null && $m[1] === 'err') ? ' ' . Ui::chip($m[0], 'err') : '') . ($a->status === 'pending' ? ' <a class="mcs-small" href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '#verify">' . Lang::t('ادامه‌ی تأیید') . '</a>' : ''))
                . Ui::td('امتیاز', (int) $a->last_scan_at > 0 && (int) $a->score >= 0 ? '<span class="mcs-score-pill mcs-tone-' . Score::tone((int) $a->score) . '">' . self::e(Text::fa((int) $a->score)) . '</span>' : '<span class="mcs-muted">—</span>')
                . Ui::td('یافته‌های باز', (int) $a->last_scan_at > 0 ? Ui::sevCounts(Assets::counts($a), 'index.php?m=mcsec&p=findings&asset=' . (int) $a->id, true) : '<span class="mcs-muted">' . Lang::t('هنوز اسکن نشده') . '</span>')
                . Ui::td('آخرین اسکن', self::e(Views::when((int) $a->last_scan_at)))
                . Ui::td('زمان‌بندی', $sched ? self::e(Lang::join(array_map(fn ($x) => Lang::t((string) $x), array_unique($sched)))) : '<span class="mcs-muted">—</span>')
                . '</tr>';
        }
        return $out . Ui::card(Ui::seg($seg, $f !== '' ? 'index.php?m=mcsec&p=assets&status=' . $f : 'index.php?m=mcsec&p=assets')
            . Ui::table(['دارایی', 'وضعیت', 'امتیاز', 'یافته‌های باز', 'آخرین اسکن', 'زمان‌بندی'], $rows), 'دارایی‌های شما', 'globe', '', '',
            self::e(Lang::t('{n} از {max} دارایی مجاز', ['n' => Text::fa(count($assets)), 'max' => Text::fa($lim['max_assets'])])));
    }

    private static function addForm(array $ctx, bool $open, int $count, int $max): string
    {
        $profiles = [];
        foreach (Catalog::forClient($ctx['who']['client_id']) as $k => $p) {
            if ($p['allowed']) {
                $profiles[$k] = $p['credits'] > 0 ? Lang::t('{label} ({n} اعتبار)', ['label' => Lang::t((string) $p['label']), 'n' => Text::fa($p['credits'])])
                    : Lang::t('{label} (رایگان)', ['label' => Lang::t((string) $p['label'])]);
            }
        }
        $body = '<div class="mcs-add">'
            . Ui::field('mcs-targets', 'دامنه، زیردامنه یا IP', '<textarea class="form-control mcs-ltr" id="mcs-targets" name="targets" rows="2" dir="ltr" placeholder="example.com&#10;shop.example.com&#10;203.0.113.10" required>' . self::e(self::prefill()) . '</textarea>',
                Lang::t('یکی یا چندتا (هر خط یکی، تا ۱۰۰ مورد). نشانی کامل مثل https://example.com/page هم پذیرفته می‌شود.'))
            . '<div class="mcs-form-row">' . Ui::field('mcs-label', 'نام دلخواه (اختیاری)', '<input class="form-control" id="mcs-label" name="label" maxlength="120" dir="auto" placeholder="' . Lang::t('مثلاً فروشگاه اصلی') . '">')
            . Ui::field('mcs-autoscan', 'پس از تأیید، خودکار اسکن کن', Ui::select('autoscan', ['' => 'نه، خودم اسکن می‌گیرم'] + $profiles, 'hygiene', 'mcs-autoscan'),
                Lang::t('تا لازم نباشد برای شروع اسکن برگردید. هزینه‌ی اعتبار هنگام شروع کم می‌شود.')) . '</div>'
            . '<button type="submit" class="btn btn-primary">' . Ui::ico('plus') . Lang::t('افزودن') . '</button></div>';
        $full = $count >= $max;
        return Ui::card($full ? Ui::alert('warning', self::e(Lang::t('به سقف {n} دارایی رسیده‌اید. دارایی بی‌استفاده را حذف کنید یا پلن بالاتری بگیرید.', ['n' => Text::fa($max)])) . ' <a href="index.php?m=mcsec&amp;p=credits">' . Lang::t('پلن‌ها') . '</a>', 'alert')
            : Ui::form($ctx, 'assets', 'add_asset', $body), 'افزودن دارایی', 'plus', '', 'mcs-addcard" id="add');
    }

    public static function detail(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $a = Assets::get($cid, (int) Text::toAscii((string) ($_GET['id'] ?? $_POST['asset'] ?? '0')));
        if (!$a) {
            return Views::missing('این دارایی', 'index.php?m=mcsec&p=assets', 'بازگشت به دارایی‌ها');
        }
        Views::$pageTitle = Ui::ltr($a->value, 'mcs-title-ltr') . ' ' . self::statusChip($a);
        $out = '';
        if (($_GET['new'] ?? '') === 'verified') {
            $out .= Ui::alert('success', $a->method === 'whmcs' ? Lang::t('دارایی افزوده و خودکار تأیید شد، چون از سرویس‌های همین حساب در مارال کلاد است. حالا اسکن بگیرید.')
                : Lang::t('دارایی افزوده و خودکار تأیید شد. حالا اسکن بگیرید.'), 'check');
        }
        if ($a->status !== 'verified') {
            $out .= self::verifyPanel($ctx, $a, ($_GET['new'] ?? '') === '1');
        }
        $out .= self::cdnPanel($ctx, $a);
        if ($a->status === 'verified') {
            Views::$pageActions = $ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=scans&amp;asset=' . (int) $a->id . '#new">' . Ui::ico('play') . Lang::t('اسکن تازه') . '</a>' : '';
        }
        $counts = Assets::counts($a);
        $score = (int) $a->last_scan_at > 0 ? (int) $a->score : -1;
        $partial = trim((string) ($a->partial ?? ''));
        $mon = Monitor::status($a);
        if ($mon !== null && $mon[1] === 'err') {
            $out .= Ui::alert('danger', Ui::plain(Lang::t('این سایت از دسترس خارج است ({why}). وقتی برگردد خبرتان می‌کنیم.', ['why' => $mon[2]])), 'alert');
        }
        $out .= '<div class="mcs-grid2">' . Ui::card(Ui::gauge($score, $score < 0 ? Lang::t('هنوز اسکنی تمام نشده است.') : self::e(Lang::t('آخرین اسکن: {when}', ['when' => Views::when((int) $a->last_scan_at)])), $partial !== '')
                . ($partial !== '' && $score >= 0 ? '<p class="mcs-small">' . Ui::plain($partial) . '</p>' : ''), 'امتیاز این دارایی', 'shield-check')
            . Ui::card(Ui::sevCounts($counts, 'index.php?m=mcsec&p=findings&asset=' . (int) $a->id) . Ui::facts([
                'نوع' => self::e(Assets::KINDS[$a->kind] ?? $a->kind),
                'در دسترس بودن' => $mon !== null ? Ui::chip($mon[0], $mon[1]) . ' <small class="mcs-muted">' . Ui::plain($mon[2]) . '</small>' : '',
                'گواهی SSL تا' => $mon !== null && (string) ($a->mon_cert_end ?? '') !== '' ? self::e(Text::ymd((string) $a->mon_cert_end)) : '',
                'سرور اصلی برای' => $a->kind === 'ip' ? implode(' ', array_map(fn ($d) => '<a href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $d->id . '">' . Ui::ltr($d->value) . '</a>',
                    Db::rows(Db::table('mod_mcsec_assets')->where('client_id', $cid)->where('origin_id', $a->id)->where('status', '!=', 'removed')->limit(10)))) : '',
                'روش تأیید' => $a->status === 'verified' ? self::e(Verify::METHODS[$a->method] ?? $a->method) . ' — ' . self::e(Text::date((int) $a->verified_at, false)) : '',
                'بررسی بعدی تأیید' => $a->status === 'verified' && !in_array($a->method, ['admin'], true) ? self::e(Text::date((int) $a->next_check_at, false)) : '',
                'برچسب‌ها' => trim((string) $a->tags) !== '' ? implode(' ', array_map(fn ($t) => Ui::chip($t), explode(',', (string) $a->tags))) : '',
            ]), 'یافته‌های باز', 'bug', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings&amp;asset=' . (int) $a->id . '">' . Lang::t('همه') . '</a>') . '</div>';

        if ($ctx['manage'] && $a->status === 'verified' && (string) $a->oasm_target !== '') {
            $out .= Ui::card('<p>' . Lang::t('گزارش فارسی هر اسکن با راه رفع در بخش «گزارش‌ها» است. این‌جا گزارش خام موتور اسکن را می‌گیرید: انگلیسی، با همه‌ی یافته‌ها و جزئیات فنی این دارایی؛ برای تیم فنی یا ممیز.') . '</p>'
                . Ui::form($ctx, 'asset', 'oasm_report', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><button type="submit" class="btn btn-default">' . Ui::ico('file') . Lang::t('دانلود گزارش فنی (PDF انگلیسی)') . '</button>'
                    . '<span class="mcs-help">' . Lang::t('ساختنش چند ثانیه طول می‌کشد.') . '</span>', '', 'mcs-inline mcs-native', false, '&amp;id=' . (int) $a->id), 'گزارش فنی موتور اسکن', 'file');
        }
        // top open findings
        $rank = "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";
        $top = Db::rows(Db::table('mod_mcsec_findings')->where('asset_id', $a->id)->where('status', 'open')->orderByDesc('priority')->orderByRaw($rank . ' DESC')->orderByDesc('last_seen_at')->limit(8));
        if ($top) {
            $list = '';
            foreach ($top as $f) {
                $list .= '<li><a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '">' . Ui::sev((string) $f->severity) . '<span class="mcs-todo-title">' . self::e($f->title) . '</span></a><span class="mcs-todo-meta">' . Ui::ltr($f->location) . '</span></li>';
            }
            $out .= Ui::card('<ol class="mcs-todo">' . $list . '</ol>', 'مهم‌ترین یافته‌ها', 'alert');
        }

        $out .= self::surfaceCard($a, $ctx);
        $scans = Scans::recent($cid, 10, (int) $a->id);
        if ($scans) {
            $out .= Ui::card(ScanViews::table($scans, false), 'اسکن‌های این دارایی', 'radar', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=scans">' . Lang::t('همه‌ی اسکن‌ها') . '</a>');
        }
        if ($ctx['manage']) {
            $settings = Ui::form($ctx, 'asset', 'asset_save', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><div class="mcs-form-row">'
                    . Ui::field('mcs-al', 'نام دلخواه', '<input class="form-control" id="mcs-al" name="label" maxlength="120" dir="auto" value="' . self::e($a->label) . '">')
                    . Ui::field('mcs-at', 'برچسب‌ها', '<input class="form-control" id="mcs-at" name="tags" maxlength="200" dir="auto" value="' . self::e(str_replace(',', Lang::t('، '), (string) $a->tags)) . '">', Lang::t('جداشده با ویرگول؛ مثلاً «تولید، فروشگاه».'))
                    . '</div><button type="submit" class="btn btn-default">' . Lang::t('ذخیره') . '</button>', '', '', false, '&amp;id=' . (int) $a->id)
                . '<hr>' . Ui::form($ctx, 'asset', 'asset_remove', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><button type="submit" class="btn btn-default btn-danger-text">' . Ui::ico('trash') . Lang::t('حذف این دارایی') . '</button>'
                    . '<p class="mcs-help">' . Lang::t('زمان‌بندی‌هایش حذف و اسکن‌های در صفش لغو می‌شوند (با بازگشت اعتبار). یافته‌ها و گزارش‌های قبلی می‌مانند.') . '</p>',
                    'این دارایی از فهرست حذف شود؟', '', false, '&amp;id=' . (int) $a->id);
            $out .= Ui::drawer('تنظیمات دارایی', $settings, false, 'key');
        }
        return $out;
    }

    /**
     * A domain behind a CDN: what that means for its scans and, when the admin allows it, the real server's IP on
     * which the scans that probe ports run instead.
     */
    private static function cdnPanel(array $ctx, object $a): string
    {
        if ($a->kind !== 'domain') {
            return '';
        }
        $behind = (string) ($a->cdn ?? '') !== '';
        $on = Settings::bool('cdn_origin_scan');
        $origin = $on ? Assets::origin($a) : null;
        if (!$behind && (!$on || $a->status !== 'verified')) {
            return '';
        }
        $body = $behind ? '<p>' . Lang::t('بازدیدکننده‌ها به سرورهای {cdn} وصل می‌شوند، نه سرور شما. «بررسی سلامت پایه» همان چیزی را می‌سنجد که بازدیدکننده می‌بیند؛ ولی اسکن‌هایی که درگاه‌ها را می‌سنجند هرگز روی سرورهای CDN اجرا نمی‌شوند، چون آن سرورها مال شما نیستند.',
            ['cdn' => self::e(Net::cdnLabel((string) $a->cdn))]) . '</p>'
            : '<p>' . Lang::t('اگر این سایت پشت CDN یا پروکسی است، IP سرور اصلی‌اش را بدهید تا بررسی‌ها مستقیم از خود سرور پرسیده شوند، نه از CDN.') . '</p>';
        if (!$on) {
            return Ui::card($body . '<p class="mcs-small mcs-muted">' . Lang::t('برای این دامنه «بررسی سلامت پایه» در دسترس است.') . '</p>', 'این دامنه پشت CDN است', 'globe');
        }
        $form = fn (string $inner, string $confirm = '') => Ui::form($ctx, 'asset', 'asset_origin', '<input type="hidden" name="asset" value="' . (int) $a->id . '">' . $inner, $confirm, '', false, '&amp;id=' . (int) $a->id);
        $skip = (int) ($a->origin_tls_skip ?? 0) === 1;
        $tick = '<label class="mcs-check"><input type="checkbox" name="tls_skip" value="1"' . ($skip ? ' checked' : '') . '><span>' . Lang::t('گواهی SSL سرور را نادیده بگیر') . '<small>'
            . Lang::t('اگر گواهی سرور خودامضا یا مخصوص CDN است تیک بزنید؛ آن‌وقت گواهی سرور سنجیده و گزارش نمی‌شود (گواهی‌ای که بازدیدکننده می‌بیند مال CDN است).') . '</small></span></label>';
        if ($origin) {
            $ok = (int) ($a->origin_ok_at ?? 0) > 0;
            $body .= Ui::facts([
                'سرور اصلی' => '<a href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $origin->id . '">' . Ui::ltr($origin->value) . '</a> ' . self::statusChip($origin),
                'این سایت روی همین سرور است؟' => $ok ? Ui::chip('بله، آزموده شد', 'ok') . ' <span class="mcs-small mcs-muted">' . self::e(Views::when((int) $a->origin_ok_at)) . '</span>' . ($skip ? ' ' . Ui::chip('گواهی سرور نادیده گرفته می‌شود', 'muted') : '')
                    : Ui::chip('هنوز دیده نشد', 'warn'),
            ]);
            $body .= $ok ? '<p class="mcs-small">' . Lang::t('«بررسی سلامت پایه» این دامنه مستقیم از همین سرور پرسیده می‌شود (با نام همین سایت)، نه از CDN.') . '</p>'
                : Ui::alert('warning', self::e(trim((string) ($a->origin_note ?? '')) !== '' ? (string) $a->origin_note : Lang::t('هنوز آزموده نشده است.'))
                    . ' <a href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '&amp;vfile=1" download>' . Lang::t('دانلود فایل تأیید') . '</a>', 'alert');
            $body .= '<p class="mcs-small">' . ($origin->status === 'verified' ? Lang::t('کشف سطح حمله و اسکن آسیب‌پذیری این دامنه روی همین IP اجرا می‌شوند.')
                : Lang::t('پس از تأیید مالکیت این IP (در صفحه‌ی خودش)، کشف سطح حمله و اسکن آسیب‌پذیری این دامنه روی آن اجرا می‌شوند.')) . '</p>';
            if ($ctx['manage']) {
                $body .= $form('<input type="hidden" name="retest" value="1">' . $tick . '<button type="submit" class="btn btn-default btn-sm">' . Ui::ico('refresh') . Lang::t('دوباره بیازما') . '</button>')
                    . $form('<input type="hidden" name="origin" value=""><button type="submit" class="btn btn-default btn-sm">' . Lang::t('برداشتن پیوند') . '</button>', 'پیوند سرور اصلی برداشته شود؟ دارایی IP آن سر جایش می‌ماند.');
            }
        } elseif ($ctx['manage']) {
            $body .= $form('<div class="mcs-form-row">' . Ui::field('mcs-origin', 'IP اصلی سرور', '<input class="form-control" id="mcs-origin" name="origin" maxlength="45" dir="ltr" inputmode="decimal" autocomplete="off" placeholder="203.0.113.10">',
                Lang::t('IP سروری که سایت واقعاً روی آن است؛ در پنل CDN، بخش DNS، به نام «IP مبدأ» یا Origin. اگر از سرویس‌های مارال کلاد در همین حساب باشد خودکار تأیید می‌شود؛ وگرنه مالکیتش را مثل هر IP دیگر تأیید می‌کنید.'))
                . '</div>' . $tick . '<p class="mcs-help">' . Lang::t('پس از ثبت، از خود همان سرور می‌پرسیم که این سایت رویش هست یا نه (با فایل تأیید همین حساب). تا این دیده نشود، هیچ درخواستی مستقیم به آن سرور فرستاده نمی‌شود.') . '</p>'
                . '<button type="submit" class="btn btn-primary">' . Lang::t('ثبت و آزمودن سرور') . '</button>');
        }
        return $behind ? Ui::card($body, 'این دامنه پشت CDN است', 'globe') : Ui::drawer(Lang::t('این سایت پشت CDN یا پروکسی است؟ (سرور اصلی)'), $body, (bool) $origin, 'globe', 'origin');
    }

    /**
     * Proof of ownership in two parts: «تأیید خودکار» (what needs nothing, or one pasted token) and «تأیید دستی» (a
     * record, a file, a tag: copyable values, a ready file to download), then one button to check now. An IP has its
     * own complete path: Maral service, file on its web server (with ready commands), reverse DNS, and a manual request.
     */
    private static function verifyPanel(array $ctx, object $a, bool $fresh): string
    {
        $acc = Accounts::ensure((int) $a->client_id);
        $proof = Accounts::proof($acc);
        $days = max(1, Settings::int('verify_recheck_days'));
        $file = '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '&amp;vfile=1" download>' . Ui::ico('file') . Lang::t('دانلود فایل آماده (mcsec-verify.txt)') . '</a>';
        $ask = self::manualRequest($a);
        $auto = '';
        $manual = '';
        if ($a->kind === 'domain') {
            $providers = $ctx['manage'] ? \McSec\DnsApi::enabled() : [];
            if ($providers) {
                $opts = [];
                $how = '';
                foreach ($providers as $p) {
                    $opts[$p] = \McSec\DnsApi::PROVIDERS[$p][0];
                    $how .= '<li>' . self::e(\McSec\DnsApi::PROVIDERS[$p][1]) . '</li>';
                }
                $auto .= Ui::drawer('ساخت خودکار رکورد با توکن پنل DNS', '<p>' . Lang::t('اگر DNS این دامنه روی یکی از این پنل‌هاست، توکن همان پنل را یک بار این‌جا بچسبانید؛ رکورد تأیید را خودمان می‌سازیم و لازم نیست به پنل DNS بروید.') . '</p>'
                    . Ui::form($ctx, 'asset', 'verify_auto', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><div class="mcs-form-row">'
                        . Ui::field('mcs-dnsp', 'پنل DNS', Ui::select('provider', $opts, (string) array_key_first($opts), 'mcs-dnsp'))
                        . Ui::field('mcs-dnst', 'توکن API', '<input class="form-control" type="password" id="mcs-dnst" name="dns_token" maxlength="220" dir="ltr" autocomplete="off" spellcheck="false" required>',
                            Lang::t('فقط برای همین یک بار استفاده می‌شود و هیچ‌جا ذخیره نمی‌شود. پس از تأیید می‌توانید آن را در پنل خودتان حذف کنید.'))
                        . '</div><button type="submit" class="btn btn-primary">' . Ui::ico('sparkle') . Lang::t('رکورد را بساز و تأیید کن') . '</button>', '', '', false, '&amp;id=' . (int) $a->id)
                    . '<details class="mcs-how"><summary>' . Lang::t('توکن را از کجا بسازم؟') . '</summary><ul>' . $how . '</ul><p class="mcs-help">' . Lang::t('توکن را فقط با دسترسی «ویرایش DNS» همین دامنه بسازید، نه دسترسی کامل حساب.') . '</p></details>', true, 'sparkle', 'verify');
            }
            $auto .= '<p class="mcs-small mcs-muted">' . Ui::ico('check') . Lang::t('دامنه‌ای که در همین حساب مارال کلاد ثبت یا میزبانی شده، و زیردامنه‌ی دامنه‌ای که قبلاً با DNS تأیید کرده‌اید، خودکار و بی هیچ کاری تأیید می‌شوند.') . '</p>';
            $manual .= Ui::drawer('روش ۱ (پیشنهادی): رکورد DNS', '<p>' . Lang::t('در پنل DNS دامنه (DirectAdmin، cPanel، آروان‌کلاد، Cloudflare یا ثبت‌کننده‌ی دامنه) یک رکورد TXT با این مشخصات بسازید:') . '</p>'
                . Ui::facts(['نوع' => '<code dir="ltr">TXT</code>', 'نام (Host)' => Ui::code('_mcsec-verify', '', false) . '<small class="mcs-help">' . Lang::t('بعضی پنل‌ها نام کامل می‌خواهند: {name}', ['name' => Ui::ltr('_mcsec-verify.' . $a->value)]) . '</small>', 'مقدار (Value)' => Ui::code($proof, '', false), 'TTL' => Lang::t('پیش‌فرض')])
                . '<p class="mcs-help">' . Lang::t('این رکورد نام جداگانه دارد و به رکورد SPF یا رکوردهای دیگر دامنه دست نمی‌زند. با تأیید {apex}، همه‌ی زیردامنه‌هایش هم تأیید می‌شوند.', ['apex' => Ui::ltr(Net::apex((string) $a->value))]) . '</p>', !$providers, 'globe', $providers ? '' : 'verify')
                . Ui::drawer('روش ۲: فایل روی سایت', '<p>' . Lang::t('فایل آماده را دانلود کنید و بی تغییر در پوشه‌ی <code dir="ltr">public_html/.well-known/</code> سایت بگذارید (با File Manager هاست یا FTP). اگر پوشه‌ی <code dir="ltr">.well-known</code> نیست، بسازیدش.') . '</p>'
                . '<p>' . $file . '</p>' . Ui::facts(['باید در این نشانی باز شود' => Ui::code('https://' . $a->value . Verify::FILE_PATH, '', false), 'محتوای فایل' => Ui::code($proof, '', false)]), false, 'file')
                . Ui::drawer('روش ۳: تگ متا در صفحه‌ی اصلی', '<p>' . Lang::t('این تگ را در بخش <code dir="ltr">&lt;head&gt;</code> صفحه‌ی اصلی بگذارید (در وردپرس: افزونه‌ی سربرگ یا Theme Header):') . '</p>'
                . Ui::code('<meta name="mcsec-verification" content="' . $acc->verify_token . '">', 'HTML'), false, 'list');
        } elseif ($a->kind === 'ip') {
            $auto .= '<p class="mcs-small mcs-muted">' . Ui::ico('check') . Lang::t('IP سرویس‌های همین حساب در مارال کلاد (سرور مجازی، سرور اختصاصی، IP اختصاصی هاست) خودکار و بی هیچ کاری تأیید می‌شود. اگر این IP از مارال کلاد است و تأیید نشده، به پشتیبانی خبر بدهید.') . '</p>';
            $manual .= Ui::drawer('روش ۱ (پیشنهادی): فایل متنی روی همین سرور', '<p>' . Lang::t('فایل آماده را دانلود کنید و بی تغییر روی وب‌سرور همین IP بگذارید، در پوشه‌ی <code dir="ltr">.well-known</code> از ریشه‌ی سایت پیش‌فرض (سایتی که با خود IP باز می‌شود).') . '</p>'
                . '<p>' . $file . '</p>' . Ui::facts(['باید در این نشانی باز شود' => Ui::code('http://' . $a->value . Verify::FILE_PATH, '', false), 'محتوای فایل' => Ui::code($proof, '', false)])
                . '<p class="mcs-small">' . Lang::t('<strong>اگر با SSH وصل می‌شوید</strong>، یکی از این دو دستور کافی است:') . '</p>'
                . Ui::code("mkdir -p /var/www/html/.well-known && echo '" . $proof . "' > /var/www/html/.well-known/mcsec-verify.txt", 'وب‌سرور دارم (nginx یا Apache، ریشه‌ی پیش‌فرض)')
                . Ui::code("mkdir -p /tmp/mcsec/.well-known && echo '" . $proof . "' > /tmp/mcsec/.well-known/mcsec-verify.txt && cd /tmp/mcsec && python3 -m http.server 80", 'وب‌سرور ندارم (موقت، با کاربر root)')
                . '<p class="mcs-help">' . Lang::t('فقط درگاه‌های 80 و 443 سنجیده می‌شوند، چون باز کردنشان دسترسی مدیر سرور می‌خواهد. دستور دوم یک وب‌سرور موقت است؛ پس از تأیید با Ctrl+C ببندیدش. تأیید هر {days} روز دوباره سنجیده می‌شود؛ اگر فایل دیگر نباشد، پس از سه بار خبرتان می‌کنیم و تأیید منقضی می‌شود. برای تأیید ماندگار، فایل را روی وب‌سرور دائمی بگذارید یا از روش ۲ استفاده کنید.',
                    ['days' => self::e(Text::fa($days))]) . '</p>', true, 'file', 'verify')
                . Ui::drawer('روش ۲: DNS معکوس (PTR)', '<p>' . Lang::t('اگر رکورد PTR این IP به نامی زیر یکی از دامنه‌های تأییدشده‌ی شما اشاره کند (مثلاً {example}) و همان نام با رکورد A به همین IP برگردد، خودکار تأیید می‌شود و ماندگار است.', ['example' => Ui::ltr('srv1.example.com')]) . '</p>'
                . '<ol><li>' . Lang::t('دامنه‌تان را در «دارایی‌ها» بیفزایید و تأیید کنید.') . '</li><li>' . Lang::t('برای آن یک رکورد A بسازید، مثل {example}.', ['example' => Ui::ltr('srv1.example.com → ' . $a->value)])
                . '</li><li>' . Lang::t('PTR این IP را در پنل سرور یا با تیکت به ارائه‌دهنده‌ی IP روی همان نام بگذارید.') . '</li></ol>', false, 'server')
                . ($ask !== '' ? Ui::drawer('روش ۳: درخواست تأیید از پشتیبانی', '<p>' . Lang::t('اگر هیچ‌کدام از دو روش بالا برایتان شدنی نیست (مثلاً سرور وب‌سرور ندارد و PTR دست شما نیست)، مدرک مالکیت IP را برای پشتیبانی بفرستید؛ پس از بررسی، دستی تأیید می‌کنیم.') . '</p>' . $ask, false, 'heart') : '');
        } else {
            $manual .= Ui::alert('info', Lang::t('بازه‌ی IP خودکار تأیید نمی‌شود. مدرک تخصیص بازه را برای پشتیبانی مارال کلاد بفرستید تا دستی تأیید شود، یا IPها را تک‌تک بیفزایید.'), 'info') . $ask;
        }
        $note = trim((string) $a->check_note) !== '' && (int) $a->checked_at > 0
            ? Ui::alert('warning', '<strong>' . Lang::t('آخرین بررسی ({when}):', ['when' => self::e(Views::when((int) $a->checked_at))]) . '</strong> ' . self::e($a->check_note), 'alert') : '';
        $check = $ctx['manage'] && $a->kind !== 'cidr' ? Ui::form($ctx, 'asset', 'verify_check', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><button type="submit" class="btn btn-primary">' . Ui::ico('refresh') . Lang::t('الان بررسی کن') . '</button>', '', 'mcs-inline', false, '&amp;id=' . (int) $a->id) : '';
        $intro = '<p>' . ($fresh ? Lang::t('دارایی افزوده شد.') . ' ' : '')
            . ((string) ($a->autoscan ?? '') !== ''
                ? Lang::t('برای این‌که اسکن فقط روی دارایی‌های خودتان انجام شود، یکی از راه‌های زیر کافی است. لازم نیست این صفحه را باز نگه دارید: هر چند دقیقه خودمان بررسی می‌کنیم و پس از تأیید خبرتان می‌کنیم و اسکن «{scan}» خودکار شروع می‌شود.', ['scan' => self::e(Catalog::label((string) ($a->autoscan)))])
                : Lang::t('برای این‌که اسکن فقط روی دارایی‌های خودتان انجام شود، یکی از راه‌های زیر کافی است. لازم نیست این صفحه را باز نگه دارید: هر چند دقیقه خودمان بررسی می‌کنیم و پس از تأیید خبرتان می‌کنیم.')) . '</p>';
        $body = $intro . ($auto !== '' ? '<h4 class="mcs-verify-h">' . Ui::ico('sparkle') . Lang::t('تأیید خودکار') . '</h4>' . $auto : '')
            . ($a->kind !== 'cidr' ? '<h4 class="mcs-verify-h">' . Ui::ico('key') . Lang::t('تأیید دستی') . '</h4>' : '') . $manual;
        return Ui::card($body . $note . '<div class="mcs-actions">' . $check . '</div>', $a->status === 'lapsed' ? 'تأیید دوباره‌ی مالکیت' : 'تأیید مالکیت', 'key', '', 'is-attention');
    }

    /** A request to the support team for manual verification (the admin approves it in the panel); '' when requests are off. */
    private static function manualRequest(object $a): string
    {
        if (!\McSec\Support::enabled()) {
            return '';
        }
        return '<a class="btn btn-default" href="index.php?m=mcsec&amp;p=support&amp;topic=verify&amp;asset=' . (int) $a->id . '">' . Ui::ico('lifebuoy') . Lang::t('درخواست تأیید از پشتیبانی') . '</a>';
    }

    /** A target handed over in the address (the box on a hosting service's page): only a clean domain or IP is put in the form. */
    private static function prefill(): string
    {
        $t = \McSec\Net::parse(mb_substr((string) ($_GET['add'] ?? ''), 0, 255));
        return isset($t['error']) ? '' : (string) $t['value'];
    }

    private static function surfaceCard(object $a, array $ctx = []): string
    {
        $canMute = Settings::bool('host_mute') && !empty($ctx['manage']);
        $s = Surface::forAsset((int) $a->id);
        if (!$s) {
            return (int) $a->last_scan_at > 0 ? '' : Ui::card('<p class="mcs-muted">' . Lang::t('پس از اسکن «کشف سطح حمله» یا «بررسی سلامت پایه»، زیردامنه‌ها، درگاه‌های باز، فناوری‌ها و گواهی‌های این دارایی این‌جا دیده می‌شوند.') . '</p>', 'سطح حمله', 'radar');
        }
        $body = '<ul class="mcs-surface-sum">';
        foreach (Surface::KINDS as $k => $label) {
            if (!empty($s[$k])) {
                $body .= '<li><strong>' . self::e(Text::fa(count($s[$k]))) . '</strong><span>' . self::e($label) . '</span></li>';
            }
        }
        $body .= '</ul>';
        // the first completed scan is the baseline: what it found is not "new"
        $baseline = (int) Db::table('mod_mcsec_scans')->where('asset_id', $a->id)->where('status', 'completed')->min('id');
        foreach (Surface::KINDS as $k => $label) {
            if (empty($s[$k])) {
                continue;
            }
            $items = '';
            foreach (array_slice($s[$k], 0, 200) as $r) {
                $m = Surface::meta($r);
                $extra = match ($k) {
                    'port' => trim(($m['service'] ?? '') . ' ' . ($m['title'] ?? '') . ' ' . ($m['server'] ?? '')),
                    'cert' => trim(($m['not_after'] ?? '') !== '' ? Lang::t('انقضا: {date} — {issuer}', ['date' => Text::ymd((string) $m['not_after']), 'issuer' => (string) ($m['issuer'] ?? '')]) : (string) ($m['issuer'] ?? '')),
                    'url' => isset($m['status']) ? 'HTTP ' . $m['status'] . ' ' . ($m['title'] ?? '') : '',
                    default => '',
                };
                $isNew = (int) $r->first_seen_at > \McSec\Clock::now() - 7 * 86400 && $baseline > 0 && (int) $r->first_scan_id > $baseline;
                $mute = '';
                if ($k === 'host' && strtolower((string) $r->value) !== strtolower((string) $a->value)) {
                    $isMuted = (int) ($r->muted ?? 0) > 0;
                    $mute = ($isMuted ? ' ' . Ui::chip('کنار گذاشته', 'muted') : '') . ($canMute ? ' ' . Ui::form($ctx, 'asset', 'host_mute', '<input type="hidden" name="id" value="' . (int) $r->id . '"><input type="hidden" name="on" value="' . ($isMuted ? '0' : '1') . '">'
                        . '<button type="submit" class="btn btn-link btn-sm">' . ($isMuted ? Lang::t('برگردان') : Lang::t('مال من نیست')) . '</button>', $isMuted ? '' : Lang::t('میزبان {host} کنار گذاشته شود؟ دیگر اسکن نمی‌شود و یافته‌ای برایش ثبت نمی‌شود.', ['host' => (string) $r->value]), 'mcs-inline', false, '&amp;id=' . (int) $a->id) : '');
                }
                $items .= '<li>' . Ui::ltr($r->value) . ($isNew ? ' ' . Ui::chip('تازه', 'warn') : '') . $mute . ($extra !== '' ? '<small dir="auto">' . self::e($extra) . '</small>' : '') . '</li>';
            }
            $body .= Ui::drawer(Lang::t($label) . ' (' . Text::fa(count($s[$k])) . ')', '<ul class="mcs-surface">' . $items . '</ul>', false);
        }
        return Ui::card($body, 'سطح حمله', 'radar', '', '', Lang::t('آنچه از این دارایی روی اینترنت دیده می‌شود'));
    }
}
