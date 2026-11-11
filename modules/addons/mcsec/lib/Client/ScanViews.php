<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Assets;
use McSec\Catalog;
use McSec\Credits;
use McSec\Db;
use McSec\Findings;
use McSec\Plans;
use McSec\Scans;
use McSec\Schedules;
use McSec\Settings;
use McSec\Text;

/** Scans: the launcher (cost before the click), history, one run with live progress, and schedules. */
final class ScanViews
{
    private static function e($s): string
    {
        return Ui::e($s);
    }

    public static function statusChip(object $s): string
    {
        $tone = ['queued' => 'muted', 'running' => 'run', 'completed' => 'ok', 'failed' => 'err', 'cancelled' => 'muted'][$s->status] ?? 'muted';
        return Ui::chip(Scans::STATUS[$s->status] ?? $s->status, $tone);
    }

    /** History table (shared by the scans page and the asset page). */
    public static function table(array $scans, bool $withAsset = true): string
    {
        $rows = '';
        foreach ($scans as $s) {
            $sum = Scans::summary($s);
            $result = match ($s->status) {
                'completed' => self::e(Text::fa((int) ($sum['new'] ?? 0)) . ' تازه، ' . Text::fa((int) ($sum['fixed'] ?? 0)) . ' رفع‌شده'),
                'running' => Ui::meter((int) $s->progress, 100, self::e(Text::fa((int) $s->progress) . '٪')),
                'failed' => '<span class="mcs-small">' . self::e($s->error) . '</span>',
                default => '',
            };
            $rows .= '<tr>' . Ui::td('اسکن', '<a href="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $s->id . '">' . self::e(Catalog::all(true)[$s->profile]['label'] ?? $s->profile) . '</a>'
                    . ((int) $s->schedule_id > 0 ? ' ' . Ui::chip('خودکار', 'info') : ''))
                . ($withAsset ? Ui::td('دارایی', Ui::ltr($s->asset_value ?? '')) : '')
                . Ui::td('وضعیت', self::statusChip($s))
                . Ui::td('نتیجه', $result)
                . Ui::td('اعتبار', self::e((int) $s->credits > 0 ? Text::fa((int) $s->credits) : 'رایگان'))
                . Ui::td('زمان', self::e(Views::when((int) ($s->started_at ?: $s->queued_at))))
                . '</tr>';
        }
        return Ui::table($withAsset ? ['اسکن', 'دارایی', 'وضعیت', 'نتیجه', 'اعتبار', 'زمان'] : ['اسکن', 'وضعیت', 'نتیجه', 'اعتبار', 'زمان'], $rows);
    }

    public static function list(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $scans = Scans::recent($cid, 50);
        $out = Ui::guide('<p>هر اسکن روی یک دارایی تأییدشده اجرا می‌شود و به اندازه‌ی عمقش اعتبار مصرف می‌کند؛ هزینه را پیش از شروع می‌بینید. اسکن‌ها در پس‌زمینه اجرا می‌شوند: لازم نیست صفحه را باز نگه دارید، پس از پایان خبرتان می‌کنیم.</p>'
            . '<p>اگر اسکن به‌خاطر خطای سامانه تمام نشود، اعتبارش خودکار برمی‌گردد.</p>', !$scans);
        if ($ctx['manage']) {
            $out .= self::launcher($ctx);
        }
        if ($scans) {
            $out .= Ui::card(self::table($scans), 'تاریخچه‌ی اسکن‌ها', 'clock');
        }
        return $out;
    }

    private static function launcher(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $verified = Assets::forClient($cid, 'verified');
        if (!$verified) {
            return Ui::card(Ui::emptyState('globe', 'دارایی تأییدشده‌ای ندارید', 'اسکن فقط روی دارایی تأییدشده انجام می‌شود. اول دارایی بیفزایید و مالکیتش را تأیید کنید.',
                '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=assets#add">افزودن دارایی</a>'), 'اسکن تازه', 'play', '', '" id="new');
        }
        $pre = (int) Text::toAscii((string) ($_GET['asset'] ?? '0'));
        $bal = Credits::balance($cid);
        $assets = '<fieldset class="mcs-checks"><legend>' . Ui::ico('globe') . 'روی کدام دارایی‌ها؟</legend>';
        foreach ($verified as $a) {
            $assets .= '<label class="mcs-check"><input type="checkbox" name="assets[]" value="' . (int) $a->id . '" data-mcs-kind="' . self::e($a->kind) . '"' . ($pre === (int) $a->id || count($verified) === 1 ? ' checked' : '') . '>'
                . '<span>' . Ui::ltr($a->value) . (trim((string) $a->label) !== '' ? '<small>' . self::e($a->label) . '</small>' : '') . '</span></label>';
        }
        $assets .= '</fieldset>';
        $cards = '<fieldset class="mcs-profiles"><legend>' . Ui::ico('radar') . 'چه اسکنی؟</legend>';
        $first = true;
        foreach (Catalog::forClient($cid) as $k => $p) {
            $engineOk = Scans::engine($p['engine'])->configured();
            $disabled = !$p['allowed'] || !$engineOk;
            $why = !$p['allowed'] ? 'در پلن فعلی نیست' : (!$engineOk ? 'موقتاً در دسترس نیست' : '');
            $cards .= '<label class="mcs-profile' . ($disabled ? ' is-locked' : '') . '"><input type="radio" name="profile" value="' . self::e($k) . '" data-mcs-cost="' . (int) $p['credits'] . '" data-mcs-kinds="' . self::e(implode(',', $p['kinds'])) . '"'
                . ($disabled ? ' disabled' : '') . ($first && !$disabled ? ' checked' : '') . '>'
                . '<span class="mcs-profile-head"><span class="mcs-profile-ico">' . Ui::ico($p['icon'] ?? 'radar') . '</span><strong>' . self::e($p['label']) . '</strong>'
                . '<span class="mcs-profile-cost">' . ((int) $p['credits'] > 0 ? self::e(Text::fa((int) $p['credits'])) . ' اعتبار' : 'رایگان') . '</span></span>'
                . '<span class="mcs-profile-desc">' . self::e($p['desc']) . '</span>'
                . '<span class="mcs-profile-meta">' . Ui::ico('clock') . self::e($p['eta']) . ' · ' . self::e(implode('، ', array_map(fn ($x) => Assets::KINDS[$x] ?? $x, $p['kinds']))) . ($why !== '' ? ' · ' . Ui::ico('lock') . self::e($why) : '') . '</span></label>';
            $first = $first && $disabled;
        }
        $cards .= '</fieldset>';
        $acc = Accounts::get($cid);
        $terms = (int) $acc->terms_at === 0 ? '<label class="mcs-check mcs-terms"><input type="checkbox" name="terms" value="1" required><span>' . self::e(Settings::get('terms_text')) . '</span></label>' : '';
        $submit = '<div class="mcs-launch-foot"><button type="submit" class="btn btn-primary btn-lg" data-mcs-launch>' . Ui::ico('play') . '<span data-mcs-launch-text>شروع اسکن</span></button>'
            . '<span class="mcs-muted mcs-small" data-mcs-balance="' . (int) $bal['total'] . '">مانده‌ی اعتبار: ' . self::e(Text::fa($bal['total'])) . '</span></div>'
            . '<noscript><p class="mcs-help">هزینه‌ی کل = هزینه‌ی نوع اسکن × تعداد دارایی‌ها (بازه‌ی IP به ازای هر ۱۶ آدرس).</p></noscript>';
        return Ui::card(Ui::form($ctx, 'scans', 'scan_start', $assets . $cards . $terms . $submit, '', 'mcs-launcher'), 'اسکن تازه', 'play', '', '" id="new');
    }

    public static function detail(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $s = Scans::get($cid, (int) Text::toAscii((string) ($_GET['id'] ?? $_POST['scan'] ?? '0')));
        if (!$s) {
            return Views::missing('این اسکن', 'index.php?m=mcsec&p=scans', 'بازگشت به اسکن‌ها');
        }
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        $profile = Catalog::all(true)[$s->profile] ?? ['label' => $s->profile, 'eta' => '', 'desc' => ''];
        Views::$pageTitle = self::e($profile['label']) . ' ' . Ui::ltr($asset->value ?? '', 'mcs-title-ltr') . ' ' . self::statusChip($s);
        $out = '';
        if (isset($_GET['started']) && in_array($s->status, ['queued', 'running'], true)) {
            $out .= Ui::alert('success', 'اسکن ثبت شد' . ((int) $s->credits > 0 ? ' و ' . self::e(Text::fa((int) $s->credits)) . ' اعتبار کم شد' : '') . '. می‌توانید این صفحه را ببندید؛ پس از پایان خبرتان می‌کنیم.', 'check');
        }
        $live = in_array($s->status, ['queued', 'running'], true);
        if ($live) {
            $body = '<div data-mcs-progress="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $s->id . '&amp;progress=1">'
                . Ui::progress((int) $s->progress, $s->status === 'queued' ? 'در صف؛ به‌زودی شروع می‌شود' : (string) $s->stage, $s->status === 'running')
                . '<p class="mcs-small mcs-muted">زمان معمول این اسکن: ' . self::e($profile['eta']) . '. ' . ($s->status === 'running' ? 'شروع: ' . self::e(Views::when((int) $s->started_at)) : 'در صف از ' . self::e(Views::when((int) $s->queued_at))) . '</p>'
                . '<noscript><p class="mcs-help">برای دیدن پیشرفت تازه، صفحه را دوباره باز کنید.</p></noscript></div>';
            if ($ctx['manage']) {
                $body .= Ui::form($ctx, 'scan', 'scan_cancel', '<input type="hidden" name="scan" value="' . (int) $s->id . '"><button type="submit" class="btn btn-default btn-sm">' . Ui::ico('x') . 'لغو اسکن</button>',
                    $s->status === 'queued' ? 'این اسکن لغو شود؟ اعتبارش برمی‌گردد.' : 'این اسکن در حال اجراست؛ با لغو، اعتبار مصرف‌شده برنمی‌گردد. لغو شود؟', 'mcs-inline', false, '&amp;id=' . (int) $s->id);
            }
            $out .= Ui::card($body, 'پیشرفت', 'radar');
        } elseif ($s->status === 'failed') {
            $out .= Ui::alert('danger', self::e($s->error) . ($s->error_ref !== '' ? ' کد پیگیری: ' . Ui::ltr($s->error_ref) : '')
                . ((int) $s->credits > 0 && Settings::bool('refund_on_fail') ? ' اعتبار این اسکن برگشت داده شد.' : ''), 'alert');
        }
        if ($s->status === 'completed') {
            $sum = Scans::summary($s);
            $out .= '<div class="mcs-grid3">' . Ui::card('<ul class="mcs-diff"><li><strong>' . self::e(Text::fa((int) ($sum['new'] ?? 0))) . '</strong><span>تازه</span></li><li class="is-ok"><strong>' . self::e(Text::fa((int) ($sum['fixed'] ?? 0)))
                . '</strong><span>رفع‌شده</span></li><li class="is-warn"><strong>' . self::e(Text::fa((int) ($sum['reopened'] ?? 0))) . '</strong><span>دوباره دیده‌شده</span></li></ul>', 'نسبت به قبل', 'activity')
                . Ui::card(Ui::sevCounts((array) ($sum['open'] ?? []), 'index.php?m=mcsec&p=findings&asset=' . (int) $s->asset_id), 'یافته‌های باز این دارایی', 'bug')
                . Ui::card(Ui::facts(['شروع' => self::e(Text::date((int) $s->started_at)), 'پایان' => self::e(Text::date((int) $s->finished_at)), 'مدت' => self::e(self::duration((int) $s->finished_at - (int) $s->started_at)),
                    'موتور' => self::e(Catalog::engineLabel((string) $s->engine)), 'سطح دیده‌شده' => self::e(Text::fa((int) ($sum['surface_seen'] ?? 0)) . ' مورد' . ((int) ($sum['surface_new'] ?? 0) > 0 ? '، ' . Text::fa((int) $sum['surface_new']) . ' تازه' : ''))]), 'جزئیات', 'info') . '</div>';
            $new = Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('first_scan_id', $s->id)->orderByRaw("CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC")->limit(30));
            if ($new) {
                $list = '';
                foreach ($new as $f) {
                    $list .= '<li><a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '">' . Ui::sev((string) $f->severity) . '<span class="mcs-todo-title">' . self::e($f->title) . '</span></a><span class="mcs-todo-meta">' . Ui::ltr($f->location) . '</span></li>';
                }
                $out .= Ui::card('<ol class="mcs-todo">' . $list . '</ol>', 'یافته‌هایی که این اسکن برای اولین بار دید', 'bug', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings&amp;scan=' . (int) $s->id . '&amp;status=all">همه</a>');
            } elseif ((int) ($sum['seen'] ?? 0) === 0) {
                $out .= Ui::card(Ui::emptyState('shield-check', 'این اسکن مشکلی پیدا نکرد', 'آفرین. با زمان‌بندی، اسکن‌های بعدی را خودکار بگیرید.'));
            }
            $reports = Db::rows(Db::table('mod_mcsec_reports')->where('client_id', $cid)->where('scan_id', $s->id)->orderByDesc('id'));
            $rep = '';
            foreach ($reports as $r) {
                $rep .= '<li><a href="index.php?m=mcsec&amp;p=report&amp;id=' . (int) $r->id . '">' . self::e($r->title) . '</a> ' . ((int) $r->ai ? Ui::chip('هوش مصنوعی', 'info') : Ui::chip('پایه')) . '</li>';
            }
            $aiOk = \McSec\Ai::configured() && Plans::limits($cid)['ai'];
            $form = $ctx['manage'] && $aiOk ? Ui::form($ctx, 'scan', 'report_create', '<input type="hidden" name="scan" value="' . (int) $s->id . '"><input type="hidden" name="ai" value="1"><button type="submit" class="btn btn-primary">'
                . Ui::ico('sparkle') . 'گزارش هوش مصنوعی' . (Settings::int('ai_report_cost') > 0 ? ' · ' . self::e(Text::fa(Settings::int('ai_report_cost'))) . ' اعتبار' : '') . '</button>', '', 'mcs-inline', false, '&amp;id=' . (int) $s->id) : '';
            $out .= Ui::card(($rep !== '' ? '<ul class="mcs-plain">' . $rep . '</ul>' : '<p class="mcs-muted">گزارش پایه پس از پایان اسکن خودکار ساخته می‌شود.</p>') . $form, 'گزارش', 'file');
        }
        if ($ctx['manage'] && in_array($s->status, ['completed', 'failed', 'cancelled'], true) && $asset && $asset->status === 'verified') {
            Views::$pageActions = Ui::form($ctx, 'scans', 'scan_start', '<input type="hidden" name="asset" value="' . (int) $s->asset_id . '"><input type="hidden" name="profile" value="' . self::e($s->profile) . '">'
                . '<button type="submit" class="btn btn-default">' . Ui::ico('refresh') . 'دوباره' . ((int) (Catalog::get((string) $s->profile)['credits'] ?? 0) > 0 ? ' · ' . self::e(Text::fa((int) Catalog::get((string) $s->profile)['credits'])) . ' اعتبار' : '') . '</button>', '', 'mcs-inline');
        }
        return $out;
    }

    private static function duration(int $sec): string
    {
        if ($sec <= 0) {
            return '—';
        }
        if ($sec < 120) {
            return Text::fa($sec) . ' ثانیه';
        }
        if ($sec < 7200) {
            return Text::fa((int) round($sec / 60)) . ' دقیقه';
        }
        return Text::fa(round($sec / 3600, 1)) . ' ساعت';
    }

    public static function schedules(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $list = Schedules::forClient($cid);
        $lim = Plans::limits($cid);
        $out = Ui::guide('<p>اسکن‌های تکراری را این‌جا تنظیم کنید تا هر تغییر (یافته‌ی تازه، درگاه تازه، گواهی رو به انقضا) خودکار پیدا و خبرش به شما داده شود. هر اجرا به اندازه‌ی همان اسکن اعتبار مصرف می‌کند؛ اگر اعتبار کافی نباشد، زمان‌بندی متوقف و خبرتان می‌شود.</p>'
            . '<p>اگر «همه‌ی دارایی‌های تأییدشده» را انتخاب کنید، دارایی‌هایی که بعداً بیفزایید هم خودکار در زمان‌بندی می‌آیند.</p>', !$list);
        $rows = '';
        foreach ($list as $s) {
            $asset = (int) $s->asset_id > 0 ? Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->value('value') : null;
            $status = $s->status === 'active' ? Ui::chip('فعال', 'ok') : Ui::chip('متوقف: ' . (Schedules::PAUSE[$s->pause_reason] ?? 'متوقف'), 'warn');
            $actions = '';
            if ($ctx['manage']) {
                $actions = Ui::form($ctx, 'schedules', 'schedule_toggle', '<input type="hidden" name="id" value="' . (int) $s->id . '"><input type="hidden" name="active" value="' . ($s->status === 'active' ? '0' : '1') . '">'
                        . '<button type="submit" class="btn btn-default btn-sm">' . Ui::ico($s->status === 'active' ? 'pause' : 'play') . ($s->status === 'active' ? 'توقف' : 'ادامه') . '</button>', '', 'mcs-inline')
                    . Ui::form($ctx, 'schedules', 'schedule_delete', '<input type="hidden" name="id" value="' . (int) $s->id . '"><button type="submit" class="btn btn-default btn-sm btn-danger-text">' . Ui::ico('trash') . '<span class="mcs-sr">حذف</span></button>',
                        'این زمان‌بندی حذف شود؟', 'mcs-inline');
            }
            $rows .= '<tr>' . Ui::td('اسکن', self::e(Catalog::all(true)[$s->profile]['label'] ?? $s->profile))
                . Ui::td('دارایی', $asset !== null ? Ui::ltr($asset) : self::e('همه‌ی دارایی‌های تأییدشده'))
                . Ui::td('تکرار', self::e(Schedules::describe($s)))
                . Ui::td('اجرای بعدی', self::e($s->status === 'active' ? Text::date((int) $s->next_run_at) : '—'))
                . Ui::td('وضعیت', $status) . Ui::td('', '<div class="mcs-actions">' . $actions . '</div>') . '</tr>';
        }
        if ($rows !== '') {
            $out .= Ui::card(Ui::table(['اسکن', 'دارایی', 'تکرار', 'اجرای بعدی', 'وضعیت', ''], $rows), 'زمان‌بندی‌های شما', 'calendar');
        }
        if (!$ctx['manage']) {
            return $out;
        }
        $assets = ['0' => 'همه‌ی دارایی‌های تأییدشده'];
        foreach (Assets::forClient($cid, 'verified') as $a) {
            $assets[(string) $a->id] = (string) $a->value;
        }
        $profiles = [];
        foreach (Catalog::forClient($cid) as $k => $p) {
            if ($p['allowed']) {
                $profiles[$k] = $p['label'] . ((int) $p['credits'] > 0 ? ' — ' . Text::fa((int) $p['credits']) . ' اعتبار هر اجرا' : ' — رایگان');
            }
        }
        $freqs = [];
        foreach (Schedules::FREQ as $k => $f) {
            if ($f['hours'] >= $lim['min_interval_h']) {
                $freqs[$k] = $f['label'];
            }
        }
        $hours = [];
        for ($h = 0; $h < 24; $h++) {
            $hours[(string) $h] = Text::fa(sprintf('%02d:00', $h));
        }
        $dom = [];
        for ($d = 1; $d <= 28; $d++) {
            $dom[(string) $d] = 'روز ' . Text::fa($d);
        }
        $body = '<div class="mcs-form-row">' . Ui::field('mcs-sa', 'دارایی', Ui::select('asset', $assets, '0', 'mcs-sa'))
            . Ui::field('mcs-sp', 'نوع اسکن', Ui::select('profile', $profiles, isset($profiles['surface']) ? 'surface' : (string) array_key_first($profiles), 'mcs-sp')) . '</div>'
            . '<div class="mcs-form-row">' . Ui::field('mcs-sf', 'تکرار', Ui::select('freq', $freqs, isset($freqs['weekly']) ? 'weekly' : (string) array_key_first($freqs), 'mcs-sf'),
                count($freqs) < 3 ? 'اسکن روزانه در پلن‌های بالاتر است.' : '')
            . Ui::field('mcs-sw', 'روز هفته (برای هفتگی)', Ui::select('dow', array_map('strval', Schedules::DOW), '6', 'mcs-sw'))
            . Ui::field('mcs-sd', 'روز ماه (برای ماهانه)', Ui::select('dom', $dom, '1', 'mcs-sd'))
            . Ui::field('mcs-sh', 'ساعت (به وقت تهران)', Ui::select('hour', $hours, '3', 'mcs-sh'), 'ساعت‌های کم‌بازدید شب برای سایت بهترند.') . '</div>'
            . '<button type="submit" class="btn btn-primary">' . Ui::ico('calendar') . 'ساختن زمان‌بندی</button>';
        $out .= count($assets) > 1 ? Ui::card(Ui::form($ctx, 'schedules', 'schedule_save', $body), 'زمان‌بندی تازه', 'plus')
            : Ui::card(Ui::emptyState('globe', 'دارایی تأییدشده‌ای ندارید', 'زمان‌بندی پس از تأیید اولین دارایی ممکن است.', '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=assets#add">افزودن دارایی</a>'));
        return $out;
    }
}
