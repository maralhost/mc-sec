<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Assets;
use McSec\Catalog;
use McSec\Credits;
use McSec\Db;
use McSec\Findings;
use McSec\Lang;
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

    /** "دامنه، IP" / "Domain, IP": the asset kinds a scan or a tool accepts. */
    private static function kinds(array $kinds): string
    {
        return Lang::join(array_map(fn ($x) => Lang::t((string) (Assets::KINDS[$x] ?? $x)), $kinds));
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
                'completed' => self::e(Lang::t('{new} تازه، {fixed} رفع‌شده', ['new' => Text::fa((int) ($sum['new'] ?? 0)), 'fixed' => Text::fa((int) ($sum['fixed'] ?? 0))])),
                'running' => Ui::meter((int) $s->progress, 100, Lang::t('{n}٪', ['n' => self::e(Text::fa((int) $s->progress))])),
                'failed' => '<span class="mcs-small">' . self::e($s->error) . '</span>',
                default => '',
            };
            $rows .= '<tr>' . Ui::td('اسکن', '<a href="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $s->id . '">' . self::e(Catalog::label((string) ($s->profile))) . '</a>'
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
        $out = Ui::guide('<p>' . Lang::t('هر اسکن روی یک دارایی تأییدشده اجرا می‌شود و به اندازه‌ی عمقش اعتبار مصرف می‌کند؛ هزینه را پیش از شروع می‌بینید. اسکن‌ها در پس‌زمینه اجرا می‌شوند: لازم نیست صفحه را باز نگه دارید، پس از پایان خبرتان می‌کنیم.') . '</p>'
            . '<p>' . Lang::t('اگر اسکن به‌خاطر خطای سامانه تمام نشود، اعتبارش خودکار برمی‌گردد.') . '</p>', !$scans);
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
            return Ui::card(Ui::emptyState('globe', 'دارایی تأییدشده‌ای ندارید', Lang::t('اسکن فقط روی دارایی تأییدشده انجام می‌شود. اول دارایی بیفزایید و مالکیتش را تأیید کنید.'),
                '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=assets#add">' . Lang::t('افزودن دارایی') . '</a>'), 'اسکن تازه', 'play', '', '" id="new');
        }
        $pre = (int) Text::toAscii((string) ($_GET['asset'] ?? '0'));
        $bal = Credits::balance($cid);
        $assets = '<fieldset class="mcs-checks"><legend>' . Ui::ico('globe') . Lang::t('روی کدام دارایی‌ها؟') . '</legend>';
        foreach ($verified as $a) {
            $assets .= '<label class="mcs-check"><input type="checkbox" name="assets[]" value="' . (int) $a->id . '" data-mcs-kind="' . self::e($a->kind) . '"' . ($pre === (int) $a->id || count($verified) === 1 ? ' checked' : '') . '>'
                . '<span>' . Ui::ltr($a->value) . (trim((string) $a->label) !== '' ? '<small>' . self::e($a->label) . '</small>' : '') . '</span></label>';
        }
        $assets .= '</fieldset>';
        $mine = Catalog::forClient($cid);
        $kindsHere = array_values(array_unique(array_map(fn ($a) => (string) $a->kind, $verified)));
        $want = array_filter(array_map('strval', (array) ($_POST['profiles'] ?? (isset($_GET['profile']) ? [$_GET['profile']] : []))));
        $card = function (string $k, array $p) use ($want): string {
            $engineOk = Scans::engine($p['engine'])->configured();
            $disabled = !$p['allowed'] || !$engineOk;
            $why = !$p['allowed'] ? 'در پلن فعلی نیست' : (!$engineOk ? 'موقتاً در دسترس نیست' : '');
            return '<label class="mcs-profile' . ($disabled ? ' is-locked' : '') . '"><input type="checkbox" name="profiles[]" value="' . self::e($k) . '" data-mcs-cost="' . (int) $p['credits'] . '" data-mcs-kinds="' . self::e(implode(',', $p['kinds'])) . '"'
                . ($disabled ? ' disabled' : '') . (!$disabled && in_array($k, $want, true) ? ' checked' : '') . '>'
                . '<span class="mcs-profile-head"><span class="mcs-profile-ico">' . Ui::ico($p['icon'] ?? 'radar') . '</span><strong>' . self::e($p['label']) . '</strong>'
                . '<span class="mcs-profile-cost">' . ((int) $p['credits'] > 0 ? Lang::t('{n} اعتبار', ['n' => self::e(Text::fa((int) $p['credits']))]) : Lang::t('رایگان')) . '</span></span>'
                . '<span class="mcs-profile-desc">' . self::e($p['desc']) . (Catalog::risk($p) === 'heavy' ? ' ' . Ui::chip('درخواست زیاد به هدف', 'warn') : '') . '</span>'
                . '<span class="mcs-profile-meta">' . Ui::ico('clock') . self::e($p['eta']) . ' · ' . self::e(self::kinds($p['kinds']))
                . ($why !== '' ? ' · ' . Ui::ico('lock') . self::e($why) : '') . '</span></label>';
        };
        // 1. the ready-made picks: what most people need, one click
        $bundles = Catalog::bundles(array_filter($mine, fn ($p) => array_intersect($p['kinds'], $kindsHere)));
        $bcards = '';
        $pre = !$want && $bundles ? (isset($bundles['b_standard']) ? 'b_standard' : array_key_first($bundles)) : '';
        foreach ($bundles as $bk => $b) {
            $names = Lang::join(array_map(fn ($k) => Lang::t((string) $mine[$k]['label']), $b['profiles']));
            $bcards .= '<label class="mcs-profile mcs-bundle"><input type="checkbox" name="bundles[]" value="' . self::e($bk) . '" data-mcs-bundle="' . self::e(implode(',', $b['profiles'])) . '"' . ($bk === $pre ? ' checked' : '') . '>'
                . '<span class="mcs-profile-head"><strong>' . self::e($b['label']) . '</strong>' . ($bk === 'b_standard' ? Ui::chip('پیشنهاد ما', 'info') : '')
                . '<span class="mcs-profile-cost">' . ($b['credits'] > 0 ? Lang::t('{n} اعتبار', ['n' => self::e(Text::fa($b['credits']))]) : Lang::t('رایگان')) . '</span></span>'
                . '<span class="mcs-profile-desc">' . self::e($b['desc']) . '</span><span class="mcs-profile-meta">' . Ui::ico('layers') . self::e($names) . '</span></label>';
        }
        $cards = $bcards !== '' ? '<fieldset class="mcs-profiles"><legend>' . Ui::ico('radar') . Lang::t('چه اسکنی؟') . '</legend>' . $bcards . '</fieldset>' : '';
        // 2. everything, by category; open only when there is no bundle or something was ticked there
        $groups = '';
        $total = 0;
        foreach (Catalog::grouped($mine) as $cat => $list) {
            [$cl, $cd, $ci] = Catalog::CATEGORIES[$cat];
            $inner = '';
            foreach ($list as $k => $p) {
                $inner .= $card((string) $k, $p);
                $total++;
            }
            $groups .= '<fieldset class="mcs-profiles mcs-cat"><legend>' . Ui::ico($ci) . self::e($cl) . ' <span class="mcs-small mcs-muted">' . self::e($cd) . '</span></legend>' . $inner . '</fieldset>';
        }
        $open = $bcards === '' || $want;
        $cards .= $bcards !== ''
            ? '<details class="mcs-drawer mcs-allscans"' . ($open ? ' open' : '') . '><summary>' . Ui::ico('list') . Lang::t('انتخاب دقیق‌تر: همه‌ی اسکن‌ها ({n} نوع، بر اساس دسته)', ['n' => self::e(Text::fa($total))]) . '</summary><div class="mcs-drawer-body">'
                . '<p class="mcs-help">' . Lang::t('هر چند تا را می‌خواهید تیک بزنید؛ هزینه‌ها جمع می‌شود و روی دکمه‌ی شروع می‌بینید. اسکنی که برای نوع دارایی انتخاب‌شده نیست، برای آن دارایی اجرا نمی‌شود.') . '</p>' . $groups . '</div></details>'
            : $groups;
        $cards .= \McSec\Recipes::allowed($cid) ? '<p class="mcs-help">' . Ui::ico('layers') . Lang::t('ترکیب دیگری می‌خواهید؟ <a href="index.php?m=mcsec&amp;p=recipes">اسکن سفارشی خودتان را بسازید</a>.') . '</p>' : '';
        $acc = Accounts::get($cid);
        $terms = (int) $acc->terms_at === 0 ? '<label class="mcs-check mcs-terms"><input type="checkbox" name="terms" value="1" required><span>' . self::e(Settings::get('terms_text')) . '</span></label>' : '';
        $submit = '<div class="mcs-launch-foot"><button type="submit" class="btn btn-primary btn-lg" data-mcs-launch>' . Ui::ico('play') . '<span data-mcs-launch-text>' . Lang::t('شروع اسکن') . '</span></button>'
            . '<span class="mcs-muted mcs-small" data-mcs-balance="' . (int) $bal['total'] . '">' . Lang::t('مانده‌ی اعتبار: {n}', ['n' => self::e(Text::fa($bal['total']))]) . '</span></div>'
            . '<noscript><p class="mcs-help">' . Lang::t('هزینه‌ی کل = جمع هزینه‌ی اسکن‌های انتخاب‌شده × تعداد دارایی‌ها (بازه‌ی IP به ازای هر ۱۶ آدرس).') . '</p></noscript>';
        return Ui::card(Ui::form($ctx, 'scans', 'scan_start', $assets . $cards . $terms . $submit, '', 'mcs-launcher'), 'اسکن تازه', 'play', '', '" id="new');
    }

    /** Advanced mode: the account's own scans and the builder (works without JavaScript: ticks and selects). */
    public static function recipes(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $guide = '<p>' . Lang::t('در حالت پیشرفته خودتان انتخاب می‌کنید کدام ابزارها روی دارایی‌تان اجرا شوند. اسکنی که می‌سازید ذخیره می‌شود و مثل اسکن‌های آماده در «اسکن‌ها» و «زمان‌بندی‌ها» دیده می‌شود.') . '</p>'
            . '<p>' . Lang::t('ترتیب اجرا را خودمان می‌چینیم (اول پیدا کردن صفحه‌ها، بعد سنجیدن آن‌ها). هزینه = جمع هزینه‌ی ابزارها برای هر دارایی. اسکن فقط روی دارایی تأییدشده‌ی خودتان اجرا می‌شود و سرعت ابزارها از حد ایمن بالاتر نمی‌رود.') . '</p>';
        if (!\McSec\Recipes::allowed($cid)) {
            return Ui::guide($guide, true) . Ui::card(Ui::emptyState('layers', 'اسکن سفارشی برای حساب‌های دارای پلن است', Lang::t('با پلن امنیت سایبری می‌توانید از ابزارهای اسکن، ترکیب دلخواه خودتان را بسازید.'),
                '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=credits">' . Lang::t('دیدن پلن و اعتبار') . '</a>'));
        }
        $mine = \McSec\Recipes::forClient($cid);
        $out = Ui::guide($guide, !$mine);
        if (isset($_GET['saved'])) {
            $out .= Ui::alert('success', Lang::t('اسکن سفارشی ذخیره شد. برای اجرا به <a href="index.php?m=mcsec&amp;p=scans#new">اسکن تازه</a> بروید و آن را انتخاب کنید.'), 'check');
        }
        if ($mine) {
            $rows = '';
            foreach ($mine as $r) {
                $p = \McSec\Recipes::profile($r);
                $act = $ctx['manage'] ? '<div class="mcs-actions"><a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=recipes&amp;edit=' . (int) $r->id . '#build">' . Lang::t('ویرایش') . '</a>'
                    . Ui::form($ctx, 'recipes', 'recipe_remove', '<input type="hidden" name="id" value="' . (int) $r->id . '"><button type="submit" class="btn btn-default btn-sm">' . Lang::t('حذف') . '</button>', Lang::t('اسکن سفارشی «{name}» حذف شود؟', ['name' => $r->name]), 'mcs-inline') . '</div>' : '';
                $rows .= '<tr>' . Ui::td('نام', '<strong dir="auto">' . self::e($r->name) . '</strong>' . (!$p['enabled'] ? ' ' . Ui::chip('یکی از ابزارها در دسترس نیست', 'warn') : ''))
                    . Ui::td('ابزارها', Ui::ltr(implode(' → ', array_map(fn ($t) => Catalog::TOOLS[$t]['label'], $p['tools']))) . (Catalog::risk($p) === 'heavy' ? ' ' . Ui::chip('درخواست زیاد به هدف', 'warn') : ''))
                    . Ui::td('برای', self::e(self::kinds($p['kinds'])))
                    . Ui::td('هزینه', self::e(Lang::t('{n} اعتبار برای هر دارایی', ['n' => Text::fa(\McSec\Rules::cost($cid, (int) $p['credits']))]))) . Ui::td('', $act) . '</tr>';
            }
            $out .= Ui::card(Ui::table(['نام', 'ابزارها', 'برای', 'هزینه', ''], $rows), 'اسکن‌های سفارشی شما', 'layers',
                '<a class="btn btn-primary btn-sm" href="index.php?m=mcsec&amp;p=scans#new">' . Ui::ico('play') . Lang::t('اجرا') . '</a>');
        }
        if (!$ctx['manage']) {
            return $out;
        }
        $edit = \McSec\Recipes::get($cid, (int) Text::toAscii((string) ($_GET['edit'] ?? '0')));
        $has = $edit ? explode(',', (string) $edit->tools) : [];
        $chosen = $edit ? \McSec\Db::decode((string) $edit->options, []) : [];
        $tools = \McSec\Recipes::tools();
        if (!$tools) {
            return $out . Ui::card('<p class="mcs-muted">' . Lang::t('فعلاً ابزاری برای اسکن سفارشی در دسترس نیست. کمی بعد دوباره سر بزنید.') . '</p>','ساختن اسکن سفارشی', 'layers');
        }
        $list = '<fieldset class="mcs-tools"><legend>' . Ui::ico('layers') . Lang::t('کدام ابزارها؟ (تا {n} ابزار)', ['n' => self::e(Text::fa(\McSec\Recipes::MAX_TOOLS))]) . '</legend>';
        foreach ($tools as $name => $t) {
            $opts = '';
            foreach (\McSec\Recipes::OPTIONS[$name] ?? [] as $o => [$label, $choices]) {
                $id = 'mcs-o-' . $name . '-' . $o;
                $opts .= '<label class="mcs-tool-opt" for="' . $id . '"><span>' . self::e($label) . '</span>'
                    . Ui::select('opt[' . $name . '][' . $o . ']', array_map(fn ($c) => $c[0], $choices), (string) ($chosen[$name][$o] ?? array_key_first($choices)), $id) . '</label>';
            }
            $list .= '<div class="mcs-tool"><label class="mcs-check"><input type="checkbox" name="tools[]" value="' . self::e($name) . '"' . (in_array($name, $has, true) ? ' checked' : '') . '>'
                . '<span><strong>' . Ui::ltr($t['label']) . '</strong> ' . self::e($t['what']) . '<small>' . self::e(Lang::t('{n} اعتبار · {risk} · برای {kinds}', ['n' => Text::fa((int) $t['credits']), 'risk' => Lang::t(Catalog::RISK[$t['risk']]), 'kinds' => self::kinds($t['kinds'])])) . '</small></span></label>'
                . ($opts !== '' ? '<div class="mcs-tool-opts">' . $opts . '</div>' : '') . '</div>';
        }
        $list .= '</fieldset>';
        $form = Ui::form($ctx, 'recipes', 'recipe_save', ($edit ? '<input type="hidden" name="id" value="' . (int) $edit->id . '">' : '')
            . Ui::field('mcs-rname', 'نام این اسکن', '<input class="form-control" id="mcs-rname" name="name" maxlength="80" dir="auto" value="' . self::e($edit->name ?? '') . '" placeholder="' . self::e(Lang::t('مثلاً بررسی هفتگی فروشگاه')) . '">')
            . $list . '<p class="mcs-help">' . Lang::t('ابزارهایی که نوع دارایی مشترک ندارند (مثلاً یکی فقط دامنه و دیگری فقط IP) با هم ذخیره نمی‌شوند.') . '</p>'
            . '<div class="mcs-actions"><button type="submit" class="btn btn-primary">' . ($edit ? Lang::t('ذخیره‌ی تغییرها') : Lang::t('ذخیره‌ی اسکن سفارشی')) . '</button>'
            . ($edit ? '<a class="btn btn-default" href="index.php?m=mcsec&amp;p=recipes">' . Lang::t('انصراف') . '</a>' : '') . '</div>');
        return $out . Ui::card($form, $edit ? Lang::t('ویرایش «{name}»', ['name' => $edit->name]) : 'ساختن اسکن سفارشی', 'layers', '', '" id="build');
    }
    /**
     * The path of a scan as steps for Charts::pipeline: queue, getting to know the asset (engines that discover first),
     * the tools as one step (their names shown, their state not guessed one by one), reading the result.
     * @return array{0:array<int,array{label:string,sub?:string}>,1:int,2:string} steps, active index, state
     */
    public static function path(object $s, array $profile): array
    {
        $tools = array_values(array_filter(array_map(fn ($t) => Catalog::TOOLS[$t]['label'] ?? '', (array) ($profile['tools'] ?? []))));
        $builtin = (string) $s->engine === 'builtin';
        $steps = [['label' => 'در صف']];
        if (!$builtin) {
            $steps[] = ['label' => 'شناخت دارایی'];
        }
        $steps[] = ['label' => $builtin ? 'بررسی‌های پایه' : 'اجرای ابزارها', 'sub' => $tools ? implode(' ', array_map(fn ($t) => '<bdi dir="ltr" class="mcs-tag">' . self::e($t) . '</bdi>', $tools)) : ''];
        $steps[] = ['label' => 'خواندن و تحلیل نتیجه'];
        $toolStep = $builtin ? 1 : 2;
        $p = (int) $s->progress;
        $active = (string) $s->status === 'queued' || (int) $s->started_at === 0 ? 0 : ($p <= 2 && !$builtin ? 1 : ($p < 96 ? $toolStep : $toolStep + 1));
        $state = match ((string) $s->status) {
            'completed' => 'done', 'failed' => 'fail', 'cancelled' => 'stop', default => 'run',
        };
        return [$steps, $active, $state];
    }

    public static function detail(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $s = Scans::get($cid, (int) Text::toAscii((string) ($_GET['id'] ?? $_POST['scan'] ?? '0')));
        if (!$s) {
            return Views::missing('این اسکن', 'index.php?m=mcsec&p=scans', 'بازگشت به اسکن‌ها');
        }
        $asset = Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->first();
        $profile = Catalog::find((string) $s->profile) ?? ['label' => $s->profile, 'eta' => '', 'desc' => ''];
        Views::$pageTitle = self::e($profile['label']) . ' ' . Ui::ltr($asset->value ?? '', 'mcs-title-ltr') . ' ' . self::statusChip($s);
        $out = '';
        // a scan of the real server behind a CDN domain says which domain it is for
        $for = $asset && $asset->kind === 'ip' ? Db::rows(Db::table('mod_mcsec_assets')->where('client_id', $cid)->where('origin_id', $asset->id)->where('status', '!=', 'removed')->limit(5)) : [];
        if ($for) {
            $out .= '<p class="mcs-small mcs-muted">' . Lang::t('سرور اصلی {domains} (پشت CDN): اسکن‌هایی که درگاه‌ها را می‌سنجند روی این IP اجرا می‌شوند، نه سرورهای CDN.', ['domains' => Lang::join(array_map(fn ($d) => Ui::ltr($d->value), $for))]) . '</p>';
        }
        if (isset($_GET['started']) && in_array($s->status, ['queued', 'running'], true)) {
            $out .= Ui::alert('success', (int) $s->credits > 0
                ? Lang::t('اسکن ثبت شد و {n} اعتبار کم شد. می‌توانید این صفحه را ببندید؛ پس از پایان خبرتان می‌کنیم.', ['n' => self::e(Text::fa((int) $s->credits))])
                : Lang::t('اسکن ثبت شد. می‌توانید این صفحه را ببندید؛ پس از پایان خبرتان می‌کنیم.'), 'check');
        }
        $went = (string) (\McSec\Db::decode((string) $s->backend_meta, [])['result']['direct'] ?? '');
        if ($went !== '') {
            $out .= '<p class="mcs-small mcs-muted">' . Ui::ico('server') . ' ' . Lang::t('بررسی‌های وب این اسکن مستقیم از سرور اصلی {ip} پرسیده شد، نه از CDN.', ['ip' => Ui::ltr($went)]) . '</p>';
        }
        $live = in_array($s->status, ['queued', 'running'], true);
        if ($live) {
            $body = '<div data-mcs-progress="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $s->id . '&amp;progress=1">'
                . Ui::progress((int) $s->progress, $s->status === 'queued' ? 'در صف؛ به‌زودی شروع می‌شود' : (string) $s->stage, $s->status === 'running')
                . Charts::pipeline(...self::path($s, $profile))
                . '<p class="mcs-small mcs-muted">' . Lang::t('زمان معمول این اسکن: {eta}.', ['eta' => self::e($profile['eta'])]) . ' '
                    . ($s->status === 'running' ? Lang::t('شروع: {when}', ['when' => self::e(Views::when((int) $s->started_at))]) : Lang::t('در صف از {when}', ['when' => self::e(Views::when((int) $s->queued_at))])) . '</p>'
                . '<noscript><p class="mcs-help">' . Lang::t('برای دیدن پیشرفت تازه، صفحه را دوباره باز کنید.') . '</p></noscript></div>';
            if ($ctx['manage']) {
                $body .= Ui::form($ctx, 'scan', 'scan_cancel', '<input type="hidden" name="scan" value="' . (int) $s->id . '"><button type="submit" class="btn btn-default btn-sm">' . Ui::ico('x') . Lang::t('لغو اسکن') . '</button>',
                    $s->status === 'queued' ? 'این اسکن لغو شود؟ اعتبارش برمی‌گردد.' : 'این اسکن در حال اجراست؛ با لغو، اعتبار مصرف‌شده برنمی‌گردد. لغو شود؟', 'mcs-inline', false, '&amp;id=' . (int) $s->id);
            }
            $out .= Ui::card($body, 'پیشرفت', 'radar');
        } elseif ($s->status === 'failed') {
            $out .= Ui::alert('danger', self::e($s->error) . ($s->error_ref !== '' ? ' ' . Lang::t('کد پیگیری: {ref}', ['ref' => Ui::ltr($s->error_ref)]) : '')
                . ((int) $s->credits > 0 && Settings::bool('refund_on_fail') ? ' ' . Lang::t('اعتبار این اسکن برگشت داده شد.') : '') . ' ' . SupportViews::link('&topic=scan&scan=' . (int) $s->id), 'alert');
        }
        if (!$live && (int) $s->started_at > 0) {
            $out .= Ui::card(Charts::pipeline(...self::path($s, $profile)), 'مسیر این اسکن', 'radar');
        }
        if ($s->status === 'completed') {
            $sum = Scans::summary($s);
            $partial = trim((string) ($sum['partial'] ?? ''));
            if ($partial !== '') {
                $out .= Ui::alert('warning', Lang::t('<strong>ارزیابی ناقص.</strong> {why} این اسکن «سالم» به حساب نمی‌آید و یافته‌هایی که این بار سنجیده نشدند باز می‌مانند تا اسکن کامل بعدی.', ['why' => Ui::plain($partial)])
                    . ((int) ($sum['refunded'] ?? 0) > 0 ? ' ' . Lang::t('{n} اعتبار این اسکن به حسابتان برگشت.', ['n' => self::e(Text::fa((int) $sum['refunded']))]) : '')
                    . (trim(Settings::get('scanner_ips')) !== '' ? ' <a href="index.php?m=mcsec&amp;p=scanner" target="_blank" rel="noopener">' . Lang::t('IPهای اسکنر برای مجاز کردن') . '</a>' : '') . ' ' . SupportViews::link('&topic=scan&scan=' . (int) $s->id), 'alert');
            }
            $out .= '<div class="mcs-grid3">' . Ui::card('<ul class="mcs-diff"><li><strong>' . self::e(Text::fa((int) ($sum['new'] ?? 0))) . '</strong><span>' . Lang::t('تازه') . '</span></li><li class="is-ok"><strong>' . self::e(Text::fa((int) ($sum['fixed'] ?? 0)))
                . '</strong><span>' . Lang::t('رفع‌شده') . '</span></li><li class="is-warn"><strong>' . self::e(Text::fa((int) ($sum['reopened'] ?? 0))) . '</strong><span>' . Lang::t('دوباره دیده‌شده') . '</span></li></ul>', 'نسبت به قبل', 'activity')
                . Ui::card(Ui::sevCounts((array) ($sum['open'] ?? []), 'index.php?m=mcsec&p=findings&asset=' . (int) $s->asset_id), 'یافته‌های باز این دارایی', 'bug')
                . Ui::card(Ui::facts(['شروع' => self::e(Text::date((int) $s->started_at)), 'پایان' => self::e(Text::date((int) $s->finished_at)), 'مدت' => self::e(self::duration((int) $s->finished_at - (int) $s->started_at)),
                    'موتور' => self::e(Catalog::engineLabel((string) $s->engine)), 'سطح دیده‌شده' => self::e((int) ($sum['surface_new'] ?? 0) > 0
                        ? Lang::t('{n} مورد، {new} تازه', ['n' => Text::fa((int) ($sum['surface_seen'] ?? 0)), 'new' => Text::fa((int) $sum['surface_new'])])
                        : Lang::t('{n} مورد', ['n' => Text::fa((int) ($sum['surface_seen'] ?? 0))]))]), 'جزئیات', 'info') . '</div>';
            $new = Db::rows(Db::table('mod_mcsec_findings')->where('client_id', $cid)->where('first_scan_id', $s->id)->orderByRaw("CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC")->limit(30));
            if ($new) {
                $list = '';
                foreach ($new as $f) {
                    $list .= '<li><a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '">' . Ui::sev((string) $f->severity) . '<span class="mcs-todo-title">' . self::e($f->title) . '</span></a><span class="mcs-todo-meta">' . Ui::ltr($f->location) . '</span></li>';
                }
                $out .= Ui::card('<ol class="mcs-todo">' . $list . '</ol>', 'یافته‌هایی که این اسکن برای اولین بار دید', 'bug', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings&amp;scan=' . (int) $s->id . '&amp;status=all">' . Lang::t('همه') . '</a>');
            } elseif ((int) ($sum['seen'] ?? 0) === 0 && $s->profile === 'surface') {
                // discovery does not look for vulnerabilities: "no problem found" would be a false reassurance
                $out .= Ui::card(Ui::emptyState('radar', 'نقشه‌ی سطح حمله آماده است', Lang::t('درگاه پرخطری باز نبود. این اسکن دنبال آسیب‌پذیری نمی‌گردد؛ برای آن، «اسکن آسیب‌پذیری» بگیرید.')));
            } elseif ((int) ($sum['seen'] ?? 0) === 0 && $partial !== '') {
                // an incomplete assessment is never "healthy"
                $out .= Ui::card(Ui::emptyState('alert', 'در بخشی که سنجیده شد مشکلی دیده نشد', Lang::t('ولی همه‌چیز سنجیده نشد (بالا را ببینید). پس از رفع مانع، «اسکن تازه» بگیرید.')));
            } elseif ((int) ($sum['seen'] ?? 0) === 0) {
                $out .= Ui::card(Ui::emptyState('shield-check', 'این اسکن مشکلی پیدا نکرد', Lang::t('آفرین. با زمان‌بندی، اسکن‌های بعدی را خودکار بگیرید.')));
            }
            $reports = Db::rows(Db::table('mod_mcsec_reports')->where('client_id', $cid)->where('scan_id', $s->id)->orderByDesc('id'));
            $rep = '';
            foreach ($reports as $r) {
                $rep .= '<li><a href="index.php?m=mcsec&amp;p=report&amp;id=' . (int) $r->id . '">' . self::e($r->title) . '</a> ' . ((int) $r->ai ? Ui::chip('هوش مصنوعی', 'info') : Ui::chip('پایه')) . '</li>';
            }
            $aiOk = \McSec\Ai::configured() && Plans::limits($cid)['ai'];
            $form = $ctx['manage'] && $aiOk ? Ui::form($ctx, 'scan', 'report_create', '<input type="hidden" name="scan" value="' . (int) $s->id . '"><input type="hidden" name="ai" value="1"><button type="submit" class="btn btn-primary">'
                . Ui::ico('sparkle') . (\McSec\Rules::cost($cid, Settings::int('ai_report_cost')) > 0 ? Lang::t('گزارش هوش مصنوعی · {n} اعتبار', ['n' => self::e(Text::fa(\McSec\Rules::cost($cid, Settings::int('ai_report_cost'))))]) : Lang::t('گزارش هوش مصنوعی')) . '</button>', '', 'mcs-inline', false, '&amp;id=' . (int) $s->id) : '';
            $out .= Ui::card(($rep !== '' ? '<ul class="mcs-plain">' . $rep . '</ul>' : '<p class="mcs-muted">' . Lang::t('گزارش پایه پس از پایان اسکن خودکار ساخته می‌شود.') . '</p>') . $form, 'گزارش', 'file');
        }
        if ($ctx['manage'] && in_array($s->status, ['completed', 'failed', 'cancelled'], true) && $asset && $asset->status === 'verified') {
            Views::$pageActions = Ui::form($ctx, 'scans', 'scan_start', '<input type="hidden" name="asset" value="' . (int) $s->asset_id . '"><input type="hidden" name="profile" value="' . self::e($s->profile) . '">'
                . '<button type="submit" class="btn btn-default">' . Ui::ico('refresh') . ((int) (Catalog::get((string) $s->profile)['credits'] ?? 0) > 0 ? Lang::t('دوباره · {n} اعتبار', ['n' => self::e(Text::fa((int) Catalog::get((string) $s->profile)['credits']))]) : Lang::t('دوباره')) . '</button>', '', 'mcs-inline');
        }
        return $out;
    }

    private static function duration(int $sec): string
    {
        if ($sec <= 0) {
            return '—';
        }
        if ($sec < 120) {
            return Lang::t('{n} ثانیه', ['n' => Text::fa($sec)]);
        }
        if ($sec < 7200) {
            return Lang::t('{n} دقیقه', ['n' => Text::fa((int) round($sec / 60))]);
        }
        return Lang::t('{n} ساعت', ['n' => Text::fa(round($sec / 3600, 1))]);
    }

    public static function schedules(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $list = Schedules::forClient($cid);
        $lim = Plans::limits($cid);
        $out = Ui::guide('<p>' . Lang::t('اسکن‌های تکراری را این‌جا تنظیم کنید تا هر تغییر (یافته‌ی تازه، درگاه تازه، گواهی رو به انقضا) خودکار پیدا و خبرش به شما داده شود. هر اجرا به اندازه‌ی همان اسکن اعتبار مصرف می‌کند؛ اگر اعتبار کافی نباشد، زمان‌بندی متوقف و خبرتان می‌شود.') . '</p>'
            . '<p>' . Lang::t('اگر «همه‌ی دارایی‌های تأییدشده» را انتخاب کنید، دارایی‌هایی که بعداً بیفزایید هم خودکار در زمان‌بندی می‌آیند.') . '</p>', !$list);
        $rows = '';
        foreach ($list as $s) {
            $asset = (int) $s->asset_id > 0 ? Db::table('mod_mcsec_assets')->where('id', $s->asset_id)->value('value') : null;
            $status = $s->status === 'active' ? Ui::chip('فعال', 'ok') : Ui::chip(Lang::t('متوقف: {why}', ['why' => Lang::t(Schedules::PAUSE[$s->pause_reason] ?? 'متوقف')]), 'warn');
            $actions = '';
            if ($ctx['manage']) {
                $actions = Ui::form($ctx, 'schedules', 'schedule_toggle', '<input type="hidden" name="id" value="' . (int) $s->id . '"><input type="hidden" name="active" value="' . ($s->status === 'active' ? '0' : '1') . '">'
                        . '<button type="submit" class="btn btn-default btn-sm">' . Ui::ico($s->status === 'active' ? 'pause' : 'play') . ($s->status === 'active' ? Lang::t('توقف') : Lang::t('ادامه')) . '</button>', '', 'mcs-inline')
                    . Ui::form($ctx, 'schedules', 'schedule_delete', '<input type="hidden" name="id" value="' . (int) $s->id . '"><button type="submit" class="btn btn-default btn-sm btn-danger-text">' . Ui::ico('trash') . '<span class="mcs-sr">' . Lang::t('حذف') . '</span></button>',
                        'این زمان‌بندی حذف شود؟', 'mcs-inline');
            }
            $rows .= '<tr>' . Ui::td('اسکن', self::e(Catalog::label((string) ($s->profile))))
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
        // the ready-made bundles first: one schedule, several scans
        foreach (Catalog::bundles(Catalog::forClient($cid)) as $bk => $bb) {
            if (count($bb['profiles']) > 1) {
                $profiles[$bk] = Lang::t('بسته‌ی «{name}» ({n} اسکن) — {credits} اعتبار هر اجرا', ['name' => Lang::t($bb['label']), 'n' => Text::fa(count($bb['profiles'])), 'credits' => Text::fa($bb['credits'])]);
            }
        }
        foreach (Catalog::forClient($cid) as $k => $p) {
            if ($p['allowed']) {
                $profiles[$k] = (int) $p['credits'] > 0
                    ? Lang::t('{scan} — {n} اعتبار هر اجرا', ['scan' => Lang::t((string) $p['label']), 'n' => Text::fa((int) $p['credits'])])
                    : Lang::t('{scan} — رایگان', ['scan' => Lang::t((string) $p['label'])]);
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
            $dom[(string) $d] = Lang::t('روز {n}', ['n' => Text::fa($d)]);
        }
        $body = '<div class="mcs-form-row">' . Ui::field('mcs-sa', 'دارایی', Ui::select('asset', $assets, '0', 'mcs-sa'))
            . Ui::field('mcs-sp', 'نوع اسکن', Ui::select('profile', $profiles, isset($profiles['surface']) ? 'surface' : (string) array_key_first($profiles), 'mcs-sp')) . '</div>'
            . '<div class="mcs-form-row">' . Ui::field('mcs-sf', 'تکرار', Ui::select('freq', $freqs, isset($freqs['weekly']) ? 'weekly' : (string) array_key_first($freqs), 'mcs-sf'),
                count($freqs) < 3 ? Lang::t('اسکن روزانه در پلن‌های بالاتر است.') : '')
            . Ui::field('mcs-sw', 'روز هفته (برای هفتگی)', Ui::select('dow', array_map('strval', Schedules::DOW), '6', 'mcs-sw'))
            . Ui::field('mcs-sd', 'روز ماه (برای ماهانه)', Ui::select('dom', $dom, '1', 'mcs-sd'))
            . Ui::field('mcs-sh', 'ساعت (به وقت تهران)', Ui::select('hour', $hours, '3', 'mcs-sh'), Lang::t('ساعت‌های کم‌بازدید شب برای سایت بهترند.')) . '</div>'
            . '<button type="submit" class="btn btn-primary">' . Ui::ico('calendar') . Lang::t('ساختن زمان‌بندی') . '</button>';
        $out .= count($assets) > 1 ? Ui::card(Ui::form($ctx, 'schedules', 'schedule_save', $body), 'زمان‌بندی تازه', 'plus')
            : Ui::card(Ui::emptyState('globe', 'دارایی تأییدشده‌ای ندارید', Lang::t('زمان‌بندی پس از تأیید اولین دارایی ممکن است.'), '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=assets#add">' . Lang::t('افزودن دارایی') . '</a>'));
        return $out;
    }
}
