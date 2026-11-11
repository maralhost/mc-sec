<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Ai;
use McSec\Assets;
use McSec\Catalog;
use McSec\Db;
use McSec\Findings;
use McSec\Kb;
use McSec\Plans;
use McSec\Reports;
use McSec\Settings;
use McSec\Text;

/** Findings: the filtered list (most important first) and one finding with evidence, the fix and its history. */
final class FindingViews
{
    private static function e($s): string
    {
        return Ui::e($s);
    }

    public static function statusChip(object $f): string
    {
        $tone = ['open' => 'info', 'fixed' => 'ok', 'accepted' => 'accepted', 'false_positive' => 'muted'][$f->status] ?? 'muted';
        return Ui::chip(Findings::STATUS[$f->status] ?? $f->status, $tone) . ((int) $f->reopened > 0 && $f->status === 'open' ? ' ' . Ui::chip('دوباره دیده‌شده', 'err') : '');
    }

    public static function list(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $f = [
            'status' => (string) ($_GET['status'] ?? 'open'), 'severity' => (string) ($_GET['severity'] ?? ''), 'asset' => (int) Text::toAscii((string) ($_GET['asset'] ?? '0')),
            'scan' => (int) Text::toAscii((string) ($_GET['scan'] ?? '0')), 'new' => (int) Text::toAscii((string) ($_GET['new'] ?? '0')),
            'q' => mb_substr(trim((string) ($_GET['q'] ?? '')), 0, 80), 'page' => (int) Text::toAscii((string) ($_GET['page'] ?? '1')),
        ];
        $res = Findings::search($cid, $f);
        $any = Db::table('mod_mcsec_findings')->where('client_id', $cid)->exists();
        $out = Ui::guide('<p>هر مشکلی که اسکن‌ها پیدا کرده‌اند یک بار این‌جا می‌آید (اگر دوباره دیده شود تکرار نمی‌شود) و از مهم‌ترین مرتب است. روی هر کدام بزنید تا ببینید <strong>چرا مهم است و چطور رفعش کنید</strong>.</p>'
            . '<ul><li><strong>رفع‌شده</strong> را فقط خود سامانه می‌زند: وقتی اسکن بعدی آن را دیگر نبیند. پس از رفع، «رفع کردم، دوباره بسنج» را بزنید.</li><li>اگر موردی برایتان پذیرفتنی است یا اشتباه است، با نوشتن دلیل «ریسک پذیرفته» یا «مثبت کاذب» کنید؛ از امتیاز و اعلان‌ها بیرون می‌رود.</li></ul>', !$any);
        $base = 'index.php?m=mcsec&p=findings';
        $keep = fn (array $over) => $base . '&' . http_build_query(array_filter(array_merge(['status' => $f['status'], 'severity' => $f['severity'], 'asset' => $f['asset'] ?: '', 'new' => $f['new'] ?: '', 'q' => $f['q'], 'scan' => $f['scan'] ?: ''], $over), fn ($v) => $v !== '' && $v !== null));
        $seg = [];
        foreach (['open' => 'باز', 'fixed' => 'رفع‌شده', 'accepted' => 'ریسک پذیرفته', 'false_positive' => 'مثبت کاذب', 'all' => 'همه'] as $k => $l) {
            $seg[$keep(['status' => $k, 'page' => ''])] = self::e($l);
        }
        $assets = ['0' => 'همه‌ی دارایی‌ها'];
        foreach (Assets::forClient($cid) as $a) {
            $assets[(string) $a->id] = (string) $a->value;
        }
        $sev = ['' => 'همه‌ی شدت‌ها'];
        foreach (Findings::SEVERITIES as $k => $s) {
            $sev[$k] = $s['label'];
        }
        $filters = '<form method="get" action="index.php" class="mcs-filters" role="search"><input type="hidden" name="m" value="mcsec"><input type="hidden" name="p" value="findings"><input type="hidden" name="status" value="' . self::e($f['status']) . '">'
            . '<label class="mcs-sr" for="mcs-fq">جستجو</label><input class="form-control" id="mcs-fq" name="q" value="' . self::e($f['q']) . '" placeholder="جستجو در عنوان، نشانی یا CVE" dir="auto">'
            . '<label class="mcs-sr" for="mcs-fs">شدت</label>' . Ui::select('severity', $sev, $f['severity'], 'mcs-fs')
            . '<label class="mcs-sr" for="mcs-fa">دارایی</label>' . Ui::select('asset', $assets, (string) $f['asset'], 'mcs-fa')
            . ($f['new'] > 0 ? '<input type="hidden" name="new" value="' . (int) $f['new'] . '">' : '')
            . '<button type="submit" class="btn btn-default">' . Ui::ico('search') . 'اعمال</button>'
            . (($f['severity'] !== '' || $f['asset'] > 0 || $f['q'] !== '' || $f['new'] > 0 || $f['scan'] > 0) ? '<a class="btn btn-link" href="' . self::e($base . '&status=' . $f['status']) . '">پاک کردن فیلترها</a>' : '') . '</form>';
        $out .= Ui::seg($seg, $keep(['status' => $f['status'], 'page' => ''])) . $filters;
        if ($f['new'] > 0) {
            $out .= Ui::alert('info', self::e('فقط یافته‌هایی که در ' . Text::fa($f['new']) . ' روز اخیر برای اولین بار دیده شدند.'), 'info');
        }
        if (!$res['rows']) {
            return $out . Ui::card($any ? Ui::emptyState('search', 'با این فیلترها یافته‌ای نیست', $f['status'] === 'open' ? 'یافته‌ی بازی با این شرایط ندارید.' : 'فیلترها را عوض کنید.')
                : Ui::emptyState('shield-check', 'هنوز یافته‌ای نیست', 'پس از اولین اسکن، مشکل‌های پیدا شده این‌جا می‌آیند.', $ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=scans">اسکن بگیرید</a>' : ''));
        }
        $rows = '';
        foreach ($res['rows'] as $r) {
            $rows .= '<tr>' . Ui::td('شدت', Ui::sev((string) $r->severity))
                . Ui::td('یافته', '<a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $r->id . '" class="mcs-finding-link">' . self::e($r->title) . '</a>'
                    . ((int) $r->first_seen_at > \McSec\Clock::now() - 7 * 86400 && $r->status === 'open' ? ' ' . Ui::chip('تازه', 'warn') : ''))
                . Ui::td('محل', Ui::ltr($r->location) . '<small class="mcs-muted">' . self::e($r->asset_label !== '' ? $r->asset_label : '') . '</small>')
                . Ui::td('وضعیت', self::statusChip($r))
                . Ui::td('دیده‌شده', self::e(Views::when((int) $r->last_seen_at))) . '</tr>';
        }
        return $out . Ui::card(Ui::table(['شدت', 'یافته', 'محل', 'وضعیت', 'آخرین بار'], $rows) . Ui::pager($keep(['page' => '']), $res['page'], $res['pages']),
            '', '', '', '', '') . '<p class="mcs-small mcs-muted">' . self::e(Text::fa($res['total'])) . ' یافته</p>';
    }

    public static function detail(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $f = Findings::get($cid, (int) Text::toAscii((string) ($_GET['id'] ?? $_POST['finding'] ?? '0')));
        if (!$f) {
            return Views::missing('این یافته', 'index.php?m=mcsec&p=findings', 'بازگشت به یافته‌ها');
        }
        $asset = Db::table('mod_mcsec_assets')->where('id', $f->asset_id)->first();
        Views::$pageTitle = self::e($f->title);
        $out = '<div class="mcs-finding-head">' . Ui::sev((string) $f->severity) . self::statusChip($f) . '<span class="mcs-muted">روی ' . Ui::ltr($asset->value ?? '') . '</span></div>';
        if ($f->status === 'accepted' || $f->status === 'false_positive') {
            $out .= Ui::alert('info', self::e((Findings::STATUS[$f->status] ?? '') . ': ' . $f->status_note) . ' <span class="mcs-muted">(' . self::e(Text::date((int) $f->status_at)) . ')</span>', 'info');
        } elseif ($f->status === 'fixed') {
            $out .= Ui::alert('success', 'این مشکل در اسکن ' . self::e(Text::date((int) $f->fixed_at)) . ' دیگر دیده نشد و رفع‌شده است.', 'check');
        }
        // what & where
        $facts = Ui::facts([
            'محل' => Ui::ltr($f->location),
            'دارایی' => '<a href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $f->asset_id . '">' . Ui::ltr($asset->value ?? '') . '</a>',
            'شناسه‌ها' => trim($f->cve . ' ' . $f->cwe) !== '' ? implode(' ', array_map(fn ($x) => Ui::ltr($x, 'mcs-tag'), array_filter(array_merge(explode(',', (string) $f->cve), explode(',', (string) $f->cwe))))) : '',
            'CVSS' => $f->cvss !== null ? Ui::ltr((string) $f->cvss) : '',
            'احتمال سوءاستفاده (EPSS)' => $f->epss !== null ? self::e(Text::fa(round((float) $f->epss * 100, 1)) . '٪') : '',
            'پیدا شده با' => self::e((Catalog::all(true)[$f->profile]['label'] ?? '') . ' (' . Catalog::engineLabel((string) $f->engine) . ')'),
            'اولین بار' => self::e(Text::date((int) $f->first_seen_at)),
            'آخرین بار' => self::e(Text::date((int) $f->last_seen_at)) . ((int) $f->reopened > 0 ? ' — ' . self::e(Text::fa((int) $f->reopened)) . ' بار پس از رفع دوباره دیده شد' : ''),
        ]);
        $out .= Ui::card(Ui::para((string) $f->description) . $facts . (trim((string) $f->evidence) !== '' ? '<p class="mcs-small"><strong>شاهد (آنچه اسکنر دید):</strong></p>' . Ui::code((string) $f->evidence, 'evidence') : ''), 'این یافته چیست؟', 'info');

        // the fix: knowledge base, AI, scanner's text
        $kbKey = (string) $f->kb !== '' ? (string) $f->kb : Kb::match((string) $f->source_key, (string) $f->title);
        $kb = Kb::get($kbKey) ?? Kb::get('generic');
        if ($kb) {
            $steps = '<ol class="mcs-fix-steps">' . implode('', array_map(fn ($s) => '<li>' . self::e($s) . '</li>', (array) $kb['steps'])) . '</ol>';
            $snips = '';
            foreach ((array) ($kb['snippets'] ?? []) as $sn) {
                $snips .= Ui::code((string) $sn['code'], (string) $sn['label']);
            }
            $refs = '';
            foreach ((array) ($kb['refs'] ?? []) as $u) {
                $refs .= '<li><a href="' . self::e($u) . '" target="_blank" rel="noopener noreferrer" dir="ltr">' . self::e(preg_replace('~^https?://~', '', $u)) . '</a></li>';
            }
            $out .= Ui::card('<p class="mcs-why"><strong>چرا مهم است؟</strong> ' . self::e($kb['why']) . '</p>' . $steps . $snips
                . (!empty($kb['effort']) ? '<p class="mcs-small mcs-muted">' . Ui::ico('clock') . 'زمان تقریبی: ' . self::e($kb['effort']) . '</p>' : '')
                . (!empty($kb['maral']) ? Ui::alert('info', self::e($kb['maral']), 'shield') : '')
                . ($refs !== '' ? '<details class="mcs-how"><summary>منبع‌ها</summary><ul class="mcs-plain">' . $refs . '</ul></details>' : ''), 'راه رفع: ' . $kb['title'], 'check');
        }
        $ai = Reports::cachedFix($f);
        $aiOk = Ai::configured() && Plans::limits($cid)['ai'];
        if ($ai) {
            $out .= self::aiCard($ai);
        } elseif ($aiOk && $ctx['manage'] && $f->status === 'open') {
            $cost = Settings::int('ai_fix_cost');
            $out .= Ui::card('<p>راهنمای بالا عمومی است. هوش مصنوعی با توجه به نوع همین یافته و فناوری‌های سایتتان، گام‌ها و تنظیم دقیق‌تری پیشنهاد می‌دهد. نام دامنه و IP شما برای مدل فرستاده نمی‌شود.</p>'
                . Ui::form($ctx, 'finding', 'finding_aifix', '<input type="hidden" name="finding" value="' . (int) $f->id . '"><button type="submit" class="btn btn-default">' . Ui::ico('sparkle') . 'راهکار با هوش مصنوعی'
                    . ($cost > 0 ? ' · ' . self::e(Text::fa($cost)) . ' اعتبار' : '') . '</button><span class="mcs-help">ممکن است تا یک دقیقه طول بکشد.</span>', '', 'mcs-inline', false, '&amp;id=' . (int) $f->id), 'راهکار با هوش مصنوعی', 'sparkle');
        }
        if (trim((string) $f->solution) !== '') {
            $out .= Ui::drawer('راه‌حل پیشنهادی اسکنر (انگلیسی)', '<div dir="ltr" class="mcs-ltr-block">' . Ui::para((string) $f->solution) . '</div>', false, 'file');
        }
        $refs = Findings::refs($f);
        if ($refs) {
            $out .= Ui::drawer('منبع‌های اسکنر', '<ul class="mcs-plain">' . implode('', array_map(fn ($u) => '<li><a href="' . self::e($u) . '" target="_blank" rel="noopener noreferrer" dir="ltr">' . self::e($u) . '</a></li>', $refs)) . '</ul>', false, 'link');
        }

        // actions
        if ($ctx['manage']) {
            $acts = '';
            if ($f->status === 'open') {
                $acts .= Ui::form($ctx, 'finding', 'finding_retest', '<input type="hidden" name="finding" value="' . (int) $f->id . '"><button type="submit" class="btn btn-primary">' . Ui::ico('refresh') . 'رفع کردم، دوباره بسنج</button>'
                    . '<span class="mcs-help">همان اسکنی که این را پیدا کرد، رایگان دوباره روی همین دارایی اجرا می‌شود (روزی یک بار برای هر یافته).</span>', '', 'mcs-inline', false, '&amp;id=' . (int) $f->id);
                $acts .= Ui::drawer('پذیرفتن ریسک یا مثبت کاذب', Ui::form($ctx, 'finding', 'finding_status', '<input type="hidden" name="finding" value="' . (int) $f->id . '">'
                    . '<div class="mcs-radios"><label><input type="radio" name="status" value="accepted" checked> ریسک را می‌پذیرم (فعلاً رفع نمی‌کنم)</label><label><input type="radio" name="status" value="false_positive"> مثبت کاذب است (مشکل واقعی نیست)</label></div>'
                    . Ui::field('mcs-fn', 'دلیل', '<textarea class="form-control" id="mcs-fn" name="note" rows="2" maxlength="500" dir="auto" required></textarea>', 'برای خودتان و همکاران؛ در گزارش‌ها هم می‌آید.')
                    . '<button type="submit" class="btn btn-default">ثبت</button>', '', '', false, '&amp;id=' . (int) $f->id), false, 'shield');
            } elseif (in_array($f->status, ['accepted', 'false_positive'], true)) {
                $acts .= Ui::form($ctx, 'finding', 'finding_status', '<input type="hidden" name="finding" value="' . (int) $f->id . '"><input type="hidden" name="status" value="open"><button type="submit" class="btn btn-default">' . Ui::ico('refresh') . 'دوباره باز شود</button>', '', 'mcs-inline', false, '&amp;id=' . (int) $f->id);
            }
            if ($acts !== '') {
                $out .= Ui::card($acts, 'کارها', 'list');
            }
        }
        return $out;
    }

    public static function aiCard(array $ai): string
    {
        $steps = '<ol class="mcs-fix-steps">' . implode('', array_map(fn ($s) => '<li dir="auto">' . self::e($s) . '</li>', (array) ($ai['steps'] ?? []))) . '</ol>';
        $snips = '';
        foreach ((array) ($ai['snippets'] ?? []) as $sn) {
            $snips .= Ui::code((string) $sn['code'], (string) $sn['label']);
        }
        $refs = '';
        foreach ((array) ($ai['references'] ?? []) as $u) {
            $refs .= '<li><a href="' . self::e($u) . '" target="_blank" rel="noopener noreferrer nofollow" dir="ltr">' . self::e(preg_replace('~^https?://~', '', $u)) . '</a></li>';
        }
        return Ui::card((!empty($ai['summary']) ? '<p dir="auto"><strong>' . self::e($ai['summary']) . '</strong></p>' : '') . (!empty($ai['why']) ? '<p class="mcs-why" dir="auto">' . self::e($ai['why']) . '</p>' : '')
            . $steps . $snips . (!empty($ai['verify']) ? '<p dir="auto"><strong>چطور مطمئن شوم رفع شده؟</strong> ' . self::e($ai['verify']) . '</p>' : '')
            . ($refs !== '' ? '<details class="mcs-how"><summary>منبع‌ها</summary><ul class="mcs-plain">' . $refs . '</ul></details>' : '')
            . '<p class="mcs-ai-note">' . Ui::ico('sparkle') . 'این متن را هوش مصنوعی نوشته است؛ پیش از اجرای دستورها روی سرور اصلی، آن‌ها را بخوانید یا با پشتیبانی هماهنگ کنید.</p>', 'راهکار هوش مصنوعی', 'sparkle', '', 'mcs-aicard');
    }
}
