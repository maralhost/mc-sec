<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Ai;
use McSec\Assets;
use McSec\Catalog;
use McSec\Db;
use McSec\Findings;
use McSec\Kb;
use McSec\Lang;
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
        $out = Ui::guide(Lang::t('<p>هر مشکلی که اسکن‌ها پیدا کرده‌اند یک بار این‌جا می‌آید (اگر دوباره دیده شود تکرار نمی‌شود) و از مهم‌ترین مرتب است. روی هر کدام بزنید تا ببینید <strong>چرا مهم است و چطور رفعش کنید</strong>.</p>')
            . Lang::t('<ul><li><strong>رفع‌شده</strong> را فقط خود سامانه می‌زند: وقتی اسکن بعدی آن را دیگر نبیند. پس از رفع، «رفع کردم، دوباره بسنج» را بزنید.</li><li>اگر موردی برایتان پذیرفتنی است یا اشتباه است، با نوشتن دلیل «ریسک پذیرفته» یا «مثبت کاذب» کنید؛ از امتیاز و اعلان‌ها بیرون می‌رود.</li></ul>'), !$any);
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
            . '<label class="mcs-sr" for="mcs-fq">' . Lang::t('جستجو') . '</label><input class="form-control" id="mcs-fq" name="q" value="' . self::e($f['q']) . '" placeholder="' . Lang::t('جستجو در عنوان، نشانی یا CVE') . '" dir="auto">'
            . '<label class="mcs-sr" for="mcs-fs">' . Lang::t('شدت') . '</label>' . Ui::select('severity', $sev, $f['severity'], 'mcs-fs')
            . '<label class="mcs-sr" for="mcs-fa">' . Lang::t('دارایی') . '</label>' . Ui::select('asset', $assets, (string) $f['asset'], 'mcs-fa')
            . ($f['new'] > 0 ? '<input type="hidden" name="new" value="' . (int) $f['new'] . '">' : '')
            . '<button type="submit" class="btn btn-default">' . Ui::ico('search') . Lang::t('اعمال') . '</button>'
            . (($f['severity'] !== '' || $f['asset'] > 0 || $f['q'] !== '' || $f['new'] > 0 || $f['scan'] > 0) ? '<a class="btn btn-link" href="' . self::e($base . '&status=' . $f['status']) . '">' . Lang::t('پاک کردن فیلترها') . '</a>' : '') . '</form>';
        $out .= Ui::seg($seg, $keep(['status' => $f['status'], 'page' => ''])) . $filters;
        if ($f['new'] > 0) {
            $out .= Ui::alert('info', self::e(Lang::t('فقط یافته‌هایی که در {n} روز اخیر برای اولین بار دیده شدند.', ['n' => Text::fa($f['new'])])), 'info');
        }
        if (!$res['rows']) {
            return $out . Ui::card($any ? Ui::emptyState('search', 'با این فیلترها یافته‌ای نیست', $f['status'] === 'open' ? Lang::t('یافته‌ی بازی با این شرایط ندارید.') : Lang::t('فیلترها را عوض کنید.'))
                : Ui::emptyState('shield-check', 'هنوز یافته‌ای نیست', Lang::t('پس از اولین اسکن، مشکل‌های پیدا شده این‌جا می‌آیند.'), $ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=scans">' . Lang::t('اسکن بگیرید') . '</a>' : ''));
        }
        $rows = '';
        foreach ($res['rows'] as $r) {
            $rows .= '<tr>' . Ui::td('شدت', Ui::sev((string) $r->severity))
                . Ui::td('یافته', '<a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $r->id . '" class="mcs-finding-link">' . self::e($r->title) . '</a>'
                    . ((int) ($r->kev ?? 0) === 1 && $r->status === 'open' ? ' ' . Ui::chip('در حال بهره‌برداری', 'err') : '')
                    . ((int) $r->first_seen_at > \McSec\Clock::now() - 7 * 86400 && $r->status === 'open' ? ' ' . Ui::chip('تازه', 'warn') : ''))
                . Ui::td('محل', Ui::ltr($r->location) . '<small class="mcs-muted">' . self::e($r->asset_label !== '' ? $r->asset_label : '') . '</small>')
                . Ui::td('وضعیت', self::statusChip($r))
                . Ui::td('دیده‌شده', self::e(Views::when((int) $r->last_seen_at))) . '</tr>';
        }
        // one click for everything that is still open, instead of a click on every finding
        $again = $ctx['manage'] && $f['status'] === 'open' && $res['total'] > 0 ? Ui::form($ctx, 'findings', 'findings_retest_all', '<button type="submit" class="btn btn-default btn-sm">' . Ui::ico('refresh') . Lang::t('رفع کردم، همه را دوباره بسنج') . '</button>',
            Lang::t('برای هر دارایی که یافته‌ی باز دارد یک بررسی دوباره‌ی رایگان گرفته شود؟'), 'mcs-inline') : '';
        $csv = Settings::bool('export_csv') ? ' · <a href="' . self::e($keep(['page' => '', 'csv' => '1'])) . '" download>' . Ui::ico('file') . Lang::t('خروجی CSV') . '</a>' : '';
        return $out . Ui::card(Ui::table(['شدت', 'یافته', 'محل', 'وضعیت', 'آخرین بار'], $rows) . Ui::pager($keep(['page' => '']), $res['page'], $res['pages']),
            '', '', '', '', '') . '<p class="mcs-small mcs-muted">' . Lang::t('{n} یافته', ['n' => self::e(Text::fa($res['total']))]) . $csv . '</p>' . ($again !== '' ? '<div class="mcs-actions">' . $again . '<span class="mcs-small mcs-muted">' . Lang::t('رایگان است؛ یافته‌ای که دیگر دیده نشود خودش «رفع‌شده» می‌شود.') . '</span></div>' : '');
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
        $out = '<div class="mcs-finding-head">' . Ui::sev((string) $f->severity) . self::statusChip($f) . '<span class="mcs-muted">' . Lang::t('روی {asset}', ['asset' => Ui::ltr($asset->value ?? '')]) . '</span></div>';
        if ($f->status === 'accepted' || $f->status === 'false_positive') {
            $out .= Ui::alert('info', self::e(Findings::STATUS[$f->status] ?? '') . ': ' . self::e($f->status_note) . ' <span class="mcs-muted">(' . self::e(Text::date((int) $f->status_at)) . ')</span>', 'info');
        } elseif ($f->status === 'fixed') {
            $out .= Ui::alert('success', Lang::t('این مشکل در اسکن {date} دیگر دیده نشد و رفع‌شده است.', ['date' => self::e(Text::date((int) $f->fixed_at))]), 'check');
        }
        if ((int) ($f->kev ?? 0) === 1 && $f->status === 'open') {
            $out .= Ui::alert('danger', Lang::t('<strong>مهاجمان همین حالا از این آسیب‌پذیری استفاده می‌کنند.</strong> سازمان امنیت سایبری آمریکا (CISA) آن را در فهرست آسیب‌پذیری‌های در حال بهره‌برداری فعال (KEV) گذاشته است. رفعش را به هیچ کار دیگری عقب نیندازید.'), 'alert');
        }
        // what & where
        $facts = Ui::facts([
            'محل' => Ui::ltr($f->location),
            'دارایی' => '<a href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $f->asset_id . '">' . Ui::ltr($asset->value ?? '') . '</a>',
            'شناسه‌ها' => trim($f->cve . ' ' . $f->cwe) !== '' ? implode(' ', array_map(fn ($x) => Ui::ltr($x, 'mcs-tag'), array_filter(array_merge(explode(',', (string) $f->cve), explode(',', (string) $f->cwe))))) : '',
            'CVSS' => $f->cvss !== null ? Ui::ltr((string) $f->cvss) : '',
            'احتمال سوءاستفاده (EPSS)' => $f->epss !== null ? self::e(Lang::t('{n}٪', ['n' => Text::fa(round((float) $f->epss * 100, 1))])) . ' <small class="mcs-muted">' . Lang::t('احتمال بهره‌برداری در ۳۰ روز آینده') . '</small>' : '',
            'در حال بهره‌برداری (KEV)' => (int) ($f->kev ?? 0) === 1 ? Ui::chip(Lang::fa() ? 'بله' : 'Yes', 'err') : '', // i18n-skip («بله» is also the messenger Bale in the dictionary; the label of this row is in the dictionary)
            'اولویت' => (int) ($f->priority ?? 0) > 0 && $f->status === 'open' ? self::e(Lang::t('{n} از ۱۰۰', ['n' => Text::fa((int) $f->priority)])) . ' <small class="mcs-muted">' . Lang::t('از شدت، احتمال و بهره‌برداری فعال') . '</small>' : '',
            'پیدا شده با' => self::e(Catalog::label((string) ($f->profile))) . ' (' . self::e(Catalog::engineLabel((string) $f->engine)) . ')',
            'اولین بار' => self::e(Text::date((int) $f->first_seen_at)),
            'آخرین بار' => self::e(Text::date((int) $f->last_seen_at)) . ((int) $f->reopened > 0 ? ' — ' . Lang::t('{n} بار پس از رفع دوباره دیده شد', ['n' => self::e(Text::fa((int) $f->reopened))]) : ''),
        ]);
        $out .= Ui::card(Ui::para((string) $f->description) . $facts . (trim((string) $f->evidence) !== '' ? '<p class="mcs-small"><strong>' . Lang::t('شاهد (آنچه اسکنر دید):') . '</strong></p>' . Ui::code((string) $f->evidence, 'evidence') : ''), 'این یافته چیست؟', 'info');

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
            $out .= Ui::card('<p class="mcs-why"><strong>' . Lang::t('چرا مهم است؟') . '</strong> ' . self::e($kb['why']) . '</p>' . $steps . $snips
                . (!empty($kb['effort']) ? '<p class="mcs-small mcs-muted">' . Ui::ico('clock') . Lang::t('زمان تقریبی: {time}', ['time' => self::e($kb['effort'])]) . '</p>' : '')
                . (!empty($kb['maral']) ? Ui::alert('info', self::e($kb['maral']), 'shield') : '')
                . ($refs !== '' ? '<details class="mcs-how"><summary>' . Lang::t('منبع‌ها') . '</summary><ul class="mcs-plain">' . $refs . '</ul></details>' : ''), Lang::t('راه رفع: {title}', ['title' => Lang::t((string) $kb['title'])]), 'check');
        }
        if ($f->status === 'open') {
            $out .= self::offer($kbKey) . self::supportCard($f, (string) ($asset->value ?? ''));
        }
        $ai = Reports::cachedFix($f);
        $aiOk = Ai::configured() && Plans::limits($cid)['ai'];
        if ($ai) {
            $out .= self::aiCard($ai);
        } elseif ($aiOk && $ctx['manage'] && $f->status === 'open') {
            $cost = \McSec\Rules::cost($cid, Settings::int('ai_fix_cost'));
            $out .= Ui::card(Lang::t('<p>راهنمای بالا عمومی است. هوش مصنوعی با توجه به نوع همین یافته و فناوری‌های سایتتان، گام‌ها و تنظیم دقیق‌تری پیشنهاد می‌دهد. نام دامنه و IP شما برای مدل فرستاده نمی‌شود.</p>')
                . Ui::form($ctx, 'finding', 'finding_aifix', '<input type="hidden" name="finding" value="' . (int) $f->id . '"><button type="submit" class="btn btn-default">' . Ui::ico('sparkle') . Lang::t('راهکار با هوش مصنوعی')
                    . ($cost > 0 ? ' · ' . Lang::t('{n} اعتبار', ['n' => self::e(Text::fa($cost))]) : '') . '</button><span class="mcs-help">' . Lang::t('ممکن است تا یک دقیقه طول بکشد.') . '</span>', '', 'mcs-inline', false, '&amp;id=' . (int) $f->id), 'راهکار با هوش مصنوعی', 'sparkle');
        }
        // a second opinion on whether it is real (an opinion only), and a way to ask the assistant about it
        $op = Settings::bool('ai_opinion') ? Reports::cachedOpinion($f) : null;
        if ($op) {
            [$vl, $vt] = Reports::VERDICTS[(string) $op['verdict']];
            $out .= Ui::card('<p>' . Ui::chip($vl, $vt) . '</p><p dir="auto">' . self::e((string) ($op['why'] ?? '')) . '</p>'
                . (!empty($op['check']) ? '<p class="mcs-small"><strong>' . Lang::t('چطور مطمئن شوم؟') . '</strong></p><ol class="mcs-fix-steps">' . implode('', array_map(fn ($s) => '<li dir="auto">' . self::e($s) . '</li>', (array) $op['check'])) . '</ol>' : '')
                . '<p class="mcs-ai-note">' . Ui::ico('sparkle') . Lang::t('این فقط نظر هوش مصنوعی از روی شواهد اسکن است؛ شدت، امتیاز و وضعیت یافته را عوض نمی‌کند.') . '</p>', 'نظر دوم هوش مصنوعی', 'sparkle', '', 'mcs-aicard');
        } elseif (Settings::bool('ai_opinion') && Ai::ready() && $ctx['manage'] && $f->status === 'open') {
            $oc = \McSec\Rules::cost($cid, Settings::int('ai_opinion_cost'));
            $out .= Ui::card(Lang::t('<p>مطمئن نیستید این مورد واقعی است؟ هوش مصنوعی شواهد همین یافته را می‌خواند و می‌گوید به احتمال زیاد واقعی است، مثبت کاذب است، یا باید دستی بررسی شود. نام دامنه‌ی شما برای مدل فرستاده نمی‌شود.</p>')
                . Ui::form($ctx, 'finding', 'finding_opinion', '<input type="hidden" name="finding" value="' . (int) $f->id . '"><button type="submit" class="btn btn-default">' . Ui::ico('sparkle') . Lang::t('نظر دوم بگیر')
                    . ($oc > 0 ? ' · ' . Lang::t('{n} اعتبار', ['n' => self::e(Text::fa($oc))]) : '') . '</button><span class="mcs-help">' . Lang::t('ممکن است تا یک دقیقه طول بکشد.') . '</span>', '', 'mcs-inline', false, '&amp;id=' . (int) $f->id), 'واقعی است یا مثبت کاذب؟', 'sparkle');
        }
        if (Settings::bool('assistant_suggest') && \McSec\Assistant::allowed($cid) && $f->status === 'open') {
            $out .= '<p class="mcs-small"><a href="index.php?m=mcsec&amp;p=assistant&amp;ask=' . rawurlencode(Lang::t('مشکل «{title}» (یافته‌ی {id}) را ساده توضیح بده و بگو چطور رفعش کنم', ['title' => mb_substr((string) $f->title, 0, 120), 'id' => (int) $f->id])) . '">' . Ui::ico('sparkle') . Lang::t('از دستیار امنیت درباره‌ی این یافته بپرسید') . '</a></p>';
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
                $acts .= Ui::form($ctx, 'finding', 'finding_retest', '<input type="hidden" name="finding" value="' . (int) $f->id . '"><button type="submit" class="btn btn-primary">' . Ui::ico('refresh') . Lang::t('رفع کردم، دوباره بسنج') . '</button>'
                    . '<span class="mcs-help">' . Lang::t('همان اسکنی که این را پیدا کرد، رایگان دوباره روی همین دارایی اجرا می‌شود (روزی یک بار برای هر یافته).') . '</span>', '', 'mcs-inline', false, '&amp;id=' . (int) $f->id);
                $acts .= Ui::drawer('پذیرفتن ریسک یا مثبت کاذب', Ui::form($ctx, 'finding', 'finding_status', '<input type="hidden" name="finding" value="' . (int) $f->id . '">'
                    . '<div class="mcs-radios"><label><input type="radio" name="status" value="accepted" checked> ' . Lang::t('ریسک را می‌پذیرم (فعلاً رفع نمی‌کنم)') . '</label><label><input type="radio" name="status" value="false_positive"> ' . Lang::t('مثبت کاذب است (مشکل واقعی نیست)') . '</label></div>'
                    . Ui::field('mcs-fn', 'دلیل', '<textarea class="form-control" id="mcs-fn" name="note" rows="2" maxlength="500" dir="auto" required></textarea>', Lang::t('برای خودتان و همکاران؛ در گزارش‌ها هم می‌آید.'))
                    . '<button type="submit" class="btn btn-default">' . Lang::t('ثبت') . '</button>', '', '', false, '&amp;id=' . (int) $f->id), false, 'shield');
            } elseif (in_array($f->status, ['accepted', 'false_positive'], true)) {
                $acts .= Ui::form($ctx, 'finding', 'finding_status', '<input type="hidden" name="finding" value="' . (int) $f->id . '"><input type="hidden" name="status" value="open"><button type="submit" class="btn btn-default">' . Ui::ico('refresh') . Lang::t('دوباره باز شود') . '</button>', '', 'mcs-inline', false, '&amp;id=' . (int) $f->id);
            }
            if ($acts !== '') {
                $out .= Ui::card($acts, 'کارها', 'list');
            }
        }
        return $out;
    }

    /**
     * A Maral service that solves this kind of finding (setting offers: "kb key | text | URL" per line), shown next
     * to the fix only. Empty setting = nothing.
     */
    public static function offer(string $kbKey): string
    {
        foreach (preg_split('~\r\n|\r|\n~', Settings::get('offers')) ?: [] as $line) {
            $p = array_map('trim', explode('|', $line));
            if (count($p) < 3 || $p[0] === '' || strcasecmp($p[0], $kbKey) !== 0 || !preg_match('~^https?://[^\s"<>]+$~i', $p[2])) {
                continue;
            }
            return Ui::card('<p>' . self::e(Text::name($p[1], 200)) . '</p><a class="btn btn-default" href="' . self::e($p[2]) . '" target="_blank" rel="noopener">' . Ui::ico('link') . Lang::t('دیدن') . '</a>', 'راه آسان‌تر', 'sparkle');
        }
        return '';
    }

    /** «درخواست بررسی کارشناس» for this finding: the form of the support page, with the finding already chosen. */
    public static function supportCard(object $f, string $assetValue): string
    {
        if (!\McSec\Support::enabled()) {
            return '';
        }
        return Ui::card(Lang::t('<p>اگر رفع این مورد از توانتان بیرون است یا مطمئن نیستید، کارشناسان ما آن را بررسی می‌کنند. مشخصات همین یافته خودکار در درخواست نوشته می‌شود.</p>')
            . '<a class="btn btn-default" href="index.php?m=mcsec&amp;p=support&amp;topic=finding&amp;finding=' . (int) $f->id . '">' . Ui::ico('lifebuoy') . Lang::t('درخواست بررسی کارشناس') . '</a>', 'کمک کارشناس', 'lifebuoy');
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
            . $steps . $snips . (!empty($ai['verify']) ? '<p dir="auto"><strong>' . Lang::t('چطور مطمئن شوم رفع شده؟') . '</strong> ' . self::e($ai['verify']) . '</p>' : '')
            . ($refs !== '' ? '<details class="mcs-how"><summary>' . Lang::t('منبع‌ها') . '</summary><ul class="mcs-plain">' . $refs . '</ul></details>' : '')
            . '<p class="mcs-ai-note">' . Ui::ico('sparkle') . Lang::t('این متن را هوش مصنوعی نوشته است؛ پیش از اجرای دستورها روی سرور اصلی، آن‌ها را بخوانید یا با پشتیبانی هماهنگ کنید.') . '</p>', 'راهکار هوش مصنوعی', 'sparkle', '', 'mcs-aicard');
    }
}
