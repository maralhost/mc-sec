<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Assets;
use McSec\Catalog;
use McSec\Db;
use McSec\Findings;
use McSec\Net;
use McSec\Plans;
use McSec\Scans;
use McSec\Score;
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
        $out = Ui::guide('<p>دامنه‌ها، زیردامنه‌ها و IPهایی که می‌خواهید بررسی شوند این‌جا هستند. <strong>فقط دارایی‌ای اسکن می‌شود که مالکیتش تأیید شده باشد</strong>؛ این قانون از سایت شما و دیگران محافظت می‌کند.</p>'
            . '<ul><li>دامنه‌ها و IPهای سرویس‌های خودتان در مارال کلاد خودکار تأیید می‌شوند.</li><li>با تأیید یک دامنه، همه‌ی زیردامنه‌هایش هم تأییدشده‌اند.</li><li>می‌توانید یک‌جا فهرستی از دامنه‌ها را بچسبانید (هر خط یکی).</li></ul>', !$assets);
        if (isset($_GET['removed'])) {
            $out .= Ui::alert('success', 'دارایی حذف شد. یافته‌ها و گزارش‌های قبلی‌اش در تاریخچه می‌مانند.', 'check');
        }
        if ($ctx['manage']) {
            $out .= self::addForm($ctx, !$assets, count($assets), $lim['max_assets']);
        }
        if (!$assets) {
            return $out . Ui::emptyState('globe', 'هنوز دارایی‌ای اضافه نکرده‌اید', 'دامنه‌ی سایتتان را در کادر بالا بنویسید تا اولین بررسی امنیتی را انجام دهیم.');
        }
        $f = (string) ($_GET['status'] ?? '');
        $shown = $f !== '' && isset(Assets::STATUS[$f]) ? array_values(array_filter($assets, fn ($a) => $a->status === $f)) : $assets;
        $seg = ['index.php?m=mcsec&p=assets' => 'همه (' . Text::fa(count($assets)) . ')'];
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
                . Ui::td('وضعیت', self::statusChip($a) . ($a->status === 'pending' ? ' <a class="mcs-small" href="index.php?m=mcsec&amp;p=asset&amp;id=' . (int) $a->id . '#verify">ادامه‌ی تأیید</a>' : ''))
                . Ui::td('امتیاز', (int) $a->last_scan_at > 0 && (int) $a->score >= 0 ? '<span class="mcs-score-pill mcs-tone-' . Score::tone((int) $a->score) . '">' . self::e(Text::fa((int) $a->score)) . '</span>' : '<span class="mcs-muted">—</span>')
                . Ui::td('یافته‌های باز', (int) $a->last_scan_at > 0 ? Ui::sevCounts(Assets::counts($a), 'index.php?m=mcsec&p=findings&asset=' . (int) $a->id, true) : '<span class="mcs-muted">هنوز اسکن نشده</span>')
                . Ui::td('آخرین اسکن', self::e(Views::when((int) $a->last_scan_at)))
                . Ui::td('زمان‌بندی', $sched ? self::e(implode('، ', array_unique($sched))) : '<span class="mcs-muted">—</span>')
                . '</tr>';
        }
        return $out . Ui::card(Ui::seg($seg, $f !== '' ? 'index.php?m=mcsec&p=assets&status=' . $f : 'index.php?m=mcsec&p=assets')
            . Ui::table(['دارایی', 'وضعیت', 'امتیاز', 'یافته‌های باز', 'آخرین اسکن', 'زمان‌بندی'], $rows), 'دارایی‌های شما', 'globe', '', '',
            self::e(Text::fa(count($assets)) . ' از ' . Text::fa($lim['max_assets']) . ' دارایی مجاز'));
    }

    private static function addForm(array $ctx, bool $open, int $count, int $max): string
    {
        $profiles = [];
        foreach (Catalog::forClient($ctx['who']['client_id']) as $k => $p) {
            if ($p['allowed']) {
                $profiles[$k] = $p['label'] . ($p['credits'] > 0 ? ' (' . Text::fa($p['credits']) . ' اعتبار)' : ' (رایگان)');
            }
        }
        $body = '<div class="mcs-add">'
            . Ui::field('mcs-targets', 'دامنه، زیردامنه یا IP', '<textarea class="form-control mcs-ltr" id="mcs-targets" name="targets" rows="2" dir="ltr" placeholder="example.com&#10;shop.example.com&#10;203.0.113.10" required></textarea>',
                'یکی یا چندتا (هر خط یکی، تا ۱۰۰ مورد). نشانی کامل مثل https://example.com/page هم پذیرفته می‌شود.')
            . '<div class="mcs-form-row">' . Ui::field('mcs-label', 'نام دلخواه (اختیاری)', '<input class="form-control" id="mcs-label" name="label" maxlength="120" dir="auto" placeholder="مثلاً فروشگاه اصلی">')
            . Ui::field('mcs-autoscan', 'پس از تأیید، خودکار اسکن کن', Ui::select('autoscan', ['' => 'نه، خودم اسکن می‌گیرم'] + $profiles, 'hygiene', 'mcs-autoscan'),
                'تا لازم نباشد برای شروع اسکن برگردید. هزینه‌ی اعتبار هنگام شروع کم می‌شود.') . '</div>'
            . '<button type="submit" class="btn btn-primary">' . Ui::ico('plus') . 'افزودن</button></div>';
        $full = $count >= $max;
        return Ui::card($full ? Ui::alert('warning', self::e('به سقف ' . Text::fa($max) . ' دارایی رسیده‌اید. دارایی بی‌استفاده را حذف کنید یا پلن بالاتری بگیرید.') . ' <a href="index.php?m=mcsec&amp;p=credits">پلن‌ها</a>', 'alert')
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
            $out .= Ui::alert('success', 'دارایی افزوده و خودکار تأیید شد' . ($a->method === 'whmcs' ? '، چون از سرویس‌های همین حساب در مارال کلاد است.' : '.') . ' حالا اسکن بگیرید.', 'check');
        }
        if ($a->status !== 'verified') {
            $out .= self::verifyPanel($ctx, $a, ($_GET['new'] ?? '') === '1');
        } else {
            Views::$pageActions = $ctx['manage'] ? '<a class="btn btn-primary" href="index.php?m=mcsec&amp;p=scans&amp;asset=' . (int) $a->id . '#new">' . Ui::ico('play') . 'اسکن تازه</a>' : '';
        }
        $counts = Assets::counts($a);
        $score = (int) $a->last_scan_at > 0 ? (int) $a->score : -1;
        $out .= '<div class="mcs-grid2">' . Ui::card(Ui::gauge($score, $score < 0 ? 'هنوز اسکنی تمام نشده است.' : self::e('آخرین اسکن: ' . Views::when((int) $a->last_scan_at))), 'امتیاز این دارایی', 'shield-check')
            . Ui::card(Ui::sevCounts($counts, 'index.php?m=mcsec&p=findings&asset=' . (int) $a->id) . Ui::facts([
                'نوع' => self::e(Assets::KINDS[$a->kind] ?? $a->kind),
                'روش تأیید' => $a->status === 'verified' ? self::e(Verify::METHODS[$a->method] ?? $a->method) . ' — ' . self::e(Text::date((int) $a->verified_at, false)) : '',
                'بررسی بعدی تأیید' => $a->status === 'verified' && !in_array($a->method, ['admin'], true) ? self::e(Text::date((int) $a->next_check_at, false)) : '',
                'برچسب‌ها' => trim((string) $a->tags) !== '' ? implode(' ', array_map(fn ($t) => Ui::chip($t), explode(',', (string) $a->tags))) : '',
            ]), 'یافته‌های باز', 'bug', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=findings&amp;asset=' . (int) $a->id . '">همه</a>') . '</div>';

        // top open findings
        $rank = "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";
        $top = Db::rows(Db::table('mod_mcsec_findings')->where('asset_id', $a->id)->where('status', 'open')->orderByRaw($rank . ' DESC')->orderByDesc('last_seen_at')->limit(8));
        if ($top) {
            $list = '';
            foreach ($top as $f) {
                $list .= '<li><a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $f->id . '">' . Ui::sev((string) $f->severity) . '<span class="mcs-todo-title">' . self::e($f->title) . '</span></a><span class="mcs-todo-meta">' . Ui::ltr($f->location) . '</span></li>';
            }
            $out .= Ui::card('<ol class="mcs-todo">' . $list . '</ol>', 'مهم‌ترین یافته‌ها', 'alert');
        }

        $out .= self::surfaceCard($a);
        $scans = Scans::recent($cid, 10, (int) $a->id);
        if ($scans) {
            $out .= Ui::card(ScanViews::table($scans, false), 'اسکن‌های این دارایی', 'radar', '<a class="btn btn-default btn-sm" href="index.php?m=mcsec&amp;p=scans">همه‌ی اسکن‌ها</a>');
        }
        if ($ctx['manage']) {
            $settings = Ui::form($ctx, 'asset', 'asset_save', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><div class="mcs-form-row">'
                    . Ui::field('mcs-al', 'نام دلخواه', '<input class="form-control" id="mcs-al" name="label" maxlength="120" dir="auto" value="' . self::e($a->label) . '">')
                    . Ui::field('mcs-at', 'برچسب‌ها', '<input class="form-control" id="mcs-at" name="tags" maxlength="200" dir="auto" value="' . self::e(str_replace(',', '، ', (string) $a->tags)) . '">', 'جداشده با ویرگول؛ مثلاً «تولید، فروشگاه».')
                    . '</div><button type="submit" class="btn btn-default">ذخیره</button>', '', '', false, '&amp;id=' . (int) $a->id)
                . '<hr>' . Ui::form($ctx, 'asset', 'asset_remove', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><button type="submit" class="btn btn-default btn-danger-text">' . Ui::ico('trash') . 'حذف این دارایی</button>'
                    . '<p class="mcs-help">زمان‌بندی‌هایش حذف و اسکن‌های در صفش لغو می‌شوند (با بازگشت اعتبار). یافته‌ها و گزارش‌های قبلی می‌مانند.</p>',
                    'این دارایی از فهرست حذف شود؟', '', false, '&amp;id=' . (int) $a->id);
            $out .= Ui::drawer('تنظیمات دارایی', $settings, false, 'key');
        }
        return $out;
    }

    /** The verification wizard: three ways, each with copyable values, and one button to check now. */
    private static function verifyPanel(array $ctx, object $a, bool $fresh): string
    {
        $acc = Accounts::ensure((int) $a->client_id);
        $proof = Accounts::proof($acc);
        $tabs = '';
        if ($a->kind === 'domain') {
            $tabs .= Ui::drawer('روش ۱ (پیشنهادی): رکورد DNS', '<p>در پنل DNS دامنه (DirectAdmin، cPanel، آروان‌کلاد، Cloudflare یا ثبت‌کننده‌ی دامنه) یک رکورد TXT با این مشخصات بسازید:</p>'
                . Ui::facts(['نوع' => '<code dir="ltr">TXT</code>', 'نام (Host)' => Ui::code('_mcsec-verify', '', false) . '<small class="mcs-help">بعضی پنل‌ها نام کامل می‌خواهند: ' . Ui::ltr('_mcsec-verify.' . $a->value) . '</small>', 'مقدار (Value)' => Ui::code($proof, '', false), 'TTL' => 'پیش‌فرض'])
                . '<p class="mcs-help">این رکورد نام جداگانه دارد و به رکورد SPF یا رکوردهای دیگر دامنه دست نمی‌زند. با تأیید ' . Ui::ltr(Net::apex((string) $a->value)) . '، همه‌ی زیردامنه‌هایش هم تأیید می‌شوند.</p>', true, 'globe', 'verify')
                . Ui::drawer('روش ۲: فایل روی سایت', '<p>فایلی متنی با این نام و محتوا بسازید و در ریشه‌ی سایت بگذارید (در File Manager هاست، پوشه‌ی <code dir="ltr">public_html/.well-known/</code>):</p>'
                . Ui::facts(['نشانی' => Ui::code('https://' . $a->value . Verify::FILE_PATH, '', false), 'محتوا' => Ui::code($proof, '', false)]), false, 'file')
                . Ui::drawer('روش ۳: تگ متا در صفحه‌ی اصلی', '<p>این تگ را در بخش <code dir="ltr">&lt;head&gt;</code> صفحه‌ی اصلی بگذارید (در وردپرس: افزونه‌ی سربرگ یا Theme Header):</p>'
                . Ui::code('<meta name="mcsec-verification" content="' . $acc->verify_token . '">', 'HTML'), false, 'list');
        } elseif ($a->kind === 'ip') {
            $tabs .= Ui::drawer('روش ۱: فایل روی وب‌سرور همین IP', '<p>اگر روی این سرور وب‌سرور دارید، این فایل را در ریشه‌ی سایت پیش‌فرض بگذارید:</p>'
                . Ui::facts(['نشانی' => Ui::code('http://' . $a->value . Verify::FILE_PATH, '', false), 'محتوا' => Ui::code($proof, '', false)]), true, 'file', 'verify')
                . Ui::drawer('روش ۲: DNS معکوس (PTR)', '<p>اگر رکورد PTR این IP به نامی زیر یکی از دامنه‌های تأییدشده‌ی شما اشاره کند (مثلاً ' . Ui::ltr('srv1.example.com') . ') و همان نام به این IP برگردد، خودکار تأیید می‌شود. PTR را در پنل سرور یا با تیکت به ارائه‌دهنده‌ی IP تنظیم کنید.</p>', false, 'server');
        } else {
            $tabs .= Ui::alert('info', 'بازه‌ی IP خودکار تأیید نمی‌شود. برای تأیید، از پشتیبانی مارال کلاد تیکت بزنید (تأیید دستی)، یا IPها را تک‌تک بیفزایید.', 'info');
        }
        $note = trim((string) $a->check_note) !== '' && (int) $a->checked_at > 0
            ? Ui::alert('warning', '<strong>آخرین بررسی (' . self::e(Views::when((int) $a->checked_at)) . '):</strong> ' . self::e($a->check_note), 'alert') : '';
        $check = $ctx['manage'] && $a->kind !== 'cidr' ? Ui::form($ctx, 'asset', 'verify_check', '<input type="hidden" name="asset" value="' . (int) $a->id . '"><button type="submit" class="btn btn-primary">' . Ui::ico('refresh') . 'الان بررسی کن</button>', '', 'mcs-inline', false, '&amp;id=' . (int) $a->id) : '';
        $intro = '<p>' . ($fresh ? 'دارایی افزوده شد. ' : '') . 'برای این‌که اسکن فقط روی دارایی‌های خودتان انجام شود، یکی از راه‌های زیر را انجام دهید. لازم نیست این صفحه را باز نگه دارید: هر چند دقیقه خودمان بررسی می‌کنیم و پس از تأیید خبرتان می‌کنیم'
            . ((string) ($a->autoscan ?? '') !== '' ? ' و اسکن «' . self::e(Catalog::all(true)[$a->autoscan]['label'] ?? $a->autoscan) . '» خودکار شروع می‌شود' : '') . '.</p>';
        return Ui::card($intro . $tabs . $note . '<div class="mcs-actions">' . $check . '</div>', $a->status === 'lapsed' ? 'تأیید دوباره‌ی مالکیت' : 'تأیید مالکیت', 'key', '', 'is-attention');
    }

    private static function surfaceCard(object $a): string
    {
        $s = Surface::forAsset((int) $a->id);
        if (!$s) {
            return (int) $a->last_scan_at > 0 ? '' : Ui::card('<p class="mcs-muted">پس از اسکن «کشف سطح حمله» یا «بررسی سلامت پایه»، زیردامنه‌ها، درگاه‌های باز، فناوری‌ها و گواهی‌های این دارایی این‌جا دیده می‌شوند.</p>', 'سطح حمله', 'radar');
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
                    'cert' => trim(($m['not_after'] ?? '') !== '' ? 'انقضا: ' . Text::ymd((string) $m['not_after']) . ' — ' . ($m['issuer'] ?? '') : (string) ($m['issuer'] ?? '')),
                    'url' => isset($m['status']) ? 'HTTP ' . $m['status'] . ' ' . ($m['title'] ?? '') : '',
                    default => '',
                };
                $isNew = (int) $r->first_seen_at > \McSec\Clock::now() - 7 * 86400 && $baseline > 0 && (int) $r->first_scan_id > $baseline;
                $items .= '<li>' . Ui::ltr($r->value) . ($isNew ? ' ' . Ui::chip('تازه', 'warn') : '') . ($extra !== '' ? '<small dir="auto">' . self::e($extra) . '</small>' : '') . '</li>';
            }
            $body .= Ui::drawer($label . ' (' . Text::fa(count($s[$k])) . ')', '<ul class="mcs-surface">' . $items . '</ul>', false);
        }
        return Ui::card($body, 'سطح حمله', 'radar', '', '', 'آنچه از این دارایی روی اینترنت دیده می‌شود');
    }
}
