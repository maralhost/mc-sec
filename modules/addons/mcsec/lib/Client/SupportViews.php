<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Assets;
use McSec\Catalog;
use McSec\Lang;
use McSec\Support;
use McSec\Text;

/**
 * «کمک کارشناس»: one short form that asks a person at Maral Cloud to look. What it is about (a finding, a scan, an
 * asset) comes from the page the customer came from and is shown as a line they can read; the technical details are
 * written into the ticket by code (Support::context), so the customer only writes what they want.
 */
final class SupportViews
{
    private static function e($s): string
    {
        return Ui::e($s);
    }

    public static function page(array $ctx): string
    {
        $cid = (int) $ctx['who']['client_id'];
        $num = fn (string $k): int => (int) Text::toAscii((string) ($_POST[$k] ?? $_GET[$k] ?? '0'));
        $out = Ui::guide('<p>' . Lang::t('اگر در رفع یک یافته ماندید، نتیجه‌ی اسکنی برایتان روشن نیست، مالکیت دارایی تأیید نمی‌شود یا می‌خواهید کارشناس نگاهی به وضعیت امنیت شما بیندازد، این‌جا بنویسید.') . '</p>'
            . '<p>' . Lang::t('درخواست شما یک <strong>تیکت پشتیبانی</strong> می‌شود و جواب را در همان تیکت می‌گیرید. مشخصات فنی (دارایی، شماره‌ی اسکن، یافته و کد پیگیری) را خودمان در تیکت می‌نویسیم؛ لازم نیست چیزی را کپی کنید.') . '</p>', false);
        if (!Support::enabled()) {
            return $out . Ui::card(Ui::emptyState('lifebuoy', 'درخواست از این‌جا فعال نیست', Lang::t('برای کمک، از بخش پشتیبانی تیکت بزنید.'), '<a class="btn btn-primary" href="submitticket.php">' . Lang::t('ثبت تیکت') . '</a>'));
        }
        $sent = (string) ($_GET['sent'] ?? '');
        $recent = Support::recent($cid);
        if ($sent !== '' && preg_match('~^[A-Za-z0-9-]{1,32}$~', $sent)) {
            $url = 'supporttickets.php';
            foreach ($recent as $r) {
                $url = $r['tid'] === $sent ? $r['url'] : $url;
            }
            $out .= Ui::alert('success', Lang::t('درخواست شما ثبت شد. شماره‌ی تیکت: {tid}. جواب کارشناس را در همان تیکت می‌بینید و با ایمیل هم خبرتان می‌کنیم. <a href="{url}">دیدن تیکت</a>', ['tid' => Ui::ltr('#' . $sent), 'url' => self::e($url)]), 'check');
        }
        $refs = Support::refs($cid, $num('asset'), $num('scan'), $num('finding'));
        $topic = (string) ($_POST['topic'] ?? $_GET['topic'] ?? '');
        $topic = isset(Support::TOPICS[$topic]) ? $topic : ($refs['finding'] ? 'finding' : ($refs['scan'] ? 'scan' : 'review'));

        if ($ctx['manage']) {
            $about = '';
            if ($refs['finding']) {
                $about .= '<li>' . Ui::sev((string) $refs['finding']->severity) . ' <a href="index.php?m=mcsec&amp;p=finding&amp;id=' . (int) $refs['finding']->id . '">' . self::e($refs['finding']->title) . '</a></li>';
            }
            if ($refs['scan']) {
                $about .= '<li>' . Ui::ico('radar') . ' <a href="index.php?m=mcsec&amp;p=scan&amp;id=' . (int) $refs['scan']->id . '">' . self::e(Lang::t('اسکن شماره‌ی {n}: {scan}', ['n' => Text::fa((int) $refs['scan']->id), 'scan' => Catalog::label((string) $refs['scan']->profile, (string) $refs['scan']->profile)])) . '</a></li>';
            }
            $hidden = '<input type="hidden" name="scan" value="' . (int) ($refs['scan']->id ?? 0) . '"><input type="hidden" name="finding" value="' . (int) ($refs['finding']->id ?? 0) . '">';
            $opts = ['0' => 'همه‌ی دارایی‌ها / مشخص نیست'];
            foreach (Assets::forClient($cid) as $a) {
                $opts[(string) (int) $a->id] = (string) $a->value;
            }
            $form = Ui::form($ctx, 'support', 'support_send', $hidden
                . ($about !== '' ? '<div class="mcs-about"><span class="mcs-small mcs-muted">' . Lang::t('این درخواست درباره‌ی:') . '</span><ul class="mcs-plain">' . $about . '</ul></div>' : '')
                . '<div class="mcs-form-row">' . Ui::field('mcs-sup-topic', 'موضوع', Ui::select('topic', Support::TOPICS, $topic, 'mcs-sup-topic'))
                . Ui::field('mcs-sup-asset', 'دارایی', Ui::select('asset', $opts, (string) (int) ($refs['asset']->id ?? 0), 'mcs-sup-asset', 'dir="ltr"')) . '</div>'
                . Ui::field('mcs-sup-text', 'چه کمکی می‌خواهید؟', '<textarea class="form-control" id="mcs-sup-text" name="text" rows="5" maxlength="4000" dir="auto" required placeholder="' . self::e(Lang::t('مثلاً: این یافته را طبق راهنما رفع کردم ولی هنوز در اسکن دیده می‌شود.')) . '">'
                    . self::e((string) ($_POST['text'] ?? '')) . '</textarea>', Lang::t('جزئیات فنی را خودمان پیوست می‌کنیم. رمز یا کلید محرمانه در متن ننویسید.'))
                . '<div class="mcs-actions"><button type="submit" class="btn btn-primary">' . Ui::ico('send') . Lang::t('فرستادن درخواست') . '</button><span class="mcs-small mcs-muted">' . Lang::t('یک تیکت پشتیبانی به نام شما ساخته می‌شود.') . '</span></div>');
            $out .= Ui::card($form, 'درخواست بررسی کارشناس', 'lifebuoy');
        } else {
            $out .= Ui::alert('info', Lang::t('کاربر شما فقط اجازه‌ی دیدن دارد. برای فرستادن درخواست، مالک حساب باید مجوز «مدیریت سرویس‌ها» را به شما بدهد.'), 'info');
        }
        if ($recent) {
            $rows = '';
            foreach ($recent as $r) {
                $rows .= '<tr>' . Ui::td('تیکت', '<a href="' . self::e($r['url']) . '">' . Ui::ltr('#' . $r['tid']) . '</a>') . Ui::td('موضوع', self::e($r['topic'])) . Ui::td('زمان', self::e(Views::when($r['at']))) . '</tr>';
            }
            $out .= Ui::card(Ui::table(['تیکت', 'موضوع', 'زمان'], $rows), 'درخواست‌های اخیر شما', 'list', '<a class="btn btn-default btn-sm" href="supporttickets.php">' . Lang::t('همه‌ی تیکت‌ها') . '</a>');
        }
        return $out;
    }

    /** A small «درخواست بررسی کارشناس» link for other pages ('' when requests are off). */
    public static function link(string $query, string $label = 'درخواست بررسی کارشناس', string $class = 'btn btn-default btn-sm'): string
    {
        return Support::enabled() ? '<a class="' . $class . '" href="index.php?m=mcsec&amp;p=support' . self::e($query) . '">' . Ui::ico('lifebuoy') . self::e($label) . '</a>' : '';
    }
}
