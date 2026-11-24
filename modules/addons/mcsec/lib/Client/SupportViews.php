<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Assets;
use McSec\Catalog;
use McSec\Credits;
use McSec\Lang;
use McSec\Requests;
use McSec\Support;
use McSec\Text;
use McSec\Whmcs;

/**
 * «کمک کارشناس»: one form that asks a person at Maral Cloud to work. Three kinds (Requests): a free question, a paid
 * «بررسی و رفع عیب» (credits taken when it is sent, said on the button), and a «تست دستی» whose price the team writes
 * later; that price waits here as a card until the customer accepts or declines it. What a request is about (a
 * finding, a scan, an asset) comes from the page the customer came from; the technical details go into the ticket by
 * code (Support::context), so the customer only writes what they want. Below: the account's requests and their state.
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
        $kinds = Requests::kinds();
        $paid = count($kinds) > 1;
        $out = Ui::guide('<p>' . Lang::t('اگر در رفع یک یافته ماندید، نتیجه‌ی اسکنی برایتان روشن نیست، مالکیت دارایی تأیید نمی‌شود یا می‌خواهید کارشناس نگاهی به وضعیت امنیت شما بیندازد، این‌جا بنویسید.') . '</p>'
            . '<p>' . Lang::t('درخواست شما یک <strong>تیکت پشتیبانی</strong> می‌شود و جواب را در همان تیکت می‌گیرید. مشخصات فنی (دارایی، شماره‌ی اسکن، یافته و کد پیگیری) را خودمان در تیکت می‌نویسیم؛ لازم نیست چیزی را کپی کنید.') . '</p>'
            . ($paid ? '<p>' . Lang::t('پرسش و راهنمایی رایگان است. برای کاری که کارشناس باید انجام دهد دو راه هست: «بررسی و رفع عیب» با هزینه‌ی ثابت که هنگام ثبت از اعتبارتان کم می‌شود، و «تست دستی» که قیمتش را تیم پس از دیدن درخواست اعلام می‌کند و تا خودتان تأیید نکنید چیزی کم نمی‌شود.') . '</p>' : ''), false);
        if (!$kinds) {
            return $out . Ui::card(Ui::emptyState('lifebuoy', 'درخواست از این‌جا فعال نیست', Lang::t('برای کمک، از بخش پشتیبانی تیکت بزنید.'), '<a class="btn btn-primary" href="submitticket.php">' . Lang::t('ثبت تیکت') . '</a>'));
        }
        $mine = Requests::forClient($cid);
        $sent = Requests::get($cid, (int) Text::toAscii((string) ($_GET['sent'] ?? '0')));
        if ($sent) {
            $out .= Ui::alert('success', Lang::t('درخواست شما ثبت شد. شماره‌ی تیکت: {tid}. جواب کارشناس را در همان تیکت می‌بینید و با ایمیل هم خبرتان می‌کنیم. <a href="{url}">دیدن تیکت</a>',
                ['tid' => Ui::ltr('#' . $sent->ticket_tid), 'url' => self::e(Support::url((string) $sent->ticket_tid, (string) $sent->ticket_c))])
                . ($sent->kind === 'fix' && (int) $sent->credits > 0 ? ' ' . Lang::t('{n} اعتبار کم شد.', ['n' => self::e(Text::fa((int) $sent->credits))]) : '')
                . ($sent->kind === 'manual' ? ' ' . Lang::t('قیمت را پس از بررسی همین‌جا اعلام می‌کنیم.') : ''), 'check');
        }
        if (isset($_GET['accepted']) && ($acc = Requests::get($cid, (int) Text::toAscii((string) $_GET['accepted']))) && $acc->status === 'accepted') {
            $out .= Ui::alert('success', Lang::t('قیمت را پذیرفتید و {n} اعتبار کم شد. کارشناس کار را شروع می‌کند و در تیکت خبرتان می‌کند.', ['n' => self::e(Text::fa((int) $acc->credits))]), 'check');
        }

        // prices that wait for a yes or a no come first
        foreach ($mine as $r) {
            if ($r->status === 'quoted') {
                $out .= self::quoteCard($ctx, $r);
            }
        }

        $refs = Support::refs($cid, $num('asset'), $num('scan'), $num('finding'));
        $topic = (string) ($_POST['topic'] ?? $_GET['topic'] ?? '');
        $topic = isset(Support::TOPICS[$topic]) ? $topic : ($refs['finding'] ? 'finding' : ($refs['scan'] ? 'scan' : 'review'));
        $kind = (string) ($_POST['kind'] ?? $_GET['kind'] ?? 'help');
        $kind = in_array($kind, $kinds, true) ? $kind : 'help';

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
            $pick = '<input type="hidden" name="kind" value="help">';
            if ($paid) {
                $bal = Credits::balance($cid)['total'];
                $cost = Requests::fixCost($cid);
                $say = [
                    'help' => [Lang::t('رایگان'), Lang::t('پرسش، راهنمایی، یا نگاهی به یک یافته، اسکن یا تأیید مالکیت.')],
                    'fix' => [$cost > 0 ? Lang::t('{n} اعتبار', ['n' => Text::fa($cost)]) : Lang::t('رایگان'), $cost > 0
                        ? Lang::t('کارشناس مشکل را بررسی و تا جایی که دسترسی دارد رفع می‌کند. {n} اعتبار هنگام ثبت کم می‌شود (مانده‌ی شما: {have}) و اگر تیم نتواند انجامش دهد برمی‌گردد.', ['n' => Text::fa($cost), 'have' => Text::fa($bal)])
                        : Lang::t('کارشناس مشکل را بررسی و تا جایی که دسترسی دارد رفع می‌کند.')],
                    'manual' => [Lang::t('قیمت پس از بررسی'), Lang::t('یک کارشناس امنیت دارایی شما را دستی می‌آزماید. تیم قیمت را اعلام می‌کند و تا خودتان تأیید نکنید چیزی کم نمی‌شود.')],
                ];
                $pick = '<fieldset class="mcs-profiles"><legend>' . Ui::ico('lifebuoy') . Lang::t('چه نوع درخواستی؟') . '</legend>';
                foreach ($kinds as $k) {
                    $pick .= '<label class="mcs-profile"><input type="radio" name="kind" value="' . $k . '"' . ($k === $kind ? ' checked' : '') . '><span class="mcs-profile-head"><strong>' . self::e(Requests::KINDS[$k]) . '</strong>'
                        . '<span class="mcs-profile-cost">' . self::e($say[$k][0]) . '</span></span><span class="mcs-profile-desc">' . self::e($say[$k][1]) . '</span></label>';
                }
                $pick .= '</fieldset>';
            }
            $form = Ui::form($ctx, 'support', 'support_send', $hidden
                . ($about !== '' ? '<div class="mcs-about"><span class="mcs-small mcs-muted">' . Lang::t('این درخواست درباره‌ی:') . '</span><ul class="mcs-plain">' . $about . '</ul></div>' : '')
                . $pick
                . '<div class="mcs-form-row">' . Ui::field('mcs-sup-topic', 'موضوع', Ui::select('topic', Support::TOPICS, $topic, 'mcs-sup-topic'))
                . Ui::field('mcs-sup-asset', 'دارایی', Ui::select('asset', $opts, (string) (int) ($refs['asset']->id ?? 0), 'mcs-sup-asset', 'dir="ltr"')) . '</div>'
                . Ui::field('mcs-sup-text', 'چه کمکی می‌خواهید؟', '<textarea class="form-control" id="mcs-sup-text" name="text" rows="5" maxlength="4000" dir="auto" required placeholder="' . self::e(Lang::t('مثلاً: این یافته را طبق راهنما رفع کردم ولی هنوز در اسکن دیده می‌شود.')) . '">'
                    . self::e((string) ($_POST['text'] ?? '')) . '</textarea>', Lang::t('جزئیات فنی را خودمان پیوست می‌کنیم. رمز یا کلید محرمانه در متن ننویسید.'))
                . '<div class="mcs-actions"><button type="submit" class="btn btn-primary">' . Ui::ico('send') . Lang::t('فرستادن درخواست') . '</button><span class="mcs-small mcs-muted">' . Lang::t('یک تیکت پشتیبانی به نام شما ساخته می‌شود.') . '</span></div>');
            $out .= Ui::card($form, 'درخواست بررسی کارشناس', 'lifebuoy');
        } else {
            $out .= Ui::alert('info', Lang::t('کاربر شما فقط اجازه‌ی دیدن دارد. برای فرستادن درخواست، مالک حساب باید مجوز «مدیریت سرویس‌ها» را به شما بدهد.'), 'info');
        }
        if ($mine) {
            $rows = '';
            foreach ($mine as $r) {
                $costCell = (int) $r->credits > 0 && $r->kind !== 'help'
                    ? self::e(Lang::t('{n} اعتبار', ['n' => Text::fa((int) $r->credits)])) . ((int) $r->refunded > 0 ? ' <span class="mcs-small mcs-muted">' . self::e(Lang::t('({n} برگشت)', ['n' => Text::fa((int) $r->refunded)])) . '</span>' : '')
                    : ($r->kind === 'manual' ? '<span class="mcs-muted">' . Lang::t('اعلام می‌شود') . '</span>' : '<span class="mcs-muted">' . Lang::t('رایگان') . '</span>');
                $state = $r->status === 'paying' ? 'quoted' : (string) $r->status;
                $rows .= '<tr>' . Ui::td('درخواست', self::e(Text::fa((int) $r->id)))
                    . Ui::td('نوع', self::e(Requests::KINDS[(string) $r->kind] ?? $r->kind))
                    . Ui::td('وضعیت', Ui::chip(Requests::STATUS[$state] ?? $state, Requests::TONE[$state] ?? '')
                        . ($r->status === 'invoiced' && (int) $r->invoice_id > 0 ? ' <a href="viewinvoice.php?id=' . (int) $r->invoice_id . '">' . Lang::t('پرداخت فاکتور') . '</a>' : ''))
                    . Ui::td('هزینه', $costCell)
                    . Ui::td('تیکت', (string) $r->ticket_tid !== '' ? '<a href="' . self::e(Support::url((string) $r->ticket_tid, (string) $r->ticket_c)) . '">' . Ui::ltr('#' . $r->ticket_tid) . '</a>' : '<span class="mcs-muted">—</span>')
                    . Ui::td('زمان', self::e(Views::when((int) $r->created_at))) . '</tr>';
            }
            $out .= Ui::card(Ui::table(['درخواست', 'نوع', 'وضعیت', 'هزینه', 'تیکت', 'زمان'], $rows), 'درخواست‌های شما', 'list', '<a class="btn btn-default btn-sm" href="supporttickets.php">' . Lang::t('همه‌ی تیکت‌ها') . '</a>');
        }
        return $out;
    }

    /** The team's price for a manual test, waiting for the customer's yes or no. */
    private static function quoteCard(array $ctx, object $r): string
    {
        $cid = (int) $ctx['who']['client_id'];
        $credits = (int) $r->credits;
        $bal = Credits::balance($cid)['total'];
        $enough = $bal >= $credits;
        $money = (float) $r->amount > 0 ? Text::money((float) $r->amount, Whmcs::currency((int) (Whmcs::client($cid)->currency ?? 0))) : '';
        $how = $enough ? Lang::t('با تأیید، {n} اعتبار از حساب شما کم می‌شود (مانده‌ی شما: {have}).', ['n' => Text::fa($credits), 'have' => Text::fa($bal)])
            : ($money !== '' ? Lang::t('اعتبار شما ({have}) کافی نیست؛ با تأیید، فاکتوری به مبلغ {money} ساخته می‌شود و کار پس از پرداخت آن شروع می‌شود.', ['have' => Text::fa($bal), 'money' => $money])
                : Lang::t('اعتبار شما ({have}) کافی نیست؛ اول از صفحه‌ی «اعتبار و پلن» بسته بخرید.', ['have' => Text::fa($bal)]));
        $body = '<p class="mcs-quote-price"><strong>' . self::e(Lang::t('{n} اعتبار', ['n' => Text::fa($credits)])) . '</strong>' . ($money !== '' ? ' <span class="mcs-muted">' . self::e(Lang::t('یا {money} با فاکتور', ['money' => $money])) . '</span>' : '') . '</p>'
            . (trim((string) $r->quote_note) !== '' ? '<div class="mcs-why">' . Ui::para((string) $r->quote_note) . '</div>' : '')
            . '<p>' . self::e($how) . '</p>';
        if ($ctx['buy']) {
            $body .= Ui::form($ctx, 'support', 'request_accept', '<input type="hidden" name="id" value="' . (int) $r->id . '">'
                . '<label class="mcs-check mcs-terms"><input type="checkbox" name="agree" value="1" required><span>' . self::e($enough ? Lang::t('قیمت را می‌پذیرم و می‌خواهم {n} اعتبار از حسابم کم شود.', ['n' => Text::fa($credits)]) : Lang::t('قیمت را می‌پذیرم و می‌خواهم فاکتور آن ساخته شود.')) . '</span></label>'
                . '<div class="mcs-actions"><button type="submit" class="btn btn-primary"' . (!$enough && $money === '' ? ' disabled' : '') . '>' . Ui::ico('check') . self::e($enough ? Lang::t('تأیید و کسر اعتبار') : Lang::t('تأیید و ساخت فاکتور')) . '</button>'
                . (!$enough ? '<a class="btn btn-default" href="index.php?m=mcsec&amp;p=credits">' . Lang::t('خرید اعتبار') . '</a>' : '') . '</div>')
                . Ui::form($ctx, 'support', 'request_decline', '<input type="hidden" name="id" value="' . (int) $r->id . '"><button type="submit" class="btn btn-default btn-sm">' . Lang::t('نمی‌خواهم') . '</button>', Lang::t('این قیمت رد شود؟ چیزی از حساب شما کم نمی‌شود.'), 'mcs-inline');
        } else {
            $body .= Ui::alert('info', Lang::t('تأیید قیمت فقط با مالک حساب یا کاربری که مجوز «فاکتورها» دارد ممکن است.'), 'info');
        }
        return Ui::card($body, Lang::t('قیمت تست دستی شما آماده است (درخواست {id})', ['id' => Text::fa((int) $r->id)]), 'coins', (string) $r->ticket_tid !== '' ? '<a class="btn btn-default btn-sm" href="' . self::e(Support::url((string) $r->ticket_tid, (string) $r->ticket_c)) . '">' . Lang::t('دیدن تیکت') . '</a>' : '', 'is-attention');
    }

    /** A small «درخواست بررسی کارشناس» link for other pages ('' when requests are off). */
    public static function link(string $query, string $label = 'درخواست بررسی کارشناس', string $class = 'btn btn-default btn-sm'): string
    {
        return Support::enabled() ? '<a class="' . $class . '" href="index.php?m=mcsec&amp;p=support' . self::e($query) . '">' . Ui::ico('lifebuoy') . self::e($label) . '</a>' : '';
    }
}
