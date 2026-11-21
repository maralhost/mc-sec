<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Ai;
use McSec\Assistant;
use McSec\Db;
use McSec\Settings;
use McSec\Text;

/**
 * «دستیار امنیت»: the conversation, the cards that wait for the customer's «تأیید و انجام», and the box to write in.
 * Works without JavaScript (every message is a form POST and a fresh page). Everything the model wrote is shown as
 * escaped text; links and the text and cost on a card are made by code (Assistant), never by the model.
 */
final class AssistantViews
{
    private const STARTERS = ['وضعیت امنیت من چطور است؟', 'مهم‌ترین کاری که الان باید بکنم چیست؟', 'یک دامنه‌ی تازه اضافه کن', 'از سایتم اسکن بگیر'];

    private static function e($s): string
    {
        return Ui::e($s);
    }

    public static function page(array $ctx): string
    {
        $who = $ctx['who'];
        $cid = (int) $who['client_id'];
        $acting = Settings::bool('assistant_actions');
        $guide = '<p>این‌جا به زبان خودتان بپرسید یا بگویید چه می‌خواهید: «وضعیت سایتم چطور است؟»، «این مشکل را چطور رفع کنم؟»' . ($acting ? '، «از سایتم اسکن بگیر»، «هر هفته خودکار بررسی کن».' : '.') . ' دستیار فقط از داده‌ی همین حساب جواب می‌دهد.</p>'
            . ($acting ? '<p><strong>هیچ کاری بی تأیید شما انجام نمی‌شود.</strong> وقتی کاری بخواهید، دستیار یک کارت با شرح دقیق کار و هزینه‌اش نشان می‌دهد و فقط با «تأیید و انجام» شما اجرا می‌شود. قانون‌ها همان است که در صفحه‌های دیگر: فقط دارایی تأییدشده‌ی خودتان اسکن می‌شود.</p>' : '')
            . '<p class="mcs-muted">دستیار یک مدل هوش مصنوعی است و ممکن است اشتباه کند؛ عددها، شدت‌ها و هزینه‌ها را همیشه از خود صفحه‌ها بخوانید.</p>';
        if (!Assistant::allowed($cid)) {
            return Ui::card(Ui::emptyState('sparkle', 'دستیار امنیت برای حساب شما روشن نیست', 'همه‌ی کارها از صفحه‌های همین بخش شدنی است. اگر دستیار را می‌خواهید، به پشتیبانی مارال کلاد پیام بدهید.',
                '<a class="btn btn-default" href="index.php?m=mcsec">بازگشت به نمای کلی</a>'));
        }
        $rows = Assistant::history($cid, (int) $who['user_id']);
        $out = Ui::guide($guide, !$rows);
        if (!Ai::ready()) {
            return $out . Ui::alert('warning', 'دستیار امنیت فعلاً در دسترس نیست. کمی بعد دوباره سر بزنید؛ همه‌ی کارها از صفحه‌های همین بخش هم شدنی است.', 'info');
        }
        $list = '';
        $last = count($rows) - 1;
        foreach ($rows as $i => $m) {
            $list .= self::message($ctx, $m, $i === $last);
        }
        if ($list === '') {
            $list = '<li class="mcs-msg mcs-msg-bot"><div class="mcs-bubble"><p>سلام. من دستیار امنیت مارال کلاد هستم. بپرسید یا بگویید چه کاری می‌خواهید؛ از یکی از نمونه‌های پایین هم می‌توانید شروع کنید.</p></div></li>';
        }
        $list .= '<li class="mcs-msg mcs-msg-bot mcs-chat-wait" aria-hidden="true"><div class="mcs-bubble"><span class="mcs-dots"><i></i><i></i><i></i></span> دستیار در حال فکر کردن است…</div></li>';
        $out .= '<ol class="mcs-chat" aria-label="گفت‌وگو با دستیار امنیت" aria-live="polite">' . $list . '</ol>';
        if (!$ctx['manage']) {
            return $out . Ui::alert('info', 'کاربر شما فقط اجازه‌ی دیدن دارد. برای گفت‌وگو با دستیار، مالک حساب باید مجوز «مدیریت سرویس‌ها» را به شما بدهد.', 'lock');
        }
        $cost = Assistant::cost($cid);
        $starters = '';
        if (!$rows) {
            foreach (self::STARTERS as $s) {
                $starters .= '<button type="submit" name="preset" value="' . self::e($s) . '" class="mcs-starter">' . self::e($s) . '</button>';
            }
            $starters = '<div class="mcs-starters" role="group" aria-label="نمونه‌ی پرسش">' . $starters . '</div>';
        }
        $kept = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['a'] ?? '') === 'chat_send' ? mb_substr(html_entity_decode((string) ($_POST['text'] ?? ''), ENT_QUOTES, 'UTF-8'), 0, Assistant::MAX_TEXT) : '';
        $form = Ui::form($ctx, 'assistant', 'chat_send', $starters
            . '<label class="mcs-sr" for="mcs-chat-text">پیام شما به دستیار</label>'
            . '<div class="mcs-composer"><textarea class="form-control" id="mcs-chat-text" name="text" rows="2" maxlength="' . Assistant::MAX_TEXT . '" dir="rtl" placeholder="بپرسید یا بگویید چه کاری می‌خواهید…">' . self::e($kept) . '</textarea>'
            . '<button type="submit" class="btn btn-primary">' . Ui::ico('send') . 'فرستادن</button></div>'
            . '<p class="mcs-help">' . self::e($cost > 0 ? 'هر پیام ' . Text::fa($cost) . ' اعتبار کم می‌کند؛ اگر دستیار جواب ندهد برمی‌گردد.' : 'گفت‌وگو با دستیار رایگان است.')
            . ' سقف روزانه: ' . self::e(Text::fa(max(1, Settings::int('assistant_daily')))) . ' پیام.</p>', '', 'mcs-chat-form" data-mcs-chat="1');
        $clear = $rows ? Ui::form($ctx, 'assistant', 'chat_clear', '<button type="submit" class="btn btn-link btn-sm">' . Ui::ico('refresh') . 'گفت‌وگوی تازه</button>', '', 'mcs-inline') : '';
        return $out . Ui::card($form . $clear, '', '', '', 'mcs-chat-box');
    }

    private static function message(array $ctx, object $m, bool $isLast): string
    {
        $id = $isLast ? ' id="mcs-chat-end"' : '';
        $when = '<span class="mcs-msg-meta">' . self::e(Views::when((int) $m->created_at)) . '</span>';
        if ($m->role === 'user') {
            return '<li class="mcs-msg mcs-msg-user"' . $id . '><span class="mcs-sr">شما: </span><div class="mcs-bubble">' . self::rich((string) $m->body) . '</div>'
                . ($m->status === 'failed' ? '<span class="mcs-msg-meta mcs-msg-fail">بی‌پاسخ ماند</span>' : $when) . '</li>';
        }
        $d = Db::decode((string) $m->data, []);
        if ($m->role === 'assistant') {
            $links = '';
            foreach (array_slice((array) ($d['links'] ?? []), 0, 3) as $l) {
                $href = (string) ($l['href'] ?? '');
                if (str_starts_with($href, 'index.php?m=mcsec&')) {
                    $links .= '<a class="mcs-chat-link" href="' . self::e($href) . '">' . Ui::ico('link') . '<span dir="auto">' . self::e((string) ($l['label'] ?? '')) . '</span></a>';
                }
            }
            return '<li class="mcs-msg mcs-msg-bot"' . $id . '><span class="mcs-sr">دستیار: </span><div class="mcs-bubble">' . self::rich((string) $m->body) . '</div>'
                . ($links !== '' ? '<div class="mcs-chat-links">' . $links . '</div>' : '') . $when . '</li>';
        }
        // an action card: text and cost written by Assistant::propose
        $tool = (string) ($d['tool'] ?? '');
        $cost = (int) ($d['cost'] ?? 0);
        $body = '<p class="mcs-act-what" dir="auto">' . self::rich((string) $m->body, false) . '</p>'
            . '<p class="mcs-act-cost">' . Ui::ico('coins') . ($cost > 0 ? 'هزینه: <strong>' . self::e(Text::fa($cost)) . ' اعتبار</strong>' : 'بی هزینه') . '</p>'
            . ((string) ($d['note'] ?? '') !== '' ? '<p class="mcs-small mcs-muted" dir="auto">' . self::rich((string) $d['note'], false) . '</p>' : '');
        if ($m->status === 'pending' && $ctx['manage']) {
            $acc = $tool === 'start_scan' ? Accounts::get((int) $ctx['who']['client_id']) : null;
            $terms = $acc && (int) $acc->terms_at === 0 ? '<label class="mcs-check mcs-terms"><input type="checkbox" name="terms" value="1" required><span>' . self::e(Settings::get('terms_text')) . '</span></label>' : '';
            $body .= '<div class="mcs-actions">' . Ui::form($ctx, 'assistant', 'chat_confirm', '<input type="hidden" name="id" value="' . (int) $m->id . '">' . $terms
                    . '<button type="submit" class="btn btn-primary">' . Ui::ico('check') . 'تأیید و انجام</button>', '', 'mcs-inline')
                . Ui::form($ctx, 'assistant', 'chat_cancel', '<input type="hidden" name="id" value="' . (int) $m->id . '"><button type="submit" class="btn btn-default">نه، لازم نیست</button>', '', 'mcs-inline') . '</div>';
        } else {
            $res = (array) ($d['result'] ?? []);
            $tone = ['done' => 'ok', 'failed' => 'err', 'pending' => 'warn', 'running' => 'run'][(string) $m->status] ?? '';
            $href = (string) ($res['href'] ?? '');
            $body .= '<p class="mcs-act-state">' . Ui::chip(Assistant::STATUS[(string) $m->status] ?? (string) $m->status, $tone)
                . ((string) ($res['message'] ?? $res['error'] ?? '') !== '' ? ' <span dir="auto">' . self::rich((string) ($res['message'] ?? $res['error']), false) . '</span>' : '')
                . ($href !== '' && str_starts_with($href, 'index.php?m=mcsec&') ? ' <a href="' . self::e($href) . '">' . self::e((string) ($res['link'] ?? 'دیدن')) . '</a>' : '') . '</p>';
        }
        return '<li class="mcs-msg mcs-msg-card' . ($m->status === 'pending' ? ' is-pending' : '') . '"' . $id . '><div class="mcs-act"><p class="mcs-act-title">' . Ui::ico('sparkle')
            . self::e(Assistant::ACTIONS[$tool][0] ?? 'کار پیشنهادی') . '</p>' . $body . '</div></li>';
    }

    /**
     * Text as escaped paragraphs; things that read left to right inside Persian (a domain, an IP, a path, a CVE id)
     * are isolated so the line does not jump. The pattern only matches letters, digits and . _ : / - so it is safe
     * on escaped text.
     */
    private static function rich(string $text, bool $paragraphs = true): string
    {
        $html = $paragraphs ? Ui::para($text) : nl2br(self::e(trim($text)), false);
        return preg_replace('~(?<![\w&#;/.-])([A-Za-z0-9][A-Za-z0-9_:/-]*(?:\.[A-Za-z0-9_:/-]+)+|CVE-\d{4}-\d{3,7})(?![\w;])~', '<bdi dir="ltr">$1</bdi>', $html) ?? $html;
    }
}
