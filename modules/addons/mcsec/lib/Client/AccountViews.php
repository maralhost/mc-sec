<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Audit;
use McSec\Catalog;
use McSec\Codes;
use McSec\Credits;
use McSec\Crypto;
use McSec\Findings;
use McSec\Notify;
use McSec\Plans;
use McSec\Rules;
use McSec\Settings;
use McSec\Text;
use McSec\Whmcs;

/** Account pages: notifications (inbox, channels, preferences), credits and plans, activity. */
final class AccountViews
{
    private static function e($s): string
    {
        return Ui::e($s);
    }

    public static function notify(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $acc = Accounts::ensure($cid);
        $notices = Notify::recent($cid, 40);
        $out = Ui::guide('<p>هر خبر مهم (یافته‌ی تازه، درگاه تازه روی اینترنت، تمام شدن اسکن، منقضی شدن تأیید، کم شدن اعتبار) این‌جا می‌آید. می‌توانید بگویید از چه راهی خبرتان کنیم: ایمیل، <strong>بله</strong>، تلگرام یا وب‌هوک (برای Slack، Mattermost یا سامانه‌ی خودتان).</p>'
            . '<p>برای این‌که خسته نشوید، فقط یافته‌هایی که از «کمترین شدت برای خبر فوری» مهم‌ترند فوری فرستاده می‌شوند؛ بقیه در گزارش دوره‌ای می‌آیند.</p>', false);
        // inbox
        $items = '';
        foreach ($notices as $n) {
            $items .= '<li class="mcs-notice' . ((int) $n->read_at === 0 ? ' is-unread' : '') . ' mcs-tone-' . self::e($n->tone) . '" data-mcs-row><div><a href="' . self::e($n->link !== '' ? $n->link : 'index.php?m=mcsec') . '"><strong dir="auto">' . self::e($n->title) . '</strong></a>'
                . ($n->body !== '' ? '<p dir="auto">' . nl2br(self::e(mb_substr((string) $n->body, 0, 600)), false) . '</p>' : '') . '<small class="mcs-muted">' . self::e(Views::when((int) $n->created_at)) . '</small></div>'
                . ((int) $n->read_at === 0 ? Ui::form($ctx, 'notify', 'notice_read', '<input type="hidden" name="notice" value="' . (int) $n->id . '"><button type="submit" class="btn btn-default btn-sm">دیدم</button>', '', 'mcs-inline', 'remove') : '') . '</li>';
        }
        $unread = Notify::unread($cid);
        $out .= Ui::card($items !== '' ? '<ul class="mcs-notices">' . $items . '</ul>' : Ui::emptyState('bell', 'خبری نیست', 'خبرهای امنیتی حساب این‌جا می‌آیند.'), 'خبرها', 'bell',
            $unread > 0 ? Ui::form($ctx, 'notify', 'notice_read', '<input type="hidden" name="notice" value="0"><button type="submit" class="btn btn-default btn-sm">همه را دیدم</button>', '', 'mcs-inline') : '');
        if (!$ctx['manage']) {
            return $out;
        }
        // channels
        $ch = '<ul class="mcs-channels">';
        $ch .= '<li>' . Ui::ico('mail') . '<div><strong>ایمیل</strong><p class="mcs-help">به ایمیل حساب در مارال کلاد' . (Settings::bool('email_enabled') ? '' : ' (فعلاً خاموش است)') . '.</p></div>' . Ui::chip('آماده', 'ok') . '</li>';
        foreach (['bale' => ['بله', 'bale_bot', 'bale_chat', 'https://ble.ir/'], 'telegram' => ['تلگرام', 'telegram_bot', 'tg_chat', 'https://t.me/']] as $which => [$label, $botKey, $chatKey, $base]) {
            if (Settings::secret($which === 'telegram' ? 'telegram_token' : 'bale_token') === '') {
                continue;
            }
            $bot = preg_replace('~[^A-Za-z0-9_]~', '', Settings::get($botKey));
            if ((string) $acc->$chatKey !== '') {
                $ch .= '<li>' . Ui::ico('send') . '<div><strong>' . self::e($label) . '</strong><p class="mcs-help">متصل است.</p></div>' . Ui::chip('متصل', 'ok')
                    . Ui::form($ctx, 'notify', 'bot_unlink', '<input type="hidden" name="which" value="' . self::e($which) . '"><button type="submit" class="btn btn-default btn-sm">قطع اتصال</button>', 'اتصال ' . $label . ' برداشته شود؟', 'mcs-inline') . '</li>';
            } else {
                $deep = $bot !== '' ? $base . $bot . '?start=' . $acc->link_code : '';
                $ch .= '<li>' . Ui::ico('send') . '<div><strong>' . self::e($label) . '</strong><p class="mcs-help">' . ($deep !== '' ? '<a href="' . self::e($deep) . '" target="_blank" rel="noopener">ربات ' . Ui::ltr('@' . $bot) . ' را باز کنید</a> و «شروع» را بزنید؛ یا این کد را برایش بفرستید: ' : 'این کد را برای ربات بفرستید: ')
                    . Ui::code((string) $acc->link_code, '', false) . '</p></div>' . Ui::chip('وصل نیست', 'muted') . '</li>';
            }
        }
        if (Settings::bool('webhook_enabled')) {
            $secret = (string) $acc->webhook_secret !== '' ? Crypto::decrypt((string) $acc->webhook_secret) : '';
            $wh = Ui::form($ctx, 'notify', 'webhook_save', Ui::field('mcs-wh', 'نشانی وب‌هوک (https)', '<input class="form-control mcs-ltr" dir="ltr" id="mcs-wh" name="webhook_url" maxlength="500" value="' . self::e($acc->webhook_url) . '" placeholder="https://hooks.slack.com/services/...">',
                'پیام JSON با فیلد text (سازگار با Slack و Mattermost). خالی بگذارید تا برداشته شود.') . '<button type="submit" class="btn btn-default">ذخیره</button>', '', '', false, '#channels');
            if ($secret !== '') {
                $wh .= '<p class="mcs-help">هر پیام سربرگ <code dir="ltr">X-MCSec-Signature: sha256=…</code> دارد: HMAC-SHA256 بدنه با این کلید. گیرنده با آن مطمئن می‌شود پیام از ماست.</p>' . Ui::code($secret, 'signing key')
                    . '<div class="mcs-actions">' . Ui::form($ctx, 'notify', 'webhook_test', '<button type="submit" class="btn btn-default btn-sm">' . Ui::ico('send') . 'فرستادن پیام آزمایشی</button>', '', 'mcs-inline')
                    . Ui::form($ctx, 'notify', 'webhook_rotate', '<button type="submit" class="btn btn-default btn-sm">کلید تازه</button>', 'کلید امضا عوض شود؟ گیرنده باید کلید تازه را بگیرد.', 'mcs-inline') . '</div>';
            }
            $ch .= '<li class="mcs-channel-wide">' . Ui::ico('webhook') . '<div><strong>وب‌هوک</strong>' . $wh . '</div></li>';
        }
        $out .= Ui::card($ch . '</ul>', 'راه‌های خبر دادن', 'send', '', '" id="channels');
        // preferences matrix
        $prefs = Notify::prefs($cid);
        $head = '<tr><th scope="col">رویداد</th><th scope="col">پنل</th>';
        foreach (Notify::CHANNELS as $c => $l) {
            $head .= '<th scope="col">' . self::e($l) . '</th>';
        }
        $rows = '';
        foreach (Notify::EVENTS as $ev => [$label]) {
            $rows .= '<tr><th scope="row">' . self::e($label) . '</th><td>' . Ui::ico('check') . '<span class="mcs-sr">همیشه</span></td>';
            foreach (Notify::CHANNELS as $c => $l) {
                $on = in_array($ev, (array) ($prefs['channels'][$c] ?? []), true);
                $rows .= '<td><label class="mcs-matrix-cell"><input type="checkbox" name="ch[' . self::e($c) . '][]" value="' . self::e($ev) . '"' . ($on ? ' checked' : '') . '><span class="mcs-sr">' . self::e($label . ' با ' . $l) . '</span></label></td>';
            }
            $rows .= '</tr>';
        }
        $sev = [];
        foreach (Findings::SEVERITIES as $k => $s) {
            $sev[$k] = $s['label'] . ' و بالاتر';
        }
        $body = '<div class="mcs-table-wrap"><table class="table mcs-matrix"><thead>' . $head . '</tr></thead><tbody>' . $rows . '</tbody></table></div>'
            . '<div class="mcs-form-row">' . Ui::field('mcs-ms', 'کمترین شدت برای خبر فوری', Ui::select('min_severity', $sev, (string) $prefs['min_severity'], 'mcs-ms'), 'یافته‌های کم‌اهمیت‌تر فقط در پنل و گزارش دوره‌ای می‌آیند.')
            . Ui::field('mcs-dg', 'گزارش دوره‌ای', Ui::select('digest', Notify::DIGEST, (string) $prefs['digest'], 'mcs-dg'), 'هفتگی: هر ' . self::e(\McSec\Schedules::DOW[Settings::int('digest_dow')] ?? '') . '؛ ماهانه: اول هر ماه.') . '</div>'
            . '<button type="submit" class="btn btn-primary">ذخیره‌ی تنظیم اعلان‌ها</button>';
        $out .= Ui::card(Ui::form($ctx, 'notify', 'notify_save', $body), 'برای چه چیزهایی خبرتان کنیم؟', 'list');
        return $out;
    }

    public static function credits(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $bal = Credits::balance($cid);
        $lim = Plans::limits($cid);
        $rule = Rules::of($cid);
        $out = Ui::guide('<p>هر اسکن به اندازه‌ی عمقش اعتبار مصرف می‌کند. اعتباری که می‌خرید منقضی نمی‌شود. اعتبار رایگان ماهانه (از پلن یا گروه شما) اول هر ماه شمسی پر می‌شود، به ماه بعد نمی‌رود و همیشه اول مصرف می‌شود.</p>'
            . '<p>اسکنی که به‌خاطر خطای سامانه تمام نشود، اعتبارش خودکار برمی‌گردد. اگر کد تخفیف، هدیه یا دعوت دارید، همین‌جا در «کد دارید؟» بنویسید.</p>', false);
        // one number; the part that ends with the month is one line under it
        $sub = [];
        if ($bal['monthly'] > 0) {
            $sub[] = Text::fa($bal['monthly']) . ' اعتبار آن تا پایان این ماه شمسی معتبر است؛ بقیه منقضی نمی‌شود.';
        }
        if ($lim['monthly'] > 0) {
            $sub[] = 'هر ماه ' . Text::fa($lim['monthly']) . ' اعتبار رایگان می‌گیرید.';
        }
        if ($rule['spend_pct'] < 100) {
            $sub[] = 'هزینه‌ی اسکن‌ها برای حساب شما ' . Text::fa(100 - $rule['spend_pct']) . '٪ کمتر است.';
        }
        $out .= '<div class="mcs-balance">' . Ui::kpi('coins', 'اعتبار شما', self::e(Text::fa($bal['total'])), self::e(implode(' ', $sub)), 'primary') . '</div>';

        // «کد دارید؟»: the one place to type any code
        $canCode = $ctx['buy'] || $ctx['manage'];
        $pending = Codes::pending($cid);
        $prefill = Codes::normalize((string) ($_GET['code'] ?? ''));
        $codeBox = $pending ? Ui::alert('info', 'کد ' . Ui::ltr($pending->code) . ' روی حساب شما فعال است: ' . self::e($pending->kind === 'discount' ? Text::fa((int) $pending->value) . '٪ تخفیف روی خرید بعدی بسته.' : Text::fa((int) $pending->value) . '٪ اعتبار بیشتر با خرید بعدی بسته.'), 'check') : '';
        if ($canCode) {
            $codeBox .= Ui::form($ctx, 'credits', 'code_redeem', '<div class="mcs-codebox">' . Ui::field('mcs-code', 'کد تخفیف، هدیه یا دعوت',
                '<input class="form-control mcs-ltr" dir="ltr" id="mcs-code" name="code" maxlength="24" autocomplete="off" autocapitalize="characters" spellcheck="false" value="' . self::e($prefill) . '">',
                'هر کدی دارید همین‌جا بنویسید؛ خودمان تشخیص می‌دهیم چه کدی است.') . '<button type="submit" class="btn btn-primary">ثبت کد</button></div>');
        } else {
            $codeBox .= '<p class="mcs-help">ثبت کد فقط با مالک حساب ممکن است.</p>';
        }
        $out .= Ui::card($codeBox, 'کد دارید؟', 'key', '', '" id="code');

        // packs, at the price this account pays right now
        $packs = Credits::packs();
        if ($packs) {
            $client = Whmcs::client($cid);
            $cur = Whmcs::currency((int) ($client->currency ?? 1));
            $gift = Settings::bool('gift_enabled');
            $cards = '<div class="mcs-packs">';
            foreach ($packs as $p) {
                $o = Credits::offer($cid, $p);
                $better = $o['why'] !== '';
                $cards .= '<div class="mcs-pack' . ($better ? ' is-offer' : '') . '"><strong>' . self::e(Text::fa($o['credits'])) . ' اعتبار</strong><span dir="auto">' . self::e($p['label']) . '</span>'
                    . ($better && $o['price'] < $p['price'] ? '<s class="mcs-muted">' . self::e(Text::money($p['price'], $cur)) . '</s>' : '')
                    . '<span class="mcs-pack-price">' . self::e(Text::money($o['price'], $cur)) . '</span>'
                    . ($better ? '<small class="mcs-pack-why">' . self::e($o['why']) . '</small>' : '<small class="mcs-muted">هر اعتبار ' . self::e(Text::money($o['price'] / max(1, $o['credits']), $cur)) . '</small>')
                    . ($ctx['buy'] ? Ui::form($ctx, 'credits', 'buy_pack', '<input type="hidden" name="pack" value="' . self::e($p['key']) . '"><button type="submit" class="btn btn-primary btn-block">خرید</button>'
                        . ($gift ? '<button type="submit" name="gift" value="1" class="btn btn-default btn-block">' . Ui::ico('send') . 'هدیه به دوست</button>' : '')) : '') . '</div>';
            }
            $out .= Ui::card($cards . '</div><p class="mcs-help">با «خرید» فاکتور ساخته می‌شود؛ با هر روش پرداخت (از جمله اعتبار حساب) بپردازید و اعتبار اسکن همان لحظه افزوده می‌شود.'
                . ($gift ? ' با «هدیه به دوست» پس از پرداخت یک کد هدیه می‌گیرید که دوستتان در حساب خودش وارد می‌کند.' : '') . '</p>'
                . (!$ctx['buy'] ? '<p class="mcs-help">خرید فقط با مالک حساب یا کاربری که مجوز «فاکتورها» دارد ممکن است.</p>' : ''), 'خرید اعتبار', 'coins');
        }

        // gift codes this account bought
        $gifts = Codes::gifts($cid);
        if ($gifts) {
            $rows = '';
            foreach ($gifts as $g) {
                $state = (int) $g->used > 0 ? ((int) $g->enabled === 1 ? Ui::chip('استفاده شد', 'ok') : Ui::chip('به اعتبار خودتان برگشت', 'muted')) : Ui::chip('منتظر دوست شما', 'info');
                $rows .= '<tr>' . Ui::td('کد', (int) $g->used > 0 ? Ui::ltr($g->code) : Ui::code((string) $g->code, '', false)) . Ui::td('اعتبار', self::e(Text::fa((int) $g->value)))
                    . Ui::td('تاریخ خرید', self::e(Text::date((int) $g->created_at, false))) . Ui::td('وضعیت', $state) . '</tr>';
            }
            $out .= Ui::card(Ui::table(['کد', 'اعتبار', 'تاریخ خرید', 'وضعیت'], $rows) . '<p class="mcs-help">کد را به دوستتان بدهید تا در حساب خودش در «کد دارید؟» وارد کند. کدی که تا یک سال استفاده نشود، به اعتبار خودتان برمی‌گردد.</p>', 'هدیه‌های شما', 'send');
        }

        // invite friends
        $invite = Codes::inviteCode($cid);
        if ($invite !== '') {
            $st = Codes::inviteStats($cid);
            $gain = [];
            if (Settings::int('invite_new_credits') > 0) {
                $gain[] = 'دوست شما ' . Text::fa(Settings::int('invite_new_credits')) . ' اعتبار هدیه می‌گیرد.';
            }
            if (Settings::int('invite_reward_verify') > 0) {
                $gain[] = 'وقتی اولین دامنه‌اش را تأیید کرد، شما ' . Text::fa(Settings::int('invite_reward_verify')) . ' اعتبار می‌گیرید.';
            }
            if (Settings::int('invite_reward_buy') > 0) {
                $gain[] = 'با اولین خریدش، شما ' . Text::fa(Settings::int('invite_reward_buy')) . ' اعتبار دیگر می‌گیرید.';
            }
            $out .= Ui::card('<p>' . self::e(implode(' ', $gain)) . '</p>' . Ui::code(rtrim(Whmcs::systemUrl(), '/') . '/index.php?m=mcsec&p=credits&code=' . $invite, 'پیوند دعوت شما')
                . '<p class="mcs-help">یا کد ' . Ui::code($invite, '', false) . ' را بدهید تا در «کد دارید؟» وارد کند.'
                . ($st['invited'] > 0 ? ' تا امروز ' . self::e(Text::fa($st['invited'])) . ' نفر با دعوت شما آمده‌اند و ' . self::e(Text::fa($st['earned'])) . ' اعتبار جایزه گرفته‌اید.' : '') . '</p>', 'دعوت از دوستان', 'send');
        }

        // auto top-up
        if (Settings::bool('auto_topup_enabled') && $packs && $ctx['buy']) {
            $acc = Accounts::get($cid);
            $on = $acc && (string) ($acc->auto_pack ?? '') !== '' && isset($packs[(string) $acc->auto_pack]);
            $opts = [];
            foreach ($packs as $p) {
                $opts[$p['key']] = $p['label'];
            }
            if ($on) {
                $body = '<p>' . Ui::chip('روشن', 'ok') . ' وقتی اعتبار به کمتر از ' . self::e(Text::fa((int) $acc->auto_below)) . ' برسد، فاکتور «' . self::e($packs[(string) $acc->auto_pack]['label']) . '» ساخته می‌شود و خبرتان می‌کنیم.</p>'
                    . Ui::form($ctx, 'credits', 'auto_save', '<input type="hidden" name="pack" value=""><button type="submit" class="btn btn-default">خاموش کردن شارژ خودکار</button>', '', 'mcs-inline');
            } else {
                $body = Ui::form($ctx, 'credits', 'auto_save', '<div class="mcs-form-row">' . Ui::field('mcs-auto-b', 'وقتی اعتبار کمتر از این شد', '<input class="form-control mcs-ltr" dir="ltr" id="mcs-auto-b" name="below" inputmode="numeric" value="10" maxlength="6">')
                    . Ui::field('mcs-auto-p', 'فاکتور این بسته ساخته شود', Ui::select('pack', $opts, (string) array_key_first($opts), 'mcs-auto-p')) . '</div>'
                    . Ui::toggle('agree', false, 'موافقم که فاکتور خودکار ساخته شود', 'چیزی خودکار از حساب شما کسر نمی‌شود: فقط فاکتور ساخته و خبر داده می‌شود و هر وقت بخواهید خاموشش می‌کنید.')
                    . '<button type="submit" class="btn btn-default">روشن کردن شارژ خودکار</button>');
            }
            $out .= Ui::drawer('شارژ خودکار: اسکن‌های زمان‌بندی‌شده بی‌اعتبار نمانند', $body, $on, 'calendar', 'auto');
        }

        // plan & limits
        $plan = $lim['plans'] ? self::e(implode('، ', $lim['plans'])) : 'بدون پلن (رایگان)';
        $out .= Ui::card(Ui::facts(['پلن فعال' => $plan, 'سقف دارایی' => self::e(Text::fa($lim['max_assets'])), 'کوتاه‌ترین فاصله‌ی زمان‌بندی' => self::e($lim['min_interval_h'] <= 24 ? 'روزانه' : ($lim['min_interval_h'] <= 168 ? 'هفتگی' : 'ماهانه')),
            'گزارش هوش مصنوعی' => self::e($lim['ai'] ? 'دارد' : 'ندارد')]) . '<p class="mcs-help">برای پلن بالاتر، از فروشگاه مارال کلاد گروه «امنیت سایبری» را ببینید یا با فروش تماس بگیرید.</p>', 'پلن و محدودیت‌ها', 'shield');
        // costs (what this account pays)
        $rows = '';
        foreach (Catalog::forClient($cid) as $p) {
            $price = (int) $p['credits'] > 0 ? Text::fa((int) $p['credits']) . ' اعتبار برای هر دارایی' : 'رایگان';
            $rows .= '<tr>' . Ui::td('اسکن', self::e($p['label'])) . Ui::td('هزینه', ((int) $p['full'] > (int) $p['credits'] ? '<s class="mcs-muted">' . self::e(Text::fa((int) $p['full'])) . '</s> ' : '') . self::e($price))
                . Ui::td('زمان معمول', self::e($p['eta'])) . Ui::td('در پلن شما', $p['allowed'] ? Ui::chip('هست', 'ok') : Ui::chip('نیست', 'muted')) . '</tr>';
        }
        $aiCost = Rules::cost($cid, Settings::int('ai_report_cost'));
        if (Settings::int('ai_report_cost') > 0) {
            $rows .= '<tr>' . Ui::td('اسکن', 'گزارش هوش مصنوعی') . Ui::td('هزینه', self::e($aiCost > 0 ? Text::fa($aiCost) . ' اعتبار' : 'رایگان')) . Ui::td('زمان معمول', 'چند دقیقه') . Ui::td('در پلن شما', $lim['ai'] ? Ui::chip('هست', 'ok') : Ui::chip('نیست', 'muted')) . '</tr>';
        }
        $out .= Ui::card(Ui::table(['اسکن', 'هزینه', 'زمان معمول', 'در پلن شما'], $rows), 'هزینه‌ی هر کار', 'list');
        // ledger
        $rows = '';
        foreach (Credits::ledger($cid, 100) as $l) {
            $rows .= '<tr>' . Ui::td('تاریخ', self::e(Text::date((int) $l->created_at))) . Ui::td('نوع', self::e(Credits::KINDS[$l->kind] ?? $l->kind) . ($l->bucket === 'monthly' ? ' <small class="mcs-muted">(تا پایان ماه)</small>' : ''))
                . Ui::td('شرح', '<span dir="auto">' . self::e($l->note) . '</span>')
                . Ui::td('مقدار', '<bdi class="mcs-num ' . ((int) $l->delta < 0 ? 'is-neg' : 'is-pos') . '">' . self::e(((int) $l->delta > 0 ? '+' : '−') . Text::fa(abs((int) $l->delta))) . '</bdi>')
                . Ui::td('مانده', self::e(Text::fa((int) $l->balance_after))) . '</tr>';
        }
        $out .= Ui::card($rows !== '' ? Ui::table(['تاریخ', 'نوع', 'شرح', 'مقدار', 'مانده'], $rows) : '<p class="mcs-muted">هنوز تراکنشی نیست.</p>', 'ریز تراکنش‌ها', 'list');
        return $out;
    }

    public static function activity(array $ctx): string
    {
        $cid = $ctx['who']['client_id'];
        $rows = '';
        $list = Audit::recent($cid, 100);
        $names = Whmcs::userNames(array_map(fn ($r) => (int) $r->user_id, $list));
        foreach ($list as $r) {
            $by = (int) $r->admin_id > 0 ? 'پشتیبانی مارال' : ((int) $r->user_id > 0 ? ($names[(int) $r->user_id] ?? 'کاربر') : 'سامانه');
            $rows .= '<tr>' . Ui::td('زمان', self::e(Text::date((int) $r->created_at))) . Ui::td('کار', self::e(Audit::ACTIONS[$r->action] ?? $r->action))
                . Ui::td('روی', '<span dir="auto">' . self::e($r->target) . '</span>') . Ui::td('توسط', '<span dir="auto">' . self::e($by) . '</span>') . '</tr>';
        }
        return Ui::guide('<p>هر کاری که در این بخش انجام شده، با زمان و انجام‌دهنده: افزودن و حذف دارایی، تأیید، اسکن، تغییر وضعیت یافته‌ها، زمان‌بندی و خرید اعتبار.</p>', false)
            . Ui::card($rows !== '' ? Ui::table(['زمان', 'کار', 'روی', 'توسط'], $rows) : '<p class="mcs-muted">هنوز کاری ثبت نشده است.</p>', 'فعالیت‌ها', 'activity');
    }
}
