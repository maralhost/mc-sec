<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Accounts;
use McSec\Audit;
use McSec\Catalog;
use McSec\Credits;
use McSec\Crypto;
use McSec\Findings;
use McSec\Notify;
use McSec\Plans;
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
        $out = Ui::guide('<p>هر اسکن به اندازه‌ی عمقش اعتبار مصرف می‌کند. اعتبار دو بخش دارد: <strong>اعتبار ماهانه</strong> (رایگانِ گروه شما و اعتبار پلن؛ اول هر ماه شمسی پر می‌شود و به ماه بعد نمی‌رود) و <strong>اعتبار خریداری‌شده</strong> که منقضی نمی‌شود. اول اعتبار ماهانه مصرف می‌شود.</p>'
            . '<p>اسکنی که به‌خاطر خطای سامانه تمام نشود، اعتبارش خودکار برمی‌گردد.</p>', false);
        $out .= '<div class="mcs-grid3">'
            . Ui::kpi('coins', 'مانده‌ی کل', self::e(Text::fa($bal['total'])), 'اعتبار', 'primary')
            . Ui::kpi('calendar', 'اعتبار ماهانه', self::e(Text::fa($bal['monthly'])), self::e('ماه ' . Text::fa($bal['period']) . ($lim['monthly'] > 0 ? ' — هر ماه ' . Text::fa($lim['monthly']) : '')))
            . Ui::kpi('key', 'اعتبار خریداری‌شده', self::e(Text::fa($bal['paid'])), 'بی‌انقضا') . '</div>';
        // plan & limits
        $plan = $lim['plans'] ? self::e(implode('، ', $lim['plans'])) : 'بدون پلن (رایگان)';
        $out .= Ui::card(Ui::facts(['پلن فعال' => $plan, 'سقف دارایی' => self::e(Text::fa($lim['max_assets'])), 'کوتاه‌ترین فاصله‌ی زمان‌بندی' => self::e($lim['min_interval_h'] <= 24 ? 'روزانه' : ($lim['min_interval_h'] <= 168 ? 'هفتگی' : 'ماهانه')),
            'گزارش هوش مصنوعی' => self::e($lim['ai'] ? 'دارد' : 'ندارد')]) . '<p class="mcs-help">برای پلن بالاتر، از فروشگاه مارال کلاد گروه «امنیت سایبری» را ببینید یا با فروش تماس بگیرید.</p>', 'پلن و محدودیت‌ها', 'shield');
        // costs
        $rows = '';
        foreach (Catalog::forClient($cid) as $p) {
            $rows .= '<tr>' . Ui::td('اسکن', self::e($p['label'])) . Ui::td('هزینه', self::e((int) $p['credits'] > 0 ? Text::fa((int) $p['credits']) . ' اعتبار برای هر دارایی' : 'رایگان'))
                . Ui::td('زمان معمول', self::e($p['eta'])) . Ui::td('در پلن شما', $p['allowed'] ? Ui::chip('هست', 'ok') : Ui::chip('نیست', 'muted')) . '</tr>';
        }
        if (Settings::int('ai_report_cost') > 0) {
            $rows .= '<tr>' . Ui::td('اسکن', 'گزارش هوش مصنوعی') . Ui::td('هزینه', self::e(Text::fa(Settings::int('ai_report_cost')) . ' اعتبار')) . Ui::td('زمان معمول', 'چند دقیقه') . Ui::td('در پلن شما', $lim['ai'] ? Ui::chip('هست', 'ok') : Ui::chip('نیست', 'muted')) . '</tr>';
        }
        $out .= Ui::card(Ui::table(['اسکن', 'هزینه', 'زمان معمول', 'در پلن شما'], $rows), 'هزینه‌ی هر کار', 'list');
        // packs
        $packs = Credits::packs();
        if ($packs) {
            $client = Whmcs::client($cid);
            $cur = Whmcs::currency((int) ($client->currency ?? 1));
            $cards = '<div class="mcs-packs">';
            foreach ($packs as $p) {
                $per = $p['credits'] > 0 ? $p['price'] / $p['credits'] : 0;
                $cards .= '<div class="mcs-pack"><strong>' . self::e(Text::fa($p['credits'])) . ' اعتبار</strong><span dir="auto">' . self::e($p['label']) . '</span><span class="mcs-pack-price">' . self::e(Text::money($p['price'], $cur)) . '</span>'
                    . '<small class="mcs-muted">هر اعتبار ' . self::e(Text::money($per, $cur)) . '</small>'
                    . ($ctx['buy'] ? Ui::form($ctx, 'credits', 'buy_pack', '<input type="hidden" name="pack" value="' . self::e($p['key']) . '"><button type="submit" class="btn btn-primary btn-block">خرید</button>') : '') . '</div>';
            }
            $out .= Ui::card($cards . '</div><p class="mcs-help">با «خرید» فاکتور WHMCS ساخته می‌شود؛ با هر روش پرداخت (از جمله اعتبار حساب) بپردازید و اعتبار اسکن همان لحظه افزوده می‌شود.</p>'
                . (!$ctx['buy'] ? '<p class="mcs-help">خرید فقط با مالک حساب یا کاربری که مجوز «فاکتورها» دارد ممکن است.</p>' : ''), 'خرید اعتبار', 'coins');
        }
        // ledger
        $rows = '';
        foreach (Credits::ledger($cid, 100) as $l) {
            $rows .= '<tr>' . Ui::td('تاریخ', self::e(Text::date((int) $l->created_at))) . Ui::td('نوع', self::e(Credits::KINDS[$l->kind] ?? $l->kind) . ' <small class="mcs-muted">(' . self::e($l->bucket === 'monthly' ? 'ماهانه' : 'خریداری‌شده') . ')</small>')
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
