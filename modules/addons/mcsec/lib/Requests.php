<?php

declare(strict_types=1);

namespace McSec;

/**
 * Requests for a person's work (0.15.0), each one a row here, a WHMCS ticket and a line in the admin panel:
 *  - help:   a question or a look at something («کمک کارشناس» of 0.13.0); free.
 *  - fix:    «بررسی و رفع عیب»: an expert looks and fixes. A fixed number of credits, taken when the request is
 *            sent, given back when the team cancels it.
 *  - manual: «تست دستی» (a manual security test). Nothing is taken when it is sent. The team writes a price (credits,
 *            and a money amount for an account without enough credits); the customer reads it and accepts or declines.
 *            On accept: the credits are taken when the wallet has them, otherwise an unpaid WHMCS invoice is made
 *            and the work starts when it is paid.
 *
 * Money rules (rule 4): every movement is one ledger row with the unique ref "req:<id>", so sending a form twice or
 * accepting twice takes credits once; a state changes with a conditional update (new → quoted → accepted …), so two
 * clicks at the same moment cannot both win; the price is the team's, never a number from the browser.
 * The ticket and its context are written by Support (always Persian, for the support team).
 */
final class Requests
{
    public const KINDS = ['help' => 'پرسش و راهنمایی', 'fix' => 'بررسی و رفع عیب توسط کارشناس', 'manual' => 'تست دستی (Manual test)'];

    public const STATUS = [
        'new' => 'ثبت شد', 'quoted' => 'قیمت اعلام شد', 'invoiced' => 'منتظر پرداخت فاکتور', 'accepted' => 'تأیید و پرداخت شد',
        'working' => 'در حال انجام', 'done' => 'انجام شد', 'declined' => 'قیمت پذیرفته نشد', 'cancelled' => 'لغو شد',
    ];

    public const TONE = ['new' => 'info', 'quoted' => 'warn', 'invoiced' => 'warn', 'accepted' => 'ok', 'working' => 'run', 'done' => 'ok', 'declined' => 'muted', 'cancelled' => 'muted'];

    /** The kinds a customer can ask for now. Help is the base; the paid ones each have their switch. @return string[] */
    public static function kinds(): array
    {
        if (!Support::enabled()) {
            return [];
        }
        return array_values(array_filter(['help', Settings::bool('expert_fix') ? 'fix' : '', Settings::bool('expert_manual') ? 'manual' : '']));
    }

    /** Credits of a «بررسی و رفع عیب» for this account (its price rule applies as for scans). */
    public static function fixCost(int $clientId): int
    {
        return Rules::cost($clientId, max(0, Settings::int('expert_fix_cost')));
    }

    public static function get(int $clientId, int $id): ?object
    {
        return $id > 0 ? Db::table('mod_mcsec_requests')->where('id', $id)->where('client_id', $clientId)->first() : null;
    }

    /** @return object[] newest first */
    public static function forClient(int $clientId, int $limit = 20): array
    {
        return Db::rows(Db::table('mod_mcsec_requests')->where('client_id', $clientId)->orderByDesc('id')->limit($limit));
    }

    /**
     * A new request. @param array{kind:string,topic:string,text:string,asset:int,scan:int,finding:int} $in
     * @return array{ok:bool,error?:string,id?:int,tid?:string}
     */
    public static function create(array $who, array $in): array
    {
        $cid = (int) $who['client_id'];
        $kind = (string) ($in['kind'] ?? 'help');
        if (!in_array($kind, self::kinds(), true)) {
            return ['ok' => false, 'error' => $kind === 'help' || !isset(self::KINDS[$kind]) ? 'درخواست بررسی کارشناس فعلاً در دسترس نیست. از بخش پشتیبانی تیکت بزنید.' : 'این نوع درخواست فعلاً در دسترس نیست.'];
        }
        $check = Support::check($cid, (string) $in['text']);
        if (!$check['ok']) {
            return $check;
        }
        $cost = $kind === 'fix' ? self::fixCost($cid) : 0;
        if ($cost > 0 && Credits::balance($cid)['total'] < $cost) {
            return ['ok' => false, 'error' => Lang::t('برای این درخواست {n} اعتبار لازم است و شما {have} اعتبار دارید. از صفحه‌ی «اعتبار و پلن» بسته بخرید و دوباره بفرستید.', ['n' => Text::fa($cost), 'have' => Text::fa(Credits::balance($cid)['total'])])];
        }
        if (!RateLimit::hit('support:' . $cid, Support::DAILY, 86400)) {
            return ['ok' => false, 'error' => 'امروز چند درخواست فرستاده‌اید. ادامه‌ی گفت‌وگو را در همان تیکت‌ها بنویسید یا فردا درخواست تازه بدهید.'];
        }
        $refs = Support::refs($cid, (int) $in['asset'], (int) $in['scan'], (int) $in['finding']);
        $topic = isset(Support::TOPICS[$in['topic'] ?? '']) ? (string) $in['topic'] : 'other';
        $id = Db::table('mod_mcsec_requests')->insertGetId(['client_id' => $cid, 'user_id' => (int) $who['user_id'], 'kind' => $kind, 'topic' => $topic, 'status' => 'new',
            'asset_id' => (int) ($refs['asset']->id ?? 0), 'scan_id' => (int) ($refs['scan']->id ?? 0), 'finding_id' => (int) ($refs['finding']->id ?? 0),
            'text' => $check['text'], 'credits' => $cost, 'created_at' => Clock::now(), 'updated_at' => Clock::now()]);
        if ($cost > 0) {
            $paid = Credits::spend($cid, $cost, 'req:' . $id, Lang::t('بررسی و رفع عیب توسط کارشناس (درخواست {id})', ['id' => $id]));
            if (!$paid['ok']) {
                Db::table('mod_mcsec_requests')->where('id', $id)->update(['status' => 'cancelled', 'admin_note' => 'credits: ' . $paid['error'], 'closed_at' => Clock::now()]);
                return ['ok' => false, 'error' => $paid['error']];
            }
            Db::table('mod_mcsec_requests')->where('id', $id)->update(['paid_with' => 'credits']);
        }
        // the ticket: its subject and the lines about money are for the support team, so always Persian // i18n-skip-begin
        $lines = Lang::with('fa', fn () => array_filter(['درخواست #' . $id . ' — ' . self::KINDS[$kind],
            $kind === 'fix' ? ($cost > 0 ? Text::fa($cost) . ' اعتبار هنگام ثبت کم شد (اگر لغو کنید برمی‌گردد).' : 'بی هزینه.') : '',
            $kind === 'manual' ? 'قیمت را در پنل مدیر ← MC-Sec ← عملیات ← درخواست‌ها اعلام کنید؛ تا مشتری نپذیرد چیزی کم نمی‌شود.' : '']));
        $subject = Lang::with('fa', fn () => $kind === 'help' ? Support::TOPICS[$topic] : self::KINDS[$kind]);
        // i18n-skip-end
        $t = Support::open($who, $subject, $check['text'], $refs, $lines);
        if (!$t['ok']) {
            $back = $cost > 0 ? Credits::refund($cid, 'req:' . $id, Lang::t('بازگشت اعتبار: تیکت درخواست {id} ساخته نشد', ['id' => $id])) : 0;
            Db::table('mod_mcsec_requests')->where('id', $id)->update(['status' => 'cancelled', 'admin_note' => 'ticket failed', 'refunded' => $back, 'closed_at' => Clock::now()]);
            return ['ok' => false, 'error' => $t['error'] . ($back > 0 ? ' ' . Lang::t('{n} اعتبار برگشت.', ['n' => Text::fa($back)]) : '')];
        }
        Db::table('mod_mcsec_requests')->where('id', $id)->update(['ticket_id' => (int) $t['id'], 'ticket_tid' => (string) $t['tid'], 'ticket_c' => (string) $t['c']]);
        Audit::log($cid, 'support', '#' . $t['tid'], ['request' => $id, 'kind' => $kind, 'topic' => $topic, 'credits' => $cost], (int) $who['user_id']);
        return ['ok' => true, 'id' => $id, 'tid' => (string) $t['tid']];
    }

    // ── the team ──

    /** The team's price for a manual test. Credits and money are both the team's numbers. @return array{ok:bool,error?:string} */
    public static function quote(int $id, int $credits, float $amount, string $note): array
    {
        $r = Db::table('mod_mcsec_requests')->where('id', $id)->first();
        if (!$r || $r->kind !== 'manual' || !in_array($r->status, ['new', 'quoted'], true)) {
            return ['ok' => false, 'error' => 'قیمت فقط برای درخواست «تست دستی» که هنوز پذیرفته نشده اعلام می‌شود.']; // i18n-skip (admin panel)
        }
        if ($credits <= 0 || $credits > 1000000) {
            return ['ok' => false, 'error' => 'شمار اعتبار را بنویسید (بیشتر از صفر).']; // i18n-skip (admin panel)
        }
        if ($amount < 0 || $amount > 1e12) {
            return ['ok' => false, 'error' => 'مبلغ فاکتور درست نیست.']; // i18n-skip (admin panel)
        }
        $n = Db::table('mod_mcsec_requests')->where('id', $id)->whereIn('status', ['new', 'quoted'])->update(['status' => 'quoted', 'credits' => $credits, 'amount' => round($amount, 2),
            'quote_note' => mb_substr(trim($note), 0, 1000), 'quoted_by' => Auth::adminId(), 'quoted_at' => Clock::now(), 'updated_at' => Clock::now()]);
        if ($n !== 1) {
            return ['ok' => false, 'error' => 'وضعیت این درخواست همین حالا عوض شد؛ صفحه را تازه کنید.']; // i18n-skip (admin panel)
        }
        Audit::log((int) $r->client_id, 'request_admin', 'quote #' . $id, ['credits' => $credits, 'amount' => round($amount, 2)]);
        Notify::event((int) $r->client_id, 'request_update', ['what' => 'quoted', 'id' => $id, 'credits' => $credits], 'reqq:' . $id . ':' . Clock::now());
        return ['ok' => true];
    }

    /** working / done by the team; cancel gives the credits back. @return array{ok:bool,error?:string,refunded?:int} */
    public static function setStatus(int $id, string $to, string $note = ''): array
    {
        $r = Db::table('mod_mcsec_requests')->where('id', $id)->first();
        if (!$r) {
            return ['ok' => false, 'error' => 'این درخواست پیدا نشد.'];
        }
        $from = ['working' => ['new', 'accepted'], 'done' => ['new', 'accepted', 'working'], 'cancelled' => ['new', 'quoted', 'invoiced', 'accepted', 'working']][$to] ?? null;
        // a manual test starts only after the customer paid; a free question or a paid fix can start at once
        if ($from !== null && $r->kind === 'manual' && $to !== 'cancelled') {
            $from = array_values(array_diff($from, ['new']));
        }
        if ($from === null || !in_array($r->status, $from, true)) {
            return ['ok' => false, 'error' => 'این تغییر وضعیت برای این درخواست ممکن نیست.']; // i18n-skip (admin panel)
        }
        $upd = ['status' => $to, 'updated_at' => Clock::now()] + ($note !== '' ? ['admin_note' => mb_substr($note, 0, 1000)] : []) + (in_array($to, ['done', 'cancelled'], true) ? ['closed_at' => Clock::now()] : []);
        if (Db::table('mod_mcsec_requests')->where('id', $id)->where('status', $r->status)->update($upd) !== 1) {
            return ['ok' => false, 'error' => 'وضعیت این درخواست همین حالا عوض شد؛ صفحه را تازه کنید.']; // i18n-skip (admin panel)
        }
        $back = 0;
        if ($to === 'cancelled' && (string) $r->paid_with === 'credits') {
            $back = Credits::forAccount((int) $r->client_id, fn () => Credits::refund((int) $r->client_id, 'req:' . $id, Lang::t('بازگشت اعتبار: درخواست {id} لغو شد', ['id' => $id])));
            Db::table('mod_mcsec_requests')->where('id', $id)->update(['refunded' => $back]);
        }
        Audit::log((int) $r->client_id, 'request_admin', $to . ' #' . $id, ['refunded' => $back]);
        Notify::event((int) $r->client_id, 'request_update', ['what' => $to, 'id' => $id, 'refunded' => $back, 'invoice' => $to === 'cancelled' && (string) $r->paid_with === 'invoice' ? (int) $r->invoice_id : 0], 'reqs:' . $id . ':' . $to);
        return ['ok' => true, 'refunded' => $back];
    }

    // ── the customer's answer to a price ──

    /** @return array{ok:bool,error?:string,invoice_id?:int,credits?:int} */
    public static function accept(array $who, int $id): array
    {
        $cid = (int) $who['client_id'];
        $r = self::get($cid, $id);
        if (!$r || $r->kind !== 'manual') {
            return ['ok' => false, 'error' => 'این درخواست پیدا نشد.'];
        }
        if ($r->status === 'invoiced' && (int) $r->invoice_id > 0) {
            return ['ok' => true, 'invoice_id' => (int) $r->invoice_id];
        }
        if ($r->status !== 'quoted' || (int) $r->credits <= 0) {
            return ['ok' => false, 'error' => 'قیمتی برای تأیید نیست؛ شاید پیش‌تر تأیید یا لغو شده باشد.'];
        }
        $credits = (int) $r->credits;
        $useCredits = Credits::balance($cid)['total'] >= $credits;
        if (!$useCredits && (float) $r->amount <= 0) {
            return ['ok' => false, 'error' => Lang::t('اعتبار کافی نیست: {n} اعتبار لازم است و شما {have} دارید. از صفحه‌ی «اعتبار و پلن» بسته بخرید و دوباره تأیید کنید.', ['n' => Text::fa($credits), 'have' => Text::fa(Credits::balance($cid)['total'])])];
        }
        // one winner: only the click that moves quoted → paying goes on
        if (Db::table('mod_mcsec_requests')->where('id', $id)->where('client_id', $cid)->where('status', 'quoted')->where('credits', $credits)->update(['status' => 'paying', 'updated_at' => Clock::now()]) !== 1) {
            return ['ok' => false, 'error' => 'این درخواست همین حالا تغییر کرد؛ صفحه را تازه کنید.'];
        }
        if ($useCredits) {
            $paid = Credits::spend($cid, $credits, 'req:' . $id, Lang::t('تست دستی امنیت (درخواست {id})', ['id' => $id]));
            if ($paid['ok']) {
                Db::table('mod_mcsec_requests')->where('id', $id)->update(['status' => 'accepted', 'paid_with' => 'credits', 'accepted_at' => Clock::now(), 'accepted_by' => (int) $who['user_id'], 'updated_at' => Clock::now()]);
                Audit::log($cid, 'request_accept', '#' . $id, ['credits' => $credits], (int) $who['user_id']);
                return ['ok' => true, 'credits' => $credits];
            }
            if ((float) $r->amount <= 0) {
                Db::table('mod_mcsec_requests')->where('id', $id)->where('status', 'paying')->update(['status' => 'quoted']);
                return ['ok' => false, 'error' => $paid['error']];
            }
        }
        $asset = (int) $r->asset_id > 0 ? (string) (Assets::get($cid, (int) $r->asset_id)->value ?? '') : '';
        $inv = Whmcs::createInvoice($cid, Lang::t('تست دستی امنیت MC-Sec{asset} #R{id}', ['asset' => $asset !== '' ? ' (' . $asset . ')' : '', 'id' => $id]), (float) $r->amount, Settings::int('invoice_due_days'));
        if (!$inv['ok'] || $inv['invoice_id'] <= 0) {
            Db::table('mod_mcsec_requests')->where('id', $id)->where('status', 'paying')->update(['status' => 'quoted']);
            $ref = Trace::error('whmcs', 'request.invoice', (string) $inv['error'], ['request' => $id], ['client_id' => $cid]);
            return ['ok' => false, 'error' => Lang::t('فاکتور ساخته نشد. کمی بعد دوباره امتحان کنید؛ اگر تکرار شد این کد را به پشتیبانی بدهید: {ref}', ['ref' => $ref])];
        }
        Db::table('mod_mcsec_requests')->where('id', $id)->update(['status' => 'invoiced', 'invoice_id' => (int) $inv['invoice_id'], 'accepted_at' => Clock::now(), 'accepted_by' => (int) $who['user_id'], 'updated_at' => Clock::now()]);
        Audit::log($cid, 'request_accept', '#' . $id, ['invoice' => (int) $inv['invoice_id'], 'amount' => (float) $r->amount], (int) $who['user_id']);
        return ['ok' => true, 'invoice_id' => (int) $inv['invoice_id']];
    }

    /** @return array{ok:bool,error?:string} */
    public static function decline(array $who, int $id): array
    {
        $cid = (int) $who['client_id'];
        if (Db::table('mod_mcsec_requests')->where('id', $id)->where('client_id', $cid)->where('status', 'quoted')->update(['status' => 'declined', 'closed_at' => Clock::now(), 'updated_at' => Clock::now()]) !== 1) {
            return ['ok' => false, 'error' => 'قیمتی برای رد کردن نیست.'];
        }
        Audit::log($cid, 'request_decline', '#' . $id, [], (int) $who['user_id']);
        return ['ok' => true];
    }

    /** InvoicePaid hook: the invoice of a manual test was paid. @return int requests moved on */
    public static function invoicePaid(int $invoiceId): int
    {
        $n = 0;
        foreach (Db::rows(Db::table('mod_mcsec_requests')->where('invoice_id', $invoiceId)->where('status', 'invoiced')) as $r) {
            $inv = Whmcs::invoice($invoiceId);
            if (!$inv || (int) $inv->userid !== (int) $r->client_id || $inv->status !== 'Paid') {
                continue;
            }
            if (Db::table('mod_mcsec_requests')->where('id', $r->id)->where('status', 'invoiced')->update(['status' => 'accepted', 'paid_with' => 'invoice', 'updated_at' => Clock::now()]) === 1) {
                Notify::event((int) $r->client_id, 'request_update', ['what' => 'paid', 'id' => (int) $r->id], 'reqp:' . $r->id);
                $n++;
            }
        }
        return $n;
    }

    /** Worker: invoices paid while the hook did not fire, and a click that died between "paying" and its result. */
    public static function reconcile(): int
    {
        $n = 0;
        foreach (Db::rows(Db::table('mod_mcsec_requests')->where('status', 'invoiced')->where('invoice_id', '>', 0)->where('updated_at', '>', Clock::now() - 90 * 86400)->limit(200)) as $r) {
            $n += self::invoicePaid((int) $r->invoice_id);
        }
        foreach (Db::rows(Db::table('mod_mcsec_requests')->where('status', 'paying')->where('updated_at', '<', Clock::now() - 600)->limit(50)) as $r) {
            // credits taken (the ledger has the row) means it was accepted; otherwise the price is offered again
            $took = Db::table('mod_mcsec_ledger')->where('client_id', (int) $r->client_id)->whereIn('ref', ['req:' . (int) $r->id . ':m', 'req:' . (int) $r->id . ':p'])->where('delta', '<', 0)->exists();
            Db::table('mod_mcsec_requests')->where('id', $r->id)->where('status', 'paying')->update($took ? ['status' => 'accepted', 'paid_with' => 'credits', 'accepted_at' => Clock::now()] : ['status' => 'quoted']);
            $n++;
        }
        return $n;
    }

    // ── the panel ──

    /** @return object[] */
    public static function all(string $filter = 'open', int $limit = 100): array
    {
        $q = Db::table('mod_mcsec_requests');
        if ($filter === 'open') {
            $q->whereIn('status', ['new', 'quoted', 'invoiced', 'accepted', 'working', 'paying']);
        } elseif ($filter === 'closed') {
            $q->whereIn('status', ['done', 'declined', 'cancelled']);
        }
        return Db::rows($q->orderByDesc('id')->limit($limit));
    }

    /** Requests that wait for the team: new ones, and paid ones not started. */
    public static function waiting(): int
    {
        try {
            return Db::table('mod_mcsec_requests')->whereIn('status', ['new', 'accepted'])->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }
}
