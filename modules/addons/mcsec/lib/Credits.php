<?php

declare(strict_types=1);

namespace McSec;

/**
 * Scan credits. Two buckets per account:
 *  - monthly: free credits of the client's group and the monthly credits of active plans; filled once per Jalali month
 *    (Tehran time) and not carried over (the leftover expires with a ledger row);
 *  - paid: welcome credits, credit packs and admin grants; never expire.
 * Spending takes the monthly bucket first. Every movement is one ledger row with a unique `ref` (idempotency: the same
 * grant, top-up, spend or refund can never apply twice, whatever retries or double clicks happen), and the wallet is
 * changed with conditional atomic updates, so the balance never goes negative. See skill mcsec-billing-safety.
 */
final class Credits
{
    /** Jalali year-month in Tehran time, e.g. "1405-08". */
    public static function period(?int $ts = null): string
    {
        $d = (new \DateTimeImmutable('@' . ($ts ?? Clock::now())))->setTimezone(new \DateTimeZone('Asia/Tehran'));
        [$y, $m] = Text::jalali((int) $d->format('Y'), (int) $d->format('n'), (int) $d->format('j'));
        return sprintf('%04d-%02d', $y, $m);
    }

    /** @return array{monthly:int,paid:int,total:int,period:string} */
    public static function balance(int $clientId): array
    {
        self::refresh($clientId);
        $w = Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->first();
        $m = (int) ($w->monthly ?? 0);
        $p = (int) ($w->paid ?? 0);
        return ['monthly' => $m, 'paid' => $p, 'total' => $m + $p, 'period' => (string) ($w->period ?? self::period())];
    }

    private static function wallet(int $clientId): object
    {
        $w = Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->first();
        if (!$w) {
            try {
                Db::table('mod_mcsec_wallets')->insert(['client_id' => $clientId, 'monthly' => 0, 'period' => self::period(), 'paid' => 0, 'updated_at' => Clock::now()]);
            } catch (\Throwable $e) {
                // created by a parallel request
            }
            $w = Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->first();
        }
        return $w;
    }

    /**
     * New month: the leftover monthly credits expire, then this month's group and plan credits are added (each once
     * per period). Cheap when nothing is due (one read).
     */
    public static function refresh(int $clientId): void
    {
        $w = self::wallet($clientId);
        $now = self::period();
        if ((string) $w->period !== $now) {
            // only the request that moves the period on expires the leftover
            if (Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->where('period', (string) $w->period)->update(['period' => $now, 'updated_at' => Clock::now()]) === 1) {
                $left = (int) Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->value('monthly');
                if ($left > 0) {
                    self::debit($clientId, $left, 'monthly', 'expire', 'expire:' . $clientId . ':' . $w->period,
                        self::forAccount($clientId, fn () => Lang::t('پایان اعتبار ماهانه‌ی {period}', ['period' => Text::fa((string) $w->period)])));
                }
            }
        }
        // one rule per account (its own, else its group's): the ref is the same for both, so a month never pays twice
        $rule = Rules::of($clientId);
        if ($rule['monthly'] > 0) {
            self::credit($clientId, $rule['monthly'], 'monthly', 'group', 'group:' . $clientId . ':' . $now, 'اعتبار ماهانه‌ی رایگان');
        }
        foreach (Plans::active($clientId) as $plan) {
            if ((int) $plan->monthly_credits > 0) {
                self::credit($clientId, (int) $plan->monthly_credits, 'monthly', 'plan', 'plan:' . $plan->service_id . ':' . $now,
                    self::forAccount($clientId, fn () => Lang::t('اعتبار ماهانه‌ی پلن {name}', ['name' => $plan->name])));
            }
        }
    }

    /**
     * Runs $fn in the account's own language: for what is written about an account whoever is looking (ledger notes
     * with a name or a number in them, invoice lines and notices made in the background). A note that is one fixed
     * text stays as it is and is translated when the page shows it.
     */
    public static function forAccount(int $clientId, callable $fn)
    {
        return Lang::with(Lang::forClient($clientId), $fn);
    }

    /** Adds credits once per ref. Returns false when that ref was already applied. */
    public static function credit(int $clientId, int $amount, string $bucket, string $kind, string $ref, string $note = '', int $adminId = 0, int $scanId = 0): bool
    {
        if ($amount <= 0 || !in_array($bucket, ['monthly', 'paid'], true)) {
            return false;
        }
        self::wallet($clientId);
        return (bool) Db::tx(function () use ($clientId, $amount, $bucket, $kind, $ref, $note, $adminId, $scanId) {
            if (!self::book($clientId, $amount, $bucket, $kind, $ref, $note, $adminId, $scanId)) {
                return false;
            }
            Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->increment($bucket, $amount, ['updated_at' => Clock::now()]);
            self::stampBalance($clientId, $ref);
            return true;
        });
    }

    /** Removes up to $amount from one bucket once per ref (expiry, admin correction). */
    public static function debit(int $clientId, int $amount, string $bucket, string $kind, string $ref, string $note = '', int $adminId = 0): bool
    {
        if ($amount <= 0) {
            return false;
        }
        return (bool) Db::tx(function () use ($clientId, $amount, $bucket, $kind, $ref, $note, $adminId) {
            $have = (int) Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->value($bucket);
            $take = min($have, $amount);
            if ($take <= 0 || !self::book($clientId, -$take, $bucket, $kind, $ref, $note, $adminId, 0)) {
                return false;
            }
            if (Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->where($bucket, '>=', $take)->decrement($bucket, $take, ['updated_at' => Clock::now()]) !== 1) {
                throw new \RuntimeException('wallet changed during debit');
            }
            self::stampBalance($clientId, $ref);
            return true;
        });
    }

    /**
     * Pays for a scan or report: monthly first, then paid. All or nothing.
     * @return array{ok:bool,error:string,monthly:int,paid:int}
     */
    public static function spend(int $clientId, int $amount, string $ref, string $note, int $scanId = 0): array
    {
        if ($amount <= 0) {
            return ['ok' => true, 'error' => '', 'monthly' => 0, 'paid' => 0];
        }
        self::refresh($clientId);
        try {
            return Db::tx(function () use ($clientId, $amount, $ref, $note, $scanId) {
                if (Db::table('mod_mcsec_ledger')->where('ref', $ref . ':m')->orWhere('ref', $ref . ':p')->exists()) {
                    return ['ok' => true, 'error' => '', 'monthly' => 0, 'paid' => 0, 'again' => true];
                }
                $w = Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->first();
                $fromM = min((int) $w->monthly, $amount);
                $fromP = $amount - $fromM;
                if ($fromP > (int) $w->paid) {
                    return ['ok' => false, 'error' => Lang::t('اعتبار کافی نیست: {need} اعتبار لازم است و {have} دارید.', ['need' => Text::fa($amount), 'have' => Text::fa((int) $w->monthly + (int) $w->paid)]), 'monthly' => 0, 'paid' => 0];
                }
                if ($fromM > 0) {
                    self::book($clientId, -$fromM, 'monthly', 'spend', $ref . ':m', $note, 0, $scanId);
                    if (Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->where('monthly', '>=', $fromM)->decrement('monthly', $fromM) !== 1) {
                        throw new \RuntimeException('race');
                    }
                }
                if ($fromP > 0) {
                    self::book($clientId, -$fromP, 'paid', 'spend', $ref . ':p', $note, 0, $scanId);
                    if (Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->where('paid', '>=', $fromP)->decrement('paid', $fromP) !== 1) {
                        throw new \RuntimeException('race');
                    }
                }
                Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->update(['updated_at' => Clock::now()]);
                self::stampBalance($clientId, $fromP > 0 ? $ref . ':p' : $ref . ':m');
                return ['ok' => true, 'error' => '', 'monthly' => $fromM, 'paid' => $fromP];
            });
        } catch (\Throwable $e) {
            Trace::warn('credit', 'spend', $e->getMessage(), ['ref' => $ref], ['client_id' => $clientId]);
            return ['ok' => false, 'error' => Lang::t('کسر اعتبار همزمان با کار دیگری بود؛ دوباره امتحان کنید.'), 'monthly' => 0, 'paid' => 0];
        }
    }

    /**
     * Gives back what one spend took, once: to the same bucket while the month is the same, otherwise to paid
     * (a refund never disappears with the month change).
     */
    public static function refund(int $clientId, string $spendRef, string $note, int $scanId = 0): int
    {
        $back = 0;
        foreach (['m' => 'monthly', 'p' => 'paid'] as $s => $bucket) {
            $row = Db::table('mod_mcsec_ledger')->where('ref', $spendRef . ':' . $s)->first();
            if (!$row || (int) $row->delta >= 0) {
                continue;
            }
            $amount = -(int) $row->delta;
            $to = $bucket === 'monthly' && self::period((int) $row->created_at) !== self::period() ? 'paid' : $bucket;
            if (self::credit($clientId, $amount, $to, 'refund', 'refund:' . $spendRef . ':' . $s, $note, 0, $scanId)) {
                $back += $amount;
            }
        }
        return $back;
    }

    private static function book(int $clientId, int $delta, string $bucket, string $kind, string $ref, string $note, int $adminId, int $scanId): bool
    {
        if (Db::table('mod_mcsec_ledger')->where('ref', $ref)->exists()) {
            return false;
        }
        try {
            Db::table('mod_mcsec_ledger')->insert([
                'client_id' => $clientId, 'delta' => $delta, 'bucket' => $bucket, 'kind' => $kind, 'ref' => substr($ref, 0, 96),
                'note' => mb_substr($note, 0, 255), 'scan_id' => $scanId, 'admin_id' => $adminId, 'created_at' => Clock::now(),
            ]);
        } catch (\Throwable $e) {
            return false; // the unique ref: a parallel request booked it first
        }
        return true;
    }

    private static function stampBalance(int $clientId, string $ref): void
    {
        $w = Db::table('mod_mcsec_wallets')->where('client_id', $clientId)->first();
        Db::table('mod_mcsec_ledger')->where('ref', $ref)->update(['balance_after' => (int) $w->monthly + (int) $w->paid]);
    }

    public static function ledger(int $clientId, int $limit = 100): array
    {
        return Db::rows(Db::table('mod_mcsec_ledger')->where('client_id', $clientId)->orderByDesc('id')->limit($limit));
    }

    public const KINDS = ['welcome' => 'خوش‌آمد', 'group' => 'رایگان گروه', 'plan' => 'پلن', 'topup' => 'خرید', 'grant' => 'هدیه‌ی مدیر', 'spend' => 'مصرف',
        'refund' => 'بازگشت', 'expire' => 'پایان ماه', 'adjust' => 'اصلاح', 'code' => 'کد', 'gift' => 'هدیه', 'invite' => 'دعوت دوستان'];

    // ── credit packs: invoice → InvoicePaid hook → credits ──

    /** @return array<string,array{key:string,credits:int,price:float,label:string}> */
    public static function packs(): array
    {
        $out = [];
        foreach (Settings::json('credit_packs') as $p) {
            $key = preg_replace('~[^a-z0-9_-]~', '', strtolower((string) ($p['key'] ?? '')));
            if ($key === '' || (int) ($p['credits'] ?? 0) <= 0 || (float) ($p['price'] ?? 0) <= 0) {
                continue;
            }
            $out[$key] = ['key' => $key, 'credits' => (int) $p['credits'], 'price' => (float) $p['price'], // a label is the admin's own text; the module's default labels have their English in the dictionary
                'label' => Lang::whole(Text::name((string) ($p['label'] ?? ''), 80)) ?: Lang::t('{credits} اعتبار', ['credits' => Text::fa((int) $p['credits'])])];
        }
        return $out;
    }

    /**
     * What this account pays for a pack right now. Discounts never stack: of the pack as it is, the account's rule
     * discount and the code waiting on the account (a discount or extra credits), the one with the lowest price per
     * credit wins.
     * @return array{price:float,credits:int,code_id:int,why:string}
     */
    public static function offer(int $clientId, array $pack): array
    {
        $best = ['price' => (float) $pack['price'], 'credits' => (int) $pack['credits'], 'code_id' => 0, 'why' => ''];
        $try = function (float $price, int $credits, int $codeId, string $why) use (&$best): void {
            if ($credits > 0 && $price > 0 && $price / $credits < $best['price'] / $best['credits'] - 1e-9) {
                $best = ['price' => $price, 'credits' => $credits, 'code_id' => $codeId, 'why' => $why];
            }
        };
        $d = Rules::of($clientId)['discount'];
        if ($d > 0) {
            $try(round($pack['price'] * (100 - $d) / 100, 2), (int) $pack['credits'], 0, Lang::t('{n}٪ تخفیف ویژه‌ی حساب شما', ['n' => Text::fa($d)]));
        }
        $code = Codes::pending($clientId);
        if ($code && $code->kind === 'discount') {
            $try(round($pack['price'] * (100 - (int) $code->value) / 100, 2), (int) $pack['credits'], (int) $code->id, Lang::t('{n}٪ تخفیف با کد {code}', ['n' => Text::fa((int) $code->value), 'code' => $code->code]));
        } elseif ($code && $code->kind === 'bonus') {
            $try((float) $pack['price'], (int) $pack['credits'] + intdiv((int) $pack['credits'] * (int) $code->value, 100), (int) $code->id, Lang::t('{n}٪ اعتبار بیشتر با کد {code}', ['n' => Text::fa((int) $code->value), 'code' => $code->code]));
        }
        return $best;
    }

    /**
     * Creates the WHMCS invoice of a pack (one open invoice per pack at a time). $opt: gift (the buyer gets a gift
     * code instead of credits), auto (made by auto top-up).
     */
    public static function buy(array $who, string $packKey, array $opt = []): array
    {
        $pack = self::packs()[$packKey] ?? null;
        if (!$pack) {
            return ['ok' => false, 'error' => 'این بسته پیدا نشد.'];
        }
        $clientId = $who['client_id'];
        $gift = !empty($opt['gift']) ? 1 : 0;
        if ($gift && !Settings::bool('gift_enabled')) {
            return ['ok' => false, 'error' => 'خرید هدیه فعلاً در دسترس نیست.'];
        }
        $offer = self::offer($clientId, $pack);
        $open = Db::table('mod_mcsec_topups')->where('client_id', $clientId)->where('pack', $packKey)->where('gift', $gift)->where('status', 'pending')
            ->where('credits', $offer['credits'])->where('created_at', '>', Clock::now() - 7 * 86400)->orderByDesc('id')->first();
        if ($open && $open->invoice_id && abs((float) $open->amount - $offer['price']) < 0.005) {
            $inv = Whmcs::invoice((int) $open->invoice_id);
            if ($inv && $inv->status === 'Unpaid') {
                return ['ok' => true, 'invoice_id' => (int) $open->invoice_id, 'again' => true];
            }
        }
        if (!RateLimit::hit('buy:' . $clientId, 10, 3600)) {
            return ['ok' => false, 'error' => 'در یک ساعت گذشته فاکتورهای زیادی ساخته شد. کمی بعد دوباره امتحان کنید.'];
        }
        $id = Db::table('mod_mcsec_topups')->insertGetId(['client_id' => $clientId, 'pack' => $packKey, 'credits' => $offer['credits'], 'amount' => $offer['price'],
            'status' => 'pending', 'user_id' => (int) ($who['user_id'] ?? 0), 'code_id' => $offer['code_id'], 'gift' => $gift, 'auto' => !empty($opt['auto']) ? 1 : 0, 'created_at' => Clock::now()]);
        // the invoice line is read by the customer: the visitor's language here, the account's when auto top-up made it (autoTopups)
        $vars = ['pack' => $pack['label'], 'n' => $offer['credits'], 'id' => $id];
        $what = $gift ? Lang::t('هدیه‌ی اعتبار اسکن امنیتی MC-Sec: {pack} ({n} credits) #T{id}', $vars) : Lang::t('اعتبار اسکن امنیتی MC-Sec: {pack} ({n} credits) #T{id}', $vars);
        $r = Whmcs::createInvoice($clientId, $what, $offer['price'], Settings::int('invoice_due_days'));
        if (!$r['ok'] || $r['invoice_id'] <= 0) {
            Db::table('mod_mcsec_topups')->where('id', $id)->update(['status' => 'cancelled']);
            return ['ok' => false, 'error' => 'فاکتور ساخته نشد. لطفاً دوباره امتحان کنید یا به پشتیبانی خبر دهید.'];
        }
        Db::table('mod_mcsec_topups')->where('id', $id)->update(['invoice_id' => $r['invoice_id']]);
        Audit::log($clientId, 'topup', 'invoice ' . $r['invoice_id'], array_filter(['pack' => $packKey, 'gift' => $gift, 'auto' => !empty($opt['auto']), 'code' => $offer['code_id']]), (int) ($who['user_id'] ?? 0));
        return ['ok' => true, 'invoice_id' => $r['invoice_id']];
    }

    /** InvoicePaid hook (and the worker, as a safety net): credits (or a gift code) for every paid pack invoice, once. */
    public static function invoicePaid(int $invoiceId): int
    {
        $done = 0;
        foreach (Db::rows(Db::table('mod_mcsec_topups')->where('invoice_id', $invoiceId)->where('status', 'pending')) as $t) {
            $inv = Whmcs::invoice($invoiceId);
            if (!$inv || $inv->status !== 'Paid' || (int) $inv->userid !== (int) $t->client_id) {
                continue;
            }
            if ((int) ($t->gift ?? 0) === 1) {
                $done += Codes::makeGift($t) !== '' ? 1 : 0; // marks the top-up paid in the same transaction
            } else {
                if (self::credit((int) $t->client_id, (int) $t->credits, 'paid', 'topup', 'topup:' . $t->id, self::forAccount((int) $t->client_id, fn () => Lang::t('خرید بسته (فاکتور {id})', ['id' => $invoiceId])))) {
                    $done++;
                    Notify::event((int) $t->client_id, 'credits_added', ['credits' => (int) $t->credits, 'invoice' => $invoiceId], 'topup:' . $t->id);
                }
                Db::table('mod_mcsec_topups')->where('id', $t->id)->where('status', 'pending')->update(['status' => 'paid', 'paid_at' => Clock::now()]);
            }
            if ((int) ($t->code_id ?? 0) > 0) {
                Codes::consumed((int) $t->code_id, (int) $t->client_id, (int) $t->id);
            }
            Codes::onPaid((int) $t->client_id);
        }
        return $done;
    }

    /**
     * Auto top-up (worker): accounts that asked for it and fell below their threshold get the invoice of their chosen
     * pack. Nothing is charged here; the customer pays the invoice as always. One open auto invoice at a time, and at
     * most auto_topup_month_cap in 30 days. Reads are batched.
     */
    public static function autoTopups(): int
    {
        if (!Settings::bool('auto_topup_enabled')) {
            return 0;
        }
        $n = 0;
        $cap = max(1, Settings::int('auto_topup_month_cap'));
        $accounts = Db::rows(Db::table('mod_mcsec_accounts')->where('auto_pack', '!=', '')->where('auto_below', '>', 0)->limit(2000));
        foreach (array_chunk($accounts, 500) as $chunk) {
            $ids = array_map(fn ($a) => (int) $a->client_id, $chunk);
            $wallets = [];
            foreach (Db::rows(Db::table('mod_mcsec_wallets')->whereIn('client_id', $ids)) as $w) {
                $wallets[(int) $w->client_id] = (int) $w->monthly + (int) $w->paid;
            }
            $recent = [];
            $openAuto = [];
            foreach (Db::rows(Db::table('mod_mcsec_topups')->whereIn('client_id', $ids)->where('auto', 1)->where('created_at', '>', Clock::now() - 30 * 86400)->where('status', '!=', 'cancelled')) as $t) {
                $recent[(int) $t->client_id] = ($recent[(int) $t->client_id] ?? 0) + 1;
                if ($t->status === 'pending') {
                    $openAuto[(int) $t->client_id] = true;
                }
            }
            foreach ($chunk as $a) {
                $cid = (int) $a->client_id;
                if (($wallets[$cid] ?? 0) >= (int) $a->auto_below || isset($openAuto[$cid]) || ($recent[$cid] ?? 0) >= $cap) {
                    continue;
                }
                // the invoice line and the notice are written in the account's own language
                $n += (int) self::forAccount($cid, function () use ($cid, $a): int {
                    $r = self::buy(['client_id' => $cid, 'user_id' => 0], (string) $a->auto_pack, ['auto' => true]);
                    if (!$r['ok'] || !empty($r['again'])) {
                        return 0;
                    }
                    Notify::event($cid, 'billing', ['title' => Lang::t('فاکتور شارژ خودکار اعتبار اسکن ساخته شد'),
                        'lines' => [Lang::t('اعتبار شما به کمتر از {n} رسید. پس از پرداخت فاکتور، اعتبار همان لحظه افزوده می‌شود.', ['n' => Text::fa((int) $a->auto_below)]), Lang::t('شارژ خودکار را هر وقت بخواهید در صفحه‌ی «اعتبار» خاموش کنید.')],
                        'link' => 'viewinvoice.php?id=' . (int) $r['invoice_id'], 'tone' => 'info'], 'auto:' . $r['invoice_id']);
                    return 1;
                });
            }
        }
        return $n;
    }

    /** Turns auto top-up on or off for an account ('' = off). */
    public static function setAuto(array $who, string $packKey, int $below): array
    {
        if ($packKey === '') {
            Accounts::update($who['client_id'], ['auto_pack' => '', 'auto_below' => 0]);
            Audit::log($who['client_id'], 'auto_topup', 'off', [], $who['user_id']);
            return ['ok' => true, 'off' => true];
        }
        if (!Settings::bool('auto_topup_enabled')) {
            return ['ok' => false, 'error' => 'شارژ خودکار فعلاً در دسترس نیست.'];
        }
        if (!isset(self::packs()[$packKey])) {
            return ['ok' => false, 'error' => 'بسته را انتخاب کنید.'];
        }
        if ($below < 1 || $below > 100000) {
            return ['ok' => false, 'error' => 'بنویسید اعتبار به کمتر از چند که رسید فاکتور ساخته شود (مثلاً ۱۰).'];
        }
        Accounts::update($who['client_id'], ['auto_pack' => $packKey, 'auto_below' => $below]);
        Audit::log($who['client_id'], 'auto_topup', $packKey, ['below' => $below], $who['user_id']);
        return ['ok' => true];
    }

    /** Worker safety net: pending top-ups whose invoice got paid while the hook did not run. */
    public static function reconcileTopups(): int
    {
        $n = 0;
        foreach (Db::rows(Db::table('mod_mcsec_topups')->where('status', 'pending')->where('invoice_id', '>', 0)->where('created_at', '>', Clock::now() - 60 * 86400)->limit(200)) as $t) {
            $inv = Whmcs::invoice((int) $t->invoice_id);
            if ($inv && $inv->status === 'Paid') {
                $n += self::invoicePaid((int) $t->invoice_id);
            } elseif ($inv && in_array($inv->status, ['Cancelled', 'Refunded'], true)) {
                Db::table('mod_mcsec_topups')->where('id', $t->id)->update(['status' => 'cancelled']);
            }
        }
        return $n;
    }

    /** Daily: one low-balance notice when the total falls to the threshold (again only after it went back up). */
    public static function lowAlerts(): int
    {
        $limit = Settings::int('low_credit_alert');
        if ($limit <= 0) {
            return 0;
        }
        $n = 0;
        foreach (Db::rows(Db::table('mod_mcsec_wallets')->whereRaw('monthly + paid <= ?', [$limit])->limit(2000)) as $w) {
            $acc = Accounts::get((int) $w->client_id);
            if (!$acc || (int) $acc->low_alert_at > Clock::now() - 14 * 86400) {
                continue;
            }
            $hasSchedules = Db::table('mod_mcsec_schedules')->where('client_id', $w->client_id)->where('status', 'active')->exists();
            if (!$hasSchedules) {
                continue; // only people who depend on credits get nudged
            }
            Notify::event((int) $w->client_id, 'credits_low', ['total' => (int) $w->monthly + (int) $w->paid], 'low:' . $w->client_id . ':' . Clock::today());
            Accounts::update((int) $w->client_id, ['low_alert_at' => Clock::now()]);
            $n++;
        }
        return $n;
    }
}
