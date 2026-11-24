<?php

declare(strict_types=1);

namespace McSec;

/**
 * Codes (mod_mcsec_codes): one mechanism and one box («کد دارید؟») for everything a customer can type in.
 *  - credit:   free credits now (until the end of this month, or without expiry: the admin's choice per code);
 *  - discount: % off the next credit pack;      - bonus: % more credits on the next pack at the same price;
 *  - gift:     credits a customer bought for a friend (made after the gift pack's invoice is paid);
 *  - invite:   every account's own code; the newcomer gets credits, the inviter is rewarded when the newcomer
 *              proves a first asset and again on the newcomer's first paid pack.
 * A code works once per account (unique code_id + client_id), its use count moves with a conditional update, and
 * every credit it gives is one ledger row with its own ref, so nothing can apply twice. Discounts never stack
 * (Credits::offer). Money still only moves through WHMCS invoices. See skill mcsec-billing-safety.
 */
final class Codes
{
    public const KINDS = ['credit' => 'اعتبار رایگان', 'discount' => 'تخفیف بسته', 'bonus' => 'اعتبار بیشتر روی بسته', 'gift' => 'هدیه', 'invite' => 'دعوت'];
    /** Kinds an admin makes by hand (gift and invite codes are made by the system). */
    public const ADMIN_KINDS = ['credit', 'discount', 'bonus'];
    /** A newcomer may use an invite code this long after opening the workspace. */
    private const INVITE_WINDOW = 30 * 86400;
    private const GIFT_RETURN_AFTER = 365 * 86400;

    /** What people type: Latin capitals, digits and dashes (Persian digits and spaces are forgiven). */
    public static function normalize(string $raw): string
    {
        return substr((string) preg_replace('~[^A-Z0-9-]~', '', strtoupper(Text::toAscii($raw))), 0, 24);
    }

    private static function random(string $prefix): string
    {
        // no 0/O/1/I: codes are read aloud and typed by hand
        $abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        for ($try = 0; $try < 20; $try++) {
            $c = $prefix;
            for ($i = 0; $i < 8; $i++) {
                $c .= ($i === 4 ? '-' : '') . $abc[random_int(0, 31)];
            }
            if (!Db::table('mod_mcsec_codes')->where('code', $c)->exists()) {
                return $c;
            }
        }
        throw new \RuntimeException('no free code');
    }

    /** Admin: a campaign code. @return array{ok:bool,error?:string,code?:string} */
    public static function create(array $in, int $adminId = 0): array
    {
        // i18n-skip-begin (codes are made in the admin panel only; its messages stay Persian)
        $kind = (string) ($in['kind'] ?? '');
        if (!in_array($kind, self::ADMIN_KINDS, true)) {
            return ['ok' => false, 'error' => 'نوع کد را انتخاب کنید.'];
        }
        $value = (int) ($in['value'] ?? 0);
        if ($kind === 'credit' ? ($value < 1 || $value > 100000) : ($value < 1 || $value > ($kind === 'discount' ? 90 : 300))) {
            return ['ok' => false, 'error' => $kind === 'credit' ? 'تعداد اعتبار را بنویسید (۱ تا ۱۰۰٬۰۰۰).' : ($kind === 'discount' ? 'درصد تخفیف باید ۱ تا ۹۰ باشد.' : 'درصد اعتبار بیشتر باید ۱ تا ۳۰۰ باشد.')];
        }
        $code = self::normalize((string) ($in['code'] ?? ''));
        if ($code === '') {
            $code = self::random('');
        } elseif (strlen($code) < 4) {
            return ['ok' => false, 'error' => 'کد دست‌کم ۴ حرف یا رقم لاتین باشد (یا خالی بگذارید تا ساخته شود).'];
        } elseif (Db::table('mod_mcsec_codes')->where('code', $code)->exists()) {
            return ['ok' => false, 'error' => 'این کد قبلاً ساخته شده است.'];
        }
        $client = max(0, (int) ($in['client_id'] ?? 0));
        if ($client > 0 && !Whmcs::client($client)) {
            return ['ok' => false, 'error' => 'حسابی با این شماره پیدا نشد.'];
        }
        // i18n-skip-end
        $days = max(0, (int) ($in['days'] ?? 0));
        Db::table('mod_mcsec_codes')->insert([
            'code' => $code, 'kind' => $kind, 'value' => $value, 'bucket' => ($in['bucket'] ?? '') === 'monthly' ? 'monthly' : 'paid',
            'max_uses' => max(0, (int) ($in['max_uses'] ?? 0)), 'group_id' => max(0, (int) ($in['group_id'] ?? 0)), 'client_id' => $client,
            'starts_at' => Clock::now(), 'expires_at' => $days > 0 ? Clock::now() + $days * 86400 : 0, 'note' => Text::name((string) ($in['note'] ?? ''), 160),
            'admin_id' => $adminId, 'created_at' => Clock::now(),
        ]);
        Audit::log(0, 'code', $code, ['kind' => $kind, 'value' => $value]);
        return ['ok' => true, 'code' => $code];
    }

    public static function disable(int $id): bool
    {
        return Db::table('mod_mcsec_codes')->where('id', $id)->whereIn('kind', self::ADMIN_KINDS)->where('enabled', 1)->update(['enabled' => 0]) > 0;
    }

    /** Why this code cannot be used by this account now ('' = it can). */
    private static function refusal(object $c, int $clientId): string
    {
        $now = Clock::now();
        if ((int) $c->enabled !== 1 || (int) $c->starts_at > $now) {
            return 'این کد دیگر فعال نیست.';
        }
        if ((int) $c->expires_at > 0 && (int) $c->expires_at <= $now) {
            return 'مهلت این کد تمام شده است.';
        }
        if ((int) $c->client_id > 0 && (int) $c->client_id !== $clientId) {
            return 'این کد برای حساب دیگری ساخته شده است.';
        }
        if ((int) $c->group_id > 0 && Whmcs::groupOf($clientId) !== (int) $c->group_id) {
            return 'این کد برای گروه دیگری از مشتریان است.';
        }
        return '';
    }

    /**
     * The customer typed a code. @return array{ok:bool,error?:string,message?:string}
     */
    public static function redeem(array $who, string $raw): array
    {
        $cid = (int) $who['client_id'];
        $code = self::normalize($raw);
        if ($code === '') {
            return ['ok' => false, 'error' => 'کد را بنویسید.'];
        }
        // guessing codes is slow: every try counts
        if (!RateLimit::hit('code:' . $cid, 12, 3600)) {
            return ['ok' => false, 'error' => 'چند کد پشت سر هم امتحان شد. یک ساعت دیگر دوباره امتحان کنید.'];
        }
        $c = Db::table('mod_mcsec_codes')->where('code', $code)->first();
        if (!$c) {
            return ['ok' => false, 'error' => 'این کد پیدا نشد. حروف و رقم‌ها را دوباره نگاه کنید.'];
        }
        $why = self::refusal($c, $cid);
        if ($why !== '') {
            return ['ok' => false, 'error' => $why];
        }
        $r = match ((string) $c->kind) {
            'credit', 'gift' => self::takeCredits($c, $cid, (int) $who['user_id']),
            'discount', 'bonus' => self::keepForPack($c, $cid, (int) $who['user_id']),
            'invite' => self::acceptInvite($c, $cid, (int) $who['user_id']),
            default => ['ok' => false, 'error' => 'این کد شناخته نشد.'],
        };
        if ($r['ok']) {
            Audit::log($cid, 'code', $code, ['kind' => (string) $c->kind], (int) $who['user_id']);
        }
        return $r;
    }

    /** Takes one use of a code for an account, or throws (inside a transaction: all or nothing). */
    private static function claim(object $c, int $clientId, int $userId, string $status): void
    {
        try {
            Db::table('mod_mcsec_redemptions')->insert(['code_id' => (int) $c->id, 'client_id' => $clientId, 'status' => $status, 'user_id' => $userId, 'created_at' => Clock::now()]);
        } catch (\Throwable $e) {
            throw new \DomainException('این کد را قبلاً استفاده کرده‌اید.');
        }
        $q = Db::table('mod_mcsec_codes')->where('id', (int) $c->id)->where('enabled', 1);
        if ((int) $c->max_uses > 0) {
            $q->where('used', '<', (int) $c->max_uses);
        }
        if ($q->increment('used') !== 1) {
            throw new \DomainException('ظرفیت این کد پر شده است.');
        }
    }

    private static function takeCredits(object $c, int $clientId, int $userId): array
    {
        Credits::balance($clientId); // the wallet exists before the transaction
        $gift = $c->kind === 'gift';
        try {
            Db::tx(function () use ($c, $clientId, $userId, $gift) {
                self::claim($c, $clientId, $userId, 'done');
                $note = Credits::forAccount($clientId, fn () => $gift ? Lang::t('کد هدیه {code}', ['code' => $c->code]) : Lang::t('کد {code}', ['code' => $c->code]));
                if (!Credits::credit($clientId, (int) $c->value, $gift ? 'paid' : (string) $c->bucket, $gift ? 'gift' : 'code', 'code:' . $c->id . ':' . $clientId, $note)) {
                    throw new \DomainException('این کد را قبلاً استفاده کرده‌اید.');
                }
            });
        } catch (\DomainException $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }
        if ($gift && (int) $c->owner_client > 0 && (int) $c->owner_client !== $clientId) {
            // the buyer of the gift reads this, in the buyer's language
            Credits::forAccount((int) $c->owner_client, fn () => Notify::event((int) $c->owner_client, 'billing', ['title' => Lang::t('هدیه‌ی شما استفاده شد'),
                'lines' => [Lang::t('کد هدیه‌ی {code} ({n} اعتبار) را دوستتان فعال کرد.', ['code' => $c->code, 'n' => Text::fa((int) $c->value)])],
                'link' => 'index.php?m=mcsec&p=credits', 'tone' => 'ok'], 'giftused:' . $c->id));
        }
        return ['ok' => true, 'message' => !$gift && $c->bucket === 'monthly' ? Lang::t('{n} اعتبار به حساب شما افزوده شد و تا پایان همین ماه شمسی معتبر است.', ['n' => Text::fa((int) $c->value)])
            : Lang::t('{n} اعتبار به حساب شما افزوده شد.', ['n' => Text::fa((int) $c->value)])];
    }

    /** A discount or bonus code waits on the account for the next pack; a newer one takes its place. */
    private static function keepForPack(object $c, int $clientId, int $userId): array
    {
        $mine = Db::table('mod_mcsec_redemptions')->where('code_id', (int) $c->id)->where('client_id', $clientId)->first();
        if ($mine && !in_array($mine->status, ['pending', 'replaced'], true)) {
            return ['ok' => false, 'error' => 'این کد را قبلاً استفاده کرده‌اید.'];
        }
        try {
            Db::tx(function () use ($c, $clientId, $userId, $mine) {
                Db::table('mod_mcsec_redemptions')->where('client_id', $clientId)->where('status', 'pending')->update(['status' => 'replaced']);
                if ($mine) {
                    Db::table('mod_mcsec_redemptions')->where('id', (int) $mine->id)->update(['status' => 'pending']);
                } else {
                    self::claim($c, $clientId, $userId, 'pending');
                }
            });
        } catch (\DomainException $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }
        return ['ok' => true, 'message' => $c->kind === 'discount' ? Lang::t('کد پذیرفته شد: {n}٪ تخفیف روی خرید بعدی بسته‌ی اعتبار. قیمت‌های پایین همین صفحه به‌روز شد.', ['n' => Text::fa((int) $c->value)])
            : Lang::t('کد پذیرفته شد: با خرید بعدی، {n}٪ اعتبار بیشتر می‌گیرید.', ['n' => Text::fa((int) $c->value)])];
    }

    /** The discount or bonus code waiting on an account, if it is still valid. */
    public static function pending(int $clientId): ?object
    {
        $r = Db::table('mod_mcsec_redemptions')->where('client_id', $clientId)->where('status', 'pending')->orderByDesc('id')->first();
        $c = $r ? Db::table('mod_mcsec_codes')->where('id', (int) $r->code_id)->whereIn('kind', ['discount', 'bonus'])->first() : null;
        return $c && self::refusal($c, $clientId) === '' ? $c : null;
    }

    /** A pack bought with the waiting code was paid: the code is spent. */
    public static function consumed(int $codeId, int $clientId, int $topupId): void
    {
        Db::table('mod_mcsec_redemptions')->where('code_id', $codeId)->where('client_id', $clientId)->where('status', 'pending')->update(['status' => 'used', 'topup_id' => $topupId]);
    }

    // ── gifts ──

    /** A paid gift pack becomes a gift code of the buyer, once (the top-up is marked paid in the same transaction). */
    public static function makeGift(object $topup): string
    {
        $code = Db::tx(function () use ($topup) {
            if (Db::table('mod_mcsec_topups')->where('id', (int) $topup->id)->where('status', 'pending')->update(['status' => 'paid', 'paid_at' => Clock::now()]) !== 1) {
                return '';
            }
            $code = self::random('G');
            Db::table('mod_mcsec_codes')->insert(['code' => $code, 'kind' => 'gift', 'value' => (int) $topup->credits, 'bucket' => 'paid', 'max_uses' => 1, 'owner_client' => (int) $topup->client_id,
                'topup_id' => (int) $topup->id, 'starts_at' => Clock::now(), 'note' => 'هدیه', 'created_at' => Clock::now()]);
            return $code;
        });
        if ($code !== '') {
            Credits::forAccount((int) $topup->client_id, fn () => Notify::event((int) $topup->client_id, 'billing', ['title' => Lang::t('کد هدیه‌ی شما آماده است'),
                'lines' => [Lang::t('کد {code} را به دوستتان بدهید: {n} اعتبار اسکن امنیتی.', ['code' => $code, 'n' => Text::fa((int) $topup->credits)]),
                    Lang::t('او کد را در صفحه‌ی «اعتبار» بخش «کد دارید؟» وارد می‌کند. کدی که تا یک سال استفاده نشود، به اعتبار خودتان برمی‌گردد.')], 'link' => 'index.php?m=mcsec&p=credits', 'tone' => 'ok'], 'gift:' . $topup->id));
        }
        return (string) $code;
    }

    /** The gift codes an account bought, newest first. @return object[] */
    public static function gifts(int $clientId): array
    {
        return Db::rows(Db::table('mod_mcsec_codes')->where('kind', 'gift')->where('owner_client', $clientId)->orderByDesc('id')->limit(30));
    }

    /** Daily: a gift nobody used for a year goes back to the buyer's own credits, once. */
    public static function returnGifts(): int
    {
        $n = 0;
        foreach (Db::rows(Db::table('mod_mcsec_codes')->where('kind', 'gift')->where('used', 0)->where('enabled', 1)->where('created_at', '<', Clock::now() - self::GIFT_RETURN_AFTER)->limit(200)) as $c) {
            // taking the single use first: a friend who redeems at the same moment and this step cannot both win
            if (Db::table('mod_mcsec_codes')->where('id', (int) $c->id)->where('used', 0)->update(['used' => 1, 'enabled' => 0]) !== 1) {
                continue;
            }
            $n += (int) Credits::forAccount((int) $c->owner_client, function () use ($c): int {
                if (!Credits::credit((int) $c->owner_client, (int) $c->value, 'paid', 'gift', 'giftback:' . $c->id, Lang::t('برگشت هدیه‌ی استفاده‌نشده {code}', ['code' => $c->code]))) {
                    return 0;
                }
                Notify::event((int) $c->owner_client, 'credits_added', ['credits' => (int) $c->value, 'note' => Lang::t('کد هدیه‌ی {code} یک سال استفاده نشد و اعتبارش به حساب خودتان برگشت.', ['code' => $c->code])], 'giftback:' . $c->id);
                return 1;
            });
        }
        return $n;
    }

    // ── invites ──

    /** The account's own invite code (made on first use). '' while invites are off. */
    public static function inviteCode(int $clientId): string
    {
        if (!Settings::bool('invite_enabled')) {
            return '';
        }
        $c = Db::table('mod_mcsec_codes')->where('kind', 'invite')->where('owner_client', $clientId)->value('code');
        if ($c === null) {
            $c = self::random('I');
            Db::table('mod_mcsec_codes')->insert(['code' => $c, 'kind' => 'invite', 'owner_client' => $clientId, 'starts_at' => Clock::now(), 'created_at' => Clock::now()]);
        }
        return (string) $c;
    }

    /** @return array{invited:int,earned:int} */
    public static function inviteStats(int $clientId): array
    {
        return ['invited' => Db::table('mod_mcsec_accounts')->where('invited_by', $clientId)->count(),
            'earned' => (int) Db::table('mod_mcsec_ledger')->where('client_id', $clientId)->where('kind', 'invite')->where('ref', 'not like', 'invite:new:%')->sum('delta')];
    }

    private static function acceptInvite(object $c, int $clientId, int $userId): array
    {
        $inviter = (int) $c->owner_client;
        if (!Settings::bool('invite_enabled')) {
            return ['ok' => false, 'error' => 'دعوت از دوستان فعلاً فعال نیست.'];
        }
        if ($inviter === $clientId) {
            return ['ok' => false, 'error' => 'این کد دعوت خود شماست؛ آن را به دوستانتان بدهید.'];
        }
        $acc = Accounts::ensure($clientId);
        if ((int) $acc->invited_by > 0) {
            return ['ok' => false, 'error' => 'شما قبلاً با یک کد دعوت آمده‌اید.'];
        }
        $me = Whmcs::client($clientId);
        $them = Whmcs::client($inviter);
        if (!$them || ($me && strtolower((string) $me->email) === strtolower((string) $them->email))) {
            return ['ok' => false, 'error' => 'این کد دعوت برای حساب شما پذیرفته نیست.'];
        }
        // only newcomers: a fresh workspace that has not bought anything yet
        if ((int) $acc->created_at < Clock::now() - self::INVITE_WINDOW || Db::table('mod_mcsec_topups')->where('client_id', $clientId)->where('status', 'paid')->exists()) {
            return ['ok' => false, 'error' => 'کد دعوت فقط برای حساب‌های تازه است (تا ۳۰ روز پس از شروع و پیش از اولین خرید).'];
        }
        $cap = max(1, Settings::int('invite_month_cap'));
        if (Db::table('mod_mcsec_accounts')->where('invited_by', $inviter)->where('invited_at', '>', Clock::now() - 30 * 86400)->count() >= $cap) {
            return ['ok' => false, 'error' => 'دعوت‌کننده‌ی شما این ماه به سقف دعوت رسیده است. ماه بعد دوباره امتحان کنید.'];
        }
        if (Db::table('mod_mcsec_accounts')->where('client_id', $clientId)->where('invited_by', 0)->update(['invited_by' => $inviter, 'invited_at' => Clock::now()]) !== 1) {
            return ['ok' => false, 'error' => 'شما قبلاً با یک کد دعوت آمده‌اید.'];
        }
        Accounts::forget($clientId);
        Db::table('mod_mcsec_codes')->where('id', (int) $c->id)->increment('used');
        $n = max(0, Settings::int('invite_new_credits'));
        if ($n > 0) {
            Credits::credit($clientId, $n, 'paid', 'invite', 'invite:new:' . $clientId, 'هدیه‌ی دعوت');
        }
        return ['ok' => true, 'message' => $n > 0 ? Lang::t('خوش آمدید! {n} اعتبار هدیه‌ی دعوت به حساب شما افزوده شد.', ['n' => Text::fa($n)]) : Lang::t('کد دعوت ثبت شد.')];
    }

    /** The invited account proved its first asset: the inviter's small reward, once. */
    public static function onVerified(int $clientId): void
    {
        self::reward($clientId, 'v', Settings::int('invite_reward_verify'), 'دوستی که دعوت کردید اولین دارایی‌اش را تأیید کرد.');
    }

    /** The invited account paid its first pack: the inviter's main reward, once. */
    public static function onPaid(int $clientId): void
    {
        self::reward($clientId, 'b', Settings::int('invite_reward_buy'), 'دوستی که دعوت کردید اولین خریدش را انجام داد.');
    }

    private static function reward(int $invitee, string $step, int $credits, string $why): void
    {
        if ($credits <= 0 || !Settings::bool('invite_enabled')) {
            return;
        }
        $acc = Accounts::get($invitee);
        $inviter = $acc ? (int) ($acc->invited_by ?? 0) : 0;
        if ($inviter <= 0 || $inviter === $invitee) {
            return;
        }
        if (Credits::credit($inviter, $credits, 'paid', 'invite', 'invite:' . $step . ':' . $invitee, 'جایزه‌ی دعوت از دوستان')) {
            // two whole sentences, in the inviter's language ($why is one of the two fixed texts above)
            Credits::forAccount($inviter, fn () => Notify::event($inviter, 'credits_added', ['credits' => $credits, 'note' => Lang::t($why) . ' ' . Lang::t('ممنون که مارال کلاد را معرفی می‌کنید.')], 'invite:' . $step . ':' . $invitee));
        }
    }
}
