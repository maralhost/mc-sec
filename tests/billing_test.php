<?php
// 0.7.0 billing: rules (group or account, one applies), codes (credit, discount, bonus), gifts, invites, auto top-up.
// Idempotency, no stacking, no negative balance, IDOR/CSRF/nonce/XSS on the new actions, tbl* untouched.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Codes;
use McSec\Credits;
use McSec\Db;
use McSec\Plans;
use McSec\Rules;
use McSec\Catalog;

$tz = new DateTimeZone('Asia/Tehran');
Clock::$fixed = (new DateTimeImmutable('2026-11-11 10:00', $tz))->getTimestamp(); // 20 Aban 1405
setting('enabled', '1');
setting('access_mode', 'all');
setting('welcome_credits', '0');
setting('credit_packs', json_encode([['key' => 'p100', 'credits' => 100, 'price' => 1000000, 'label' => 'بسته‌ی ۱۰۰'], ['key' => 'p500', 'credits' => 500, 'price' => 4000000, 'label' => 'بسته‌ی ۵۰۰']]));
$pack = Credits::packs()['p100'];
$sum = fn (int $c) => (int) Db::table('mod_mcsec_ledger')->where('client_id', $c)->sum('delta');

section('rules: the account rule wins over the group rule, never both');
ok(Rules::of(3) === Rules::NONE, 'no rule: normal price');
ok(Rules::save(['scope' => 'group', 'target' => 2, 'monthly' => 30, 'max_assets' => 8, 'discount' => 10])['ok'], 'group rule saved');
ok(!Rules::save(['scope' => 'group', 'target' => 99])['ok'] && !Rules::save(['scope' => 'client', 'target' => 9999])['ok'], 'unknown group or account refused');
Accounts::ensure(3);
ok(Credits::balance(3)['monthly'] === 30 && Plans::limits(3)['max_assets'] === 8, 'client 3 (group 2): 30 monthly, 8 assets');
ok(Rules::save(['scope' => 'client', 'target' => 3, 'monthly' => 100, 'spend_pct' => 50, 'discount' => 25, 'profiles' => 'vuln,nope', 'days' => 10])['ok'], 'account rule saved');
$r = Rules::of(3);
ok($r['scope'] === 'client' && $r['monthly'] === 100 && $r['discount'] === 25 && $r['profiles'] === ['vuln'], 'account rule applies; unknown scan types dropped');
Credits::refresh(3);
ok(Credits::balance(3)['monthly'] === 30, 'a second rule in the same month never pays the month twice');
ok(Rules::cost(3, 5) === 3 && Rules::cost(3, 1) === 1 && Rules::cost(1, 5) === 5 && Rules::cost(3, 0) === 0, 'half price, rounded up; others pay the normal price');
$cat = Catalog::forClient(3);
ok($cat['vuln']['allowed'] === true && $cat['vuln']['credits'] === Rules::cost(3, $cat['vuln']['full']), 'the rule opens vuln without a plan, at the lower cost');
ok((Catalog::forClient(1)['vuln']['allowed'] ?? null) === (bool) Catalog::get('vuln')['free'], 'other accounts are not affected');
Clock::$fixed += 11 * 86400; // the account rule ended
Rules::forget();
ok(Rules::of(3)['scope'] === 'group' && Rules::of(3)['discount'] === 10, 'after its end date the group rule is back');
Clock::$fixed -= 11 * 86400;
Rules::forget();
$newer = Rules::save(['scope' => 'group', 'target' => 2, 'monthly' => 40]);
ok(Db::table('mod_mcsec_rules')->where('scope', 'group')->where('target', 2)->where('enabled', 1)->count() === 1, 'a new rule for the same group replaces the old one');
ok(Rules::disable($newer['id']) && !Rules::disable($newer['id']), 'rule removed once');

section('migration of the old group setting');
setting('group_rules', json_encode([['group' => 1, 'monthly' => 7, 'max_assets' => 4]]));
\McSec\Installer::install();
\McSec\Settings::forget();
$m = Db::table('mod_mcsec_rules')->where('scope', 'group')->where('target', 1)->first();
ok($m && (int) $m->monthly === 7 && \McSec\Settings::get('group_rules') === '[]', 'old setting became a rule and was emptied');
\McSec\Installer::install();
ok(Db::table('mod_mcsec_rules')->where('scope', 'group')->where('target', 1)->count() === 1, 'installing again adds nothing');

section('offer: discounts never stack, the best one wins');
Rules::forget();
ok(Credits::offer(1, $pack)['price'] === 1000000.0 && Credits::offer(1, $pack)['why'] === '', 'no rule, no code: list price');
ok(Credits::offer(3, $pack)['price'] === 750000.0 && Credits::offer(3, $pack)['code_id'] === 0, 'client 3: 25% from its rule');
$who3 = login(3, 3);
ok(Codes::create(['kind' => 'discount', 'value' => 10, 'code' => 'small10'])['ok'], 'discount code made (normalised to capitals)');
ok(Codes::redeem($who3, 'SMALL10')['ok'] && Credits::offer(3, $pack)['price'] === 750000.0, '10% code + 25% rule: still 25%, not 35%');
ok(Codes::create(['kind' => 'discount', 'value' => 40, 'code' => 'BIG40'])['ok'] && Codes::redeem($who3, 'big40')['ok'], 'a newer code replaces the waiting one');
$o = Credits::offer(3, $pack);
ok($o['price'] === 600000.0 && $o['credits'] === 100 && $o['code_id'] > 0, '40% code beats the 25% rule');
ok(Db::table('mod_mcsec_redemptions')->where('client_id', 3)->where('status', 'pending')->count() === 1, 'one waiting code per account');

section('discount code on a pack: invoice at the lower price, code spent when paid');
$b = Credits::buy($who3, 'p100');
$inv = Db::table('tblinvoices')->where('id', $b['invoice_id'])->first();
ok($b['ok'] && (float) $inv->total === 600000.0, 'invoice total 600,000');
$paidBefore = Credits::balance(3)['paid'];
pay_invoice($b['invoice_id']);
ok(Credits::balance(3)['paid'] === $paidBefore + 100, '100 credits after payment');
ok(Codes::pending(3) === null && Credits::offer(3, $pack)['price'] === 750000.0, 'the code is spent; the rule discount remains');
ok(!Codes::redeem($who3, 'BIG40')['ok'], 'a spent code cannot be used again by the same account');
pay_invoice($b['invoice_id']);
ok(Credits::balance(3)['paid'] === $paidBefore + 100, 'InvoicePaid twice: once');

section('bonus code: same price, more credits');
$who1 = login(1, 1);
Accounts::ensure(1);
ok(Codes::create(['kind' => 'bonus', 'value' => 20, 'code' => 'YALDA', 'max_uses' => 1])['ok'], 'bonus code with one use');
ok(Codes::redeem($who1, ' yalda ')['ok'], 'client 1 takes it');
$o = Credits::offer(1, $pack);
ok($o['price'] === 1000000.0 && $o['credits'] === 120, '120 credits for the price of 100');
$who2 = login(2, 2);
Accounts::ensure(2);
$r = Codes::redeem($who2, 'YALDA');
ok(!$r['ok'] && str_contains($r['error'], 'ظرفیت'), 'use limit reached for the next account');
ok(Db::table('mod_mcsec_redemptions')->where('client_id', 2)->count() === 0, 'a refused code leaves no trace on the account');
$b = Credits::buy($who1, 'p100');
pay_invoice($b['invoice_id']);
ok(Credits::balance(1)['paid'] === 120, 'paid: 120 credits');

section('credit codes: once per account, limits, expiry, targeting');
ok(Codes::create(['kind' => 'credit', 'value' => 15, 'code' => 'FREE15', 'bucket' => 'monthly', 'max_uses' => 2, 'days' => 5])['ok'], 'credit code');
ok(!Codes::create(['kind' => 'credit', 'value' => 15, 'code' => 'FREE15'])['ok'], 'duplicate code refused');
ok(!Codes::create(['kind' => 'gift', 'value' => 15])['ok'] && !Codes::create(['kind' => 'discount', 'value' => 95])['ok'] && !Codes::create(['kind' => 'credit', 'value' => 0])['ok'], 'admin cannot make gift codes, 95% or 0 credits');
$before = Credits::balance(2);
$r = Codes::redeem($who2, 'free15');
ok($r['ok'] && Credits::balance(2)['monthly'] === $before['monthly'] + 15, '15 credits until the end of the month');
$r = Codes::redeem($who2, 'FREE15');
ok(!$r['ok'] && Credits::balance(2)['total'] === $before['total'] + 15, 'the same account cannot take it twice');
ok(Db::table('mod_mcsec_ledger')->where('ref', 'code:' . Db::table('mod_mcsec_codes')->where('code', 'FREE15')->value('id') . ':2')->count() === 1, 'one ledger row with its own ref');
ok((int) Db::table('mod_mcsec_codes')->where('code', 'FREE15')->value('used') === 1, 'a refused try does not count as a use');
Clock::$fixed += 6 * 86400;
ok(!Codes::redeem($who1, 'FREE15')['ok'], 'expired code refused');
Clock::$fixed -= 6 * 86400;
Codes::create(['kind' => 'credit', 'value' => 5, 'code' => 'ONLY3', 'client_id' => 3]);
Codes::create(['kind' => 'credit', 'value' => 5, 'code' => 'GROUP2', 'group_id' => 2]);
ok(!Codes::redeem($who1, 'ONLY3')['ok'] && !Codes::redeem($who1, 'GROUP2')['ok'], 'codes of another account or group refused');
ok(Codes::redeem($who3, 'ONLY3')['ok'] && Codes::redeem($who3, 'GROUP2')['ok'], 'the right account takes both');
ok(!Codes::redeem($who1, 'NOPE-NOPE')['ok'] && !Codes::redeem($who1, '')['ok'], 'unknown and empty codes refused');
$id = (int) Db::table('mod_mcsec_codes')->where('code', 'GROUP2')->value('id');
ok(Codes::disable($id) && !Codes::disable($id), 'code switched off once');

section('guessing codes is rate limited');
$who9 = login(9, 9);
Accounts::ensure(9);
$last = [];
for ($i = 0; $i < 14; $i++) {
    $last = Codes::redeem($who9, 'GUESS' . $i);
}
ok(!$last['ok'] && str_contains($last['error'], 'یک ساعت'), 'after 12 tries in an hour the box stops answering');
Codes::create(['kind' => 'credit', 'value' => 5, 'code' => 'REAL5']);
ok(!Codes::redeem($who9, 'REAL5')['ok'] && Credits::balance(9)['total'] === 0, 'even a real code is refused while limited');

section('gift: paid pack → code for the buyer → friend redeems once');
setting('gift_enabled', '0');
ok(!Credits::buy($who1, 'p100', ['gift' => true])['ok'], 'gifts off: refused');
setting('gift_enabled', '1');
$own = Credits::balance(1)['total'];
$g = Credits::buy($who1, 'p100', ['gift' => true]);
ok($g['ok'] && $g['invoice_id'] > 0, 'gift invoice in the buyer\'s name');
ok(Codes::gifts(1) === [], 'no code before payment');
pay_invoice($g['invoice_id']);
pay_invoice($g['invoice_id']);
Credits::reconcileTopups();
$gifts = Codes::gifts(1);
ok(count($gifts) === 1 && (int) $gifts[0]->value === 100 && str_starts_with($gifts[0]->code, 'G'), 'exactly one gift code of 100 credits');
ok(Credits::balance(1)['total'] === $own, 'the buyer\'s own credits did not change');
ok(Db::table('mod_mcsec_notices')->where('client_id', 1)->where('event', 'billing')->where('body', 'like', '%' . $gifts[0]->code . '%')->exists(), 'the buyer is told the code');
$who4 = login(4, 4);
Accounts::ensure(4);
ok(Codes::redeem($who4, strtolower($gifts[0]->code))['ok'] && Credits::balance(4)['paid'] === 100, 'the friend gets 100 credits that never expire');
$who5 = login(5, 5);
Accounts::ensure(5);
ok(!Codes::redeem($who5, $gifts[0]->code)['ok'] && Credits::balance(5)['total'] === 0, 'a gift code works for one account only');
ok(!Codes::redeem($who4, $gifts[0]->code)['ok'] && Credits::balance(4)['paid'] === 100, 'and only once');
ok(Db::table('mod_mcsec_notices')->where('client_id', 1)->where('title', 'هدیه‌ی شما استفاده شد')->exists(), 'the buyer hears that it was used');

section('gift nobody used for a year returns to the buyer, once');
$g2 = Credits::buy($who1, 'p500', ['gift' => true]);
pay_invoice($g2['invoice_id']);
$code2 = Codes::gifts(1)[0];
ok(Codes::returnGifts() === 0, 'not before a year');
Clock::$fixed += 366 * 86400;
$before = Credits::balance(1)['paid'];
ok(Codes::returnGifts() === 1 && Credits::balance(1)['paid'] === $before + 500, '500 credits back to the buyer');
ok(Codes::returnGifts() === 0 && Credits::balance(1)['paid'] === $before + 500, 'only once');
ok(!Codes::redeem($who5, $code2->code)['ok'] && Credits::balance(5)['total'] === 0, 'the returned code is dead');
Clock::$fixed -= 366 * 86400;

section('invite: newcomer bonus, inviter rewarded on first proof and first purchase');
setting('invite_enabled', '0');
ok(Codes::inviteCode(1) === '', 'invites off: no code');
setting('invite_enabled', '1');
setting('invite_new_credits', '10');
setting('invite_reward_verify', '5');
setting('invite_reward_buy', '30');
setting('invite_month_cap', '2');
$inv1 = Codes::inviteCode(1);
ok($inv1 !== '' && Codes::inviteCode(1) === $inv1 && str_starts_with($inv1, 'I'), 'one stable invite code per account');
ok(!Codes::redeem($who1, $inv1)['ok'], 'inviting yourself is refused');
$who6 = login(6, 6);
Accounts::ensure(6);
$r = Codes::redeem($who6, $inv1);
ok($r['ok'] && Credits::balance(6)['paid'] === 10 && (int) Accounts::get(6)->invited_by === 1, 'newcomer 6 gets 10 credits and is linked to 1');
$inv7 = Codes::inviteCode(7);
ok(!Codes::redeem($who6, $inv7)['ok'] && !Codes::redeem($who6, $inv1)['ok'] && Credits::balance(6)['paid'] === 10, 'one invite per newcomer, ever');
$b1 = Credits::balance(1)['paid'];
Codes::onVerified(6);
Codes::onVerified(6);
ok(Credits::balance(1)['paid'] === $b1 + 5, 'first proof: 5 credits to the inviter, once');
$b6 = Credits::buy($who6, 'p100');
pay_invoice($b6['invoice_id']);
pay_invoice($b6['invoice_id']);
ok(Credits::balance(1)['paid'] === $b1 + 35, 'first purchase: 30 more, once');
$b6b = Credits::buy($who6, 'p500');
pay_invoice($b6b['invoice_id']);
ok(Credits::balance(1)['paid'] === $b1 + 35, 'a second purchase pays nothing more');
ok(Codes::inviteStats(1) === ['invited' => 1, 'earned' => 35], 'stats for the inviter');
// newcomers only
ok(!Codes::redeem($who3, $inv1)['ok'], 'an account that already bought is not a newcomer');
Accounts::ensure(8);
Db::table('mod_mcsec_accounts')->where('client_id', 8)->update(['created_at' => Clock::now() - 40 * 86400]);
Accounts::forget();
ok(!Codes::redeem(login(8, 8), $inv1)['ok'], 'a workspace older than 30 days is not a newcomer');
// monthly cap of the inviter (2): 6 is one, 5 the second, 10 is refused
ok(Codes::redeem($who5, $inv1)['ok'], 'second newcomer accepted');
Accounts::ensure(10);
$r = Codes::redeem(login(10, 10), $inv1);
ok(!$r['ok'] && str_contains($r['error'], 'سقف') && Credits::balance(10)['total'] === 0, 'the inviter\'s cap stops the third');
// the real verification path rewards too
setting('ownership_autoverify', '1');
$who5 = login(5, 5);
$b1 = Credits::balance(1)['paid'];
$asset = (object) ['id' => 0];
$aid = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => 5, 'kind' => 'domain', 'value' => 'friend.example', 'status' => 'pending', 'created_at' => Clock::now()]);
\McSec\Verify::markVerified(Db::table('mod_mcsec_assets')->where('id', $aid)->first(), 'dns');
ok(Credits::balance(1)['paid'] === $b1 + 5, 'Verify::markVerified pays the inviter');

section('auto top-up: consent, threshold, one open invoice, cap');
setting('auto_topup_enabled', '0');
ok(!Credits::setAuto($who4, 'p100', 10)['ok'] && Credits::autoTopups() === 0, 'off: nothing');
setting('auto_topup_enabled', '1');
setting('auto_topup_month_cap', '2');
ok(!Credits::setAuto($who4, 'nope', 10)['ok'] && !Credits::setAuto($who4, 'p100', 0)['ok'], 'unknown pack or no threshold refused');
ok(Credits::setAuto($who4, 'p100', 200)['ok'], 'client 4: below 200 → pack p100');
$n = Db::table('mod_mcsec_topups')->where('client_id', 4)->count();
ok(Credits::autoTopups() === 1 && Db::table('mod_mcsec_topups')->where('client_id', 4)->where('auto', 1)->count() === 1, 'balance 100 < 200: one invoice');
ok(Credits::balance(4)['paid'] === 100, 'nothing is charged or credited by itself');
ok(Db::table('mod_mcsec_notices')->where('client_id', 4)->where('event', 'billing')->where('link', 'like', 'viewinvoice.php?id=%')->exists(), 'the customer is told, with the invoice link');
ok(Credits::autoTopups() === 0, 'no second invoice while the first is open');
$t = Db::table('mod_mcsec_topups')->where('client_id', 4)->where('auto', 1)->first();
pay_invoice((int) $t->invoice_id);
ok(Credits::balance(4)['paid'] === 200 && Credits::autoTopups() === 0, 'paid: 200, not below the threshold any more');
Credits::spend(4, 150, 'scan:777001', 'test');
ok(Credits::autoTopups() === 1, 'below again: second invoice');
pay_invoice((int) Db::table('mod_mcsec_topups')->where('client_id', 4)->where('auto', 1)->orderByDesc('id')->value('invoice_id'));
Credits::spend(4, 140, 'scan:777002', 'test');
ok(Credits::balance(4)['paid'] < 200 && Credits::autoTopups() === 0, 'the cap of 2 in 30 days stops a third');
ok(Credits::setAuto($who4, '', 0)['ok'] && (string) Accounts::get(4)->auto_pack === '', 'switched off');

section('ledger adds up and nothing went negative');
foreach ([1, 2, 3, 4, 5, 6] as $c) {
    $w = Db::table('mod_mcsec_wallets')->where('client_id', $c)->first();
    ok((int) $w->monthly >= 0 && (int) $w->paid >= 0 && (int) $w->monthly + (int) $w->paid === $sum($c), "client {$c}: wallet = sum of the ledger, not negative");
}
ok(Db::table('mod_mcsec_ledger')->selectRaw('ref, COUNT(*) AS n')->groupBy('ref')->havingRaw('COUNT(*) > 1')->count() === 0, 'every ref is unique');

section('client area: the code box, CSRF, nonce, permissions, XSS');
setting('enabled', '1');
$who2 = login(2, 2);
$page = html(client_get(['p' => 'credits', 'code' => '"><script>alert(9)</script>abc-12']));
ok(str_contains($page, 'کد دارید؟') && str_contains($page, 'name="code"'), 'the credits page has the code box');
ok(!str_contains($page, '<script>alert(9)') && str_contains($page, 'value="SCRIPTALERT9SCRIPTABC-12"'), 'a code in the link is prefilled, cleaned to capitals and digits');
ok(str_contains($page, 'هدیه به دوست') && str_contains($page, 'دعوت از دوستان') && str_contains($page, 'شارژ خودکار'), 'gift, invite and auto top-up are shown when on');
ok(substr_count($page, 'class="mcs-kpi-value"') === 1, 'one number: «اعتبار شما»');
Codes::create(['kind' => 'credit', 'value' => 9, 'code' => 'PAGE9']);
$t2 = Credits::balance(2)['total'];
$_SERVER['REQUEST_METHOD'] = 'POST';
$_GET = ['m' => 'mcsec'];
$_POST = ['a' => 'code_redeem', 'p' => 'credits', 'code' => 'PAGE9', 'token' => 'whmcs-token', 'mcs_csrf' => 'wrong', 'mcs_nonce' => \McSec\Nonce::issue(2, 2, 'form')];
\McSec\Client\Controller::handle();
ok(Credits::balance(2)['total'] === $t2, 'wrong CSRF token: nothing');
$r = client_post('code_redeem', ['p' => 'credits', 'code' => 'PAGE9'], [], false);
ok(Credits::balance(2)['total'] === $t2, 'no nonce: nothing');
$nonce = \McSec\Nonce::issue(2, 2, 'form');
$r = client_post('code_redeem', ['p' => 'credits', 'code' => 'PAGE9', 'mcs_nonce' => $nonce]);
ok(Credits::balance(2)['total'] === $t2 + 9 && str_contains(flash_of($r), 'افزوده شد'), 'with everything: 9 credits');
$r = client_post('code_redeem', ['p' => 'credits', 'code' => 'PAGE9', 'mcs_nonce' => $nonce]);
ok(Credits::balance(2)['total'] === $t2 + 9, 'the same form sent twice: once');
$r = client_post('code_redeem', ['p' => 'credits', 'code' => '<script>alert(9)</script>']);
ok(!str_contains(html($r), '<script>alert(9)'), 'a hostile code is never echoed as HTML');
// a viewer (products only) of client 1 cannot redeem, buy a gift or set auto top-up
login(11, 1);
Codes::create(['kind' => 'credit', 'value' => 9, 'code' => 'VIEW9']);
$t1 = Credits::balance(1)['total'];
$r = client_post('code_redeem', ['p' => 'credits', 'code' => 'VIEW9']);
ok(Credits::balance(1)['total'] === $t1 && str_contains(flash_of($r), 'مالک'), 'a viewer cannot redeem a code');
$r = client_post('auto_save', ['p' => 'credits', 'pack' => 'p100', 'below' => '10', 'agree' => '1']);
ok((string) Accounts::get(1)->auto_pack === '', 'a viewer cannot turn auto top-up on');
ok(!str_contains(html(client_get(['p' => 'credits'])), 'name="code"'), 'and does not see the box');
// the owner needs the consent tick
login(1, 1);
$r = client_post('auto_save', ['p' => 'credits', 'pack' => 'p100', 'below' => '۱۰']);
ok((string) Accounts::get(1)->auto_pack === '' && str_contains(flash_of($r), 'موافقت'), 'auto top-up needs the consent tick');
$r = client_post('auto_save', ['p' => 'credits', 'pack' => 'p100', 'below' => '۱۰', 'agree' => '1']);
ok((string) Accounts::get(1)->auto_pack === 'p100' && (int) Accounts::get(1)->auto_below === 10, 'with consent: on (Persian digits accepted)');
// masquerading admin: look only
login(1, 1, true);
$t1 = Credits::balance(1)['total'];
client_post('code_redeem', ['p' => 'credits', 'code' => 'VIEW9']);
ok(Credits::balance(1)['total'] === $t1, '«ورود به‌جای مشتری» cannot redeem');
// gift purchase through the controller
login(2, 2);
$r = client_post('buy_pack', ['p' => 'credits', 'pack' => 'p100', 'gift' => '1']);
ok(str_starts_with((string) ($r['redirect'] ?? ''), 'viewinvoice.php?id=') && Db::table('mod_mcsec_topups')->where('client_id', 2)->where('gift', 1)->count() === 1, 'gift button → invoice');
// GET never changes anything
$u = (int) Db::table('mod_mcsec_codes')->where('code', 'VIEW9')->value('used');
client_get(['p' => 'credits', 'a' => 'code_redeem', 'code' => 'VIEW9']);
ok((int) Db::table('mod_mcsec_codes')->where('code', 'VIEW9')->value('used') === $u, 'a GET with a code only prefills the box');

section('admin: rules and codes pages, tiers, CSRF, XSS');
$adminPost = function (string $act, array $post, string $page = 'credits', bool $csrf = true): string {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = ['module' => 'mcsec', 'mcsa' => $page];
    $_POST = $post + ['mcsa_act' => $act, 'mcsa_csrf' => $csrf ? \McSec\Auth::csrf() : 'wrong'];
    return \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
};
admin('ops');
$h = $adminPost('save_rule', ['rl_scope' => 'client', 'rl_client' => '7', 'rl_monthly' => '50']);
ok(Rules::of(7) === Rules::NONE && str_contains($h, 'اجازه'), 'an ops admin cannot change prices');
admin('settings');
$h = $adminPost('save_rule', ['rl_scope' => 'client', 'rl_client' => '7', 'rl_monthly' => '50'], 'credits', false);
Rules::forget();
ok(Rules::of(7) === Rules::NONE, 'wrong admin CSRF: nothing');
$h = $adminPost('save_rule', ['rl_scope' => 'client', 'rl_client' => '۷', 'rl_monthly' => '۵۰', 'rl_discount' => '15', 'rl_spend' => '', 'rl_note' => '<script>alert(9)</script>']);
Rules::forget();
ok(Rules::of(7)['monthly'] === 50 && Rules::of(7)['spend_pct'] === 100 && Rules::of(7)['discount'] === 15, 'rule saved from the form (empty cost = normal price)');
ok(!str_contains($h, '<script>alert(9)') && str_contains($h, 'حساب #7'), 'the note is escaped in the list');
$h = $adminPost('save_code', ['cd_kind' => 'bonus', 'cd_value' => '25', 'cd_code' => 'adm<b>25', 'cd_note' => '<script>alert(9)</script>'], 'codes');
ok(Db::table('mod_mcsec_codes')->where('code', 'ADMB25')->where('kind', 'bonus')->exists() && !str_contains($h, '<script>alert(9)'), 'code made from the form, cleaned and escaped');
$cid = (int) Db::table('mod_mcsec_codes')->where('code', 'ADMB25')->value('id');
$h = $adminPost('disable_code', ['code_id' => (string) $cid], 'codes');
ok((int) Db::table('mod_mcsec_codes')->where('id', $cid)->value('enabled') === 0, 'code switched off from the page');
$giftId = (int) Db::table('mod_mcsec_codes')->where('kind', 'gift')->where('used', 0)->where('enabled', 1)->value('id');
if ($giftId > 0) {
    $adminPost('disable_code', ['code_id' => (string) $giftId], 'codes');
    ok((int) Db::table('mod_mcsec_codes')->where('id', $giftId)->value('enabled') === 1, 'a customer\'s paid gift code cannot be switched off from the page');
}
$_SERVER['REQUEST_METHOD'] = 'GET';
$_POST = [];
$_GET = ['module' => 'mcsec', 'mcsa' => 'codes'];
admin('view');
$h = \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
ok(str_contains($h, 'راهنمای این صفحه') && str_contains($h, 'کدهای کمپین') && !str_contains($h, 'disable_code'), 'a view-only admin reads the codes page without action buttons');
done();
