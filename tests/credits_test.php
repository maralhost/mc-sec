<?php
// Credits: welcome once, group monthly refill once per Jalali month, expiry, spend order, all-or-nothing, refunds,
// idempotent refs, credit packs through a WHMCS invoice and InvoicePaid, plans on the provisioning module.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Credits;
use McSec\Db;
use McSec\Plans;

$tz = new DateTimeZone('Asia/Tehran');
Clock::$fixed = (new DateTimeImmutable('2026-11-11 10:00', $tz))->getTimestamp(); // 20 Aban 1405
setting('welcome_credits', '10');
setting('group_rules', json_encode([['group' => 2, 'monthly' => 30, 'max_assets' => 8]]));

section('welcome credits exactly once');
Accounts::ensure(1);
Accounts::forget();
Accounts::ensure(1);
ok(Credits::balance(1)['paid'] === 10 && Credits::balance(1)['monthly'] === 0, 'client 1: 10 paid, 0 monthly');
ok(Db::table('mod_mcsec_ledger')->where('client_id', 1)->where('kind', 'welcome')->count() === 1, 'one welcome row');

section('group monthly credits (client 3 is in group 2)');
Accounts::ensure(3);
$b = Credits::balance(3);
ok($b['monthly'] === 30 && $b['paid'] === 10 && $b['total'] === 40, 'group 30 monthly + 10 welcome');
Credits::balance(3);
Credits::refresh(3);
ok(Credits::balance(3)['monthly'] === 30, 'refill is once per month');

section('spend: monthly first, then paid, all or nothing');
$r = Credits::spend(3, 35, 'scan:9001', 'test');
ok($r['ok'] && $r['monthly'] === 30 && $r['paid'] === 5, 'took 30 monthly + 5 paid');
ok(Credits::balance(3)['total'] === 5, 'total 5 left');
$again = Credits::spend(3, 35, 'scan:9001', 'test');
ok($again['ok'] && !empty($again['again']) && Credits::balance(3)['total'] === 5, 'same ref never charges twice');
$no = Credits::spend(3, 6, 'scan:9002', 'test');
ok(!$no['ok'] && Credits::balance(3)['total'] === 5 && !Db::table('mod_mcsec_ledger')->where('ref', 'like', 'scan:9002%')->exists(), 'insufficient: nothing taken');

section('refund: same bucket this month, once');
ok(Credits::refund(3, 'scan:9001', 'test refund') === 35, 'refund 35');
ok(Credits::balance(3)['monthly'] === 30 && Credits::balance(3)['paid'] === 10, 'buckets restored');
ok(Credits::refund(3, 'scan:9001', 'again') === 0, 'refund only once');

section('month change: leftover monthly expires, new month refills once');
Credits::spend(3, 12, 'scan:9003', 'test'); // 18 monthly left
Clock::$fixed = (new DateTimeImmutable('2026-11-23 09:00', $tz))->getTimestamp(); // 2 Azar 1405
$b = Credits::balance(3);
ok($b['period'] === '1405-09', 'new period');
ok($b['monthly'] === 30 && $b['paid'] === 10, 'leftover 18 expired, refilled 30 (got ' . json_encode($b) . ')');
ok(Db::table('mod_mcsec_ledger')->where('ref', 'expire:3:1405-08')->value('delta') == -18, 'expiry booked');
ok(Credits::refund(3, 'scan:9003', 'late') === 12 && Credits::balance(3)['paid'] === 22, 'a refund from last month goes to paid credits');

section('credit packs: invoice → paid → credits once');
setting('credit_packs', json_encode([['key' => 'p50', 'credits' => 50, 'price' => 5000000, 'label' => 'بسته‌ی ۵۰']]));
$who = login(1, 1);
$r = Credits::buy($who, 'p50');
ok($r['ok'] && $r['invoice_id'] > 0, 'invoice created via localAPI CreateInvoice');
$r2 = Credits::buy($who, 'p50');
ok($r2['ok'] && $r2['invoice_id'] === $r['invoice_id'] && !empty($r2['again']), 'open invoice reused');
ok(Credits::balance(1)['paid'] === 10, 'nothing before payment');
pay_invoice($r['invoice_id']);
ok(Credits::balance(1)['paid'] === 60, '50 credits after InvoicePaid');
run_hook('InvoicePaid', ['invoiceid' => $r['invoice_id']]);
Credits::reconcileTopups();
ok(Credits::balance(1)['paid'] === 60, 'hook again and the worker net: still once');
ok(Db::table('mod_mcsec_notices')->where('client_id', 1)->where('event', 'credits_added')->exists(), 'customer told');
ok(!Credits::buy($who, 'nope')['ok'], 'unknown pack refused');

section('plans: provisioning module');
$params = ['serviceid' => 501, 'userid' => 2, 'pid' => 1, 'configoption1' => '150', 'configoption2' => '10', 'configoption3' => 'hygiene,surface,vuln,deep', 'configoption4' => '24', 'configoption5' => 'on'];
ok(mcsecplan_CreateAccount($params) === 'success', 'CreateAccount');
$lim = Plans::limits(2);
ok($lim['max_assets'] === 10 && $lim['min_interval_h'] === 24 && in_array('deep', $lim['profiles'], true), 'limits from the plan');
ok(Credits::balance(2)['monthly'] === 150, 'this month 150 plan credits');
ok(mcsecplan_Renew($params) === 'success' && Credits::balance(2)['monthly'] === 150, 'renewal in the same month: not doubled');
ok(mcsecplan_SuspendAccount($params) === 'success' && Plans::limits(2)['profiles'] === null, 'suspended plan gives nothing');
ok(mcsecplan_UnsuspendAccount($params) === 'success' && Plans::limits(2)['max_assets'] === 10, 'unsuspended');
Clock::$fixed = (new DateTimeImmutable('2026-12-23 09:00', $tz))->getTimestamp(); // 2 Dey
ok(Credits::balance(2)['monthly'] === 150, 'next month refilled by the plan (not carried over)');
ok(Db::table('mod_mcsec_ledger')->where('client_id', 2)->where('kind', 'plan')->count() === 2, 'two plan grants in two months');
ok(mcsecplan_TerminateAccount($params) === 'success' && Plans::active(2) === [], 'terminated');

section('balance never negative under a race');
$w = Db::table('mod_mcsec_wallets')->where('client_id', 1)->first();
Db::table('mod_mcsec_wallets')->where('client_id', 1)->update(['paid' => 3]); // someone else spent meanwhile
$r = Credits::spend(1, 5, 'scan:9100', 'race');
ok(!$r['ok'] && (int) Db::table('mod_mcsec_wallets')->where('client_id', 1)->value('paid') === 3, 'spend refused, no negative balance');
done();
