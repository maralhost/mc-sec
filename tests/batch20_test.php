<?php
// 0.20.0: findings grouped by their fix, fix deadlines per severity, handing a finding to a user of the account,
// and a product of this WHMCS next to a fix.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\Findings;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'welcome_credits' => '0'] as $k => $v) {
    setting($k, $v);
}
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
Accounts::update(1, ['terms_at' => Clock::now()]);
$asset = fn (int $cid, string $v) => Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $cid, 'kind' => 'domain', 'value' => $v, 'status' => 'verified', 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
$n = 0;
$find = function (int $cid, int $aid, string $kb, string $sev, int $daysAgo, array $x = []) use (&$n) {
    $n++;
    return Db::table('mod_mcsec_findings')->insertGetId($x + ['client_id' => $cid, 'asset_id' => $aid, 'fp' => 'fp' . $n, 'engine' => 'builtin', 'profile' => 'hygiene', 'source_key' => 'k' . $n, 'kb' => $kb,
        'title' => 'Finding ' . $n, 'severity' => $sev, 'location' => 'https://x.example/' . $n, 'status' => 'open', 'first_seen_at' => Clock::now() - $daysAgo * 86400, 'last_seen_at' => Clock::now()]);
};
$a1 = $asset(1, 'one.example');
$a2 = $asset(1, 'two.example');
$b1 = $asset(2, 'other.example');
$f1 = $find(1, $a1, 'hdr-hsts', 'medium', 3);
$f2 = $find(1, $a2, 'hdr-hsts', 'high', 40);
$f3 = $find(1, $a1, 'tls-expiring', 'critical', 10);
$f4 = $find(1, $a1, 'no-such-key', 'low', 400);
$f5 = $find(1, $a1, '', 'info', 5);
$fixed = $find(1, $a1, 'hdr-hsts', 'critical', 100, ['status' => 'fixed', 'fixed_at' => Clock::now() - 86400]);
$other = $find(2, $b1, 'hdr-hsts', 'critical', 100);

section('findings grouped by their fix');
$g = Findings::groups(1);
ok(count($g) === 3 && $g[0]['kb'] === 'tls-expiring' && $g[0]['severity'] === 'critical' && $g[1]['kb'] === 'hdr-hsts' && $g[1]['n'] === 2 && $g[1]['assets'] === 2 && $g[1]['severity'] === 'high', 'one row per fix, most severe first, open findings of this account only');
ok($g[2]['kb'] === 'generic' && $g[2]['n'] === 2, 'findings without a known fix share the general guidance');
$h = html(client_get(['p' => 'findings', 'group' => '1']));
ok(str_contains($h, 'kb=hdr-hsts') && str_contains($h, 'بر اساس راه رفع') && !str_contains($h, 'Finding 1<'), 'the page lists the fixes, not the findings');
$h = html(client_get(['p' => 'findings', 'kb' => 'hdr-hsts']));
ok(str_contains($h, 'Finding 1') && str_contains($h, 'Finding 2') && !str_contains($h, 'Finding 3') && !str_contains($h, 'Finding 7'), 'a fix opens its own findings, never another account\'s');
ok(!str_contains(html(client_get(['p' => 'findings', 'kb' => '<script>alert(9)</script>'])), '<script>alert(9)'), 'a made-up key is ignored');
ok(count(Findings::search(1, ['kb' => 'generic'])['rows']) === 2, 'the general row opens both of its findings');

section('fix deadlines');
ok(Findings::due(Findings::get(1, $f3)) === 0 && Findings::overdueCount(1) === 0 && !str_contains(html(client_get(['p' => 'findings'])), 'مهلت گذشته'), 'off by default: no deadline anywhere');
setting('fix_deadlines', '1');
ok(Findings::due(Findings::get(1, $f3)) === Clock::now() - 3 * 86400 && Findings::due(Findings::get(1, $f1)) === Clock::now() + 87 * 86400, 'the deadline counts from the day it was first seen');
ok(Findings::due(Findings::get(1, $f4)) === 0 && Findings::due(Findings::get(1, $fixed)) === 0, 'none for a severity set to zero, none for a fixed finding');
ok(Findings::overdueCount(1) === 2, 'critical after 7 days and high after 30 are overdue');
$h = html(client_get(['p' => 'findings', 'overdue' => '1']));
ok(str_contains($h, 'Finding 2') && str_contains($h, 'Finding 3') && !str_contains($h, 'Finding 1<') && str_contains($h, 'مهلت گذشته (۲)'), 'the overdue view shows exactly those');
ok(str_contains(html(client_get(['p' => 'finding', 'id' => $f3])), 'مهلت گذشته') && str_contains(html(client_get(['p' => 'finding', 'id' => $f1])), '۸۷ روز مهلت'), 'the finding page shows the deadline');
Db::table('mod_mcsec_findings')->where('id', $f3)->update(['fixed_at' => Clock::now() - 86400, 'reopened' => 1]);
ok(Findings::due(Findings::get(1, $f3)) === Clock::now() + 6 * 86400 && Findings::overdueCount(1) === 1, 'a finding that came back after a fix gets a fresh deadline');
setting('sla_high', '0');
ok(Findings::overdueCount(1) === 0, 'the admin\'s days decide');
setting('sla_high', '30');

section('handing a finding to a user of the account');
ok(!Findings::assign($who, $f1, 12)['ok'] && !str_contains(html(client_get(['p' => 'finding', 'id' => $f1])), 'finding_assign'), 'off by default');
setting('finding_assign', '1');
ok(str_contains(html(client_get(['p' => 'finding', 'id' => $f1])), 'value="finding_assign"'), 'the form appears when the account has more than one user');
$r = client_post('finding_assign', ['finding' => $f1, 'user' => 12], ['p' => 'finding', 'id' => $f1], false);
ok(str_contains(flash_of($r), 'واگذار شد') && (int) Findings::get(1, $f1)->assignee === 12, 'a user of the account can be chosen');
ok(!Findings::assign($who, $f1, 2)['ok'] && (int) Findings::get(1, $f1)->assignee === 12, 'a user of another account cannot');
ok(!Findings::assign($who, $other, 12)['ok'] && (int) Db::table('mod_mcsec_findings')->where('id', $other)->value('assignee') === 0, 'another account\'s finding cannot be assigned');
ok(str_contains(html(client_get(['p' => 'finding', 'id' => $f1])), 'Tech One') && str_contains(html(client_get(['p' => 'findings'])), 'Tech One'), 'the name is shown on the finding and in the list');
login(12, 1);
$h = html(client_get(['p' => 'findings', 'mine' => '1']));
ok(str_contains($h, 'Finding 1') && !str_contains($h, 'Finding 2'), '«کارهای من» shows only what was handed to this user');
login(11, 1);
$r = client_post('finding_assign', ['finding' => $f2, 'user' => 11], ['p' => 'finding', 'id' => $f2], false);
ok(str_contains(flash_of($r), 'فقط اجازه‌ی دیدن') && (int) Findings::get(1, $f2)->assignee === 0, 'a view-only user cannot assign');
$who = login(1, 1);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['m' => 'mcsec', 'p' => 'finding', 'id' => $f2, 'mcs_action' => 'finding_assign', 'finding' => $f2, 'user' => 12];
client_get($_GET);
ok((int) Findings::get(1, $f2)->assignee === 0, 'a GET changes nothing');
ok(Findings::assign($who, $f1, 0)['ok'] && (int) Findings::get(1, $f1)->assignee === 0, 'the assignment can be removed');
Db::table('tblusers')->where('id', 12)->update(['first_name' => '<script>alert(9)</script>']);
Findings::assign($who, $f1, 12);
ok(!str_contains(html(client_get(['p' => 'finding', 'id' => $f1])) . html(client_get(['p' => 'findings'])), '<script>alert(9)'), 'a user name is escaped');

section('a product next to the fix');
setting('offers', "hdr-hsts | گواهی با تمدید خودکار | pid:12\ntls-expiring | <script>alert(9)</script> | https://maral.example/ssl\ngeneric | bad | javascript:alert(9)\nhsts | x | pid:12&evil=1");
$h = html(client_get(['p' => 'finding', 'id' => $f1]));
ok(str_contains($h, 'href="cart.php?a=add&amp;pid=12"') && str_contains($h, 'افزودن به سبد خرید'), 'pid:12 becomes a link to the cart of this WHMCS');
$h = html(client_get(['p' => 'finding', 'id' => $f3]));
ok(str_contains($h, 'href="https://maral.example/ssl"') && !str_contains($h, '<script>alert(9)'), 'a full link still works and its text is escaped');
ok(!str_contains(html(client_get(['p' => 'finding', 'id' => $f5])), 'javascript:'), 'anything else is not a link');
ok(str_contains(html(client_get(['p' => 'findings', 'group' => '1'])), 'cart.php?a=add&amp;pid=12'), 'the list of fixes carries the same offer');

section('WHMCS tables');
ok(Db::table('tblusers_clients')->count() === 12, 'the user links of WHMCS are untouched');
done();
