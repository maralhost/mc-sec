<?php
// 0.13.0 «درخواست بررسی کارشناس»: one form inside the security section; WHMCS opens the ticket (localAPI OpenTicket)
// and code writes the context. IDOR (another account's finding, scan, asset), CSRF/nonce, viewer, XSS, daily cap,
// the switch, the department fallback, and tbl* untouched outside localAPI.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\Support;
use WHMCS\Database\Capsule;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'welcome_credits' => '0'] as $k => $v) {
    setting($k, $v);
}
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
$asset = fn (int $client, string $value) => Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $client, 'kind' => 'domain', 'value' => $value, 'status' => 'verified', 'method' => 'admin', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
$a1 = $asset(1, 'shop.example');
$a2 = $asset(2, 'secret-other.example');
$scan = fn (int $client, int $aid, string $status, string $err = '') => Db::table('mod_mcsec_scans')->insertGetId(['client_id' => $client, 'asset_id' => $aid, 'profile' => 'hygiene', 'engine' => 'builtin', 'status' => $status,
    'error' => $err, 'error_ref' => $err !== '' ? 'MS-ABC123' : '', 'queued_at' => Clock::now(), 'finished_at' => Clock::now(), 'summary' => '{}']);
$s1 = $scan(1, $a1, 'failed', 'موتور جواب نداد');
$s2 = $scan(2, $a2, 'completed');
$finding = fn (int $client, int $aid, string $title) => Db::table('mod_mcsec_findings')->insertGetId(['client_id' => $client, 'asset_id' => $aid, 'fp' => md5($title), 'engine' => 'builtin', 'source_key' => 'k' . md5($title),
    'title' => $title, 'severity' => 'high', 'status' => 'open', 'location' => 'https://x/', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()]);
$f1 = $finding(1, $a1, 'سرآیند امنیتی <script>alert(9)</script> نیست');
$f2 = $finding(2, $a2, 'راز حساب دیگر');
$tickets = fn () => as_whmcs(fn () => Capsule::table('tbltickets')->orderBy('id')->get()->all());

section('page and entry points');
$h = html(client_get(['p' => 'support']));
ok(str_contains($h, 'درخواست بررسی کارشناس') && str_contains($h, 'name="a" value="support_send"'), 'support page has the form');
ok(str_contains($h, 'p=support') && str_contains($h, 'کمک کارشناس'), 'side menu has «کمک کارشناس»');
ok(str_contains($h, 'این بخش چه کار می‌کند؟'), 'page has the guide box');
$h = html(client_get(['p' => 'finding', 'id' => $f1]));
ok(str_contains($h, 'p=support&amp;topic=finding&amp;finding=' . $f1), 'finding page links to the request with the finding chosen');
ok(!str_contains($h, '<script>alert(9)</script>'), 'finding title is escaped on its page');
$h = html(client_get(['p' => 'scan', 'id' => $s1]));
ok(str_contains($h, 'p=support&amp;topic=scan&amp;scan=' . $s1), 'failed scan links to the request');
$h = html(client_get(['p' => 'support', 'topic' => 'finding', 'finding' => $f1]));
ok(str_contains($h, 'این درخواست درباره‌ی') && !str_contains($h, '<script>alert(9)</script>') && str_contains($h, '&lt;script&gt;'), 'the chosen finding is shown, escaped');
ok(str_contains($h, 'name="finding" value="' . $f1 . '"'), 'the finding rides in the form');
$h = html(client_get(['p' => 'support', 'finding' => $f2, 'scan' => $s2, 'asset' => $a2]));
ok(!str_contains($h, 'راز حساب دیگر') && !str_contains($h, 'secret-other.example') && str_contains($h, 'name="finding" value="0"'), 'IDOR: another account\'s finding, scan and asset are not shown');

section('sending');
$n0 = count($GLOBALS['__localapi']);
$r = client_post('support_send', ['topic' => 'finding', 'finding' => $f1, 'text' => 'این مورد را رفع کردم ولی هنوز دیده می‌شود <b>x</b>.'], ['p' => 'support']);
ok(str_contains((string) ($r['redirect'] ?? ''), 'p=support&sent=100000'), 'redirects to the confirmation with the ticket number');
$t = $tickets();
ok(count($t) === 1 && (int) $t[0]->userid === 1, 'one ticket, in the customer\'s name');
ok((int) $t[0]->did === 2, 'no department chosen: the first one customers can see (hidden one skipped)');
ok(str_starts_with($t[0]->title, '[امنیت سایبری] کمک برای رفع یک یافته: '), 'subject says the section and the topic');
ok(str_contains($t[0]->message, 'این مورد را رفع کردم') && str_contains($t[0]->message, 'یافته شماره‌ی ' . $f1) && str_contains($t[0]->message, 'shop.example') && str_contains($t[0]->message, 'شدت بالا'), 'message: the customer\'s words and the context written by code');
$call = $GLOBALS['__localapi'][count($GLOBALS['__localapi']) - 1];
ok($call[0] === 'OpenTicket' && $call[1]['markdown'] === false && !isset($call[1]['noemail']) && !isset($call[1]['admin']), 'OpenTicket: plain text, no noemail, not as an admin');
ok((int) ($call[1]['serviceid'] ?? 0) > 0 && (int) $t[0]->service > 0, 'the plan service is attached, so the ticket is filed under the security product');
ok(Db::table('mod_mcsec_audit')->where('client_id', 1)->where('action', 'support')->where('target', '#100000')->exists(), 'request is in the activity log');
$h = html(client_get(['p' => 'support', 'sent' => '100000']));
ok(str_contains($h, 'درخواست شما ثبت شد') && str_contains($h, 'viewticket.php?tid=100000&amp;c=Ab12Cd34') && str_contains($h, 'درخواست‌های اخیر شما'), 'confirmation links to the ticket; recent requests listed');
$h = html(client_get(['p' => 'support', 'sent' => '"><script>alert(9)</script>']));
ok(!str_contains($h, '<script>alert(9)</script>') && !str_contains($h, 'درخواست شما ثبت شد'), 'a forged sent= shows nothing');

setting('support_dept', '3');
$r = client_post('support_send', ['topic' => 'scan', 'scan' => $s1, 'text' => 'چرا این اسکن ناموفق شد؟ لطفاً بررسی کنید.'], ['p' => 'support']);
$t = $tickets();
ok(count($t) === 2 && (int) $t[1]->did === 3, 'the admin\'s department is used');
ok(str_contains($t[1]->message, 'اسکن شماره‌ی ' . $s1) && str_contains($t[1]->message, 'MS-ABC123') && str_contains($t[1]->message, 'موتور جواب نداد'), 'scan context: number, error and tracking code');
setting('support_dept', '99');
$r = client_post('support_send', ['topic' => 'other', 'text' => 'یک پرسش کلی درباره‌ی امنیت سایت دارم.'], ['p' => 'support']);
ok((int) $tickets()[2]->did === 2, 'a department that no longer exists falls back to a visible one');

login(2, 2);
client_post('support_send', ['topic' => 'review', 'text' => 'لطفاً وضعیت امنیت حساب من را بررسی کنید.'], ['p' => 'support']);
$t = $tickets();
ok((int) $t[3]->userid === 2 && (int) $t[3]->service === 0 && str_contains($t[3]->message, 'حساب #2'), 'an account without a plan: no service attached, account named');
login(1, 1);

section('guards');
$n = count($tickets());
$r = client_post('support_send', ['topic' => 'finding', 'finding' => $f2, 'scan' => $s2, 'asset' => $a2, 'text' => 'تلاش برای دیدن حساب دیگر، متن کافی.'], ['p' => 'support']);
$t = $tickets();
ok(count($t) === $n + 1 && !str_contains($t[$n]->message, 'راز حساب دیگر') && !str_contains($t[$n]->message, 'secret-other') && !str_contains($t[$n]->title, 'راز'), 'IDOR: another account\'s ids add nothing to the ticket');
$n = count($tickets());
$r = client_post('support_send', ['topic' => 'other', 'text' => 'کوتاه'], ['p' => 'support']);
ok(str_contains(flash_of($r), 'دست‌کم') && count($tickets()) === $n, 'too short: refused');
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.', 'mcs_csrf' => 'bad'], ['p' => 'support']);
ok(str_contains(flash_of($r), 'منقضی') && count($tickets()) === $n, 'CSRF: refused');
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.'], ['p' => 'support'], false);
ok(str_contains(flash_of($r), 'یک بار') && count($tickets()) === $n, 'no nonce: refused');
$nonce = \McSec\Nonce::issue(1, 1, 'form');
client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.', 'mcs_nonce' => $nonce], ['p' => 'support']);
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.', 'mcs_nonce' => $nonce], ['p' => 'support']);
ok(count($tickets()) === $n + 1, 'the same nonce twice: one ticket');
login(11, 1);
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.'], ['p' => 'support']);
ok(str_contains(flash_of($r), 'فقط اجازه‌ی دیدن') && count($tickets()) === $n + 1, 'a viewer cannot send');
ok(!str_contains(html(client_get(['p' => 'support'])), 'value="support_send"'), 'a viewer sees no form');
login(1, 1, true);
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.'], ['p' => 'support']);
ok(count($tickets()) === $n + 1, 'an admin logged in as the client cannot send');
login(1, 1);
$n = count($tickets());
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.'], ['p' => 'support']);
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.'], ['p' => 'support']);
ok(Db::table('mod_mcsec_audit')->where('client_id', 1)->where('action', 'support')->count() === 6 && str_contains(flash_of($r), 'امروز چند درخواست'), 'daily cap of ' . Support::DAILY . ' per account');
Db::table('mod_mcsec_hits')->where('k', 'support:1')->delete();
$GLOBALS['__fail_api']['OpenTicket'] = 'Department ID Not Found';
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.'], ['p' => 'support']);
ok(str_contains(flash_of($r), 'تیکت ساخته نشد') && preg_match('~MS-[A-Z0-9]{6}~', flash_of($r)) === 1, 'WHMCS refuses: a clear message with a tracking code');
unset($GLOBALS['__fail_api']['OpenTicket']);

section('the switch');
setting('support_requests', '0');
$h = html(client_get(['p' => 'finding', 'id' => $f1]));
ok(!str_contains($h, 'p=support'), 'off: no link on the finding page or in the menu');
$n = count($tickets());
$r = client_post('support_send', ['topic' => 'other', 'text' => 'متن کافی برای یک درخواست درست.'], ['p' => 'support']);
ok(count($tickets()) === $n && str_contains(flash_of($r), 'در دسترس نیست'), 'off: nothing is sent');
ok(str_contains(html(client_get(['p' => 'support'])), 'submitticket.php'), 'off: the page points to the ticket form');

done();
