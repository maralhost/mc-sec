<?php
// 0.22.0: a new expert request reaches the admin's chat, the admin's «درآمد و مصرف» page, and the public DNS check.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\PublicCheck;
use McSec\Requests;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'welcome_credits' => '0'] as $k => $v) {
    setting($k, $v);
}
Accounts::ensure(1);

section('a new request reaches the admin\'s chat');
$sent = [];
http_mock(function ($method, $url, $headers = [], $body = null) use (&$sent) {
    $sent[] = [$url, is_string($body) ? $body : json_encode($body, JSON_UNESCAPED_UNICODE)];
    return ['status' => 200, 'body' => '{"ok":true,"result":{}}'];
});
$req = fn (int $cid, string $kind, int $age = 60, array $x = []) => Db::table('mod_mcsec_requests')->insertGetId($x + ['client_id' => $cid, 'user_id' => $cid, 'kind' => $kind, 'topic' => 'general', 'status' => 'new',
    'text' => 'SECRET words of the customer', 'created_at' => Clock::now() - $age, 'updated_at' => Clock::now() - $age]);
$q1 = $req(1, 'fix', 60, ['credits' => 20]);
ok(Requests::deliverAlerts() === 0 && !$sent && (int) Db::table('mod_mcsec_requests')->where('id', $q1)->value('alerted_at') > 0, 'with no chat set nothing is sent, and the request is marked');
\McSec\Settings::setSecret('bale_token', 'tok');
setting('ops_alert_bale', '123456');
$q2 = $req(2, 'manual');
$old = $req(3, 'help', 7 * 3600);
$n = Requests::deliverAlerts();
$all = implode("\n", array_map(fn ($x) => $x[0] . ' ' . $x[1], $sent));
ok($n === 1 && count($sent) === 1 && str_contains($all, '123456') && (str_contains($all, 'تست دستی') || str_contains($all, 'تست')), 'one message for the new request, to the admin\'s chat');
ok(!str_contains($all, 'SECRET') && !str_contains(json_decode('"' . str_replace('"', '\"', $all) . '"') ?? $all, 'SECRET'), 'the customer\'s own words are not in it');
ok(Requests::deliverAlerts() === 0 && count($sent) === 1, 'each request once');
ok((int) Db::table('mod_mcsec_requests')->where('id', $old)->value('alerted_at') === 0, 'a request older than six hours is left alone (nothing floods the chat after an upgrade)');
setting('request_alerts', '0');
$q3 = $req(1, 'help');
ok(Requests::deliverAlerts() === 0 && count($sent) === 1, 'the admin can turn it off');
setting('request_alerts', '1');

section('the admin\'s money page');
admin('view');
$page = function (): string {
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_GET = ['module' => 'mcsec', 'mcsa' => 'revenue'];
    $_POST = [];
    return \McSec\Admin\Controller::handle('addonmodules.php?module=mcsec');
};
Db::table('mod_mcsec_topups')->insert([
    ['client_id' => 1, 'pack' => 'p100', 'credits' => 100, 'amount' => 500000, 'invoice_id' => 1, 'status' => 'paid', 'created_at' => Clock::now() - 5 * 86400, 'paid_at' => Clock::now() - 5 * 86400],
    ['client_id' => 2, 'pack' => 'p50', 'credits' => 50, 'amount' => 250000, 'invoice_id' => 2, 'status' => 'paid', 'created_at' => Clock::now() - 40 * 86400, 'paid_at' => Clock::now() - 40 * 86400],
    ['client_id' => 2, 'pack' => 'p50', 'credits' => 50, 'amount' => 250000, 'invoice_id' => 3, 'status' => 'pending', 'created_at' => Clock::now() - 86400, 'paid_at' => 0],
]);
Db::table('tblclients')->where('id', 1)->update(['firstname' => '<script>alert(9)</script>']);
$tbl = fn () => [Db::table('mod_mcsec_topups')->count(), Db::table('mod_mcsec_ledger')->count(), Db::table('tblclients')->count()];
$before = $tbl();
$h = $page();
ok(str_contains($h, 'درآمد و مصرف') && str_contains($h, 'شش بازه‌ی ۳۰ روزه') && str_contains($h, 'پرخریدترین حساب‌ها'), 'the page is there for an admin who may only look');
ok(str_contains($h, '+۱۰۰٪') && str_contains($h, '#1 ') && str_contains($h, '#2 '), 'this period against the one before, and the accounts that bought');
ok(!str_contains($h, '<script>alert(9)') && $tbl() === $before, 'names are escaped, and the page writes nothing');

section('the public DNS check');
\McSec\Auth::$testClient = null;
$dns = [];
\McSec\Net::$resolver = function (string $name, string $type) use (&$dns) {
    $GLOBALS['__asked'][] = $type . ' ' . $name;
    return $dns[$type . ' ' . $name] ?? [];
};
$dns = ['NS good.example' => [['target' => 'ns1.x'], ['target' => 'ns2.x']], 'A good.example' => [['ip' => '93.184.216.34']], 'MX good.example' => [['target' => 'mx.good.example']],
    'TXT good.example' => [['txt' => 'v=spf1 include:_spf.x -all']], 'TXT _dmarc.good.example' => [['txt' => 'v=DMARC1; p=reject']], 'CAA good.example' => [['value' => 'letsencrypt.org']],
    'NS weak.example' => [['target' => 'ns1.x']], 'A weak.example' => [['ip' => '93.184.216.35']], 'TXT weak.example' => [['txt' => 'v=spf1 +all']], 'TXT _dmarc.weak.example' => [['txt' => 'v=DMARC1; p=none']]];
$post = function (string $domain): array {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_SERVER['REMOTE_ADDR'] = '198.51.100.7';
    $_GET = ['m' => 'mcsec', 'p' => 'check'];
    $_POST = ['domain' => $domain];
    return \McSec\Client\Controller::handle();
};
ok(str_contains(html(client_get(['p' => 'check'])), 'در دسترس نیست') && !PublicCheck::run('good.example', '198.51.100.7')['ok'], 'off by default');
setting('public_check', '1');
$g = client_get(['p' => 'check']);
ok(($g['requirelogin'] ?? true) === false && str_contains(html($g), 'name="domain"') && empty($GLOBALS['__asked']), 'the page needs no login, and opening it looks nothing up');
$GLOBALS['__http'] = 0;
http_mock(function () {
    $GLOBALS['__http']++;
    return ['status' => 200, 'body' => ''];
});
$h = html($post('Good.Example'));
ok(str_contains($h, 'good.example') && substr_count($h, 'mcs-chip') >= 6 && str_contains($h, 'DMARC ایمیل جعلی را قرنطینه یا رد می‌کند') && !str_contains($h, 'نیاز به توجه دارد'), 'a well-kept domain: every record is fine');
ok($GLOBALS['__http'] === 0, 'only DNS was read: no request went anywhere');
$h = html($post('https://weak.example/path'));
ok(str_contains($h, 'جلوی جعل را نمی‌گیرد') && str_contains($h, 'p=none') && str_contains($h, 'کمتر از دو سرور نام') && str_contains($h, '۳ مورد نیاز به توجه دارد'), 'a weak one: what is wrong, in plain words');
ok(!preg_match('~امن است|امتیاز~u', $h) && str_contains($h, 'تأیید مالکیت'), 'no score and no "secure"; the rest needs a login and proof of ownership');
ok(str_contains(html($post('nothere.example')), 'پیدا نشد') && str_contains(html($post('93.184.216.34')), 'نام یک دامنه') && !str_contains(html($post('<script>alert(9)</script>')), '<script>alert(9)'), 'an unknown domain, an IP or junk gets a plain answer, escaped');
ok(Db::table('mod_mcsec_assets')->count() === 0 && Db::table('mod_mcsec_scans')->count() === 0, 'nothing is stored: no asset, no scan');
setting('blocklist', "good.example");
ok(str_contains(html($post('good.example')), 'بررسی نمی‌شود'), 'the blocklist applies');
setting('blocklist', '');
ok(str_contains(html($post('good.example')), 'رکوردهای DNS') && str_contains(html($post('good.example')), 'چند بررسی انجام داده‌اید'), 'five checks an hour for one visitor, then a plain refusal');
$_SERVER['REMOTE_ADDR'] = '198.51.100.8';
setting('public_check_daily', '10');
$res = [];
for ($i = 0; $i < 6; $i++) {
    $res[] = PublicCheck::run('good.example', '203.0.113.' . $i)['ok'];
}
ok($res === [true, true, true, true, true, false], 'and a daily ceiling for everyone together');

section('WHMCS tables');
ok(Db::table('tblclients')->count() === 10, 'nothing was written to tbl*');
done();
