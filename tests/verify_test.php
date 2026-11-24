<?php
// 0.11.0 ownership proof, by hand and automatic: the ready proof file to download, a complete path for an IP, and the
// proof record created with the customer's own DNS-panel token (used once, kept nowhere). Creating the record never
// verifies by itself: only the public DNS does. IDOR, CSRF/nonce, XSS, the token never stored or logged.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\DnsApi;

Clock::$fixed = strtotime('2026-11-22T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '50', 'welcome_credits' => '0', 'ownership_autoverify' => '1'] as $k => $v) {
    setting($k, $v);
}
$who = login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
$proof = Accounts::proof(Accounts::get(1));
$mk = function (string $value, string $kind = 'domain', int $client = 1): object {
    $id = Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $client, 'kind' => $kind, 'value' => $value, 'status' => 'pending', 'created_at' => Clock::now(), 'next_check_at' => Clock::now() + 9999]);
    return Db::table('mod_mcsec_assets')->where('id', $id)->first();
};
$dom = $mk('cf-site.example');
$sub = $mk('app.arvan-site.example');
$ip = $mk('93.184.216.50', 'ip');
$cidr = $mk('93.184.216.0/28', 'cidr');
$other = $mk('other.example', 'domain', 2);
$status = fn (object $a) => (string) Db::table('mod_mcsec_assets')->where('id', $a->id)->value('status');
$TOKEN = 'cfTok_abcdefghijklmnopqrstuvwxyz0123456789';
$calls = [];
$cf = ['zones' => 200, 'record' => 200];
http_mock(function ($method, $url, $headers, $body) use (&$calls, &$cf) {
    $b = is_array($body) ? $body : (json_decode((string) $body, true) ?: []);
    $calls[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $b];
    if (str_starts_with($url, 'https://api.cloudflare.com/client/v4/zones?name=')) {
        return $cf['zones'] === 200 ? ['status' => 200, 'body' => json_encode(['success' => true, 'result' => str_contains($url, 'cf-site.example') ? [['id' => str_repeat('a', 32)]] : []])]
            : ['status' => $cf['zones'], 'body' => '{"success":false}'];
    }
    if (str_starts_with($url, 'https://api.cloudflare.com/client/v4/zones/' . str_repeat('a', 32) . '/dns_records')) {
        return $cf['record'] === 200 ? ['status' => 200, 'body' => '{"success":true,"result":{"id":"r1"}}'] : ['status' => 400, 'body' => '{"success":false,"errors":[{"code":' . $cf['record'] . '}]}'];
    }
    if (str_starts_with($url, 'https://napi.arvancloud.ir/cdn/4.0/domains/')) {
        return ['status' => 201, 'body' => '{"data":{"id":"x"}}'];
    }
    return ['status' => 404, 'body' => ''];
});
$auto = fn (object $a, string $provider, string $token, bool $nonce = true) => client_post('verify_auto', ['asset' => $a->id, 'provider' => $provider, 'dns_token' => $token], ['p' => 'asset', 'id' => $a->id], $nonce);

section('the page: automatic and by hand');
$h = html(client_get(['p' => 'asset', 'id' => $dom->id]));
ok(str_contains($h, 'تأیید خودکار') && str_contains($h, 'تأیید دستی') && str_contains($h, 'روش ۱ (پیشنهادی): رکورد DNS') && str_contains($h, 'تگ متا'), 'a domain: both headings, the three ways by hand');
ok(!str_contains($h, 'name="dns_token"') && !DnsApi::enabled(), 'the token form is off until the admin turns it on');
ok(str_contains($h, 'vfile=1') && str_contains($h, 'mcsec-verify.txt'), 'the file way offers the ready file');
$r = $auto($dom, 'cloudflare', $TOKEN);
ok(!$calls && $status($dom) === 'pending' && str_contains(flash_of($r), 'پشتیبانی نمی‌شود'), 'switch off: the action is refused and nothing is called');

section('the ready proof file');
$r = client_get(['p' => 'asset', 'id' => $dom->id, 'vfile' => '1']);
ok(($r['raw']['bytes'] ?? '') === $proof . "\n" && str_starts_with((string) $r['raw']['mime'], 'text/plain') && $r['raw']['name'] === 'mcsec-verify.txt', 'the file holds exactly this account\'s proof');
ok(client_get(['p' => 'asset', 'id' => $ip->id, 'vfile' => '1'])['raw']['bytes'] === $proof . "\n", 'the same file for an IP');
ok(client_get(['p' => 'asset', 'id' => $other->id, 'vfile' => '1'])['raw'] === null && client_get(['p' => 'asset', 'id' => $cidr->id, 'vfile' => '1'])['raw'] === null, 'not for another account\'s asset (IDOR), not for a range');

section('an IP: a complete path');
setting('support_dept', '3');
$h = html(client_get(['p' => 'asset', 'id' => $ip->id]));
ok(str_contains($h, 'سرویس‌های همین حساب در مارال کلاد') && str_contains($h, 'روش ۱ (پیشنهادی): فایل متنی روی همین سرور') && str_contains($h, 'روش ۲: DNS معکوس (PTR)') && str_contains($h, 'روش ۳: درخواست تأیید از پشتیبانی'), 'automatic (Maral service), file, reverse DNS, manual request');
ok(str_contains($h, 'http://93.184.216.50/.well-known/mcsec-verify.txt') && str_contains($h, 'python3 -m http.server 80') && str_contains($h, '/var/www/html/.well-known') && substr_count($h, $proof) >= 3, 'the address to open, the file content and two ready commands');
ok(str_contains($h, 'p=support&amp;topic=verify&amp;asset=' . $ip->id), 'the manual request opens the expert-request form with this asset');
ok(!str_contains($h, 'name="dns_token"') && str_contains($h, 'الان بررسی کن'), 'no DNS token for an IP; the check button is there');
setting('support_requests', '0');
ok(!str_contains(html(client_get(['p' => 'asset', 'id' => $ip->id])), 'درخواست تأیید از پشتیبانی'), 'expert requests off: no manual-request way');
setting('support_requests', '1');
ok(str_contains(html(client_get(['p' => 'asset', 'id' => $cidr->id])), 'p=support&amp;topic=verify'), 'a range: the manual request');
// the file way still works for an IP, on port 80
http_mock(function ($method, $url) use ($proof) {
    return $url === 'http://93.184.216.50/.well-known/mcsec-verify.txt' ? ['status' => 200, 'body' => $proof . "\n"] : ['status' => 0, 'error' => 'refused', 'body' => ''];
});
client_post('verify_check', ['asset' => $ip->id], ['p' => 'asset', 'id' => $ip->id]);
ok($status($ip) === 'verified' && Db::table('mod_mcsec_assets')->where('id', $ip->id)->value('method') === 'file', 'the uploaded file verifies the IP');

section('automatic: the record is created with the customer\'s token');
http_mock(function ($method, $url, $headers, $body) use (&$calls, &$cf) {
    $b = is_array($body) ? $body : (json_decode((string) $body, true) ?: []);
    $calls[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $b];
    if (str_starts_with($url, 'https://api.cloudflare.com/client/v4/zones?name=')) {
        return $cf['zones'] === 200 ? ['status' => 200, 'body' => json_encode(['success' => true, 'result' => str_contains($url, 'cf-site.example') ? [['id' => str_repeat('a', 32)]] : []])]
            : ['status' => $cf['zones'], 'body' => '{"success":false}'];
    }
    if (str_starts_with($url, 'https://api.cloudflare.com/client/v4/zones/' . str_repeat('a', 32) . '/dns_records')) {
        return $cf['record'] === 200 ? ['status' => 200, 'body' => '{"success":true,"result":{"id":"r1"}}'] : ['status' => 400, 'body' => '{"success":false,"errors":[{"code":' . $cf['record'] . '}]}'];
    }
    if (str_starts_with($url, 'https://napi.arvancloud.ir/cdn/4.0/domains/')) {
        return ['status' => 201, 'body' => '{"data":{"id":"x"}}'];
    }
    return ['status' => 0, 'error' => 'refused', 'body' => ''];
});
setting('verify_dns_api', '1');
$h = html(client_get(['p' => 'asset', 'id' => $dom->id]));
ok(str_contains($h, 'name="dns_token"') && str_contains($h, 'type="password"') && str_contains($h, 'autocomplete="off"') && str_contains($h, 'Cloudflare') && str_contains($h, 'آروان‌کلاد') && str_contains($h, 'ذخیره نمی‌شود'), 'the form: panel, a password box, and it says the token is not kept');
$calls = [];
$r = $auto($dom, 'cloudflare', $TOKEN, false);
ok(!$calls, 'without the nonce: refused');
$auto($other, 'cloudflare', $TOKEN);
$auto($ip, 'cloudflare', $TOKEN);
ok(!$calls && $status($other) === 'pending', 'another account\'s asset (IDOR) and an IP: refused before any call');
$r = $auto($dom, 'cloudflare', 'short');
$r2 = $auto($dom, 'cloudflare', 'has spaces and <script>alert(9)</script> inside it......');
ok(!$calls && str_contains(flash_of($r), 'توکن را کامل') && !str_contains(html($r2), '<script>alert(9)'), 'a token that cannot be one: refused before any call, never echoed');
$r = $auto($dom, 'cloudflare', $TOKEN);
$post = array_values(array_filter($calls, fn ($c) => $c['method'] === 'POST'))[0] ?? null;
ok(count($calls) === 2 && ($calls[0]['headers']['Authorization'] ?? '') === 'Bearer ' . $TOKEN && str_contains($calls[0]['url'], 'zones?name=cf-site.example'), 'the zone is looked up with the customer\'s token');
ok($post && $post['body']['type'] === 'TXT' && $post['body']['name'] === '_mcsec-verify.cf-site.example' && $post['body']['content'] === $proof, 'the proof record is created under its own name');
ok($status($dom) === 'pending' && str_contains(flash_of($r), 'ساخته شد') && str_contains(flash_of($r), 'ذخیره نشد'), 'creating the record does NOT verify: the public DNS has not shown it yet, and the customer is told');
ok((int) Db::table('mod_mcsec_assets')->where('id', $dom->id)->value('next_check_at') <= Clock::now() + 60, 'the next automatic check is in a minute');
$leak = false;
foreach (\WHMCS\Database\Capsule::select("select name from sqlite_master where type='table'") as $t) {
    $leak = $leak || str_contains(json_encode(\WHMCS\Database\Capsule::table($t->name)->get()), $TOKEN);
}
ok(!$leak && !str_contains(html($r), $TOKEN), 'the token is in no table (settings, log, activity, key-value) and not in the page');
ok(Db::table('mod_mcsec_audit')->where('client_id', 1)->where('action', 'verify_auto')->count() === 1, 'the activity log says a record was created, without the token');
dns_txt('_mcsec-verify.cf-site.example', $proof);
$r = $auto($dom, 'cloudflare', $TOKEN);
ok($status($dom) === 'verified' && Db::table('mod_mcsec_assets')->where('id', $dom->id)->value('method') === 'dns' && str_contains(flash_of($r), 'تأیید شد'), 'once the record is visible in the public DNS, it is verified (method: DNS)');

section('refusals from the panel, said plainly');
$d2 = $mk('gone.example');
$r = $auto($d2, 'cloudflare', $TOKEN);
ok($status($d2) === 'pending' && str_contains(flash_of($r), 'پیدا نشد') && str_contains(flash_of($r), 'دستی'), 'the domain is not in that account: says so and points to the manual way');
$cf['zones'] = 403;
$r = $auto($d2, 'cloudflare', $TOKEN);
ok(str_contains(flash_of($r), 'نپذیرفت'), 'a token the panel refuses');
$cf['zones'] = 200;
$d3 = $mk('www.cf-site.example');
Db::table('mod_mcsec_assets')->where('id', $d3->id)->update(['status' => 'pending', 'method' => '']);
$cf['record'] = 81057;
$r = $auto($d3, 'cloudflare', $TOKEN);
ok(str_contains(flash_of($r), 'ساخته شد') || str_contains(flash_of($r), 'تأیید'), 'the record is already there from an earlier try: fine');
$cf['record'] = 200;

section('providers and limits');
$calls = [];
$r = $auto($sub, 'arvan', 'Apikey 0123456789abcdef-0123-4567-89ab-cdef01234567');
$c = $calls[0] ?? null;
ok($c && $c['url'] === 'https://napi.arvancloud.ir/cdn/4.0/domains/arvan-site.example/dns-records' && $c['headers']['Authorization'] === 'Apikey 0123456789abcdef-0123-4567-89ab-cdef01234567'
    && $c['body']['type'] === 'txt' && $c['body']['name'] === '_mcsec-verify.app' && $c['body']['value'] === ['text' => $proof], 'ArvanCloud: the record under the subdomain, in the zone of the main domain');
setting('verify_dns_providers', 'cloudflare');
$calls = [];
$r = $auto($sub, 'arvan', $TOKEN);
ok(!$calls && str_contains(flash_of($r), 'پشتیبانی نمی‌شود') && !str_contains(html(client_get(['p' => 'asset', 'id' => $sub->id])), 'آروان‌کلاد</option>'), 'a panel the admin did not allow: refused and not offered');
$r = $auto($sub, 'https://evil.example/api', $TOKEN);
ok(!$calls, 'the panel is a name from a fixed list, never an address');
login(11, 1); // viewer
ok(!str_contains(html(client_get(['p' => 'asset', 'id' => $sub->id])), 'name="dns_token"'), 'a viewer sees no token form');
$auto($sub, 'cloudflare', $TOKEN);
ok(!$calls, 'and cannot use it');
login(1, 1);
Db::table('mod_mcsec_hits')->where('k', 'like', 'vauto:%')->delete();
for ($i = 0; $i < 12; $i++) {
    $r = $auto($d2, 'cloudflare', $TOKEN);
}
ok(str_contains(flash_of($r), 'چند بار امتحان'), 'at most ten tries an hour');

done();
