<?php
// 0.16.0 nobody verifies what is not theirs. Found by the founder: order hosting for google.com and the module
// believed it. Proof now is only what the customer cannot simply type: an ACTIVE domain registered here, an IP set by
// provisioning, a DNS record, a file that IS the proof, a meta tag in the page's own <head>. Proofs that rest on the
// database are looked at again when a scan is queued.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Assets;
use McSec\Clock;
use McSec\Db;
use McSec\Scans;
use McSec\Verify;
use WHMCS\Database\Capsule;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '80', 'welcome_credits' => '0', 'ownership_autoverify' => '1', 'daily_scan_cap' => '500'] as $k => $v) {
    setting($k, $v);
}
$who = login(1, 1);
Accounts::ensure(1);
$proof = Accounts::proof(Accounts::get(1));
$token = (string) Accounts::get(1)->verify_token;
$st = fn (int $id) => Db::table('mod_mcsec_assets')->where('id', $id)->first();
$add = function (string $v) use ($who) {
    $r = Assets::add($who, $v);
    return $r['ok'] ? (int) $r['id'] : 0;
};
foreach (['google.com', 'www.google.com', 'transfer-me.com', 'expired-mine.ir', 'page.example', 'echo.example', 'spa.example', 'listing.example', 'mine.example', 'filesite.example'] as $d) {
    dns_a($d, '93.184.216.' . (20 + strlen($d)));
}
http_mock(fn () => ['status' => 0, 'error' => 'refused', 'body' => '']);

section('the hosting-order trick');
as_whmcs(fn () => Capsule::table('tblhosting')->insert([['userid' => 1, 'packageid' => 2, 'domain' => 'google.com', 'domainstatus' => 'Active'], ['userid' => 1, 'packageid' => 2, 'domain' => 'www.google.com', 'domainstatus' => 'Pending']]));
$g = $add('google.com');
ok($g > 0 && $st($g)->status === 'pending' && (string) $st($g)->method === '', 'a hosting service ordered for google.com proves nothing');
$w = $add('mail.google.com');
ok($w > 0 && $st($w)->status === 'pending', 'nor does it cover a subdomain');
client_post('verify_check', ['asset' => $g], ['p' => 'asset', 'id' => $g]);
ok($st($g)->status === 'pending', 'the «بررسی کن» button does not believe it either');
Verify::due(30);
ok($st($g)->status === 'pending' && $st($w)->status === 'pending', 'nor the background check');
$r = Scans::queue(1, $st($g), 'hygiene', 0, 1);
ok(!$r['ok'] && !Db::table('mod_mcsec_scans')->where('asset_id', $g)->exists(), 'and nothing is scanned');
$b = $add('blog.example.org');
ok($b > 0 && $st($b)->status === 'pending', 'the hosting domain of the test fixture is not verified by itself any more');

section('a registered domain: only when the registrar made it active');
as_whmcs(fn () => Capsule::table('tbldomains')->insert([['userid' => 1, 'domain' => 'transfer-me.com', 'status' => 'Pending Transfer'], ['userid' => 1, 'domain' => 'pending-reg.com', 'status' => 'Pending'],
    ['userid' => 1, 'domain' => 'expired-mine.ir', 'status' => 'Expired'], ['userid' => 1, 'domain' => 'cancelled.ir', 'status' => 'Cancelled'], ['userid' => 1, 'domain' => 'fraud.ir', 'status' => 'Fraud'], ['userid' => 2, 'domain' => 'theirs.ir', 'status' => 'Active']]));
foreach (['transfer-me.com' => 'a transfer still pending', 'pending-reg.com' => 'a registration still pending', 'expired-mine.ir' => 'an expired domain', 'cancelled.ir' => 'a cancelled domain', 'fraud.ir' => 'a domain marked fraud', 'theirs.ir' => 'another account\'s active domain'] as $d => $what) {
    $id = $add($d);
    ok($id > 0 && $st($id)->status === 'pending', $what . ' is not proof');
}
$own = $add('shop-maral.ir');
$sub = $add('api.shop-maral.ir');
ok($st($own)->status === 'verified' && $st($own)->method === 'whmcs' && $st($sub)->status === 'verified' && $st($sub)->method === 'parent', 'an active domain registered here is verified at once, with its subdomains');

section('a proof that stops being true');
as_whmcs(fn () => Capsule::table('tbldomains')->where('domain', 'shop-maral.ir')->update(['userid' => 2]));
$r = Scans::queue(1, $st($own), 'hygiene', 0, 1);
ok(!$r['ok'] && $st($own)->status === 'lapsed', 'the domain left the account: the next scan is refused and the asset lapses at once');
$r = Scans::queue(1, $st($sub), 'hygiene', 0, 1);
ok(!$r['ok'] && $st($sub)->status === 'lapsed', 'and so does the subdomain that leaned on it');
ok(Db::table('mod_mcsec_notices')->where('client_id', 1)->where('event', 'asset_lapsed')->count() === 2, 'the customer is told, once per asset');
as_whmcs(fn () => Capsule::table('tbldomains')->where('domain', 'shop-maral.ir')->update(['userid' => 1]));
Db::table('mod_mcsec_assets')->whereIn('id', [$own, $sub])->update(['next_check_at' => 0]);
Verify::due(30);
ok($st($own)->status === 'verified' && $st($sub)->status === 'verified', 'back in the account: verified again by itself');
// an asset verified by the old rule (hosting domain) before the upgrade
Db::table('mod_mcsec_assets')->where('id', $g)->update(['status' => 'verified', 'method' => 'whmcs', 'verified_at' => Clock::now() - 86400, 'next_check_at' => Clock::now() + 86400 * 20]);
\McSec\Installer::install();
ok((int) $st($g)->next_check_at === 0, 'the upgrade puts every database proof up for a re-check');
ok(!Scans::queue(1, $st($g), 'hygiene', 0, 1)['ok'] && $st($g)->status === 'lapsed', 'google.com verified by the old rule cannot be scanned after the upgrade');
Db::table('mod_mcsec_assets')->where('id', $b)->update(['status' => 'verified', 'method' => 'whmcs', 'next_check_at' => 0]);
Verify::due(30);
ok($st($b)->status === 'lapsed', 'and the background pass lapses the others without waiting for three failures');

section('the file must be the proof');
$page = fn (string $body, int $code = 200) => http_mock(fn ($m, $url) => str_ends_with($url, '/.well-known/mcsec-verify.txt') ? ['status' => $code, 'body' => $body] : ['status' => 404, 'body' => '']);
$fs = $add('filesite.example');
foreach (['a page that only mentions the code' => '<html><body>Not found: you searched for ' . $proof . '</body></html>', 'a listing with the code in it' => "index of /\n" . $proof . "\nother.txt", 'the code with something after it' => $proof . ' extra',
    'another account\'s code' => 'mcsec-verify=' . str_repeat('a', 32), 'an empty file' => ''] as $what => $body) {
    $page($body);
    ok(!Verify::check($st($fs))['ok'] && $st($fs)->status === 'pending', 'refused: ' . $what);
}
$page($proof, 404);
ok(!Verify::check($st($fs))['ok'], 'refused: the right code on an error page (404)');
http_mock(fn ($m, $url) => ['status' => 302, 'body' => $proof, 'headers' => ['location' => ['https://evil.example/.well-known/mcsec-verify.txt']]]);
ok(!Verify::check($st($fs))['ok'], 'refused: a redirect (never followed)');
ok(Verify::fileIsProof("\xEF\xBB\xBF" . $proof . "\r\n", $proof) && !Verify::fileIsProof($proof, ''), 'a byte-order mark and a line end are fine; an empty proof never matches');
$page($proof . "\n");
ok(Verify::check($st($fs))['ok'] && $st($fs)->method === 'file', 'the real file verifies');
$fsub = $add('deep.filesite.example');
ok($st($fsub)->status === 'pending', 'a file proves one website: its subdomains are not covered');

section('the meta tag must be the owner\'s own');
$home = fn (string $html) => http_mock(fn ($m, $url) => preg_match('~^https?://[^/]+/$~', $url) ? ['status' => 200, 'body' => $html] : ['status' => 404, 'body' => '']);
$meta = '<meta name="mcsec-verification" content="' . $token . '">';
$metaQ = "<meta name='mcsec-verification' content='" . $token . "'>";
$cases = [
    'echoed into the body (a comment, a search box)' => '<html><head><title>x</title></head><body><p>latest comment: ' . $meta . '</p></body></html>',
    'inside a JSON blob in a script in the head' => '<html><head><script>window.__DATA__={"posts":[{"text":"' . $metaQ . '"}]}</script></head><body></body></html>',
    'inside a script in the body' => '<html><head></head><body><script>var s="' . $metaQ . '";</script></body></html>',
    'inside an HTML comment' => '<html><head><!-- ' . $meta . ' --></head><body></body></html>',
    'inside the title' => '<html><head><title>' . $meta . '</title></head><body></body></html>',
    'inside a textarea' => '<html><head></head><body><textarea>' . $meta . '</textarea></body></html>',
    'inside a noscript or template block' => '<html><head><noscript>' . $meta . '</noscript><template>' . $meta . '</template></head><body></body></html>',
    'a page with no head at all' => $meta . '<p>hello</p>',
    'after the head was closed' => '<html><head></head>' . $meta . '<body></body></html>',
    'an unclosed comment that swallows the head' => '<html><head><!-- ' . $meta . '</head><body></body></html>',
    'the right tag with another account\'s code' => '<html><head><meta name="mcsec-verification" content="' . str_repeat('b', 32) . '"></head><body></body></html>',
];
$ms = $add('echo.example');
foreach ($cases as $what => $html) {
    $home($html);
    ok(!Verify::check($st($ms))['ok'] && $st($ms)->status === 'pending', 'refused: ' . $what);
}
$home('<!doctype html><html lang="fa"><HEAD><meta charset="utf-8"><script>var a=1;</script>' . $meta . '<title>shop</title></HEAD><body><p>hi</p></body></html>');
ok(Verify::check($st($ms))['ok'] && $st($ms)->method === 'meta', 'the tag in the page\'s own head verifies');
ok($st($add('sub.echo.example'))->status === 'pending', 'a meta tag proves one website: its subdomains are not covered');

section('reverse DNS only under a domain proved in DNS');
$ip = $add('93.184.216.77');
$GLOBALS['__dns']['77.216.184.93.in-addr.arpa']['PTR'][] = ['target' => 'srv.filesite.example'];
dns_a('srv.filesite.example', '93.184.216.77');
http_mock(fn () => ['status' => 0, 'error' => 'refused', 'body' => '']);
ok(!Verify::check($st($ip))['ok'] && $st($ip)->status === 'pending', 'a PTR under a domain verified only by a file does not verify the IP');
$dz = $add('mine.example');
dns_txt('_mcsec-verify.mine.example', $proof);
ok(Verify::check($st($dz))['ok'] && $st($dz)->method === 'dns', 'a DNS record verifies the domain');
$ip2 = $add('93.184.216.78');
$GLOBALS['__dns']['78.216.184.93.in-addr.arpa']['PTR'][] = ['target' => 'srv.mine.example'];
ok(!Verify::check($st($ip2))['ok'], 'a PTR that does not resolve back is not enough');
dns_a('srv.mine.example', '93.184.216.78');
ok(Verify::check($st($ip2))['ok'] && $st($ip2)->method === 'ptr', 'a PTR under a DNS-proved domain that resolves back verifies the IP');

section('DNS: only this account\'s exact code');
$dn = $add('page.example');
dns_txt('_mcsec-verify.page.example', 'mcsec-verify=' . str_repeat('c', 32));
dns_txt('page.example', 'v=spf1 include:' . $proof . ' ~all');
ok(!Verify::check($st($dn))['ok'], 'another code, or the code buried in another record, is refused');
Accounts::ensure(2);
ok(Accounts::proof(Accounts::get(2)) !== $proof, 'each account has its own code');

section('server IPs come from provisioning');
setting('allow_private_ips', '1'); // the fixture's server IP is from a documentation range
$sip = $add('203.0.113.5');
ok($st($sip)->status === 'verified' && $st($sip)->method === 'whmcs', 'a dedicated IP of an active service is verified');
as_whmcs(fn () => Capsule::table('tblhosting')->where('dedicatedip', '203.0.113.5')->update(['domainstatus' => 'Terminated']));
ok(!Scans::queue(1, $st($sip), 'hygiene', 0, 1)['ok'] && $st($sip)->status === 'lapsed', 'the service ended: the IP lapses at the next scan');

done();
