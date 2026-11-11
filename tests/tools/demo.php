<?php
// Demo data for the page tests and the visual preview: one shop on Maral (auto-verified), its API subdomain, a
// pending foreign domain, a server IP; a real built-in scan, nuclei-style findings, surface, a running scan, schedules,
// notices, credits, a basic and an AI report (model mocked), and 30 days of score history. Development only.
declare(strict_types=1);

use McSec\Clock;
use McSec\Db;

function demo_data(): void
{
    $tz = new DateTimeZone('Asia/Tehran');
    Clock::$fixed = (new DateTimeImmutable('2026-11-11 10:00', $tz))->getTimestamp();
    foreach (['enabled' => '1', 'access_mode' => 'all', 'max_assets_free' => '20', 'ai_enabled' => '1', 'ai_model' => 'gpt-4.1-mini', 'allow_private_ips' => '1',
        'group_rules' => json_encode([['group' => 2, 'monthly' => 30, 'max_assets' => 10]]), 'telegram_bot' => 'MaralSecBot', 'bale_bot' => 'maralsec_bot'] as $k => $v) {
        setting($k, $v);
    }
    \McSec\Settings::setSecret('ai_key', 'demo');
    \McSec\Settings::setSecret('bale_token', 'demo');
    \McSec\Ai::$mock = function (array $body) {
        $user = (string) ($body['messages'][1]['content'] ?? '');
        preg_match_all('~"id":(\d+)~', $user, $m);
        $ids = array_slice(array_values(array_unique(array_map('intval', $m[1]))), 0, 20);
        if (str_contains($user, 'Explain and give the fix')) {
            return ['ok' => true, 'text' => json_encode(['summary' => 'پوشه‌ی .git سایت از اینترنت خوانده می‌شود.', 'why' => 'با این پوشه کد کامل سایت و گاهی رمز پایگاه داده بازسازی می‌شود.',
                'steps' => ['دسترسی به پوشه‌های نقطه‌دار را در وب‌سرور ببندید.', 'پوشه‌ی .git را از ریشه‌ی سایت بیرون ببرید.', 'رمزهایی که در مخزن بوده‌اند را عوض کنید.'],
                'snippets' => [['label' => 'nginx', 'code' => "location ~ /\\.git { deny all; return 404; }"], ['label' => 'Apache', 'code' => "RedirectMatch 404 /\\.git"]],
                'verify' => 'نشانی /.git/HEAD باید 404 برگرداند.', 'effort' => '۱۰ دقیقه', 'references' => ['https://owasp.org/www-project-web-security-testing-guide/']], JSON_UNESCAPED_UNICODE)];
        }
        $f = [];
        foreach ($ids as $i => $id) {
            $f[] = ['id' => $id, 'priority' => $i + 1, 'why' => 'این مورد برای فروشگاه شما ریسک واقعی دارد و مهاجم می‌تواند از آن برای دسترسی بیشتر استفاده کند.',
                'steps' => ['تنظیم پیشنهادی را در وب‌سرور اعمال کنید.', 'سرویس را دوباره بارگذاری کنید.', 'با «رفع کردم، دوباره بسنج» نتیجه را ببینید.'],
                'snippet' => ['label' => 'nginx', 'code' => 'add_header Strict-Transport-Security "max-age=31536000" always;'], 'verify' => 'اسکن بعدی دیگر این مورد را نمی‌بیند.', 'effort' => '۱۵ دقیقه', 'needs_confirmation' => false];
        }
        return ['ok' => true, 'text' => json_encode(['executive_summary' => 'وضعیت امنیت فروشگاه در مجموع قابل قبول است، ولی دو مشکل جدی دارد: پوشه‌ی کد منبع از اینترنت خوانده می‌شود و یک آسیب‌پذیری شناخته‌شده‌ی بحرانی در افزونه‌ی وردپرس باز است. با رفع این دو در همین هفته، امتیاز امنیت به بالای ۷۵ می‌رسد.',
            'risk_level' => 'high', 'key_risks' => [['title' => 'نشت کد منبع', 'impact' => 'مهاجم با کد سایت، رمزها و نقطه‌ضعف‌ها را پیدا می‌کند.', 'finding_ids' => array_slice($ids, 0, 1)]],
            'quick_wins' => ['بستن دسترسی به /.git در وب‌سرور', 'به‌روزرسانی افزونه‌ی آسیب‌پذیر', 'افزودن رکورد DMARC'], 'plan' => [['when' => 'این هفته', 'action' => 'رفع دو مورد بحرانی و مهم'], ['when' => 'این ماه', 'action' => 'هدرهای امنیتی و SPF/DMARC']],
            'findings' => $f], JSON_UNESCAPED_UNICODE)];
    };
    $who = login(1, 1);
    \McSec\Accounts::ensure(1);
    \McSec\Credits::credit(1, 200, 'paid', 'topup', 'topup:demo', 'خرید بسته (فاکتور ۱۰۲۴۵)');
    // assets
    $shop = \McSec\Assets::add($who, 'shop-maral.ir', 'فروشگاه اصلی')['id'];
    $api = \McSec\Assets::add($who, 'api.shop-maral.ir')['id'];
    $srv = \McSec\Assets::add($who, '198.51.100.7', 'سرور ابری')['id'];
    \McSec\Assets::add($who, 'example-partner.com');
    // a built-in hygiene scan on the shop with a realistic website
    $GLOBALS['__dns']['shop-maral.ir']['A'] = [['ip' => '198.51.100.7']];
    $GLOBALS['__dns']['shop-maral.ir']['TXT'] = [['txt' => 'v=spf1 include:_spf.mail.test ~all']];
    $GLOBALS['__certs']['shop-maral.ir'] = ['days' => 12, 'not_after' => '2026-11-23', 'issuer' => "Let's Encrypt", 'cn' => 'shop-maral.ir', 'san' => ['shop-maral.ir', 'www.shop-maral.ir'], 'valid_host' => true, 'self_signed' => false, 'proto' => 'TLSv1.3'];
    $GLOBALS['__open_ports']['198.51.100.7'] = [22, 443, 3306];
    http_mock(function ($m, $url) {
        return match (true) {
            $url === 'https://shop-maral.ir/' => ['status' => 200, 'body' => '<title>فروشگاه</title>', 'headers' => ['server' => ['nginx/1.18.0'], 'x-powered-by' => ['PHP/7.4.33'], 'set-cookie' => ['wordpress_logged_in=1; path=/']]],
            $url === 'http://shop-maral.ir/' => ['status' => 200, 'body' => 'ok'],
            $url === 'https://shop-maral.ir/.git/HEAD' => ['status' => 200, 'body' => "ref: refs/heads/main\n"],
            default => ['status' => 404, 'body' => ''],
        };
    });
    $q = \McSec\Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $shop)->first(), 'hygiene', 0, 1);
    \McSec\Scans::dispatch(microtime(true) + 30);
    // nuclei-style findings from a completed OASM vulnerability scan
    $sid = Db::table('mod_mcsec_scans')->insertGetId(['client_id' => 1, 'asset_id' => $shop, 'profile' => 'vuln', 'engine' => 'oasm', 'status' => 'completed', 'credits' => 6,
        'queued_at' => Clock::now() - 7200, 'started_at' => Clock::now() - 7000, 'finished_at' => Clock::now() - 3600, 'stage' => 'تمام شد', 'progress' => 100]);
    $vs = Db::table('mod_mcsec_scans')->where('id', $sid)->first();
    $asset = Db::table('mod_mcsec_assets')->where('id', $shop)->first();
    $diff = \McSec\Findings::ingest($vs, $asset, [
        ['key' => 'oasm.cve-2024-27956', 'title' => 'WordPress Automatic Plugin < 3.92.1 - SQL Injection', 'severity' => 'critical', 'location' => 'https://shop-maral.ir/wp-content/plugins/wp-automatic/inc/csv.php',
            'description' => 'The WordPress Automatic plugin is vulnerable to unauthenticated SQL injection.', 'cve' => ['CVE-2024-27956'], 'cwe' => ['CWE-89'], 'cvss' => 9.9, 'epss' => 0.94, 'refs' => ['https://nvd.nist.gov/vuln/detail/CVE-2024-27956'], 'tags' => ['wordpress', 'sqli', 'kev']],
        ['key' => 'oasm.wordpress-xmlrpc', 'title' => 'WordPress XML-RPC Enabled', 'severity' => 'low', 'location' => 'https://shop-maral.ir/xmlrpc.php', 'description' => 'xmlrpc.php answers system.listMethods'],
        ['key' => 'oasm.phpinfo', 'title' => 'phpinfo() Page Exposed', 'severity' => 'medium', 'location' => 'https://shop-maral.ir/info.php', 'evidence' => 'PHP Version 7.4.33'],
    ], true);
    \McSec\Surface::ingest($vs, $asset, [['kind' => 'host', 'value' => 'shop-maral.ir'], ['kind' => 'host', 'value' => 'www.shop-maral.ir'], ['kind' => 'host', 'value' => 'mail.shop-maral.ir'],
        ['kind' => 'port', 'value' => '198.51.100.7:443', 'meta' => ['title' => 'فروشگاه', 'server' => 'nginx']], ['kind' => 'tech', 'value' => 'WordPress:6.4.2'], ['kind' => 'tech', 'value' => 'WooCommerce']], []);
    Db::table('mod_mcsec_scans')->where('id', $sid)->update(['summary' => json_encode(['new' => count($diff['new']), 'fixed' => 0, 'reopened' => 0, 'seen' => 3, 'open' => \McSec\Findings::openCounts(0, $shop), 'surface_new' => 2, 'surface_seen' => 6])]);
    Db::table('mod_mcsec_assets')->where('id', $shop)->update(['last_scan_at' => Clock::now() - 3600]);
    // a running surface scan on the API, and a hygiene scan on the server
    Db::table('mod_mcsec_scans')->insert(['client_id' => 1, 'asset_id' => $api, 'profile' => 'surface', 'engine' => 'oasm', 'status' => 'running', 'credits' => 2, 'backend_ref' => 't-demo',
        'queued_at' => Clock::now() - 900, 'started_at' => Clock::now() - 840, 'synced_at' => Clock::now(), 'progress' => 45, 'stage' => 'در حال اجرا: naabu']);
    \McSec\Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $srv)->first(), 'hygiene', 0, 1);
    \McSec\Scans::dispatch(microtime(true) + 30);
    // schedules, notification channels, reports, history
    \McSec\Schedules::save($who, ['asset' => 0, 'profile' => 'hygiene', 'freq' => 'weekly', 'dow' => 6, 'hour' => 3]);
    \McSec\Schedules::save($who, ['asset' => $shop, 'profile' => 'vuln', 'freq' => 'monthly', 'dom' => 1, 'hour' => 2]);
    \McSec\Accounts::update(1, ['bale_chat' => '123456']);
    \McSec\Reports::process(microtime(true) + 30);
    $rid = \McSec\Reports::queue(1, 'account', [], true, 1)['report_id'];
    \McSec\Reports::build($rid);
    \McSec\Reports::aiFix($who, (int) Db::table('mod_mcsec_findings')->where('source_key', 'builtin.web.git')->value('id'));
    $score = 40;
    for ($d = 30; $d >= 1; $d--) {
        $score = max(20, min(95, $score + random_int(-4, 6)));
        Db::table('mod_mcsec_snapshots')->insertOrIgnore(['client_id' => 1, 'day' => Clock::today(-$d), 'score' => $score, 'counts' => '{}']);
    }
}
