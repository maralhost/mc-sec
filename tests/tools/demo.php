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
        'gift_enabled' => '1', 'invite_enabled' => '1', 'auto_topup_enabled' => '1', 'advanced_enabled' => '1', 'advanced_plan_only' => '0', 'assistant_enabled' => '1', 'assistant_all' => '1', 'verify_dns_api' => '1', 'support_dept' => '1', 'export_csv' => '1', 'host_mute' => '1', 'ai_opinion' => '1', 'service_box' => '1', 'domain_watch' => '1', 'threat_alerts' => '1', 'telegram_bot' => 'MaralSecBot', 'bale_bot' => 'maralsec_bot'] as $k => $v) {
        setting($k, $v);
    }
    foreach (['geo_map', 'report_share', 'site_badge', 'report_compliance', 'fix_deadlines', 'finding_assign'] as $k) {
        setting($k, '1'); // what 0.20.0 and 0.21.0 added, all on for the preview
    }
    setting('pdf_whitelabel', '*');
    \McSec\Rules::save(['scope' => 'group', 'target' => 2, 'monthly' => 30, 'max_assets' => 10]);
    \McSec\Settings::setSecret('ai_key', 'demo');
    \McSec\Settings::setSecret('bale_token', 'demo');
    \McSec\Ai::$mock = function (array $body) {
        if (($a = demo_assistant($body)) !== null) {
            return $a;
        }
        if (str_contains((string) ($body['messages'][1]['content'] ?? ''), 'second opinion')) {
            return ['ok' => true, 'text' => json_encode(['verdict' => 'likely_real', 'why' => 'پاسخ سرور همان الگویی را دارد که این آسیب‌پذیری می‌سازد و نسخه‌ی دیده‌شده در بازه‌ی آسیب‌پذیر است.',
                'check' => ['نسخه‌ی افزونه را در پیشخوان وردپرس ببینید.', 'پس از به‌روزرسانی، «رفع کردم، دوباره بسنج» را بزنید.']], JSON_UNESCAPED_UNICODE)];
        }
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
    // a domain behind Cloudflare whose real server is the Maral server above
    $GLOBALS['__dns']['blog-maral.ir']['A'] = [['ip' => '104.16.5.5']];
    setting('cdn_origin_scan', '1');
    $blog = \McSec\Assets::add($who, 'blog-maral.ir', 'وبلاگ')['id'];
    \McSec\Verify::adminApprove((int) $blog, 'demo');
    \McSec\Assets::setOrigin($who, (int) $blog, '198.51.100.7');
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
            str_contains($url, 'blog-maral.ir') => ['status' => 403, 'body' => 'Attention Required!', 'headers' => ['server' => ['cloudflare']]],
            default => ['status' => 404, 'body' => ''],
        };
    });
    // 0.2.0: KEV facts, monitoring, support link, an offer, the scanner page
    foreach (['support_dept' => '2', 'offers' => 'tls-expiring | گواهی SSL با تمدید خودکار و بی‌دردسر از مارال کلاد | https://maral.cloud/ssl', 'monitor_enabled' => '1', 'intel_enabled' => '1',
        'abuse_email' => 'abuse@maral.cloud', 'scanner_ips' => "185.165.119.10\n185.165.119.11"] as $k => $v) {
        setting($k, $v);
    }
    Db::table('mod_mcsec_intel')->insertOrIgnore(['cve' => 'CVE-2024-27956', 'kev' => 1, 'kev_added' => '2024-05-01', 'kev_ransom' => 0, 'epss' => 0.94, 'epss_at' => Clock::now(), 'updated_at' => Clock::now()]);
    $q = \McSec\Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $shop)->first(), 'hygiene', 0, 1);
    \McSec\Scans::dispatch(microtime(true) + 30);
    // the blog behind Cloudflare: its WAF answers the check with 403, so the basic check is incomplete
    \McSec\Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $blog)->first(), 'hygiene', 0, 1);
    \McSec\Scans::dispatch(microtime(true) + 30);
    \McSec\Scans::pollRunning(microtime(true) + 30);
    Db::table('mod_mcsec_assets')->where('id', $shop)->update(['mon_status' => 'up', 'mon_at' => Clock::now() - 420, 'mon_since' => Clock::now() - 86400 * 9, 'mon_cert_at' => Clock::now() - 3600, 'mon_cert_end' => '2026-11-23']);
    Db::table('mod_mcsec_assets')->where('id', $blog)->update(['mon_status' => 'down', 'mon_at' => Clock::now() - 300, 'mon_since' => Clock::now() - 1800, 'mon_fails' => 6, 'mon_note' => 'HTTP 502']);
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
    \McSec\Surface::ingest($vs, $asset, [['kind' => 'ip', 'value' => '185.165.119.20', 'meta' => ['cc' => 'IR', 'country' => 'Iran', 'city' => 'Tehran', 'lat' => 35.69, 'lon' => 51.42]],
        ['kind' => 'ip', 'value' => '49.12.10.4', 'meta' => ['cc' => 'DE', 'country' => 'Germany', 'city' => 'Falkenstein', 'lat' => 50.47, 'lon' => 12.37]],
        ['kind' => 'ip', 'value' => '49.12.10.5', 'meta' => ['cc' => 'DE', 'country' => 'Germany', 'city' => 'Nuremberg', 'lat' => 49.45, 'lon' => 11.08]],
        ['kind' => 'ip', 'value' => '104.21.3.9', 'meta' => ['cc' => 'US', 'country' => 'United States', 'city' => 'San Francisco', 'lat' => 37.77, 'lon' => -122.42]]], []);
    \McSec\Surface::ingest($vs, $asset, [['kind' => 'host', 'value' => 'shop-maral.ir'], ['kind' => 'host', 'value' => 'www.shop-maral.ir'], ['kind' => 'host', 'value' => 'mail.shop-maral.ir'],
        ['kind' => 'port', 'value' => '198.51.100.7:443', 'meta' => ['title' => 'فروشگاه', 'server' => 'nginx']], ['kind' => 'tech', 'value' => 'WordPress:6.4.2'], ['kind' => 'tech', 'value' => 'WooCommerce']], []);
    Db::table('mod_mcsec_scans')->where('id', $sid)->update(['summary' => json_encode(['new' => count($diff['new']), 'fixed' => 0, 'reopened' => 0, 'seen' => 3, 'open' => \McSec\Findings::openCounts(0, $shop), 'surface_new' => 2, 'surface_seen' => 6])]);
    Db::table('mod_mcsec_assets')->where('id', $shop)->update(['last_scan_at' => Clock::now() - 3600]);
    // a running surface scan on the API, and a hygiene scan on the server
    Db::table('mod_mcsec_scans')->insert(['client_id' => 1, 'asset_id' => $api, 'profile' => 'surface', 'engine' => 'oasm', 'status' => 'running', 'credits' => 2, 'backend_ref' => 't-demo',
        'queued_at' => Clock::now() - 900, 'started_at' => Clock::now() - 840, 'synced_at' => Clock::now(), 'progress' => 45, 'stage' => 'در حال اجرا: naabu']);
    \McSec\Scans::queue(1, Db::table('mod_mcsec_assets')->where('id', $srv)->first(), 'hygiene', 0, 1);
    \McSec\Scans::dispatch(microtime(true) + 30);
    // a real screenshot for the visual preview only (MCSEC_DEMO_SHOT=path to a JPEG or PNG); the tests run without it
    $shotFile = (string) getenv('MCSEC_DEMO_SHOT');
    if ($shotFile !== '' && is_file($shotFile) && \McSec\Shots::mime((string) file_get_contents($shotFile)) !== '') {
        foreach ([$shop, $api] as $aid) {
            Db::table('mod_mcsec_shots')->insert(['asset_id' => (int) $aid, 'client_id' => 1, 'host' => 'demo', 'mime' => \McSec\Shots::mime((string) file_get_contents($shotFile)), 'data' => base64_encode((string) file_get_contents($shotFile)), 'taken_at' => Clock::now()]);
        }
    }
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

/** A stand-in for the model behind «دستیار امنیت» in the preview: a few fixed turns in the assistant's JSON protocol. */
function demo_assistant(array $body): ?array
{
    if (!str_contains((string) ($body['messages'][0]['content'] ?? ''), 'دستیار امنیت')) {
        return null;
    }
    $user = (string) ($body['messages'][1]['content'] ?? '');
    $talk = json_decode((string) (preg_match('~<conversation>\n(.*)\n</conversation>~s', $user, $m) ? $m[1] : '[]'), true) ?: [];
    $last = '';
    foreach ($talk as $t) {
        $last = ($t['role'] ?? '') === 'customer' ? (string) $t['text'] : $last;
    }
    $data = json_decode((string) (preg_match('~<scan_data>\n(.*)\n</scan_data>~s', $user, $m) ? $m[1] : '{}'), true) ?: [];
    $acc = (array) ($data['account'] ?? []);
    $site = null;
    foreach ((array) ($acc['assets'] ?? []) as $a) {
        $site ??= ($a['status'] ?? '') === 'verified' && ($a['kind'] ?? '') === 'domain' ? $a : null;
    }
    $out = fn (string $reply, string $tool = '', array $args = []) => ['ok' => true, 'text' => json_encode(['reply' => $reply, 'tool' => $tool, 'args' => (object) $args], JSON_UNESCAPED_UNICODE)];
    if (!empty($data['tool_results'])) {
        $r = (array) end($data['tool_results']);
        if (isset($r['error'])) {
            return $out('این کار الان شدنی نیست: ' . $r['error']);
        }
        $f = (array) ($r['result'] ?? []);
        if (isset($f['fix'])) {
            return $out('مشکل «' . ($f['title'] ?? '') . '» روی ' . ($f['asset'] ?? '') . " است.\n" . ($f['fix']['why'] ?? '') . "\n\nقدم‌ها:\n- " . implode("\n- ", array_slice((array) ($f['fix']['steps'] ?? []), 0, 3)) . "\n\nوقتی رفع کردید بگویید تا دوباره بسنجم.");
        }
        return $out('اطلاعات را دیدم؛ جزئیات در پیوند زیر است.');
    }
    if (preg_match('~هفته|خودکار|زمان‌بندی~u', $last) && $site) {
        return $out('زمان‌بندی هفتگی «بررسی سلامت پایه» را برای ' . $site['value'] . ' آماده کردم. اگر درست است روی کارت تأیید کنید.', 'create_schedule', ['asset' => $site['id'], 'type' => 'hygiene', 'every' => 'weekly', 'hour' => 3, 'weekday' => 6]);
    }
    if (preg_match('~اسکن~u', $last) && $site) {
        return $out('«بررسی سلامت پایه» را برای ' . $site['value'] . ' آماده کردم. هزینه روی کارت نوشته شده؛ اگر موافقید تأیید کنید.', 'start_scan', ['asset' => $site['id'], 'type' => 'hygiene']);
    }
    if (preg_match('~([a-z0-9-]+(?:\.[a-z0-9-]+)+)~i', $last, $d) && preg_match('~اضافه|افزود|بیفزا~u', $last)) {
        return $out('افزودن ' . $d[1] . ' را آماده کردم. پس از تأیید شما، باید مالکیتش هم تأیید شود.', 'add_target', ['value' => $d[1]]);
    }
    if (preg_match('~اضافه|افزود~u', $last)) {
        return $out('نشانی دامنه یا IP را بنویسید، مثل example.com، تا برای افزودن آماده‌اش کنم.');
    }
    $top = (array) (($acc['most_important_findings'] ?? [])[0] ?? []);
    if (preg_match('~رفع|چطور|مهم‌ترین~u', $last) && $top) {
        return $out('', 'investigate_vulnerability', ['finding' => $top['id']]);
    }
    $o = (array) ($acc['open_findings'] ?? []);
    return $out('امتیاز امنیت حساب شما ' . ($acc['score'] ?? '—') . ' از 100 است (' . ($acc['score_label'] ?? '') . '). ' . (int) ($o['critical'] ?? 0) . ' مورد بحرانی و ' . (int) ($o['high'] ?? 0)
        . ' مورد مهم باز دارید و ' . ($acc['credits'] ?? 0) . " اعتبار.\nاگر بخواهید، مهم‌ترین مورد را توضیح می‌دهم یا یک اسکن تازه آماده می‌کنم.");
}
