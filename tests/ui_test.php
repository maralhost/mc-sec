<?php
// 0.26.0: the UI standard. Design tokens instead of colours written in the code, the order and page size of the
// findings list applied by the server to the whole set, and a CSV file that follows the same filters as the page.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use McSec\Accounts;
use McSec\Clock;
use McSec\Db;
use McSec\Findings;

Clock::$fixed = strtotime('2026-11-25T10:00:00Z');
foreach (['enabled' => '1', 'access_mode' => 'all', 'export_csv' => '1', 'welcome_credits' => '0'] as $k => $v) {
    setting($k, $v);
}
login(1, 1);
Accounts::ensure(1);
Accounts::ensure(2);
$asset = fn (int $cid, string $v) => Db::table('mod_mcsec_assets')->insertGetId(['client_id' => $cid, 'kind' => 'domain', 'value' => $v, 'status' => 'verified', 'method' => 'dns', 'verified_at' => Clock::now(), 'created_at' => Clock::now()]);
$a = $asset(1, 'one.example');
$b = $asset(2, 'other.example');
$rows = [];
for ($i = 1; $i <= 60; $i++) {
    $rows[] = ['client_id' => 1, 'asset_id' => $a, 'fp' => 'fp' . $i, 'engine' => 'builtin', 'profile' => 'hygiene', 'source_key' => 'k' . $i, 'kb' => $i <= 10 ? 'hdr-hsts' : 'xss', 'title' => sprintf('F%03d', $i),
        'severity' => $i === 60 ? 'critical' : 'low', 'priority' => $i === 60 ? 90 : 10, 'location' => 'https://one.example/' . $i, 'status' => 'open',
        'first_seen_at' => Clock::now() - $i * 3600, 'last_seen_at' => Clock::now() - (61 - $i) * 60];
}
$rows[] = ['client_id' => 2, 'asset_id' => $b, 'fp' => 'x', 'engine' => 'builtin', 'profile' => 'hygiene', 'source_key' => 'x', 'kb' => 'hdr-hsts', 'title' => 'Secret of two', 'severity' => 'critical', 'priority' => 99,
    'location' => 'https://other.example/', 'status' => 'open', 'first_seen_at' => Clock::now(), 'last_seen_at' => Clock::now()];
foreach (array_chunk($rows, 20) as $chunk) {
    Db::table('mod_mcsec_findings')->insert($chunk);
}
$titles = fn (array $f) => array_map(fn ($r) => $r->title, Findings::search(1, $f)['rows']);

section('the order is the server\'s, over the whole set');
ok($titles([])[0] === 'F060' && count($titles([])) === 25, 'by default the most important first, 25 on a page');
ok($titles(['sort' => 'newest'])[0] === 'F001' && $titles(['sort' => 'newest', 'page' => 3])[0] === 'F051', 'newest first: page three continues where page two ended');
ok($titles(['sort' => 'oldest'])[0] === 'F060' && $titles(['sort' => 'oldest'])[1] === 'F059', 'oldest first');
ok($titles(['sort' => 'seen'])[0] === 'F060' && $titles(['sort' => 'seen'])[1] === 'F059', 'last seen');
ok($titles(['sort' => 'title; DROP TABLE x'])[0] === 'F060' && $titles(['sort' => ['a']])[0] === 'F060', 'an order that is not in the list is the default one');

section('the page size');
ok(count($titles(['per' => 50])) === 50 && count($titles(['per' => 100])) === 60 && count($titles(['per' => 5000])) === 25 && count($titles(['per' => -1])) === 25, 'only the listed sizes; anything else is 25');
$r = Findings::search(1, ['per' => 50, 'page' => 9]);
ok($r['pages'] === 2 && $r['page'] === 2 && count($r['rows']) === 10, 'a page past the end is the last one');
ok(!in_array('Secret of two', $titles(['per' => 100, 'sort' => 'newest']), true), 'never another account\'s finding, whatever the order and size');

section('the page');
$h = html(client_get(['p' => 'findings', 'sort' => 'newest', 'per' => '50']));
ok(str_contains($h, 'name="sort"') && str_contains($h, '<option value="newest" selected') && str_contains($h, '<option value="50" selected'), 'the filter form offers the order and the size, and remembers them');
ok(str_contains($h, 'sort=newest') && str_contains($h, 'per=50') && str_contains($h, '۱ تا ۵۰ از ۶۰ یافته'), 'the pager keeps them, and the line under the table says what is shown out of how many');
ok(substr_count($h, 'mcs-finding-link') === 50 && strpos($h, 'F001') < strpos($h, 'F002'), 'fifty rows, in the chosen order');
$h = html(client_get(['p' => 'findings', 'sort' => '"><script>alert(9)</script>', 'per' => '<script>alert(9)</script>']));
ok(!str_contains($h, '<script>alert(9)') && substr_count($h, 'mcs-finding-link') === 25, 'a made-up order or size changes nothing and is not echoed');
$h = html(client_get(['p' => 'findings', 'status' => ['x'], 'severity' => ['y'], 'q' => ['z'], 'kb' => ['k'], 'sort' => ['s'], 'per' => ['p'], 'page' => ['1']]));
ok(substr_count($h, 'mcs-finding-link') === 25 && !str_contains($h, 'Warning'), 'parameters sent as lists are ignored, without a warning');
$h = html(client_get(['p' => 'findings', 'kb' => 'hdr-hsts', 'sort' => 'oldest']));
ok(str_contains($h, 'name="kb" value="hdr-hsts"') && substr_count($h, 'mcs-finding-link') === 10, 'changing the order keeps the «راه رفع» filter');

section('the CSV file follows the page');
$csv = fn (array $get) => (string) (client_get($get + ['p' => 'findings', 'csv' => '1'])['raw']['bytes'] ?? '');
$all = $csv([]);
ok(substr_count($all, "\r\n") === 61 && !str_contains($all, 'Secret of two'), 'every matching finding of this account, not only the page');
$one = $csv(['kb' => 'hdr-hsts']);
ok(substr_count($one, "\r\n") === 11 && str_contains($one, 'F010') && !str_contains($one, 'F011'), 'with «راه رفع» chosen, the file holds exactly those findings');
$new = $csv(['sort' => 'newest']);
ok(strpos($new, 'F001') < strpos($new, 'F002') && strpos($new, 'F002') < strpos($new, 'F060'), 'and it is in the order of the page');
Db::table('mod_mcsec_findings')->where('title', 'F001')->update(['title' => '=HYPERLINK("http://x","y")']);
ok(str_contains($csv(['sort' => 'newest']), '"\'=HYPERLINK'), 'a cell that a spreadsheet would run stays text');
setting('export_csv', '0');
ok(!isset(client_get(['p' => 'findings', 'csv' => '1'])['raw']), 'with the export switched off there is no file');

section('design tokens instead of colours in the code');
$lib = dirname(__DIR__) . '/modules/addons/mcsec/lib/';
$css = (string) file_get_contents($lib . 'Client/client.css');
foreach (['--mds-background', '--mds-foreground', '--mds-surface', '--mds-primary', '--mds-secondary', '--mds-muted', '--mds-accent', '--mds-border', '--mds-ring', '--mds-success', '--mds-warning', '--mds-destructive', '--mds-info',
    '--mds-radius', '--mds-shadow', '--mds-font', '--mds-space-4', '--mds-chart-1', '--mds-sev-critical', '--mds-sev-info', '--mds-risk-strong', '--mds-scan-running', '--mds-asset-verified'] as $t) {
    $missing[] = str_contains($css, $t . ':') ? null : $t;
}
ok(!array_filter($missing), 'the customer panel defines the shared semantic tokens (' . implode(' ', array_filter($missing)) . ')');
$admin = (string) file_get_contents($lib . 'Admin/Views.php');
$adminCss = substr($admin, (int) strpos($admin, 'private static function css()'));
$tokensEnd = (int) strpos($adminCss, "--r:var(--mds-destructive);'");
ok($tokensEnd > 0 && !preg_match('~#[0-9a-fA-F]{3,8}\b~', substr($adminCss, $tokensEnd)), 'the admin panel\'s rules use tokens: no colour is written after the token block');
ok(str_contains($adminCss, '--mds-primary:') && str_contains($adminCss, '--mds-surface:') && str_contains($adminCss, '--ink:var(--mds-foreground)'), 'the same token names, the admin panel\'s own values, the old short names kept as aliases');
foreach (glob($lib . 'Client/*.php') ?: [] as $file) {
    if (basename($file) === 'Ui.php') {
        continue; // the icon paths
    }
    if (preg_match_all('~[\'"](#[0-9a-fA-F]{6})[\'"]~', (string) file_get_contents($file), $m)) {
        $raw[] = basename($file) . ': ' . implode(' ', $m[1]);
    }
}
ok(empty($raw), 'no colour is written in the customer pages\' PHP (' . implode(' | ', $raw ?? []) . ')');
$svg = \McSec\Client\Charts::lines(['2026-11-24', '2026-11-25'], [['میزبان', [1, 2], 2], ['فناوری', [2, 3], 99], ['نشانی', [1, 1], '#ff0000"><script>alert(9)</script>']]);
ok(str_contains($svg, 'class="mcs-s2"') && str_contains($svg, 'class="mcs-s6"') && str_contains($svg, 'class="mcs-s1"') && !str_contains($svg, 'stroke="#') && !str_contains($svg, '<script'), 'a chart series is a token number; a colour or markup passed in is never printed');
ok(!preg_match('~^\.(?!mcs)[a-z]|^(html|body|\*)[ ,{]~m', preg_replace('~html\.lagom-dark-mode \.mcs|body:not\(\.lagom\) \.mcs~', '.mcs', $css)) && !preg_match('~\}\s*(?!\.mcsa|@media|\'|\s)[a-z*]~', $adminCss), 'every rule stays under .mcs or .mcsa: nothing global');
done();
