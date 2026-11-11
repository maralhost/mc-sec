<?php
// MC-Sec test harness: the real Illuminate query builder on SQLite + a fake WHMCS (tables, localAPI, hooks), the
// same pattern as MC-Team and MC-AI. Network is never touched: Http::$mock, Net::$resolver and the built-in engine's
// probes are replaced. Any write to a tbl* table outside the fake localAPI fails the suite.
declare(strict_types=1);

define('WHMCS', true);
define('MCSEC_TESTING', true);
date_default_timezone_set('Asia/Tehran');
error_reporting(E_ALL);
set_error_handler(function ($no, $str, $file, $line) {
    if (!(error_reporting() & $no)) {
        return false;
    }
    echo "  PHP Warning: {$str} at " . basename($file) . ":{$line}\n";
    $GLOBALS['__fails'] = ($GLOBALS['__fails'] ?? 0) + 1;
    return true;
});
$LF = __DIR__ . '/lib/illuminate/';
$ROOT = dirname(__DIR__);

eval('namespace Psr\Container; interface ContainerInterface { public function get(string $id); public function has(string $id): bool; } interface ContainerExceptionInterface {} interface NotFoundExceptionInterface extends ContainerExceptionInterface {}');
spl_autoload_register(function ($class) use ($LF) {
    if (str_starts_with($class, 'Illuminate\\')) {
        $parts = explode('\\', substr($class, strlen('Illuminate\\')));
        $top = array_shift($parts);
        $candidates = [$LF . $top . '/' . implode('/', $parts) . '.php'];
        if ($top === 'Support') {
            foreach (['Collections', 'Conditionable', 'Macroable'] as $d) {
                $candidates[] = $LF . $d . '/' . implode('/', $parts) . '.php';
            }
        }
        foreach ($candidates as $f) {
            if (is_file($f)) {
                require_once $f;
                return;
            }
        }
    }
});
require_once $LF . 'Collections/helpers.php';
require_once $LF . 'Support/helpers.php';
eval('namespace WHMCS\Database; class Capsule extends \Illuminate\Database\Capsule\Manager {}');

$capsule = new \WHMCS\Database\Capsule();
$capsule->addConnection(['driver' => 'sqlite', 'database' => getenv('SQLITE_FILE') ?: ':memory:', 'prefix' => '']);
$capsule->setAsGlobal();

$GLOBALS['__in_api'] = 0;
$GLOBALS['__tbl_violations'] = [];
\WHMCS\Database\Capsule::connection()->listen(function ($q) {
    if ($GLOBALS['__in_api'] > 0) {
        return;
    }
    if (preg_match('~^\s*(insert|update|delete|replace)\b[^;]*?\b(into|from)?\s*["`]?(tbl\w+)~i', $q->sql) || preg_match('~^\s*update\s+["`]?(tbl\w+)~i', $q->sql)) {
        $GLOBALS['__tbl_violations'][] = $q->sql;
    }
});
function as_whmcs(callable $fn)
{
    $GLOBALS['__in_api']++;
    try {
        return $fn();
    } finally {
        $GLOBALS['__in_api']--;
    }
}

as_whmcs(function () {
    $s = \WHMCS\Database\Capsule::schema();
    if ($s->hasTable('tblconfiguration')) {
        return;
    }
    $s->create('tblconfiguration', function ($t) { $t->string('setting')->primary(); $t->text('value')->nullable(); });
    $s->create('tblcurrencies', function ($t) { $t->increments('id'); $t->string('code'); $t->string('prefix')->default(''); $t->string('suffix')->default(''); $t->integer('format')->default(1); });
    $s->create('tblclientgroups', function ($t) { $t->increments('id'); $t->string('groupname'); });
    $s->create('tblclients', function ($t) {
        $t->increments('id'); $t->string('firstname')->default(''); $t->string('lastname')->default(''); $t->string('companyname')->default(''); $t->string('email')->default('');
        $t->integer('currency')->default(1); $t->integer('groupid')->default(0); $t->string('status')->default('Active');
    });
    $s->create('tblusers', function ($t) { $t->increments('id'); $t->string('first_name')->default(''); $t->string('last_name')->default(''); $t->string('email')->default(''); });
    $s->create('tblusers_clients', function ($t) { $t->increments('id'); $t->integer('auth_user_id'); $t->integer('client_id'); $t->integer('owner')->default(0); $t->text('permissions')->nullable(); });
    $s->create('tbladmins', function ($t) { $t->increments('id'); $t->integer('roleid')->default(1); $t->string('username')->default(''); });
    $s->create('tblhosting', function ($t) { $t->increments('id'); $t->integer('userid'); $t->integer('packageid')->default(1); $t->string('domain')->default(''); $t->string('domainstatus')->default('Active'); $t->string('dedicatedip')->default(''); $t->text('assignedips')->nullable(); });
    $s->create('tbldomains', function ($t) { $t->increments('id'); $t->integer('userid'); $t->string('domain')->default(''); $t->string('status')->default('Active'); });
    $s->create('tblinvoices', function ($t) { $t->increments('id'); $t->integer('userid'); $t->string('status')->default('Unpaid'); $t->decimal('total', 16, 2)->default(0); });
    $s->create('tblproducts', function ($t) { $t->increments('id'); $t->string('name'); $t->string('servertype')->default(''); });

    $db = '\WHMCS\Database\Capsule';
    $db::table('tblconfiguration')->insert([['setting' => 'SystemURL', 'value' => 'https://my.maralcloud.test/']]);
    $db::table('tblcurrencies')->insert([['id' => 1, 'code' => 'IRR', 'suffix' => ' ریال', 'format' => 4]]);
    $db::table('tblclientgroups')->insert([['id' => 1, 'groupname' => 'VIP'], ['id' => 2, 'groupname' => 'همکاران']]);
    $db::table('tbladmins')->insert([['id' => 1, 'roleid' => 1, 'username' => 'root'], ['id' => 2, 'roleid' => 2, 'username' => 'support']]);
    for ($i = 1; $i <= 10; $i++) {
        $db::table('tblclients')->insert(['id' => $i, 'firstname' => 'Owner' . $i, 'lastname' => 'Test', 'companyname' => $i === 1 ? 'فروشگاه نمونه' : '', 'email' => "c{$i}@example.test", 'groupid' => $i === 3 ? 2 : 0]);
        $db::table('tblusers')->insert(['id' => $i, 'first_name' => 'User' . $i, 'last_name' => 'Test', 'email' => "u{$i}@example.test"]);
        $db::table('tblusers_clients')->insert(['auth_user_id' => $i, 'client_id' => $i, 'owner' => 1, 'permissions' => '']);
    }
    // user 11: a viewer of client 1 (products only); user 12: a manager of client 1
    $db::table('tblusers')->insert([['id' => 11, 'first_name' => 'Viewer', 'last_name' => 'One', 'email' => 'viewer@example.test'], ['id' => 12, 'first_name' => 'Tech', 'last_name' => 'One', 'email' => 'tech@example.test']]);
    $db::table('tblusers_clients')->insert([['auth_user_id' => 11, 'client_id' => 1, 'owner' => 0, 'permissions' => 'products'], ['auth_user_id' => 12, 'client_id' => 1, 'owner' => 0, 'permissions' => 'products,manageproducts']]);
    // Maral services of client 1: a registered domain, a hosting service and a server IP
    $db::table('tbldomains')->insert(['userid' => 1, 'domain' => 'shop-maral.ir', 'status' => 'Active']);
    $db::table('tblhosting')->insert(['userid' => 1, 'domain' => 'blog.example.org', 'domainstatus' => 'Active', 'dedicatedip' => '203.0.113.5', 'assignedips' => "198.51.100.7\n198.51.100.8"]);
    $db::table('tblproducts')->insert(['id' => 1, 'name' => 'MC-Sec Pro', 'servertype' => 'mcsecplan']);
});

$GLOBALS['__localapi'] = [];
$GLOBALS['__emails'] = [];
$GLOBALS['__hooks'] = [];
function add_hook($name, $prio, $fn) { $GLOBALS['__hooks'][$name][] = $fn; }
function run_hook(string $name, array $vars = []) { $out = []; foreach ($GLOBALS['__hooks'][$name] ?? [] as $fn) { $out[] = $fn($vars); } return $out; }
function logActivity($m) { $GLOBALS['__activity'][] = $m; }
function generate_token($t = 'plain') { return 'whmcs-token'; }
function localAPI($cmd, $params = [], $admin = null)
{
    $GLOBALS['__localapi'][] = [$cmd, $params];
    return as_whmcs(function () use ($cmd, $params) {
        $db = '\WHMCS\Database\Capsule';
        if ($fail = ($GLOBALS['__fail_api'][$cmd] ?? null)) {
            return ['result' => 'error', 'message' => $fail];
        }
        switch ($cmd) {
            case 'SendEmail':
                if (empty($params['customtype']) || !$db::table('tblclients')->where('id', $params['id'] ?? 0)->exists()) {
                    return ['result' => 'error', 'message' => 'Client ID Not Found'];
                }
                $GLOBALS['__emails'][] = $params;
                return ['result' => 'success'];
            case 'CreateInvoice':
                if (!$db::table('tblclients')->where('id', $params['userid'] ?? 0)->exists()) {
                    return ['result' => 'error', 'message' => 'Client ID Not Found'];
                }
                $id = $db::table('tblinvoices')->insertGetId(['userid' => (int) $params['userid'], 'status' => 'Unpaid', 'total' => (float) $params['itemamount1']]);
                return ['result' => 'success', 'invoiceid' => $id, 'status' => 'Unpaid'];
        }
        return ['result' => 'error', 'message' => 'fake localAPI: unknown command ' . $cmd];
    });
}
/** WHMCS marks an invoice paid (payment gateway) and runs InvoicePaid. */
function pay_invoice(int $id): void
{
    as_whmcs(fn () => \WHMCS\Database\Capsule::table('tblinvoices')->where('id', $id)->update(['status' => 'Paid']));
    run_hook('InvoicePaid', ['invoiceid' => $id]);
}

require_once $ROOT . '/modules/addons/mcsec/bootstrap.php';
require_once $ROOT . '/modules/addons/mcsec/mcsec.php';
require_once $ROOT . '/modules/addons/mcsec/hooks.php';
require_once $ROOT . '/modules/servers/mcsecplan/mcsecplan.php';
\McSec\Installer::install();
\McSec\Settings::set('schema_version', MCSEC_VERSION);
if (session_status() !== PHP_SESSION_ACTIVE) {
    $_SESSION = [];
}
\McSec\Client\Controller::$testMode = true;

// default: no network at all (a test that needs it sets its own mock)
\McSec\Http::$mock = function ($method, $url) {
    $GLOBALS['__http'][] = $method . ' ' . $url;
    return ['status' => 0, 'error' => 'network disabled in tests'];
};
\McSec\Net::$resolver = function ($name, $type) {
    return $GLOBALS['__dns'][strtolower($name)][$type] ?? [];
};
\McSec\Engines\Builtin::$portProbe = fn ($ip, $ports) => $GLOBALS['__open_ports'][$ip] ?? [];
\McSec\Engines\Builtin::$certProbe = fn ($host) => $GLOBALS['__certs'][$host] ?? null;

function dns_txt(string $name, string $value): void
{
    $GLOBALS['__dns'][strtolower($name)]['TXT'][] = ['txt' => $value, 'entries' => [$value]];
}
function dns_a(string $name, string $ip): void
{
    $GLOBALS['__dns'][strtolower($name)]['A'][] = ['ip' => $ip];
}
function http_mock(callable $fn): void
{
    \McSec\Http::$mock = $fn;
}

/** The session of a person on an account. */
function login(int $userId, int $clientId, bool $masq = false): array
{
    $l = \McSec\Whmcs::link($userId, $clientId);
    $who = ['client_id' => $clientId, 'user_id' => $userId, 'owner' => $l ? $l['owner'] : false, 'perms' => $l ? $l['perms'] : [], 'masq' => $masq];
    \McSec\Auth::$testClient = $who;
    \McSec\Accounts::forget();
    return $who;
}
function admin(string $tier = 'settings'): void
{
    \McSec\Auth::$testAdmin = ['id' => 1, 'tier' => $tier];
}
function setting(string $k, string $v): void
{
    \McSec\Settings::set($k, $v);
}
/** A client-area request through the real controller. */
function client_get(array $get): array
{
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_GET = $get + ['m' => 'mcsec'];
    $_POST = [];
    return \McSec\Client\Controller::handle();
}
function client_post(string $action, array $post, array $get = [], bool $nonce = true): array
{
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = $get + ['m' => 'mcsec'];
    $who = \McSec\Auth::$testClient;
    $_POST = $post + ['a' => $action, 'token' => 'whmcs-token', 'mcs_csrf' => \McSec\Auth::csrf()];
    if ($nonce && !isset($post['mcs_nonce'])) {
        $_POST['mcs_nonce'] = \McSec\Nonce::issue($who['user_id'], $who['client_id'], 'form');
    }
    return \McSec\Client\Controller::handle();
}
function html(array $r): string
{
    return (string) ($r['vars']['mcsec_html'] ?? $r['json']['html'] ?? '');
}
function flash_of(array $r): string
{
    $h = html($r);
    return preg_match('~class="alert[^"]*"[^>]*>.*?<div class="alert-body">(.*?)</div>~s', $h, $m) ? trim(strip_tags($m[1])) : '';
}

$GLOBALS['__fails'] = $GLOBALS['__fails'] ?? 0;
$GLOBALS['__passes'] = 0;
function ok(bool $cond, string $label): void
{
    if ($cond) {
        $GLOBALS['__passes']++;
    } else {
        $GLOBALS['__fails']++;
        echo "  FAIL: {$label}\n";
    }
}
function section(string $name): void
{
    echo "── {$name}\n";
}
function done(): void
{
    if ($GLOBALS['__tbl_violations']) {
        $GLOBALS['__fails']++;
        echo "  FAIL: WHMCS tables written outside localAPI:\n    " . implode("\n    ", array_slice(array_unique($GLOBALS['__tbl_violations']), 0, 10)) . "\n";
    }
    if ($GLOBALS['__fails'] > 0) {
        echo "FAILED {$GLOBALS['__fails']} of " . ($GLOBALS['__fails'] + $GLOBALS['__passes']) . " checks\n";
        exit(1);
    }
    echo "PASSED {$GLOBALS['__passes']} checks\n";
    exit(0);
}
