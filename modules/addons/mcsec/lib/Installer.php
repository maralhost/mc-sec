<?php

declare(strict_types=1);

namespace McSec;

use WHMCS\Database\Capsule;

/**
 * Tables of MC-Sec (prefix mod_mcsec_). Idempotent and additive only: CREATE TABLE IF NOT EXISTS and new columns;
 * never DROP, TRUNCATE or dropColumn. A fresh install and an upgrade reach the same schema. Every new table or
 * column means raising MCSEC_VERSION (the admin page and cron run install() only when the version changed).
 * Times are Unix epoch integers (Clock). Money and credits are integers.
 */
final class Installer
{
    public static function install(): void
    {
        $s = Capsule::schema();
        $make = function (string $name, callable $def) use ($s): void {
            if (!$s->hasTable($name)) {
                $s->create($name, function ($t) use ($def) {
                    if (method_exists($t, 'charset')) {
                        $t->charset = 'utf8mb4';
                        $t->collation = 'utf8mb4_unicode_ci';
                    }
                    $def($t);
                });
            }
        };

        $make('mod_mcsec_settings', function ($t) {
            $t->string('k', 64)->primary();
            $t->mediumText('v')->nullable();
        });

        // one row per WHMCS client that opened the workspace
        $make('mod_mcsec_accounts', function ($t) {
            $t->integer('client_id')->primary();
            $t->string('verify_token', 40);
            $t->string('oasm_workspace', 64)->default('');
            $t->string('oasm_user', 190)->default('');  // the client's own OASM user (a user owns at most 5 workspaces)
            $t->text('oasm_secret')->nullable();        // its password, encrypted (Crypto)
            $t->text('prefs')->nullable();           // notification preferences (Notify::prefs)
            $t->string('webhook_url', 500)->default('');
            $t->string('webhook_secret', 200)->default('');
            $t->string('tg_chat', 64)->default('');
            $t->string('bale_chat', 64)->default('');
            $t->string('link_code', 16)->default('');
            $t->integer('terms_at')->default(0);
            $t->integer('terms_user')->default(0);
            $t->integer('welcome_at')->default(0);
            $t->integer('digest_at')->default(0);
            $t->integer('low_alert_at')->default(0);
            $t->integer('created_at')->default(0);
            $t->integer('updated_at')->default(0);
        });

        $make('mod_mcsec_assets', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->string('kind', 12);                  // domain | ip | cidr
            $t->string('value', 255);
            $t->string('label', 120)->default('');
            $t->string('tags', 255)->default('');
            $t->integer('parent_id')->default(0);    // verified apex this one inherits from
            $t->string('status', 16)->default('pending'); // pending | verified | lapsed | blocked | removed
            $t->string('method', 16)->default('');   // dns | file | meta | whmcs | parent | ptr | admin
            $t->integer('verified_at')->default(0);
            $t->integer('checked_at')->default(0);
            $t->integer('next_check_at')->default(0);
            $t->integer('fails')->default(0);
            $t->string('check_note', 255)->default('');
            $t->string('oasm_target', 64)->default('');
            $t->integer('score')->default(-1);
            $t->string('counts', 255)->default('');  // open findings per severity (json)
            $t->integer('last_scan_at')->default(0);
            $t->string('autoscan', 32)->default('');  // profile to start once verified ('' = none)
            $t->integer('created_by')->default(0);
            $t->integer('created_at')->default(0);
            $t->integer('removed_at')->default(0);
            $t->index(['client_id', 'value']);
            $t->index(['status', 'next_check_at']);
        });

        $make('mod_mcsec_scans', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->integer('asset_id')->index();
            $t->string('profile', 32);
            $t->string('engine', 16);
            $t->string('status', 16)->default('queued'); // queued | running | completed | failed | cancelled
            $t->integer('credits')->default(0);
            $t->string('backend_ref', 128)->default('');
            $t->text('backend_meta')->nullable();
            $t->integer('progress')->default(0);
            $t->string('stage', 160)->default('');
            $t->integer('schedule_id')->default(0);
            $t->integer('requested_by')->default(0);  // user id (0 = schedule)
            $t->integer('admin_id')->default(0);
            $t->integer('queued_at')->default(0);
            $t->integer('started_at')->default(0);
            $t->integer('finished_at')->default(0);
            $t->integer('synced_at')->default(0);
            $t->integer('tries')->default(0);
            $t->string('error', 255)->default('');
            $t->string('error_ref', 16)->default('');
            $t->text('summary')->nullable();          // counts: new, open, fixed, surface changes (json)
            $t->integer('report_id')->default(0);
            $t->index(['status', 'engine']);
        });

        $make('mod_mcsec_findings', function ($t) {
            $t->increments('id');
            $t->integer('client_id');
            $t->integer('asset_id')->index();
            $t->string('fp', 40);                     // fingerprint (Findings::fingerprint)
            $t->string('engine', 16);
            $t->string('profile', 32)->default('');  // the scan profile that last reported it (decides auto-fix)
            $t->string('source_key', 160)->default(''); // template / check id
            $t->string('kb', 64)->default('');
            $t->string('title', 255);
            $t->string('severity', 10);               // critical | high | medium | low | info
            $t->decimal('cvss', 4, 1)->nullable();
            $t->decimal('epss', 6, 5)->nullable();
            $t->string('cve', 255)->default('');
            $t->string('cwe', 255)->default('');
            $t->string('location', 500)->default('');
            $t->text('description')->nullable();
            $t->text('evidence')->nullable();
            $t->text('solution')->nullable();
            $t->text('refs')->nullable();
            $t->string('tags', 255)->default('');
            $t->string('status', 16)->default('open'); // open | fixed | accepted | false_positive
            $t->string('status_note', 500)->default('');
            $t->integer('status_by')->default(0);
            $t->integer('status_at')->default(0);
            $t->integer('first_scan_id')->default(0);
            $t->integer('last_scan_id')->default(0);
            $t->integer('fixed_scan_id')->default(0);
            $t->integer('first_seen_at')->default(0);
            $t->integer('last_seen_at')->default(0);
            $t->integer('fixed_at')->default(0);
            $t->integer('reopened')->default(0);
            $t->unique(['client_id', 'fp']);
            $t->index(['client_id', 'status', 'severity']);
        });

        // discovered attack surface: hosts, ports, services, technologies, certificates, urls
        $make('mod_mcsec_surface', function ($t) {
            $t->increments('id');
            $t->integer('client_id');
            $t->integer('asset_id');
            $t->string('kind', 12);                   // host | port | tech | cert | url | dns
            $t->string('value', 255);
            $t->text('meta')->nullable();
            $t->integer('first_scan_id')->default(0);
            $t->integer('first_seen_at')->default(0);
            $t->integer('last_seen_at')->default(0);
            $t->integer('gone_at')->default(0);
            $t->unique(['asset_id', 'kind', 'value']);
            $t->index(['client_id', 'kind']);
        });

        // credits: two buckets per account (monthly free/plan credits that reset; paid credits that never expire)
        $make('mod_mcsec_wallets', function ($t) {
            $t->integer('client_id')->primary();
            $t->integer('monthly')->default(0);
            $t->string('period', 8)->default('');     // Jalali YYYY-MM the monthly bucket belongs to
            $t->integer('paid')->default(0);
            $t->integer('updated_at')->default(0);
        });
        $make('mod_mcsec_ledger', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->integer('delta');
            $t->string('bucket', 8);                  // monthly | paid
            $t->string('kind', 16);                   // welcome | group | plan | topup | grant | spend | refund | expire | adjust
            $t->string('ref', 96)->unique();          // idempotency key: one movement per ref, ever
            $t->string('note', 255)->default('');
            $t->integer('scan_id')->default(0);
            $t->integer('admin_id')->default(0);
            $t->integer('balance_after')->default(0);
            $t->integer('created_at')->default(0);
        });
        $make('mod_mcsec_topups', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->string('pack', 32);
            $t->integer('credits');
            $t->decimal('amount', 16, 2);
            $t->integer('invoice_id')->default(0)->index();
            $t->string('status', 12)->default('pending'); // pending | paid | cancelled
            $t->integer('user_id')->default(0);
            $t->integer('created_at')->default(0);
            $t->integer('paid_at')->default(0);
        });
        // plans: one row per WHMCS service of a product on the mcsec provisioning module
        $make('mod_mcsec_plans', function ($t) {
            $t->integer('service_id')->primary();
            $t->integer('client_id')->index();
            $t->integer('product_id')->default(0);
            $t->string('name', 120)->default('');
            $t->string('status', 12)->default('active'); // active | suspended | terminated
            $t->integer('monthly_credits')->default(0);
            $t->integer('max_assets')->default(0);
            $t->string('profiles', 255)->default(''); // csv of allowed profiles ('' = all)
            $t->integer('min_interval_h')->default(24);
            $t->integer('ai_reports')->default(1);
            $t->string('granted_period', 8)->default('');
            $t->integer('updated_at')->default(0);
        });

        $make('mod_mcsec_schedules', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->integer('asset_id')->default(0);     // 0 = every verified asset of the account
            $t->string('profile', 32);
            $t->string('freq', 12);                   // daily | weekly | monthly
            $t->integer('dow')->default(6);
            $t->integer('dom')->default(1);
            $t->integer('hour')->default(3);
            $t->string('status', 12)->default('active'); // active | paused
            $t->string('pause_reason', 255)->default('');
            $t->integer('next_run_at')->default(0)->index();
            $t->integer('last_run_at')->default(0);
            $t->integer('runs')->default(0);
            $t->integer('created_by')->default(0);
            $t->integer('created_at')->default(0);
        });

        $make('mod_mcsec_reports', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->string('kind', 12);                   // scan | asset | periodic | account
            $t->integer('scan_id')->default(0);
            $t->integer('asset_id')->default(0);
            $t->string('title', 255)->default('');
            $t->string('status', 12)->default('queued'); // queued | ready | failed
            $t->integer('ai')->default(0);
            $t->integer('credits')->default(0);
            $t->mediumText('data')->nullable();       // structured report (Reports::build + AI sections)
            $t->string('error', 255)->default('');
            $t->integer('period_from')->default(0);
            $t->integer('period_to')->default(0);
            $t->integer('requested_by')->default(0);
            $t->integer('created_at')->default(0);
            $t->integer('ready_at')->default(0);
        });

        // in-panel notices and the delivery queue of other channels
        $make('mod_mcsec_notices', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->string('event', 32);
            $t->string('title', 255);
            $t->text('body')->nullable();
            $t->string('link', 255)->default('');
            $t->string('tone', 8)->default('info');
            $t->string('ref', 96)->unique();
            $t->integer('read_at')->default(0);
            $t->integer('created_at')->default(0);
        });
        $make('mod_mcsec_outbox', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->string('channel', 12);               // email | telegram | bale | webhook
            $t->string('event', 32);
            $t->mediumText('payload');
            $t->string('status', 12)->default('pending'); // pending | sent | failed
            $t->integer('tries')->default(0);
            $t->integer('next_try_at')->default(0);
            $t->integer('sent_at')->default(0);
            $t->string('error', 255)->default('');
            $t->string('ref', 120)->unique();
            $t->integer('created_at')->default(0);
            $t->index(['status', 'next_try_at']);
        });

        $make('mod_mcsec_ai_cache', function ($t) {
            $t->string('k', 64)->primary();
            $t->mediumText('content');
            $t->string('model', 80)->default('');
            $t->integer('hits')->default(0);
            $t->integer('created_at')->default(0);
        });
        $make('mod_mcsec_snapshots', function ($t) {
            $t->increments('id');
            $t->integer('client_id');
            $t->string('day', 10);
            $t->integer('score')->default(0);
            $t->string('counts', 255)->default('');
            $t->unique(['client_id', 'day']);
        });

        $make('mod_mcsec_audit', function ($t) {
            $t->increments('id');
            $t->integer('client_id')->index();
            $t->integer('user_id')->default(0);
            $t->integer('admin_id')->default(0);
            $t->string('action', 48);
            $t->string('target', 160)->default('');
            $t->text('detail')->nullable();
            $t->string('ip', 45)->default('');
            $t->integer('created_at')->default(0);
        });
        $make('mod_mcsec_log', function ($t) {
            $t->increments('id');
            $t->string('ref', 12)->index();
            $t->string('level', 8);
            $t->string('area', 16);
            $t->string('action', 64);
            $t->integer('client_id')->default(0);
            $t->integer('user_id')->default(0);
            $t->integer('admin_id')->default(0);
            $t->string('message', 255);
            $t->text('detail')->nullable();
            $t->string('ip', 45)->default('');
            $t->integer('created_at')->default(0)->index();
        });
        $make('mod_mcsec_nonces', function ($t) {
            $t->string('nonce', 32)->primary();
            $t->integer('user_id');
            $t->integer('client_id');
            $t->string('purpose', 32);
            $t->integer('used_at')->default(0);
            $t->integer('expires_at')->index();
        });
        $make('mod_mcsec_hits', function ($t) {
            $t->string('k', 96)->primary();
            $t->integer('window_start');
            $t->integer('n')->default(0);
        });
        $make('mod_mcsec_locks', function ($t) {
            $t->string('name', 64)->primary();
            $t->string('owner', 64);
            $t->integer('locked_until');
        });
        $make('mod_mcsec_kv', function ($t) {       // engine sessions, circuit breakers, health
            $t->string('k', 96)->primary();
            $t->mediumText('v')->nullable();
            $t->integer('expires_at')->default(0);
        });

        // seed: nothing customer-facing (feature off until the admin turns it on)
        if (!Db::table('mod_mcsec_settings')->where('k', 'installed_at')->exists()) {
            Db::table('mod_mcsec_settings')->insert(['k' => 'installed_at', 'v' => (string) Clock::now()]);
        }
    }
}
