<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Access;
use McSec\Accounts;
use McSec\Assets;
use McSec\Audit;
use McSec\Auth;
use McSec\Clock;
use McSec\Credits;
use McSec\Crypto;
use McSec\Findings;
use McSec\Lang;
use McSec\Net;
use McSec\Nonce;
use McSec\Notify;
use McSec\RateLimit;
use McSec\Reports;
use McSec\Scans;
use McSec\Schedules;
use McSec\Settings;
use McSec\Text;
use McSec\Trace;
use McSec\Verify;

/**
 * Client area router: index.php?m=mcsec&p=<page>, POST a=<action>.
 * Every page works without JavaScript; with it, links and forms swap the view in place (pjax=1 answers JSON
 * {html, title} or {redirect}); a running scan's page asks progress=1 for {status, progress, stage}.
 * Identity only from the session (Auth::client); every id from the browser is checked against the session's client
 * (Assets::get, Scans::get, Findings::get …: IDOR). Every POST needs the WHMCS token, the module's session CSRF token
 * and, for actions that create something or cost credits, a one-time nonce. GET never changes anything.
 */
final class Controller
{
    /** Tests: return arrays instead of printing JSON and exiting. */
    public static bool $testMode = false;

    public const PAGES = ['home', 'assets', 'asset', 'scans', 'scan', 'findings', 'finding', 'reports', 'report', 'schedules', 'recipes', 'assistant', 'support', 'notify', 'credits', 'activity'];

    /** Actions that create something or cost credits also need the page's one-time nonce. */
    private const NEEDS_NONCE = ['add_asset', 'scan_start', 'report_create', 'schedule_save', 'buy_pack', 'finding_aifix', 'webhook_test', 'finding_retest', 'asset_origin', 'code_redeem', 'recipe_save', 'chat_send', 'chat_confirm', 'finding_opinion', 'verify_auto', 'support_send', 'request_accept'];
    /** Actions a viewer (WHMCS permission 'products' only) may do. */
    private const VIEWER_ACTIONS = ['notice_read', 'view_mode'];
    /** Money actions: the owner or a user with the WHMCS permission 'invoices' (checked in each case). */
    private const BUYER_ACTIONS = ['buy_pack', 'code_redeem', 'auto_save', 'request_accept', 'request_decline'];

    public static function handle(): array
    {
        $pjax = ($_GET['pjax'] ?? $_POST['pjax'] ?? '') === '1';
        if (($_GET['p'] ?? '') === 'scanner' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
            // public page for site owners who saw the scanner in their logs: no login, nothing changes
            $label = Lang::t('درباره‌ی اسکنر امنیتی');
            return ['pagetitle' => $label, 'breadcrumb' => ['index.php?m=mcsec&p=scanner' => $label], 'templatefile' => 'templates/page', 'requirelogin' => false, 'forcessl' => true,
                'vars' => ['mcsec_html' => Views::scanner()]];
        }
        $who = Auth::client();
        if ($who === null) {
            return $pjax ? self::json(['ok' => true, 'redirect' => 'clientarea.php']) : self::page('home', '');
        }
        Trace::$ctx = ['client_id' => $who['client_id'], 'user_id' => $who['user_id']];
        if (!Auth::canView($who) || !Access::clientAllowed($who['client_id'], $who['masq'])) {
            return self::out('home', Views::closed($who), $pjax);
        }
        if (($_GET['p'] ?? '') === 'shot' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
            return self::shot($who['client_id'], (int) Text::toAscii((string) ($_GET['id'] ?? '0')));
        }
        if (($_GET['p'] ?? '') === 'report' && ($_GET['pdf'] ?? '') === '1' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
            return self::reportPdf($who['client_id'], (int) Text::toAscii((string) ($_GET['id'] ?? '0')));
        }
        if (($_GET['p'] ?? '') === 'findings' && ($_GET['csv'] ?? '') === '1' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && Settings::bool('export_csv')) {
            // the same list the page shows, as a file; reading only
            $f = ['status' => (string) ($_GET['status'] ?? 'open'), 'severity' => (string) ($_GET['severity'] ?? ''), 'asset' => (int) Text::toAscii((string) ($_GET['asset'] ?? '0')),
                'scan' => (int) Text::toAscii((string) ($_GET['scan'] ?? '0')), 'new' => (int) Text::toAscii((string) ($_GET['new'] ?? '0')), 'q' => mb_substr(trim((string) ($_GET['q'] ?? '')), 0, 80)];
            return self::file(['mime' => 'text/csv; charset=utf-8', 'bytes' => Findings::csv($who['client_id'], $f), 'name' => 'mcsec-findings-' . date('Ymd', Clock::now()) . '.csv']);
        }
        Accounts::ensure($who['client_id']);
        if (($_GET['p'] ?? '') === 'asset' && ($_GET['vfile'] ?? '') === '1' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
            // the proof file, ready to upload as it is: made here from the account's own code, for one of its own assets
            $a = Assets::get($who['client_id'], (int) Text::toAscii((string) ($_GET['id'] ?? '0')));
            return self::file($a && $a->kind !== 'cidr' ? ['mime' => 'text/plain; charset=utf-8', 'bytes' => Accounts::proof(Accounts::get($who['client_id'])) . "\n", 'name' => 'mcsec-verify.txt'] : null);
        }
        $ctx = ['who' => $who, 'manage' => Auth::canManage($who) && Auth::mayAct($who), 'buy' => Auth::canBuy($who) && Auth::mayAct($who)];
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && ($_GET['progress'] ?? '') === '1') {
            return self::json(self::progress($ctx, (int) Text::toAscii((string) ($_GET['id'] ?? '0'))));
        }
        $flash = '';
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $r = self::post($ctx, (string) ($_POST['a'] ?? ''));
            if (array_key_exists('file', $r)) {
                return self::file($r['file']);
            }
            if ($pjax && ($_POST['quiet'] ?? '') === '1' && !isset($r['redirect'])) {
                [$kind, $msg] = array_pad(explode(':', (string) ($r['flash'] ?? ''), 2), 2, '');
                // this text goes to the page as it is (no e() on the way), so each line gets its English here
                return self::json(['ok' => $kind === 'ok', 'flash' => implode("\n", array_map([Lang::class, 'whole'], explode("\n", $msg))), 'unread' => Notify::unread($who['client_id'])]);
            }
            if (isset($r['redirect'])) {
                if ($pjax) {
                    return self::json(['ok' => true, 'redirect' => $r['redirect']]);
                }
                if (self::$testMode) {
                    return ['redirect' => $r['redirect']];
                }
                header('Location: ' . $r['redirect']);
                exit;
            }
            $flash = $r['flash'] ?? '';
        }
        $p = (string) ($_GET['p'] ?? $_POST['p'] ?? 'home');
        if (!in_array($p, self::PAGES, true)) {
            $p = 'home';
        }
        return self::out($p, Views::render($p, $ctx, $flash), $pjax);
    }

    private static function out(string $p, string $html, bool $pjax): array
    {
        if (!$pjax) {
            return self::page($p, $html);
        }
        return self::json(['ok' => true, 'page' => $p, 'title' => Views::title($p), 'html' => Views::$view]);
    }

    private static function page(string $p, string $html): array
    {
        $label = Settings::menuLabel();
        return ['pagetitle' => $label, 'breadcrumb' => ['index.php?m=mcsec' => $label], 'templatefile' => 'templates/page', 'requirelogin' => true, 'forcessl' => true,
            'vars' => ['mcsec_html' => $html]];
    }

    /** The stored screenshot of one of this account's assets, as an image. */
    private static function shot(int $clientId, int $assetId): array
    {
        return self::file(\McSec\Shots::get($clientId, $assetId), 86400);
    }

    /**
     * Sends bytes instead of a page (a picture or a PDF): the only way out that is not HTML. The type is one this
     * module decided from the bytes or made itself, never one a scanned site supplied; nosniff; private cache.
     * @param array{mime:string,bytes:string,name?:string}|null $file null = not found
     */
    private static function file(?array $file, int $cache = 0): array
    {
        if (self::$testMode) {
            return ['raw' => $file];
        }
        if ($file === null) {
            http_response_code(404);
            exit;
        }
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: ' . $file['mime']);
        header('Content-Length: ' . strlen($file['bytes']));
        header('X-Content-Type-Options: nosniff');
        header('Content-Security-Policy: default-src \'none\'');
        header('Cache-Control: private, ' . ($cache > 0 ? 'max-age=' . $cache : 'no-store'));
        if (!empty($file['name'])) {
            header('Content-Disposition: attachment; filename="' . preg_replace('~[^A-Za-z0-9._-]~', '', (string) $file['name']) . '"');
        }
        echo $file['bytes'];
        exit;
    }

    /** A ready report of this account as a PDF made here (Pdf); null when it is not this account's or no PDF can be made. */
    private static function reportPdf(int $clientId, int $id): array
    {
        $r = \McSec\Reports::get($clientId, $id);
        $bytes = $r && $r->status === 'ready' ? \McSec\Pdf::render(\McSec\Reports::data($r)) : '';
        return self::file($bytes !== '' ? ['mime' => 'application/pdf', 'bytes' => $bytes, 'name' => 'mcsec-report-' . $id . '.pdf'] : null);
    }

    private static function json(array $out): array
    {
        if (self::$testMode) {
            return ['json' => $out];
        }
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode($out, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP);
        exit;
    }

    /** {status, progress, stage, done} of one scan of this client; may poll the engine (live sync, circuit-guarded). */
    private static function progress(array $ctx, int $id): array
    {
        $s = Scans::get($ctx['who']['client_id'], $id);
        if (!$s) {
            return ['ok' => false];
        }
        if (session_status() === PHP_SESSION_ACTIVE && !self::$testMode) {
            session_write_close();
        }
        if ($s->status === 'running' && Settings::bool('live_sync') && (int) $s->synced_at < Clock::now() - 20 && $s->engine !== 'builtin'
            && RateLimit::hit('live:' . $ctx['who']['client_id'], 30, 300)) {
            $s = \McSec\Lock::with('mcsec_scan_' . $s->id, fn () => Scans::syncOne((int) $s->id, true), 120) ?? $s;
        }
        return ['ok' => true, 'status' => (string) $s->status, 'progress' => (int) $s->progress, 'stage' => Lang::whole((string) $s->stage), 'step' => ScanViews::path($s, \McSec\Catalog::find((string) $s->profile) ?? [])[1],
            'done' => !in_array($s->status, ['queued', 'running'], true), 'label' => Lang::whole((string) (Scans::STATUS[$s->status] ?? $s->status))];
    }

    /** @return array{flash?:string,redirect?:string} */
    private static function post(array $ctx, string $a): array
    {
        $who = $ctx['who'];
        if (!Auth::checkWhmcsToken((string) ($_POST['token'] ?? '')) || !Auth::checkCsrf((string) ($_POST['mcs_csrf'] ?? ''))) {
            return ['flash' => 'err:' . Lang::t('این فرم منقضی شده است. صفحه را تازه کنید و دوباره بفرستید.')];
        }
        if (in_array($a, self::NEEDS_NONCE, true) && !Nonce::consume((string) ($_POST['mcs_nonce'] ?? ''), $who['user_id'], $who['client_id'], 'form')) {
            return ['flash' => 'err:' . Lang::t('این فرم یک بار فرستاده شده است. اگر نتیجه را نمی‌بینید، صفحه را تازه کنید.')];
        }
        if (!Auth::mayAct($who)) {
            return ['flash' => 'err:' . Lang::t('شما با «ورود به‌جای مشتری» آمده‌اید و در این حالت فقط دیدن ممکن است.')];
        }
        if (!in_array($a, self::VIEWER_ACTIONS, true) && !in_array($a, self::BUYER_ACTIONS, true) && !$ctx['manage']) {
            return ['flash' => 'err:' . Lang::t('کاربر شما فقط اجازه‌ی دیدن دارد. برای این کار، مالک حساب باید مجوز «مدیریت سرویس‌ها» را به شما بدهد.')];
        }
        $in = fn (string $k): string => html_entity_decode(trim((string) ($_POST[$k] ?? '')), ENT_QUOTES, 'UTF-8');
        $int = fn (string $k): int => (int) Text::toAscii((string) ($_POST[$k] ?? '0'));
        $cid = $who['client_id'];
        switch ($a) {
            case 'add_asset':
                $text = $in('targets');
                $autoscan = $in('autoscan');
                $lines = array_values(array_filter(preg_split('~[\s,;،]+~u', Text::toAscii($text)) ?: [], 'strlen')); // i18n-skip (a pattern, not a text)
                if (!$lines) {
                    return ['flash' => 'err:' . Lang::t('دامنه یا IP را بنویسید، مثل example.com')];
                }
                if (!RateLimit::hit('add:' . $cid, 300, 86400)) {
                    return ['flash' => 'err:' . Lang::t('امروز دارایی زیادی افزوده‌اید. فردا ادامه دهید.')];
                }
                if (count($lines) === 1) {
                    $r = Assets::add($who, $lines[0], $in('label'), $autoscan);
                    if (!$r['ok']) {
                        return ['flash' => 'err:' . $r['error']];
                    }
                    return ['redirect' => 'index.php?m=mcsec&p=asset&id=' . $r['id'] . ($r['verified'] ? '&new=verified' : '&new=1')];
                }
                $r = Assets::bulk($who, $text, $autoscan);
                $msg = [];
                if ($r['added']) {
                    $msg[] = $r['verified'] ? Lang::t('{n} دارایی افزوده شد؛ {verified} مورد خودکار تأیید شد.', ['n' => Text::fa(count($r['added'])), 'verified' => Text::fa($r['verified'])])
                        : Lang::t('{n} دارایی افزوده شد.', ['n' => Text::fa(count($r['added']))]);
                }
                $msg = array_merge($msg, $r['failed']);
                return ['flash' => ($r['added'] ? 'ok:' : 'err:') . implode("\n", $msg)];
            case 'verify_check':
                $asset = Assets::get($cid, $int('asset'));
                if (!$asset) {
                    return ['flash' => 'err:' . Lang::t('این دارایی پیدا نشد.')];
                }
                if ($asset->status === 'verified') {
                    return ['flash' => 'ok:' . Lang::t('این دارایی تأییدشده است.')];
                }
                if (!RateLimit::hit('verify:' . $cid, 20, 600)) {
                    return ['flash' => 'err:' . Lang::t('چند دقیقه صبر کنید و دوباره بررسی کنید. ما هم خودکار هر چند دقیقه بررسی می‌کنیم و خبرتان می‌کنیم.')];
                }
                $r = Verify::check($asset);
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('مالکیت {asset} تأیید شد ({method}). حالا می‌توانید اسکن بگیرید.', ['asset' => $asset->value, 'method' => Lang::whole((string) (Verify::METHODS[$r['method']] ?? $r['method']))])
                    : 'err:' . Lang::t('هنوز تأیید نشد. {note}', ['note' => Lang::whole((string) $r['note'])]) . "\n" . Lang::t('اگر رکورد را تازه گذاشته‌اید، تا یک ساعت صبر کنید؛ خودکار دوباره بررسی می‌کنیم و خبرتان می‌کنیم.')];
            case 'verify_auto':
                // creates the proof record with the customer's own DNS-panel token (used now, kept nowhere); the public DNS still decides
                $asset = Assets::get($cid, $int('asset'));
                if (!$asset || $asset->kind !== 'domain') {
                    return ['flash' => 'err:' . Lang::t('این دارایی پیدا نشد.')];
                }
                if ($asset->status === 'verified') {
                    return ['flash' => 'ok:' . Lang::t('این دارایی تأییدشده است.')];
                }
                if (!RateLimit::hit('vauto:' . $cid, 10, 3600)) {
                    return ['flash' => 'err:' . Lang::t('در یک ساعت اخیر چند بار امتحان کرده‌اید. کمی بعد دوباره امتحان کنید یا رکورد را دستی بسازید.')];
                }
                $r = \McSec\DnsApi::addProof($in('provider'), (string) ($_POST['dns_token'] ?? ''), (string) $asset->value, Accounts::proof(Accounts::get($cid)));
                unset($_POST['dns_token']);
                if (!$r['ok']) {
                    return ['flash' => 'err:' . $r['error']];
                }
                Audit::log($cid, 'verify_auto', (string) $asset->value, ['provider' => $in('provider')], $who['user_id']);
                $v = Verify::check($asset);
                if ($v['ok']) {
                    return ['flash' => 'ok:' . Lang::t('رکورد ساخته شد و مالکیت {asset} تأیید شد. حالا می‌توانید اسکن بگیرید.', ['asset' => $asset->value])];
                }
                \McSec\Db::table('mod_mcsec_assets')->where('id', (int) $asset->id)->where('client_id', $cid)->update(['next_check_at' => Clock::now() + 60]);
                return ['flash' => 'ok:' . Lang::t('رکورد تأیید در پنل DNS ساخته شد. دیده شدنش در اینترنت چند دقیقه طول می‌کشد؛ خودمان هر چند دقیقه بررسی می‌کنیم و پس از تأیید خبرتان می‌کنیم. توکن شما ذخیره نشد.')];
            case 'asset_save':
                $r = Assets::setLabel($who, $int('asset'), $in('label'), $in('tags'));
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('ذخیره شد.') : 'err:' . $r['error']];
            case 'oasm_report':
                // OASM's own technical PDF (English) for one asset: made and fetched now, in this explicit POST
                $asset = Assets::get($cid, $int('asset'));
                if (!$asset || $asset->status !== 'verified' || (string) $asset->oasm_target === '') {
                    return ['flash' => 'err:' . Lang::t('برای این دارایی هنوز اسکنی روی OASM انجام نشده است؛ اول «کشف سطح حمله» یا «اسکن آسیب‌پذیری» بگیرید.')];
                }
                if (!\McSec\RateLimit::hit('oasmpdf:' . $cid, 6, 3600)) {
                    return ['flash' => 'err:' . Lang::t('در یک ساعت اخیر چند بار گزارش فنی گرفته‌اید. کمی بعد دوباره امتحان کنید.')];
                }
                $pdf = (new \McSec\Engines\Oasm())->report($asset);
                if (!$pdf['ok']) {
                    $ref = Trace::error('engine', 'oasm.report', (string) $pdf['error'], ['asset' => (int) $asset->id], ['client_id' => $cid]);
                    return ['flash' => 'err:' . Lang::t('گزارش فنی از موتور اسکن گرفته نشد. کمی بعد دوباره امتحان کنید؛ اگر تکرار شد این کد را به پشتیبانی بدهید: {ref}', ['ref' => $ref])];
                }
                Audit::log($cid, 'oasm_report', (string) $asset->value, ['bytes' => strlen($pdf['bytes'])], $who['user_id']);
                return ['file' => ['mime' => 'application/pdf', 'bytes' => $pdf['bytes'], 'name' => 'oasm-report-' . (int) $asset->id . '.pdf']];
            case 'view_mode':
                \McSec\Kv::set('view:' . $cid . ':' . (int) $who['user_id'], $in('view') === 'advanced' ? 'advanced' : 'simple');
                return ['redirect' => 'index.php?m=mcsec'];
            case 'asset_origin':
                $r = Assets::setOrigin($who, $int('asset'), $in('origin'));
                if (!$r['ok']) {
                    return ['flash' => 'err:' . $r['error']];
                }
                if (!empty($r['unlinked'])) {
                    return ['flash' => 'ok:' . Lang::t('پیوند سرور اصلی برداشته شد. دارایی IP آن سر جایش ماند.')];
                }
                return ['flash' => 'ok:' . ($r['verified'] ? Lang::t('سرور اصلی ثبت و تأیید شد. کشف سطح حمله و اسکن آسیب‌پذیری این دامنه روی {ip} اجرا می‌شوند.', ['ip' => $r['value']])
                    : Lang::t('سرور اصلی ثبت شد. حالا مالکیت {ip} را در صفحه‌ی همان IP تأیید کنید؛ پس از آن اسکن‌ها روی آن اجرا می‌شوند.', ['ip' => $r['value']]))];
            case 'asset_remove':
                $r = Assets::remove($who, $int('asset'));
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=assets&removed=1'] : ['flash' => 'err:' . $r['error']];
            case 'scan_start':
                $acc = Accounts::get($cid);
                if ((int) $acc->terms_at === 0) {
                    if (($_POST['terms'] ?? '') !== '1') {
                        return ['flash' => 'err:' . Lang::t('برای اولین اسکن، تأیید کنید که مالک دارایی هستید یا اجازه دارید.')];
                    }
                    Accounts::update($cid, ['terms_at' => Clock::now(), 'terms_user' => $who['user_id']]);
                    Audit::log($cid, 'terms', '', ['text' => Settings::get('terms_text')], $who['user_id']);
                }
                $ids = array_values(array_unique(array_filter(array_map(fn ($v) => (int) Text::toAscii((string) $v), (array) ($_POST['assets'] ?? [$_POST['asset'] ?? 0])))));
                if (!$ids) {
                    return ['flash' => 'err:' . Lang::t('دارایی را انتخاب کنید.')];
                }
                // one or several scan types: ticked ones, plus those of a ready-made bundle (legacy forms send one `profile`)
                $mine = \McSec\Catalog::forClient($cid);
                $one = $in('profile');
                $keys = \McSec\Catalog::chosen($mine, array_merge($one !== '' ? [$one] : [], array_map(fn ($v) => is_scalar($v) ? (string) $v : '', (array) ($_POST['profiles'] ?? []))),
                    array_map(fn ($v) => is_scalar($v) ? (string) $v : '', (array) ($_POST['bundles'] ?? [])));
                if (!$keys) {
                    return ['flash' => 'err:' . Lang::t('نوع اسکن را انتخاب کنید: یکی از بسته‌های آماده، یا از فهرست همه‌ی اسکن‌ها.')];
                }
                $queued = [];
                $errors = [];
                $spent = 0;
                $multi = count($keys) > 1;
                foreach (array_slice($ids, 0, 50) as $aid) {
                    $asset = Assets::get($cid, $aid);
                    if (!$asset) {
                        $errors[] = Lang::t('دارایی پیدا نشد.');
                        continue;
                    }
                    $fits = 0;
                    foreach (array_slice($keys, 0, 12) as $key) {
                        // with several types chosen, one that is not for this kind of asset (a port scan on a domain) is left out quietly
                        if ($multi && !in_array((string) $asset->kind, (array) ($mine[$key]['kinds'] ?? []), true)) {
                            continue;
                        }
                        $fits++;
                        $r = Scans::queue($cid, $asset, $key, 0, $who['user_id']);
                        if ($r['ok']) {
                            $queued[] = (int) $r['scan_id'];
                            $spent += (int) ($r['credits'] ?? 0);
                        } else {
                            $errors[] = $asset->value . ' — ' . \McSec\Catalog::label($key) . ': ' . Lang::t((string) $r['error']);
                        }
                    }
                    if ($fits === 0) {
                        $errors[] = Lang::t('{asset}: هیچ‌کدام از اسکن‌های انتخاب‌شده برای این نوع دارایی نیست.', ['asset' => $asset->value]);
                    }
                }
                if (count($queued) === 1 && !$errors) {
                    return ['redirect' => 'index.php?m=mcsec&p=scan&id=' . $queued[0] . '&started=1'];
                }
                $msg = $queued ? ['ok:' . ($spent > 0 ? Lang::t('{n} اسکن در صف قرار گرفت ({credits} اعتبار). نتیجه را در «اسکن‌ها» ببینید و پس از پایان خبرتان می‌کنیم.', ['n' => Text::fa(count($queued)), 'credits' => Text::fa($spent)])
                    : Lang::t('{n} اسکن در صف قرار گرفت. نتیجه را در «اسکن‌ها» ببینید و پس از پایان خبرتان می‌کنیم.', ['n' => Text::fa(count($queued))]))] : ['err:'];
                return ['flash' => $msg[0] . ($errors ? "\n" . implode("\n", $errors) : '')];
            case 'scan_cancel':
                $r = Scans::cancel($who, $int('scan'));
                return ['flash' => $r['ok'] ? 'ok:' . (!empty($r['refunded']) ? Lang::t('اسکن لغو شد و اعتبارش برگشت.') : Lang::t('اسکن لغو شد.')) : 'err:' . $r['error']];
            case 'finding_status':
                $r = Findings::setStatus($who, $int('finding'), $in('status'), $in('note'));
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('وضعیت یافته ذخیره شد.') : 'err:' . $r['error']];
            case 'finding_retest':
                $r = Findings::retest($who, $int('finding'));
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=scan&id=' . (int) $r['scan_id'] . '&started=1'] : ['flash' => 'err:' . $r['error']];
            case 'finding_aifix':
                $r = Reports::aiFix($who, $int('finding'));
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('راهکار هوش مصنوعی آماده شد.') : 'err:' . $r['error']];
            case 'finding_opinion':
                $r = Reports::opinion($who, $int('finding'));
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('نظر دوم هوش مصنوعی آماده شد.') : 'err:' . $r['error']];
            case 'host_mute':
                $on = ($_POST['on'] ?? '') === '1';
                $r = \McSec\Surface::mute($who, $int('id'), $on);
                if (!$r['ok']) {
                    return ['flash' => 'err:' . $r['error']];
                }
                return ['flash' => 'ok:' . ($on ? (!empty($r['engine']) ? Lang::t('این میزبان کنار گذاشته شد؛ دیگر یافته‌ای برایش ثبت نمی‌شود و در موتور اسکن هم خاموش شد.')
                        : Lang::t('این میزبان کنار گذاشته شد؛ دیگر یافته‌ای برایش ثبت نمی‌شود. خاموش کردنش در موتور اسکن الان انجام نشد؛ با اسکن بعدی دوباره تلاش می‌کنیم.'))
                    : Lang::t('این میزبان دوباره بررسی می‌شود.'))];
            case 'report_create':
                $kind = $in('kind') === 'asset' ? 'asset' : 'account';
                $assetId = $int('asset');
                if ($kind === 'asset' && !Assets::get($cid, $assetId)) {
                    return ['flash' => 'err:' . Lang::t('دارایی را انتخاب کنید.')];
                }
                $scanId = $int('scan');
                if ($scanId > 0) {
                    $s = Scans::get($cid, $scanId);
                    if (!$s || $s->status !== 'completed') {
                        return ['flash' => 'err:' . Lang::t('این اسکن هنوز تمام نشده است.')];
                    }
                    $r = Reports::queue($cid, 'scan', ['scan_id' => $scanId, 'asset_id' => (int) $s->asset_id], ($_POST['ai'] ?? '') === '1', $who['user_id']);
                } else {
                    $r = Reports::queue($cid, $kind, ['asset_id' => $assetId], ($_POST['ai'] ?? '') === '1', $who['user_id']);
                }
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=report&id=' . (int) $r['report_id']] : ['flash' => 'err:' . $r['error']];
            case 'schedule_save':
                $r = Schedules::save($who, ['id' => $int('id'), 'asset' => $int('asset'), 'profile' => $in('profile'), 'freq' => $in('freq'), 'dow' => $int('dow'), 'dom' => $int('dom'), 'hour' => $int('hour')]);
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('زمان‌بندی ذخیره شد.') : 'err:' . $r['error']];
            case 'recipe_save':
                // tools and choices are matched against fixed lists in Recipes::save; nothing typed reaches a tool
                $opts = [];
                foreach ((array) ($_POST['opt'] ?? []) as $tool => $set) {
                    foreach ((array) $set as $o => $c) {
                        $opts[(string) $tool][(string) $o] = is_scalar($c) ? (string) $c : '';
                    }
                }
                $r = \McSec\Recipes::save($who, ['id' => $int('id'), 'name' => $in('name'), 'tools' => array_map(fn ($t) => is_scalar($t) ? (string) $t : '', (array) ($_POST['tools'] ?? [])), 'options' => $opts]);
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=recipes&saved=' . (int) $r['id']] : ['flash' => 'err:' . $r['error']];
            case 'chat_send':
                // the model is called here, in the customer's own POST; it can only answer or put a card up for confirmation
                $r = \McSec\Assistant::send($who, $in('preset') !== '' ? $in('preset') : $in('text'));
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=assistant#mcs-chat-end'] : ['flash' => 'err:' . $r['error']];
            case 'chat_confirm':
                $r = \McSec\Assistant::confirm($who, $int('id'), ($_POST['terms'] ?? '') === '1');
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=assistant#mcs-chat-end'] : ['flash' => 'err:' . $r['error']];
            case 'chat_cancel':
                \McSec\Assistant::cancel($who, $int('id'));
                return ['redirect' => 'index.php?m=mcsec&p=assistant#mcs-chat-end'];
            case 'chat_clear':
                \McSec\Assistant::clear($who);
                return ['redirect' => 'index.php?m=mcsec&p=assistant'];
            case 'support_send':
                // the customer's own request for a person to look: WHMCS opens the ticket, code writes the context
                $r = \McSec\Requests::create($who, ['kind' => $in('kind') !== '' ? $in('kind') : 'help', 'topic' => $in('topic'), 'text' => $in('text'), 'asset' => $int('asset'), 'scan' => $int('scan'), 'finding' => $int('finding')]);
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=support&sent=' . (int) $r['id']] : ['flash' => 'err:' . Lang::t((string) $r['error'])];
            case 'request_accept':
                // the customer's yes to the team's price: credits when the wallet has them, otherwise an invoice
                if (!$ctx['buy']) {
                    return ['flash' => 'err:' . Lang::t('تأیید قیمت فقط با مالک حساب یا کاربری که مجوز «فاکتورها» دارد ممکن است.')];
                }
                if (($_POST['agree'] ?? '') !== '1') {
                    return ['flash' => 'err:' . Lang::t('برای تأیید، تیک «قیمت را می‌پذیرم» را بزنید.')];
                }
                $r = \McSec\Requests::accept($who, $int('id'));
                if (!$r['ok']) {
                    return ['flash' => 'err:' . Lang::t((string) $r['error'])];
                }
                return !empty($r['invoice_id']) ? ['redirect' => 'viewinvoice.php?id=' . (int) $r['invoice_id']] : ['redirect' => 'index.php?m=mcsec&p=support&accepted=' . $int('id')];
            case 'request_decline':
                if (!$ctx['buy']) {
                    return ['flash' => 'err:' . Lang::t('تأیید قیمت فقط با مالک حساب یا کاربری که مجوز «فاکتورها» دارد ممکن است.')];
                }
                $r = \McSec\Requests::decline($who, $int('id'));
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('قیمت پذیرفته نشد و چیزی کم نشد. اگر نظرتان عوض شد، در تیکت همین درخواست بنویسید.') : 'err:' . Lang::t((string) $r['error'])];
            case 'recipe_remove':
                $r = \McSec\Recipes::remove($who, $int('id'));
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('اسکن سفارشی حذف شد. اسکن‌های قبلی و یافته‌هایش می‌مانند؛ زمان‌بندی‌هایش متوقف می‌شوند.') : 'err:' . $r['error']];
            case 'schedule_toggle':
                $r = Schedules::setActive($who, $int('id'), ($_POST['active'] ?? '') === '1');
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('ذخیره شد.') : 'err:' . $r['error']];
            case 'schedule_delete':
                $r = Schedules::delete($who, $int('id'));
                return ['flash' => $r['ok'] ? 'ok:' . Lang::t('زمان‌بندی حذف شد.') : 'err:' . $r['error']];
            case 'notify_save':
                $matrix = [];
                foreach (Notify::CHANNELS as $c => $_) {
                    $matrix[$c] = array_map('strval', (array) ($_POST['ch'][$c] ?? []));
                }
                Notify::savePrefs($who, $matrix, $in('min_severity'), $in('digest'));
                return ['flash' => 'ok:' . Lang::t('تنظیم اعلان‌ها ذخیره شد.')];
            case 'webhook_save':
                $url = $in('webhook_url');
                if ($url === '') {
                    Accounts::update($cid, ['webhook_url' => '', 'webhook_secret' => '']);
                    return ['flash' => 'ok:' . Lang::t('وب‌هوک برداشته شد.')];
                }
                $chk = Net::publicUrl($url);
                if (!$chk['ok'] || !str_starts_with(strtolower($url), 'https://')) {
                    return ['flash' => 'err:' . ($chk['ok'] ? 'نشانی وب‌هوک باید https باشد.' : $chk['error'])];
                }
                $acc = Accounts::get($cid);
                Accounts::update($cid, ['webhook_url' => mb_substr($url, 0, 500), 'webhook_secret' => (string) $acc->webhook_secret !== '' ? (string) $acc->webhook_secret : Crypto::encrypt(Crypto::token(24))]);
                return ['flash' => 'ok:' . Lang::t('وب‌هوک ذخیره شد. برای امتحان، «فرستادن پیام آزمایشی» را بزنید.')];
            case 'webhook_rotate':
                Accounts::update($cid, ['webhook_secret' => Crypto::encrypt(Crypto::token(24))]);
                return ['flash' => 'ok:' . Lang::t('کلید امضای تازه ساخته شد؛ آن را در سامانه‌ی گیرنده هم عوض کنید.')];
            case 'webhook_test':
                if (!RateLimit::hit('whtest:' . $cid, 5, 3600)) {
                    return ['flash' => 'err:' . Lang::t('در یک ساعت فقط ۵ پیام آزمایشی.')];
                }
                Notify::event($cid, 'credits_added', ['credits' => 0, 'note' => Lang::with(Lang::forClient($cid), fn () => Lang::t('این یک پیام آزمایشی است.'))], 'test:' . Clock::now());
                return ['flash' => 'ok:' . Lang::t('پیام آزمایشی در صف ارسال است و تا چند دقیقه می‌رسد.')];
            case 'bot_unlink':
                $which = $in('which') === 'bale' ? 'bale_chat' : 'tg_chat';
                Accounts::update($cid, [$which => '']);
                return ['flash' => 'ok:' . Lang::t('اتصال برداشته شد.')];
            case 'notice_read':
                $n = Notify::markRead($cid, $int('notice'));
                return ['flash' => $n > 0 ? 'ok:' . Lang::t('دیده شد.') : 'err:' . Lang::t('خبری برای علامت زدن نبود.')];
            case 'buy_pack':
                if (!$ctx['buy']) {
                    return ['flash' => 'err:' . Lang::t('خرید اعتبار فقط با مالک حساب یا کاربری که مجوز «فاکتورها» دارد ممکن است.')];
                }
                $r = Credits::buy($who, $in('pack'), ['gift' => ($_POST['gift'] ?? '') === '1']);
                return $r['ok'] ? ['redirect' => 'viewinvoice.php?id=' . (int) $r['invoice_id']] : ['flash' => 'err:' . $r['error']];
            case 'code_redeem':
                if (!$ctx['buy'] && !$ctx['manage']) {
                    return ['flash' => 'err:' . Lang::t('ثبت کد فقط با مالک حساب یا کاربری که مجوز «فاکتورها» یا «مدیریت سرویس‌ها» دارد ممکن است.')];
                }
                $r = \McSec\Codes::redeem($who, $in('code'));
                return ['flash' => $r['ok'] ? 'ok:' . $r['message'] : 'err:' . $r['error']];
            case 'auto_save':
                if (!$ctx['buy']) {
                    return ['flash' => 'err:' . Lang::t('شارژ خودکار را فقط مالک حساب یا کاربری که مجوز «فاکتورها» دارد می‌تواند تنظیم کند.')];
                }
                if ($in('pack') !== '' && ($_POST['agree'] ?? '') !== '1') {
                    return ['flash' => 'err:' . Lang::t('برای روشن کردن شارژ خودکار، تیک موافقت را بزنید.')];
                }
                $r = Credits::setAuto($who, $in('pack'), $int('below'));
                return ['flash' => $r['ok'] ? (!empty($r['off']) ? 'ok:' . Lang::t('شارژ خودکار خاموش شد.') : 'ok:' . Lang::t('شارژ خودکار روشن شد. وقتی اعتبار کم شود فاکتور می‌سازیم و خبرتان می‌کنیم.')) : 'err:' . $r['error']];
        }
        return ['flash' => 'err:' . Lang::t('این کار شناخته نشد.')];
    }
}
