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

    public const PAGES = ['home', 'assets', 'asset', 'scans', 'scan', 'findings', 'finding', 'reports', 'report', 'schedules', 'notify', 'credits', 'activity'];

    /** Actions that create something or cost credits also need the page's one-time nonce. */
    private const NEEDS_NONCE = ['add_asset', 'scan_start', 'report_create', 'schedule_save', 'buy_pack', 'finding_aifix', 'webhook_test', 'finding_retest'];
    /** Actions a viewer (WHMCS permission 'products' only) may do. */
    private const VIEWER_ACTIONS = ['notice_read'];

    public static function handle(): array
    {
        $pjax = ($_GET['pjax'] ?? $_POST['pjax'] ?? '') === '1';
        $who = Auth::client();
        if ($who === null) {
            return $pjax ? self::json(['ok' => true, 'redirect' => 'clientarea.php']) : self::page('home', '');
        }
        Trace::$ctx = ['client_id' => $who['client_id'], 'user_id' => $who['user_id']];
        if (!Auth::canView($who) || !Access::clientAllowed($who['client_id'], $who['masq'])) {
            return self::out('home', Views::closed($who), $pjax);
        }
        Accounts::ensure($who['client_id']);
        $ctx = ['who' => $who, 'manage' => Auth::canManage($who) && Auth::mayAct($who), 'buy' => Auth::canBuy($who) && Auth::mayAct($who)];
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && ($_GET['progress'] ?? '') === '1') {
            return self::json(self::progress($ctx, (int) Text::toAscii((string) ($_GET['id'] ?? '0'))));
        }
        $flash = '';
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $r = self::post($ctx, (string) ($_POST['a'] ?? ''));
            if ($pjax && ($_POST['quiet'] ?? '') === '1' && !isset($r['redirect'])) {
                [$kind, $msg] = array_pad(explode(':', (string) ($r['flash'] ?? ''), 2), 2, '');
                return self::json(['ok' => $kind === 'ok', 'flash' => $msg, 'unread' => Notify::unread($who['client_id'])]);
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
        return ['ok' => true, 'status' => (string) $s->status, 'progress' => (int) $s->progress, 'stage' => (string) $s->stage,
            'done' => !in_array($s->status, ['queued', 'running'], true), 'label' => Scans::STATUS[$s->status] ?? $s->status];
    }

    /** @return array{flash?:string,redirect?:string} */
    private static function post(array $ctx, string $a): array
    {
        $who = $ctx['who'];
        if (!Auth::checkWhmcsToken((string) ($_POST['token'] ?? '')) || !Auth::checkCsrf((string) ($_POST['mcs_csrf'] ?? ''))) {
            return ['flash' => 'err:این فرم منقضی شده است. صفحه را تازه کنید و دوباره بفرستید.'];
        }
        if (in_array($a, self::NEEDS_NONCE, true) && !Nonce::consume((string) ($_POST['mcs_nonce'] ?? ''), $who['user_id'], $who['client_id'], 'form')) {
            return ['flash' => 'err:این فرم یک بار فرستاده شده است. اگر نتیجه را نمی‌بینید، صفحه را تازه کنید.'];
        }
        if (!Auth::mayAct($who)) {
            return ['flash' => 'err:شما با «ورود به‌جای مشتری» آمده‌اید و در این حالت فقط دیدن ممکن است.'];
        }
        if (!in_array($a, self::VIEWER_ACTIONS, true) && $a !== 'buy_pack' && !$ctx['manage']) {
            return ['flash' => 'err:کاربر شما فقط اجازه‌ی دیدن دارد. برای این کار، مالک حساب باید مجوز «مدیریت سرویس‌ها» را به شما بدهد.'];
        }
        $in = fn (string $k): string => html_entity_decode(trim((string) ($_POST[$k] ?? '')), ENT_QUOTES, 'UTF-8');
        $int = fn (string $k): int => (int) Text::toAscii((string) ($_POST[$k] ?? '0'));
        $cid = $who['client_id'];
        switch ($a) {
            case 'add_asset':
                $text = $in('targets');
                $autoscan = $in('autoscan');
                $lines = array_values(array_filter(preg_split('~[\s,;،]+~u', Text::toAscii($text)) ?: [], 'strlen'));
                if (!$lines) {
                    return ['flash' => 'err:دامنه یا IP را بنویسید، مثل example.com'];
                }
                if (!RateLimit::hit('add:' . $cid, 300, 86400)) {
                    return ['flash' => 'err:امروز دارایی زیادی افزوده‌اید. فردا ادامه دهید.'];
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
                    $msg[] = Text::fa(count($r['added'])) . ' دارایی افزوده شد' . ($r['verified'] ? '؛ ' . Text::fa($r['verified']) . ' مورد خودکار تأیید شد.' : '.');
                }
                $msg = array_merge($msg, $r['failed']);
                return ['flash' => ($r['added'] ? 'ok:' : 'err:') . implode("\n", $msg)];
            case 'verify_check':
                $asset = Assets::get($cid, $int('asset'));
                if (!$asset) {
                    return ['flash' => 'err:این دارایی پیدا نشد.'];
                }
                if ($asset->status === 'verified') {
                    return ['flash' => 'ok:این دارایی تأییدشده است.'];
                }
                if (!RateLimit::hit('verify:' . $cid, 20, 600)) {
                    return ['flash' => 'err:چند دقیقه صبر کنید و دوباره بررسی کنید. ما هم خودکار هر چند دقیقه بررسی می‌کنیم و خبرتان می‌کنیم.'];
                }
                $r = Verify::check($asset);
                return ['flash' => $r['ok'] ? 'ok:مالکیت ' . $asset->value . ' تأیید شد (' . (Verify::METHODS[$r['method']] ?? $r['method']) . '). حالا می‌توانید اسکن بگیرید.'
                    : 'err:هنوز تأیید نشد. ' . $r['note'] . "\nاگر رکورد را تازه گذاشته‌اید، تا یک ساعت صبر کنید؛ خودکار دوباره بررسی می‌کنیم و خبرتان می‌کنیم."];
            case 'asset_save':
                $r = Assets::setLabel($who, $int('asset'), $in('label'), $in('tags'));
                return ['flash' => $r['ok'] ? 'ok:ذخیره شد.' : 'err:' . $r['error']];
            case 'asset_remove':
                $r = Assets::remove($who, $int('asset'));
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=assets&removed=1'] : ['flash' => 'err:' . $r['error']];
            case 'scan_start':
                $acc = Accounts::get($cid);
                if ((int) $acc->terms_at === 0) {
                    if (($_POST['terms'] ?? '') !== '1') {
                        return ['flash' => 'err:برای اولین اسکن، تأیید کنید که مالک دارایی هستید یا اجازه دارید.'];
                    }
                    Accounts::update($cid, ['terms_at' => Clock::now(), 'terms_user' => $who['user_id']]);
                    Audit::log($cid, 'terms', '', ['text' => Settings::get('terms_text')], $who['user_id']);
                }
                $ids = array_values(array_unique(array_filter(array_map(fn ($v) => (int) Text::toAscii((string) $v), (array) ($_POST['assets'] ?? [$_POST['asset'] ?? 0])))));
                if (!$ids) {
                    return ['flash' => 'err:دارایی را انتخاب کنید.'];
                }
                $queued = [];
                $errors = [];
                $spent = 0;
                foreach (array_slice($ids, 0, 50) as $aid) {
                    $asset = Assets::get($cid, $aid);
                    if (!$asset) {
                        $errors[] = 'دارایی پیدا نشد.';
                        continue;
                    }
                    $r = Scans::queue($cid, $asset, $in('profile'), 0, $who['user_id']);
                    if ($r['ok']) {
                        $queued[] = (int) $r['scan_id'];
                        $spent += (int) ($r['credits'] ?? 0);
                    } else {
                        $errors[] = $asset->value . ': ' . $r['error'];
                    }
                }
                if (count($queued) === 1 && !$errors) {
                    return ['redirect' => 'index.php?m=mcsec&p=scan&id=' . $queued[0] . '&started=1'];
                }
                $msg = $queued ? ['ok:' . Text::fa(count($queued)) . ' اسکن در صف قرار گرفت' . ($spent > 0 ? ' (' . Text::fa($spent) . ' اعتبار)' : '') . '. نتیجه را در «اسکن‌ها» ببینید و پس از پایان خبرتان می‌کنیم.'] : ['err:'];
                return ['flash' => $msg[0] . ($errors ? "\n" . implode("\n", $errors) : '')];
            case 'scan_cancel':
                $r = Scans::cancel($who, $int('scan'));
                return ['flash' => $r['ok'] ? 'ok:اسکن لغو شد' . (!empty($r['refunded']) ? ' و اعتبارش برگشت.' : '.') : 'err:' . $r['error']];
            case 'finding_status':
                $r = Findings::setStatus($who, $int('finding'), $in('status'), $in('note'));
                return ['flash' => $r['ok'] ? 'ok:وضعیت یافته ذخیره شد.' : 'err:' . $r['error']];
            case 'finding_retest':
                $r = Findings::retest($who, $int('finding'));
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=scan&id=' . (int) $r['scan_id'] . '&started=1'] : ['flash' => 'err:' . $r['error']];
            case 'finding_aifix':
                $r = Reports::aiFix($who, $int('finding'));
                return ['flash' => $r['ok'] ? 'ok:راهکار هوش مصنوعی آماده شد.' : 'err:' . $r['error']];
            case 'report_create':
                $kind = $in('kind') === 'asset' ? 'asset' : 'account';
                $assetId = $int('asset');
                if ($kind === 'asset' && !Assets::get($cid, $assetId)) {
                    return ['flash' => 'err:دارایی را انتخاب کنید.'];
                }
                $scanId = $int('scan');
                if ($scanId > 0) {
                    $s = Scans::get($cid, $scanId);
                    if (!$s || $s->status !== 'completed') {
                        return ['flash' => 'err:این اسکن هنوز تمام نشده است.'];
                    }
                    $r = Reports::queue($cid, 'scan', ['scan_id' => $scanId, 'asset_id' => (int) $s->asset_id], ($_POST['ai'] ?? '') === '1', $who['user_id']);
                } else {
                    $r = Reports::queue($cid, $kind, ['asset_id' => $assetId], ($_POST['ai'] ?? '') === '1', $who['user_id']);
                }
                return $r['ok'] ? ['redirect' => 'index.php?m=mcsec&p=report&id=' . (int) $r['report_id']] : ['flash' => 'err:' . $r['error']];
            case 'schedule_save':
                $r = Schedules::save($who, ['id' => $int('id'), 'asset' => $int('asset'), 'profile' => $in('profile'), 'freq' => $in('freq'), 'dow' => $int('dow'), 'dom' => $int('dom'), 'hour' => $int('hour')]);
                return ['flash' => $r['ok'] ? 'ok:زمان‌بندی ذخیره شد.' : 'err:' . $r['error']];
            case 'schedule_toggle':
                $r = Schedules::setActive($who, $int('id'), ($_POST['active'] ?? '') === '1');
                return ['flash' => $r['ok'] ? 'ok:ذخیره شد.' : 'err:' . $r['error']];
            case 'schedule_delete':
                $r = Schedules::delete($who, $int('id'));
                return ['flash' => $r['ok'] ? 'ok:زمان‌بندی حذف شد.' : 'err:' . $r['error']];
            case 'notify_save':
                $matrix = [];
                foreach (Notify::CHANNELS as $c => $_) {
                    $matrix[$c] = array_map('strval', (array) ($_POST['ch'][$c] ?? []));
                }
                Notify::savePrefs($who, $matrix, $in('min_severity'), $in('digest'));
                return ['flash' => 'ok:تنظیم اعلان‌ها ذخیره شد.'];
            case 'webhook_save':
                $url = $in('webhook_url');
                if ($url === '') {
                    Accounts::update($cid, ['webhook_url' => '', 'webhook_secret' => '']);
                    return ['flash' => 'ok:وب‌هوک برداشته شد.'];
                }
                $chk = Net::publicUrl($url);
                if (!$chk['ok'] || !str_starts_with(strtolower($url), 'https://')) {
                    return ['flash' => 'err:' . ($chk['ok'] ? 'نشانی وب‌هوک باید https باشد.' : $chk['error'])];
                }
                $acc = Accounts::get($cid);
                Accounts::update($cid, ['webhook_url' => mb_substr($url, 0, 500), 'webhook_secret' => (string) $acc->webhook_secret !== '' ? (string) $acc->webhook_secret : Crypto::encrypt(Crypto::token(24))]);
                return ['flash' => 'ok:وب‌هوک ذخیره شد. برای امتحان، «فرستادن پیام آزمایشی» را بزنید.'];
            case 'webhook_rotate':
                Accounts::update($cid, ['webhook_secret' => Crypto::encrypt(Crypto::token(24))]);
                return ['flash' => 'ok:کلید امضای تازه ساخته شد؛ آن را در سامانه‌ی گیرنده هم عوض کنید.'];
            case 'webhook_test':
                if (!RateLimit::hit('whtest:' . $cid, 5, 3600)) {
                    return ['flash' => 'err:در یک ساعت فقط ۵ پیام آزمایشی.'];
                }
                Notify::event($cid, 'credits_added', ['credits' => 0, 'note' => 'این یک پیام آزمایشی است.'], 'test:' . Clock::now());
                return ['flash' => 'ok:پیام آزمایشی در صف ارسال است و تا چند دقیقه می‌رسد.'];
            case 'bot_unlink':
                $which = $in('which') === 'bale' ? 'bale_chat' : 'tg_chat';
                Accounts::update($cid, [$which => '']);
                return ['flash' => 'ok:اتصال برداشته شد.'];
            case 'notice_read':
                $n = Notify::markRead($cid, $int('notice'));
                return ['flash' => $n > 0 ? 'ok:دیده شد.' : 'err:خبری برای علامت زدن نبود.'];
            case 'buy_pack':
                if (!$ctx['buy']) {
                    return ['flash' => 'err:خرید اعتبار فقط با مالک حساب یا کاربری که مجوز «فاکتورها» دارد ممکن است.'];
                }
                $r = Credits::buy($who, $in('pack'));
                return $r['ok'] ? ['redirect' => 'viewinvoice.php?id=' . (int) $r['invoice_id']] : ['flash' => 'err:' . $r['error']];
        }
        return ['flash' => 'err:این کار شناخته نشد.'];
    }
}
