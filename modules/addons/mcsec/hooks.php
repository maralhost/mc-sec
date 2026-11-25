<?php
/**
 * MC-Sec hooks. Loaded by WHMCS on every page while the module is active, so each hook: returns early when the
 * feature is off, never touches the network (database only, short caches), and never throws (try/catch + log).
 * Heavy work only in AfterCronJob (Worker, with a lock).
 */

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/bootstrap.php';

/** Whether the logged-in client may see MC-Sec on this request (cached per request; database only). */
function mcsec_hook_client(): ?array
{
    static $who = false;
    if ($who !== false) {
        return $who;
    }
    $who = null;
    try {
        if (!\McSec\Settings::bool('enabled') && empty($_SESSION['adminid'])) {
            return null;
        }
        $w = \McSec\Auth::client();
        if ($w && \McSec\Auth::canView($w) && \McSec\Access::clientAllowed($w['client_id'], $w['masq'])) {
            $who = $w;
        }
    } catch (\Throwable $e) {
        \McSec\Db::log('hook client check failed: ' . $e->getMessage());
    }
    return $who;
}

add_hook('AfterCronJob', 1, function ($vars) {
    try {
        \McSec\Worker::run();
    } catch (\Throwable $e) {
        \McSec\Trace::error('hook', 'AfterCronJob', $e->getMessage(), \McSec\Trace::exception($e));
    }
});

add_hook('DailyCronJob', 1, function ($vars) {
    try {
        \McSec\Worker::daily();
    } catch (\Throwable $e) {
        \McSec\Trace::error('hook', 'DailyCronJob', $e->getMessage(), \McSec\Trace::exception($e));
    }
});

/** A paid credit-pack invoice adds its credits at once (the worker re-checks, so a missed hook is not lost). */
add_hook('InvoicePaid', 1, function ($vars) {
    try {
        $id = (int) ($vars['invoiceid'] ?? 0);
        if ($id > 0 && \McSec\Db::table('mod_mcsec_topups')->where('invoice_id', $id)->where('status', 'pending')->exists()) {
            \McSec\Credits::invoicePaid($id);
        }
        if ($id > 0 && \McSec\Db::table('mod_mcsec_requests')->where('invoice_id', $id)->where('status', 'invoiced')->exists()) {
            \McSec\Requests::invoicePaid($id); // a manual test the customer accepted without enough credits
        }
    } catch (\Throwable $e) {
        \McSec\Trace::error('hook', 'InvoicePaid', $e->getMessage(), \McSec\Trace::exception($e));
    }
});

/**
 * The menu item in the client area: one more entry under «سرویس‌ها», not a top-level menu of its own (Lagom2 reads
 * WHMCS's primary navbar). No number beside it: the theme draws that badge its own way and it cannot be styled from
 * here (rule 5); the count of unread notices is on the bell inside the section and on the home panel.
 */
add_hook('ClientAreaPrimaryNavbar', 1, function ($primaryNavbar) {
    try {
        if (!is_object($primaryNavbar) || mcsec_hook_client() === null) {
            return;
        }
        $label = \McSec\Settings::menuLabel();
        $item = ['label' => $label, 'uri' => 'index.php?m=mcsec', 'icon' => 'fa-shield-alt'];
        $services = method_exists($primaryNavbar, 'getChild') ? $primaryNavbar->getChild('Services') : null;
        if (is_object($services)) {
            $services->addChild('mcsec', $item + ['order' => 25]);
        } else {
            $primaryNavbar->addChild('mcsec', $item + ['order' => 65]); // a menu without «سرویس‌ها»
        }
    } catch (\Throwable $e) {
        \McSec\Db::log('navbar hook failed: ' . $e->getMessage());
    }
});

/** A small panel on the client area home page: score, open urgent issues and a link. */
add_hook('ClientAreaHomepagePanels', 1, function ($homePagePanels) {
    try {
        $who = mcsec_hook_client();
        if ($who === null || !is_object($homePagePanels) || !\McSec\Accounts::get($who['client_id'])) {
            return;
        }
        $score = \McSec\Score::forClient($who['client_id']);
        $c = \McSec\Findings::openCounts($who['client_id']);
        $urgent = $c['critical'] + $c['high'];
        $e = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
        $t = fn (string $fa, array $v = []) => \McSec\Lang::t($fa, $v);
        $body = '<div class="mcs-home" ' . \McSec\Lang::attrs() . ' style="padding:12px 16px;line-height:1.9">'
            . ($score['score'] >= 0
                ? '<div>' . $t('<strong>{score}</strong> از ۱۰۰ — {label}', ['score' => $e(\McSec\Text::fa($score['score'])), 'label' => $e($t((string) $score['label']))]) . '</div>'
                    . ($urgent > 0 ? '<div>' . $t('{n} مشکل بحرانی یا مهم باز است.', ['n' => $e(\McSec\Text::fa($urgent))]) . '</div>' : '<div>' . $t('مشکل مهمی باز نیست.') . '</div>')
                : '<div>' . $t('دارایی‌هایتان را اضافه و اسکن کنید تا وضعیت امنیت این‌جا دیده شود.') . '</div>')
            . '</div>';
        $homePagePanels->addChild('mcsec', [
            'label' => \McSec\Settings::menuLabel(),
            'icon' => 'fa-shield-alt',
            'order' => 15,
            'extras' => ['color' => $urgent > 0 ? 'red' : 'green', 'btn-link' => 'index.php?m=mcsec', 'btn-text' => $t('باز کردن')],
            'bodyHtml' => $body,
        ]);
    } catch (\Throwable $e) {
        \McSec\Db::log('home panel hook failed: ' . $e->getMessage());
    }
});

/** A small "security of this site" box on a hosting service's page (switch service_box). Database only. */
add_hook('ClientAreaProductDetailsOutput', 1, function ($vars) {
    try {
        if (!\McSec\Settings::bool('service_box')) {
            return '';
        }
        $who = mcsec_hook_client();
        $svc = $vars['service'] ?? null;
        if ($who === null || !is_object($svc)) {
            return '';
        }
        return \McSec\Watch::serviceBox((int) $who['client_id'], (string) ($svc->domain ?? ''));
    } catch (\Throwable $e) {
        \McSec\Db::log('service box hook failed: ' . $e->getMessage());
        return '';
    }
});
