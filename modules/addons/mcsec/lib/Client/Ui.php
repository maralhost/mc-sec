<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Auth;
use McSec\Findings;
use McSec\Nonce;
use McSec\Score;
use McSec\Text;

/**
 * Building blocks of the client pages: panels, figures, severity badges (shape + Persian word + colour, never colour
 * alone), the score gauge, code blocks with a copy button, menus and panels that open without JavaScript
 * (<details>), and forms with every hidden field. Every dynamic value goes through e(); technical tokens (domains, IPs,
 * ports, CVE ids, code) are isolated left-to-right. Colours come from Lagom2's variables (client.css).
 */
final class Ui
{
    private const ICONS = [
        'shield' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'shield-check' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
        'home' => '<path d="m3 11 9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-5h4v5"/>',
        'globe' => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
        'server' => '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 8h.01M7 17h.01"/>',
        'radar' => '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 19 5"/><circle cx="12" cy="12" r="1"/>',
        'bug' => '<rect x="7" y="7" width="10" height="13" rx="5"/><path d="M12 7V4M9 4l1.5 2M15 4l-1.5 2M3 13h4M17 13h4M4 7l3 2M20 7l-3 2M4 19l3-2M20 19l-3-2"/>',
        'heart' => '<path d="M20.8 5.6a5 5 0 0 0-7.1 0L12 7.3l-1.7-1.7a5 5 0 0 0-7.1 7.1L12 21.5l8.8-8.8a5 5 0 0 0 0-7.1z"/><path d="M3 12h4l2-3 3 6 2-3h7"/>',
        'search' => '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
        'layers' => '<path d="m12 3 9 5-9 5-9-5 9-5z"/><path d="m3 13 9 5 9-5"/>',
        'list' => '<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>',
        'file' => '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4M9 13h6M9 17h6"/>',
        'calendar' => '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
        'bell' => '<path d="M6 16V11a6 6 0 0 1 12 0v5l2 2H4z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
        'coins' => '<ellipse cx="9" cy="7" rx="6" ry="3"/><path d="M3 7v4c0 1.7 2.7 3 6 3s6-1.3 6-3V7"/><path d="M9 14v3c0 1.7 2.7 3 6 3s6-1.3 6-3v-4c0-1.7-2.7-3-6-3"/>',
        'clock' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'plus' => '<path d="M12 5v14M5 12h14"/>',
        'check' => '<path d="m5 12 5 5 9-10"/>',
        'x' => '<path d="M6 6l12 12M18 6 6 18"/>',
        'alert' => '<path d="M12 3 2 21h20L12 3z"/><path d="M12 10v5m0 3v.01"/>',
        'info' => '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-9v.01"/>',
        'play' => '<path d="m7 4 13 8-13 8z"/>',
        'pause' => '<path d="M8 5v14M16 5v14"/>',
        'refresh' => '<path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4"/>',
        'copy' => '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
        'printer' => '<path d="M7 8V3h10v5M7 17H4v-7h16v7h-3"/><rect x="7" y="14" width="10" height="7"/>',
        'trash' => '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
        'link' => '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
        'sparkle' => '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"/>',
        'key' => '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9m-3 3 3 3m-6 0 2 2"/>',
        'more' => '<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>',
        'expand' => '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
        'menu' => '<path d="M4 6h16M4 12h16M4 18h16"/>',
        'chevron' => '<path d="m15 6-6 6 6 6"/>',
        'activity' => '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
        'mail' => '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
        'send' => '<path d="M22 2 11 13M22 2l-7 20-4-9-9-4z"/>',
        'webhook' => '<circle cx="6" cy="17" r="3"/><circle cx="18" cy="17" r="3"/><circle cx="12" cy="6" r="3"/><path d="M9 17h6M7.5 14.5l3-6M16.5 14.5l-3-6"/>',
        'lock' => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
        // severity shapes (the shape itself carries meaning for colour-blind readers)
        'sev-critical' => '<path d="M8 2h8l6 6v8l-6 6H8l-6-6V8z"/><path d="M12 7v6m0 3v.01"/>',
        'sev-high' => '<path d="M12 3 2 21h20L12 3z"/><path d="M12 10v5m0 3v.01"/>',
        'sev-medium' => '<path d="m12 2 10 10-10 10L2 12z"/><path d="M12 8v5m0 3v.01"/>',
        'sev-low' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v9m-3.5-3.5L12 16l3.5-3.5"/>',
        'sev-info' => '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-9v.01"/>',
    ];

    public static function e($s): string
    {
        return Text::e($s);
    }

    public static function ico(string $name): string
    {
        return '<svg class="mcs-ico" aria-hidden="true" focusable="false"><use href="#mcs-i-' . self::e($name) . '"></use></svg>';
    }

    public static function sprite(): string
    {
        $h = '<svg xmlns="http://www.w3.org/2000/svg" hidden aria-hidden="true" style="display:none">';
        foreach (self::ICONS as $id => $paths) {
            $h .= '<symbol id="mcs-i-' . $id . '" viewBox="0 0 24 24">' . $paths . '</symbol>';
        }
        return $h . '</svg>';
    }

    /** An LTR technical token (domain, IP, port, CVE, path) inside Persian text. */
    public static function ltr($s, string $class = ''): string
    {
        return '<bdi dir="ltr" class="mcs-ltr' . ($class !== '' ? ' ' . $class : '') . '">' . self::e($s) . '</bdi>';
    }

    /** A labelled status: text and colour together. tone: ok, warn, err, info, run, muted, accepted */
    public static function chip(string $text, string $tone = ''): string
    {
        return '<span class="mcs-chip' . ($tone !== '' ? ' mcs-chip-' . $tone : '') . '">' . self::e($text) . '</span>';
    }

    public static function sev(string $severity, bool $short = false): string
    {
        $s = Findings::SEVERITIES[$severity] ?? Findings::SEVERITIES['info'];
        $key = isset(Findings::SEVERITIES[$severity]) ? $severity : 'info';
        return '<span class="mcs-sev mcs-sev-' . $key . '">' . self::ico('sev-' . $key) . '<span' . ($short ? ' class="mcs-sr"' : '') . '>' . self::e($s['label']) . '</span></span>';
    }

    /** Five severity counts in a row; each a link to the filtered findings when $link is given. */
    public static function sevCounts(array $c, string $link = '', bool $compact = false): string
    {
        $h = '<ul class="mcs-sevcounts' . ($compact ? ' is-compact' : '') . '">';
        foreach (Findings::SEVERITIES as $k => $s) {
            $n = (int) ($c[$k] ?? 0);
            $inner = self::ico('sev-' . $k) . '<strong>' . self::e(Text::fa($n)) . '</strong><span' . ($compact ? ' class="mcs-sr"' : '') . '>' . self::e($s['label']) . '</span>';
            $h .= '<li class="mcs-sev-' . $k . ($n === 0 ? ' is-zero' : '') . '">'
                . ($link !== '' && $n > 0 ? '<a href="' . self::e($link . '&severity=' . $k) . '" title="' . self::e($s['label']) . '">' . $inner . '</a>' : '<span title="' . self::e($s['label']) . '">' . $inner . '</span>') . '</li>';
        }
        return $h . '</ul>';
    }

    /** The score: a ring with the number and its word. */
    public static function gauge(int $score, string $sub = ''): string
    {
        $tone = Score::tone($score);
        $pct = $score < 0 ? 0 : $score;
        $r = 52;
        $len = 2 * M_PI * $r;
        $dash = round($len * $pct / 100, 1);
        return '<div class="mcs-gauge mcs-tone-' . $tone . '" role="img" aria-label="' . self::e('امتیاز امنیت ' . ($score < 0 ? 'ندارد' : Text::fa($score) . ' از ۱۰۰، ' . Score::label($score))) . '">'
            . '<svg viewBox="0 0 120 120" aria-hidden="true"><circle class="mcs-gauge-track" cx="60" cy="60" r="' . $r . '"/>'
            . '<circle class="mcs-gauge-bar" cx="60" cy="60" r="' . $r . '" stroke-dasharray="' . $dash . ' ' . round($len, 1) . '" transform="rotate(-90 60 60)"/></svg>'
            . '<div class="mcs-gauge-text"><strong>' . ($score < 0 ? '—' : self::e(Text::fa($score))) . '</strong><span>' . self::e(Score::label($score)) . '</span></div>'
            . ($sub !== '' ? '<p class="mcs-gauge-sub">' . $sub . '</p>' : '') . '</div>';
    }

    /** A small line of the score over time (RTL: the newest point is on the left, as time runs right to left). */
    public static function spark(array $points, int $w = 260, int $h = 56): string
    {
        if (count($points) < 2) {
            return '<p class="mcs-muted mcs-small">برای نمودار روند، دست‌کم دو روز اسکن لازم است.</p>';
        }
        $n = count($points);
        $xy = [];
        foreach (array_values($points) as $i => $p) {
            $x = round($w - ($i * ($w - 8) / ($n - 1)) - 4, 1); // oldest on the right
            $y = round($h - 4 - (max(0, min(100, (int) $p['score'])) / 100) * ($h - 8), 1);
            $xy[] = $x . ',' . $y;
        }
        $last = end($points);
        return '<figure class="mcs-spark"><svg viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . self::e('روند امتیاز در ' . Text::fa($n) . ' روز؛ امروز ' . Text::fa((int) $last['score'])) . '">'
            . '<polyline points="' . implode(' ', $xy) . '" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/></svg></figure>';
    }

    /** kind: info, success, warning, danger. $html must already be escaped. */
    public static function alert(string $kind, string $html, string $icon = 'info'): string
    {
        $role = in_array($kind, ['danger', 'warning'], true) ? 'alert' : 'status';
        return '<div class="alert alert-lagom alert-' . $kind . ' mcs-alert" role="' . $role . '">' . self::ico($icon) . '<div class="alert-body">' . $html . '</div></div>';
    }

    public static function card(string $body, string $title = '', string $icon = '', string $actions = '', string $extra = '', string $sub = ''): string
    {
        $head = $title === '' ? '' : '<div class="mcs-card-head"><div class="mcs-card-titles"><h3 class="mcs-card-title">' . ($icon !== '' ? '<span class="mcs-card-ico">' . self::ico($icon) . '</span>' : '')
            . self::e($title) . '</h3>' . ($sub !== '' ? '<p class="mcs-card-sub">' . $sub . '</p>' : '') . '</div>'
            . ($actions !== '' ? '<div class="mcs-actions">' . $actions . '</div>' : '') . '</div>';
        return '<section class="card mcs-card' . ($extra !== '' ? ' ' . $extra : '') . '"><div class="card-body">' . $head . $body . '</div></section>';
    }

    public static function kpi(string $icon, string $label, string $value, string $sub = '', string $tone = '', string $href = ''): string
    {
        $inner = '<span class="mcs-kpi-ico">' . self::ico($icon) . '</span><span class="mcs-kpi-body"><span class="mcs-kpi-label">' . self::e($label) . '</span>'
            . '<strong class="mcs-kpi-value">' . $value . '</strong>' . ($sub !== '' ? '<span class="mcs-kpi-sub">' . $sub . '</span>' : '') . '</span>';
        $cls = 'mcs-kpi' . ($tone !== '' ? ' mcs-kpi-' . $tone : '');
        return $href !== '' ? '<a class="' . $cls . '" href="' . self::e($href) . '">' . $inner . '</a>' : '<div class="' . $cls . '">' . $inner . '</div>';
    }

    public static function emptyState(string $icon, string $title, string $desc, string $action = ''): string
    {
        return '<div class="mcs-empty"><span class="mcs-empty-ico">' . self::ico($icon) . '</span><h3>' . self::e($title) . '</h3><p>' . $desc . '</p>' . $action . '</div>';
    }

    /** «این بخش چه کار می‌کند؟» — open while the person has not done the page's first thing yet. */
    public static function guide(string $html, bool $open): string
    {
        return '<details class="mcs-guide"' . ($open ? ' open' : '') . '><summary>' . self::ico('info') . 'این بخش چه کار می‌کند؟</summary><div class="mcs-guide-body">' . $html . '</div></details>';
    }

    public static function flash(string $flash): string
    {
        if ($flash === '') {
            return '';
        }
        [$kind, $msg] = array_pad(explode(':', $flash, 2), 2, '');
        $lines = array_values(array_filter(explode("\n", $msg), 'strlen'));
        $html = count($lines) > 1 ? '<ul>' . implode('', array_map(fn ($l) => '<li>' . self::e($l) . '</li>', $lines)) . '</ul>' : self::e($lines[0] ?? '');
        return $kind === 'ok' ? self::alert('success', $html, 'check') : ($kind === 'info' ? self::alert('info', $html, 'info') : self::alert('danger', $html, 'alert'));
    }

    /** A copyable LTR code/value block. */
    public static function code(string $text, string $label = '', bool $block = true): string
    {
        $id = 'mcs-c-' . substr(md5($text . $label . random_int(0, PHP_INT_MAX)), 0, 10);
        if (!$block) {
            return '<span class="mcs-copyline"><code dir="ltr" id="' . $id . '">' . self::e($text) . '</code><button type="button" class="mcs-copy" data-mcs-copy="' . $id . '" hidden aria-label="کپی">' . self::ico('copy') . '<span>کپی</span></button></span>';
        }
        return '<div class="mcs-code">' . ($label !== '' ? '<div class="mcs-code-head"><span dir="ltr">' . self::e($label) . '</span><button type="button" class="mcs-copy" data-mcs-copy="' . $id . '" hidden>' . self::ico('copy') . '<span>کپی</span></button></div>' : '')
            . '<pre dir="ltr" id="' . $id . '"><code>' . self::e($text) . '</code></pre>' . ($label === '' ? '<button type="button" class="mcs-copy mcs-copy-float" data-mcs-copy="' . $id . '" hidden>' . self::ico('copy') . '<span>کپی</span></button>' : '') . '</div>';
    }

    public static function progress(int $pct, string $text, bool $running = false): string
    {
        $pct = max(0, min(100, $pct));
        return '<div class="mcs-progress' . ($running ? ' is-running' : '') . '"><div class="mcs-progress-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' . $pct . '" aria-label="' . self::e($text) . '"><span style="inline-size:' . $pct . '%"></span></div>'
            . '<div class="mcs-progress-text"><span data-mcs-stage>' . self::e($text) . '</span><strong data-mcs-pct>' . self::e(Text::fa($pct)) . '٪</strong></div></div>';
    }

    public static function meter(float $used, float $max, string $text): string
    {
        $pct = $max > 0 ? (int) min(100, round($used / $max * 100)) : 0;
        $tone = $pct >= 100 ? ' is-full' : ($pct >= 80 ? ' is-high' : '');
        return '<div class="mcs-meter' . $tone . '"><span class="mcs-meter-bar" aria-hidden="true"><span style="inline-size:' . $pct . '%"></span></span><span class="mcs-meter-text">' . $text . '</span></div>';
    }

    /** One nonce per rendered page, shared by its forms. */
    public static ?string $nonce = null;

    public static function hidden(array $ctx, string $page): string
    {
        $who = $ctx['who'];
        self::$nonce ??= Nonce::issue($who['user_id'], $who['client_id'], 'form');
        return '<input type="hidden" name="token" value="' . self::e(self::token()) . '"><input type="hidden" name="mcs_csrf" value="' . self::e(Auth::csrf()) . '">'
            . '<input type="hidden" name="mcs_nonce" value="' . self::e(self::$nonce) . '"><input type="hidden" name="p" value="' . self::e($page) . '">';
    }

    private static function token(): string
    {
        if (Auth::$testClient !== null) {
            return 'whmcs-token';
        }
        try {
            return function_exists('generate_token') ? (string) generate_token('plain') : '';
        } catch (\Throwable $e) {
            return '';
        }
    }

    public static function form(array $ctx, string $page, string $action, string $body, string $confirm = '', string $class = '', bool|string $quiet = false, string $query = ''): string
    {
        return '<form method="post" action="index.php?m=mcsec&amp;p=' . self::e($page) . $query . '"' . ($class !== '' ? ' class="' . $class . '"' : '')
            . ($quiet !== false ? ' data-mcs-quiet' . ($quiet === 'remove' ? ' data-mcs-remove' : '') : '')
            . ($confirm !== '' ? ' data-mcs-confirm="' . self::e($confirm) . '"' : '') . ' novalidate>' . self::hidden($ctx, $page)
            . '<input type="hidden" name="a" value="' . self::e($action) . '">' . $body . '</form>';
    }

    public static function table(array $head, string $rows, string $extra = ''): string
    {
        $th = '';
        foreach ($head as $h) {
            $th .= '<th scope="col">' . ($h === '' ? '<span class="mcs-sr">کارها</span>' : self::e($h)) . '</th>';
        }
        return '<div class="mcs-table-wrap"><table class="table mcs-table mcs-cards' . ($extra !== '' ? ' ' . $extra : '') . '"><thead><tr>' . $th . '</tr></thead><tbody>' . $rows . '</tbody></table></div>';
    }

    /** A <td> with the column label for the phone card layout. */
    public static function td(string $label, string $html, string $class = ''): string
    {
        return '<td data-label="' . self::e($label) . '"' . ($class !== '' ? ' class="' . $class . '"' : '') . '>' . $html . '</td>';
    }

    public static function menu(string $items, string $label = 'کارهای بیشتر'): string
    {
        return '<details class="mcs-menu"><summary class="btn btn-default btn-sm" aria-label="' . self::e($label) . '">' . self::ico('more') . '<span class="mcs-sr">' . self::e($label) . '</span></summary>'
            . '<div class="mcs-menu-list">' . $items . '</div></details>';
    }

    public static function drawer(string $summary, string $body, bool $open = false, string $icon = '', string $id = ''): string
    {
        return '<details class="mcs-drawer"' . ($id !== '' ? ' id="' . self::e($id) . '"' : '') . ($open ? ' open' : '') . '><summary>' . ($icon !== '' ? self::ico($icon) : '') . self::e($summary) . '</summary><div class="mcs-drawer-body">' . $body . '</div></details>';
    }

    public static function toggle(string $name, bool $on, string $label, string $help = '', string $id = '', string $value = '1'): string
    {
        $id = $id !== '' ? $id : 'mcs-t-' . substr(md5($name . $label . $value), 0, 8);
        return '<div class="mcs-toggle"><input type="checkbox" role="switch" id="' . self::e($id) . '" name="' . self::e($name) . '" value="' . self::e($value) . '"' . ($on ? ' checked' : '') . '>'
            . '<label for="' . self::e($id) . '"><span class="mcs-toggle-ui" aria-hidden="true"></span><span><strong>' . self::e($label) . '</strong>'
            . ($help !== '' ? '<small>' . $help . '</small>' : '') . '</span></label></div>';
    }

    public static function field(string $id, string $label, string $control, string $help = ''): string
    {
        return '<div class="form-group mcs-field"><label class="control-label" for="' . self::e($id) . '">' . self::e($label) . '</label>' . $control
            . ($help !== '' ? '<span class="mcs-help">' . $help . '</span>' : '') . '</div>';
    }

    /** @param array<string,string> $options value => label */
    public static function select(string $name, array $options, string $current, string $id = '', string $extra = ''): string
    {
        $h = '<select class="form-control" name="' . self::e($name) . '"' . ($id !== '' ? ' id="' . self::e($id) . '"' : '') . ($extra !== '' ? ' ' . $extra : '') . '>';
        foreach ($options as $v => $l) {
            $h .= '<option value="' . self::e((string) $v) . '"' . ((string) $v === $current ? ' selected' : '') . '>' . self::e($l) . '</option>';
        }
        return $h . '</select>';
    }

    /** Segmented filter links. @param array<string,string> $items href => label */
    public static function seg(array $items, string $active): string
    {
        $h = '<nav class="mcs-seg" aria-label="فیلتر">';
        foreach ($items as $href => $label) {
            $h .= '<a class="mcs-seg-item' . ($href === $active ? ' active" aria-current="true' : '') . '" href="' . self::e($href) . '">' . $label . '</a>';
        }
        return $h . '</nav>';
    }

    /** Previous / next page links that keep the current filters. */
    public static function pager(string $base, int $page, int $pages): string
    {
        if ($pages <= 1) {
            return '';
        }
        $h = '<nav class="mcs-pager" aria-label="صفحه‌ها">';
        if ($page > 1) {
            $h .= '<a class="btn btn-default btn-sm" href="' . self::e($base . '&page=' . ($page - 1)) . '">قبلی</a>';
        }
        $h .= '<span class="mcs-muted">صفحه‌ی ' . self::e(Text::fa($page)) . ' از ' . self::e(Text::fa($pages)) . '</span>';
        if ($page < $pages) {
            $h .= '<a class="btn btn-default btn-sm" href="' . self::e($base . '&page=' . ($page + 1)) . '">بعدی</a>';
        }
        return $h . '</nav>';
    }

    /** Definition list of facts. @param array<string,string> $rows label => HTML */
    public static function facts(array $rows): string
    {
        $h = '<dl class="mcs-facts">';
        foreach ($rows as $k => $v) {
            if ($v === '') {
                continue;
            }
            $h .= '<div><dt>' . self::e($k) . '</dt><dd>' . $v . '</dd></div>';
        }
        return $h . '</dl>';
    }

    /** Plain text with line breaks kept, escaped (descriptions from scanners and the model). */
    public static function para(string $text): string
    {
        $text = trim($text);
        if ($text === '') {
            return '';
        }
        $out = '';
        foreach (preg_split('~\n{2,}~', $text) ?: [] as $p) {
            $out .= '<p dir="auto">' . nl2br(self::e(trim($p)), false) . '</p>';
        }
        return $out;
    }
}
