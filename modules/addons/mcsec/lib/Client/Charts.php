<?php

declare(strict_types=1);

namespace McSec\Client;

use McSec\Findings;
use McSec\Lang;
use McSec\Text;

/**
 * The pictures of the overview and the scan page (0.13.0), all drawn here as inline SVG: no library, no script, no
 * outside file. Every picture has a text twin (aria-label and a visible legend with the same numbers), colours come
 * from the severity and tone tokens of client.css, and movement stops with prefers-reduced-motion.
 * Time runs the way the page reads: in a right-to-left page the newest day is on the left.
 */
final class Charts
{
    /** Set by Views from the page's direction. */
    public static bool $rtl = true;

    private static function e($s): string
    {
        return Ui::e($s);
    }

    /** x of slot $i of $n across $w, oldest first in reading order. */
    private static function x(int $i, int $n, float $w, float $pad = 0): float
    {
        $t = $n > 1 ? $i / ($n - 1) : 0.5;
        return round($pad + (self::$rtl ? 1 - $t : $t) * ($w - 2 * $pad), 1);
    }

    /** Open findings by severity as a ring, with the legend that carries the same numbers as links. */
    public static function donut(array $counts, string $link): string
    {
        $total = 0;
        foreach (Findings::SEVERITIES as $k => $_) {
            $total += (int) ($counts[$k] ?? 0);
        }
        $r = 42;
        $len = 2 * M_PI * $r;
        $arcs = '';
        $at = 0.0;
        $legend = '';
        $say = [];
        foreach (Findings::SEVERITIES as $k => $s) {
            $n = (int) ($counts[$k] ?? 0);
            if ($n > 0 && $total > 0) {
                $part = $len * $n / $total;
                $gap = $n === $total ? 0 : min(2.0, $part / 3);
                $arcs .= '<circle class="mcs-arc mcs-arc-' . $k . '" cx="60" cy="60" r="' . $r . '" stroke-dasharray="' . round($part - $gap, 2) . ' ' . round($len - $part + $gap, 2) . '" stroke-dashoffset="' . round(-$at, 2) . '"/>';
                $at += $part;
            }
            $inner = '<i class="mcs-key mcs-key-' . $k . '" aria-hidden="true"></i><span>' . self::e($s['label']) . '</span><strong>' . self::e(Text::fa($n)) . '</strong>';
            $legend .= '<li' . ($n === 0 ? ' class="is-zero"' : '') . '>' . ($n > 0 && $link !== '' ? '<a href="' . self::e($link . '&severity=' . $k) . '">' . $inner . '</a>' : '<span>' . $inner . '</span>') . '</li>';
            $say[] = Text::fa($n) . ' ' . Lang::t($s['label']);
        }
        return '<div class="mcs-donut"><div class="mcs-donut-ring" role="img" aria-label="' . self::e(Lang::t('یافته‌های باز: {list}', ['list' => Lang::join($say)])) . '">'
            . '<svg viewBox="0 0 120 120" aria-hidden="true"><circle class="mcs-arc-track" cx="60" cy="60" r="' . $r . '"/><g transform="rotate(-90 60 60)">' . $arcs . '</g></svg>'
            . '<div class="mcs-donut-mid"><strong>' . self::e(Text::fa($total)) . '</strong><span>' . Lang::t('باز') . '</span></div></div><ul class="mcs-legend">' . $legend . '</ul></div>';
    }

    /**
     * New findings (above the line) and fixed ones (below it) per day. @param array<string,int> $new day => n
     * @param array<string,int> $fixed @param string[] $days oldest first (Y-m-d)
     */
    public static function days(array $days, array $new, array $fixed): string
    {
        $n = count($days);
        $max = max(1, max(array_map(fn ($d) => (int) ($new[$d] ?? 0), $days) ?: [0]), max(array_map(fn ($d) => (int) ($fixed[$d] ?? 0), $days) ?: [0]));
        $w = 280;
        $mid = 52;
        $room = 44;
        $bw = max(4, (int) floor(($w - 16) / max(1, $n)) - 4);
        $bars = '';
        $sumNew = 0;
        $sumFixed = 0;
        foreach ($days as $i => $d) {
            $a = (int) ($new[$d] ?? 0);
            $b = (int) ($fixed[$d] ?? 0);
            $sumNew += $a;
            $sumFixed += $b;
            $x = self::x($i, $n, $w, 8 + $bw / 2) - $bw / 2;
            if ($a > 0) {
                $h = max(3, round($room * $a / $max, 1));
                $bars .= '<rect class="mcs-bar-new" x="' . $x . '" y="' . ($mid - 1 - $h) . '" width="' . $bw . '" height="' . $h . '" rx="2"><title>' . self::e(Lang::t('{day}: {n} تازه', ['day' => Text::ymd($d), 'n' => Text::fa($a)])) . '</title></rect>';
            }
            if ($b > 0) {
                $h = max(3, round($room * $b / $max, 1));
                $bars .= '<rect class="mcs-bar-fixed" x="' . $x . '" y="' . ($mid + 1) . '" width="' . $bw . '" height="' . $h . '" rx="2"><title>' . self::e(Lang::t('{day}: {n} رفع‌شده', ['day' => Text::ymd($d), 'n' => Text::fa($b)])) . '</title></rect>';
            }
        }
        $label = Lang::t('{days} روز اخیر: {new} یافته‌ی تازه، {fixed} رفع‌شده', ['days' => Text::fa($n), 'new' => Text::fa($sumNew), 'fixed' => Text::fa($sumFixed)]);
        return '<figure class="mcs-days"><svg viewBox="0 0 ' . $w . ' 104" role="img" aria-label="' . self::e($label) . '" preserveAspectRatio="none">'
            . '<line class="mcs-axis" x1="0" x2="' . $w . '" y1="' . $mid . '" y2="' . $mid . '"/>' . $bars . '</svg>'
            . '<figcaption><span><i class="mcs-key mcs-key-new" aria-hidden="true"></i>' . self::e(Lang::t('تازه: {n}', ['n' => Text::fa($sumNew)])) . '</span><span><i class="mcs-key mcs-key-fixed" aria-hidden="true"></i>' . self::e(Lang::t('رفع‌شده: {n}', ['n' => Text::fa($sumFixed)])) . '</span>'
            . '<span class="mcs-muted">' . self::e(Lang::t('{n} روز اخیر', ['n' => Text::fa($n)])) . '</span></figcaption></figure>';
    }

    /** The score over time as a filled line, with the two ceilings (49 and 79) as faint guides. @param array<int,array{day?:string,score:int}> $points */
    public static function area(array $points, int $now): string
    {
        $points = array_values($points);
        $n = count($points);
        if ($n < 2) {
            return '<div class="mcs-chart-empty"><p class="mcs-muted mcs-small">' . Lang::t('نمودار روند از دومین روزِ اسکن پر می‌شود.') . '</p></div>';
        }
        $w = 280;
        $h = 104;
        $y = fn (int $s) => round($h - 6 - (max(0, min(100, $s)) / 100) * ($h - 14), 1);
        $xy = [];
        foreach ($points as $i => $p) {
            $xy[] = self::x($i, $n, $w, 4) . ',' . $y((int) $p['score']);
        }
        $first = explode(',', $xy[0]);
        $last = explode(',', $xy[$n - 1]);
        $fill = $first[0] . ',' . ($h - 2) . ' ' . implode(' ', $xy) . ' ' . $last[0] . ',' . ($h - 2);
        $min = min(array_map(fn ($p) => (int) $p['score'], $points));
        $max = max(array_map(fn ($p) => (int) $p['score'], $points));
        $id = 'mcs-g-' . substr(md5(implode(' ', $xy)), 0, 8);
        return '<figure class="mcs-area"><svg viewBox="0 0 ' . $w . ' ' . $h . '" role="img" preserveAspectRatio="none" aria-label="' . self::e(Lang::t('روند امتیاز در {n} روز: از {from} به {to}', ['n' => Text::fa($n), 'from' => Text::fa((int) $points[0]['score']), 'to' => Text::fa($now)])) . '">'
            . '<defs><linearGradient id="' . $id . '" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="currentColor" stop-opacity=".28"/><stop offset="1" stop-color="currentColor" stop-opacity="0"/></linearGradient></defs>'
            . '<line class="mcs-guide-line" x1="0" x2="' . $w . '" y1="' . $y(79) . '" y2="' . $y(79) . '"/><line class="mcs-guide-line" x1="0" x2="' . $w . '" y1="' . $y(49) . '" y2="' . $y(49) . '"/>'
            . '<polygon points="' . $fill . '" fill="url(#' . $id . ')"/><polyline points="' . implode(' ', $xy) . '" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>'
            . '<circle cx="' . $last[0] . '" cy="' . $last[1] . '" r="3.5" fill="currentColor"/></svg>'
            . '<figcaption><span>' . self::e(Lang::t('اکنون: {n}', ['n' => Text::fa($now)])) . '</span><span class="mcs-muted">' . self::e(Lang::t('کمترین {min} · بیشترین {max}', ['min' => Text::fa($min), 'max' => Text::fa($max)])) . '</span><span class="mcs-muted">' . self::e(Lang::t('{n} روز', ['n' => Text::fa($n)])) . '</span></figcaption></figure>';
    }

    /** Horizontal bars. @param array<int,array{0:string,1:int,2?:string}> $rows label, number, link */
    public static function hbars(array $rows): string
    {
        $max = max(1, max(array_map(fn ($r) => (int) $r[1], $rows) ?: [0]));
        $h = '<ul class="mcs-hbars">';
        foreach ($rows as $r) {
            $n = (int) $r[1];
            $label = self::e($r[0]);
            $h .= '<li><span class="mcs-hbar-label">' . (!empty($r[2]) && $n > 0 ? '<a href="' . self::e($r[2]) . '">' . $label . '</a>' : $label) . '</span>'
                . '<span class="mcs-hbar" aria-hidden="true"><i style="inline-size:' . ($n > 0 ? max(3, (int) round(100 * $n / $max)) : 0) . '%"></i></span><strong>' . self::e(Text::fa($n)) . '</strong></li>';
        }
        return $h . '</ul>';
    }

    /**
     * The radar of the console: one dot per asset, nearer the centre the lower its score, coloured by its state.
     * Decoration with meaning; the same facts are in the tiles and the asset list. @param array<int,array{name:string,score:int,tone:string}> $blips
     */
    public static function radar(array $blips): string
    {
        $dots = '';
        foreach (array_slice($blips, 0, 24) as $b) {
            $hash = crc32($b['name']);
            $angle = deg2rad($hash % 360);
            $dist = $b['score'] < 0 ? 78 : 18 + 62 * (max(0, min(100, $b['score'])) / 100);
            $x = round(100 + cos($angle) * $dist, 1);
            $y = round(100 + sin($angle) * $dist, 1);
            $dots .= '<g class="mcs-blip mcs-blip-' . self::e($b['tone']) . '"><circle class="mcs-blip-ring" cx="' . $x . '" cy="' . $y . '" r="4"/><circle cx="' . $x . '" cy="' . $y . '" r="3.2"/><title>' . self::e($b['name']) . '</title></g>';
        }
        return '<div class="mcs-radar" aria-hidden="true"><svg viewBox="0 0 200 200" focusable="false">'
            . '<defs><linearGradient id="mcs-sweep" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="currentColor" stop-opacity=".55"/><stop offset="1" stop-color="currentColor" stop-opacity="0"/></linearGradient></defs>'
            . '<circle class="mcs-radar-ring" cx="100" cy="100" r="92"/><circle class="mcs-radar-ring" cx="100" cy="100" r="62"/><circle class="mcs-radar-ring" cx="100" cy="100" r="32"/>'
            . '<path class="mcs-radar-ring" d="M100 8v184M8 100h184"/><path class="mcs-radar-sweep" d="M100 100 100 8A92 92 0 0 1 192 100Z" fill="url(#mcs-sweep)"/>' . $dots
            . '<circle class="mcs-radar-core" cx="100" cy="100" r="3"/></svg></div>';
    }

    /**
     * The path of a scan as steps. @param array<int,array{label:string,sub?:string}> $steps
     * $active: index of the step being done; $state: run | done | fail | stop
     */
    public static function pipeline(array $steps, int $active, string $state): string
    {
        $h = '<ol class="mcs-pipe mcs-pipe-' . self::e($state) . '" data-mcs-steps>';
        foreach ($steps as $i => $s) {
            $cls = $state === 'done' || $i < $active ? 'is-done' : ($i === $active ? ($state === 'fail' ? 'is-fail' : ($state === 'stop' ? 'is-stop' : 'is-active')) : 'is-todo');
            $h .= '<li class="' . $cls . '"' . ($i === $active && $state === 'run' ? ' aria-current="step"' : '') . '><span class="mcs-pipe-dot" aria-hidden="true">' . Ui::ico($cls === 'is-done' ? 'check' : ($cls === 'is-fail' ? 'x' : 'radar')) . '</span>'
                . '<span class="mcs-pipe-text"><strong>' . self::e($s['label']) . '</strong>' . (!empty($s['sub']) ? '<small>' . $s['sub'] . '</small>' : '') . '</span></li>';
        }
        return $h . '</ol>';
    }
}
