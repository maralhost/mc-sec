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

    // ── 0.17.0: the dashboard's pictures ──

    /** The line of a stat card: 14 values as a soft filled curve along the card's foot (decoration; the number is above it). */
    public static function mini(array $vals): string
    {
        $vals = array_values(array_map('intval', $vals));
        $n = count($vals);
        if ($n < 2) {
            return '';
        }
        $max = max(1, max($vals));
        $w = 200;
        $h = 44;
        $pts = [];
        foreach ($vals as $i => $v) {
            $pts[] = [self::x($i, $n, $w), round($h - 3 - ($v / $max) * ($h - 10), 1)];
        }
        $d = self::smooth($pts);
        $first = $pts[0];
        $last = $pts[$n - 1];
        return '<svg class="mcs-mini" viewBox="0 0 ' . $w . ' ' . $h . '" preserveAspectRatio="none" aria-hidden="true" focusable="false">'
            . '<path class="mcs-mini-fill" d="' . $d . ' L' . $last[0] . ',' . $h . ' L' . $first[0] . ',' . $h . ' Z"/><path class="mcs-mini-line" d="' . $d . '" vector-effect="non-scaling-stroke"/></svg>';
    }

    /** A smooth path through points (a gentle curve between neighbours; never above or below both of them). @param array<int,array{0:float,1:float}> $pts */
    private static function smooth(array $pts): string
    {
        $d = 'M' . $pts[0][0] . ',' . $pts[0][1];
        for ($i = 1, $n = count($pts); $i < $n; $i++) {
            $mx = round(($pts[$i - 1][0] + $pts[$i][0]) / 2, 1);
            $d .= ' C' . $mx . ',' . $pts[$i - 1][1] . ' ' . $mx . ',' . $pts[$i][1] . ' ' . $pts[$i][0] . ',' . $pts[$i][1];
        }
        return $d;
    }

    /** Round steps for an axis that ends at or above $max. @return int[] from 0 up */
    private static function ticks(int $max): array
    {
        $max = max(4, $max);
        $step = (int) ceil($max / 4);
        foreach ([1, 2, 5, 10, 15, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000] as $nice) {
            if ($nice >= $step) {
                $step = $nice;
                break;
            }
        }
        return [0, $step, 2 * $step, 3 * $step, 4 * $step];
    }

    /** The frame shared by the two big charts: horizontal guides with their numbers and a few dates under the axis. */
    private static function frame(array $days, array $ticks, int $w, int $h, int $padL, int $padB): string
    {
        $top = end($ticks);
        $g = '';
        foreach ($ticks as $t) {
            $y = round(($h - $padB) - ($t / $top) * ($h - $padB - 10), 1);
            $g .= '<line class="mcs-axis" x1="' . $padL . '" x2="' . $w . '" y1="' . $y . '" y2="' . $y . '"/><text class="mcs-tick" x="' . ($padL - 6) . '" y="' . ($y + 3) . '" text-anchor="end">' . $t . '</text>';
        }
        $n = count($days);
        foreach ($days as $i => $day) {
            if ($i % 2 === 0 || $i === $n - 1) {
                $x = $padL + self::x($i, $n, $w - $padL, 8);
                $g .= '<text class="mcs-tick" x="' . $x . '" y="' . ($h - 4) . '" text-anchor="middle">' . self::e(self::dayLabel((string) $day)) . '</text>';
            }
        }
        return $g;
    }

    private static function dayLabel(string $ymd): string
    {
        if (!\McSec\Lang::fa()) {
            return date('M j', (int) strtotime($ymd . ' 12:00:00'));
        }
        $p = array_map('intval', explode('-', $ymd));
        [, $m, $d] = Text::jalali($p[0], $p[1], $p[2]);
        return Text::fa($d) . ' ' . Text::MONTHS[$m - 1];
    }

    /**
     * Several counts over the same days as lines, with a legend that carries today's numbers.
     * @param string[] $days Y-m-d, oldest first @param array<int,array{0:string,1:int[],2:string}> $series label, values, colour
     */
    public static function lines(array $days, array $series): string
    {
        $n = count($days);
        $max = 0;
        foreach ($series as $sr) {
            $max = max($max, max($sr[1] ?: [0]));
        }
        if ($n < 2 || $max === 0) {
            return '<div class="mcs-chart-empty"><p class="mcs-muted mcs-small">' . \McSec\Lang::t('پس از اولین «کشف سطح حمله»، روند این‌جا رسم می‌شود.') . '</p></div>';
        }
        [$w, $h, $padL, $padB] = [720, 250, 34, 22];
        $ticks = self::ticks($max);
        $top = end($ticks);
        $paths = '';
        $legend = '';
        $say = [];
        foreach ($series as [$label, $vals, $color]) {
            $pts = [];
            foreach (array_values($vals) as $i => $v) {
                $pts[] = [$padL + self::x($i, $n, $w - $padL, 8), round(($h - $padB) - ((int) $v / $top) * ($h - $padB - 10), 1)];
            }
            $paths .= '<path d="' . self::smooth($pts) . '" fill="none" stroke="' . $color . '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>';
            $now = (int) end($vals);
            $legend .= '<span><i style="background:' . $color . '" aria-hidden="true"></i>' . self::e(\McSec\Lang::t($label)) . ' <strong>' . self::e(Text::fa($now)) . '</strong></span>';
            $say[] = \McSec\Lang::t($label) . ' ' . Text::fa($now);
        }
        return '<figure class="mcs-big"><svg viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . self::e(\McSec\Lang::t('۱۴ روز اخیر؛ اکنون: {list}', ['list' => \McSec\Lang::join($say)])) . '">'
            . self::frame($days, $ticks, $w, $h, $padL, $padB) . $paths . '</svg><figcaption>' . $legend . '</figcaption></figure>';
    }

    /** One count over the days as a filled curve (open findings). @param string[] $days @param int[] $vals */
    public static function trend(array $days, array $vals, string $what): string
    {
        $n = count($days);
        $vals = array_values(array_map('intval', $vals));
        if ($n < 2 || max($vals ?: [0]) === 0) {
            return '<div class="mcs-chart-empty"><p class="mcs-muted mcs-small">' . \McSec\Lang::t('یافته‌ی بازی در این ۱۴ روز نبوده است.') . '</p></div>';
        }
        [$w, $h, $padL, $padB] = [720, 230, 34, 22];
        $ticks = self::ticks(max($vals));
        $top = end($ticks);
        $pts = [];
        foreach ($vals as $i => $v) {
            $pts[] = [$padL + self::x($i, $n, $w - $padL, 8), round(($h - $padB) - ($v / $top) * ($h - $padB - 10), 1)];
        }
        $d = self::smooth($pts);
        $base = $h - $padB;
        return '<figure class="mcs-big mcs-big-area"><svg viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . self::e(\McSec\Lang::t('۱۴ روز اخیر؛ اکنون: {list}', ['list' => $what . ' ' . Text::fa((int) end($vals))])) . '">'
            . '<defs><linearGradient id="mcs-g-trend" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="currentColor" stop-opacity=".26"/><stop offset="1" stop-color="currentColor" stop-opacity="0"/></linearGradient></defs>'
            . self::frame($days, $ticks, $w, $h, $padL, $padB)
            . '<path d="' . $d . ' L' . $pts[$n - 1][0] . ',' . $base . ' L' . $pts[0][0] . ',' . $base . ' Z" fill="url(#mcs-g-trend)"/><path d="' . $d . '" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" vector-effect="non-scaling-stroke"/></svg></figure>';
    }

    /** The score as a ring with its grade letter (A to F) and the number under it. */
    public static function grade(int $score, bool $partial = false): string
    {
        $letter = $score < 0 ? '—' : ($score >= 90 ? 'A' : ($score >= 75 ? 'B' : ($score >= 60 ? 'C' : ($score >= 50 ? 'D' : 'F'))));
        $tone = $partial ? 'warn' : \McSec\Score::tone($score);
        $word = $partial ? \McSec\Lang::t('ارزیابی ناقص') : \McSec\Lang::t(\McSec\Score::label($score));
        $r = 52;
        $len = 2 * M_PI * $r;
        // three quarters of a circle, open at the foot, like a dial
        $arc = $len * 0.75;
        $fill = round($arc * max(0, $score) / 100, 1);
        return '<div class="mcs-grade mcs-tone-' . $tone . '" role="img" aria-label="' . self::e($score < 0 ? \McSec\Lang::t('امتیاز امنیت ندارد') : \McSec\Lang::t('امتیاز امنیت {score} از ۱۰۰، رتبه‌ی {grade}، {word}', ['score' => Text::fa($score), 'grade' => $letter, 'word' => $word])) . '">'
            . '<svg viewBox="0 0 120 120" aria-hidden="true"><circle class="mcs-grade-track" cx="60" cy="60" r="' . $r . '" stroke-dasharray="' . round($arc, 1) . ' ' . round($len, 1) . '" transform="rotate(135 60 60)"/>'
            . '<circle class="mcs-grade-bar" cx="60" cy="60" r="' . $r . '" stroke-dasharray="' . $fill . ' ' . round($len, 1) . '" transform="rotate(135 60 60)"/></svg>'
            . '<div class="mcs-grade-mid"><span>' . \McSec\Lang::t('امتیاز امنیت') . '</span><strong dir="ltr">' . $letter . '</strong><small>' . ($score < 0 ? self::e($word) : self::e(\McSec\Lang::t('{score} از ۱۰۰', ['score' => Text::fa($score)]))) . '</small></div>'
            . '<p class="mcs-grade-word">' . self::e($word) . '</p></div>';
    }

    /** A ranked list with a bar under each line. @param array<int,array{0:string,1:int,2:string}> $rows name (left-to-right), count, tag */
    public static function ranked(array $rows): string
    {
        $max = max(1, max(array_map(fn ($r) => (int) $r[1], $rows)));
        $h = '<ul class="mcs-ranked">';
        foreach ($rows as [$name, $n, $tag]) {
            $h .= '<li' . ($tag !== '' ? ' class="is-risky"' : '') . '><span class="mcs-ranked-top"><bdi dir="ltr">' . self::e($name) . '</bdi>' . ($tag !== '' ? '<em>' . self::e($tag) . '</em>' : '') . '<strong>' . self::e(Text::fa((int) $n)) . '</strong></span>'
                . '<span class="mcs-ranked-bar" aria-hidden="true"><i style="inline-size:' . max(4, (int) round(100 * (int) $n / $max)) . '%"></i></span></li>';
        }
        return $h . '</ul>';
    }

    /**
     * Rough outlines of the land (longitude, latitude), only to place dots: a dotted world map needs no more, and
     * this way no map file or library comes with the module.
     */
    private const LAND = [
        [[-168, 66], [-156, 71], [-128, 70], [-110, 68], [-95, 72], [-82, 70], [-78, 62], [-64, 60], [-56, 52], [-66, 45], [-70, 42], [-76, 35], [-81, 31], [-80, 25], [-84, 30], [-90, 29], [-97, 26], [-97, 20], [-90, 21], [-87, 16], [-83, 10], [-78, 8], [-80, 7], [-86, 12], [-92, 15], [-105, 20], [-110, 24], [-115, 31], [-124, 40], [-124, 48], [-135, 58], [-152, 58], [-165, 55]],
        [[-55, 60], [-44, 60], [-22, 70], [-20, 80], [-40, 83], [-60, 82], [-72, 78], [-55, 68]],
        [[-78, 8], [-72, 12], [-62, 10], [-52, 4], [-50, 0], [-35, -6], [-39, -15], [-41, -22], [-48, -27], [-54, -34], [-62, -39], [-65, -45], [-68, -54], [-74, -52], [-73, -40], [-71, -30], [-70, -18], [-76, -14], [-81, -5], [-80, 0]],
        [[-17, 21], [-13, 28], [-6, 35], [10, 37], [11, 33], [20, 32], [25, 32], [33, 31], [35, 24], [37, 18], [43, 12], [51, 11], [48, 4], [41, -2], [39, -8], [40, -15], [35, -24], [32, -29], [27, -34], [19, -35], [15, -27], [12, -17], [13, -8], [9, -1], [9, 4], [4, 6], [-4, 5], [-8, 4], [-13, 8], [-17, 14]],
        [[-9, 37], [-9, 43], [-2, 44], [-4, 48], [3, 51], [8, 54], [9, 57], [12, 55], [20, 55], [28, 60], [22, 60], [22, 65], [18, 63], [12, 56], [6, 58], [5, 62], [14, 68], [28, 71], [42, 67], [60, 69], [70, 73], [90, 76], [105, 78], [115, 74], [140, 73], [160, 70], [180, 69], [180, 66], [170, 60], [163, 58], [156, 51], [142, 54], [135, 44], [129, 40], [129, 35], [126, 34], [122, 40], [118, 38], [122, 31], [120, 25], [110, 21], [108, 16], [109, 11], [105, 9], [100, 13], [100, 7], [103, 1], [98, 8], [97, 16], [92, 22], [88, 22], [80, 15], [78, 8], [73, 16], [72, 21], [67, 25], [57, 25], [57, 22], [59, 18], [52, 16], [45, 13], [43, 13], [39, 21], [35, 28], [36, 36], [30, 36], [27, 37], [26, 40], [23, 38], [22, 37], [20, 40], [19, 42], [14, 45], [12, 44], [18, 40], [16, 38], [12, 42], [9, 44], [3, 43], [0, 39], [-5, 36]],
        [[-5, 50], [1, 51], [0, 54], [-2, 58], [-6, 58], [-5, 54]], [[-10, 52], [-6, 52], [-6, 55], [-10, 54]], [[-24, 64], [-14, 64], [-14, 66], [-23, 66]],
        [[130, 31], [136, 34], [141, 36], [142, 42], [145, 44], [141, 45], [139, 38], [133, 35]],
        [[114, -22], [114, -34], [118, -35], [129, -32], [138, -35], [146, -39], [150, -37], [153, -28], [146, -19], [142, -11], [136, -12], [130, -12], [122, -17]],
        [[166, -46], [172, -44], [178, -38], [174, -36], [173, -41], [168, -44]],
        [[95, 5], [104, -5], [106, -6], [100, 2]], [[109, 1], [117, 7], [119, 1], [116, -4], [110, -3]], [[106, -6], [114, -7], [114, -9], [106, -8]], [[131, -1], [141, -3], [150, -6], [147, -10], [141, -9], [134, -4]],
        [[120, 16], [122, 18], [124, 13], [126, 7], [122, 7]], [[44, -25], [47, -25], [50, -16], [49, -12], [44, -17]], [[79, 9], [82, 7], [81, 6], [80, 6]],
    ];

    private static function onLand(float $x, float $y): bool
    {
        foreach (self::LAND as $poly) {
            $in = false;
            $n = count($poly);
            for ($i = 0, $j = $n - 1; $i < $n; $j = $i++) {
                [$xi, $yi] = $poly[$i];
                [$xj, $yj] = $poly[$j];
                if (($yi > $y) !== ($yj > $y) && $x < ($xj - $xi) * ($y - $yi) / ($yj - $yi) + $xi) {
                    $in = !$in;
                }
            }
            if ($in) {
                return true;
            }
        }
        return false;
    }

    /**
     * A dotted world map with a marker for each place. Always west on the left, whatever the language (a map is not
     * text). @param array<int,array{0:float,1:float}> $points longitude, latitude
     */
    public static function world(array $points): string
    {
        static $dots = null;
        if ($dots === null) {
            $dots = '';
            for ($lat = 75; $lat >= -54; $lat -= 3) {
                for ($lon = -168; $lon <= 180; $lon += 3) {
                    if (self::onLand($lon + 0.5, $lat + 0.5)) {
                        $dots .= '<circle cx="' . ($lon + 180) . '" cy="' . (90 - $lat) . '" r="1"/>';
                    }
                }
            }
        }
        $marks = '';
        foreach ($points as $p) {
            $x = round(max(-180.0, min(180.0, (float) $p[0])) + 180, 1);
            $y = round(90 - max(-90.0, min(90.0, (float) $p[1])), 1);
            $marks .= '<circle class="mcs-world-halo" cx="' . $x . '" cy="' . $y . '" r="6"/><circle class="mcs-world-pin" cx="' . $x . '" cy="' . $y . '" r="2.4"/>';
        }
        return '<svg class="mcs-world" viewBox="8 10 356 138" role="img" aria-label="' . self::e(Lang::t('نقشه‌ی موقعیت سرورها')) . '" dir="ltr"><g class="mcs-world-land">' . $dots . '</g>' . $marks . '</svg>';
    }
}
