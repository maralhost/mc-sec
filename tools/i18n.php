<?php
/**
 * MC-Sec: checks the English of everything a customer sees.
 *
 *   php tools/i18n.php                 every customer-facing file
 *   php tools/i18n.php lib/Scans.php   only these (paths under modules/addons/mcsec/, or the server module's file)
 *
 * The Persian text in the code is the key; modules/addons/mcsec/lang/en/*.php hold [Persian => English].
 * Rules it checks:
 *  1. every Persian string literal in a customer-facing file is a key of the dictionary (so a sentence built from
 *     pieces has to become one Lang::t('… {x} …') with placeholders, not three fragments);
 *  2. a translation has no Persian or Arabic letters left, and the same {placeholders} as its key;
 *  3. no key is defined twice with two different translations.
 * Not for customers, so skipped: a line that has the comment i18n-skip, the lines between i18n-skip-begin and
 * i18n-skip-end, and the files in SKIP (admin panel, settings, installer, technical log, scan journal, changelog).
 * Exit code 1 when something is missing. Reads files only.
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$mod = $root . '/modules/addons/mcsec/';
const SKIP = ['lib/Admin/', 'lib/Installer.php', 'lib/Settings.php', 'lib/Trace.php', 'lib/ScanLog.php', 'lib/Lang.php', 'changelog.php', 'lang/'];

$dict = [];
$problems = [];
foreach (glob($mod . 'lang/en/*.php') ?: [] as $f) {
    $d = include $f;
    foreach (is_array($d) ? $d : [] as $k => $v) {
        $k = (string) $k;
        if (isset($dict[$k]) && $dict[$k] !== $v) {
            $problems[] = basename($f) . ': a second, different translation of «' . mb_substr($k, 0, 60) . '»';
        }
        $dict[$k] = (string) $v;
        if (preg_match('~[\x{0600}-\x{06FF}]~u', (string) $v)) {
            $problems[] = basename($f) . ': Persian letters left in the translation of «' . mb_substr($k, 0, 60) . '»';
        }
        preg_match_all('~\{[a-z0-9_]+\}~', $k, $a);
        preg_match_all('~\{[a-z0-9_]+\}~', (string) $v, $b);
        sort($a[0]);
        sort($b[0]);
        if ($a[0] !== $b[0]) {
            $problems[] = basename($f) . ': placeholders differ in «' . mb_substr($k, 0, 60) . '»';
        }
    }
}

$files = [];
$args = array_slice($argv, 1);
if ($args) {
    foreach ($args as $a) {
        $files[] = is_file($a) ? $a : (is_file($mod . $a) ? $mod . $a : $root . '/' . $a);
    }
} else {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($mod, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if ($f->getExtension() === 'php') {
            $files[] = str_replace('\\', '/', $f->getPathname());
        }
    }
    $files[] = $root . '/modules/servers/mcsecplan/mcsecplan.php';
    sort($files);
}

$missing = 0;
foreach ($files as $file) {
    $rel = str_replace(str_replace('\\', '/', $mod), '', str_replace('\\', '/', $file));
    if (!$args) {
        foreach (SKIP as $s) {
            if (str_starts_with($rel, $s)) {
                continue 2;
            }
        }
    }
    $src = (string) file_get_contents($file);
    $lines = explode("\n", $src);
    $skip = [];
    $in = false;
    foreach ($lines as $i => $l) {
        if (str_contains($l, 'i18n-skip-begin')) {
            $in = true;
        }
        if ($in || str_contains($l, 'i18n-skip')) {
            $skip[$i + 1] = true;
        }
        if (str_contains($l, 'i18n-skip-end')) {
            $in = false;
        }
    }
    $out = [];
    foreach (token_get_all($src) as $t) {
        if (!is_array($t) || !in_array($t[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true) || !preg_match('~[\x{0600}-\x{06FF}]~u', $t[1])) {
            continue;
        }
        $line = $t[2];
        $span = substr_count($t[1], "\n");
        for ($i = $line; $i <= $line + $span; $i++) {
            if (isset($skip[$i])) {
                continue 2;
            }
        }
        $val = $t[0] === T_CONSTANT_ENCAPSED_STRING ? stripcslashes_php($t[1]) : $t[1];
        if (!isset($dict[$val])) {
            $out[] = '  ' . $line . ': ' . mb_substr(str_replace("\n", '⏎', $val), 0, 110);
        }
    }
    if ($out) {
        $missing += count($out);
        echo $rel . ' (' . count($out) . ")\n" . implode("\n", $out) . "\n";
    }
}
foreach (array_unique($problems) as $p) {
    echo 'DICT: ' . $p . "\n";
}
echo ($missing === 0 && !$problems ? 'OK' : 'MISSING ' . $missing . ', dictionary problems ' . count(array_unique($problems))) . ' (' . count($dict) . " entries)\n";
exit($missing === 0 && !$problems ? 0 : 1);

/** The value of a quoted PHP string literal. */
function stripcslashes_php(string $lit): string
{
    $q = $lit[0];
    $body = substr($lit, 1, -1);
    if ($q === "'") {
        return str_replace(["\\\\", "\\'"], ["\\", "'"], $body);
    }
    return stripcslashes($body);
}
