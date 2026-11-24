<?php
// Writes a sample report PDF with the current template: php tests/tools/pdf_sample.php <out.pdf> [fa|en] [key=value ...]
// Needs TCPDF in tests/tmp/tcpdf (WHMCS ships its own). Settings given as key=value are set for this run only (SQLite in memory).
declare(strict_types=1);
require dirname(__DIR__) . '/bootstrap.php';
$tc = dirname(__DIR__) . '/tmp/tcpdf/tcpdf.php';
if (!is_file($tc)) {
    fwrite(STDERR, "TCPDF not found in tests/tmp/tcpdf\n");
    exit(1);
}
require_once $tc;
\McSec\Clock::$fixed = strtotime('2026-11-24T10:00:00Z');
$out = $argv[1] ?? (sys_get_temp_dir() . '/mcsec-sample.pdf');
\McSec\Lang::$force = ($argv[2] ?? 'fa') === 'en' ? 'en' : 'fa';
foreach (array_slice($argv, 3) as $kv) {
    [$k, $v] = array_pad(explode('=', $kv, 2), 2, '');
    if (str_starts_with($v, '@')) {
        \McSec\Blobs::put($k, (string) file_get_contents(substr($v, 1)));
    } else {
        setting($k, $v);
    }
}
$bytes = \McSec\Pdf::render(\McSec\Pdf::sample());
file_put_contents($out, $bytes);
echo $out . ' ' . strlen($bytes) . " bytes\n";
