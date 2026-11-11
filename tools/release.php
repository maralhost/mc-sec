<?php
// Builds the release zip: modules/addons/mcsec, modules/servers/mcsecplan and README.md (CLAUDE.md "release").
// The zip goes to releases/ (git-ignored) and is published on GitHub Releases, never committed. Refuses to build when
// anything that must not ship is found (secrets, test data, fonts, the staging credentials of the backends).
//   php tools/release.php
declare(strict_types=1);

$root = dirname(__DIR__);
$boot = (string) file_get_contents($root . '/modules/addons/mcsec/bootstrap.php');
if (!preg_match("~define\('MCSEC_VERSION', '([0-9]+\.[0-9]+\.[0-9]+)'\)~", $boot, $m)) {
    fwrite(STDERR, "MCSEC_VERSION not found in bootstrap.php\n");
    exit(1);
}
$version = $m[1];
$include = ['modules/addons/mcsec', 'modules/servers/mcsecplan', 'README.md'];
$files = [];
foreach ($include as $rel) {
    $path = $root . '/' . $rel;
    if (is_file($path)) {
        $files[] = $rel;
        continue;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        $files[] = str_replace('\\', '/', substr($f->getPathname(), strlen($root) + 1));
    }
}
sort($files);
$bad = [];
foreach ($files as $rel) {
    if (preg_match('~(^|/)(\.env|.*\.(sqlite|log|sql|bak|orig|swp|ttf|otf|woff2?|eot|zip)|\.DS_Store|Thumbs\.db|desktop\.ini)$~i', $rel)) {
        $bad[] = $rel . ' (file type)';
        continue;
    }
    $text = (string) file_get_contents($root . '/' . $rel);
    if (preg_match('~sk-[A-Za-z0-9]{20,}|nap_[A-Za-z0-9]{20,}|BEGIN (RSA |EC )?PRIVATE KEY|\d{8,10}:AA[A-Za-z0-9_-]{30,}~', $text)) {
        $bad[] = $rel . ' (looks like a secret)';
    }
    // the backends' own access (staging host IPs and accounts) never ships; compared by hash so it is not written here
    preg_match_all('~[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\b\d{1,3}(?:\.\d{1,3}){3}\b~', $text, $tokens);
    foreach ($tokens[0] as $tok) {
        if (in_array(hash('sha256', strtolower($tok)), [
            '144e6a65cb4945641636b0d7299c723db38dcf976a9a3658e247d6b66fa3737a', // OASM staging login
            '6f14d76af4c12fb30668f6ed27f19f70324c8a794592fbf45428b2efbabd693a', // Osmedeus server address
        ], true)) {
            $bad[] = $rel . ' (backend access detail)';
        }
    }
    if (str_ends_with($rel, '.php') && !str_contains($text, '<?php')) {
        $bad[] = $rel . ' (php without open tag)';
    }
}
if ($bad) {
    fwrite(STDERR, "REFUSED, these must not ship:\n  " . implode("\n  ", $bad) . "\n");
    exit(1);
}
@mkdir($root . '/releases');
$zipPath = $root . '/releases/mcsec-' . $version . '.zip';
@unlink($zipPath);
$zip = new ZipArchive();
if ($zip->open($zipPath, ZipArchive::CREATE) !== true) {
    fwrite(STDERR, "cannot create {$zipPath}\n");
    exit(1);
}
foreach ($files as $rel) {
    $zip->addFile($root . '/' . $rel, $rel);
    $zip->setMtimeName($rel, 1767225600);
}
$zip->close();
printf("releases/mcsec-%s.zip: %d files, %s KB, sha256 %s\n", $version, count($files), number_format(filesize($zipPath) / 1024, 1), hash_file('sha256', $zipPath));
