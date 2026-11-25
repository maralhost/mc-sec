<?php

declare(strict_types=1);

namespace McSec;

/**
 * A report as a real PDF file, made on the server with TCPDF, the library WHMCS itself ships for invoices (no file is
 * added to the module: rule 5). Since 0.14.0 it is laid out as a professional report and follows the admin's template
 * («قالب گزارش»): a cover with the logo, the score and the severity counts; a header and footer on every page; a table
 * of contents; a numbered summary, the assets, an index of the findings, each finding as a card with its facts and
 * fix, the attack surface, the scans, and a page on method and limits.
 *
 * Fonts: Persian needs a font with Arabic presentation forms. WHMCS has DejaVu Sans and FreeSans (both shape
 * پ چ ژ گ ی and the ZWNJ correctly); an admin may upload their own TTF (kept in the database by Blobs, converted once
 * into a cache folder outside the module). When TCPDF or a usable font is missing, available() is false and the
 * report page keeps only the browser's "print or PDF" button.
 *
 * Everything in the PDF is escaped text from Reports::data (the same data the page shows) and the admin's own
 * settings: no network, no file read except the font cache. Left-to-right tokens (domains, URLs, CVE ids) are wrapped
 * in bidi embedding marks, or TCPDF would reverse them inside a Persian sentence.
 */
final class Pdf
{
    private const SEV_COLOR = ['critical' => '#b4123a', 'high' => '#c2410c', 'medium' => '#a16207', 'low' => '#1d4ed8', 'info' => '#475569'];
    private const SEV_SOFT = ['critical' => '#fde8ee', 'high' => '#ffedd5', 'medium' => '#fef3c7', 'low' => '#dbeafe', 'info' => '#f1f5f9'];
    /** Glyphs TCPDF's shaping puts on the page for Persian: a font without them prints empty boxes. */
    private const NEEDS = [0xFE8E, 0xFB57, 0xFB7B, 0xFB8B, 0xFB93, 0xFBFD, 0xFB8F, 0x0041];
    public const PAGES = ['A4', 'LETTER'];

    // ── the template (admin settings, each with a safe default) ──

    /** A #rrggbb colour from a setting, or the default when it is not one. */
    public static function color(string $key, string $default): string
    {
        $v = strtolower(trim(Settings::get($key)));
        return preg_match('~^#[0-9a-f]{6}$~', $v) ? $v : $default;
    }

    /** @return int[] r, g, b */
    private static function rgb(string $hex): array
    {
        return [hexdec(substr($hex, 1, 2)), hexdec(substr($hex, 3, 2)), hexdec(substr($hex, 5, 2))];
    }

    /** The name on the report: the admin's, or Maral Cloud. */
    /** Set while a PDF is made for an account that prints its own name (white label): ['name' => …, 'contact' => …]. */
    public static ?array $own = null;

    /** May this account put its own name on its PDFs? (setting pdf_whitelabel: '' nobody, * everyone, or account ids) */
    public static function ownAllowed(int $clientId): bool
    {
        $v = trim(Settings::get('pdf_whitelabel'));
        return $v === '*' || ($v !== '' && in_array((string) $clientId, array_map('trim', preg_split('~[\s,،]+~u', $v) ?: []), true)); // i18n-skip (a pattern)
    }

    /** Runs $fn with the account's own name on the PDF, when it may and has set one. */
    public static function asClient(int $clientId, callable $fn)
    {
        $a = self::ownAllowed($clientId) ? Accounts::get($clientId) : null;
        $name = $a ? Text::name((string) ($a->brand_name ?? ''), 60) : '';
        $old = self::$own;
        self::$own = $name !== '' ? ['name' => $name, 'contact' => Text::name((string) ($a->brand_contact ?? ''), 160)] : null;
        try {
            return $fn();
        } finally {
            self::$own = $old;
        }
    }

    public static function brand(): string
    {
        if (self::$own) {
            return (string) self::$own['name'];
        }
        $b = Text::name(Settings::get('pdf_brand'), 60);
        return Lang::t($b !== '' ? $b : 'مارال کلاد');
    }

    /** @return array{primary:string,accent:string,size:int,page:string,cover:bool,toc:bool,index:bool,assets:bool,method:bool,label:string,footer:string,contact:string,disclaimer:string} */
    public static function template(): array
    {
        $page = strtoupper(trim(Settings::get('pdf_page')));
        $label = Text::name(Settings::get('pdf_label'), 40);
        $footer = Text::name(Settings::get('pdf_footer'), 120);
        return [
            'primary' => self::color('pdf_color', '#0b1f3a'), 'accent' => self::color('pdf_accent', '#0ea5e9'),
            'size' => max(8, min(12, Settings::int('pdf_size') ?: 10)), 'page' => in_array($page, self::PAGES, true) ? $page : 'A4',
            'cover' => Settings::bool('pdf_cover'), 'toc' => Settings::bool('pdf_toc'), 'index' => Settings::bool('pdf_index'), 'assets' => Settings::bool('pdf_assets'), 'method' => Settings::bool('pdf_method'),
            'label' => $label === '-' ? '' : Lang::t($label),
            'footer' => self::$own ? self::brand() : ($footer !== '' ? Lang::t($footer) : Lang::t('بخش امنیت سایبری {brand}', ['brand' => self::brand()])),
            'contact' => self::$own ? (string) self::$own['contact'] : Text::name(Settings::get('pdf_contact'), 160),
            'disclaimer' => trim(Settings::get('pdf_disclaimer')),
        ];
    }

    // ── fonts ──

    /** Where converted fonts are kept: outside the module, rebuilt from the database whenever it is missing. */
    private static function fontDir(string $sha): string
    {
        return rtrim(str_replace('\\', '/', sys_get_temp_dir()), '/') . '/mcsec-fonts-' . substr($sha, 0, 16) . '/';
    }

    /**
     * The uploaded font, converted for TCPDF. @return array{name:string,file:string,bold:string,error:string}
     * 'name' is '' when there is none or it cannot be used ('error' says why, for the admin page).
     */
    public static function customFont(): array
    {
        static $memo = null;
        if ($memo !== null && !defined('MCSEC_TESTING')) {
            return $memo;
        }
        $none = fn (string $why = '') => ['name' => '', 'file' => '', 'bold' => '', 'error' => $why];
        $reg = Blobs::get('pdf_font');
        if ($reg === null || !class_exists('\\TCPDF_FONTS')) {
            return $memo = $none();
        }
        $bold = Blobs::get('pdf_font_bold');
        $dir = self::fontDir(sha1($reg['sha'] . '|' . ($bold['sha'] ?? '')));
        try {
            if (!is_file($dir . 'mcsfont.php')) {
                if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
                    return $memo = $none('پوشه‌ی موقت سرور نوشتنی نیست.'); // i18n-skip (admin page)
                }
                foreach (['mcsfont' => $reg, 'mcsfontb' => $bold] as $name => $blob) {
                    if ($blob === null) {
                        continue;
                    }
                    file_put_contents($dir . $name . '.ttf', $blob['bytes']);
                    $made = @\TCPDF_FONTS::addTTFfont($dir . $name . '.ttf', 'TrueTypeUnicode', '', 32, $dir);
                    @unlink($dir . $name . '.ttf');
                    if ($made !== $name || !is_file($dir . $name . '.php')) {
                        @unlink($dir . 'mcsfont.php');
                        return $memo = $none('این فایل فونت خوانده نشد.'); // i18n-skip (admin page)
                    }
                }
            }
            $cw = (static function (string $f): array {
                $cw = [];
                include $f;
                return is_array($cw) ? $cw : [];
            })($dir . 'mcsfont.php');
            foreach (self::NEEDS as $glyph) {
                if (empty($cw[$glyph])) {
                    return $memo = $none('این فونت شکل‌های چسبان حروف فارسی (Arabic Presentation Forms) را ندارد و در PDF مربع خالی چاپ می‌شود. فونت دیگری بگذارید.'); // i18n-skip (admin page)
                }
            }
        } catch (\Throwable $e) {
            return $memo = $none('این فایل فونت خوانده نشد.'); // i18n-skip (admin page)
        }
        return $memo = ['name' => 'mcsfont', 'file' => $dir . 'mcsfont.php', 'bold' => is_file($dir . 'mcsfontb.php') ? $dir . 'mcsfontb.php' : $dir . 'mcsfont.php', 'error' => ''];
    }

    /** A font TCPDF itself has, or ''. */
    private static function builtin(): string
    {
        if (!class_exists('\\TCPDF') || !defined('K_PATH_FONTS')) {
            // TCPDF defines its paths when the class file is loaded; a build without them cannot be trusted
            return '';
        }
        $want = strtolower(trim(Settings::get('pdf_font')));
        foreach (array_unique([$want, 'dejavusans', 'freesans']) as $f) {
            if (in_array($f, ['dejavusans', 'freesans'], true) && is_file(K_PATH_FONTS . $f . '.php')) {
                return $f;
            }
        }
        return '';
    }

    /** The font to use, or '' when no PDF can be made here. */
    public static function font(): string
    {
        $b = self::builtin();
        if ($b === '' && !class_exists('\\TCPDF')) {
            return '';
        }
        if (in_array(strtolower(trim(Settings::get('pdf_font'))), ['dejavusans', 'freesans'], true)) {
            return $b;
        }
        $c = self::customFont();
        return $c['name'] !== '' ? $c['name'] : $b;
    }

    public static function available(): bool
    {
        return self::font() !== '';
    }

    // ── text ──

    private static function e($s): string
    {
        return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** A left-to-right token inside Persian text: embedded so it keeps its order; hyphens kept from breaking lines. */
    public static function ltr($s): string
    {
        $s = trim((string) $s);
        if (!Lang::fa()) {
            return self::e(mb_substr($s, 0, 300)); // a left-to-right page needs no embedding marks
        }
        return $s === '' ? '' : "\u{202A}" . self::e(str_replace('-', "\u{2011}", mb_substr($s, 0, 300))) . "\u{202C}";
    }

    /** Escaped Persian text in which Latin runs with digits or dots (versions, CVE ids, "HTTP 502") keep their order. */
    public static function text($s): string
    {
        if (!Lang::fa()) {
            return self::e($s); // English page: plain escaped text (a dictionary text is given in English)
        }
        // a Latin run may be several words ("Let's Encrypt", "Zone Editor", "HTTP 502"): embedded as one, so the words
        // keep their order; the run is found in the raw text and each piece is escaped on its own
        $parts = preg_split('~([A-Za-z][A-Za-z0-9._:/@+\'\x{2011}=-]*(?: [A-Za-z0-9][A-Za-z0-9._:/@+\'\x{2011}=-]*)*)~u', str_replace('-', "\u{2011}", (string) $s), -1, PREG_SPLIT_DELIM_CAPTURE) ?: [];
        $out = '';
        foreach ($parts as $i => $p) {
            $out .= $i % 2 === 1 ? "\u{202A}" . self::e($p) . "\u{202C}" : self::e($p);
        }
        return $out;
    }

    private static function code(string $code): string
    {
        $lines = array_slice(preg_split('~\r\n|\r|\n~', mb_substr($code, 0, 1500)) ?: [], 0, 24);
        $h = implode('<br>', array_map(fn ($l) => str_replace(' ', '&nbsp;', self::e($l)), $lines));
        return '<table cellpadding="6"><tr><td dir="ltr" align="left" style="background-color:#0f172a;font-size:8pt;color:#e2e8f0">' . $h . '</td></tr></table>';
    }

    private static function scoreColor(int $score): string
    {
        return $score < 0 ? '#64748b' : ($score < 50 ? '#b91c1c' : ($score < 75 ? '#b45309' : '#15803d'));
    }

    private static function scoreWord(int $score): string
    {
        return $score < 0 ? Lang::t('بی‌اسکن') : Lang::t(Score::label($score));
    }

    // ── the body: numbered sections, each a small HTML subset TCPDF understands ──

    /** @return array<int,array{0:string,1:string|string[]}> [title, html or pieces that may each start a page] in order. $d = Reports::data(). */
    public static function sections(array $d): array
    {
        $t = self::template();
        $ai = is_array($d['ai'] ?? null) ? $d['ai'] : null;
        $score = (int) ($d['score'] ?? -1);
        $c = (array) ($d['counts'] ?? []);
        $start = Lang::rtl() ? 'right' : 'left';
        $th = fn (string $label, string $w, string $align = '') => '<td width="' . $w . '" align="' . ($align !== '' ? $align : $start) . '" style="background-color:' . $t['primary'] . ';color:#ffffff;font-weight:bold;font-size:8pt">' . self::e(Lang::t($label)) . '</td>';
        $out = [];

        // 1. summary: the words, then the numbers as a strip and one bar
        $h = $ai && (string) ($ai['executive_summary'] ?? '') !== '' ? '<p>' . nl2br(self::text($ai['executive_summary'])) . '</p>'
            : '<ul>' . implode('', array_map(fn ($l) => '<li>' . self::text($l) . '</li>', (array) ($d['basic_summary'] ?? []))) . '</ul>';
        $total = 0;
        $boxes = '<td width="20%" align="center" style="border:1px solid #e2e8f0;background-color:#f8fafc"><span style="font-size:8pt;color:#64748b">' . Lang::t('امتیاز امنیت') . '</span><br><span style="font-size:17pt;font-weight:bold;color:' . self::scoreColor($score) . '">'
            . ($score < 0 ? '—' : self::e(Text::fa($score))) . '</span><br><span style="font-size:8pt">' . self::e($score < 0 ? self::scoreWord($score) : Lang::t('{label} (از ۱۰۰)', ['label' => self::scoreWord($score)])) . '</span></td>';
        foreach (Findings::SEVERITIES as $k => $s) {
            $n = (int) ($c[$k] ?? 0);
            $total += $n;
            $boxes .= '<td width="16%" align="center" style="border:1px solid #e2e8f0;background-color:' . self::SEV_SOFT[$k] . '"><span style="font-size:8pt;color:' . self::SEV_COLOR[$k] . '">' . self::e(Lang::t($s['label'])) . '</span><br>'
                . '<span style="font-size:17pt;font-weight:bold;color:' . self::SEV_COLOR[$k] . '">' . self::e(Text::fa($n)) . '</span><br><span style="font-size:8pt;color:#64748b">' . Lang::t('یافته‌ی باز') . '</span></td>';
        }
        $h .= '<table cellpadding="5" nobr="true"><tr>' . $boxes . '</tr></table>';
        if ($total > 0) {
            $bar = '';
            $left = 100;
            $shown = array_filter(array_keys(Findings::SEVERITIES), fn ($k) => (int) ($c[$k] ?? 0) > 0);
            foreach ($shown as $i => $k) {
                $w = $k === end($shown) ? $left : max(4, (int) round(100 * (int) $c[$k] / $total));
                $w = min($w, $left - 4 * (count($shown) - 1 - array_search($k, array_values($shown), true)));
                $left -= $w;
                $bar .= '<td width="' . $w . '%" align="center" style="background-color:' . self::SEV_COLOR[$k] . ';color:#ffffff;font-size:7pt">' . self::e(Text::fa((int) $c[$k])) . '</td>';
            }
            $h .= '<br><table cellpadding="2" nobr="true"><tr>' . $bar . '</tr></table>';
        }
        $out[] = [Lang::t('خلاصه‌ی مدیریتی'), $h];

        // 2. the assets in scope
        $assets = (array) ($d['assets'] ?? []);
        if ($t['assets'] && $assets) {
            $rows = '';
            foreach (array_slice($assets, 0, 40) as $i => $a) {
                $ac = (array) ($a['counts'] ?? []);
                $sc = (int) ($a['score'] ?? -1);
                $bg = $i % 2 ? '#f8fafc' : '#ffffff';
                $rows .= '<tr><td width="40%" style="background-color:' . $bg . '">' . self::ltr($a['value'] ?? '') . '</td><td width="12%" align="center" style="background-color:' . $bg . ';font-weight:bold;color:' . self::scoreColor($sc) . '">' . ($sc < 0 ? '—' : self::e(Text::fa($sc))) . '</td>';
                foreach (['critical', 'high', 'medium', 'low'] as $k) {
                    $n = (int) ($ac[$k] ?? 0);
                    $rows .= '<td width="12%" align="center" style="background-color:' . $bg . ';color:' . ($n > 0 ? self::SEV_COLOR[$k] : '#94a3b8') . ($n > 0 ? ';font-weight:bold' : '') . '">' . self::e(Text::fa($n)) . '</td>';
                }
                $rows .= '</tr>';
            }
            $out[] = [Lang::t('دارایی‌های بررسی‌شده'), '<table cellpadding="4"><tr>' . $th('دارایی', '40%') . $th('امتیاز', '12%', 'center') . $th('بحرانی', '12%', 'center') . $th('بالا', '12%', 'center') . $th('متوسط', '12%', 'center') . $th('پایین', '12%', 'center') . '</tr>' . $rows . '</table>'
                . (count($assets) > 40 ? '<p style="font-size:8pt;color:#64748b">' . Lang::t('و {n} دارایی دیگر.', ['n' => self::e(Text::fa(count($assets) - 40))]) . '</p>' : '')];
        }

        // 3. what the model wrote, when there is a model
        if ($ai) {
            $h = '';
            if (!empty($ai['key_risks'])) {
                $h .= '<p style="font-weight:bold;color:' . $t['primary'] . '">' . Lang::t('ریسک‌های اصلی') . '</p>';
                foreach ((array) $ai['key_risks'] as $k) {
                    $h .= '<table cellpadding="5" nobr="true"><tr><td width="1.5%" style="background-color:#b91c1c"></td><td width="98.5%" style="background-color:#fef2f2"><b>' . self::text($k['title'] ?? '') . '</b><br>' . self::text($k['impact'] ?? '') . '</td></tr></table><br>';
                }
            }
            if (!empty($ai['quick_wins'])) {
                $h .= '<p style="font-weight:bold;color:' . $t['primary'] . '">' . Lang::t('کارهای سریع (کمتر از یک ساعت)') . '</p><ul>' . implode('', array_map(fn ($q) => '<li>' . self::text($q) . '</li>', (array) $ai['quick_wins'])) . '</ul>';
            }
            if (!empty($ai['plan'])) {
                $rows = '';
                foreach ((array) $ai['plan'] as $i => $p) {
                    $bg = $i % 2 ? '#f8fafc' : '#ffffff';
                    $rows .= '<tr><td width="24%" style="background-color:' . $bg . ';font-weight:bold">' . self::text($p['when'] ?? '') . '</td><td width="76%" style="background-color:' . $bg . '">' . self::text($p['action'] ?? '') . '</td></tr>';
                }
                $h .= '<p style="font-weight:bold;color:' . $t['primary'] . '">' . Lang::t('برنامه‌ی پیشنهادی') . '</p><table cellpadding="4"><tr>' . $th('زمان', '24%') . $th('کار', '76%') . '</tr>' . $rows . '</table>';
            }
            if ($h !== '') {
                $out[] = [Lang::t('ریسک‌ها و برنامه‌ی پیشنهادی'), $h];
            }
        }

        // 4. the findings as a list to scan, 5. each finding with its facts and fix
        $fs = (array) ($d['findings'] ?? []);
        if ($t['index'] && $fs) {
            $rows = '';
            foreach ($fs as $i => $f) {
                $sev = (string) ($f['severity'] ?? 'info');
                $bg = $i % 2 ? '#f8fafc' : '#ffffff';
                $rows .= '<tr><td width="7%" align="center" style="background-color:' . $bg . '">' . self::e(Text::fa($i + 1)) . '</td>'
                    . '<td width="13%" align="center" style="background-color:' . (self::SEV_COLOR[$sev] ?? '#475569') . ';color:#ffffff;font-size:8pt;font-weight:bold">' . self::e(Lang::t((string) (Findings::SEVERITIES[$sev]['label'] ?? $sev))) . '</td>'
                    . '<td width="50%" style="background-color:' . $bg . '">' . self::text(Lang::whole((string) ($f['title'] ?? ''))) . (!empty($f['new']) ? ' <span style="color:#b45309;font-size:7pt">(' . Lang::t('تازه') . ')</span>' : '') . '</td>'
                    . '<td width="30%" style="background-color:' . $bg . ';font-size:8pt">' . self::ltr(mb_substr((string) (($f['asset'] ?? '') !== '' ? $f['asset'] : ($f['location'] ?? '')), 0, 60)) . '</td></tr>';
            }
            $out[] = [Lang::t('فهرست یافته‌ها'), '<table cellpadding="4"><tr>' . $th('#', '7%', 'center') . $th('شدت', '13%', 'center') . $th('یافته', '50%') . $th('دارایی', '30%') . '</tr>' . $rows . '</table>'];
        }
        $chunks = $fs ? [] : ['<p>' . Lang::t('یافته‌ی بازی نیست.') . '</p>'];
        foreach ($fs as $i => $f) {
            $sev = (string) ($f['severity'] ?? 'info');
            $col = self::SEV_COLOR[$sev] ?? '#475569';
            $af = $ai['findings'][$f['id'] ?? 0] ?? null;
            $kb = is_array($f['kb'] ?? null) ? $f['kb'] : null;
            $why = $af ? (string) ($af['why'] ?? '') : (string) ($kb['why'] ?? '');
            $steps = $af ? (array) ($af['steps'] ?? []) : (array) ($kb['steps'] ?? []);
            $snip = $af ? ($af['snippet'] ?? null) : ($kb['snippets'][0] ?? null);
            $effort = $af && (string) ($af['effort'] ?? '') !== '' ? (string) $af['effort'] : (string) ($kb['effort'] ?? '');
            $facts = [[Lang::t('محل'), self::ltr($f['location'] ?? '')]];
            if ((string) ($f['cve'] ?? '') !== '') {
                $facts[] = ['CVE', self::ltr($f['cve'])];
            }
            if (($f['cvss'] ?? null) !== null && (float) $f['cvss'] > 0) {
                $facts[] = ['CVSS', self::e(Text::fa(number_format((float) $f['cvss'], 1)))];
            }
            if ((int) ($f['first_seen'] ?? 0) > 0) {
                $facts[] = [Lang::t('اولین بار'), self::e(Text::date((int) $f['first_seen'], false))];
            }
            if ($effort !== '') {
                $facts[] = [Lang::t('زمان تقریبی رفع'), self::text($effort)];
            }
            $frows = '';
            foreach ($facts as [$k, $v]) {
                $frows .= '<tr><td width="22%" style="color:#64748b;font-size:8pt;border-bottom:1px solid #e2e8f0">' . self::e($k) . '</td><td width="78%" style="font-size:8pt;border-bottom:1px solid #e2e8f0">' . $v . '</td></tr>';
            }
            $chunks[] = '<table cellpadding="5" nobr="true"><tr><td width="1.5%" style="background-color:' . $col . '"></td>'
                . '<td width="82.5%" style="background-color:' . (self::SEV_SOFT[$sev] ?? '#f1f5f9') . ';font-weight:bold;color:#0f172a;font-size:' . ($t['size'] + 1) . 'pt">' . self::e(Text::fa($i + 1)) . '. ' . self::text(Lang::whole((string) ($f['title'] ?? '')))
                . (!empty($f['new']) ? ' <span style="color:#b45309;font-size:8pt">(' . Lang::t('تازه') . ')</span>' : '') . '</td>'
                . '<td width="16%" align="center" style="background-color:' . $col . ';color:#ffffff;font-size:9pt;font-weight:bold">' . self::e(Lang::t((string) (Findings::SEVERITIES[$sev]['label'] ?? $sev))) . '</td></tr><tr><td colspan="3"><table cellpadding="3">' . $frows . '</table></td></tr></table>'
                . ($why !== '' ? '<p><b>' . Lang::t('چرا مهم است:') . '</b> ' . self::text($why) . '</p>' : '')
                . ($steps ? '<p><b>' . Lang::t('راه رفع:') . '</b></p><ol>' . implode('', array_map(fn ($s) => '<li>' . self::text($s) . '</li>', array_slice($steps, 0, 10))) . '</ol>' : '')
                . (is_array($snip) && (string) ($snip['code'] ?? '') !== '' ? '<p style="font-size:8pt;color:#475569">' . self::text($snip['label'] ?? '') . '</p>' . self::code((string) $snip['code']) : '')
                . ($af && (string) ($af['verify'] ?? '') !== '' ? '<p style="font-size:8pt"><b>' . Lang::t('سنجش رفع:') . '</b> ' . self::text($af['verify']) . '</p>' : '');
        }
        if ((int) ($d['more'] ?? 0) > 0) {
            $chunks[] = '<p style="color:#64748b">' . Lang::t('و {n} یافته‌ی کم‌اهمیت‌تر در صفحه‌ی «یافته‌ها».', ['n' => self::e(Text::fa((int) $d['more']))]) . '</p>';
        }
        $out[] = [Lang::t('یافته‌ها و راه رفع'), $chunks];

        if (!empty($d['fixed'])) {
            $out[] = [Lang::t('رفع‌شده‌ها'), '<ul>' . implode('', array_map(fn ($f) => '<li>' . self::text($f['title'] ?? '') . ' — ' . self::ltr($f['location'] ?? '') . '</li>', array_slice((array) $d['fixed'], 0, 30))) . '</ul>'];
        }
        $sf = (array) ($d['surface'] ?? []);
        if (!empty($sf['counts']) && array_sum($sf['counts']) > 0) {
            $cells = '';
            foreach (Surface::KINDS as $k => $l) {
                $cells .= '<td align="center" style="border:1px solid #e2e8f0;background-color:#f8fafc"><span style="font-size:13pt;font-weight:bold;color:' . $t['primary'] . '">' . self::e(Text::fa((int) ($sf['counts'][$k] ?? 0))) . '</span><br><span style="font-size:8pt;color:#64748b">' . self::e(Lang::t($l)) . '</span></td>';
            }
            $out[] = [Lang::t('سطح حمله'), '<table cellpadding="5" nobr="true"><tr>' . $cells . '</tr></table>'
                . (!empty($sf['ports']) ? '<p style="font-size:8pt"><b>' . Lang::t('درگاه‌های باز:') . '</b></p><p dir="ltr" align="left" style="font-size:8pt">' . self::e(implode('   ', array_slice((array) $sf['ports'], 0, 30))) . '</p>' : '')
                . (!empty($sf['tech']) ? '<p style="font-size:8pt"><b>' . Lang::t('فناوری‌ها:') . '</b></p><p dir="ltr" align="left" style="font-size:8pt">' . self::e(implode('   ', array_slice((array) $sf['tech'], 0, 30))) . '</p>' : '')];
        }
        if (!empty($d['scans'])) {
            $rows = '';
            foreach (array_slice((array) $d['scans'], 0, 50) as $i => $s) {
                $bg = $i % 2 ? '#f8fafc' : '#ffffff';
                $rows .= '<tr><td width="30%" style="background-color:' . $bg . '">' . self::text($s['profile'] ?? '') . '</td><td width="30%" style="background-color:' . $bg . '">' . self::ltr($s['asset'] ?? '') . '</td>'
                    . '<td width="16%" style="background-color:' . $bg . '">' . self::e(Lang::t((string) (Scans::STATUS[$s['status'] ?? ''] ?? ''))) . '</td><td width="24%" style="background-color:' . $bg . '">' . self::e(Text::date((int) ($s['finished_at'] ?? 0))) . '</td></tr>';
            }
            $out[] = [Lang::t('اسکن‌های این دوره'), '<table cellpadding="4"><tr>' . $th('نوع اسکن', '30%') . $th('دارایی', '30%') . $th('وضعیت', '16%') . $th('پایان', '24%') . '</tr>' . $rows . '</table>'];
        }

        $cp = is_array($d['compliance'] ?? null) ? $d['compliance'] : null;
        if ($cp && !empty($cp['owasp'])) {
            $crow = function (int $i, string $code, string $title, array $x): string {
                $bg = $i % 2 ? '#f8fafc' : '#ffffff';
                $sev = (string) ($x['severity'] ?? '');
                return '<tr><td width="14%" style="background-color:' . $bg . '">' . self::ltr($code) . '</td><td width="50%" style="background-color:' . $bg . '">' . self::e(Lang::t($title)) . '</td>'
                    . '<td width="18%" align="center" style="background-color:' . $bg . ((int) ($x['n'] ?? 0) > 0 ? ';font-weight:bold' : ';color:#94a3b8') . '">' . ((int) ($x['n'] ?? 0) > 0 ? self::e(Text::fa((int) $x['n'])) : self::e(Lang::t('دیده نشد'))) . '</td>'
                    . '<td width="18%" align="center" style="background-color:' . $bg . ';color:' . (self::SEV_COLOR[$sev] ?? '#94a3b8') . '">' . ($sev !== '' ? self::e(Lang::t((string) (Findings::SEVERITIES[$sev]['label'] ?? ''))) : '') . '</td></tr>';
            };
            $chead = '<tr>' . $th('بند', '14%') . $th('عنوان', '50%') . $th('یافته‌ی باز', '18%', 'center') . $th('بالاترین شدت', '18%', 'center') . '</tr>';
            $ow = '';
            $i = 0;
            foreach (Compliance::OWASP as $k => $title) {
                $ow .= $crow($i++, $k, $title, (array) ($cp['owasp'][$k] ?? []));
            }
            $iso = '';
            $i = 0;
            foreach ((array) ($cp['iso'] ?? []) as $k => $x) {
                $iso .= isset(Compliance::ISO[$k]) ? $crow($i++, (string) $k, Compliance::ISO[$k], (array) $x) : '';
            }
            $out[] = [Lang::t('نگاشت به استانداردها'), '<p><b>' . self::ltr('OWASP Top 10 (2021)') . '</b></p><table cellpadding="4">' . $chead . $ow . '</table>'
                . ($iso !== '' ? '<p><b>' . self::ltr('ISO/IEC 27001:2022 — Annex A') . '</b></p><table cellpadding="4">' . $chead . $iso . '</table>' : '')
                . '<p style="font-size:8pt;color:#64748b">' . self::e(Compliance::note()) . '</p>'];
        }

        // last: how to read this report, and what it is not
        $note = '<p style="font-size:8pt;color:#64748b">' . ($t['disclaimer'] !== '' ? nl2br(self::text($t['disclaimer'])) : Lang::t('این گزارش از داده‌ی اسکن‌های خودکار ساخته شده و جای تست نفوذ دستی را نمی‌گیرد.'))
            . ($ai ? ' ' . Lang::t('بخش‌های هوش مصنوعی با مدل {model} نوشته شده‌اند؛ پیش از اجرای دستورها آن‌ها را بخوانید.', ['model' => self::ltr($ai['model'] ?? '')]) : '') . '</p>';
        if ($t['method']) {
            $sevRows = '';
            foreach ([['critical', 'همین حالا می‌شود از آن سوءاستفاده کرد و پیامدش جدی است؛ همان روز رفع شود.'], ['high', 'احتمال سوءاستفاده یا اثرش زیاد است؛ در همین هفته رفع شود.'], ['medium', 'در شرایط خاص خطرناک است یا راه را برای حمله‌ی دیگر باز می‌کند؛ در برنامه‌ی ماه بگذارید.'],
                ['low', 'اثر کمی دارد؛ در نگهداری معمول رفع شود.'], ['info', 'مشکل نیست؛ اطلاعی است که بهتر است بدانید.']] as [$k, $what]) {
                $sevRows .= '<tr><td width="16%" align="center" style="background-color:' . self::SEV_COLOR[$k] . ';color:#ffffff;font-size:8pt;font-weight:bold">' . self::e(Lang::t(Findings::SEVERITIES[$k]['label'])) . '</td><td width="84%" style="font-size:8pt;border-bottom:1px solid #e2e8f0">' . Lang::t($what) . '</td></tr>';
            }
            $out[] = [Lang::t('روش کار و محدودیت‌ها'), '<p>' . Lang::t('این گزارش از اسکن‌های خودکار و غیرتهاجمی ساخته شده است: هیچ رمزی حدس زده نمی‌شود، از هیچ آسیب‌پذیری‌ای بهره‌برداری نمی‌شود و فقط دارایی‌هایی بررسی می‌شوند که مالکیتشان تأیید شده است.') . '</p>'
                . '<p><b>' . Lang::t('امتیاز امنیت:') . '</b> ' . Lang::t('از ۱۰۰ شروع می‌شود و هر یافته‌ی باز به اندازه‌ی اهمیتش از آن کم می‌کند. یک یافته‌ی بحرانیِ باز امتیاز را حداکثر ۴۹ و یک یافته‌ی بالا حداکثر ۷۹ نگه می‌دارد.') . '</p>'
                . '<p><b>' . Lang::t('شدت یافته‌ها:') . '</b></p><table cellpadding="4">' . $sevRows . '</table><br>' . $note];
        } else {
            $out[] = [Lang::t('یادداشت'), $note];
        }
        return $out;
    }

    private static function heading(int $n, string $title, array $t): string
    {
        return '<table cellpadding="4" nobr="true"><tr><td width="1.5%" style="background-color:' . $t['accent'] . '"></td><td width="98.5%" style="font-size:' . ($t['size'] + 4) . 'pt;font-weight:bold;color:' . $t['primary'] . '">'
            . self::e(Text::fa($n)) . '. ' . self::e($title) . '</td></tr></table>';
    }

    /** The whole body as one HTML string (the same sections the PDF writes one by one), with a plain title block. */
    public static function html(array $d): string
    {
        $t = self::template();
        $score = (int) ($d['score'] ?? -1);
        $h = '<table cellpadding="2"><tr><td><span style="font-size:8pt;color:#64748b">' . self::e(Lang::t(Reports::KINDS[$d['kind'] ?? ''] ?? 'گزارش')) . ' — ' . self::text($d['client'] ?? '') . '</span><br>'
            . '<span style="font-size:16pt;font-weight:bold;color:' . $t['primary'] . '">' . self::text($d['title'] ?? '') . '</span><br>'
            . '<span style="font-size:8pt;color:#64748b">' . self::meta($d) . ($score < 0 ? ' — ' . self::e(self::scoreWord($score)) : '') . '</span></td></tr></table>';
        foreach (self::sections($d) as $i => [$title, $body]) {
            $h .= '<br>' . self::heading($i + 1, $title, $t) . implode('<br>', (array) $body);
        }
        return $h;
    }

    private static function meta(array $d): string
    {
        return Lang::t('ساخته‌شده: {date}', ['date' => self::e(Text::date((int) ($d['generated_at'] ?? 0)))])
            . ((int) ($d['period']['from'] ?? 0) > 0 ? ' — ' . Lang::t('دوره: {from} تا {to}', ['from' => self::e(Text::date((int) $d['period']['from'], false)), 'to' => self::e(Text::date((int) $d['period']['to'], false))]) : '');
    }

    // ── the file ──

    /** The PDF bytes of a report, or '' when it cannot be made here. */
    public static function render(array $d): string
    {
        $font = self::font();
        if ($font === '') {
            return '';
        }
        $t = self::template();
        $rtl = Lang::rtl();
        $logo = self::$own ? null : Blobs::get('pdf_logo'); // another company's name never sits under our logo
        $pdf = new class('P', 'mm', $t['page'], true, 'UTF-8', false) extends \TCPDF {
            public string $mcsFont = 'dejavusans';
            public array $mcs = [];
            public bool $mcsChrome = false;
            public bool $mcsCover = false;

            public function __construct(...$a)
            {
                parent::__construct(...$a);
                $this->tcpdflink = false;
            }

            public function Header(): void
            {
                if (!$this->mcsChrome || ($this->mcsCover && $this->getPage() === 1)) {
                    return;
                }
                $m = $this->mcs;
                $w = $this->getPageWidth();
                $rtl = $this->getRTL();
                $this->setRTL(false);
                if ($m['logo'] !== null) {
                    $lw = min(34.0, 8.0 * $m['logo']['ratio']);
                    try {
                        $this->Image('@' . $m['logo']['bytes'], $rtl ? $w - 16 - $lw : 16, 8, $lw, 0, '', '', '', true, 300);
                    } catch (\Throwable $e) {
                        $this->mcs['logo'] = null;
                    }
                }
                $this->setRTL($rtl);
                $this->SetFont($this->mcsFont, $m['logo'] === null ? 'B' : '', 8);
                $this->SetTextColor(100, 116, 139);
                $this->SetXY(16, 9);
                if ($m['logo'] === null) {
                    $this->Cell(($w - 32) / 2, 6, $m['brand'], 0, 0, $rtl ? 'R' : 'L');
                    $this->SetFont($this->mcsFont, '', 8);
                } else {
                    $this->Cell(($w - 32) / 2, 6, '', 0, 0);
                }
                $this->Cell(($w - 32) / 2, 6, $m['title'], 0, 0, $rtl ? 'L' : 'R');
                $this->SetDrawColor(...$m['accent']);
                $this->SetLineWidth(0.5);
                $this->Line(16, 18, $w - 16, 18);
            }

            public function Footer(): void
            {
                if (!$this->mcsChrome || ($this->mcsCover && $this->getPage() === 1)) {
                    return;
                }
                $m = $this->mcs;
                $w = $this->getPageWidth();
                $rtl = $this->getRTL();
                $this->SetDrawColor(226, 232, 240);
                $this->SetLineWidth(0.2);
                $this->Line(16, $this->getPageHeight() - 15, $w - 16, $this->getPageHeight() - 15);
                $this->SetY(-13);
                $this->SetX(16);
                $this->SetFont($this->mcsFont, '', 7.5);
                $this->SetTextColor(100, 116, 139);
                $third = ($w - 32) / 3;
                $this->Cell($third, 6, $m['footer'], 0, 0, $rtl ? 'R' : 'L');
                $this->SetTextColor(...$m['labelColor']);
                $this->Cell($third, 6, $m['label'], 0, 0, 'C');
                $this->SetTextColor(100, 116, 139);
                $this->Cell($third, 6, $m['pageWord'] . ' ' . $this->getAliasNumPage() . ' / ' . $this->getAliasNbPages(), 0, 0, $rtl ? 'L' : 'R');
            }
        };
        $custom = $font === 'mcsfont' ? self::customFont() : null;
        if ($custom) {
            $pdf->AddFont('mcsfont', '', $custom['file']);
            $pdf->AddFont('mcsfont', 'B', $custom['bold']);
        }
        $logoInfo = null;
        if ($logo !== null && ($sz = @getimagesizefromstring($logo['bytes']))) {
            $logoInfo = ['bytes' => $logo['bytes'], 'ratio' => $sz[0] / max(1, $sz[1])];
        }
        $title = mb_substr((string) ($d['title'] ?? 'MC-Sec report'), 0, 90);
        $pdf->mcsFont = $font;
        $pdf->mcs = ['brand' => self::brand(), 'title' => $title, 'footer' => $t['footer'], 'label' => $t['label'], 'labelColor' => [185, 28, 28], 'accent' => self::rgb($t['accent']), 'logo' => $logoInfo, 'pageWord' => Lang::t('صفحه')];
        $pdf->SetCreator('MC-Sec ' . MCSEC_VERSION);
        $pdf->SetAuthor(self::brand());
        $pdf->SetTitle($title);
        $pdf->SetSubject(Lang::t(Reports::KINDS[$d['kind'] ?? ''] ?? 'گزارش'));
        $pdf->setPrintHeader(true);
        $pdf->setPrintFooter(true);
        $pdf->SetMargins(16, 24, 16);
        $pdf->setHeaderMargin(8);
        $pdf->SetAutoPageBreak(true, 20);
        $pdf->setRTL($rtl);
        $pdf->SetFont($font, '', $t['size']);
        $pdf->setCellHeightRatio(1.45);
        $pdf->setListIndentWidth(5);

        if ($t['cover']) {
            $pdf->mcsCover = true;
            self::cover($pdf, $d, $t, $font, $logoInfo);
        }
        $pdf->mcsChrome = true;
        $pdf->AddPage();
        if (!$t['cover']) {
            $pdf->writeHTML('<span style="font-size:8pt;color:#64748b">' . self::e(Lang::t(Reports::KINDS[$d['kind'] ?? ''] ?? 'گزارش')) . ' — ' . self::text($d['client'] ?? '') . '</span><br>'
                . '<span style="font-size:16pt;font-weight:bold;color:' . $t['primary'] . '">' . self::text($d['title'] ?? '') . '</span><br><span style="font-size:8pt;color:#64748b">' . self::meta($d) . '</span><br>', true, false, true, false, '');
        }
        foreach (self::sections($d) as $i => [$stitle, $body]) {
            if ($i > 0) {
                $pdf->Ln(3);
            }
            // a heading never sits alone at the foot of a page
            if ($pdf->GetY() > $pdf->getPageHeight() - 55) {
                $pdf->AddPage();
            }
            $pdf->Bookmark(Text::fa($i + 1) . '. ' . $stitle, 0, 0, '', '', [0, 0, 0]);
            foreach (array_values((array) $body) as $n => $piece) {
                if ($n > 0) {
                    $pdf->Ln(4);
                    // the head of a finding never sits alone at the foot of a page
                    if ($pdf->GetY() > $pdf->getPageHeight() - 70) {
                        $pdf->AddPage();
                    }
                }
                $pdf->writeHTML(($n === 0 ? self::heading($i + 1, $stitle, $t) : '') . $piece, true, false, true, false, '');
            }
        }
        if ($t['toc']) {
            $pdf->addTOCPage();
            $pdf->SetFont($font, 'B', $t['size'] + 6);
            $pdf->SetTextColor(...self::rgb($t['primary']));
            $pdf->Cell(0, 12, Lang::t('فهرست'), 0, 1, $rtl ? 'R' : 'L');
            $pdf->Ln(2);
            $pdf->SetFont($font, '', $t['size'] + 1);
            $pdf->SetTextColor(15, 23, 42);
            $pdf->addTOC($t['cover'] ? 2 : 1, $font, '.', Lang::t('فهرست'), '', self::rgb($t['primary']));
            $pdf->endTOCPage();
        }
        return (string) $pdf->Output('report.pdf', 'S');
    }

    /** The first page: a band in the brand's colour with the logo and the title, the score as a ring, who and when, the counts. */
    private static function cover(\TCPDF $pdf, array $d, array $t, string $font, ?array $logo): void
    {
        $rtl = Lang::rtl();
        $pdf->mcsChrome = false;
        $pdf->AddPage();
        $pdf->SetAutoPageBreak(false);
        $w = $pdf->getPageWidth();
        $ph = $pdf->getPageHeight();
        $band = 128.0;
        $align = $rtl ? 'R' : 'L';
        $score = (int) ($d['score'] ?? -1);
        // drawing in page coordinates, whatever the direction of the text
        $pdf->setRTL(false);
        $pdf->SetFillColor(...self::rgb($t['primary']));
        $pdf->Rect(0, 0, $w, $band, 'F');
        $pdf->SetFillColor(...self::rgb($t['accent']));
        $pdf->Rect(0, $band, $w, 2.2, 'F');
        $pdf->SetAlpha(0.07);
        $pdf->SetFillColor(255, 255, 255);
        $pdf->Circle($rtl ? 18 : $w - 18, 18, 62, 0, 360, 'F');
        $pdf->Circle($rtl ? 60 : $w - 60, $band - 6, 34, 0, 360, 'F');
        $pdf->SetAlpha(1);
        if ($logo !== null) {
            $lh = 16.0;
            $lw = min(70.0, $lh * $logo['ratio']);
            try {
                $pdf->Image('@' . $logo['bytes'], $rtl ? $w - 18 - $lw : 18, 18, $lw, 0, '', '', '', true, 300);
            } catch (\Throwable $e) {
                $logo = null;
                $pdf->mcs = ['logo' => null] + $pdf->mcs;
            }
        }
        // the score: a white disc on the edge of the band with a ring in the score's colour
        $cx = $rtl ? 46.0 : $w - 46.0;
        $cy = $band;
        $pdf->SetFillColor(255, 255, 255);
        $pdf->Circle($cx, $cy, 27, 0, 360, 'F');
        $pdf->SetLineStyle(['width' => 3.2, 'cap' => 'butt', 'color' => [226, 232, 240]]);
        $pdf->Circle($cx, $cy, 21.5, 0, 360, 'D');
        if ($score > 0) {
            $pdf->SetLineStyle(['width' => 3.2, 'cap' => 'round', 'color' => self::rgb(self::scoreColor($score))]);
            // TCPDF measures angles counter-clockwise from 3 o'clock: start at the top and go round clockwise
            $pdf->Circle($cx, $cy, 21.5, 90 - 360 * min(100, $score) / 100, 90, 'D');
        }
        $pdf->SetLineStyle(['width' => 0.2, 'cap' => 'butt', 'color' => [0, 0, 0]]);
        $pdf->SetTextColor(...self::rgb(self::scoreColor($score)));
        $pdf->SetFont($font, 'B', 26);
        $pdf->SetXY($cx - 20, $cy - 9.5);
        $pdf->Cell(40, 12, $score < 0 ? '—' : Text::fa($score), 0, 0, 'C');
        $pdf->SetFont($font, '', 7.5);
        $pdf->SetTextColor(100, 116, 139);
        $pdf->SetXY($cx - 20, $cy + 3.5);
        $pdf->Cell(40, 5, Lang::t('امتیاز امنیت'), 0, 0, 'C');
        $pdf->setRTL($rtl);

        // words on the band
        $pdf->SetTextColor(255, 255, 255);
        if ($logo === null) {
            $pdf->SetFont($font, 'B', 15);
            $pdf->SetXY(18, 19);
            $pdf->Cell($w - 36, 9, self::brand(), 0, 0, $align);
        }
        if ($t['label'] !== '') {
            $pdf->SetFont($font, 'B', 8);
            $pdf->SetXY(18, 21);
            $pdf->Cell($w - 36, 6, $t['label'], 0, 0, $rtl ? 'L' : 'R');
        }
        $pdf->SetFont($font, '', 11);
        $pdf->SetTextColor(...self::rgb($t['accent']));
        $pdf->SetXY(18, 56);
        $pdf->Cell($w - 36, 7, Lang::t(Reports::KINDS[$d['kind'] ?? ''] ?? 'گزارش'), 0, 1, $align);
        $pdf->SetTextColor(255, 255, 255);
        $pdf->SetFont($font, 'B', 24);
        $pdf->SetX(18);
        $pdf->MultiCell($w - 36, 12, mb_substr((string) ($d['title'] ?? ''), 0, 110), 0, $align, false, 1, null, null, true, 0, false, true, 0, 'T', false);
        $pdf->Ln(3);
        $pdf->SetFont($font, '', 13);
        $pdf->SetTextColor(203, 213, 225);
        $pdf->SetX(18);
        $pdf->Cell($w - 36, 8, mb_substr((string) ($d['client'] ?? ''), 0, 80), 0, 1, $align);

        // who, when, what
        $rows = [[Lang::t('تهیه‌شده برای'), self::text($d['client'] ?? '')], [Lang::t('تاریخ گزارش'), self::e(Text::date((int) ($d['generated_at'] ?? 0)))]];
        if ((int) ($d['period']['from'] ?? 0) > 0) {
            $rows[] = [Lang::t('دوره'), Lang::t('{from} تا {to}', ['from' => self::e(Text::date((int) $d['period']['from'], false)), 'to' => self::e(Text::date((int) $d['period']['to'], false))])];
        }
        $assets = (array) ($d['assets'] ?? []);
        if ($assets) {
            $rows[] = [Lang::t('دامنه‌ی بررسی'), count($assets) === 1 ? self::ltr($assets[0]['value'] ?? '') : Lang::t('{n} دارایی', ['n' => self::e(Text::fa(count($assets)))])];
        }
        if (is_array($d['scan'] ?? null)) {
            $rows[] = [Lang::t('نوع اسکن'), self::text($d['scan']['profile'] ?? '')];
        }
        $rows[] = [Lang::t('وضعیت کلی'), '<span style="font-weight:bold;color:' . self::scoreColor($score) . '">' . self::e(self::scoreWord($score)) . '</span>'];
        $h = '<table cellpadding="5">';
        foreach ($rows as [$k, $v]) {
            $h .= '<tr><td width="30%" style="color:#64748b;font-size:9pt;border-bottom:1px solid #e2e8f0">' . self::e($k) . '</td><td width="70%" style="font-size:10pt;color:#0f172a;border-bottom:1px solid #e2e8f0">' . $v . '</td></tr>';
        }
        $pdf->SetFont($font, '', 10);
        $pdf->SetTextColor(15, 23, 42);
        $pdf->writeHTMLCell($w - 36 - 62, 0, 18, $band + 16, $h . '</table>', 0, 1, false, true, $align);

        // the counts
        $c = (array) ($d['counts'] ?? []);
        $cells = '';
        foreach (Findings::SEVERITIES as $k => $s) {
            $cells .= '<td width="20%" align="center" style="background-color:' . self::SEV_SOFT[$k] . ';border:1px solid #ffffff"><span style="font-size:20pt;font-weight:bold;color:' . self::SEV_COLOR[$k] . '">' . self::e(Text::fa((int) ($c[$k] ?? 0))) . '</span><br>'
                . '<span style="font-size:8pt;color:' . self::SEV_COLOR[$k] . '">' . self::e(Lang::t($s['label'])) . '</span></td>';
        }
        $pdf->writeHTMLCell($w - 36, 0, 18, max($pdf->GetY() + 10, $ph - 92), '<span style="font-size:9pt;color:#64748b">' . Lang::t('یافته‌های باز به تفکیک شدت') . '</span><br><table cellpadding="7"><tr>' . $cells . '</tr></table>', 0, 1, false, true, $align);

        // the foot of the cover
        $pdf->SetFont($font, 'B', 9);
        $pdf->SetTextColor(...self::rgb($t['primary']));
        $pdf->SetXY(18, $ph - 30);
        $pdf->Cell($w - 36, 6, Lang::t('تهیه‌شده توسط {brand}', ['brand' => self::brand()]), 0, 1, $align);
        $pdf->SetFont($font, '', 8);
        $pdf->SetTextColor(100, 116, 139);
        if ($t['contact'] !== '') {
            $pdf->SetX(18);
            $pdf->Cell($w - 36, 5, $t['contact'], 0, 1, $align);
        }
        $pdf->SetX(18);
        $pdf->Cell($w - 36, 5, Lang::t('این سند برای گیرنده‌ی آن تهیه شده است؛ پیش از انتشار با صاحب گزارش هماهنگ کنید.'), 0, 1, $align);
        $pdf->SetAutoPageBreak(true, 20);
        $pdf->SetTextColor(15, 23, 42);
        $pdf->SetFont($font, '', $t['size']);
    }

    /** A made-up report with every part filled, for the admin's «نمونه» button and for looking at a template. */
    public static function sample(): array
    {
        $now = Clock::now();
        $kb = fn (string $k) => ($e = Kb::get($k)) ? ['title' => $e['title'], 'why' => $e['why'], 'steps' => $e['steps'], 'snippets' => $e['snippets'] ?? [], 'effort' => $e['effort'] ?? ''] : null;
        $f = fn (int $id, string $title, string $sev, string $asset, string $loc, string $k, string $cve = '', ?float $cvss = null, bool $new = false) => ['id' => $id, 'title' => Lang::t($title), 'severity' => $sev, 'asset' => $asset, 'location' => $loc,
            'cve' => $cve, 'cvss' => $cvss, 'first_seen' => $now - 5 * 86400, 'new' => $new, 'kb' => $kb($k)];
        return ['v' => 1, 'kind' => 'account', 'title' => Lang::t('گزارش نمونه‌ی امنیت'), 'generated_at' => $now, 'client' => Lang::t('شرکت نمونه'), 'period' => ['from' => $now - 30 * 86400, 'to' => $now], 'scan' => null,
            'assets' => [['id' => 1, 'value' => 'shop.example.com', 'status' => 'verified', 'score' => 49, 'counts' => ['critical' => 1, 'high' => 1, 'medium' => 1, 'low' => 2]],
                ['id' => 2, 'value' => 'blog.example.com', 'status' => 'verified', 'score' => 82, 'counts' => ['critical' => 0, 'high' => 0, 'medium' => 1, 'low' => 1]],
                ['id' => 3, 'value' => '203.0.113.10', 'status' => 'verified', 'score' => 74, 'counts' => ['critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 0]]],
            'score' => 49, 'counts' => ['critical' => 1, 'high' => 2, 'medium' => 2, 'low' => 3, 'info' => 4], 'open_total' => 12,
            'findings' => [
                $f(1, 'تزریق SQL در افزونه‌ی وردپرس', 'critical', 'shop.example.com', 'https://shop.example.com/wp-content/plugins/x/inc/csv.php', 'sqli', 'CVE-2024-27956', 9.8, true),
                $f(2, 'پوشه‌ی .git روی سایت در دسترس است', 'high', 'shop.example.com', 'https://shop.example.com/.git/HEAD', 'web-git', '', null, true),
                $f(3, 'درگاه MySQL روی اینترنت باز است', 'high', '203.0.113.10', '203.0.113.10:3306', 'port-exposed'),
                $f(4, 'گواهی SSL به‌زودی منقضی می‌شود', 'medium', 'blog.example.com', 'blog.example.com:443', 'tls-expiring'),
                $f(5, 'هدر HSTS تنظیم نشده است', 'low', 'shop.example.com', 'https://shop.example.com/', 'hdr-hsts'),
            ],
            'more' => 7, 'fixed' => [['title' => Lang::t('گواهی SSL منقضی شده است'), 'location' => 'shop.example.com:443']],
            'surface' => ['counts' => ['host' => 5, 'port' => 6, 'tech' => 5, 'cert' => 2, 'url' => 14, 'dns' => 9], 'ports' => ['203.0.113.10:22', '203.0.113.10:80', '203.0.113.10:443', '203.0.113.10:3306'], 'tech' => ['nginx 1.24', 'PHP 8.2', 'WordPress 6.6', 'WooCommerce']],
            'scans' => [['id' => 1, 'profile' => Lang::t('اسکن آسیب‌پذیری'), 'asset' => 'shop.example.com', 'status' => 'completed', 'finished_at' => $now - 86400], ['id' => 2, 'profile' => Lang::t('بررسی سلامت پایه'), 'asset' => 'blog.example.com', 'status' => 'completed', 'finished_at' => $now - 2 * 86400]],
            'basic_summary' => [Lang::t('این یک گزارش نمونه است تا قالب را ببینید؛ داده‌هایش ساختگی است.'), Lang::t('۳ کار فوری دارید: ۱ بحرانی و ۲ بالا.'), Lang::t('امتیاز امنیت ۴۹ از ۱۰۰ است، چون یک یافته‌ی بحرانی باز است.')],
        ];
    }
}
