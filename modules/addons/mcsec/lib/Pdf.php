<?php

declare(strict_types=1);

namespace McSec;

/**
 * A report as a real PDF file, made on the server with TCPDF, the library WHMCS itself ships for invoices (no file is
 * added to the module, no font is bundled: rule 5). Persian needs a font with Arabic shaping; WHMCS has DejaVu Sans
 * and FreeSans, both checked to shape پ چ ژ گ ی and the ZWNJ correctly. When TCPDF or such a font is missing,
 * available() is false and the report page keeps only the browser's "print or PDF" button.
 * Everything in the PDF is escaped text from Reports::data (the same data the page shows): no network, no file read.
 * Left-to-right tokens (domains, URLs, CVE ids) are wrapped in bidi embedding marks, or TCPDF would reverse them
 * inside a Persian sentence.
 */
final class Pdf
{
    private const SEV_COLOR = ['critical' => '#b4123a', 'high' => '#c2410c', 'medium' => '#a16207', 'low' => '#1d4ed8', 'info' => '#475569'];

    /** The font to use, or '' when no PDF can be made here. */
    public static function font(): string
    {
        if (!class_exists('\\TCPDF')) {
            return '';
        }
        if (!defined('K_PATH_FONTS')) {
            // TCPDF defines its paths when the class file is loaded; a build without them cannot be trusted
            return '';
        }
        foreach (['dejavusans', 'freesans'] as $f) {
            if (is_file(K_PATH_FONTS . $f . '.php')) {
                return $f;
            }
        }
        return '';
    }

    public static function available(): bool
    {
        return self::font() !== '';
    }

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
        return '<table cellpadding="5"><tr><td dir="ltr" align="left" style="background-color:#f1f5f9;font-size:8pt;color:#0f172a">' . $h . '</td></tr></table>';
    }

    /** The report as the small HTML subset TCPDF understands. $d = Reports::data(). */
    public static function html(array $d): string
    {
        $ai = is_array($d['ai'] ?? null) ? $d['ai'] : null;
        $score = (int) ($d['score'] ?? -1);
        $h = '<table cellpadding="2"><tr><td width="72%"><span style="font-size:8pt;color:#64748b">' . self::e(Lang::t(Reports::KINDS[$d['kind'] ?? ''] ?? 'گزارش')) . ' — ' . self::text($d['client'] ?? '') . '</span><br>'
            . '<span style="font-size:16pt;font-weight:bold;color:#0f172a">' . self::text($d['title'] ?? '') . '</span><br>'
            . '<span style="font-size:8pt;color:#64748b">' . Lang::t('ساخته‌شده: {date}', ['date' => self::e(Text::date((int) ($d['generated_at'] ?? 0)))])
            . ((int) ($d['period']['from'] ?? 0) > 0 ? ' — ' . Lang::t('دوره: {from} تا {to}', ['from' => self::e(Text::date((int) $d['period']['from'], false)), 'to' => self::e(Text::date((int) $d['period']['to'], false))]) : '') . '</span></td>'
            . '<td width="28%" align="center" style="border:1px solid #e2e8f0"><span style="font-size:8pt;color:#64748b">' . Lang::t('امتیاز امنیت') . '</span><br><span style="font-size:22pt;font-weight:bold;color:' . ($score < 0 ? '#64748b' : ($score < 50 ? '#b91c1c' : ($score < 75 ? '#b45309' : '#15803d'))) . '">'
            . ($score < 0 ? '—' : self::e(Text::fa($score))) . '</span><br><span style="font-size:8pt">' . self::e($score < 0 ? Lang::t('بی‌اسکن') : Lang::t('{label} (از ۱۰۰)', ['label' => Lang::t(Score::label($score))])) . '</span></td></tr></table>';
        $sec = fn (string $title) => '<br><table cellpadding="4"><tr><td style="background-color:#eef2ff;font-size:11pt;font-weight:bold;color:#1e3a8a">' . self::e(Lang::t($title)) . '</td></tr></table>';

        $h .= $sec('خلاصه');
        if ($ai && (string) ($ai['executive_summary'] ?? '') !== '') {
            $h .= '<p>' . nl2br(self::text($ai['executive_summary'])) . '</p>';
        } else {
            $h .= '<ul>' . implode('', array_map(fn ($l) => '<li>' . self::text($l) . '</li>', (array) ($d['basic_summary'] ?? []))) . '</ul>';
        }
        $c = (array) ($d['counts'] ?? []);
        $h .= '<table border="0" cellpadding="4"><tr>';
        foreach (Findings::SEVERITIES as $k => $s) {
            $h .= '<td align="center" style="border:1px solid #e2e8f0"><span style="font-size:13pt;font-weight:bold;color:' . self::SEV_COLOR[$k] . '">' . self::e(Text::fa((int) ($c[$k] ?? 0))) . '</span><br><span style="font-size:8pt">' . self::e(Lang::t($s['label'])) . '</span></td>';
        }
        $h .= '</tr></table>';

        if ($ai) {
            if (!empty($ai['key_risks'])) {
                $h .= $sec('ریسک‌های اصلی') . '<ul>' . implode('', array_map(fn ($k) => '<li><b>' . self::text($k['title'] ?? '') . '</b><br>' . self::text($k['impact'] ?? '') . '</li>', (array) $ai['key_risks'])) . '</ul>';
            }
            if (!empty($ai['quick_wins'])) {
                $h .= $sec('کارهای سریع (کمتر از یک ساعت)') . '<ul>' . implode('', array_map(fn ($q) => '<li>' . self::text($q) . '</li>', (array) $ai['quick_wins'])) . '</ul>';
            }
            if (!empty($ai['plan'])) {
                $h .= $sec('برنامه‌ی پیشنهادی') . '<ol>' . implode('', array_map(fn ($p) => '<li><b>' . self::text($p['when'] ?? '') . ':</b> ' . self::text($p['action'] ?? '') . '</li>', (array) $ai['plan'])) . '</ol>';
            }
        }

        $fs = (array) ($d['findings'] ?? []);
        $h .= $sec('یافته‌ها و راه رفع');
        if (!$fs) {
            $h .= '<p>' . Lang::t('یافته‌ی بازی نیست.') . '</p>';
        }
        foreach ($fs as $i => $f) {
            $sev = (string) ($f['severity'] ?? 'info');
            $af = $ai['findings'][$f['id'] ?? 0] ?? null;
            $kb = is_array($f['kb'] ?? null) ? $f['kb'] : null;
            $why = $af ? (string) ($af['why'] ?? '') : (string) ($kb['why'] ?? '');
            $steps = $af ? (array) ($af['steps'] ?? []) : (array) ($kb['steps'] ?? []);
            $snip = $af ? ($af['snippet'] ?? null) : ($kb['snippets'][0] ?? null);
            $effort = $af && (string) ($af['effort'] ?? '') !== '' ? (string) $af['effort'] : (string) ($kb['effort'] ?? '');
            $h .= '<br><table cellpadding="3"><tr><td width="14%" align="center" style="background-color:' . (self::SEV_COLOR[$sev] ?? '#475569') . ';color:#ffffff;font-size:9pt;font-weight:bold">' . self::e(Lang::t((string) (Findings::SEVERITIES[$sev]['label'] ?? $sev))) . '</td>'
                . '<td width="86%" style="font-weight:bold;color:#0f172a">' . self::e(Text::fa($i + 1)) . '. ' . self::text(Lang::whole((string) ($f['title'] ?? ''))) . (!empty($f['new']) ? ' <span style="color:#b45309;font-size:8pt">(' . Lang::t('تازه') . ')</span>' : '') . '</td></tr></table>'
                . '<p style="font-size:8pt;color:#475569">' . Lang::t('محل: {where}', ['where' => self::ltr($f['location'] ?? '')]) . ((string) ($f['cve'] ?? '') !== '' ? ' — ' . self::ltr($f['cve']) : '') . ($effort !== '' ? ' — ' . Lang::t('زمان تقریبی: {time}', ['time' => self::text($effort)]) : '') . '</p>'
                . ($why !== '' ? '<p>' . self::text($why) . '</p>' : '')
                . ($steps ? '<ol>' . implode('', array_map(fn ($s) => '<li>' . self::text($s) . '</li>', array_slice($steps, 0, 10))) . '</ol>' : '')
                . (is_array($snip) && (string) ($snip['code'] ?? '') !== '' ? '<p style="font-size:8pt;color:#475569">' . self::text($snip['label'] ?? '') . '</p>' . self::code((string) $snip['code']) : '')
                . ($af && (string) ($af['verify'] ?? '') !== '' ? '<p style="font-size:8pt"><b>' . Lang::t('سنجش رفع:') . '</b> ' . self::text($af['verify']) . '</p>' : '');
        }
        if ((int) ($d['more'] ?? 0) > 0) {
            $h .= '<p style="color:#64748b">' . Lang::t('و {n} یافته‌ی کم‌اهمیت‌تر در صفحه‌ی «یافته‌ها».', ['n' => self::e(Text::fa((int) $d['more']))]) . '</p>';
        }
        if (!empty($d['fixed'])) {
            $h .= $sec('رفع‌شده‌ها') . '<ul>' . implode('', array_map(fn ($f) => '<li>' . self::text($f['title'] ?? '') . ' — ' . self::ltr($f['location'] ?? '') . '</li>', array_slice((array) $d['fixed'], 0, 30))) . '</ul>';
        }
        $sf = (array) ($d['surface'] ?? []);
        if (!empty($sf['counts']) && array_sum($sf['counts']) > 0) {
            $parts = [];
            foreach (Surface::KINDS as $k => $l) {
                if (!empty($sf['counts'][$k])) {
                    $parts[] = self::e(Lang::t($l) . ': ' . Text::fa((int) $sf['counts'][$k]));
                }
            }
            $h .= $sec('سطح حمله') . '<p>' . implode(' · ', $parts) . '</p>'
                . (!empty($sf['ports']) ? '<p style="font-size:8pt"><b>' . Lang::t('درگاه‌های باز:') . '</b></p><p dir="ltr" align="left" style="font-size:8pt">' . self::e(implode('   ', array_slice((array) $sf['ports'], 0, 30))) . '</p>' : '')
                . (!empty($sf['tech']) ? '<p style="font-size:8pt"><b>' . Lang::t('فناوری‌ها:') . '</b></p><p dir="ltr" align="left" style="font-size:8pt">' . self::e(implode('   ', array_slice((array) $sf['tech'], 0, 30))) . '</p>' : '');
        }
        if (!empty($d['scans'])) {
            $h .= $sec('اسکن‌های این دوره') . '<ul>' . implode('', array_map(fn ($s) => '<li>' . self::text($s['profile'] ?? '') . ' — ' . self::ltr($s['asset'] ?? '') . ' — ' . self::e(Lang::t((string) (Scans::STATUS[$s['status'] ?? ''] ?? ''))) . ' — ' . self::e(Text::date((int) ($s['finished_at'] ?? 0))) . '</li>', array_slice((array) $d['scans'], 0, 50))) . '</ul>';
        }
        return $h . '<br><p style="font-size:8pt;color:#64748b">' . Lang::t('این گزارش از داده‌ی اسکن‌های خودکار ساخته شده و جای تست نفوذ دستی را نمی‌گیرد.')
            . ($ai ? ' ' . Lang::t('بخش‌های هوش مصنوعی با مدل {model} نوشته شده‌اند؛ پیش از اجرای دستورها آن‌ها را بخوانید.', ['model' => self::ltr($ai['model'] ?? '')]) : '') . '</p>';
    }

    /** The PDF bytes of a report, or '' when it cannot be made here. */
    public static function render(array $d): string
    {
        $font = self::font();
        if ($font === '') {
            return '';
        }
        $pdf = new class('P', 'mm', 'A4', true, 'UTF-8', false) extends \TCPDF {
            public string $mcsFont = 'dejavusans';
            public string $mcsFoot = '';

            public function __construct(...$a)
            {
                parent::__construct(...$a);
                $this->tcpdflink = false;
            }

            public function Footer(): void
            {
                $this->SetY(-12);
                $this->SetFont($this->mcsFont, '', 8);
                $this->SetTextColor(100, 116, 139);
                $this->Cell(0, 6, $this->mcsFoot . ' — ' . $this->getAliasNumPage() . ' / ' . $this->getAliasNbPages(), 0, 0, 'C');
            }
        };
        $pdf->mcsFont = $font;
        $pdf->mcsFoot = Lang::t('بخش امنیت سایبری مارال کلاد');
        $pdf->SetCreator('MC-Sec ' . MCSEC_VERSION);
        $pdf->SetAuthor('Maral Cloud');
        $pdf->SetTitle(mb_substr((string) ($d['title'] ?? 'MC-Sec report'), 0, 120));
        $pdf->setPrintHeader(false);
        $pdf->SetMargins(14, 14, 14);
        $pdf->SetAutoPageBreak(true, 16);
        $pdf->setRTL(Lang::rtl()); // Persian: right-to-left as always; English: a left-to-right page
        $pdf->SetFont($font, '', 10);
        $pdf->AddPage();
        $pdf->writeHTML(self::html($d), true, false, true, false, '');
        return (string) $pdf->Output('report.pdf', 'S');
    }
}
