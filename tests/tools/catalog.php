<?php
// The component catalog (development only; tests/ is never in the module's package). Every shared building block of
// the customer panel with its states, from the real functions (lib/Client/Ui.php, Charts.php), so a new page starts by
// looking here. http://127.0.0.1:8796/catalog.php  (&dark=1, &lang=en)
// At the end, when it was installed for the trial (tests/browser/node_modules), one Apache ECharts chart next to the
// SVG one it would stand in for: the limited trial the owner approved, not a part of the module.
declare(strict_types=1);

use McSec\Client\Charts;
use McSec\Client\Ui;
use McSec\Lang;

Charts::$rtl = Lang::rtl();
$ctx = ['who' => ['client_id' => 1, 'user_id' => 1, 'owner' => true, 'perms' => [], 'masq' => false], 'manage' => true, 'buy' => true];
$sec = fn (string $title, string $what, string $html) => '<section class="mcs-cat" id="' . Ui::e(preg_replace('~\W+~', '-', strtolower($what))) . '"><h3>' . Ui::e($title)
    . ' <code dir="ltr">' . Ui::e($what) . '</code></h3><div class="mcs-cat-body">' . $html . '</div></section>';
$row = fn (string ...$items) => '<div class="mcs-cat-row">' . implode('', $items) . '</div>';
$evil = '<script>alert(9)</script>';
$days = [];
for ($i = 13; $i >= 0; $i--) {
    $days[] = date('Y-m-d', \McSec\Clock::now() - $i * 86400);
}
$up = fn (int $from, int $step) => array_map(fn ($i) => $from + (int) round($i * $step + ($i % 3)), range(0, 13));

$out = '<div class="mcs-pagehead"><div><h2>کاتالوگ کامپوننت‌ها</h2><p>هر کامپوننت مشترک پنل مشتری با حالت‌هایش، از همان توابع واقعی. پیش از ساختن چیز تازه این‌جا را ببینید. راهنما: <code dir="ltr">docs/frontend/COMPONENT_GUIDELINES.md</code></p></div></div>';

$sw = '';
foreach (['background', 'surface', 'surface-sunken', 'foreground', 'heading', 'muted-foreground', 'border', 'primary', 'primary-soft', 'accent', 'success', 'warning', 'destructive', 'info', 'progress', 'inverse'] as $t) {
    $sw .= '<span class="mcs-cat-sw"><i style="background:var(--mds-' . $t . ')"></i><code dir="ltr">--mds-' . $t . '</code></span>';
}
$out .= $sec('توکن‌های عمومی', 'tokens', $row($sw));
$sw = '';
foreach (['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info', 'risk-strong', 'risk-good', 'risk-fair', 'risk-poor', 'risk-none', 'scan-queued', 'scan-running', 'scan-completed', 'scan-partial', 'scan-failed',
    'asset-verified', 'asset-pending', 'asset-lapsed', 'chart-1', 'chart-2', 'chart-3', 'chart-4', 'chart-5', 'chart-6', 'cert-expired', 'cert-month', 'cert-quarter', 'cert-long'] as $t) {
    $sw .= '<span class="mcs-cat-sw"><i style="background:var(--mds-' . $t . ')"></i><code dir="ltr">--mds-' . $t . '</code></span>';
}
$out .= $sec('توکن‌های امنیتی و نمودار', 'security tokens', $row($sw));

$out .= $sec('شدت یافته', 'Ui::sev, Ui::sevCounts', $row(Ui::sev('critical'), Ui::sev('high'), Ui::sev('medium'), Ui::sev('low'), Ui::sev('info'))
    . $row(Ui::sev('critical', true), Ui::sev('high', true), Ui::sev('medium', true), Ui::sev('low', true), Ui::sev('info', true))
    . Ui::sevCounts(['critical' => 1, 'high' => 4, 'medium' => 9, 'low' => 2, 'info' => 0]) . Ui::sevCounts(['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0]));
$out .= $sec('نشان و وضعیت', 'Ui::chip', $row(Ui::chip('تأییدشده', 'ok'), Ui::chip('در انتظار تأیید', 'warn'), Ui::chip('ناموفق', 'err'), Ui::chip('باز', 'info'), Ui::chip('در حال اجرا', 'run'),
    Ui::chip('لغو شد', 'muted'), Ui::chip('ریسک پذیرفته', 'accepted'), Ui::chip($evil, 'warn')));
$out .= $sec('امتیاز امنیت', 'Ui::gauge, Charts::grade', '<div class="mcs-grid3">' . Ui::card(Ui::gauge(92, 'آخرین اسکن: دیروز'), 'قوی') . Ui::card(Ui::gauge(64, 'آخرین اسکن: دیروز', true), 'ارزیابی ناقص')
    . Ui::card(Ui::gauge(-1, 'هنوز اسکنی تمام نشده است.'), 'ارزیابی‌نشده (نه صفر)') . '</div><div class="mcs-grid3">' . Ui::card(Charts::grade(95), 'A') . Ui::card(Charts::grade(41), 'ضعیف') . Ui::card(Charts::grade(-1), 'بی داده') . '</div>');
$out .= $sec('عدد اصلی', 'Ui::kpi', '<div class="mcs-grid3">' . Ui::kpi('globe', 'دارایی تأییدشده', '۱۲', '۲ تازه در این هفته') . Ui::kpi('bug', 'کار فوری', '۵', 'بحرانی و بالا', 'err', 'index.php?m=mcsec&p=findings')
    . Ui::kpi('shield-check', 'امتیاز', '—', 'هنوز اسکنی نیست', 'none') . '</div>');
$out .= $sec('هشدار و پیام', 'Ui::alert, Ui::flash', Ui::alert('info', 'برای اطلاع: اسکن در صف است.', 'info') . Ui::alert('success', 'انجام شد.', 'check') . Ui::alert('warning', '<strong>ارزیابی ناقص.</strong> اسکنر مسدود شد؛ این اسکن «سالم» به حساب نمی‌آید.', 'alert')
    . Ui::alert('danger', 'اسکن ناموفق شد. کد پیگیری: ' . Ui::ltr('MS-4F2A91'), 'alert') . Ui::flash('ok:ذخیره شد.') . Ui::flash("err:این فرم منقضی شده است.\nصفحه را تازه کنید."));
$out .= $sec('کارت', 'Ui::card', '<div class="mcs-grid2">' . Ui::card('<p>بدنه‌ی کارت.</p>', 'عنوان کارت', 'shield', '<a class="btn btn-default btn-sm" href="#">کار</a>') . Ui::card('<p>کارت بی عنوان.</p>') . '</div>');
$out .= $sec('حالت خالی', 'Ui::emptyState', '<div class="mcs-grid2">' . Ui::card(Ui::emptyState('shield-check', 'هنوز یافته‌ای نیست', 'پس از اولین اسکن، مشکل‌های پیدا شده این‌جا می‌آیند.', '<a class="btn btn-primary" href="#">اسکن بگیرید</a>'))
    . Ui::card(Ui::emptyState('search', 'با این فیلترها یافته‌ای نیست', 'فیلترها را عوض کنید.')) . '</div>');
$rows = '<tr>' . Ui::td('شدت', Ui::sev('high')) . Ui::td('یافته', '<a class="mcs-finding-link" href="#">سرآیند HSTS تنظیم نشده است</a>') . Ui::td('محل', Ui::ltr('https://shop.example/')) . Ui::td('وضعیت', Ui::chip('باز', 'info')) . '</tr>'
    . '<tr>' . Ui::td('شدت', Ui::sev('low')) . Ui::td('یافته', Ui::e($evil)) . Ui::td('محل', Ui::ltr('203.0.113.10:8443')) . Ui::td('وضعیت', Ui::chip('رفع‌شده', 'ok')) . '</tr>';
$out .= $sec('جدول، زبانه و صفحه‌بندی', 'Ui::table, Ui::td, Ui::seg, Ui::pager', Ui::seg(['#a' => 'باز', '#b' => 'رفع‌شده', '#c' => 'همه'], '#a')
    . Ui::card(Ui::table(['شدت', 'یافته', 'محل', 'وضعیت'], $rows) . Ui::pager('index.php?m=mcsec&p=findings', 2, 5)));
$out .= $sec('فرم', 'Ui::form, Ui::field, Ui::select, Ui::toggle', Ui::card(Ui::form($ctx, 'home', 'noop', '<div class="mcs-form-row">'
    . Ui::field('cat-a', 'دامنه یا IP', '<input class="form-control" id="cat-a" dir="ltr" placeholder="example.com">', 'متن کمکی زیر فیلد.')
    . Ui::field('cat-b', 'نوع', Ui::select('kind', ['a' => 'گزینه‌ی یک', 'b' => 'گزینه‌ی دو'], 'b', 'cat-b')) . '</div>'
    . Ui::toggle('t', true, 'با هوش مصنوعی', 'توضیح کوتاه کلید.', 'cat-t') . '<button type="submit" class="btn btn-primary" disabled>ثبت</button> <button type="button" class="btn btn-default">انصراف</button>')));
$out .= $sec('پیشرفت و مصرف', 'Ui::progress, Ui::meter, Charts::pipeline', Ui::card(Ui::progress(45, 'اجرای ابزارها', true) . Ui::progress(100, 'تمام شد') . Ui::meter(7, 20, '۷ از ۲۰')
    . Charts::pipeline([['label' => 'صف'], ['label' => 'شناخت دارایی'], ['label' => 'اجرای ابزارها', 'sub' => Ui::ltr('nuclei')], ['label' => 'خواندن نتیجه']], 2, 'run')));
$out .= $sec('کد، توکن فنی و واقعیت‌ها', 'Ui::code, Ui::ltr, Ui::facts', Ui::card(Ui::facts(['دامنه' => Ui::ltr('shop.example'), 'نشانی IP' => Ui::ltr('203.0.113.10'), 'شناسه' => Ui::ltr('CVE-2024-12345', 'mcs-tag'), 'خالی (حذف می‌شود)' => ''])
    . Ui::code("Strict-Transport-Security: max-age=31536000\n" . $evil, 'شاهد (فقط متن)')));
$out .= $sec('کشو، منو و راهنما', 'Ui::drawer, Ui::menu, Ui::guide', Ui::guide('<p>کادر «این بخش چه کار می‌کند؟».</p>', false) . Ui::drawer('بخش بازشو (بی JavaScript)', '<p>درون کشو.</p>', false, 'key')
    . Ui::menu('<a href="#">کار یک</a><a href="#">کار دو</a>'));
$out .= $sec('نمودارها', 'Charts::lines, trend, mini, ranked', '<div class="mcs-grid2">' . Ui::card(Charts::lines($days, [['سرویس و درگاه', $up(20, 2), 1], ['میزبان', $up(8, 1), 2], ['فناوری', $up(5, 1), 3], ['نشانی', $up(30, 3), 4], ['دارایی', $up(3, 0), 5]]), 'چند سری (توکن ۱ تا ۵)', 'activity')
    . Ui::card(Charts::trend($days, array_reverse($up(4, 1)), 'یافته‌ی باز'), 'یک سری', 'bug') . '</div><div class="mcs-grid2">'
    . Ui::card(Charts::ranked([['443', 12, ''], ['3306', 3, 'پایگاه داده'], ['22', 2, '']]), 'فهرست رتبه‌ای', 'layers') . Ui::card(Charts::lines($days, []) . Charts::mini($up(2, 1)), 'بی داده، و خط کوچک', 'activity') . '</div>');

// the limited ECharts trial (development only)
$ec = dirname(__DIR__) . '/browser/node_modules/echarts/dist/echarts.min.js';
if (is_file($ec)) {
    $series = [['سرویس و درگاه', $up(20, 2)], ['میزبان', $up(8, 1)], ['فناوری', $up(5, 1)], ['نشانی', $up(30, 3)], ['دارایی', $up(3, 0)]];
    $table = '<table class="mcs-table"><thead><tr><th>روز</th>' . implode('', array_map(fn ($s) => '<th>' . Ui::e($s[0]) . '</th>', $series)) . '</tr></thead><tbody>';
    foreach ([0, 6, 13] as $i) {
        $table .= '<tr><td>' . Ui::ltr($days[$i]) . '</td>' . implode('', array_map(fn ($s) => '<td>' . Ui::e(\McSec\Text::fa($s[1][$i])) . '</td>', $series)) . '</tr>';
    }
    $table .= '</tbody></table>';
    $data = json_encode(['days' => $days, 'series' => array_map(fn ($s) => ['name' => Lang::t($s[0]), 'data' => $s[1]], $series), 'rtl' => Lang::rtl()], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP);
    $out .= $sec('نمونه‌ی آزمایشی Apache ECharts (فقط توسعه؛ در بسته نیست)', 'echarts 5.6.0, Apache-2.0', '<div class="mcs-grid2">'
        . Ui::card('<div id="mcs-ec" style="block-size:300px" role="img" aria-label="روند سطح حمله، ۱۴ روز"></div><noscript>' . $table . '</noscript><details class="mcs-how"><summary>داده به‌صورت جدول</summary>' . $table . '</details>', 'ECharts: همان داده، با tooltip و بزرگ‌نمایی', 'activity')
        . Ui::card(Charts::lines($days, array_map(fn ($s, $i) => [$s[0], $s[1], $i + 1], $series, array_keys($series))), 'SVG فعلی (بی JavaScript)', 'activity') . '</div>'
        . '<script>' . str_replace('</', '<\/', (string) file_get_contents($ec)) . '</script><script>(function(){var d=' . $data . ',el=document.getElementById("mcs-ec"),cs=getComputedStyle(el.closest(".mcs"));'
        . 'var v=function(n){return cs.getPropertyValue(n).trim()};var c=echarts.init(el,null,{renderer:"svg"});'
        . 'c.setOption({color:[1,2,3,4,5].map(function(i){return v("--mds-chart-"+i)}),textStyle:{fontFamily:"inherit",color:v("--mds-foreground")},'
        . 'tooltip:{trigger:"axis",renderMode:"richText"},legend:{bottom:0,textStyle:{color:v("--mds-foreground")}},grid:{top:16,left:40,right:16,bottom:70},dataZoom:[{type:"slider",bottom:28,height:18}],'
        . 'xAxis:{type:"category",data:d.days,inverse:d.rtl,axisLine:{lineStyle:{color:v("--mds-border")}}},yAxis:{type:"value",position:d.rtl?"right":"left",splitLine:{lineStyle:{color:v("--mds-border")}}},'
        . 'series:d.series.map(function(s){return{name:s.name,type:"line",smooth:true,showSymbol:false,data:s.data}})});window.addEventListener("resize",function(){c.resize()});})();</script>');
}

$out .= '<style>.mcs .mcs-cat{margin-block-end:1.5rem}.mcs .mcs-cat>h3{margin-block-end:.6rem;display:flex;flex-wrap:wrap;gap:.5rem;align-items:baseline}.mcs .mcs-cat>h3 code{font-size:.75rem;font-weight:400;color:var(--mds-muted-foreground)}'
    . '.mcs .mcs-cat-row{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;margin-block-end:.6rem}.mcs .mcs-cat-sw{display:inline-flex;align-items:center;gap:.4rem;font-size:.75rem}'
    . '.mcs .mcs-cat-sw i{inline-size:1.6rem;block-size:1.6rem;border-radius:6px;border:1px solid var(--mds-border)}</style>';
return \McSec\Client\Views::bare($out);
