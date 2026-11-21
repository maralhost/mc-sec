<?php
// Design proposals for the 0.5 overview, as static pages (development only; nothing here ships in the module).
//   php tests/tools/design.php   ->  docs/design/dashboard-{a,b}-{simple,advanced}[-dark].html
// Tokens come from the real client.css so the proposals sit in the same Lagom2 skin; demo content only.
declare(strict_types=1);

$root = dirname(__DIR__, 2);
$css = (string) file_get_contents($root . '/modules/addons/mcsec/lib/Client/client.css');
preg_match('~\.mcs\{.*?\n\}~s', $css, $light);
preg_match('~html\.lagom-dark-mode \.mcs,\.mcs\.mcs-dark\{.*?\n\}~s', $css, $dark);
$tokens = ($light[0] ?? '') . "\n" . ($dark[0] ?? '');

$own = <<<'CSS'
*{box-sizing:border-box}body{margin:0;background:#f4f6f9;font-family:Tahoma,sans-serif}body.dark{background:#0b1220}
.mcs.mcs-dark{--t-bg:#111a2b;--t-sunk:#0b1220;--t-text:#cbd5e1;--t-head:#f1f5f9;--t-muted:#94a3b8;--t-line:#22304a;--t-primary:#60a5fa;--t-primary-soft:rgba(96,165,250,.12);--t-soft:rgba(148,163,184,.12)}
.dz{max-width:1180px;margin:0 auto;padding:20px 16px 40px;font-size:14.5px}
.dz h1{font-size:1.25rem;margin:0;color:var(--t-head)}.dz h2{font-size:1rem;margin:0 0 .7rem;color:var(--t-head)}.dz p{margin:0}
.dz a{color:var(--t-primary);text-decoration:none}.dz bdi{font-family:var(--t-mono);font-size:.86em;direction:ltr;unicode-bidi:isolate}
.dz-top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 0 14px;flex-wrap:wrap}
.dz-switch{display:inline-flex;background:var(--t-soft);border-radius:999px;padding:3px}
.dz-switch span{padding:.25rem .9rem;border-radius:999px;color:var(--t-muted);font-size:.85rem}.dz-switch .on{background:var(--t-bg);color:var(--t-head);font-weight:700;box-shadow:0 1px 2px rgba(0,0,0,.12)}
.dz-card{background:var(--t-bg);border:1px solid var(--t-line);border-radius:12px;padding:18px 20px}
.dz-grid{display:grid;gap:14px}.dz-muted{color:var(--t-muted)}.dz-small{font-size:.82rem}
.dz-sev{display:inline-flex;align-items:center;gap:.3rem;border-radius:999px;padding:.05rem .6rem;font-size:.78rem;font-weight:700;white-space:nowrap}
.dz-sev.c{background:var(--sev-c-bg);color:var(--sev-c-fg)}.dz-sev.h{background:var(--sev-h-bg);color:var(--sev-h-fg)}.dz-sev.m{background:var(--sev-m-bg);color:var(--sev-m-fg)}.dz-sev.l{background:var(--sev-l-bg);color:var(--sev-l-fg)}
.dz-chip{display:inline-block;border-radius:999px;padding:0 .55rem;font-size:.76rem;font-weight:700;white-space:nowrap}
.dz-chip.ok{background:var(--t-ok-bg);color:var(--t-ok)}.dz-chip.err{background:var(--t-err-bg);color:var(--t-err)}.dz-chip.warn{background:var(--t-warn-bg);color:var(--t-warn)}.dz-chip.mut{background:var(--t-soft);color:var(--t-muted)}
.dz-btn{display:inline-block;border:1px solid var(--t-line);border-radius:8px;padding:.3rem .8rem;font-size:.85rem;color:var(--t-head);background:var(--t-bg);white-space:nowrap}
.dz-btn.pri{background:var(--t-primary);border-color:var(--t-primary);color:#fff}
.dz-list{list-style:none;margin:0;padding:0}.dz-list li{display:flex;align-items:center;gap:.7rem;padding:.6rem 0;border-top:1px solid var(--t-line)}.dz-list li:first-child{border-top:0}
.dz-list .t{flex:1;min-width:0}.dz-list .t strong{display:block;color:var(--t-head);font-weight:700}.dz-list .t span{color:var(--t-muted);font-size:.82rem}
.dz-ring{position:relative;width:104px;height:104px;flex:none}.dz-ring svg{width:100%;height:100%}.dz-ring b{position:absolute;inset:0;display:grid;place-items:center;font-size:1.7rem;color:var(--t-head)}
.dz-feed{list-style:none;margin:0;padding:0}.dz-feed li{position:relative;padding:0 1.1rem .8rem 0;border-right:2px solid var(--t-line);margin-right:.35rem}
.dz-feed li:last-child{padding-bottom:0}.dz-feed li::before{content:"";position:absolute;right:-6px;top:.45rem;width:10px;height:10px;border-radius:50%;background:var(--d,var(--t-muted))}
.dz-feed time{display:block;color:var(--t-muted);font-size:.78rem}
table.dz-t{width:100%;border-collapse:collapse}table.dz-t th{font-weight:400;color:var(--t-muted);font-size:.8rem;text-align:right;padding:.3rem .5rem;border-bottom:1px solid var(--t-line);white-space:nowrap}
table.dz-t td{padding:.55rem .5rem;border-bottom:1px solid var(--t-line);vertical-align:middle}table.dz-t tr:last-child td{border-bottom:0}
/* A: status first */
.a-hero{display:flex;gap:20px;align-items:center}.a-hero .say{flex:1}.a-hero .say strong{display:block;font-size:1.35rem;color:var(--t-head);line-height:1.5}
.a-sites{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.a-site{border:1px solid var(--t-line);border-radius:10px;overflow:hidden;background:var(--t-bg)}
.a-shot{height:96px;background:linear-gradient(180deg,var(--t-soft) 0 16px,transparent 16px),var(--t-sunk);position:relative;border-bottom:1px solid var(--t-line)}
.a-shot::before{content:"";position:absolute;top:5px;right:8px;width:26px;height:6px;border-radius:3px;background:var(--t-line)}
.a-shot i{position:absolute;right:12px;left:12px;height:7px;border-radius:4px;background:var(--t-line)}.a-shot i:nth-child(1){top:30px;left:45%}.a-shot i:nth-child(2){top:46px}.a-shot i:nth-child(3){top:60px;left:30%}.a-shot i:nth-child(4){top:74px;left:60%;background:var(--t-primary-soft2)}
.a-shot.down{background:repeating-linear-gradient(135deg,var(--t-err-bg) 0 10px,transparent 10px 20px),var(--t-sunk)}.a-shot.down i{display:none}
.a-site .b{padding:.6rem .75rem}.a-site .b bdi{display:block;color:var(--t-head);font-size:.85rem;margin-bottom:.3rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.a-site .b div{display:flex;gap:.35rem;flex-wrap:wrap}
/* B: asset map */
.b-stats{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--t-line);border-radius:12px;background:var(--t-bg);overflow:hidden}
.b-stats div{padding:.8rem 1rem;border-inline-start:1px solid var(--t-line)}.b-stats div:first-child{border:0}.b-stats span{display:block;color:var(--t-muted);font-size:.8rem}.b-stats strong{font-size:1.35rem;color:var(--t-head)}.b-stats small{color:var(--t-muted)}
.b-dots{display:inline-flex;gap:3px;align-items:center}.b-dots i{width:9px;height:9px;border-radius:2px;background:var(--t-line)}
.b-dots i.c{background:var(--sev-c-ic)}.b-dots i.h{background:var(--sev-h-ic)}.b-dots i.m{background:var(--sev-m-ic)}.b-dots i.l{background:var(--sev-l-ic)}
.b-bar{height:6px;border-radius:3px;background:var(--t-line);overflow:hidden;min-width:70px}.b-bar i{display:block;height:100%;background:var(--g,var(--t-ok))}
@media (max-width:820px){.a-sites{grid-template-columns:repeat(2,1fr)}.b-stats{grid-template-columns:repeat(2,1fr)}.dz-2{grid-template-columns:1fr!important}.a-hero{flex-direction:column;align-items:flex-start}table.dz-t .opt{display:none}}
CSS;

$ring = fn (int $score, string $color) => '<div class="dz-ring" role="img" aria-label="امتیاز ' . $score . ' از ۱۰۰"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" fill="none" stroke="var(--t-line)" stroke-width="10"/>'
    . '<circle cx="60" cy="60" r="52" fill="none" stroke="' . $color . '" stroke-width="10" stroke-linecap="round" stroke-dasharray="' . round(326.7 * $score / 100, 1) . ' 326.7" transform="rotate(-90 60 60)"/></svg><b>۴۹</b></div>';
$spark = '<svg viewBox="0 0 220 44" width="220" height="44" aria-hidden="true"><polyline fill="none" stroke="var(--t-primary)" stroke-width="2" points="0,14 22,12 44,13 66,10 88,12 110,11 132,16 154,15 176,22 198,30 220,34"/></svg>';
$actions = [
    ['c', 'بحرانی', 'افزونه‌ی وردپرس «Automatic» را به‌روز کنید', 'shop-maral.ir · مهاجمان همین حالا از این آسیب‌پذیری استفاده می‌کنند · حدود ۱۵ دقیقه'],
    ['h', 'بالا', 'دسترسی به پوشه‌ی .git را ببندید', 'shop-maral.ir · کد سایت از اینترنت خوانده می‌شود · حدود ۱۰ دقیقه'],
    ['h', 'بالا', 'درگاه MySQL را به روی اینترنت ببندید', '198.51.100.7:3306 · حدود ۲۰ دقیقه'],
];
$actionList = '<ul class="dz-list">';
foreach ($actions as [$s, $l, $t, $m]) {
    $actionList .= '<li><span class="dz-sev ' . $s . '">' . $l . '</span><span class="t"><strong>' . $t . '</strong><span>' . $m . '</span></span><a class="dz-btn" href="#">چطور رفع کنم؟</a></li>';
}
$actionList .= '</ul>';
$feed = '<ul class="dz-feed"><li style="--d:var(--t-err)"><time>امروز، ۰۹:۴۰</time><bdi>blog-maral.ir</bdi> از دسترس خارج شد (HTTP 502)</li><li style="--d:var(--sev-h-ic)"><time>دیروز</time>درگاه تازه‌ی <bdi>3306</bdi> روی <bdi>198.51.100.7</bdi> باز شد</li>'
    . '<li style="--d:var(--t-ok)"><time>۳ روز پیش</time>۲ یافته روی <bdi>shop-maral.ir</bdi> رفع شد</li><li><time>۵ روز پیش</time>زیردامنه‌ی تازه: <bdi>mail.shop-maral.ir</bdi></li></ul>';
$sites = [['shop-maral.ir', 'ok', 'در دسترس', 'warn', 'SSL: ۱۱ روز', '۲ فوری'], ['blog-maral.ir', 'err', 'از دسترس خارج', 'ok', 'SSL: ۶۴ روز', ''], ['api.shop-maral.ir', 'ok', 'در دسترس', 'ok', 'SSL: ۸۸ روز', ''], ['198.51.100.7', 'mut', 'سرور', 'mut', '۳ درگاه باز', '۱ فوری']];
$siteCards = '<div class="a-sites">';
foreach ($sites as [$n, $c1, $t1, $c2, $t2, $u]) {
    $siteCards .= '<div class="a-site"><div class="a-shot' . ($c1 === 'err' ? ' down' : '') . '"><i></i><i></i><i></i><i></i></div><div class="b"><bdi>' . $n . '</bdi><div><span class="dz-chip ' . $c1 . '">' . $t1 . '</span><span class="dz-chip ' . $c2 . '">' . $t2 . '</span>'
        . ($u !== '' ? '<span class="dz-chip err">' . $u . '</span>' : '') . '</div></div></div>';
}
$siteCards .= '</div>';
$rows = [['shop-maral.ir', 'دامنه', ['c', 'h', 'm', 'm', 'l', 'l', 'l'], 49, 'در دسترس', 'ok', '۲۰ دقیقه پیش', '443، 80', 'WordPress، nginx، PHP 7.4', '۱۱ روز'],
    ['blog-maral.ir', 'دامنه · پشت CDN', ['m', 'm', 'l'], 91, 'از دسترس خارج', 'err', 'ناقص', '443', 'Cloudflare', '۶۴ روز'],
    ['api.shop-maral.ir', 'زیردامنه', [], 100, 'در دسترس', 'ok', 'در حال اسکن ۴۵٪', '443', 'nginx', '۸۸ روز'],
    ['198.51.100.7', 'IP سرور', ['h', 'l'], 79, '—', 'mut', '۲۰ دقیقه پیش', '22، 443، 3306', 'OpenSSH، MySQL', '—']];
$matrix = function (bool $adv) use ($rows) {
    $h = '<table class="dz-t"><thead><tr><th>دارایی</th><th>یافته‌های باز</th><th>امتیاز</th><th>در دسترس بودن</th><th class="opt">آخرین اسکن</th>' . ($adv ? '<th class="opt">درگاه‌ها</th><th class="opt">فناوری</th><th class="opt">گواهی</th>' : '') . '<th></th></tr></thead><tbody>';
    foreach ($rows as [$n, $k, $f, $sc, $up, $uc, $last, $ports, $tech, $cert]) {
        $dots = '<span class="b-dots">';
        foreach ($f as $x) {
            $dots .= '<i class="' . $x . '"></i>';
        }
        $dots .= $f ? '' : '<span class="dz-muted dz-small">بی یافته</span>';
        $col = $sc < 50 ? 'var(--t-err)' : ($sc < 80 ? 'var(--t-warn)' : 'var(--t-ok)');
        $h .= '<tr><td><bdi style="color:var(--t-head)">' . $n . '</bdi><div class="dz-muted dz-small">' . $k . '</div></td><td>' . $dots . '</span></td>'
            . '<td><div style="display:flex;align-items:center;gap:.5rem"><strong style="color:var(--t-head);min-width:1.8rem">' . str_replace(range(0, 9), ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'], (string) $sc) . '</strong><div class="b-bar" style="--g:' . $col . '"><i style="width:' . $sc . '%"></i></div></div></td>'
            . '<td><span class="dz-chip ' . $uc . '">' . $up . '</span></td><td class="opt dz-small dz-muted">' . $last . '</td>'
            . ($adv ? '<td class="opt"><bdi>' . $ports . '</bdi></td><td class="opt dz-small">' . $tech . '</td><td class="opt dz-small">' . $cert . '</td>' : '') . '<td><a class="dz-btn" href="#">اسکن</a></td></tr>';
    }
    return $h . '</tbody></table>';
};
$advExtra = '<div class="dz-grid dz-2" style="grid-template-columns:1fr 1fr"><div class="dz-card"><h2>گواهی‌های SSL</h2><table class="dz-t"><tbody><tr><td><bdi>shop-maral.ir</bdi></td><td>Let\'s Encrypt</td><td><span class="dz-chip warn">۱۱ روز</span></td></tr>'
    . '<tr><td><bdi>blog-maral.ir</bdi></td><td>Cloudflare</td><td><span class="dz-chip ok">۶۴ روز</span></td></tr><tr><td><bdi>api.shop-maral.ir</bdi></td><td>Let\'s Encrypt</td><td><span class="dz-chip ok">۸۸ روز</span></td></tr></tbody></table></div>'
    . '<div class="dz-card"><h2>یافته‌ها به تفکیک ابزار</h2><table class="dz-t"><thead><tr><th>ابزار</th><th>بحرانی</th><th>بالا</th><th>متوسط</th><th>پایین</th></tr></thead><tbody><tr><td>بررسی پایه</td><td>۰</td><td>۲</td><td>۳</td><td>۹</td></tr><tr><td>Nuclei</td><td>۱</td><td>۰</td><td>۱</td><td>۱</td></tr><tr><td>ZAP</td><td>۰</td><td>۰</td><td>۴</td><td>۶</td></tr></tbody></table>'
    . '<p class="dz-small dz-muted" style="margin-top:.6rem">خروجی CSV و JSON · وب‌هوک · پایپ‌لاین‌های من</p></div></div>';

$page = function (string $variant, bool $adv, bool $dark) use ($tokens, $own, $ring, $spark, $actionList, $feed, $siteCards, $matrix, $advExtra): string {
    $switch = '<span class="dz-switch" role="group" aria-label="نما"><span class="' . ($adv ? '' : 'on') . '">ساده</span><span class="' . ($adv ? 'on' : '') . '">پیشرفته</span></span>';
    $top = '<div class="dz-top"><h1>امنیت سایبری</h1>' . $switch . '</div>';
    if ($variant === 'a') {
        $body = '<div class="dz-grid"><div class="dz-card a-hero">' . $ring(49, 'var(--t-err)') . '<div class="say"><strong>سه کار فوری دارید؛ یکی از سایت‌ها هم از دسترس خارج است.</strong>'
            . '<p class="dz-muted">امتیاز از هفته‌ی پیش ۲۲ واحد پایین آمده، چون یک آسیب‌پذیری بحرانی تازه پیدا شد.</p></div><div>' . $spark . '<p class="dz-small dz-muted">روند ۶۰ روز</p></div></div>'
            . '<div class="dz-card"><h2>اول این‌ها را انجام دهید</h2>' . $actionList . '</div>'
            . '<div><h2 style="margin:.4rem .2rem .6rem">سایت‌ها و سرورهای شما</h2>' . $siteCards . '</div>'
            . ($adv ? '<div class="dz-card"><h2>همه‌ی دارایی‌ها</h2>' . $matrix(true) . '</div>' . $advExtra : '')
            . '<div class="dz-card"><h2>این هفته چه عوض شد؟</h2>' . $feed . '</div></div>';
    } else {
        $body = '<div class="dz-grid"><div class="b-stats"><div><span>امتیاز امنیت</span><strong>۴۹</strong> <small>پرخطر · ۲۲− در هفته</small></div><div><span>کار فوری</span><strong>۳</strong> <small>۱ بحرانی، ۲ بالا</small></div>'
            . '<div><span>در دسترس</span><strong>۲ از ۳</strong> <small>یک سایت خارج است</small></div><div><span>نزدیک‌ترین انقضای SSL</span><strong>۱۱ روز</strong> <small><bdi>shop-maral.ir</bdi></small></div></div>'
            . '<div class="dz-card"><h2>دارایی‌های شما</h2>' . $matrix($adv) . '<p class="dz-small dz-muted" style="margin-top:.6rem">هر مربع یک یافته‌ی باز است؛ رنگ، شدت آن.</p></div>'
            . '<div class="dz-grid dz-2" style="grid-template-columns:2fr 1fr"><div class="dz-card"><h2>اول این‌ها را انجام دهید</h2>' . $actionList . '</div><div class="dz-card"><h2>این هفته چه عوض شد؟</h2>' . $feed . '</div></div>'
            . ($adv ? $advExtra : '') . '</div>';
    }
    return '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MC-Sec · طرح ' . strtoupper($variant) . '</title><style>'
        . $tokens . $own . '</style></head><body class="' . ($dark ? 'dark' : '') . '"><div class="mcs' . ($dark ? ' mcs-dark' : '') . '"><div class="dz">' . $top . $body . '</div></div></body></html>';
};

@mkdir($root . '/docs/design', 0777, true);
foreach (['a', 'b'] as $v) {
    foreach ([false, true] as $adv) {
        foreach ([false, true] as $dark) {
            $name = 'dashboard-' . $v . '-' . ($adv ? 'advanced' : 'simple') . ($dark ? '-dark' : '') . '.html';
            file_put_contents($root . '/docs/design/' . $name, $page($v, $adv, $dark));
            echo $name . "\n";
        }
    }
}
