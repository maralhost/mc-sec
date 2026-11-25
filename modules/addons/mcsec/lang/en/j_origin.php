<?php

declare(strict_types=1);

// English of the direct route to the origin server and the checklist that can be put away (0.18.0).
return [
    'برای این دامنه سرور اصلی ثبت نشده است.' => 'No origin server is set for this domain.',
    'اول مالکیت خود دامنه را تأیید کنید.' => 'Verify ownership of the domain itself first.',
    'اگر این سایت پشت CDN یا پروکسی است، IP سرور اصلی‌اش را بدهید تا بررسی‌ها مستقیم از خود سرور پرسیده شوند، نه از CDN.' => 'If this site is behind a CDN or a proxy, give the IP of its origin server so checks ask the server itself, not the CDN.',
    'گواهی SSL سرور را نادیده بگیر' => 'Ignore the server\'s SSL certificate',
    'اگر گواهی سرور خودامضا یا مخصوص CDN است تیک بزنید؛ آن‌وقت گواهی سرور سنجیده و گزارش نمی‌شود (گواهی‌ای که بازدیدکننده می‌بیند مال CDN است).' => 'Tick this if the server\'s certificate is self-signed or issued for the CDN only; the server\'s certificate is then not checked or reported (visitors see the CDN\'s certificate).',
    'این سایت روی همین سرور است؟' => 'Is this site on this server?',
    'بله، آزموده شد' => 'Yes, tested',
    'گواهی سرور نادیده گرفته می‌شود' => 'Server certificate ignored',
    'هنوز دیده نشد' => 'Not seen yet',
    '«بررسی سلامت پایه» این دامنه مستقیم از همین سرور پرسیده می‌شود (با نام همین سایت)، نه از CDN.' => 'The "Basic health check" of this domain asks this server directly (by the site\'s name), not the CDN.',
    'هنوز آزموده نشده است.' => 'Not tested yet.',
    'دانلود فایل تأیید' => 'Download the proof file',
    'دوباره بیازما' => 'Test again',
    'پس از ثبت، از خود همان سرور می‌پرسیم که این سایت رویش هست یا نه (با فایل تأیید همین حساب). تا این دیده نشود، هیچ درخواستی مستقیم به آن سرور فرستاده نمی‌شود.' => 'After saving, we ask that server itself whether this site is on it (using this account\'s proof file). Until that is seen, no request is sent straight to that server.',
    'ثبت و آزمودن سرور' => 'Save and test the server',
    'این سایت پشت CDN یا پروکسی است؟ (سرور اصلی)' => 'Is this site behind a CDN or proxy? (origin server)',
    'در یک ساعت اخیر چند بار آزموده‌اید. کمی بعد دوباره امتحان کنید.' => 'You have tested several times in the last hour. Try again a little later.',
    'این سایت روی همین سرور است. بررسی‌های وب از این پس مستقیم از سرور پرسیده می‌شوند.' => 'This site is on this server. From now on web checks ask the server directly.',
    'هنوز دیده نشد که این سایت روی همین سرور است: {note}' => 'It has not been seen yet that this site is on this server: {note}',
    'بررسی‌های وب این اسکن مستقیم از سرور اصلی {ip} پرسیده شد، نه از CDN.' => 'The web checks of this scan asked the origin server {ip} directly, not the CDN.',
    'راهنمای شروع کار ({n} از {total} گام) را نشان بده' => 'Show the getting-started guide ({n} of {total} steps)',
    'این کادر را ببند؛ هر وقت خواستید از همین صفحه برمی‌گردد' => 'Close this box; you can bring it back from this page any time',
    'بستن' => 'Close',
    'این IP پذیرفته نیست (خصوصی، رزروشده یا از سرورهای CDN).' => 'This IP is not accepted (private, reserved, or a CDN server).',
    'گواهی SSL این سرور برای {domain} معتبر نیست. اگر گواهی سرور شما خودامضا یا مخصوص CDN است، «گواهی SSL سرور را نادیده بگیر» را تیک بزنید و دوباره بیازمایید.' => 'This server\'s SSL certificate is not valid for {domain}. If your server\'s certificate is self-signed or for the CDN only, tick "Ignore the server\'s SSL certificate" and test again.',
    'سرور {ip} روی درگاه ۸۰ و ۴۴۳ جواب نداد. اگر فایروال سرور فقط به CDN اجازه می‌دهد، IPهای اسکنر را هم مجاز کنید.' => 'The server {ip} did not answer on ports 80 and 443. If its firewall only lets the CDN in, allow the scanner IPs too.',
    'سرور {ip} جواب داد، ولی فایل تأیید {domain} روی آن نبود. فایل تأیید را روی همین سرور، در مسیر /.well-known/mcsec-verify.txt همین سایت بگذارید و دوباره بیازمایید.' => 'The server {ip} answered, but the proof file of {domain} was not on it. Put the proof file on this server, at /.well-known/mcsec-verify.txt of this site, and test again.',
];
