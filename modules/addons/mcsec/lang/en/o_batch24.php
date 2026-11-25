<?php

declare(strict_types=1);

// English of 0.24.0: the origin server accepted by its certificate; ownership of the IP is optional.
return [
    'اختیاری: اگر مالکیت خود این IP را هم (در صفحه‌ی خودش) تأیید کنید، اسکن‌هایی که درگاه‌ها را می‌سنجند روی آن اجرا می‌شوند. برای بررسی‌های وب این دامنه لازم نیست.' => 'Optional: if you also prove ownership of this IP (on its own page), the scans that probe ports run on it. It is not needed for the web checks of this domain.',
    'پس از ثبت، از خود همان سرور می‌پرسیم که این سایت رویش هست یا نه: اگر گواهی SSL معتبری برای همین نام داشته باشد خودکار پذیرفته می‌شود؛ وگرنه فایل تأیید همین حساب را روی آن می‌گذارید. تا این دیده نشود، هیچ بررسی دیگری مستقیم به آن سرور فرستاده نمی‌شود.' => 'After saving, we ask that server itself whether this site is on it: if it has a valid SSL certificate for this very name it is accepted automatically; otherwise you put this account’s proof file on it. Until that is seen, no other check is sent straight to that server.',
    'سرور اصلی ثبت شد، ولی هنوز دیده نشد که این سایت روی همین سرور است: {note}' => 'The origin server was saved, but the site has not been seen on it yet: {note}',
    'اسکن‌هایی که درگاه‌ها را می‌سنجند هم روی {ip} اجرا می‌شوند.' => 'The scans that probe ports also run on {ip}.',
    'اختیاری: اگر اسکن درگاه‌های خود این سرور را هم می‌خواهید، مالکیت {ip} را در صفحه‌ی همان IP تأیید کنید. برای بررسی‌های وب این دامنه لازم نیست.' => 'Optional: if you also want the ports of this server itself scanned, prove ownership of {ip} on the page of that IP. It is not needed for the web checks of this domain.',
    'سرور {ip} جواب داد، ولی نشانه‌ای ندیدیم که {domain} مال همین سرور باشد: گواهی SSL معتبری برای این نام نداشت و فایل تأیید هم روی آن نبود. فایل تأیید را روی همین سرور در مسیر /.well-known/mcsec-verify.txt همین سایت بگذارید و «دوباره بیازما» را بزنید.' => 'The server {ip} answered, but we saw no sign that {domain} belongs on it: it had no valid SSL certificate for this name and the proof file was not on it. Put the proof file on this server at /.well-known/mcsec-verify.txt of this site and press “Test again”.',
];
