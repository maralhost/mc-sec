<?php

declare(strict_types=1);

// English of 0.19.0: Nuclei by topic, scheduled bundles, re-check all, change-triggered checks, CDN-or-server.
return [
    'سنجش دوباره‌ی همه‌ی یافته‌ها' => 'Re-check of all findings',
    'بررسی خودکار پس از تغییر' => 'Automatic check after a change',
    'فقط CVEهای شناخته‌شده' => 'Known CVEs only',
    '۱۵ دقیقه تا ۱ ساعت' => '15 minutes to 1 hour',
    'فقط آسیب‌پذیری‌هایی که شماره‌ی CVE دارند: همان‌هایی که خبرشان می‌پیچد و مهاجمان خودکار دنبالشان می‌گردند.' => 'Only vulnerabilities that have a CVE number: the ones that make the news and that automated attackers look for.',
    'فایل‌ها و اطلاعات لورفته' => 'Exposed files and information',
    'فایل پشتیبان، فایل تنظیمات، کلید و رمز و هر چیزی که نباید از بیرون دیده شود ولی در دسترس مانده است.' => 'Backup files, configuration files, keys and passwords, and anything else that should not be visible from outside but is.',
    'پنل‌های مدیریت و رمز پیش‌فرض' => 'Admin panels and default passwords',
    'صفحه‌های ورود و پنل‌های مدیریتی که از اینترنت باز هستند، و سامانه‌هایی که هنوز رمز کارخانه را دارند.' => 'Login pages and admin panels open to the internet, and systems still using the factory password.',
    'پیکربندی نادرست' => 'Misconfiguration',
    'تنظیم‌های اشتباه رایج وب‌سرور و نرم‌افزارها: دسترسی‌های باز، صفحه‌های اشکال‌زدایی روشن و مانند آن.' => 'Common wrong settings of web servers and software: open access, debug pages left on, and the like.',
    'تسخیر زیردامنه' => 'Subdomain takeover',
    'زیردامنه‌هایی که به سرویسی اشاره می‌کنند که دیگر مال شما نیست و هر کسی می‌تواند آن را به نام شما بگیرد.' => 'Subdomains that point to a service that is no longer yours, which anyone could claim in your name.',
    '{n} بررسی دوباره‌ی رایگان در صف قرار گرفت. هر یافته‌ای که دیگر دیده نشود خودش «رفع‌شده» می‌شود و خبرتان می‌کنیم.' => '{n} free re-checks were queued. Any finding that is no longer seen becomes "fixed" by itself, and we will tell you.',
    '{n} مورد به سقف امروز خورد و فردا می‌شود سنجید.' => '{n} hit today\'s allowance and can be checked tomorrow.',
    'رفع کردم، همه را دوباره بسنج' => 'I fixed them, re-check all',
    'برای هر دارایی که یافته‌ی باز دارد یک بررسی دوباره‌ی رایگان گرفته شود؟' => 'Run one free re-check for every asset that has open findings?',
    'رایگان است؛ یافته‌ای که دیگر دیده نشود خودش «رفع‌شده» می‌شود.' => 'It is free; a finding that is no longer seen becomes "fixed" by itself.',
    'بسته‌ی «{name}» ({n} اسکن) — {credits} اعتبار هر اجرا' => 'Bundle "{name}" ({n} scans) — {credits} credits per run',
    'یافته‌ی بازی برای سنجیدن نیست.' => 'There is no open finding to check.',
    'امروز یک بار همه را دوباره سنجیده‌اید. فردا دوباره امتحان کنید یا یک یافته را جدا بسنجید.' => 'You have already re-checked everything once today. Try again tomorrow, or re-check one finding on its own.',
    'سقف بررسی دوباره‌ی رایگان امروز پر شده است. فردا دوباره امتحان کنید.' => 'Today\'s free re-check allowance is used up. Try again tomorrow.',
    'برای این یافته‌ها از قبل اسکنی در جریان است.' => 'A scan is already running for these findings.',
    'سرور خودتان جواب می‌دهد؛ مشکل از CDN یا تنظیم آن است' => 'your own server answers; the problem is the CDN or its settings',
    'سرور خودتان هم جواب نمی‌دهد' => 'your own server does not answer either',
    'سرور خودتان جواب می‌دهد؛ مشکل از CDN یا تنظیم آن است.' => 'Your own server answers; the problem is the CDN or its settings.',
    'سرور خودتان هم جواب نمی‌دهد.' => 'Your own server does not answer either.',
];
