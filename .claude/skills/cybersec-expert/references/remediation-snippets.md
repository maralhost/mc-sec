# قطعه‌های آماده‌ی راهکار، به تفکیک بستر

برای نوشتن بخش «چطور رفع کنم؟» (SKILL.md بخش ۸). هر قطعه پیش از انتشار در پایگاه دانش (`Kb`) روی یک سایت آزمایشی مارال آزموده شود. نام منوی پنل‌ها بسته به نسخه و پوسته فرق دارد؛ در متن مشتری «معمولاً» بنویس و تصویر یا مسیر نسخه‌ی نصب‌شده‌ی مارال را بگذار.

## ۱. HSTS و رفتن به HTTPS
اول مطمئن شو HTTPS روی همه‌ی زیردامنه‌ها سالم است. با `max-age` کوتاه (۳۰۰) شروع کن، بعد ۶ ماه و بعد دو سال. `includeSubDomains` فقط وقتی همه‌ی زیردامنه‌ها HTTPS دارند. `preload` تقریباً برگشت‌ناپذیر است؛ در متن مشتری پیشنهادش نکن.

nginx (داخل `server` با `listen 443`؛ اگر `location` خودش `add_header` دارد، هدرهای بالاتر به ارث نمی‌رسند و باید آن‌جا تکرار شوند):
```nginx
add_header Strict-Transport-Security "max-age=15552000; includeSubDomains" always;
```
```nginx
server { listen 80; server_name example.com www.example.com; return 301 https://$host$request_uri; }
```
Apache یا LiteSpeed با `.htaccess` (به `mod_headers` و `mod_rewrite` نیاز دارد؛ روی هاست مارال فعال‌اند ⚠ بسنج):
```apache
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains" "expr=%{HTTPS} == 'on'"
</IfModule>
RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```
IIS (`web.config`):
```xml
<system.webServer>
  <httpProtocol><customHeaders>
    <add name="Strict-Transport-Security" value="max-age=15552000; includeSubDomains" />
  </customHeaders></httpProtocol>
</system.webServer>
```
cPanel: «Domains» ← «Force HTTPS Redirect». DirectAdmin: «SSL Certificates» ← «Force SSL with https redirect». گواهی رایگان: cPanel «SSL/TLS Status» (AutoSSL)، DirectAdmin «SSL Certificates» ← Let's Encrypt.

## ۲. هدرهای امنیتی پایه
```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```
```apache
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```
CSP را آماده‌ی کپی نده: سیاست اشتباه سایت را می‌شکند. اول `Content-Security-Policy-Report-Only` و یک هفته دیدن گزارش‌ها، بعد اعمال. برای وردپرس با افزونه‌های زیاد، CSP را «پیشرفته؛ با طراح سایت» علامت بزن.

## ۳. بستن فایل‌های نقطه‌دار و بکاپ (`.git`، `.env`)
بستن کافی نیست: رمزهای داخل فایل افشاشده را عوض کن (پایگاه داده، کلید API، کلید برنامه).
```nginx
location ~ /\.(?!well-known/) { deny all; }
location ~* \.(sql|bak|old|orig|swp|zip|tar|gz|7z)$ { deny all; }
```
```apache
RedirectMatch 404 /\.(?!well-known/)
<FilesMatch "\.(sql|bak|old|orig|swp|zip|tar|gz|7z)$">
  Require all denied
</FilesMatch>
```
بهتر از هر قاعده: فایل بکاپ و `.git` را از پوشه‌ی `public_html` بیرون ببر. مسیر `/.well-known/` باز می‌ماند چون تأیید MC-Sec و Let's Encrypt از آن است.

## ۴. فهرست پوشه و صفحه‌ی خطا
```apache
Options -Indexes
```
nginx: `autoindex off;` (پیش‌فرض خاموش است؛ اگر روشن شده، از پیکربندی بردار). وردپرس:
```php
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('DISALLOW_FILE_EDIT', true);
```
اگر `debug.log` لازم است: `define('WP_DEBUG_LOG', '/home/<user>/logs/wp-debug.log');` بیرون از `public_html`.

## ۵. وردپرس
- به‌روزرسانی: پیشخوان ← به‌روزرسانی‌ها؛ یا cPanel ← WP Toolkit (اگر فعال است). **پیش از به‌روزرسانی بکاپ بگیر** (JetBackup در cPanel اگر مارال فعال کرده ⚠ بسنج).
- افزونه‌ی آسیب‌پذیر بی وصله: غیرفعال کردن کافی نیست؛ پوشه را حذف کن یا جایگزین بیاب.
- `xmlrpc.php` (اگر Jetpack یا اپ موبایل وردپرس نداری):
```apache
<Files "xmlrpc.php">
  Require all denied
</Files>
```
- فهرست کاربران از REST: با افزونه‌ی امنیتی معتبر یا فیلتر `rest_endpoints`؛ کد آماده نده مگر آزموده.

## ۶. نسخه‌ی PHP
cPanel: «Software» ← «MultiPHP Manager» (یا «Select PHP Version» روی CloudLinux). DirectAdmin: «Domain Setup» یا «Select PHP version». پیش از تغییر: سازگاری افزونه‌ها و قالب را روی نسخه‌ی تازه بسنج یا از پشتیبانی مارال بخواه نسخه‌ی آزمایشی بسازد.

## ۷. ایمیل: SPF، DMARC، DKIM
SPF (فقط **یک** رکورد TXT با `v=spf1` روی دامنه؛ همه‌ی فرستنده‌ها در همان یکی):
```dns
example.com.  TXT  "v=spf1 a mx include:<فرستنده‌ی-شما> ~all"
```
`-all` وقتی همه‌ی فرستنده‌ها را می‌شناسی. هرگز `+all`. بیش از ۱۰ جستجوی DNS (هر `include`، `a`، `mx`) SPF را باطل می‌کند.

DMARC، مرحله‌ای (RFC 9989؛ برچسب `pct` دیگر نیست):
```dns
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```
پس از دو تا چهار هفته دیدن گزارش‌ها: `p=quarantine`، بعد `p=reject`.

دامنه‌ای که ایمیل نمی‌فرستد:
```dns
example.com.         TXT  "v=spf1 -all"
_dmarc.example.com.  TXT  "v=DMARC1; p=reject"
example.com.         MX   0 .
```
DKIM: در cPanel «Email Deliverability» رکورد را می‌سازد و درست بودنش را نشان می‌دهد؛ در DirectAdmin «DNS Management» یا گزینه‌ی DKIM حساب. روی DNS مارال این کار با یک دکمه شدنی است (فرصت «رفع یک‌کلیکی»).

## ۸. CAA
```dns
example.com.  CAA  0 issue "letsencrypt.org"
example.com.  CAA  0 issue "sectigo.com"
```
**هشدار:** هر صادرکننده‌ای که استفاده می‌شود (AutoSSL، Let's Encrypt، گواهی خریداری‌شده) باید در فهرست باشد؛ وگرنه تمدید بعدی گواهی شکست می‌خورد و سایت بالا نمی‌آید. اگر مطمئن نیستی، CAA را پیشنهاد نکن.

## ۹. درگاه‌های باز روی سرور مجازی یا اختصاصی
- UFW: `ufw deny 3306/tcp` یا `ufw allow from <IP-شما> to any port 3306 proto tcp`.
- firewalld: `firewall-cmd --permanent --remove-service=mysql && firewall-cmd --reload`.
- CSF: `TCP_IN` در `/etc/csf/csf.conf` را ویرایش و `csf -r`.
- بهتر از فایروال: سرویس را روی `127.0.0.1` گوش‌به‌زنگ کن (`bind-address = 127.0.0.1` در MySQL، `bind 127.0.0.1` و `protected-mode yes` در Redis).
- Docker: هرگز `-H tcp://0.0.0.0:2375`؛ از socket محلی یا TLS (`2376`) استفاده کن.

## ۱۰. زیردامنه‌ی معلق (takeover)
رکورد CNAME زیردامنه‌ای را که سرویسش حذف شده پاک کن (cPanel «Zone Editor»، DirectAdmin «DNS Management»، پنل ابر آروان یا Cloudflare). اگر هنوز لازمش داری، اول منبع را در همان سرویس دوباره بساز و بعد رکورد را نگه دار.

## منابع
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN، HTTP Observatory (آزمون‌ها و امتیاز): https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring
- سخت‌سازی وردپرس: https://developer.wordpress.org/advanced-administration/security/hardening/
- RFC 7208، RFC 9989، RFC 7505، RFC 8659 (پیوندها در `catalogue.md`)
