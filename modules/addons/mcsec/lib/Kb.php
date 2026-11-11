<?php

declare(strict_types=1);

namespace McSec;

/**
 * Remediation knowledge base: one entry per kind of finding, with a plain-language Persian explanation of the risk,
 * ordered steps, copyable snippets (config and commands stay in English, most common platforms first), a rough
 * effort, references and an optional note on how Maral Cloud support can help.
 * Findings store a kb key. Engines that do not set one get it from match(), which maps the engine's source key
 * (e.g. "builtin.hdr.hsts", "nuclei.cve-2021-44228", "oasm.git-config") plus the finding title to a key through
 * ordered rules: built-in check keys first, then a kb key written directly after the engine prefix, then keyword
 * rules (first match wins). It returns '' when nothing fits; callers fall back to 'generic' themselves.
 */
final class Kb
{
    /** key => ['title','why','steps'=>[],'snippets'=>[['label','code']],'effort','refs'=>[],'maral'?] */
    public const ENTRIES = [
        'dns-no-address' => [
            'title' => 'افزودن رکورد A برای دامنه',
            'why' => 'این نام در DNS به هیچ نشانی IP اشاره نمی‌کند، پس هیچ‌کس نمی‌تواند سایت را باز کند. اگر دامنه فقط برای ایمیل است یا عمداً سایتی ندارد، خطری در کار نیست و می‌توانید این مورد را «ریسک پذیرفته» علامت بزنید.',
            'steps' => [
                'مطمئن شوید این نام واقعاً باید سایت داشته باشد. اگر فقط برای ایمیل یا رزرو است، کاری لازم نیست.',
                'پیدا کنید DNS دامنه کجا مدیریت می‌شود: با دستور dig NS یا nslookup -type=NS سرورهای نام (NS) را ببینید. تغییر را باید در همان سرویس بدهید، نه در پنل دیگر.',
                'در پنل همان سرویس (مثلاً Zone Editor در cPanel، بخش DNS Management در DirectAdmin یا پنل CDN) یک رکورد A برای خود دامنه (@) با IP سرور بسازید و برای www یک CNAME به دامنه‌ی اصلی.',
                'اگر سرور IPv6 دارد، رکورد AAAA هم اضافه کنید.',
                'بسته به TTL، از چند دقیقه تا چند ساعت صبر کنید تا تغییر پخش شود و بعد دوباره بسنجید.',
            ],
            'snippets' => [
                ['label' => 'نمونه‌ی رکورد DNS', 'code' => 'example.com.      3600  IN  A      203.0.113.10
www.example.com.  3600  IN  CNAME  example.com.'],
                ['label' => 'بررسی از خط فرمان', 'code' => 'dig +short NS example.com
dig +short A example.com
nslookup example.com'],
            ],
            'effort' => 'حدود ۱۰ دقیقه، به‌اضافه‌ی زمان پخش DNS',
            'refs' => ['https://www.cloudflare.com/learning/dns/dns-records/dns-a-record/'],
            'maral' => 'اگر هاست یا سرورتان در مارال کلاد است، پشتیبانی می‌تواند IP درست سرور را به شما بگوید و در ثبت رکورد راهنمایی‌تان کند.',
        ],
        'tls-expired' => [
            'title' => 'تمدید گواهی SSL',
            'why' => 'گواهی منقضی شده است و مرورگرها پیش از باز کردن سایت هشدار «اتصال امن نیست» نشان می‌دهند. بیشتر بازدیدکننده‌ها همان‌جا برمی‌گردند، اتصال برنامه‌ها و درگاه پرداخت هم ممکن است قطع شود. کاربری که عادت کند هشدار را رد کند، در برابر شنود واقعی هم بی‌دفاع می‌ماند.',
            'steps' => [
                'اگر گواهی رایگان دارید (Let\'s Encrypt یا AutoSSL): در cPanel به SSL/TLS Status بروید و Run AutoSSL را بزنید؛ در DirectAdmin از بخش SSL Certificates گواهی Let\'s Encrypt را دوباره بگیرید؛ روی سرور شخصی، تمدید certbot را اجرا کنید.',
                'اگر گواهی خریده‌اید: از فروشنده تمدیدش کنید، فایل گواهی (CRT) و زنجیره‌ی میانی (CA Bundle) را بگیرید و در پنل یا وب‌سرور جایگزین کنید.',
                'اگر سایت پشت CDN است (مثل ابر آروان یا Cloudflare)، گواهی سمت CDN را هم در پنل همان CDN بررسی کنید؛ بازدیدکننده آن گواهی را می‌بیند.',
                'وب‌سرور را reload کنید و تاریخ انقضای تازه را در مرورگر یا با دستور openssl ببینید.',
                'علت را پیدا کنید. تمدید خودکار معمولاً به خاطر تغییر DNS، بسته بودن درگاه ۸۰ یا رکورد CAA نادرست شکست می‌خورد؛ تا علت رفع نشود، گواهی دوباره منقضی می‌شود.',
            ],
            'snippets' => [
                ['label' => 'certbot (سرور شخصی)', 'code' => 'sudo certbot renew --dry-run
sudo certbot renew
sudo systemctl reload nginx    # or: sudo systemctl reload apache2'],
                ['label' => 'cPanel / DirectAdmin', 'code' => 'cPanel: SSL/TLS Status → Run AutoSSL
DirectAdmin: Account Manager → SSL Certificates → Free & automatic certificate from Let\'s Encrypt'],
                ['label' => 'دیدن تاریخ انقضا', 'code' => 'echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -subject -issuer -dates'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://letsencrypt.org/docs/', 'https://certbot.eff.org/'],
            'maral' => 'اگر سایتتان روی هاست مارال کلاد است و AutoSSL خطا می‌دهد، متن خطا را برای پشتیبانی بفرستید تا علت را بررسی کنند.',
        ],
        'tls-expiring' => [
            'title' => 'تمدید به‌موقع گواهی SSL',
            'why' => 'گواهی سایت به‌زودی منقضی می‌شود. اگر تا آن روز تمدید نشود، مرورگرها سایت را ناامن اعلام می‌کنند و بازدیدکننده و فروش از دست می‌رود.',
            'steps' => [
                'ببینید گواهی خودکار تمدید می‌شود یا نه. گواهی‌های Let\'s Encrypt و AutoSSL معمولاً چند هفته پیش از انقضا خودکار تمدید می‌شوند؛ اگر کمتر از دو هفته مانده و هنوز تمدید نشده، تمدید خودکار احتمالاً شکست خورده است.',
                'روی سرور شخصی، زمان‌بندی certbot را بررسی کنید و یک تمدید آزمایشی (dry-run) بگیرید تا خطا معلوم شود.',
                'اگر گواهی خریداری‌شده است، از همین حالا سفارش تمدید بدهید؛ صدور گواهی‌های OV و EV ممکن است چند روز طول بکشد.',
                'به ایمیل یادآوری تکیه نکنید؛ Let\'s Encrypt از سال ۲۰۲۵ دیگر ایمیل یادآوری انقضا نمی‌فرستد. اسکن دوره‌ای MC-Sec همین مورد را به شما هشدار می‌دهد.',
            ],
            'snippets' => [
                ['label' => 'certbot (سرور شخصی)', 'code' => 'systemctl list-timers | grep -i certbot
sudo certbot certificates
sudo certbot renew --dry-run'],
                ['label' => 'cPanel / DirectAdmin', 'code' => 'cPanel: SSL/TLS Status → Run AutoSSL
DirectAdmin: Account Manager → SSL Certificates'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://letsencrypt.org/docs/', 'https://certbot.eff.org/'],
            'maral' => 'اگر سایتتان روی هاست مارال کلاد است و تمدید خودکار انجام نمی‌شود، پشتیبانی می‌تواند علت را بررسی کند.',
        ],
        'tls-hostname' => [
            'title' => 'صدور گواهی SSL برای نام درست',
            'why' => 'گواهی روی سرور برای نام دیگری صادر شده است؛ مثلاً فقط برای example.com و نه www، یا گواهی پیش‌فرض خود سرور. مرورگر هشدار می‌دهد که ممکن است سایت جعلی باشد و از دید کاربر فرقی با سایت تقلبی ندارد.',
            'steps' => [
                'فهرست نام‌هایی را که بازدیدکننده‌ها با آن وارد می‌شوند بنویسید (معمولاً دامنه‌ی اصلی و www). گواهی باید همه را پوشش دهد.',
                'مطمئن شوید DNS همین نام به سرور درست اشاره می‌کند. اگر هنوز به هاست قدیمی اشاره کند، گواهی همان سرور قدیمی دیده می‌شود.',
                'گواهی را با همه‌ی نام‌ها دوباره بگیرید: در cPanel پس از درست شدن DNS دوباره Run AutoSSL بزنید؛ روی سرور شخصی certbot را با چند ‎-d اجرا کنید.',
                'در nginx یا Apache مطمئن شوید این نام در server_name یا ServerName/ServerAlias آمده است؛ وگرنه سرور گواهی پیش‌فرضش را نشان می‌دهد.',
            ],
            'snippets' => [
                ['label' => 'nginx + certbot', 'code' => 'sudo certbot --nginx -d example.com -d www.example.com'],
                ['label' => 'Apache + certbot', 'code' => 'sudo certbot --apache -d example.com -d www.example.com'],
                ['label' => 'دیدن نام‌های گواهی', 'code' => 'echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -ext subjectAltName'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://letsencrypt.org/docs/', 'https://certbot.eff.org/'],
        ],
        'tls-self-signed' => [
            'title' => 'جایگزینی گواهی خودامضا با گواهی معتبر',
            'why' => 'گواهی خودامضا را هیچ مرجع معتبری تأیید نکرده، پس مرورگرها و برنامه‌ها به آن اعتماد نمی‌کنند. مهاجمی که در مسیر شبکه باشد هم می‌تواند گواهی خودامضای خودش را جا بزند و کاربر تفاوتی نمی‌بیند.',
            'steps' => [
                'یک گواهی رایگان و معتبر از Let\'s Encrypt بگیرید: از AutoSSL در cPanel، بخش SSL Certificates در DirectAdmin یا certbot روی سرور شخصی.',
                'اگر این سرویس فقط برای استفاده‌ی داخلی است (مثلاً پنل مدیریت)، بهتر است به‌جای گواهی عمومی، دسترسی‌اش را از اینترنت ببندید و فقط از VPN یا IPهای مشخص باز بگذارید.',
                'پس از نصب، صادرکننده (Issuer) گواهی را در مرورگر ببینید.',
                'اگر در برنامه‌ها و اسکریپت‌هایی که به این سرور وصل می‌شوند بررسی گواهی را خاموش کرده بودید (مثل verify=false)، دوباره روشنش کنید.',
            ],
            'snippets' => [
                ['label' => 'nginx + certbot', 'code' => 'sudo certbot --nginx -d example.com -d www.example.com'],
                ['label' => 'Apache + certbot', 'code' => 'sudo certbot --apache -d example.com -d www.example.com'],
                ['label' => 'cPanel / DirectAdmin', 'code' => 'cPanel: SSL/TLS Status → Run AutoSSL
DirectAdmin: Account Manager → SSL Certificates → Free & automatic certificate from Let\'s Encrypt'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://letsencrypt.org/getting-started/', 'https://certbot.eff.org/'],
        ],
        'tls-old-protocol' => [
            'title' => 'خاموش کردن TLS 1.0 و TLS 1.1',
            'why' => 'نسخه‌های قدیمی TLS ضعف‌های شناخته‌شده دارند و از سال ۲۰۲۱ رسماً منسوخ شده‌اند (RFC 8996). مرورگرهای امروزی به آن‌ها نیازی ندارند؛ باز ماندنشان فقط راه حمله‌ی پایین‌آوردن نسخه (downgrade) را باز می‌گذارد و در ممیزی‌هایی مثل PCI DSS هم رد می‌شود.',
            'steps' => [
                'در تنظیمات وب‌سرور فقط TLS 1.2 و TLS 1.3 را مجاز کنید.',
                'سرویس‌های دیگر همین سرور را که TLS دارند (ایمیل، FTP، پنل مدیریت) هم بررسی کنید.',
                'پیکربندی را آزمایش کنید (nginx -t یا apachectl configtest) و سرویس را reload کنید.',
                'با ابزار SSL Labs مطمئن شوید TLS 1.0 و 1.1 دیگر پذیرفته نمی‌شوند.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => 'ssl_protocols TLSv1.2 TLSv1.3;'],
                ['label' => 'Apache', 'code' => 'SSLProtocol -all +TLSv1.2 +TLSv1.3'],
                ['label' => 'WHM (cPanel)', 'code' => 'WHM: Service Configuration → Apache Configuration → Global Configuration
SSL/TLS Protocols: -all +TLSv1.2 +TLSv1.3'],
                ['label' => 'IIS / Windows (PowerShell)', 'code' => 'foreach ($v in "TLS 1.0", "TLS 1.1") {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\Server"
    New-Item $k -Force | Out-Null
    New-ItemProperty $k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty $k -Name DisabledByDefault -Value 1 -PropertyType DWord -Force | Out-Null
}
# Restart Windows for the change to take effect.'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://ssl-config.mozilla.org/', 'https://www.rfc-editor.org/rfc/rfc8996', 'https://www.ssllabs.com/ssltest/'],
            'maral' => 'روی هاست اشتراکی، این تنظیم در سطح سرور است؛ اگر هاستتان در مارال کلاد است، موضوع را با پشتیبانی در میان بگذارید.',
        ],
        'web-no-https' => [
            'title' => 'راه‌اندازی HTTPS',
            'why' => 'سایت فقط با HTTP بی‌رمز کار می‌کند. هر کسی در مسیر شبکه (وای‌فای عمومی، شبکه‌ی اداری، اپراتور) می‌تواند رمزهای ورود، فرم‌ها و کوکی‌ها را بخواند یا محتوای صفحه را عوض کند. مرورگرها هم چنین سایتی را «ناامن» نشان می‌دهند.',
            'steps' => [
                'یک گواهی رایگان بگیرید: در cPanel از SSL/TLS Status و دکمه‌ی Run AutoSSL، در DirectAdmin از SSL Certificates، و روی سرور شخصی با certbot.',
                'مطمئن شوید هم دامنه‌ی اصلی و هم www در گواهی هستند و DNS هر دو به همین سرور اشاره می‌کند.',
                'سایت را با https:// باز کنید و ببینید درست بالا می‌آید.',
                'آدرس سایت را در تنظیمات برنامه https کنید؛ در وردپرس از «تنظیمات ← عمومی»، هر دو فیلد «نشانی وردپرس» و «نشانی سایت».',
                'بعد HTTP را به HTTPS هدایت کنید و در پایان HSTS را فعال کنید.',
            ],
            'snippets' => [
                ['label' => 'nginx + certbot', 'code' => 'sudo certbot --nginx -d example.com -d www.example.com'],
                ['label' => 'Apache + certbot', 'code' => 'sudo certbot --apache -d example.com -d www.example.com'],
                ['label' => 'cPanel / DirectAdmin', 'code' => 'cPanel: SSL/TLS Status → Run AutoSSL
DirectAdmin: Account Manager → SSL Certificates → Free & automatic certificate from Let\'s Encrypt'],
                ['label' => 'WordPress (WP-CLI)', 'code' => 'wp option update home "https://example.com"
wp option update siteurl "https://example.com"'],
            ],
            'effort' => 'حدود ۳۰ دقیقه',
            'refs' => ['https://letsencrypt.org/getting-started/', 'https://certbot.eff.org/', 'https://ssl-config.mozilla.org/'],
            'maral' => 'اگر هاستتان در مارال کلاد است و گواهی رایگان صادر نمی‌شود، پیام خطا را برای پشتیبانی بفرستید تا علت را بررسی کنند.',
        ],
        'web-no-redirect' => [
            'title' => 'هدایت HTTP به HTTPS',
            'why' => 'سایت HTTPS دارد، اما کسی که http:// را تایپ کند یا روی پیوند قدیمی بزند، روی اتصال بی‌رمز می‌ماند. در این حالت رمز و کوکی‌های او مثل سایتی بدون HTTPS قابل شنود است.',
            'steps' => [
                'در پنل هاست گزینه‌ی هدایت اجباری به HTTPS را روشن کنید، یا قاعده‌ی هدایت ۳۰۱ را به پیکربندی وب‌سرور اضافه کنید.',
                'اگر سایت پشت CDN است، هدایت را در خود CDN روشن کنید (گزینه‌ای مثل Always Use HTTPS). قاعده‌ی .htaccess پشت CDN ممکن است حلقه‌ی بی‌پایان هدایت بسازد، چون اتصال CDN به سرور شما گاهی HTTP است.',
                'آدرس http:// را در پنجره‌ی خصوصی مرورگر باز کنید و ببینید با کد ۳۰۱ به https:// می‌رود.',
                'پس از اطمینان، HSTS را فعال کنید تا مرورگر دیگر سراغ HTTP نرود.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => 'server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}'],
                ['label' => 'Apache / .htaccess', 'code' => 'RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]'],
                ['label' => 'cPanel / DirectAdmin', 'code' => 'cPanel: Domains → Force HTTPS Redirect → On
DirectAdmin: Domain Setup → (your domain) → Force SSL with https redirect'],
                ['label' => 'IIS (web.config, URL Rewrite)', 'code' => '<system.webServer>
  <rewrite>
    <rules>
      <rule name="Redirect to HTTPS" stopProcessing="true">
        <match url="(.*)" />
        <conditions>
          <add input="{HTTPS}" pattern="off" />
        </conditions>
        <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
      </rule>
    </rules>
  </rewrite>
</system.webServer>'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections', 'https://httpd.apache.org/docs/2.4/rewrite/remapping.html'],
        ],
        'hdr-hsts' => [
            'title' => 'فعال کردن HSTS',
            'why' => 'HSTS به مرورگر می‌گوید این سایت را از این به بعد فقط با HTTPS باز کند. بدون آن، مهاجمی که روی همان شبکه است (مثلاً وای‌فای عمومی) می‌تواند اولین درخواست HTTP را بگیرد و کاربر را روی نسخه‌ی بی‌رمز نگه دارد؛ به این حمله SSL stripping می‌گویند.',
            'steps' => [
                'پیش از هر چیز مطمئن شوید سایت روی HTTPS درست کار می‌کند و HTTP به HTTPS هدایت می‌شود.',
                'هدر را اول با max-age کوتاه (مثلاً 300 ثانیه) بگذارید و چند روز سایت را زیر نظر بگیرید؛ بعد آن را به یک سال (31536000) برسانید.',
                'includeSubDomains را فقط وقتی اضافه کنید که همه‌ی زیردامنه‌ها، حتی پنل‌ها و سرویس‌هایی مثل mail، HTTPS دارند؛ وگرنه آن زیردامنه‌ها در مرورگر کاربران باز نمی‌شوند.',
                'در nginx اگر داخل یک بلوک location هم add_header دارید، این هدر را آنجا هم تکرار کنید؛ هدرهای سطح server به آن location نمی‌رسند.',
                'اگر سایت پشت CDN است، می‌توانید HSTS را از تنظیمات SSL خود CDN روشن کنید.',
                'ثبت دامنه در فهرست preload مرورگرها (hstspreload.org) اختیاری است و خارج شدن از آن ماه‌ها طول می‌کشد؛ بی‌عجله تصمیم بگیرید.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => '# inside the HTTPS server { } block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'],
                ['label' => 'Apache / .htaccess', 'code' => '<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
    </customHeaders>
  </httpProtocol>
</system.webServer>'],
                ['label' => 'WordPress (functions.php قالب فرزند)', 'code' => 'add_action("send_headers", function () {
    if (is_ssl()) {
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    }
});'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security', 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html', 'https://hstspreload.org/'],
        ],
        'hdr-csp' => [
            'title' => 'تنظیم سیاست امنیت محتوا (CSP)',
            'why' => 'CSP به مرورگر می‌گوید اسکریپت، استایل و فریم را فقط از کدام منبع‌ها بپذیرد. اگر مهاجم روزی بتواند کدی در صفحه تزریق کند (XSS)، یک CSP خوب جلوی اجرای آن یا فرستادن اطلاعات کاربر به سرور مهاجم را می‌گیرد. CSP جای رفع خود آسیب‌پذیری را نمی‌گیرد؛ یک لایه‌ی دفاعی اضافه است.',
            'steps' => [
                'با یک سیاست سبک شروع کنید که تقریباً هیچ سایتی را خراب نمی‌کند: object-src \'none\'; base-uri \'self\'; frame-ancestors \'self\'.',
                'سیاست سخت‌گیرانه‌تر را اول با نام Content-Security-Policy-Report-Only بفرستید. این حالت چیزی را مسدود نمی‌کند و فقط موارد ناسازگار را در Console مرورگر نشان می‌دهد.',
                'چند روز صفحه‌های مهم را بگردید (فرم‌ها، پرداخت، ورود) و منبع‌های لازم مثل CDN، درگاه پرداخت یا ابزار آمار را از روی پیام‌های Console به سیاست اضافه کنید.',
                'وقتی پیام مهمی نماند، همان سیاست را با نام Content-Security-Policy اجرا کنید.',
                'تا جای ممکن \'unsafe-inline\' و \'unsafe-eval\' را در script-src نگذارید؛ این دو بیشتر اثر CSP در برابر XSS را از بین می‌برند. اگر قالب یا افزونه‌ای بدون آن‌ها کار نمی‌کند، بدانید حفاظتتان جزئی است و اسکریپت‌های درون‌خطی را به‌تدریج به فایل جدا یا nonce منتقل کنید.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => "# Step 1: a light policy that rarely breaks anything\nadd_header Content-Security-Policy \"object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" always;\n\n# Step 2: test a stricter policy; it only reports, it blocks nothing\nadd_header Content-Security-Policy-Report-Only \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'\" always;"],
                ['label' => 'Apache / .htaccess', 'code' => "<IfModule mod_headers.c>\n    Header always set Content-Security-Policy \"object-src 'none'; base-uri 'self'; frame-ancestors 'self'\"\n    Header always set Content-Security-Policy-Report-Only \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'\"\n</IfModule>"],
                ['label' => 'IIS (web.config)', 'code' => "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"Content-Security-Policy\" value=\"object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"],
                ['label' => 'WordPress (functions.php قالب فرزند)', 'code' => "add_action(\"send_headers\", function () {\n    header(\"Content-Security-Policy: object-src 'none'; base-uri 'self'; frame-ancestors 'self'\");\n});"],
            ],
            'effort' => 'یک ساعت برای شروع، چند روز برای آزمایش',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP', 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html', 'https://csp-evaluator.withgoogle.com/'],
        ],
        'hdr-frame' => [
            'title' => 'جلوگیری از Clickjacking',
            'why' => 'بدون این تنظیم، سایت دیگری می‌تواند صفحه‌ی شما را نامرئی در یک iframe بگذارد و کاربر را فریب دهد تا بی‌آنکه بداند روی دکمه‌های سایت شما کلیک کند؛ مثلاً تنظیمات حسابش را عوض کند یا کاری را تأیید کند.',
            'steps' => [
                'هدر X-Frame-Options را با مقدار SAMEORIGIN بفرستید تا فقط صفحه‌های خود سایت بتوانند آن را در iframe نشان دهند.',
                'روش جدیدتر، دستور frame-ancestors در CSP است. اگر CSP دارید، frame-ancestors \'self\' را به همان اضافه کنید؛ داشتن هر دو اشکالی ندارد.',
                'اگر سایت دیگری (مثلاً یک ابزارک یا سامانه‌ی همکار) باید صفحه‌ی شما را در iframe نشان دهد، دامنه‌اش را در frame-ancestors بنویسید؛ X-Frame-Options این حالت را پشتیبانی نمی‌کند.',
                'پس از تغییر، صفحه‌هایی را که خودتان در iframe استفاده می‌کنید بررسی کنید.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => "add_header X-Frame-Options \"SAMEORIGIN\" always;\n# or, better, add frame-ancestors to your existing CSP:\n# add_header Content-Security-Policy \"frame-ancestors 'self'\" always;"],
                ['label' => 'Apache / .htaccess', 'code' => '<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
</IfModule>'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Frame-Options" value="SAMEORIGIN" />
    </customHeaders>
  </httpProtocol>
</system.webServer>'],
                ['label' => 'WordPress (functions.php قالب فرزند)', 'code' => 'add_action("send_headers", "send_frame_options_header", 10, 0);'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options', 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'],
        ],
        'hdr-nosniff' => [
            'title' => 'افزودن هدر X-Content-Type-Options',
            'why' => 'بعضی مرورگرها وقتی نوع فایل روشن نباشد، آن را از روی محتوا حدس می‌زنند. مهاجم می‌تواند فایلی بارگذاری کند که ظاهراً تصویر یا متن است ولی مرورگر آن را اسکریپت تشخیص دهد و اجرا کند. مقدار nosniff این حدس زدن را خاموش می‌کند.',
            'steps' => [
                'هدر X-Content-Type-Options را با مقدار nosniff به همه‌ی پاسخ‌ها اضافه کنید.',
                'مطمئن شوید سرور برای فایل‌های CSS و JavaScript نوع درست (Content-Type) می‌فرستد؛ با nosniff، فایلی که نوعش اشتباه اعلام شود بارگذاری نمی‌شود.',
                'صفحه‌های اصلی سایت را باز کنید و در Console مرورگر دنبال خطای MIME type بگردید.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => 'add_header X-Content-Type-Options "nosniff" always;'],
                ['label' => 'Apache / .htaccess', 'code' => '<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
</IfModule>'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Content-Type-Options" value="nosniff" />
    </customHeaders>
  </httpProtocol>
</system.webServer>'],
                ['label' => 'WordPress (functions.php قالب فرزند)', 'code' => 'add_action("send_headers", "send_nosniff_header");'],
            ],
            'effort' => 'حدود ۵ دقیقه',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options', 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
        ],
        'hdr-version' => [
            'title' => 'پنهان کردن نسخه‌ی نرم‌افزار در هدرها',
            'why' => 'سرور نام و نسخه‌ی دقیق نرم‌افزارش (مثلاً Apache/2.4.41 یا PHP/7.4.3) را در هر پاسخ اعلام می‌کند. این به‌تنهایی نفوذ نیست، اما به مهاجم و ابزارهای خودکار کمک می‌کند در چند ثانیه آسیب‌پذیری‌های همان نسخه را پیدا کنند. پنهان کردن نسخه جای به‌روزرسانی را نمی‌گیرد.',
            'steps' => [
                'اول ببینید نسخه‌ی نمایش‌داده‌شده قدیمی است یا نه؛ اگر هست، به‌روزرسانی از پنهان کردن مهم‌تر است.',
                'نمایش نسخه را در وب‌سرور خاموش کنید: server_tokens در nginx، و ServerTokens و ServerSignature در Apache.',
                'برای هدر X-Powered-By، گزینه‌ی expose_php را در php.ini روی Off بگذارید؛ در cPanel این کار از MultiPHP INI Editor انجام می‌شود.',
                'سرویس را reload کنید و با دستور curl -I https://example.com هدرها را دوباره ببینید.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => '# in the http { } block
server_tokens off;'],
                ['label' => 'Apache', 'code' => '# main server config (not .htaccess)
ServerTokens Prod
ServerSignature Off'],
                ['label' => 'PHP (php.ini)', 'code' => 'expose_php = Off'],
                ['label' => 'WHM (cPanel)', 'code' => 'WHM: Service Configuration → Apache Configuration → Global Configuration
Server Tokens: ProductOnly
Server Signature: Off'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <security>
    <requestFiltering removeServerHeader="true" />
  </security>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
<!-- ASP.NET: <system.web><httpRuntime enableVersionHeader="false" /></system.web> -->'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens', 'https://httpd.apache.org/docs/2.4/mod/core.html#servertokens', 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
            'maral' => 'روی هاست اشتراکی، هدر Server در سطح سرور تنظیم می‌شود؛ اگر هاستتان در مارال کلاد است، می‌توانید از پشتیبانی بپرسید.',
        ],
        'cookie-flags' => [
            'title' => 'افزودن پرچم‌های Secure و HttpOnly به کوکی نشست',
            'why' => 'کوکی نشست چیزی است که کاربر را «واردشده» نگه می‌دارد؛ هر کس آن را داشته باشد، بدون رمز وارد حساب می‌شود. بدون HttpOnly، یک اسکریپت تزریق‌شده (XSS) می‌تواند کوکی را بخواند، و بدون Secure ممکن است مرورگر آن را روی اتصال بی‌رمز HTTP هم بفرستد.',
            'steps' => [
                'بهترین جا برای این تنظیم خود برنامه یا PHP است، نه وب‌سرور.',
                'در PHP گزینه‌های session.cookie_secure، session.cookie_httponly و session.cookie_samesite را در php.ini تنظیم کنید؛ در cPanel از MultiPHP INI Editor.',
                'در Laravel، Django، ASP.NET و فریم‌ورک‌های دیگر از تنظیمات session همان فریم‌ورک استفاده کنید (نمونه‌ها پایین آمده‌اند).',
                'در وردپرس، اگر آدرس سایت با https شروع شود، کوکی‌های ورود خودبه‌خود Secure می‌شوند؛ «نشانی وردپرس» و «نشانی سایت» را بررسی کنید.',
                'پس از تغییر، یک بار خارج و دوباره وارد شوید و در DevTools مرورگر (Application ← Cookies) ستون‌های Secure و HttpOnly را ببینید.',
            ],
            'snippets' => [
                ['label' => 'PHP (php.ini)', 'code' => 'session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Lax"'],
                ['label' => 'Laravel (.env)', 'code' => 'SESSION_SECURE_COOKIE=true
# http_only is already true by default in config/session.php'],
                ['label' => 'Django (settings.py)', 'code' => 'SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True'],
                ['label' => 'ASP.NET (web.config)', 'code' => '<system.web>
  <httpCookies httpOnlyCookies="true" requireSSL="true" />
</system.web>'],
                ['label' => 'nginx (پراکسی جلوی برنامه، nginx 1.19.3 به بعد)', 'code' => 'proxy_cookie_flags ~ secure httponly samesite=lax;'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies', 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
        ],
        'web-listing' => [
            'title' => 'خاموش کردن نمایش فهرست فایل‌ها',
            'why' => 'وقتی پوشه‌ای فایل index ندارد، وب‌سرور فهرست همه‌ی فایل‌هایش را نشان می‌دهد. این فهرست ممکن است نسخه‌ی پشتیبان، فایل تنظیمات، فاکتورها یا مدارک بارگذاری‌شده‌ی کاربران را لو بدهد و پیدا کردن هدف را برای مهاجم خیلی آسان می‌کند.',
            'steps' => [
                'نمایش فهرست را برای کل سایت خاموش کنید (نمونه‌ها پایین آمده‌اند).',
                'در cPanel از بخش Indexes برای پوشه‌ی public_html گزینه‌ی No Indexing را انتخاب کنید.',
                'فایل‌هایی را که در فهرست دیده می‌شد مرور کنید. اگر فایل حساسی (پشتیبان، خروجی پایگاه داده، مدارک) بود، فرض کنید دیگران هم دیده‌اند: آن را از پوشه‌ی عمومی بیرون ببرید و رمزهای داخلش را عوض کنید.',
                'آدرس پوشه را دوباره باز کنید؛ باید خطای 403 یا 404 ببینید.',
            ],
            'snippets' => [
                ['label' => 'Apache / .htaccess', 'code' => 'Options -Indexes'],
                ['label' => 'nginx', 'code' => '# in http { }, server { } or location { }
autoindex off;'],
                ['label' => 'cPanel', 'code' => 'cPanel: Advanced → Indexes → public_html → No Indexing → Save'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <directoryBrowse enabled="false" />
</system.webServer>'],
            ],
            'effort' => 'حدود ۵ دقیقه',
            'refs' => ['https://httpd.apache.org/docs/2.4/mod/core.html#options', 'https://nginx.org/en/docs/http/ngx_http_autoindex_module.html'],
        ],
        'web-git' => [
            'title' => 'بستن دسترسی به پوشه‌ی .git',
            'why' => 'پوشه‌ی .git کل تاریخچه‌ی کد سایت را نگه می‌دارد. اگر از روی وب در دسترس باشد، با ابزارهای رایگان می‌شود همه‌ی کد منبع را بیرون کشید؛ همراه با رمزها و کلیدهایی که زمانی در کد بوده‌اند، حتی اگر بعداً پاک شده باشند.',
            'steps' => [
                'همین حالا دسترسی وب به .git را ببندید؛ بهتر است همه‌ی فایل‌ها و پوشه‌هایی را که نامشان با نقطه شروع می‌شود (به‌جز .well-known) ببندید.',
                'فرض کنید کد و تاریخچه‌اش دیده شده است: رمز پایگاه داده، کلیدهای API، رمز SMTP و هر رازی را که زمانی در مخزن بوده عوض کنید.',
                'از این به بعد سایت را بدون .git منتشر کنید؛ مثلاً با git archive یا rsync با exclude، یا ریشه‌ی سایت را پوشه‌ای جدا از مخزن بگذارید.',
                'آدرس ‎/.git/HEAD را دوباره باز کنید؛ باید خطای 403 یا 404 ببینید.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => '# block dot-files and dot-folders, except /.well-known
location ~ /\.(?!well-known) {
    deny all;
}'],
                ['label' => 'Apache / .htaccess', 'code' => '# .htaccess in the site root
RedirectMatch 404 /\.(git|svn|hg)(/|$)'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <security>
    <requestFiltering>
      <hiddenSegments>
        <add segment=".git" />
      </hiddenSegments>
    </requestFiltering>
  </security>
</system.webServer>'],
                ['label' => 'انتشار بدون .git', 'code' => 'git archive --format=tar HEAD | tar -x -C /var/www/example.com
# or
rsync -a --delete --exclude=".git" ./ user@server:/var/www/example.com/'],
            ],
            'effort' => 'حدود ۱۵ دقیقه، به‌اضافه‌ی زمان عوض کردن رمزها',
            'refs' => ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
        ],
        'web-env' => [
            'title' => 'بستن دسترسی به فایل .env و عوض کردن رازها',
            'why' => 'فایل .env معمولاً رمز پایگاه داده، کلید رمزنگاری برنامه، رمز ایمیل و کلیدهای سرویس‌های بیرونی را دارد. اگر از وب دانلود شود، مهاجم می‌تواند مستقیم به پایگاه داده یا سرویس‌های شما وصل شود. این مورد فوری است.',
            'steps' => [
                'همین حالا دسترسی وب به .env را ببندید (نمونه‌ها پایین آمده‌اند).',
                'ریشه‌ی وب را درست کنید: در Laravel و بیشتر فریم‌ورک‌ها، ریشه‌ی سایت (Document Root) باید پوشه‌ی public باشد تا .env اصلاً در دسترس وب نباشد.',
                'فرض کنید فایل خوانده شده است: رمز پایگاه داده، رمز ایمیل و همه‌ی کلیدهای API داخل آن را عوض کنید. عوض کردن APP_KEY در Laravel نشست‌ها و داده‌های رمزنگاری‌شده را باطل می‌کند؛ پیش از آن مستندات برنامه را بخوانید.',
                'در لاگ دسترسی وب‌سرور ببینید چه کسی و چه زمانی ‎/.env را دریافت کرده است، و ورودهای مشکوک به پایگاه داده و سرویس‌ها را بررسی کنید.',
                'آدرس ‎/.env را دوباره باز کنید؛ باید خطای 403 یا 404 ببینید.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => '# block dot-files and dot-folders, except /.well-known
location ~ /\.(?!well-known) {
    deny all;
}
# Laravel: the web root must be the public folder
# root /var/www/example.com/public;'],
                ['label' => 'Apache / .htaccess', 'code' => '<Files ".env">
    Require all denied
</Files>'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <security>
    <requestFiltering>
      <hiddenSegments>
        <add segment=".env" />
      </hiddenSegments>
    </requestFiltering>
  </security>
</system.webServer>'],
                ['label' => 'جست‌وجو در لاگ', 'code' => 'grep -h "GET /\.env" /var/log/nginx/access.log* /var/log/apache2/access.log* 2>/dev/null
zgrep -h "GET /\.env" /var/log/nginx/access.log*.gz 2>/dev/null'],
            ],
            'effort' => 'حدود ۳۰ دقیقه، به‌اضافه‌ی زمان عوض کردن رمزها',
            'refs' => ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', 'https://laravel.com/docs/deployment', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
            'maral' => 'اگر سایتتان روی هاست مارال کلاد است و برای دیدن لاگ‌ها یا تغییر ریشه‌ی سایت کمک لازم دارید، از پشتیبانی بپرسید.',
        ],
        'web-server-status' => [
            'title' => 'محدود کردن صفحه‌ی server-status آپاچی',
            'why' => 'صفحه‌ی server-status درخواست‌های در حال اجرا، IP بازدیدکننده‌ها، آدرس‌های داخلی و گاهی پارامترهای حساس را زنده نشان می‌دهد؛ یعنی نقشه‌ای رایگان از سایت و کاربرانش برای مهاجم.',
            'steps' => [
                'اگر از این صفحه استفاده نمی‌کنید، ماژول status را خاموش کنید.',
                'اگر لازمش دارید، دسترسی را فقط به localhost یا IP مدیر محدود کنید.',
                'اگر جلوی Apache روی همان سرور nginx یا پراکسی دیگری هست، Require local کافی نیست، چون همه‌ی درخواست‌ها از 127.0.0.1 می‌رسند؛ در این حالت مسیر را در خود nginx هم ببندید.',
                'روی سرورهای cPanel و DirectAdmin این تنظیم در سطح سرور است و باید مدیر سرور آن را انجام دهد.',
                'آدرس ‎/server-status را از بیرون دوباره باز کنید؛ باید خطای 403 یا 404 ببینید.',
            ],
            'snippets' => [
                ['label' => 'Apache', 'code' => '<Location "/server-status">
    SetHandler server-status
    Require local
    # or: Require ip 203.0.113.5
</Location>'],
                ['label' => 'Apache (Debian / Ubuntu): خاموش کردن ماژول', 'code' => 'sudo a2dismod status
sudo systemctl reload apache2'],
                ['label' => 'nginx (پراکسی جلوی Apache)', 'code' => 'location ~ ^/server-(status|info) {
    deny all;
}'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://httpd.apache.org/docs/2.4/mod/mod_status.html'],
            'maral' => 'روی هاست اشتراکی این تنظیم با مدیر سرور است؛ اگر هاستتان در مارال کلاد است، موضوع را به پشتیبانی اطلاع دهید.',
        ],
        'port-exposed' => [
            'title' => 'بستن درگاه سرویس‌های حساس به روی اینترنت',
            'why' => 'سرویس‌هایی مثل پایگاه داده (MySQL، PostgreSQL، MongoDB، Redis)، دسترسی از راه دور (RDP، VNC)، اشتراک فایل (SMB) یا Docker API برای دسترسی عمومی ساخته نشده‌اند. ربات‌ها شبانه‌روز اینترنت را دنبال همین درگاه‌ها می‌گردند، رمز حدس می‌زنند یا از آسیب‌پذیری‌های شناخته‌شده استفاده می‌کنند؛ نتیجه‌ی رایجش نشت داده، باج‌افزار یا استخراج رمزارز روی سرور شماست.',
            'steps' => [
                'اول ببینید آیا این سرویس اصلاً باید از اینترنت در دسترس باشد. برای پایگاه داده، Redis و Docker API پاسخ تقریباً همیشه «نه» است.',
                'اگر فقط برنامه‌های همین سرور به آن وصل می‌شوند، سرویس را فقط روی 127.0.0.1 در دسترس بگذارید (تنظیم bind).',
                'اگر از جای دیگری هم لازم است، با فایروال فقط IPهای مشخص را مجاز کنید یا از VPN و تونل SSH استفاده کنید. عوض کردن شماره‌ی درگاه امنیت واقعی نمی‌آورد.',
                'در سرور ابری، فایروال پنل ارائه‌دهنده (مثل Security Group) را هم تنظیم کنید؛ این لایه پیش از رسیدن ترافیک به سرور عمل می‌کند.',
                'اگر سرویس با Docker اجرا می‌شود، درگاه‌هایی که با ‎-p منتشر می‌شوند از قواعد ufw رد می‌شوند؛ درگاه را به‌شکل ‎127.0.0.1:3306:3306 منتشر کنید. Docker API (درگاه 2375) را هرگز بدون TLS باز نگذارید؛ دسترسی به آن یعنی دسترسی کامل root به سرور.',
                'اگر این درگاه مدتی باز بوده، لاگ ورودهای سرویس را بررسی و رمزهایش را عوض کنید.',
            ],
            'snippets' => [
                ['label' => 'فقط localhost (bind)', 'code' => "# MySQL / MariaDB (my.cnf, [mysqld] section)\nbind-address = 127.0.0.1\n\n# Redis (redis.conf)\nbind 127.0.0.1 -::1\nprotected-mode yes\n\n# MongoDB (mongod.conf)\nnet:\n  bindIp: 127.0.0.1\n\n# PostgreSQL (postgresql.conf)\nlisten_addresses = 'localhost'\n\n# Docker: publish to localhost only\ndocker run -d -p 127.0.0.1:6379:6379 redis"],
                ['label' => 'ufw (Ubuntu / Debian)', 'code' => '# allow SSH first, or you will lock yourself out
sudo ufw allow 22/tcp
sudo ufw allow 80,443/tcp
sudo ufw allow from 203.0.113.5 to any port 3306 proto tcp
sudo ufw default deny incoming
sudo ufw enable
sudo ufw status numbered'],
                ['label' => 'CSF (cPanel / DirectAdmin)', 'code' => '# 1) /etc/csf/csf.conf: remove the port (e.g. 3306) from TCP_IN
# 2) /etc/csf/csf.allow: allow one IP to that port only
tcp|in|d=3306|s=203.0.113.5
# 3) apply
csf -r'],
                ['label' => 'iptables', 'code' => 'iptables -I INPUT -p tcp --dport 3306 -j DROP
iptables -I INPUT -p tcp --dport 3306 -s 203.0.113.5 -j ACCEPT
# keep after reboot (Debian/Ubuntu with iptables-persistent)
netfilter-persistent save'],
                ['label' => 'Windows Firewall (PowerShell)', 'code' => 'New-NetFirewallRule -DisplayName "RDP from office" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 203.0.113.5 -Action Allow
# then turn off the built-in rules that allow RDP from anywhere
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"'],
            ],
            'effort' => 'حدود ۱۵ تا ۳۰ دقیقه',
            'refs' => ['https://help.ubuntu.com/community/UFW', 'https://docs.docker.com/engine/security/protect-access/', 'https://www.cisecurity.org/cis-benchmarks'],
            'maral' => 'اگر سرور مجازی یا اختصاصی‌تان در مارال کلاد است و در تنظیم فایروال تردید دارید، پشتیبانی می‌تواند راهنمایی‌تان کند تا دسترسی خودتان قطع نشود.',
        ],
        'mail-spf' => [
            'title' => 'تنظیم رکورد SPF',
            'why' => 'SPF فهرست سرورهایی است که اجازه دارند به نام دامنه‌ی شما ایمیل بفرستند. بدون آن، یا با ‎+all و ‎?all، هر کسی می‌تواند ایمیلی با نشانی فرستنده‌ی شما بفرستد؛ مثلاً فاکتور جعلی برای مشتریانتان. ایمیل‌های واقعی شما هم بیشتر به پوشه‌ی اسپم می‌روند.',
            'steps' => [
                'همه‌ی جاهایی را که به نام دامنه ایمیل می‌فرستند فهرست کنید: سرور هاست یا ایمیل خود سایت، ایمیل سازمانی (مثل Google Workspace یا Microsoft 365)، سامانه‌ی خبرنامه، و فرم‌ها و فروشگاه سایت.',
                'مقدار include یا IP هر فرستنده را از مستندات همان سرویس بردارید. هر دامنه فقط یک رکورد SPF می‌تواند داشته باشد؛ اگر دو رکورد دارید، ادغامشان کنید.',
                'رکورد را به‌شکل TXT روی خود دامنه (@) در DNS ثبت کنید؛ مثلاً در Zone Editor در cPanel. بخش Email Deliverability در cPanel مقدار پیشنهادی سرور را هم نشان می‌دهد.',
                'با ‎~all شروع کنید (ایمیل از فرستنده‌ی ناشناس مشکوک علامت می‌خورد). وقتی مطمئن شدید همه‌ی فرستنده‌ها در رکورد هستند، به ‎-all بروید (ناشناس رد می‌شود).',
                'رکورد نباید بیش از ۱۰ جست‌وجوی DNS (هر include، a یا mx یکی حساب می‌شود) داشته باشد؛ وگرنه نامعتبر شمرده می‌شود.',
                'اگر دامنه اصلاً ایمیل نمی‌فرستد، رکورد v=spf1 -all بگذارید تا کسی نتواند به نامش ایمیل جعل کند.',
            ],
            'snippets' => [
                ['label' => 'نمونه‌ی رکورد SPF', 'code' => 'example.com.  3600  IN  TXT  "v=spf1 a mx include:spf.YOUR-MAIL-PROVIDER ~all"'],
                ['label' => 'Google Workspace / Microsoft 365', 'code' => '"v=spf1 include:_spf.google.com ~all"
"v=spf1 include:spf.protection.outlook.com -all"'],
                ['label' => 'دامنه‌ای که ایمیل نمی‌فرستد', 'code' => 'example.com.  3600  IN  TXT  "v=spf1 -all"'],
                ['label' => 'cPanel', 'code' => 'cPanel: Email → Email Deliverability → (your domain) → Manage'],
                ['label' => 'بررسی', 'code' => 'dig +short TXT example.com
nslookup -type=TXT example.com'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://www.rfc-editor.org/rfc/rfc7208', 'https://support.google.com/a/answer/33786'],
            'maral' => 'اگر ایمیل دامنه‌تان روی هاست مارال کلاد است، مقدار درست SPF سرور ایمیل را از پشتیبانی بپرسید.',
        ],
        'mail-dmarc' => [
            'title' => 'تنظیم رکورد DMARC',
            'why' => 'DMARC به سرویس‌های ایمیل گیرنده (Gmail، Outlook و…) می‌گوید با ایمیلی که به نام دامنه‌ی شما آمده ولی SPF و DKIM تأییدش نمی‌کنند چه کنند: کاری نکنند، به اسپم بفرستند یا رد کنند. بدون DMARC جعل نام شما در فیشینگ آسان‌تر است و از تلاش‌های جعل هم گزارشی نمی‌گیرید.',
            'steps' => [
                'پیش‌نیاز: SPF درست و DKIM فعال. در cPanel بخش Email Deliverability هر دو را نشان می‌دهد و DKIM را می‌سازد؛ در ایمیل سازمانی از پنل همان سرویس.',
                'مرحله‌ی ۱ (نظارت): رکورد TXT را روی ‎_dmarc.example.com با p=none و یک نشانی rua برای دریافت گزارش بگذارید. نشانی گزارش بهتر است در همین دامنه باشد.',
                'دو تا چهار هفته گزارش‌ها را بخوانید (ابزارهای تحلیل گزارش DMARC کار را ساده می‌کنند) و هر فرستنده‌ی قانونی را که SPF یا DKIM درست ندارد اصلاح کنید.',
                'مرحله‌ی ۲: p را به quarantine تغییر دهید تا ایمیل‌های جعلی به اسپم بروند و چند هفته زیر نظر بگیرید.',
                'مرحله‌ی ۳: وقتی مطمئن شدید ایمیل قانونی‌ای گم نمی‌شود، p را reject کنید تا ایمیل جعلی کاملاً رد شود.',
                'برای دامنه‌هایی که اصلاً ایمیل نمی‌فرستند، می‌توانید از همان اول p=reject بگذارید.',
            ],
            'snippets' => [
                ['label' => 'مرحله‌ی ۱: نظارت', 'code' => '_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"'],
                ['label' => 'مرحله‌ی ۲: قرنطینه', 'code' => '_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com"'],
                ['label' => 'مرحله‌ی ۳: رد', 'code' => '_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"'],
                ['label' => 'دامنه‌ای که ایمیل نمی‌فرستد', 'code' => '_dmarc.example.com.  3600  IN  TXT  "v=DMARC1; p=reject"'],
                ['label' => 'بررسی', 'code' => 'dig +short TXT _dmarc.example.com'],
            ],
            'effort' => 'حدود ۱۵ دقیقه برای ثبت، چند هفته تا رسیدن به reject',
            'refs' => ['https://www.rfc-editor.org/rfc/rfc7489', 'https://dmarc.org/'],
            'maral' => 'اگر ایمیل دامنه‌تان روی هاست مارال کلاد است، پشتیبانی می‌تواند در فعال کردن DKIM و بررسی رکوردها راهنمایی‌تان کند.',
        ],
        'dns-caa' => [
            'title' => 'افزودن رکورد CAA',
            'why' => 'رکورد CAA مشخص می‌کند کدام مرجع‌های صدور گواهی (CA) اجازه دارند برای دامنه‌ی شما گواهی SSL صادر کنند. بدون آن هر مرجعی می‌تواند صادر کند و اگر یکی فریب بخورد، گواهی معتبری به نام شما دست کس دیگری می‌افتد. اولویتش پایین است ولی تنظیمش ساده است.',
            'steps' => [
                'ببینید گواهی‌های فعلی‌تان از کدام مرجع است (بخش Issuer گواهی در مرورگر). AutoSSL در cPanel ممکن است از Let\'s Encrypt یا Sectigo گواهی بگیرد و CDNها هم گاهی چند مرجع دارند.',
                'برای هر مرجعی که استفاده می‌کنید یک رکورد CAA با تگ issue بسازید. اگر مرجعی را جا بیندازید، تمدید بعدی گواهی شکست می‌خورد.',
                'در صورت تمایل یک رکورد iodef با نشانی ایمیل بگذارید تا درخواست‌های ردشده به شما گزارش شود.',
                'رکورد را در Zone Editor در cPanel، بخش DNS Management در DirectAdmin یا پنل DNS یا CDN خود ثبت کنید و با dig بررسی کنید.',
            ],
            'snippets' => [
                ['label' => 'نمونه‌ی رکورد CAA', 'code' => 'example.com.  3600  IN  CAA  0 issue "letsencrypt.org"
example.com.  3600  IN  CAA  0 issue "sectigo.com"
example.com.  3600  IN  CAA  0 iodef "mailto:security@example.com"'],
                ['label' => 'بررسی', 'code' => 'dig +short CAA example.com'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://letsencrypt.org/docs/caa/', 'https://www.rfc-editor.org/rfc/rfc8659'],
        ],
        'cve-patch' => [
            'title' => 'نصب وصله‌ی آسیب‌پذیری شناخته‌شده (CVE)',
            'why' => 'نرم‌افزاری که روی سرور یا سایت دارید آسیب‌پذیری ثبت‌شده‌ای با شناسه‌ی CVE دارد. جزئیات این آسیب‌پذیری‌ها عمومی است و برای بسیاری از آن‌ها ابزار حمله‌ی آماده وجود دارد؛ ربات‌ها چند روز، گاهی چند ساعت پس از انتشار، اینترنت را برایشان اسکن می‌کنند.',
            'steps' => [
                'با شناسه‌ی CVE در جزئیات یافته، نرم‌افزار و نسخه‌های آسیب‌پذیر را در اطلاعیه‌ی سازنده یا پایگاه NVD ببینید و مطمئن شوید نسخه‌ی شما واقعاً در آن بازه است.',
                'پیش از به‌روزرسانی از فایل‌ها و پایگاه داده پشتیبان بگیرید و اگر می‌توانید، اول روی نسخه‌ی آزمایشی امتحان کنید.',
                'به نسخه‌ی وصله‌شده به‌روزرسانی کنید؛ از مخزن سیستم‌عامل، پنل هاست یا سایت سازنده.',
                'اگر وصله هنوز منتشر نشده یا فوراً نمی‌توانید به‌روز کنید، بخش آسیب‌پذیر را خاموش کنید، دسترسی به آن را به IPهای مشخص محدود کنید یا با WAF (قاعده‌های CDN یا ModSecurity) درخواست‌های حمله را مسدود کنید. به این کار «وصله‌ی مجازی» می‌گویند و فقط راه‌حل موقت است.',
                'اگر این CVE در فهرست آسیب‌پذیری‌هایی است که فعالانه از آن‌ها سوءاستفاده می‌شود (CISA KEV)، یا مدتی بی‌وصله مانده، نشانه‌های نفوذ را هم بگردید: کاربر مدیر تازه، فایل‌های تغییرکرده، کارهای زمان‌بندی‌شده‌ی ناشناس.',
                'پس از وصله، دوباره بسنجید.',
            ],
            'snippets' => [
                ['label' => 'Ubuntu / Debian', 'code' => 'sudo apt update
sudo apt list --upgradable
sudo apt upgrade'],
                ['label' => 'AlmaLinux / Rocky / RHEL', 'code' => 'sudo dnf check-update
sudo dnf upgrade --refresh'],
                ['label' => 'WordPress (WP-CLI)', 'code' => 'wp core update
wp plugin update --all
wp theme update --all'],
                ['label' => 'Docker Compose', 'code' => 'docker compose pull
docker compose up -d'],
            ],
            'effort' => 'از ۱۵ دقیقه تا چند ساعت، بسته به نرم‌افزار',
            'refs' => ['https://nvd.nist.gov/', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'https://www.cve.org/'],
            'maral' => 'اگر برای به‌روزرسانی نرم‌افزارهای سرور کمک لازم دارید، شرایط انجامش را از پشتیبانی مارال کلاد بپرسید.',
        ],
        'outdated-software' => [
            'title' => 'به‌روزرسانی نرم‌افزار قدیمی یا بدون پشتیبانی',
            'why' => 'نسخه‌ی یک نرم‌افزار (مثلاً PHP، وب‌سرور، سیستم‌عامل یا CMS) قدیمی است یا دیگر از سازنده‌اش وصله‌ی امنیتی نمی‌گیرد. هر آسیب‌پذیری تازه‌ای که پیدا شود، برای این نسخه هرگز رفع نمی‌شود.',
            'steps' => [
                'نسخه‌ی دقیق را پیدا کنید و در endoflife.date ببینید هنوز پشتیبانی امنیتی دارد یا نه.',
                'اگر فقط نسخه‌ی جزئی عقب است، به آخرین نسخه‌ی همان شاخه به‌روز کنید؛ این کار معمولاً بی‌دردسر است.',
                'اگر خود شاخه به پایان عمر رسیده (مثلاً PHP 7.4 یا CentOS 7)، ارتقا را برنامه‌ریزی کنید و اول سازگاری سایت و افزونه‌ها را روی محیط آزمایشی بسنجید.',
                'در cPanel نسخه‌ی PHP هر دامنه را از MultiPHP Manager عوض کنید و بلافاصله سایت را بررسی کنید.',
                'تا زمان ارتقا، دسترسی‌ها را محدودتر کنید و اسکن را منظم تکرار کنید.',
            ],
            'snippets' => [
                ['label' => 'دیدن نسخه‌ها', 'code' => 'php -v
nginx -v
apachectl -v
mysql --version
cat /etc/os-release'],
                ['label' => 'cPanel', 'code' => 'cPanel: Software → MultiPHP Manager → (your domain) → PHP Version → Apply'],
            ],
            'effort' => 'از ۱۵ دقیقه تا یک روز، بسته به اندازه‌ی ارتقا',
            'refs' => ['https://endoflife.date/', 'https://www.php.net/supported-versions.php', 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'],
            'maral' => 'اگر سرور یا هاستتان در مارال کلاد است و برای ارتقای سیستم‌عامل یا PHP راهنمایی می‌خواهید، از پشتیبانی بپرسید.',
        ],
        'wordpress-core-outdated' => [
            'title' => 'به‌روزرسانی هسته‌ی وردپرس',
            'why' => 'نسخه‌ی وردپرس سایت قدیمی است. وصله‌های امنیتی وردپرس عمومی منتشر می‌شوند و مهاجم دقیقاً می‌داند در نسخه‌های قدیمی چه چیزی رفع نشده است؛ سایت‌های وردپرسی قدیمی از رایج‌ترین هدف‌های حمله‌ی خودکارند.',
            'steps' => [
                'از فایل‌ها و پایگاه داده پشتیبان کامل بگیرید؛ مثلاً با Backup Wizard در cPanel یا یک افزونه‌ی پشتیبان‌گیری.',
                'از «پیشخوان ← به‌روزرسانی‌ها» وردپرس را به آخرین نسخه برسانید، بعد افزونه‌ها و پوسته‌ها را هم به‌روز کنید.',
                'اگر سایت مهم است و افزونه‌های زیادی دارد، اول روی یک نسخه‌ی آزمایشی (staging) امتحان کنید.',
                'به‌روزرسانی خودکار نسخه‌های جزئی (امنیتی) را روشن نگه دارید؛ این پیش‌فرض وردپرس است، مگر کسی خاموشش کرده باشد.',
                'اگر سایت مدت زیادی به‌روز نشده، درستی فایل‌های هسته را با wp core verify-checksums بسنجید تا فایل دست‌کاری‌شده‌ای نمانده باشد.',
            ],
            'snippets' => [
                ['label' => 'WP-CLI', 'code' => 'wp db export ~/backup-before-update.sql
wp core update
wp core update-db
wp plugin update --all
wp theme update --all
wp core verify-checksums'],
                ['label' => 'wp-config.php', 'code' => 'define("WP_AUTO_UPDATE_CORE", "minor");
// and make sure this line is NOT present:
// define("AUTOMATIC_UPDATER_DISABLED", true);'],
            ],
            'effort' => 'حدود ۳۰ دقیقه',
            'refs' => ['https://developer.wordpress.org/advanced-administration/security/hardening/', 'https://developer.wordpress.org/cli/commands/core/update/', 'https://wordpress.org/news/category/security/'],
            'maral' => 'اگر سایتتان روی هاست مارال کلاد است و پیش از به‌روزرسانی به پشتیبان یا بازگردانی آن نیاز دارید، پشتیبانی می‌تواند راهنمایی کند.',
        ],
        'wordpress-plugin-vuln' => [
            'title' => 'به‌روزرسانی یا حذف افزونه‌ی آسیب‌پذیر وردپرس',
            'why' => 'یکی از افزونه‌ها یا پوسته‌های سایت آسیب‌پذیری شناخته‌شده دارد. بیشتر نفوذها به سایت‌های وردپرسی از همین راه است، نه از خود وردپرس، و ربات‌ها افزونه‌های آسیب‌پذیر را خودکار امتحان می‌کنند.',
            'steps' => [
                'نام افزونه و نسخه‌ی اصلاح‌شده را از جزئیات یافته پیدا کنید.',
                'پشتیبان بگیرید و افزونه را از «پیشخوان ← افزونه‌ها» به آخرین نسخه به‌روز کنید.',
                'اگر نسخه‌ی اصلاح‌شده‌ای نیست یا افزونه رها شده، آن را غیرفعال و حذف کنید و جایگزین معتبری پیدا کنید. افزونه‌ی غیرفعال هم تا وقتی فایل‌هایش روی سرور است، گاهی قابل سوءاستفاده است.',
                'از نسخه‌های نال‌شده یا کرک‌شده‌ی افزونه‌ها و پوسته‌های پولی استفاده نکنید؛ به‌روزرسانی نمی‌گیرند و گاهی از اول درِ پشتی دارند.',
                'اگر آسیب‌پذیری جدی بوده (مثل اجرای کد یا SQL injection)، نشانه‌های نفوذ را بررسی کنید: کاربر مدیر ناشناس، فایل PHP در پوشه‌ی uploads، تغییر ناگهانی در صفحه‌ها.',
                'افزونه‌هایی را که لازم ندارید کامل حذف کنید؛ هر افزونه‌ی اضافه، یک راه ورود اضافه است.',
            ],
            'snippets' => [
                ['label' => 'WP-CLI', 'code' => 'wp plugin list --update=available
wp plugin update PLUGIN-SLUG
# when no fixed version exists:
wp plugin deactivate PLUGIN-SLUG
wp plugin delete PLUGIN-SLUG'],
                ['label' => 'بررسی نشانه‌های نفوذ', 'code' => 'wp user list --role=administrator
wp plugin verify-checksums --all
find wp-content/uploads -type f -name "*.php"'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://wpscan.com/', 'https://www.wordfence.com/threat-intel/vulnerabilities/', 'https://patchstack.com/database/'],
            'maral' => 'اگر به نفوذ مشکوک هستید و سایتتان روی هاست مارال کلاد است، پشتیبانی می‌تواند در بازگردانی پشتیبان سالم راهنمایی کند.',
        ],
        'exposed-panel' => [
            'title' => 'محدود کردن دسترسی به پنل مدیریت',
            'why' => 'یک صفحه‌ی ورود یا پنل مدیریت (مثل wp-admin، phpMyAdmin، پنل سرور یا داشبورد یک سرویس) از همه‌جای اینترنت در دسترس است. ربات‌ها روی این صفحه‌ها رمز حدس می‌زنند و هر آسیب‌پذیری تازه‌ی آن نرم‌افزار مستقیم به دسترسی مدیر می‌رسد.',
            'steps' => [
                'ببینید پنل اصلاً باید عمومی باشد یا نه. اگر فقط شما و همکارانتان استفاده می‌کنید، دسترسی را به IPهای دفتر یا VPN محدود کنید.',
                'اگر IP ثابت ندارید، یک لایه‌ی رمز اضافه (Basic Auth) جلوی پنل بگذارید؛ در cPanel از بخش Directory Privacy.',
                'ورود دومرحله‌ای (2FA) را برای همه‌ی حساب‌های مدیر روشن کنید؛ در وردپرس افزونه‌هایی مثل Two Factor یا Wordfence این امکان را می‌دهند.',
                'رمزها را یکتا و طولانی کنید و برای ورود ناموفق محدودیت بگذارید (fail2ban، CSF/LFD یا افزونه‌ی امنیتی).',
                'ابزارهایی مثل phpMyAdmin یا Adminer را اگر استفاده نمی‌کنید حذف کنید. عوض کردن آدرس پنل فقط سروصدای ربات‌ها را کم می‌کند و جای کارهای بالا را نمی‌گیرد.',
                'اگر سایت پشت CDN است، محدودیت IP باید IP واقعی بازدیدکننده را ببیند (ماژول real_ip در nginx یا remoteip در Apache)، وگرنه فقط IP خود CDN دیده می‌شود.',
            ],
            'snippets' => [
                ['label' => 'nginx (وردپرس و phpMyAdmin)', 'code' => '# http { }: who may reach admin pages
geo $admin_ip {
    default 0;
    203.0.113.5 1;   # office IP
}
map "$admin_ip:$uri" $block_admin {
    default 0;
    "~^0:/wp-admin/admin-ajax\.php$" 0;
    "~^0:/(wp-admin|wp-login\.php|phpmyadmin)" 1;
}

# server { }:
if ($block_admin) {
    return 403;
}'],
                ['label' => 'Apache / .htaccess (wp-login.php)', 'code' => '# .htaccess in the WordPress root
<Files "wp-login.php">
    Require ip 203.0.113.5
</Files>'],
                ['label' => 'Apache / .htaccess (پوشه‌ی wp-admin)', 'code' => '# wp-admin/.htaccess
Require ip 203.0.113.5
<Files "admin-ajax.php">
    Require all granted
</Files>'],
                ['label' => 'cPanel', 'code' => 'cPanel: Files → Directory Privacy → (folder) → Password protect this directory'],
            ],
            'effort' => 'حدود ۲۰ دقیقه',
            'refs' => ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces', 'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html', 'https://wordpress.org/plugins/two-factor/'],
        ],
        'default-credentials' => [
            'title' => 'عوض کردن نام کاربری و رمز پیش‌فرض',
            'why' => 'سرویس یا دستگاهی با نام کاربری و رمز پیش‌فرض کارخانه (مثل admin/admin) کار می‌کند. این رمزها در فهرست‌های عمومی هستند و اولین چیزی‌اند که ربات‌ها امتحان می‌کنند؛ یعنی عملاً هر کسی می‌تواند وارد شود.',
            'steps' => [
                'همین حالا رمز را به یک رمز طولانی و یکتا (دست‌کم ۱۶ نویسه، ترجیحاً ساخته‌ی مدیر رمز) عوض کنید.',
                'اگر می‌شود، حساب پیش‌فرض (مثل admin) را غیرفعال کنید و برای هر نفر حساب جداگانه با کمترین دسترسی لازم بسازید.',
                'فرض کنید ممکن است کسی پیش‌تر وارد شده باشد: فهرست کاربران، تنظیمات و لاگ ورودها را بررسی کنید.',
                'دسترسی به این سرویس را به IPهای مشخص محدود کنید و اگر پشتیبانی می‌کند، ورود دومرحله‌ای را روشن کنید.',
                'برای دستگاه‌ها (مودم، دوربین، NAS) فریم‌ور را هم به‌روز کنید.',
            ],
            'snippets' => [
                ['label' => 'ساخت رمز تصادفی', 'code' => 'openssl rand -base64 24'],
                ['label' => 'MySQL / MariaDB', 'code' => "ALTER USER 'root'@'localhost' IDENTIFIED BY 'NEW-LONG-RANDOM-PASSWORD';\n-- accounts that may log in from any host\nSELECT user, host FROM mysql.user WHERE host = '%';"],
                ['label' => 'WordPress (WP-CLI)', 'code' => 'wp user list --role=administrator
# then change passwords in Users → Profile, and delete unknown admins'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials', 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'],
        ],
        'subdomain-takeover' => [
            'title' => 'پاک کردن رکورد DNS رهاشده (خطر تصاحب زیردامنه)',
            'why' => 'یک زیردامنه هنوز با رکورد CNAME یا A به سرویسی اشاره می‌کند که دیگر مال شما نیست یا حذف شده است (مثلاً سایت‌ساز، فضای ابری یا CDN). مهاجم می‌تواند همان نام را در آن سرویس برای خودش ثبت کند و زیر نام دامنه‌ی شما محتوای دلخواهش را نشان دهد؛ برای فیشینگ، سرقت کوکی‌های دامنه‌ی اصلی یا آسیب به اعتبار برند.',
            'steps' => [
                'رکورد زیردامنه را با dig یا nslookup ببینید و مشخص کنید به کدام سرویس اشاره می‌کند.',
                'اگر دیگر از آن سرویس استفاده نمی‌کنید، رکورد را همین حالا از DNS پاک کنید؛ این سریع‌ترین و مطمئن‌ترین راه است.',
                'اگر هنوز لازمش دارید، منبع را دوباره با حساب خودتان در همان سرویس بسازید و دامنه را در آن ثبت و تأیید کنید.',
                'زیردامنه را در مرورگر باز کنید. اگر محتوای ناشناسی نشان می‌دهد، ممکن است تصاحب شده باشد: رکورد را پاک کنید، و اگر کوکی ورود سایت اصلی برای همه‌ی زیردامنه‌ها (Domain=.example.com) تنظیم شده، نشست‌های کاربران را باطل کنید.',
                'از این به بعد هنگام کنار گذاشتن هر سرویس، اول رکورد DNS آن را پاک کنید و بعد خود سرویس را. فهرست رکوردهای DNS را هر چند ماه یک بار مرور کنید.',
            ],
            'snippets' => [
                ['label' => 'بررسی رکورد', 'code' => 'dig +short CNAME shop.example.com
dig +short A shop.example.com
nslookup -type=CNAME shop.example.com'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers', 'https://github.com/EdOverflow/can-i-take-over-xyz', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover'],
        ],
        'exposed-backup' => [
            'title' => 'حذف فایل‌های پشتیبان از پوشه‌ی عمومی سایت',
            'why' => 'یک فایل پشتیبان یا خروجی پایگاه داده (مثل .zip، .sql، .bak یا .tar.gz) از روی وب دانلودشدنی است. این فایل‌ها معمولاً کل کد سایت، رمز پایگاه داده و اطلاعات مشتریان را دارند؛ دانلود یکی از آن‌ها برای مهاجم یعنی یک نسخه‌ی کامل از سایت شما.',
            'steps' => [
                'همین حالا فایل را از پوشه‌ی عمومی (مثل public_html) پاک کنید یا به پوشه‌ای بیرون از آن ببرید.',
                'در همان پوشه و پوشه‌های دیگر دنبال فایل‌های مشابه بگردید (دستور find پایین).',
                'فرض کنید فایل دانلود شده است: رمز پایگاه داده و رمزهای داخل فایل‌های تنظیمات را عوض کنید. اگر اطلاعات مشتریان در آن بود، موضوع را جدی بگیرید و تعهدات قانونی و قراردادی‌تان را برای اطلاع‌رسانی بررسی کنید.',
                'در لاگ دسترسی وب‌سرور ببینید فایل پیش‌تر دانلود شده است یا نه.',
                'از این به بعد پشتیبان‌ها را بیرون از ریشه‌ی وب (مثلاً ‎/home/USER/backups) یا در فضای ذخیره‌سازی جداگانه نگه دارید. پشتیبان کامل cPanel در پوشه‌ی خانه ساخته می‌شود، نه در public_html؛ آن را به پوشه‌ی سایت منتقل نکنید.',
                'برای احتیاط، دانلود پسوندهای پشتیبان را در وب‌سرور هم ببندید.',
            ],
            'snippets' => [
                ['label' => 'پیدا کردن فایل‌های پشتیبان', 'code' => 'find /home/USER/public_html -type f \( -iname "*.sql" -o -iname "*.sql.gz" -o -iname "*.zip" -o -iname "*.tar" -o -iname "*.tar.gz" -o -iname "*.tgz" -o -iname "*.rar" -o -iname "*.7z" -o -iname "*.bak" -o -iname "*.old" \) -ls'],
                ['label' => 'nginx', 'code' => '# careful: this also blocks legitimate downloads with these extensions
location ~* \.(sql|bak|old|tar|tgz|gz|zip|rar|7z)$ {
    deny all;
}'],
                ['label' => 'Apache / .htaccess', 'code' => '<FilesMatch "\.(sql|bak|old|tar|tgz|gz|zip|rar|7z)$">
    Require all denied
</FilesMatch>'],
                ['label' => 'جست‌وجو در لاگ', 'code' => 'grep -E "\.(sql|zip|bak|rar|tar\.gz)[ ?]" /var/log/nginx/access.log* | grep " 200 "'],
            ],
            'effort' => 'حدود ۱۵ دقیقه، به‌اضافه‌ی زمان عوض کردن رمزها',
            'refs' => ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
            'maral' => 'اگر هاستتان در مارال کلاد است و برای یافتن فایل‌ها یا خواندن لاگ دانلودها کمک می‌خواهید، از پشتیبانی بپرسید.',
        ],
        'exposed-config' => [
            'title' => 'حذف یا بستن فایل‌های تنظیمات و اشکال‌زدایی',
            'why' => 'فایلی مثل phpinfo.php، فایل تنظیمات، لاگ، .DS_Store یا web.config از روی وب خوانده می‌شود. این فایل‌ها مسیرهای سرور، نسخه‌ها، نام فایل‌های پنهان و گاهی رمز پایگاه داده یا کلید API را لو می‌دهند و نقشه‌ی راه مهاجم می‌شوند.',
            'steps' => [
                'فایل‌های آزمایشی و اشکال‌زدایی (مثل phpinfo.php، info.php، test.php) را کامل پاک کنید؛ روی سایت در حال کار جایی ندارند.',
                'فایل‌های تنظیمات و لاگ را بیرون از ریشه‌ی وب نگه دارید یا دسترسی وب به آن‌ها را ببندید.',
                'فایل‌های .DS_Store (ساخته‌ی macOS) را پاک کنید و جلوی بارگذاری دوباره‌شان را با تنظیم FTP یا .gitignore بگیرید.',
                'اگر در فایل رمز یا کلیدی بود، فرض کنید دیده شده و عوضش کنید.',
                'آدرس فایل را دوباره باز کنید؛ باید خطای 403 یا 404 ببینید.',
            ],
            'snippets' => [
                ['label' => 'پیدا کردن فایل‌ها', 'code' => 'find /home/USER/public_html \( -name "phpinfo.php" -o -name "info.php" -o -name "test.php" -o -name ".DS_Store" -o -name "*.log" \) -ls'],
                ['label' => 'nginx', 'code' => '# dot-files (except /.well-known) and config or log files
location ~ /\.(?!well-known) {
    deny all;
}
location ~* \.(ini|log|conf|ya?ml|bak|dist)$ {
    deny all;
}'],
                ['label' => 'Apache / .htaccess', 'code' => '<FilesMatch "(^\.|\.(ini|log|conf|ya?ml|bak|dist)$)">
    Require all denied
</FilesMatch>'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <security>
    <requestFiltering>
      <fileExtensions>
        <add fileExtension=".log" allowed="false" />
        <add fileExtension=".ini" allowed="false" />
        <add fileExtension=".bak" allowed="false" />
      </fileExtensions>
    </requestFiltering>
  </security>
</system.webServer>'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'],
        ],
        'info-disclosure' => [
            'title' => 'خاموش کردن نمایش خطا و حالت اشکال‌زدایی',
            'why' => 'سایت پیام‌های خطای فنی، ردپای خطا (stack trace) یا صفحه‌ی حالت اشکال‌زدایی را به بازدیدکننده نشان می‌دهد. این صفحه‌ها مسیر فایل‌ها، نسخه‌ها، پرس‌وجوهای پایگاه داده و گاهی متغیرهای محیطی و رمزها را لو می‌دهند؛ صفحه‌ی اشکال‌زدایی بعضی فریم‌ورک‌ها حتی اجرای کد را ممکن می‌کند.',
            'steps' => [
                'در محیط واقعی (production) نمایش خطا به کاربر را خاموش و ثبت خطا در لاگ را روشن کنید.',
                'حالت debug فریم‌ورک را خاموش کنید: APP_DEBUG در Laravel، WP_DEBUG_DISPLAY در وردپرس، DEBUG در Django و customErrors در ASP.NET.',
                'برای خطاهای 404 و 500 یک صفحه‌ی خطای ساده و عمومی بگذارید.',
                'اگر صفحه‌ی اشکال‌زدایی مدتی باز بوده و متغیرهای محیطی یا رمزها را نشان می‌داده، آن رمزها را عوض کنید.',
                'صفحه‌ای را که خطا می‌داد دوباره باز کنید و مطمئن شوید فقط پیام عمومی دیده می‌شود.',
            ],
            'snippets' => [
                ['label' => 'PHP (php.ini)', 'code' => 'display_errors = Off
log_errors = On'],
                ['label' => 'Laravel (.env)', 'code' => 'APP_ENV=production
APP_DEBUG=false'],
                ['label' => 'WordPress (wp-config.php)', 'code' => 'define("WP_DEBUG", false);
define("WP_DEBUG_DISPLAY", false);
define("WP_DEBUG_LOG", false); // true writes wp-content/debug.log, which is publicly readable by default'],
                ['label' => 'Django (settings.py)', 'code' => 'DEBUG = False
ALLOWED_HOSTS = ["example.com", "www.example.com"]'],
                ['label' => 'ASP.NET / IIS (web.config)', 'code' => '<system.web>
  <customErrors mode="RemoteOnly" />
</system.web>
<system.webServer>
  <httpErrors errorMode="DetailedLocalOnly" />
</system.webServer>'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html', 'https://www.php.net/manual/en/errorfunc.configuration.php'],
        ],
        'cors-misconfig' => [
            'title' => 'محدود کردن CORS به دامنه‌های مجاز',
            'why' => 'تنظیم CORS به مرورگر می‌گوید کدام سایت‌های دیگر اجازه دارند پاسخ‌های سایت شما را بخوانند. اگر سرور هر Origin را بپذیرد یا مقدارش را عیناً برگرداند و هم‌زمان Access-Control-Allow-Credentials: true بفرستد، هر سایت مخربی که کاربرِ واردشده‌ی شما باز کند، می‌تواند اطلاعات حساب او را از API شما بخواند.',
            'steps' => [
                'دامنه‌هایی را که واقعاً باید به API دسترسی داشته باشند فهرست کنید (مثلاً اپ وب یا پنل خودتان).',
                'Origin درخواست را با همین فهرست به‌طور دقیق مقایسه کنید و فقط در صورت تطابق، همان را در Access-Control-Allow-Origin برگردانید. مقایسه با «شامل بودن» یا «پایان یافتن با» به‌راحتی دور زده می‌شود.',
                'هرگز مقدار Origin را بدون بررسی برنگردانید و Origin با مقدار null را مجاز نکنید.',
                'اگر API عمومی است و به کوکی یا ورود نیاز ندارد، Access-Control-Allow-Origin: * بی‌خطر است، به شرط اینکه Allow-Credentials فرستاده نشود.',
                'هدر Vary: Origin را هم بفرستید تا پاسخ‌ها در cache با هم قاطی نشوند.',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => '# http { }
map $http_origin $cors_origin {
    default "";
    "https://app.example.com" $http_origin;
    "https://www.example.com" $http_origin;
}

# server { } or location { }
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;
add_header Vary Origin always;'],
                ['label' => 'PHP', 'code' => '$allowed = ["https://app.example.com", "https://www.example.com"];
$origin = $_SERVER["HTTP_ORIGIN"] ?? "";
if (in_array($origin, $allowed, true)) {
    header("Access-Control-Allow-Origin: " . $origin);
    header("Access-Control-Allow-Credentials: true");
}
header("Vary: Origin");'],
                ['label' => 'آزمایش', 'code' => 'curl -s -I -H "Origin: https://attacker.example" https://example.com/api/ | grep -i access-control'],
            ],
            'effort' => 'حدود ۳۰ دقیقه',
            'refs' => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS', 'https://portswigger.net/web-security/cors'],
        ],
        'open-redirect' => [
            'title' => 'جلوگیری از هدایت باز (Open Redirect)',
            'why' => 'یک پارامتر در آدرس سایت (مثل ‎?next=‎ یا ‎?url=‎) بازدیدکننده را بدون بررسی به هر سایتی می‌فرستد. فیشرها پیوندی با نام دامنه‌ی معتبر شما می‌سازند که به صفحه‌ی جعلی خودشان می‌رسد؛ کاربر به نام شما اعتماد می‌کند و رمزش را جای دیگری وارد می‌کند.',
            'steps' => [
                'پارامترهای هدایت را در کد پیدا کنید (next، url، redirect، return، returnUrl و مانند این‌ها).',
                'بهترین راه این است که به‌جای آدرس کامل، فقط مسیرهای داخلی از پیش تعیین‌شده یا یک شناسه را بپذیرید و آدرس واقعی را در سرور بسازید.',
                'اگر ناچارید آدرس بپذیرید، فقط مسیر نسبی داخل سایت (شروع با یک / و نه // یا \\) یا دامنه‌های فهرست مجاز را قبول کنید و بقیه را به صفحه‌ی اصلی بفرستید.',
                'در وردپرس به‌جای wp_redirect از wp_safe_redirect استفاده کنید؛ این تابع فقط به میزبان‌های مجاز هدایت می‌کند.',
                'اگر مشکل در افزونه یا نرم‌افزار آماده است، آن را به‌روز کنید.',
            ],
            'snippets' => [
                ['label' => 'PHP (فهرست مجاز)', 'code' => '$allowed = ["/", "/account", "/orders"];
$next = (string) ($_GET["next"] ?? "/");
if (!in_array($next, $allowed, true)) {
    $next = "/";
}
header("Location: " . $next, true, 302);
exit;'],
                ['label' => 'WordPress', 'code' => 'wp_safe_redirect($url);   // instead of wp_redirect($url)
exit;'],
            ],
            'effort' => 'حدود ۳۰ دقیقه',
            'refs' => ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html', 'https://cwe.mitre.org/data/definitions/601.html'],
        ],
        'xss' => [
            'title' => 'رفع آسیب‌پذیری XSS (تزریق اسکریپت)',
            'why' => 'در XSS ورودی کاربر بدون پاک‌سازی در صفحه چاپ می‌شود و مهاجم می‌تواند جاوااسکریپت خودش را در مرورگر کاربران دیگر اجرا کند؛ نشست مدیر را بدزدد، به نام کاربر کاری انجام دهد یا فرم ورود جعلی نشان دهد.',
            'steps' => [
                'پارامتر یا فیلدی را که در یافته آمده پیدا کنید و ببینید مقدارش کجای صفحه چاپ می‌شود.',
                'هر داده‌ای را که از کاربر یا پایگاه داده می‌آید، هنگام چاپ با تابع مناسب همان جایگاه escape کنید: htmlspecialchars در PHP، و esc_html، esc_attr و esc_url در وردپرس. موتورهای قالب مثل Blade و Twig این کار را خودکار انجام می‌دهند، مگر اینکه خروجی خام ({!! !!} یا ‎|raw) استفاده شود.',
                'اگر باید HTML کاربر را نگه دارید (مثل ویرایشگر متن)، آن را با کتابخانه‌ای مثل HTML Purifier یا تابع wp_kses_post پاک‌سازی کنید.',
                'اگر آسیب‌پذیری در افزونه، پوسته یا نرم‌افزار آماده است، به‌روز کنید یا تا رفعش غیرفعالش کنید.',
                'CSP و پرچم HttpOnly کوکی‌ها را هم تنظیم کنید تا اثر XSSهای احتمالی بعدی کمتر شود.',
            ],
            'snippets' => [
                ['label' => 'PHP', 'code' => 'echo htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");'],
                ['label' => 'WordPress', 'code' => '<a href="<?php echo esc_url($link); ?>" title="<?php echo esc_attr($title); ?>">
    <?php echo esc_html($title); ?>
</a>'],
                ['label' => 'JavaScript', 'code' => '// put user data in with textContent, not innerHTML
element.textContent = userInput;'],
            ],
            'effort' => 'از ۳۰ دقیقه تا چند ساعت',
            'refs' => ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html', 'https://portswigger.net/web-security/cross-site-scripting'],
        ],
        'sqli' => [
            'title' => 'رفع آسیب‌پذیری SQL Injection',
            'why' => 'ورودی کاربر مستقیم داخل دستور SQL گذاشته می‌شود و مهاجم می‌تواند دستور پایگاه داده را عوض کند: اطلاعات همه‌ی کاربران و سفارش‌ها را بخواند، رمزها را بردارد، داده‌ها را تغییر دهد یا پاک کند. این از جدی‌ترین آسیب‌پذیری‌های وب است.',
            'steps' => [
                'اگر آسیب‌پذیری در افزونه یا نرم‌افزار آماده است، فوراً به‌روز کنید یا تا رفعش غیرفعالش کنید.',
                'در کد خودتان همه‌ی پرس‌وجوها را با prepared statement بنویسید (پارامتر جدا از دستور). چسباندن ورودی به رشته‌ی SQL، حتی با escape دستی، راه مطمئنی نیست.',
                'کاربر پایگاه داده‌ی سایت فقط دسترسی‌های لازم را داشته باشد؛ نه root، و نه دسترسی به پایگاه‌های دیگر.',
                'تا رفع کامل، یک WAF (قاعده‌های CDN یا ModSecurity با OWASP CRS) جلوی بیشتر تلاش‌ها را می‌گیرد.',
                'بررسی کنید سوءاستفاده‌ای شده است یا نه: لاگ وب‌سرور را برای الگوهایی مثل UNION SELECT بگردید، کاربران مدیر را مرور کنید و اگر شک دارید، رمزها را بازنشانی کنید.',
            ],
            'snippets' => [
                ['label' => 'PHP (PDO)', 'code' => '$stmt = $pdo->prepare("SELECT id, name FROM customers WHERE email = ?");
$stmt->execute([$email]);
$row = $stmt->fetch();'],
                ['label' => 'WordPress', 'code' => '$row = $wpdb->get_row(
    $wpdb->prepare("SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $orderId)
);'],
                ['label' => 'جست‌وجو در لاگ', 'code' => 'grep -iE "union(%20|\+|\s)+select|information_schema|sleep\(" /var/log/nginx/access.log*'],
            ],
            'effort' => 'از یک ساعت تا چند روز، بسته به کد',
            'refs' => ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html', 'https://portswigger.net/web-security/sql-injection'],
            'maral' => 'اگر به سوءاستفاده مشکوک هستید و سایتتان روی هاست مارال کلاد است، پشتیبانی می‌تواند در بازگردانی پشتیبان سالم راهنمایی کند.',
        ],
        'ssrf' => [
            'title' => 'رفع آسیب‌پذیری SSRF',
            'why' => 'سایت آدرسی را از کاربر می‌گیرد و خودش به آن درخواست می‌فرستد (مثلاً برای پیش‌نمایش پیوند یا دریافت تصویر). مهاجم به‌جای آدرس عادی، آدرس سرویس‌های داخلی را می‌دهد و از راه سایت شما به جاهایی می‌رسد که از بیرون بسته‌اند؛ مثل پنل‌های داخلی، پایگاه داده یا سرویس metadata ابری که کلید دسترسی دارد.',
            'steps' => [
                'اگر این قابلیت در نرم‌افزار آماده است، به‌روز کنید یا تا رفعش غیرفعالش کنید.',
                'تا جای ممکن فقط دامنه‌های فهرست مجاز را بپذیرید، نه هر آدرسی را.',
                'اگر ناچارید آدرس دلخواه بپذیرید: فقط http و https را قبول کنید، نام را به IP تبدیل کنید و IPهای داخلی (127.0.0.0/8، 10.0.0.0/8، 172.16.0.0/12، 192.168.0.0/16، 169.254.0.0/16 و معادل‌های IPv6) را رد کنید. بعد به همان IP بررسی‌شده وصل شوید تا تغییر DNS در میانه‌ی کار بررسی را دور نزند.',
                'دنبال کردن خودکار هدایت (redirect) را خاموش کنید، یا هر مقصد را دوباره بسنجید.',
                'در سطح شبکه هم دسترسی خروجی وب‌سرور به شبکه‌ی داخلی و آدرس metadata را با فایروال ببندید.',
            ],
            'snippets' => [
                ['label' => 'PHP', 'code' => '$parts = parse_url((string) $_POST["url"]);
$scheme = $parts["scheme"] ?? "";
if (!in_array($scheme, ["http", "https"], true) || empty($parts["host"])) {
    throw new RuntimeException("Invalid URL");
}
$ip = gethostbyname($parts["host"]);
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    throw new RuntimeException("Blocked address");
}
// connect to the checked IP only, and do not follow redirects
$port = $parts["port"] ?? ($scheme === "https" ? 443 : 80);
$ch = curl_init((string) $_POST["url"]);
curl_setopt_array($ch, [
    CURLOPT_RESOLVE => [$parts["host"] . ":" . $port . ":" . $ip],
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 10,
]);'],
                ['label' => 'iptables (بستن metadata برای کاربر وب‌سرور)', 'code' => 'iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner www-data -j REJECT'],
            ],
            'effort' => 'از یک ساعت تا چند روز',
            'refs' => ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html', 'https://portswigger.net/web-security/ssrf'],
        ],
        'lfi-rce' => [
            'title' => 'اقدام فوری برای آسیب‌پذیری خواندن فایل یا اجرای کد',
            'why' => 'این دسته از آسیب‌پذیری‌ها (پیمایش مسیر، include فایل، اجرای کد از راه دور) به مهاجم اجازه می‌دهد فایل‌های سرور مثل تنظیمات و رمزها را بخواند یا مستقیم روی سرور فرمان اجرا کند. اجرای کد یعنی کنترل کامل سایت و اغلب کل حساب هاست؛ این مورد را اضطراری بدانید.',
            'steps' => [
                'فوراً جلوی دسترسی را بگیرید: بخش آسیب‌پذیر (افزونه، اسکریپت یا مسیر) را غیرفعال کنید، یا با WAF و محدودیت IP ببندید. اگر لازم است، سایت را موقتاً در حالت تعمیر بگذارید.',
                'پیش از پاک‌سازی، از وضعیت فعلی (فایل‌ها، پایگاه داده و لاگ‌ها) یک نسخه‌ی جدا نگه دارید تا بعداً بشود فهمید چه اتفاقی افتاده است.',
                'نرم‌افزار آسیب‌پذیر را به نسخه‌ی وصله‌شده به‌روز کنید یا حذفش کنید.',
                'نشانه‌های نفوذ را بگردید: فایل‌های PHP تازه یا تغییرکرده (به‌خصوص در پوشه‌ی uploads)، کدهای مشکوک مثل eval و base64_decode، کاربران مدیر ناشناس، کارهای زمان‌بندی‌شده (cron) و کلیدهای SSH ناآشنا.',
                'همه‌ی رمزها و کلیدها را عوض کنید: پایگاه داده، پنل هاست، FTP و SSH، مدیران سایت و کلیدهای API داخل تنظیمات.',
                'اگر از پاک بودن سرور مطمئن نیستید، سایت را از پشتیبان سالمِ پیش از نفوذ بازگردانید و بعد وصله کنید؛ پاک‌سازی دستی معمولاً درِ پشتی‌های پنهان را جا می‌اندازد.',
            ],
            'snippets' => [
                ['label' => 'فایل‌های PHP تازه یا مشکوک', 'code' => 'find /home/USER/public_html -type f -name "*.php" -mtime -7 -ls
find /home/USER/public_html/wp-content/uploads -type f -name "*.php"'],
                ['label' => 'جست‌وجوی کد مشکوک', 'code' => 'grep -rlE "eval\(|base64_decode\(|gzinflate\(|str_rot13\(|assert\(|shell_exec\(|passthru\(|system\(" --include=*.php /home/USER/public_html'],
                ['label' => 'cron، کلیدها و مدیران', 'code' => 'crontab -l
ls -la ~/.ssh/
wp user list --role=administrator'],
                ['label' => 'PHP (php.ini) برای سخت‌تر کردن', 'code' => 'allow_url_include = Off
allow_url_fopen = Off   ; only if the site does not need it
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
; test the site afterwards: some plugins need some of these'],
            ],
            'effort' => 'از چند ساعت تا یک روز',
            'refs' => ['https://portswigger.net/web-security/file-path-traversal', 'https://owasp.org/www-community/attacks/Path_Traversal', 'https://owasp.org/www-community/attacks/Command_Injection'],
            'maral' => 'اگر سایتتان روی هاست یا سرور مارال کلاد است، بی‌درنگ به پشتیبانی خبر دهید تا در جدا کردن سایت و بازگردانی پشتیبان سالم راهنمایی‌تان کنند.',
        ],
        'weak-ssh' => [
            'title' => 'ایمن کردن ورود SSH',
            'why' => 'سرور SSH ورود با رمز یا ورود مستقیم کاربر root را می‌پذیرد. ربات‌ها شبانه‌روز روی SSH رمز حدس می‌زنند و یک رمز ضعیف یا تکراری کافی است تا کنترل کامل سرور از دست برود.',
            'steps' => [
                'یک کلید SSH بسازید و روی سرور نصبش کنید (ssh-keygen و ssh-copy-id).',
                'در یک پنجره‌ی جدید مطمئن شوید با کلید وارد می‌شوید. پنجره‌ی فعلی را تا پایان کار نبندید تا اگر اشتباهی شد، دسترسی‌تان قطع نشود.',
                'ورود با رمز و ورود مستقیم root را خاموش کنید. در توزیع‌های جدید، فایل‌های پوشه‌ی ‎/etc/ssh/sshd_config.d/ (مثلاً تنظیمی که cloud-init می‌گذارد) بر sshd_config مقدم‌اند؛ تنظیم را در فایلی به نام 00-hardening.conf بگذارید تا اول خوانده شود.',
                'پیکربندی را با sshd -t آزمایش کنید، سرویس را reload کنید و تنظیم نهایی را با sshd -T ببینید.',
                'اگر می‌شود، درگاه SSH را فقط برای IPهای مشخص باز بگذارید و fail2ban یا CSF/LFD را برای مسدود کردن حدس رمز روشن کنید.',
            ],
            'snippets' => [
                ['label' => 'ساخت و نصب کلید', 'code' => 'ssh-keygen -t ed25519 -C "you@example.com"
ssh-copy-id user@server.example.com'],
                ['label' => 'sshd', 'code' => '# /etc/ssh/sshd_config.d/00-hardening.conf
# (older systems without sshd_config.d: put these in /etc/ssh/sshd_config)
PermitRootLogin no        # or prohibit-password, if root must log in with a key
PasswordAuthentication no
KbdInteractiveAuthentication no   # OpenSSH older than 8.7: ChallengeResponseAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3'],
                ['label' => 'اعمال و بررسی', 'code' => 'sudo sshd -t && sudo systemctl reload ssh    # RHEL / AlmaLinux: sshd
sudo sshd -T | grep -Ei "permitrootlogin|passwordauthentication"'],
                ['label' => 'fail2ban (Ubuntu / Debian)', 'code' => 'sudo apt install fail2ban
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd'],
            ],
            'effort' => 'حدود ۲۰ دقیقه',
            'refs' => ['https://infosec.mozilla.org/guidelines/openssh', 'https://man.openbsd.org/sshd_config'],
            'maral' => 'اگر سرورتان در مارال کلاد است و دسترسی SSH را از دست دادید، از راه کنسول پنل یا پشتیبانی می‌شود دسترسی را برگرداند.',
        ],
        'ftp-plaintext' => [
            'title' => 'جایگزینی FTP بی‌رمز با SFTP یا FTPS',
            'why' => 'FTP نام کاربری، رمز و فایل‌ها را بدون رمزنگاری می‌فرستد و هر کس در مسیر شبکه باشد رمز را می‌بیند. رمز FTP معمولاً یعنی اجازه‌ی نوشتن روی فایل‌های سایت، و این یکی از راه‌های رایج آلوده شدن سایت‌هاست. FTP ناشناس (anonymous) هم اگر باز باشد، فایل‌ها را در اختیار همه می‌گذارد.',
            'steps' => [
                'اگر دسترسی SSH دارید، به‌جای FTP از SFTP استفاده کنید؛ نرم‌افزارهایی مثل FileZilla و WinSCP آن را پشتیبانی می‌کنند.',
                'اگر FTP لازم است، رمزنگاری را اجباری کنید (FTPS یعنی FTP روی TLS). در WHM از FTP Server Configuration گزینه‌ی TLS Encryption Support را روی Required بگذارید.',
                'در FileZilla، در Site Manager گزینه‌ی Encryption را روی Require explicit FTP over TLS بگذارید.',
                'ورود ناشناس (anonymous) را خاموش و حساب‌های FTP بی‌استفاده را حذف کنید.',
                'اگر دیگر به FTP نیازی نیست، سرویس را خاموش کنید و درگاه 21 را در فایروال ببندید.',
                'رمز حساب‌هایی را که تا امروز روی FTP بی‌رمز استفاده شده‌اند عوض کنید.',
            ],
            'snippets' => [
                ['label' => 'WHM (cPanel)', 'code' => 'WHM: Service Configuration → FTP Server Configuration
TLS Encryption Support: Required (Command)
Allow Anonymous Logins: No'],
                ['label' => 'vsftpd', 'code' => '# /etc/vsftpd.conf
anonymous_enable=NO
ssl_enable=YES
force_local_logins_ssl=YES
force_local_data_ssl=YES
rsa_cert_file=/etc/ssl/certs/ftp.example.com.pem
rsa_private_key_file=/etc/ssl/private/ftp.example.com.key'],
                ['label' => 'SFTP', 'code' => 'sftp user@server.example.com'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://security.appspot.com/vsftpd/vsftpd_conf.html', 'https://man.openbsd.org/sftp'],
        ],
        'smtp-open-relay' => [
            'title' => 'بستن رله‌ی باز ایمیل (Open Relay)',
            'why' => 'سرور ایمیل شما ایمیل هر فرستنده‌ای را بدون ورود به حساب، به هر مقصدی می‌رساند. اسپمرها خیلی زود از چنین سروری برای ارسال انبوه استفاده می‌کنند؛ IP سرور به فهرست‌های سیاه می‌رود و ایمیل‌های واقعی شما و همه‌ی سایت‌های روی آن سرور دیگر به مقصد نمی‌رسند.',
            'steps' => [
                'رله را طوری تنظیم کنید که فقط کاربرانِ واردشده (SMTP AUTH) و خود سرور بتوانند به دامنه‌های بیرونی ایمیل بفرستند.',
                'صف ایمیل را بررسی کنید؛ اگر پر از اسپم است، پس از بستن رله خالی‌اش کنید.',
                'با یک آزمایش از بیرون مطمئن شوید ایمیل بدون ورود به مقصد بیرونی پذیرفته نمی‌شود (پاسخ Relay access denied).',
                'IP سرور را در فهرست‌های سیاه (مثل Spamhaus) بررسی کنید و پس از رفع مشکل، درخواست حذف بدهید.',
            ],
            'snippets' => [
                ['label' => 'Postfix (main.cf)', 'code' => 'mynetworks = 127.0.0.0/8 [::1]/128
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination'],
                ['label' => 'اعمال و دیدن صف', 'code' => 'sudo postfix check && sudo systemctl reload postfix
postqueue -p | tail -n 1'],
                ['label' => 'آزمایش از بیرون', 'code' => 'swaks --server mail.example.com --from test@example.net --to someone@example.org
# expected: "Relay access denied" (a 5xx reply)'],
            ],
            'effort' => 'حدود ۲۰ دقیقه',
            'refs' => ['https://www.postfix.org/SMTPD_ACCESS_README.html', 'https://www.postfix.org/postconf.5.html', 'https://www.spamhaus.org/'],
            'maral' => 'اگر سرور ایمیلتان در مارال کلاد است و IP آن در فهرست سیاه رفته، پشتیبانی می‌تواند در پیگیری حذف راهنمایی‌تان کند.',
        ],
        'dns-zone-transfer' => [
            'title' => 'بستن انتقال ناحیه‌ی DNS (AXFR)',
            'why' => 'سرور نام دامنه به هر کسی اجازه می‌دهد فهرست کامل رکوردها را یک‌جا بگیرد. این فهرست همه‌ی زیردامنه‌ها، از جمله سرورهای آزمایشی، پنل‌های داخلی و سرویس‌هایی را که قرار نبود دیده شوند، به مهاجم نشان می‌دهد.',
            'steps' => [
                'انتقال ناحیه را فقط برای سرورهای نام ثانویه‌ی خودتان (با IP مشخص یا کلید TSIG) مجاز کنید و برای بقیه ببندید.',
                'اگر سرور نام ثانویه ندارید، انتقال ناحیه را کامل خاموش کنید.',
                'این کار را روی همه‌ی سرورهای نام دامنه (همه‌ی NSها) انجام دهید.',
                'با dig از بیرون آزمایش کنید؛ پاسخ باید Transfer failed یا REFUSED باشد.',
            ],
            'snippets' => [
                ['label' => 'BIND (named.conf)', 'code' => '// in options { } or in each zone { }
allow-transfer { none; };
// or only your secondary name servers:
// allow-transfer { 203.0.113.53; };'],
                ['label' => 'PowerDNS (pdns.conf)', 'code' => 'disable-axfr=yes
# or only your secondary: allow-axfr-ips=203.0.113.53/32'],
                ['label' => 'Windows DNS (PowerShell)', 'code' => 'Set-DnsServerPrimaryZone -Name "example.com" -SecureSecondaries NoTransfer'],
                ['label' => 'آزمایش', 'code' => 'dig AXFR example.com @ns1.example.com'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://www.rfc-editor.org/rfc/rfc5936', 'https://bind9.readthedocs.io/'],
        ],
        'dnssec-missing' => [
            'title' => 'فعال کردن DNSSEC (اختیاری)',
            'why' => 'DNSSEC پاسخ‌های DNS دامنه را امضا می‌کند تا کسی نتواند در مسیر پاسخ جعلی جا بزند و بازدیدکننده را به سرور دیگری بفرستد. برای بیشتر سایت‌ها خطر نبودنش کم و اولویتش پایین است؛ اما تنظیم نادرستش می‌تواند کل دامنه را از دسترس خارج کند.',
            'steps' => [
                'بررسی کنید که هم ارائه‌دهنده‌ی DNS و هم ثبت‌کننده‌ی دامنه (registrar) از DNSSEC پشتیبانی می‌کنند.',
                'DNSSEC را در پنل ارائه‌دهنده‌ی DNS روشن کنید؛ این پنل یک رکورد DS به شما می‌دهد.',
                'رکورد DS را در پنل ثبت‌کننده‌ی دامنه وارد کنید.',
                'چند ساعت بعد با dig یا ابزار DNSViz درستی زنجیره را بسنجید.',
                'مهم: پیش از بردن DNS به ارائه‌دهنده‌ی دیگر، اول رکورد DS را نزد ثبت‌کننده حذف کنید؛ وگرنه دامنه از دسترس خارج می‌شود.',
            ],
            'snippets' => [
                ['label' => 'بررسی', 'code' => 'dig +short DS example.com
dig +dnssec example.com A'],
            ],
            'effort' => 'حدود ۳۰ دقیقه',
            'refs' => ['https://www.rfc-editor.org/rfc/rfc4033', 'https://dnsviz.net/', 'https://developers.cloudflare.com/dns/dnssec/'],
        ],
        'http-methods' => [
            'title' => 'خاموش کردن متدهای HTTP غیرضروری (TRACE، PUT و…)',
            'why' => 'سرور متدهایی مثل TRACE، PUT یا DELETE را می‌پذیرد که سایت معمولی به آن‌ها نیازی ندارد. PUT و DELETE اگر واقعاً کار کنند (مثلاً با WebDAV)، اجازه‌ی بارگذاری یا پاک کردن فایل روی سرور را می‌دهند؛ TRACE هم در کنار مشکلات دیگر به سرقت اطلاعات نشست کمک می‌کند.',
            'steps' => [
                'در Apache متد TRACE را با TraceEnable off خاموش کنید؛ nginx به‌طور پیش‌فرض TRACE را نمی‌پذیرد.',
                'اگر از WebDAV استفاده نمی‌کنید، ماژولش را خاموش کنید (mod_dav در Apache، نقش WebDAV در IIS).',
                'متدها را به همان‌هایی محدود کنید که سایت لازم دارد. سایت معمولی فقط GET، HEAD و POST می‌خواهد؛ APIها ممکن است PUT، PATCH، DELETE و OPTIONS (برای CORS) هم لازم داشته باشند.',
                'با curl آزمایش کنید که TRACE پاسخ 405 یا 403 می‌گیرد.',
            ],
            'snippets' => [
                ['label' => 'Apache', 'code' => '# main server config
TraceEnable off
# Debian/Ubuntu, if WebDAV is not used:
# sudo a2dismod dav_fs dav'],
                ['label' => 'nginx', 'code' => 'location / {
    limit_except GET POST {   # GET also allows HEAD
        deny all;
    }
    # ... the rest of this location
}'],
                ['label' => 'WHM (cPanel)', 'code' => 'WHM: Service Configuration → Apache Configuration → Global Configuration → Trace Enable: Off'],
                ['label' => 'IIS (web.config)', 'code' => '<system.webServer>
  <security>
    <requestFiltering>
      <verbs allowUnlisted="true">
        <add verb="TRACE" allowed="false" />
        <add verb="TRACK" allowed="false" />
      </verbs>
    </requestFiltering>
  </security>
</system.webServer>'],
                ['label' => 'آزمایش', 'code' => 'curl -i -X TRACE https://example.com/
curl -i -X OPTIONS https://example.com/'],
            ],
            'effort' => 'حدود ۱۰ دقیقه',
            'refs' => ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods', 'https://httpd.apache.org/docs/2.4/mod/core.html#traceenable'],
        ],
        'weak-cipher' => [
            'title' => 'حذف رمزهای ضعیف TLS',
            'why' => 'سرور هنوز مجموعه‌رمزهای (cipher suite) قدیمی مثل RC4، 3DES یا رمزهای بدون Forward Secrecy را می‌پذیرد. این رمزها حمله‌های شناخته‌شده دارند و مهاجم گاهی می‌تواند اتصال را به ضعیف‌ترین گزینه پایین بیاورد. مرورگرهای امروزی به هیچ‌کدامشان نیاز ندارند.',
            'steps' => [
                'پیکربندی پیشنهادی Mozilla را در حالت Intermediate، برای وب‌سرور و نسخه‌ی OpenSSL خودتان، از ssl-config.mozilla.org بسازید؛ این حالت با تقریباً همه‌ی مرورگرهای امروزی سازگار است.',
                'فقط TLS 1.2 و 1.3 و رمزهای AEAD (مثل AES-GCM و ChaCha20) با تبادل کلید ECDHE را نگه دارید.',
                'پیکربندی را آزمایش و سرویس را reload کنید.',
                'نتیجه را با SSL Labs بسنجید؛ هدف نمره‌ی A است.',
                'روی سرورهای cPanel و DirectAdmin این تنظیم در سطح سرور است (WHM یا پیکربندی وب‌سرور).',
            ],
            'snippets' => [
                ['label' => 'nginx', 'code' => 'ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;'],
                ['label' => 'Apache', 'code' => 'SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder off'],
                ['label' => 'WHM (cPanel)', 'code' => 'WHM: Service Configuration → Apache Configuration → Global Configuration → SSL Cipher Suite'],
                ['label' => 'IIS / Windows (PowerShell)', 'code' => 'Get-TlsCipherSuite | Where-Object { $_.Name -match "RC4|3DES|NULL|EXPORT|_CBC_" } | ForEach-Object { Disable-TlsCipherSuite -Name $_.Name }
# test your clients afterwards; a restart may be needed'],
                ['label' => 'آزمایش', 'code' => 'nmap --script ssl-enum-ciphers -p 443 example.com'],
            ],
            'effort' => 'حدود ۱۵ دقیقه',
            'refs' => ['https://ssl-config.mozilla.org/', 'https://wiki.mozilla.org/Security/Server_Side_TLS', 'https://www.ssllabs.com/ssltest/'],
            'maral' => 'روی هاست اشتراکی این تنظیم در سطح سرور است؛ اگر هاستتان در مارال کلاد است، موضوع را با پشتیبانی در میان بگذارید.',
        ],
        // @@KB-MORE@@
    ];

    /** Built-in check keys (after "builtin.", dashes read as underscores): prefix => kb key. */
    private const BUILTIN = [
        'dns.no_address' => 'dns-no-address',
        'dns.no_caa' => 'dns-caa',
        'dns.caa' => 'dns-caa',
        'tls.expired' => 'tls-expired',
        'tls.expiring' => 'tls-expiring',
        'tls.hostname' => 'tls-hostname',
        'tls.self_signed' => 'tls-self-signed',
        'tls.old_protocol' => 'tls-old-protocol',
        'tls.weak_cipher' => 'weak-cipher',
        'web.no_https' => 'web-no-https',
        'web.no_redirect' => 'web-no-redirect',
        'web.listing' => 'web-listing',
        'web.git' => 'web-git',
        'web.env' => 'web-env',
        'web.server_status' => 'web-server-status',
        'hdr.hsts' => 'hdr-hsts',
        'hdr.csp' => 'hdr-csp',
        'hdr.frame' => 'hdr-frame',
        'hdr.nosniff' => 'hdr-nosniff',
        'hdr.version' => 'hdr-version',
        'cookie.flags' => 'cookie-flags',
        'cookie' => 'cookie-flags',
        'port' => 'port-exposed',
        'mail.spf' => 'mail-spf',
        'mail.dmarc' => 'mail-dmarc',
    ];

    /**
     * Keyword rules for other engines, first match wins. Matched against "<source key> <title>" in lower case
     * (ASCII lower-casing only, so Persian titles pass through unchanged and simply do not match).
     */
    private const RULES = [
        ['~takeover|dangling[-_ ]?(cname|dns|record)~', 'subdomain-takeover'],
        ['~default[-_ ]?(login|cred|password|account|admin)|weak[-_ ]?(login|cred|password)|(?<![a-z])blank[-_ ]?password~', 'default-credentials'],
        ['~open[-_ ]?relay~', 'smtp-open-relay'],
        ['~axfr|zone[-_ ]?transfer~', 'dns-zone-transfer'],
        ['~(?<![a-z])(panels?|dashboard)(?![a-z])|admin[-_ ]?(interface|console|portal)|^(?=.*login)(?=.*(exposed|detect))~s', 'exposed-panel'],
        ['~^(?=.*(wordpress|(?<![a-z])wp[-_]))(?=.*(plugin|theme))~s', 'wordpress-plugin-vuln'],
        ['~^(?=.*(wordpress|(?<![a-z])wp[-_]))(?=.*(version|outdated|core|eol|update))~s', 'wordpress-core-outdated'],
        ['~(?<![a-z])cve-\d{4}-\d{3,}~', 'cve-patch'],
        ['~stack[-_ ]?trace|traceback|debug[-_ ]?(mode|page|enabled|bar|toolbar)|ignition|werkzeug|whoops~', 'info-disclosure'],
        ['~^(?=.*cookie)(?=.*(secure|httponly|http[-_ ]?only|samesite|flag|attribute))~s', 'cookie-flags'],
        ['~x[-_ ]?powered[-_ ]?by|server[-_ ]?(header|banner)|^(?=.*version)(?=.*(header|banner|disclos|leak))~s', 'hdr-version'],
        ['~(?<![a-z])(git|svn|hg|bzr)(?![a-z])~', 'web-git'],
        ['~\.env(?![a-z])|dotenv|(?<![a-z])env[-_ ]?file|[-_]env(?![a-z])~', 'web-env'],
        ['~directory[-_ ]?(listing|browsing|indexing)|dir[-_ ]?listing|index[-_ ]?of|autoindex|open[-_ ]?directory~', 'web-listing'],
        ['~server[-_ ]?(status|info)(?![a-z])~', 'web-server-status'],
        ['~xss|cross[-_ ]?site[-_ ]?scripting~', 'xss'],
        ['~sqli(?![a-z])|sql[-_ ]?injection~', 'sqli'],
        ['~ssrf|server[-_ ]?side[-_ ]?request~', 'ssrf'],
        ['~(?<![a-z])(lfi|rfi|rce|ssti)(?![a-z])|traversal|file[-_ ]?inclusion|remote[-_ ]?code|code[-_ ]?(execution|injection)|command[-_ ]?injection|os[-_ ]?command|deserializ|web[-_ ]?shell|backdoor|arbitrary[-_ ]?file~', 'lfi-rce'],
        ['~(?<![a-z])cors(?![a-z])|cross[-_ ]?origin~', 'cors-misconfig'],
        ['~http[-_ ]?to[-_ ]?https|(missing|no)[-_ ]?(https[-_ ]?)?redirect~', 'web-no-redirect'],
        ['~redirect~', 'open-redirect'],
        ['~backup|(?<![a-z])bak(?![a-z])|\.sql(?![a-z])|\.zip(?![a-z])|\.tar(?![a-z])|\.t?gz(?![a-z])|\.rar(?![a-z])|\.7z(?![a-z])|\.old(?![a-z])|\.swp(?![a-z])|dump~', 'exposed-backup'],
        ['~phpinfo|\.ds_store|ds[-_]store|web\.config|\.htaccess|\.htpasswd|docker[-_]compose|(?<![a-z])config|\.ini(?![a-z])|\.ya?ml(?![a-z])|\.log(?![a-z])|debug|(?<![a-z])(settings|credentials|secrets?)\.~', 'exposed-config'],
        ['~^(?=.*(?<![a-z])ssh)(?=.*(weak|password|root|auth|cipher|algo|brute|kex|mac))~s', 'weak-ssh'],
        ['~(?<![a-z])ftp~', 'ftp-plaintext'],
        ['~tls[-_ ]?v?1[._-]?[01](?![0-9])|ssl[-_ ]?v?[23](?![0-9])|(deprecated|old|legacy|insecure|obsolete)[-_ ]?(tls|ssl)|(tls|ssl)[-_ ]?(version|protocol)[-_ ]?(deprecated|old|legacy|insecure|obsolete)~', 'tls-old-protocol'],
        ['~cipher|weak[-_ ]?(tls|ssl)|^(?=.*(ssl|tls))(?=.*(weak|insecure|sweet32|rc4|3des|export|logjam|freak|beast))~s', 'weak-cipher'],
        ['~^(?=.*expired)(?=.*(ssl|tls|cert))~s', 'tls-expired'],
        ['~^(?=.*expir)(?=.*(ssl|tls|cert))~s', 'tls-expiring'],
        ['~self[-_ ]?signed~', 'tls-self-signed'],
        ['~^(?=.*(ssl|tls|cert))(?=.*(mismatch|hostname|wrong[-_ ]?host|common[-_ ]?name))~s', 'tls-hostname'],
        ['~(no|missing|without)[-_ ]?(https|ssl|tls)(?![a-z])|plain[-_ ]?http(?![a-z])|unencrypted[-_ ]?http~', 'web-no-https'],
        ['~hsts|strict[-_ ]?transport~', 'hdr-hsts'],
        ['~(?<![a-z])csp(?![a-z])|content[-_ ]?security[-_ ]?policy~', 'hdr-csp'],
        ['~x[-_ ]?frame|clickjack|frame[-_ ]?(options|ancestors)~', 'hdr-frame'],
        ['~nosniff|content[-_ ]?type[-_ ]?options~', 'hdr-nosniff'],
        ['~(?<![a-z])spf(?![a-z])~', 'mail-spf'],
        ['~dmarc~', 'mail-dmarc'],
        ['~(?<![a-z])caa(?![a-z])~', 'dns-caa'],
        ['~dnssec~', 'dnssec-missing'],
        ['~security[._ -]?txt~', 'security-txt'],
        ['~mixed[-_ ]?content~', 'mixed-content'],
        ['~(?<![a-z])(trace|track)(?![a-z])|http[-_ ]?methods?|webdav|(?<![a-z])(put|delete|options)[-_ ]?method~', 'http-methods'],
        ['~(no|missing|without)[-_ ]?waf|waf[-_ ]?(missing|not[-_ ]?detected|absent)~', 'waf-missing'],
        ['~^(?=.*(?<![a-z])(mysql|mariadb|postgres|mongo|redis|elasticsearch|memcached|rdp|smb|docker|vnc|telnet|mssql|rabbitmq|kubernetes|kubelet|etcd|zookeeper|couchdb|cassandra|rsync|nfs|ldap|snmp|rpcbind|winrm))(?=.*(exposed|unauth|open|no[-_ ]?auth|detect|service|port))|open[-_ ]?port|exposed[-_ ]?(port|service)~s', 'port-exposed'],
        ['~outdated|end[-_ ]?of[-_ ]?life|(?<![a-z])eol(?![a-z])|unsupported|obsolete|(?<![a-z])version~', 'outdated-software'],
        ['~disclos|error|exception|leak|verbose|sensitive|exposure~', 'info-disclosure'],
    ];

    /** The entry for a kb key, or null when the key is unknown. */
    public static function get(string $key): ?array
    {
        return self::ENTRIES[$key] ?? null;
    }

    /**
     * Best kb key for a finding from its engine source key (e.g. "builtin.hdr.hsts", "nuclei.cve-2021-44228",
     * "oasm.git-config") and title; '' when nothing fits.
     */
    public static function match(string $sourceKey, string $title): string
    {
        $key = strtolower(trim($sourceKey));
        $dot = strpos($key, '.');
        $engine = $dot === false ? '' : substr($key, 0, $dot);
        $rest = $dot === false ? $key : substr($key, $dot + 1);

        // 1. built-in checks: the key names the check exactly
        if ($engine === 'builtin') {
            $check = str_replace('-', '_', $rest);
            foreach (self::BUILTIN as $prefix => $kb) {
                if ($check === $prefix || str_starts_with($check, $prefix . '.') || str_starts_with($check, $prefix . '_')) {
                    return $kb;
                }
            }
        }

        // 2. an engine that already speaks kb keys ("oasm.web-git", or a bare "web-git")
        if ($rest !== 'generic' && isset(self::ENTRIES[$rest])) {
            return $rest;
        }

        // 3. keywords in the key and the title
        $hay = $key . ' ' . strtolower(trim($title));
        foreach (self::RULES as [$re, $kb]) {
            if (preg_match($re, $hay) === 1) {
                return $kb;
            }
        }
        return '';
    }
}
