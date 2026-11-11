# MC-Sec — راهنمای کار برای Claude Code

ماژول افزودنی WHMCS 9.0.9 (production) و 9.1 (PHP 8.3، قالب Lagom2) برای **فضای کار امنیت سایبری** مشتریان مارال کلاد: دارایی (دامنه، زیردامنه، فهرست، IP، بازه‌ی کوچک IPv4) با **تأیید مالکیت**، اسکن روی **OASM**، **Osmedeus** و بررسی‌های داخلی، یافته با چرخه‌ی عمر و راه رفع فارسی، گزارش پایه و **هوش مصنوعی**، **زمان‌بندی**، **اعلان** (پنل، ایمیل WHMCS، بله، تلگرام، وب‌هوک امضاشده) و **کیف اعتبار اسکن** (اعتبار ماهانه‌ی رایگان گروه/پلن + اعتبار خریداری‌شده، بسته با فاکتور WHMCS، پلن با ماژول سرور `mcsecplan`). مخزن `maralhost/mc-sec`. وضعیت: نسخه‌ی `0.1.0` (اولین نسخه؛ هنوز روی staging نصب نشده). طرح کامل در `docs/DESIGN.md`، پژوهش‌ها در `docs/research/`.

## با بنیان‌گذار چطور کار کنیم
- **اولویت اول او:** راحتی، روانی و سادگی در همه‌ی سطوح؛ کاربرمحوری. حذف یک گام بهتر از افزودن یک کنترل است.
- به فارسی جواب بده. متن رابط فارسی است (نیم‌فاصله، «ی» و «ک» فارسی، رقم فارسی برای شمارش و اعتبار، تاریخ شمسی، «مارال کلاد»). توکن‌های فنی (دامنه، IP، درگاه، CVE، کد) جدا (`bdi dir=ltr`) و با رقم لاتین.
- هر صفحه کادر «این بخش چه کار می‌کند؟» دارد؛ هر صفحه‌ی مدیر «راهنمای این صفحه»؛ هر تنظیم ⓘ با توضیح و پیش‌فرض. پیام خطا: چه شد، چرا، و قدم بعدی (و کد پیگیری `MS-XXXXXX` برای خطای سامانه).
- برای تصمیم‌های برگشت‌ناپذیر یا دوپهلو اول کوتاه بپرس. بقیه را خودت تصمیم بگیر و بگو چه کردی.
- هر نسخه اول روی staging نصب می‌شود (چک‌لیست `docs/DESIGN.md` §۱۲).

## قوانین سخت (هرگز نقض نشود)
1. **هیچ اسکنی بدون تأیید مالکیت.** `Scans::queue` تأیید، فهرست ممنوع، نوع دارایی، پلن و موتور را می‌سنجد. ارث تأیید از دامنه‌ی اصلی فقط از روش‌های کنترل منطقه‌ی DNS (`Verify::ZONE_METHODS`). درگاه‌های IP فقط وقتی سنجیده می‌شوند که IP مال همین حساب باشد (IP تأییدشده یا IP سرویس مارال؛ `Builtin::portScopeFor`). IP خصوصی و رزروشده پیش‌فرض رد می‌شود. قانون‌های کامل: اسکیل `cybersec-expert`.
2. **داده‌ی WHMCS فقط با `localAPI`**، و فقط از `lib/Whmcs.php`: `SendEmail` (فقط پیام سفارشی `general` با آکولادهای خنثی‌شده) و `CreateInvoice` (فقط بسته‌ی اعتبار، `Credits::buy`). خواندن `tbl*` هم فقط در `Whmcs.php` (و `Auth`/`Access` از راه آن). هیچ `INSERT`/`UPDATE`/`DELETE` در `tbl*` (آزمون‌ها هر نوشتن بیرون از localAPI را شکست می‌دانند). `noemail` هرگز.
3. **هیچ `DROP`، `TRUNCATE`، `dropColumn` یا حذف بدون `where`.** تغییر schema فقط افزودنی در `lib/Installer.php`. **هر جدول یا ستون تازه یعنی بالا بردن `MCSEC_VERSION`** در `bootstrap.php`.
4. **اعتبار:** هر جابه‌جایی یک ردیف دفتر با `ref` یکتا (idempotent)، تغییر کیف با update شرطی اتمی، مانده هرگز منفی نمی‌شود، اسکنی که سامانه نتوانست تمام کند اعتبارش برمی‌گردد. اسکیل `mcsec-billing-safety`.
5. **فایل‌های قالب Lagom2 تغییر نمی‌کنند**؛ فقط هوک و CSS محدود به `.mcs` (ناحیه‌ی کاربری) و `.mcsa` (پنل). CDN، کتابخانه و فایل بیرونی ممنوع. فونت Ray هرگز در git یا بسته.
6. **امنیت هر مسیر تازه:** هویت فقط از نشست (`Auth::client`)؛ هر شناسه‌ی مرورگر با `client_id` نشست سنجیده می‌شود (`Assets::get`، `Scans::get`، `Findings::get`، `Reports::get`، `Schedules::get`). هر POST ناحیه‌ی کاربری: توکن WHMCS + `mcs_csrf`؛ کارهایی که چیزی می‌سازند یا اعتبار مصرف می‌کنند nonce یک‌بارمصرف (`Controller::NEEDS_NONCE`). مالک یا مجوز `manageproducts` برای کار، `products` برای دیدن، `invoices` برای خرید. هر POST پنل: `mcsa_csrf` و سطح (`Admin\Controller::ACTIONS`). هر خروجی escape‌شده؛ در JS فقط `textContent`؛ GET هرگز داده عوض نمی‌کند؛ هر صفحه بی JavaScript کار می‌کند. «ورود به‌جای مشتری» فقط دیدن، مگر `masq_actions`.
7. **شبکه فقط در Worker، POST صریح، یا poll پیشرفت پشت circuit breaker.** هوک‌ها شبکه نمی‌زنند، داخل `try/catch` هستند و اگر قابلیت خاموش است زود برمی‌گردند. URL مشتری (وب‌هوک، فایل تأیید) از گارد SSRF `Net::publicUrl` می‌گذرد و curl به IP سنجیده pin می‌شود.
8. **رمزها:** گذرواژه‌ها، کلید API، توکن ربات و کوکی نشست موتورها رمزنگاری‌شده (`Crypto`، با `encrypt()` خود WHMCS) و هرگز نمایش یا لاگ نمی‌شوند (`Trace::scrub`). داده‌ی اسکن پیش از رفتن به مدل ماسک می‌شود و «داده» است، نه دستور (`Ai::SYSTEM`).
9. هر قابلیتی که روی مشتری اثر دارد پیش‌فرض خاموش است (`enabled = 0`، `access_mode = list`). کلید اضطراری `scans_paused`.
10. حدود ۱۳ هزار حساب: query در حلقه‌ی مشتری‌ها ممنوع؛ خواندن‌ها دسته‌ای (`whereIn`، تکه‌های ۵۰۰تایی).
11. ایمیل شخصی بنیان‌گذار هیچ جای کد، commit یا درخواست‌ها نمی‌آید. هویت git: `maralhost <maralhost@users.noreply.github.com>`. **بدون تأیید صریح بنیان‌گذار push نکن.** رمز و دسترسی پنل‌های OASM و Osmedeus هرگز در مخزن نمی‌آید.

## اسکیل‌ها (`.claude/skills/`)
- معماری، مرز ماژول‌ها، افزودن موتور یا مرحله‌ی کرون، تصمیم فنی: `mcsec-architect`. ساختن و تغییر هر بخش WHMCS: `whmcs-addon` (مشترک همه‌ی مخزن‌های مارال).
- امنیت محتوا (چه چیزی اسکن شود، شدت، امتیاز، متن یافته و راه رفع، مثبت کاذب، قانون): `cybersec-expert`.
- اتصال به OASM و Osmedeus (endpoint، احراز هویت، دام‌ها): `mcsec-backends` و `docs/research/oasm-api.md`، `osmedeus-api.md`.
- گزارش و پرامپت هوش مصنوعی، کش، هزینه، تزریق پرامپت: `mcsec-ai-reports`.
- اعتبار، قیمت، پلن، فاکتور و بازگشت: `mcsec-billing-safety`؛ ایده‌ی قیمت: `pricing`.
- ایده، نسخه‌ی بعد، «این جریان درست است؟»، رقبا: `mcsec-ideation` (جریان‌ها در `references/flows.md`؛ پس از هر تغییر جریان به‌روز کن)؛ طوفان فکری باز: `product-brainstorming`، `opportunity-solution-tree`، `prioritization-frameworks`.
- ظاهر: اول `mcsec-rtl-review`، بعد `design-critique`، `ux-copy`، `accessibility-review`، `web-design-guidelines`، `dashboard-designer`، `form-design`، `information-architecture`، `ux-heuristics`. طرح تازه: `frontend-design`. پیش‌نمایش: `php -S 127.0.0.1:8796 tests/tools/preview.php` (حالت تیره `&dark=1`، پنل `addonmodules.php?module=mcsec`).
- بازبینی امنیتی هر نسخه: `differential-review`، یافته‌ها با `fp-check`؛ `audit-context-building`، `sharp-edges`، `insecure-defaults`.

## نقشه‌ی کد
مسیرها نسبت به `modules/addons/mcsec/`. پیشوند جدول `mod_mcsec_`، namespace `McSec\`.

| فایل | نقش |
| --- | --- |
| `mcsec.php`، `bootstrap.php`، `hooks.php` | چرخه‌ی عمر، نسخه، autoloader؛ هوک‌ها: `AfterCronJob`/`DailyCronJob` (Worker)، `InvoicePaid` (بسته‌ی اعتبار)، منو، کادر خانه |
| `lib/Installer.php`، `Settings.php` | جدول‌ها (فقط افزودنی) و تنظیمات با برچسب و توضیح فارسی |
| `lib/Whmcs.php`، `Auth.php`، `Access.php` | تنها جای `tbl*` و `localAPI`؛ هویت و مجوز؛ چه کسی بخش را می‌بیند |
| `lib/Accounts.php` | فضای امنیت هر حساب: توکن تأیید، فضای OASM، کانال‌ها، اعتبار خوش‌آمد |
| `lib/Assets.php`، `Verify.php`، `Net.php` | دارایی، تأیید مالکیت (DNS/فایل/متا/PTR/WHMCS/ارث/مدیر)، تجزیه‌ی هدف، apex، فهرست ممنوع، DNS، گارد SSRF |
| `lib/Catalog.php` | نوع‌های اسکن (موتور، هزینه، workflow، نوع دارایی) با override مدیر |
| `lib/Scans.php`، `lib/Engines/*` | صف، dispatch با سقف همزمانی، poll، collect، بازگشت اعتبار؛ موتورها: `Builtin`، `Oasm` (کاربر و فضای جدا برای هر حساب)، `Osmedeus` |
| `lib/Findings.php`، `Surface.php`، `Score.php`، `Kb.php` | یافته با اثرانگشت و چرخه‌ی عمر، سطح حمله (تازه/رفته)، امتیاز ۰–۱۰۰ با سقف، پایگاه دانش راه رفع فارسی |
| `lib/Credits.php`، `Plans.php` | کیف دو بخشی، دفتر idempotent، بسته با فاکتور، پلن‌ها و محدودیت‌ها |
| `lib/Schedules.php` | زمان‌بندی روزانه/هفتگی/ماهانه‌ی شمسی، توقف بی‌اعتبار |
| `lib/Reports.php`، `Ai.php` | گزارش پایه (قطعی)، غنی‌سازی هوش مصنوعی، «راهکار با هوش مصنوعی» با کش مشترک، گزارش دوره‌ای |
| `lib/Notify.php` | خبر پنل، صف ارسال (ایمیل، بله، تلگرام، وب‌هوک HMAC)، اتصال ربات با کد، digest |
| `lib/Worker.php`، `Lock.php`، `Kv.php`، `Http.php` | کار پس‌زمینه با قفل و بودجه‌ی زمان؛ قفل، کلید-مقدار با انقضا، HTTP با سقف و circuit breaker |
| `lib/Trace.php`، `Audit.php`، `Nonce.php`، `RateLimit.php`، `Crypto.php`، `Text.php`، `Clock.php`، `Db.php` | گزارش فنی با کد پیگیری، دفتر کارها، nonce، محدودیت نرخ، رمزنگاری، فارسی و شمسی، زمان |
| `lib/Client/*` | ناحیه‌ی کاربری: `Controller` (مسیر، POST، pjax، progress)، `Views` (پوسته، نمای کلی)، `AssetViews`، `ScanViews`، `FindingViews`، `ReportViews`، `AccountViews`، `Ui`، `client.css`، `client.js` |
| `lib/Admin/*` | پنل: نمای کلی، راه‌اندازی موتورها، قیمت و پلن، اعتبار گروه‌ها، دارایی‌ها و تأیید دستی، صف اسکن، تنظیمات، گزارش فنی |
| `../../servers/mcsecplan/mcsecplan.php` | ماژول سرور پلن‌ها (نامش `mcsecplan` است چون نام تابع PHP به بزرگی و کوچکی حساس نیست و `mcsec_ClientArea` با `mcsec_clientarea` افزونه برخورد می‌کرد) |

## آزمون و انتشار
- `bash tests/run.sh` (SQLite، Illuminate واقعی، WHMCS ساختگی). هیچ آزمونی به شبکه، پایگاه یا WHMCS واقعی وصل نمی‌شود (`Http::$mock`، `Net::$resolver`).
- هر تغییر آزمون می‌خواهد: IDOR، CSRF/nonce، XSS با `<script>alert(9)</script>`، دست‌نخوردن `tbl*`، و برای اعتبار: idempotency و نبودن مانده‌ی منفی.
- `php -l` روی فایل‌های تغییرکرده؛ بعد `php tools/release.php` (zip ماژول‌ها و README، در `releases/`، commit نمی‌شود).
- آزمون زنده‌ی موتورها: `php tools/selftest.php` روی سرور WHMCS (خواندن تنظیمات ماژول، بدون نوشتن).
