---
name: whmcs-addon
description: >
  Build or change a Maral Cloud WHMCS addon module (MC-Care/maralsegment, MC-Raya, MC-Quality)
  the way these projects already do it: entry-file lifecycle (_config, _activate, _deactivate,
  _upgrade, _output, _clientarea), additive and idempotent schema changes, hooks.php that can
  never slow down or break a WHMCS page, cron hooks, localAPI calls, admin pages and AJAX inside
  addonmodules.php, CSRF and admin roles, client-area features on Lagom2, PHP compatibility, and
  the WHMCS quirks that already caused real bugs here. Use when adding or changing a page, action,
  table, column, setting, hook, cron step, localAPI call or client-area feature, when preparing a
  release zip, or when asked about WHMCS module development (ماژول WHMCS، افزونه، هوک، کرون، localAPI).
---

# ساخت و تغییر افزونه‌ی WHMCS در پروژه‌های مارال کلاد

این اسکیل جای `CLAUDE.md` را نمی‌گیرد؛ قاعده‌های همان مخزن اول‌اند. این‌جا دانش WHMCS آمده که هر سه ماژول به آن نیاز دارند، به‌همراه اشتباه‌هایی که در همین پروژه‌ها واقعاً پیش آمده است. همین فایل در هر سه مخزن یکسان است.

## ۰. پیش از نوشتن کد
1. `CLAUDE.md` (و اگر هست `CLAUDE-MEMORY.md`) را بخوان.
2. کتابخانه، فریم‌ورک یا CDN تازه اضافه نکن. هیچ‌کدام از این ماژول‌ها Composer، Monolog، مدل Eloquent، Svelte/Tailwind یا فایل بیرونی ندارند. helperهای خود ماژول را به کار ببر:

| | MC-Care | رایا | MC-Quality |
| --- | --- | --- | --- |
| پوشه | `modules/addons/maralsegment` | `modules/addons/mc_raya` | `modules/addons/mcquality` |
| پیشوند جدول | `mod_maralseg_` | `mod_mcraya_` | `mod_mcq_` |
| کمترین PHP | **7.4** | 8.1 (هدف 8.3) | 8.3 |
| schema | `Service::schema()`، `TABLES`، `MIGRATIONS` | `Core\Schema`، `Settings::ensureSchema()` | `lib/Installer.php` |
| CSRF | `tokenField()` (فیلد `ms_token`) | ادمین `Ui::checkToken()`، مشتری `Guard::checkCsrf()` | ادمین `Auth::csrf()` (`mcq_csrf`)، مشتری `mcq_nonce` |
| escape خروجی | `$this->h()` | `Ui::e()` | `View::e`، `Text::e` |
| دسترسی ادمین | `ACTION_PERMS`، `needRole()` | طبق `CLAUDE.md` | `Auth::can()` |
| آزمون | `tests/run_all.sh` | `php modules/addons/mc_raya/tests/run.php` | `bash tests/run.sh` |

## ۱. فایل ورودی و چرخه‌ی عمر
| تابع | قاعده |
| --- | --- |
| `<m>_config()` | نام، نسخه و کمترین فیلد. تنظیمات اصلی در صفحه‌ی خود ماژول است، نه در Configure صفحه‌ی Addon Modules (بازخورد نصب رایا 0.1). |
| `_activate()` | فقط نصب idempotent: `CREATE TABLE IF NOT EXISTS` و seed بی‌تکرار. هرگز `DROP` یا `dropIfExists` پیش از ساختن، چون فعال‌سازی دوباره داده را پاک می‌کند. |
| `_deactivate()` | داده را نگه می‌دارد. حذف فقط وقتی مدیر صریحاً خواسته باشد (MC-Care: گزینه‌ی `delete_on_deactivate`). |
| `_upgrade($vars)` | `$vars['version']` نسخه‌ی **قبلیِ** نصب‌شده است. اولین باری اجرا می‌شود که پس از عوض شدن نسخه ماژول در پنل باز شود. اگر نسخه را مقایسه می‌کنی، با `version_compare()`؛ هرگز با `<` روی رشته (`'1.10' < '1.9'` درست درمی‌آید). فقط افزودنی: بدون `DROP`، `TRUNCATE` یا `dropColumn`. |
| `_output($vars)` | صفحه‌ی ادمین داخل قالب WHMCS؛ آدرس پایه `$vars['modulelink']`. |
| `_clientarea($vars)` | آرایه‌ای با `pagetitle`، `breadcrumb`، `templatefile` (نسبت به پوشه‌ی ماژول، بدون `.tpl`)، `requirelogin` و `vars`. |

نصب تازه و ارتقا باید به یک schema برسند: هر جدول یا ستون تازه هم در نصب بیاید هم در مهاجرت، و آزمون ارتقا از نسخه‌ی قبل اجرا شود (MC-Care: `tests/whmcs_sim2.php` با `tests/fixtures/Service.v1.php`؛ MC-Quality: `tests/upgrade_*.php`).

## ۲. hooks.php: هرگز کند نکن، هرگز نشکن
- WHMCS فایل `hooks.php` ماژول را فقط وقتی ماژول فعال است بار می‌کند، آن هم در **همه‌ی** صفحه‌ها. اگر `hooks.php` را به ماژولی اضافه کنی که از قبل فعال است، تا تنظیمات ماژول در Setup › Addon Modules دوباره ذخیره نشود شناخته نمی‌شود.
- بدنه‌ی هر هوک در `try { … } catch (\Throwable $e)` با لاگ باشد (MC-Care: `maralsegment_hook_log()` که به `logActivity` می‌نویسد). خطای بیرون‌زده صفحه‌ی WHMCS را برای همه خراب می‌کند.
- در هوک‌های صفحه هیچ درخواست شبکه‌ای نزن: نه مدل، نه وب‌هوک، نه `localAPI`ی که به ثبت‌کننده یا سرور وصل می‌شود. کندی ورود رایا 0.1 از `DomainGetNameservers` برای هر دامنه در پنل داشبورد بود. فقط پایگاه داده، با کش کوتاه.
- اول بررسی کن قابلیت روشن است و اگر نیست زود برگرد. هر قابلیتی که روی مشتری اثر دارد پیش‌فرض خاموش است.
- هوک‌های خروجی (`ClientAreaFooterOutput`، `AdminAreaHeadOutput` و…) رشته‌ی HTML برمی‌گردانند. assetها را فقط در صفحه‌هایی بگذار که لازمشان دارند، با شماره‌ی نسخه در query.
- کرون: `DailyCronJob` روزی یک بار اجرا می‌شود؛ `AfterCronJob` بعد از **هر** اجرای cron (معمولاً هر ۵ دقیقه). پس کار `AfterCronJob` کوتاه و قفل‌دار باشد (`SELECT GET_LOCK(?, 0)` و `RELEASE_LOCK` در `finally`). مرحله‌های کار روزانه مستقل باشند تا شکست یکی بقیه را متوقف نکند (MC-Care: `CareCron`).
- هوک‌های تیکت (`TicketOpen`، `TicketAdminReply`، `TicketUserReply`، `TicketStatusChange`، `TicketClose`): نام وضعیت را فرض نکن. وضعیت‌های سفارشی در `tblticketstatuses` هستند و «بسته» یعنی `showactive = 0`.

## ۳. localAPI و داده‌ی WHMCS
- `localAPI($command, $params, $adminUsername)` فقط وقتی موفق است که `$r['result'] === 'success'` باشد؛ پیام خطا در `$r['message']` است. خطای خام را به مشتری نشان نده و متن فارسی ساده بساز (رایا: `Actions\Failure::explain()`).
- داده‌ی `tbl*` را فقط با `localAPI` و فقط در مسیرهایی تغییر بده که `CLAUDE.md` اجازه داده است. در MC-Care فقط `Service::apply()` و `rollback()` گروه مشتری را عوض می‌کنند؛ MC-Quality فقط در `tbltodolist` می‌نویسد.
- ایمیل‌های WHMCS را سرکوب نکن: `noemail` هرگز فرستاده نمی‌شود.
- `OpenTicket` از طرف کارشناس (`'admin' => true`) و Flag روی WHMCS 9.1 هنوز روی staging آزموده نشده است. هر تغییری در آن را به چک‌لیست staging اضافه کن.

## ۴. پایگاه داده
- WHMCS حالت پیش‌فرض PDO را `FETCH_OBJ` می‌گذارد. helperهای ماژول آرایه‌ی ASSOC برمی‌گردانند؛ اگر مستقیم `getPdo()` می‌گیری، حالت fetch را خودت تعیین کن.
- همه‌ی queryها پارامتری باشند. فهرست شناسه‌ها با helper ماژول ساخته شود (MC-Care: `Service::in()`)، هرگز با `implode` روی ورودی.
- جدول تازه `utf8mb4` و با پیشوند ماژول باشد. جدول‌های `tbl*` را alter نکن.
- حدود ۱۳ هزار حساب مشتری داریم: N+1 نساز و query را در حلقه‌ی مشتری‌ها نگذار.

## ۵. صفحه‌ی ادمین و AJAX داخل `addonmodules.php`
- WHMCS ورودی‌های `$_GET` و `$_POST` را HTML-escape می‌کند. پیش از ذخیره decode کن، یا بدنه‌ی خام `php://input` را بخوان. در رایا `&quot;` در قیمت‌ها از همین بود.
- `check_token()` خود WHMCS در شکست HTML چاپ می‌کند و پاسخ JSON را خراب می‌کند. توکن خود ماژول را با `hash_equals` بسنج. MC-Care هر دو را در فرم می‌گذارد: `ms_token` و `generate_token('form')`.
- پاسخ JSON از داخل `addonmodules.php`: همه‌ی بافرها را خالی کن (`while (ob_get_level() > 0) ob_end_clean();`)، هدر `Content-Type: application/json; charset=utf-8` بفرست، چاپ کن و `exit`. وگرنه JSON با HTML قالب ادمین قاطی می‌شود.
- هر اکشن تازه کنترل دسترسی دارد (MC-Care: ثبت در `ACTION_PERMS`). دسترسی کلی به ماژول برای هر نقش ادمین در Setup › Addon Modules › Access Control تعیین می‌شود؛ نقش‌های تازه را آن‌جا تیک بزن.
- درخواست GET داده را تغییر نمی‌دهد. هر صفحه بدون JavaScript هم کار کند.
- پنل کناری یا لایه‌ی شناور باید بالای منوی ادمین WHMCS قرار بگیرد (`z-index` دست‌کم 10400).
- CDN ممنوع است. داخل JS درون‌خطی `</` ننویس (به‌جایش `<\/`).

## ۶. ناحیه‌ی کاربری (Lagom2)
- فایل‌های قالب Lagom2 را تغییر نده؛ فقط هوک، و CSS محدود به کلاس‌های خود ماژول.
- هویت مشتری فقط از نشست WHMCS، هرگز از ورودی. در WHMCS 8+ ورود با «کاربر» است و یک کاربر می‌تواند به چند حساب مشتری دسترسی داشته باشد (`tblusers_clients`). مجوز کاربر غیرمالک را بسنج و هر رکورد را با `client_id` نشست چک کن (IDOR).
- در endpointهای AJAX بلافاصله پس از احراز هویت `session_write_close()` بزن؛ وگرنه قفل نشست PHP بقیه‌ی درخواست‌های همان مشتری را پشت سر هم صف می‌کند.
- اگر سرویس بیرونی قطع باشد، سایت نباید کند شود: timeout کوتاه، قطع‌کن (circuit breaker) و بارگذاری ناهمگام.

## ۷. سازگاری PHP و متن فارسی
- MC-Care باید روی PHP 7.4 هم کار کند: `match`، `?->`، `str_contains`، `fn`، named arguments، union types، trailing comma در پارامترها و `catch` بدون متغیر ممنوع‌اند. mbstring اجباری نیست (`Util::len`، `Util::cut`، `Util::lower`).
- `trim()` با نویسه‌ی فارسی در charlist متن چندبایتی را خراب می‌کند؛ از `preg_replace('/…/u', …)` استفاده کن.
- تاریخ نمایشی شمسی و رقم فارسی با helper ماژول باشد؛ ورودی تاریخ و عدد، رقم فارسی را هم بپذیرد.
- هر فایل PHP با گارد `if (!defined('WHMCS'))` شروع شود، به‌جز فایلی که خودش `init.php` را بار می‌کند. هر پوشه‌ی تازه یک `index.php` خالی دارد.

## ۸. فراخوانی مدل OpenAI (رایا، MC-Quality، دستیار MC-Care)
- مدل‌های تازه `max_tokens` را رد می‌کنند و `max_completion_tokens` می‌خواهند. پارامترها را خودکار تطبیق بده و نتیجه را برای هر مدل نگه دار (رایا: `AI\Client::adapt()`).
- آدرس سرویس پیش از درخواست از کنترل ضد SSRF بگذرد (MC-Care: `Notify::checkUrl`). داده‌ی شخصی پیش از ارسال ماسک شود. متن مشتری و تیکت «داده» است، نه دستور.
- کلید API رمزنگاری‌شده ذخیره می‌شود و هرگز نمایش داده یا لاگ نمی‌شود.

## ۹. انتشار
1. نسخه را بالا ببر (MC-Care: `maralsegment.php` و `schema_version`؛ رایا: `lib/version.php`) و تغییرها را ثبت کن.
2. همه‌ی آزمون‌ها را اجرا کن و `php -l` را روی فایل‌های تغییرکرده بزن.
3. zip فقط `modules/addons/<ماژول>/` را دارد؛ نه `tests/`، نه `tools/`، نه `.claude/`. zip در مخزن commit نمی‌شود و در GitHub Releases قرار می‌گیرد.
4. اول روی staging نصب کن: صفحه‌ی Addon Modules را باز کن تا `_upgrade` اجرا شود، Access Control را بررسی کن و چک‌لیست staging همان پروژه را برو.

## ۱۰. چک‌لیست پیش از تحویل
- [ ] نصب تازه و ارتقا به یک schema می‌رسند؛ هیچ `DROP` یا `TRUNCATE`ی نیست.
- [ ] هوک تازه: try/catch دارد، به شبکه وصل نمی‌شود و اگر قابلیت خاموش است زود برمی‌گردد.
- [ ] اکشن تازه: CSRF، کنترل نقش، خروجی escape‌شده، و بدون JS هم کار می‌کند.
- [ ] داده‌ی WHMCS فقط با `localAPI` و فقط در مسیر مجاز تغییر می‌کند؛ `noemail` فرستاده نمی‌شود.
- [ ] ناحیه‌ی کاربری: `client_id` از نشست، مجوز کاربر غیرمالک، `session_write_close()`.
- [ ] با کمترین PHP همان ماژول سازگار است (MC-Care: 7.4).
- [ ] برای تغییر آزمون نوشته شده و همه‌ی آزمون‌ها موفق‌اند.

## منابع
- مستندات رسمی: [Addon Modules](https://developers.whmcs.com/addon-modules/)، [Hooks](https://developers.whmcs.com/hooks/)، [API Reference](https://developers.whmcs.com/api/)، و نمونه‌ی رسمی [WHMCS/sample-addon-module](https://github.com/WHMCS/sample-addon-module).
- اسکیل عمومی [servicioshosting/whmcs-addon-module-skill](https://github.com/servicioshosting/whmcs-addon-module-skill) (commit `cbf9a05`، ۳۰ مهر ۱۴۰۵) بررسی شد ولی نصب نشد. دلیلش این بود که با قاعده‌های این پروژه‌ها نمی‌خواند: در `_activate` و `_deactivate` جدول‌ها را حذف می‌کند، نسخه‌ها را با `<` رشته‌ای مقایسه می‌کند، و Composer، Monolog، Eloquent، Notyf و رابط Svelte/Tailwind می‌آورد. ایده‌ی قفل `GET_LOCK` برای `AfterCronJob` از آن گرفته شد.
