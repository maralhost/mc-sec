---
name: mcsec-architect
description: >
  Software architect / designer for MC-Sec, the Maral Cloud cyber-security workspace (WHMCS addon). Holds the
  architecture (layers, data model, engine adapters, orchestrator, worker, credits ledger, notifications, AI layer),
  the boundaries and invariants that must not break, the decision records (ADRs) and the checklists for adding an
  engine, a scan profile, a page, a table, a cron step or a notification channel. Use before designing or changing any
  structural part, when reviewing a design, estimating impact, or answering "where should this go / how does X flow"
  (معماری، طراح نرم‌افزار، ساختار، موتور تازه، جریان داده، تصمیم فنی، ADR).
---

# معمار نرم‌افزار MC-Sec

این اسکیل جای `CLAUDE.md` را نمی‌گیرد؛ قاعده‌های سخت همان‌جاست. این‌جا «چرا»ی ساختار و روش تغییر دادنش است. دانش WHMCS در `whmcs-addon`، دانش امنیت در `cybersec-expert`، موتورها در `mcsec-backends`، پول در `mcsec-billing-safety`.

## ۱. لایه‌ها (از بیرون به درون)
```
WHMCS (Lagom2, cron, invoices)        ← hooks.php: منو، کادر خانه، AfterCronJob/DailyCronJob، InvoicePaid
  ├─ Client\Controller  /  Admin\Controller   (مسیر، CSRF، nonce، مجوز، pjax)
  │     └─ *Views + Ui                          (HTML سروری، escape، بی‌JS کار می‌کند)
  ├─ دامنه: Assets · Verify · Scans · Findings · Surface · Score · Credits · Plans · Schedules · Reports · Notify
  ├─ زیرساخت: Engines\{Builtin,Oasm,Osmedeus} · Ai · Http · Net · Kv · Lock · Crypto · Trace · Audit
  └─ داده: mod_mcsec_* (Installer)   |   tbl* فقط از Whmcs (خواندن) و localAPI (نوشتن)
Worker (هر ۵ دقیقه با قفل و بودجه‌ی زمان): topups → poll → dispatch → schedules → verify → reports → digests → deliver → bots
```
- **کنترلر نازک، دامنه ضخیم:** منطق در کلاس‌های دامنه است و هر کدام آرایه‌ی `['ok'=>…, 'error'=>متن فارسی]` برمی‌گرداند. کنترلر فقط ورودی را نرمال، مجوز را می‌سنجد و پیام را می‌سازد.
- **شبکه فقط در سه جا:** Worker، POST صریح کاربر (بررسی تأیید، راهکار هوش مصنوعی، آزمودن موتور در پنل)، و poll پیشرفت (با `live_sync`، `RateLimit` و circuit breaker). صفحه‌ها هرگز شبکه نمی‌زنند.
- **همه‌چیز idempotent:** `ref` یکتا در دفتر اعتبار، خبر و صف ارسال؛ ادعای نوبت زمان‌بندی با update شرطی؛ قفل هر اسکن (`mcsec_scan_<id>`).

## ۲. مدل داده (خلاصه)
| جدول | کلید و نکته |
| --- | --- |
| `accounts` | یک ردیف برای هر حساب WHMCS: `verify_token`، `oasm_workspace`/`oasm_user`/`oasm_secret`، ترجیح اعلان، کانال‌ها، پرچم‌های یک‌باره |
| `assets` | `status`: pending/verified/lapsed/removed؛ `method`؛ `autoscan`؛ `score` و `counts` کش‌شده |
| `scans` | queued → running → completed/failed/cancelled؛ `credits` (ref اعتبار `scan:<id>`)؛ `backend_ref/meta`؛ `summary` (diff) |
| `findings` | یکتا روی `(client_id, fp)`؛ `profile` که آخرین بار دید (پایه‌ی «رفع خودکار»)؛ open/fixed/accepted/false_positive |
| `surface` | یکتا روی `(asset_id, kind, value)`؛ `first_scan_id` (تازه) و `gone_at` (رفته) |
| `wallets`/`ledger` | دو سطل monthly/paid؛ دفتر با `ref` یکتا و `balance_after` |
| `topups`/`plans` | فاکتور بسته؛ ردیف هر سرویس پلن |
| `schedules`/`reports`/`notices`/`outbox` | زمان‌بندی؛ گزارش (داده‌ی JSON، رندر هنگام نمایش)؛ خبر پنل؛ صف ارسال با retry |
| `kv`/`locks`/`hits`/`nonces`/`log`/`audit`/`ai_cache`/`snapshots` | زیرساخت |

## ۳. تصمیم‌های معماری (ADR کوتاه)
1. **HTML سروری + pjax، نه SPA.** قاعده‌ی مارال: بی‌JS کار کند، CDN ممنوع، Lagom2 دست نخورد. همان الگوی MC-Team.
2. **موتورها پشت یک رابط (`Engines\Engine`).** start/poll/collect/cancel/health و خروجی نرمال (finding و surface). یافته‌ها با اثرانگشت `sha1(asset|key|location نرمال)` یکی می‌شوند، از هر موتوری که بیایند.
3. **رفع خودکار فقط به دست همان profile.** اسکنی که کامل شد، یافته‌های باز همان دارایی و همان profile را که ندید «رفع‌شده» می‌کند. نتیجه‌ی یک موتور هرگز یافته‌ی موتور دیگر را نمی‌بندد.
4. **OASM: کاربر و فضای کار جدا برای هر حساب.** OASM هر کاربر را به ۵ فضا محدود کرده و فقط مالک فضا هدف می‌سازد؛ پس حساب سرویس (admin) برای هر مشتری کاربر می‌سازد و نشست همان کاربر را به کار می‌برد. زمان‌بندی خود OASM خاموش می‌ماند تا اعتبار و اعلان از MC-Sec بگذرد.
5. **Osmedeus: یک workspace برای هر دارایی (`space_name`).** نتیجه‌ی هر اجرا با `last_seen_at` از تاریخچه جدا می‌شود. صف ندارد؛ سقف همزمانی در `Scans::dispatch`.
6. **زمان‌بندی در WHMCS cron، نه در موتورها.** تا پرداخت، توقف بی‌اعتبار، تأیید منقضی و اعلان یک‌جا باشد.
7. **گزارش = داده‌ی قطعی + لایه‌ی هوش مصنوعی.** گزارش پایه همیشه ساخته می‌شود؛ هوش مصنوعی اختیاری، با اعتبار، و اگر شکست خورد اعتبار برمی‌گردد. راهکار هر یافته بر اساس نوعش کش مشترک دارد.
8. **اعتبار دو سطلی.** ماهانه (گروه و پلن، بی‌انتقال) اول مصرف می‌شود؛ خریداری‌شده بی‌انقضا. ساده برای مشتری، امن برای حساب‌داری.
9. **ماژول سرور با نام دیگر (`mcsecplan`).** نام توابع PHP حساس به بزرگی/کوچکی نیست؛ `mcsec_ClientArea` با `mcsec_clientarea` افزونه fatal می‌داد.

## ۴. چک‌لیست تغییرهای رایج
**موتور تازه:** کلاس در `lib/Engines` با رابط `Engine` ← ثبت در `Scans::engine` ← profile در `Catalog::DEFAULTS` (engine، kinds، credits، eta، desc) ← سقف همزمانی در `Settings` و `Scans::dispatch` ← تنظیمات اتصال در گروه `engines` و فرم «راه‌اندازی» ← `health()` ← آزمون با `Http::$mock` در `tests/engines_test.php` ← بازبینی دامنه‌ی اسکن با `cybersec-expert` (چه چیزی را لمس می‌کند؟) ← سند در `mcsec-backends`.
**profile تازه روی موتور موجود:** فقط `Catalog::DEFAULTS` + متن فارسی + هزینه (`mcsec-billing-safety`) + آزمون launcher.
**جدول یا ستون:** `Installer` (افزودنی) ← بالا بردن `MCSEC_VERSION` ← آزمون نصب دوباره.
**صفحه‌ی مشتری:** `Controller::PAGES` ← تابع در *Views ← عنوان و توضیح در `Views::PAGES/DESC` ← منو در `Views::MENU` ← کادر «این بخش چه کار می‌کند؟» ← آزمون رندر و XSS ← `mcsec-rtl-review`.
**اکشن POST:** case در `Controller::post` ← اگر چیزی می‌سازد یا هزینه دارد در `NEEDS_NONCE` ← مجوز (manage/buy) ← شناسه‌ها با `*::get(client_id, id)` ← آزمون IDOR/CSRF.
**مرحله‌ی Worker:** تابع مستقل با بودجه‌ی `$deadline`، بی‌استثنا به بیرون، در آرایه‌ی `Worker::run`؛ اگر لازم نیست هر بار، با `Worker::every`.
**کانال اعلان:** `Notify::CHANNELS` و `channelReady` و `send` ← ترجیح پیش‌فرض در `EVENTS` ← گارد SSRF اگر URL مشتری است.

## ۵. ریسک‌ها و بدهی فنی شناخته‌شده (۰٫۱٫۰)
- یافته‌ی یکسان از دو موتور (مثلاً HSTS از بررسی داخلی و nuclei) دو ردیف می‌شود؛ نگاشت کلید بین موتورها (roadmap X در `mcsec-ideation`).
- اسکن‌های OASM و Osmedeus زیردامنه‌ها را پیدا و درگاه‌هایشان را می‌سنجند؛ IP آن‌ها ممکن است مشترک باشد. محدودیت ابزار در پیکربندی خود موتورهاست (پروفایل ابزار OASM، `exclude_modules` در Osmedeus) — پیش از روشن کردن «ارزیابی عمیق» بازبینی شود.
- poll زنده در درخواست مشتری حداکثر ۸ ثانیه طول می‌کشد (timeout موتور)؛ اگر شکایت شد، `live_sync` را خاموش کنید.
- گزارش PDF با چاپ مرورگر است؛ PDF سروری (TCPDF خود WHMCS) در roadmap.
