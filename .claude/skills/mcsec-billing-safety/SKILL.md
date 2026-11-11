---
name: mcsec-billing-safety
description: >
  Rules for everything in MC-Sec that touches money or credits: the two-bucket wallet, the idempotent ledger,
  spending, refunds, free credits for client groups, welcome credits, credit packs sold through WHMCS invoices
  (CreateInvoice + InvoicePaid), plans on the mcsecplan provisioning module (CreateAccount/Renew/Suspend), pricing of
  scan profiles and AI, abuse controls, and the tests each change needs. Use before changing lib/Credits.php,
  lib/Plans.php, the provisioning module, pricing settings, Scans::queue/fail, Reports::queue, or when designing a new
  paid feature (اعتبار، قیمت، پلن، فاکتور، بازگشت اعتبار، تخفیف، شارژ).
---

# ایمنی پول و اعتبار در MC-Sec

## ۱. مدل
- **دو سطل در `mod_mcsec_wallets`:** `monthly` (اعتبار رایگان گروه و اعتبار پلن؛ برای ماه شمسی `period`؛ به ماه بعد نمی‌رود) و `paid` (خوش‌آمد، بسته‌ی خریداری‌شده، هدیه‌ی مدیر؛ بی‌انقضا). مصرف: اول monthly.
- **دفتر `mod_mcsec_ledger`:** هر جابه‌جایی یک ردیف، `ref` **یکتا** (ستون unique)، `delta` علامت‌دار، `bucket`، `kind`، `balance_after`. حذف یا ویرایش ردیف دفتر ممنوع؛ اصلاح = ردیف تازه (`adjust`).
- **refها (قرارداد):** `welcome:<client>`، `group:<client>:<YYYY-MM>`، `plan:<service>:<YYYY-MM>`، `topup:<topup_id>`، `grant:<admin>:<random>`، `scan:<scan_id>:m|p`، `report:<report_id>:m|p`، `aifix:<finding>:<day>:m|p`، `refund:<spend-ref>:m|p`، `expire:<client>:<YYYY-MM>`.

## ۲. قاعده‌ها (هرگز نقض نشود)
1. **idempotent:** هر تابع اعتبار اول ref را می‌سنجد؛ تکرار درخواست، دابل‌کلیک، retry Worker یا هوک دوباره هیچ‌وقت دو بار اعمال نمی‌کند.
2. **اتمی و بی‌مانده‌ی منفی:** کم کردن فقط با `UPDATE … WHERE bucket >= x` (decrement شرطی) داخل تراکنش؛ اگر سطر عوض نشد، کل تراکنش برمی‌گردد.
3. **همه یا هیچ:** `spend` یا کل مبلغ را می‌گیرد یا هیچ؛ ردیف اسکن یا گزارشی که پولش گرفته نشد حذف می‌شود.
4. **بازگشت خودکار وقتی تقصیر سامانه است:** شکست شروع پس از ۵ تلاش، شکست اجرا در موتور، شکست خواندن نتیجه، timeout، لغو مدیر، لغو مشتری **پیش از شروع**، حذف دارایی با اسکن در صف، شکست لایه‌ی AI. لغو مشتری در حین اجرا برنمی‌گردد (در پنجره‌ی تأیید گفته می‌شود).
5. **بازگشت به همان سطل در همان ماه؛ ماه بعد به paid** تا بازگشت با پایان ماه گم نشود.
6. **پول WHMCS فقط با localAPI:** خرید = `CreateInvoice` (فقط در `Credits::buy`)؛ اعتبار = هوک `InvoicePaid` + آشتی‌سازی Worker (`reconcileTopups`)، هر دو با `topup:<id>`. فاکتور باید `Paid` و مال همان مشتری باشد. هیچ نوشتنی در `tblinvoices`/`tblcredit`/`tblclients`.
7. **پلن‌ها:** فقط از ماژول سرور `mcsecplan`. `Renew` در همان ماه دوباره اعتبار نمی‌دهد (ref ماهانه)؛ ماه تازه را `Credits::refresh` خودکار پر می‌کند. Suspend/Terminate محدودیت‌ها را برمی‌دارد ولی اعتبار خریداری‌شده می‌ماند.
8. **مبلغ‌ها:** اعتبار عدد صحیح؛ قیمت بسته به ارز پیش‌فرض WHMCS (IRR بی‌اعشار). نمایش با `Text::money`.

## ۳. قیمت‌گذاری (پیش‌فرض‌ها و منطق)
| profile | اعتبار | منطق |
| --- | --- | --- |
| hygiene | ۰ | قیف: «کشف رایگان، اسکن عمیق اعتباری» (Attaxion/Halo). هزینه‌ی واقعی ناچیز (چند درخواست از سرور WHMCS) |
| surface | ۲ | OASM: subfinder/dnsx/naabu/httpx |
| vuln | ۶ | nuclei، چند دقیقه تا دو ساعت worker |
| recon | ۸ | Osmedeus fast |
| deep | ۳۰ | Osmedeus general؛ فقط با پلن |
| گزارش AI | ۲ | توکن مدل؛ پاسخ‌های fix کش مشترک دارند |
- قاعده‌ی سود: قیمت هر اعتبار در بسته‌ها ≥ ۳ برابر هزینه‌ی تمام‌شده‌ی میانگین یک اعتبار (زیرساخت + مدل). پیشنهاد پلن‌ها و بسته‌ها در `docs/research/competitive-analysis.md`.
- بازه‌ی IP: هر ۱۶ آدرس = ۱ برابر (`Catalog::cost`).

## ۴. کنترل سوءاستفاده
سقف دارایی (پلن/گروه/رایگان)، سقف اسکن روزانه (`daily_scan_cap`)، یک اسکن هم‌زمان از هر profile روی هر دارایی، همزمانی هر حساب (`client_concurrency`)، سقف بررسی دوباره‌ی رایگان (`retest_daily_cap` و یکی در روز برای هر یافته)، ۱۰ فاکتور در ساعت، ۳۰۰ افزودن دارایی در روز، کلید اضطراری `scans_paused`.

## ۵. آزمون‌های لازم برای هر تغییر
`tests/credits_test.php` را گسترش بده: تکرار ref، نبود مانده‌ی منفی در race، همه‌یا‌هیچ، بازگشت یک‌باره، تغییر ماه (انقضا و پر شدن یک‌باره)، فاکتور پرداخت‌نشده/لغوشده/مال مشتری دیگر، Renew در یک ماه، و نبود نوشتن در `tbl*`.
