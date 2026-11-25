---
paths:
  - "modules/addons/mcsec/lib/Client/**"
  - "modules/addons/mcsec/lib/Admin/**"
  - "modules/addons/mcsec/lib/Pdf.php"
  - "modules/addons/mcsec/hooks.php"
  - "tests/tools/catalog.php"
  - "tests/browser/**"
  - "docs/frontend/**"
---

# قاعده‌های رابط کاربری MC-Sec

پیش از هر کار روی رابط کاربری این سندها را بخوانید (مرجع: `docs/frontend/FRONTEND_UI_STANDARDS.md`):

- `docs/frontend/DESIGN_SYSTEM.md`: توکن‌ها و دو سطح (پنل مشتری، پنل مدیر)
- `docs/frontend/COMPONENT_GUIDELINES.md`: کامپوننت‌های موجود و حالت‌ها
- `docs/frontend/SECURE_DATA_PRESENTATION.md`: نمایش داده‌ی غیرقابل‌اعتماد
- `docs/frontend/SECURITY_ANALYTICS_UI.md`: شدت، امتیاز، اولویت، وضعیت
- `docs/frontend/APPROVED_LIBRARIES.md`: آنچه تأیید شده است

قاعده‌ها:

1. MC-Sec یک «Advanced Hybrid WHMCS Module» است: PHP، HTML، CSS و JavaScript ساده. React، Tailwind، Vite، shadcn/ui و TanStack نصب نشده‌اند و بی تأیید جدای بنیان‌گذار نصب نمی‌شوند. shadcn/ui و ReUI فقط مرجع طراحی‌اند.
2. پیش از ساختن کامپوننت، `Ui.php`، `Charts.php` و کاتالوگ (`/catalog.php` در پیش‌نمایش) را ببینید. کامپوننت تازه = نمونه در کاتالوگ + ردیف در `COMPONENT_GUIDELINES.md`.
3. رنگ فقط از توکن `--mds-*`. کد رنگ در PHP یا قاعده‌ی CSS ممنوع است (`tests/ui_test.php` می‌سنجد). شدت، امتیاز، وضعیت اسکن و دارایی توکن خودشان را دارند.
4. همه‌ی CSS زیر `.mcs` یا `.mcsa`؛ هیچ reset سراسری؛ فایل‌های Lagom2 دست نمی‌خورند.
5. پنل مدیر هویت MC-Care را دارد و پنل مشتری هویت Lagom2 و محصول امنیت را؛ ظاهر یکی به دیگری تحمیل نمی‌شود.
6. هر کار اصلی بی JavaScript انجام می‌شود. GET چیزی را عوض نمی‌کند. توکن WHMCS، `mcs_csrf`، nonce و سنجش‌های سمت سرور همان می‌مانند.
7. هر مقدار از اسکنر، سایت مشتری، مدل یا کاربر غیرقابل‌اعتماد است: escape، فقط متن، توکن فنی چپ‌به‌راست.
8. هیچ عدد یا شاخص ساختگی. صفر، «ارزیابی‌نشده»، «ارزیابی ناقص» و «داده نیست» چهار چیز جدا هستند.
9. کتابخانه‌ی تازه: فقط با نیاز واقعی، مجوز همان نسخه، فایل محلی در بسته، و تأیید بنیان‌گذار؛ ثبت در `APPROVED_LIBRARIES.md`. CDN ممنوع. نصب ماژول هرگز Node.js، npm یا Composer نمی‌خواهد.
10. پس از هر تغییر: `bash tests/run.sh`، `php tools/i18n.php`، و در `tests/browser`: `npx playwright test` (فقط توسعه). نتیجه‌ی پیش‌نمایش محلی را «سازگار با Lagom2 واقعی» ننامید.
