# الگوهای رقبا و محصول‌های مشابه

منبع واگرایی در ایده‌پردازی، نه فهرست کپی. هر الگو پیش از پیشنهاد از فیلتر گام ۴ اسکیل می‌گذرد. ستون «در MC-Sec» یکی از این‌هاست:
- **هست:** همین را داریم (با نام کلاس یا تنظیم).
- **ایده:** با شناسه‌ی `roadmap-ideas.md`.
- **نه:** با قواعد درگیری، ارزش‌های برند یا WHMCS نمی‌خواند (دلیل در یک خط).

ادعاها از `docs/research/competitive-analysis.md` و `ux-research.md` (بازدید آبان ۱۴۰۵) آمده‌اند؛ پیش از استناد بیرونی، صفحه‌ی منبع را دوباره ببین. ادعای فروشنده (مثل نرخ تبدیل) ادعاست، نه داده.

## ۱. تأیید مالکیت و شروع
| الگو | چه کسی | چرا کار می‌کند | در MC-Sec | منبع |
| --- | --- | --- | --- | --- |
| یک رکورد TXT برای دامنه و همه‌ی زیردامنه‌ها؛ بازبینی دوره‌ای و هشدار اگر توکن حذف شود؛ خطای مشخص («رکورد پیدا نشد»، «مقدار نمی‌خواند») | Google Search Console (Domain property) | یک کار برای کل دامنه؛ کاربر می‌داند کجا خراب است | **هست:** `_mcsec-verify`، ارث زیردامنه، بازبینی ۳۰ روزه و `lapsed` | https://support.google.com/webmasters/answer/9008080 |
| سه روش DNS، فایل در `.well-known`، متا؛ IP تکی با فایل؛ بازه را کارمند تأیید می‌کند؛ توصیه به نگه داشتن رکورد | Detectify | پوشش همه‌ی بسترها؛ مسیر انسانی برای حالت سخت | **هست:** `Verify` و `adminApprove` برای بازه | https://docs.detectify.com/getting-started/asset-verification |
| مالکیت ضمنی: دارایی از قبل در حساب است | Cloudflare (zone)، SiteLock روی MarketConnect، WP Toolkit | صفر گام برای اکثر مشتری‌ها | **هست:** تأیید `whmcs`؛ بزرگ‌ترین مزیت ما | https://docs.whmcs.com/marketconnect/service-providers/sitelock |
| بررسی خودکار با فاصله‌ی فزاینده و ایمیل هنگام تغییر وضعیت؛ دکمه‌ی بررسی دستی | Cloudflare (pending zone) | کاربر لازم نیست منتظر بماند | **هست:** `Verify::due` + «اسکن پس از تأیید» | https://developers.cloudflare.com/dns/zone-setups/reference/domain-status/ |
| نام TXT اختصاصی چون TXT روی میزبان دارای CNAME کار نمی‌کند | Snyk API & Web (Probely) | خطای رایج را از ریشه حذف می‌کند و به SPF روی `@` دست نمی‌زند | **هست:** `_mcsec-verify.<domain>` | https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-api-web/configure-targets/verify-domain-ownership |
| HTTP-01 زیر `/.well-known/` و DNS-01 زیر نام اختصاصی | Let's Encrypt | قرارداد آشنای مدیران سایت | **هست:** `/.well-known/mcsec-verify.txt` | https://letsencrypt.org/docs/challenge-types/ |

## ۲. اسکن و پایش
| الگو | چه کسی | چرا کار می‌کند | در MC-Sec | منبع |
| --- | --- | --- | --- | --- |
| دو حالت Light (غیرتهاجمی) و Deep (آزمون‌های فعال فقط این‌جا) | Pentest-Tools | انتخاب ساده با اثر روشن | **هست:** `hygiene` تا `deep` در `Catalog` (⚑۸ نام‌ها) | https://pentest-tools.com/docs/tools/website-scanner |
| Emerging Threat Scans: با CVE تازه فقط هدف‌های دارای همان فناوری اسکن می‌شوند | Intruder | واکنش سریع با هزینه‌ی کم | **ایده X10** | https://www.intruder.io/pricing |
| تست ساخته‌شده با AI از روی CVE، با بازبینی انسانی پیش از انتشار | Detectify (Alfred) | سرعت پوشش CVE تازه | **نه فعلاً:** ظرفیت نوشتن و بازبینی قالب نداریم؛ قالب‌های عمومی nuclei کافی‌اند | https://blog.detectify.com/product-updates/introducing-alfred-for-ai-built-vulnerability-assessments |
| کشف همه‌ی دارایی‌ها رایگان، اسکن فقط در سهمیه | Halo Security، Attaxion | کاربر ارزش را می‌بیند و برای عمق می‌پردازد | **هست بخشی:** `hygiene` رایگان و `surface` ارزان | https://www.halosecurity.com/start · https://attaxion.com/pricing |
| فقط ۵۰٪ نتایج در نسخه‌ی رایگان | Attaxion Community | فشار ارتقا | **نه:** دریغ کردن اطلاعات امنیتی با شفافیت نمی‌خواند | https://attaxion.com/pricing |
| دکمه‌ی Scan Now با cooldown؛ اصلاح یک‌کلیکی فایروال | AegisWhite (ماژول WHMCS) | کنترل هزینه؛ رفع، نه فقط گزارش | cooldown: **هست بخشی** (`daily_scan_cap`)؛ رفع یک‌کلیکی: **ایده X15** | https://marketplace.whmcs.com/product/8608-aegiswhite-security-monitoring-dark-web-port-scanning |
| insightهای رایگان DMARC، SPF، CNAME معلق، رکورد unproxied | Cloudflare Security Center | کف انتظار بازار برای چک‌های بهداشت | **هست:** `Builtin`؛ باید دست‌کم هم‌سطح بماند | https://developers.cloudflare.com/security-center/security-insights |

## ۳. یافته، رفع و اولویت
| الگو | چه کسی | چرا کار می‌کند | در MC-Sec | منبع |
| --- | --- | --- | --- | --- |
| تفکیک هر اسکن به «جدید یا بازگشایی‌شده، هنوز باز، بسته‌شده»؛ پذیرش ریسک با یادداشت | HostedScan | پیام «چه عوض شد»؛ ممیزی تصمیم | **هست:** `Findings::ingest` (new، reopened، fixed) | https://docs.hostedscan.com/api · https://help.hostedscan.com/help/what-is-an-accepted-risk |
| «Fixed» فقط خودکار وقتی اسکن یا Re-test بعدی نبیند؛ دکمه‌ی Re-test | Probely | امتیاز و آمار دروغ نمی‌گویند | **هست:** «رفعش کردم» ⇐ بررسی مجدد رایگان | https://help.probely.com/en/articles/6673828-what-is-the-meaning-of-a-finding-s-state |
| دلیل اجباری برای بستن؛ بازگشایی خودکار اگر دوباره دیده شود | GitLab، GitHub code scanning | ممیزی و جلوگیری از پنهان شدن مشکل | **هست** | https://docs.gitlab.com/user/application_security/vulnerabilities/ |
| تفکیک شدت ثابت (CVSS) از اولویت پویا (احتمال بهره‌برداری) | Tenable (VPR)، Snyk (priority score) | ترتیب درست بی گیج کردن کاربر با عدد دوم | **هست به‌عنوان قاعده** (`cybersec-expert` §۲ و §۳)؛ برچسب KEV را بسنج | https://docs.tenable.com/vulnerability-management/Content/Analysis/RiskMetrics.htm |
| «Prominent Issues»: پنج کاری که بیشترین بهبود امتیاز را می‌دهد | Intruder | پاسخ به «الان چه کنم؟» | **طرح** در `ux-research.md` §۵٫۱ (M5)؛ وضعیت کد را ببین | https://help.intruder.io/en/articles/6681094-portal-dashboard |
| AI: گفتگو، خلاصه‌ی مدیریتی، اولویت با CVSS و EPSS، راهکار متناسب با stack؛ اعتبار AI جدا | Intruder (GregAI) | ارزش برای غیرمتخصص؛ کنترل هزینه‌ی LLM | گزارش و راهکار AI: **هست**؛ گفتگو: **ایده X13** | https://help.intruder.io/en/articles/13004626-gregai-your-ai-assistant-in-intruder |

## ۴. امتیاز
| الگو | چه کسی | چرا کار می‌کند | در MC-Sec | منبع |
| --- | --- | --- | --- | --- |
| رتبه با سقف: یک مشکل جدی سقف رتبه را پایین می‌آورد | Qualys SSL Labs | یک مشکل بحرانی پشت ده چک سالم پنهان نمی‌ماند | **هست:** بحرانی ⇐ حداکثر ۴۹، بالا ⇐ ۷۹ (`Score`) | https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide |
| امتیاز تشویقی فقط وقتی پایه دست‌کم ۹۰ است | Mozilla HTTP Observatory | جایزه برای کار اضافه بی پنهان کردن ضعف | **نه فعلاً:** فرمول را ساده نگه می‌داریم | https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring |
| میانگین وزنی که دارایی ضعیف‌تر وزن بیشتری دارد | UpGuard | سایت فراموش‌شده پنهان نمی‌ماند | **پرسش باز:** کد میانگین ساده با سقف است (`cybersec-expert` §۸) | https://help.upguard.com/en/articles/3765184-how-are-upguard-s-security-ratings-calculated |
| Site Health score + صف اقدام اولویت‌دار | SiteLock 2.0 | یک عدد و یک فهرست برای صاحب سایت | **هست:** امتیاز + کارهای پیشنهادی (M5) | https://www.businesswire.com/news/home/20241015588245/en/Sectigo-Unveils-SiteLock-2.0-Simplifies-Complex-Website-Security-Management-for-Small-to-Medium-sized-Businesses |

## ۵. فروش در کانال هاستینگ
| الگو | چه کسی | چرا کار می‌کند | در MC-Sec | منبع |
| --- | --- | --- | --- | --- |
| معرفی در صفحه‌ی اصلی، سبد و صفحه‌ی سرویس هاست؛ پیشنهاد هنگام تسویه؛ پلن رایگان Lite | SiteLock روی WHMCS MarketConnect | فروش در لحظه‌ی مرتبط، بی کانال جدا | **ایده X6** (بی پیام ترساننده) | https://docs.whmcs.com/marketconnect/service-providers/sitelock |
| هشدار آسیب‌پذیری رایگان برای همه‌ی مشتریان هاست، محافظت به‌عنوان ارتقا؛ widget چند خطی | Patchstack (برنامه‌ی هاستینگ؛ ادعای فروشنده: ۴٫۵٪ تبدیل در WP Umbrella) | ارزش رایگان واقعی، ارتقای طبیعی | **ایده X4 و X14** | https://patchstack.com/articles/new-patchstack-web-host-integration-unlocks-proactive-website-security-with-industry-leading-upsell-conversions/ |
| سطح رایگان «فقط دیدن»، بعد پاک‌سازی و پیشگیری؛ خط قرمز: پیام ترساننده نه، شرط پنهان نه، اصلاح پایه دریغ نشود | Monarx (و بررسی ۶۵ هاست، ۲۰۲۶) | upsell بی آسیب به برند | **هست به‌عنوان اصل:** `hygiene` رایگان، فیلتر برند در گام ۴ | https://www.monarx.com/solutions/built-in-upsell · https://webhosting.today/2026/11/05/monarx-reviewed-65-hosts-10-of-12-large-hosting-brands-sell-website-security-add-ons/ |
| اسکن passive رایگان بی ثبت‌نام به‌عنوان قیف | Sucuri SiteCheck | ارزش پیش از تعهد | **ایده X9** (فقط passive، بی جزئیات حساس) | https://sitecheck.sucuri.net/ |
| لایسنس ۳۰ روزه برای هر هدف؛ تعویض هدف فقط پس از ۳۰ روز | Intruder، Astra Agency | جلوی چرخاندن هدف را می‌گیرد | **نه فعلاً:** ما برای هر اسکن قیمت می‌دهیم؛ اگر پلن بر پایه‌ی شمار میزبان پایش‌شده شد، دوباره بسنج | https://help.intruder.io/en/articles/2946211-targets-explained · https://www.getastra.com/pricing |
| اعتبار به ازای هدف-روز | Snyk API & Web | دقیق برای پایش مداوم | **نه:** پیش‌بینی هزینه برای مشتری کوچک سخت | https://snyk.io/policies/credit-based-billing/ |
| برنامه‌ی MSP با white-label و چند مستأجر | HostedScan، Detectify، Astra Agency | درآمد از آژانس‌ها | **ایده X20** (اول نسخه‌ی ساده‌تر) | https://hostedscan.com/enterprise-reseller-whitelabel |
| خدمت انسانی یک‌باره (اسکن و تحلیل، سخت‌سازی، پاک‌سازی) با قیمت بسته‌ای | Ideaas، ووکامرس فارسی، rgb.ir (بازار ایران) | فرهنگ خرید «بسته + پشتیبانی» | **ایده Y1** | https://ideaas.ir/security/ · https://rgb.ir/en/website-security/ |

## ۶. رابط و ریزمتن
| الگو | چه کسی | چرا کار می‌کند | در MC-Sec | منبع |
| --- | --- | --- | --- | --- |
| هزینه پیش از کلیک؛ موجودی پس از اقدام | Schematic (credit UX) | اعتماد و تیکت کمتر | **هست:** هزینه روی دکمه | https://docs.schematichq.com/use-cases/pre-flight |
| دیالوگ تأیید برای کار پراثر با توضیح اثر جانبی | Vercel (Attack Challenge Mode) | رضایت آگاهانه | **طرح** برای اسکن عمیق (⚑۹) | https://vercel.com/docs/attack-challenge-mode |
| تفکیک «وضعیت» از «شدت»؛ آیکون + رنگ + برچسب | PatternFly، Carbon | دسترس‌پذیری و خوانایی | **هست:** `Ui::sev` و `Ui::chip` (`mcsec-rtl-review`) | https://www.patternfly.org/patterns/status-and-severity/ |
| نشانگر پیشرفت درصدی و مرحله‌ای برای کار بیش از ۱۰ ثانیه | NN/g | اضطراب کمتر | **هست:** `Ui::progress` و مرحله‌ها | https://www.nngroup.com/articles/progress-indicators/ |

## دیده نشد
سازوکار تأیید مالکیت Intruder، Pentest-Tools و HostedScan در منابع عمومی اعلام نشده بود (احتمالاً پذیرش شرایط استفاده). قیمت عمده‌ی SiteLock روی MarketConnect پشت ورود است. داده‌ی بازار ایران ناقص است و بررسی میدانی می‌خواهد (`competitive-analysis.md` §۲).
