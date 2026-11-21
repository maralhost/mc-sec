---
name: mcsec-backends
description: >
  Reference for MC-Sec's scan backends: OASM (Open Attack Surface Management, oasm-platform/open-asm v0.12.1, checked
  live on Maral's staging) and Osmedeus v5 (j3ssie/osmedeus, from source). Auth models, the exact endpoints MC-Sec calls,
  customer isolation, progress detection, result normalization, pitfalls and the operator checklist. Use when writing or
  reviewing lib/Engines/*, the engine tests, the admin "setup" page, or when asked about OASM / Osmedeus APIs
  (اواس‌ام، اوسمدئوس، موتور اسکن، endpoint، workspace، nuclei).
---

# مرجع اتصال MC-Sec به OASM و Osmedeus

مرجع کامل و منبع‌دار: `docs/research/oasm-api.md` (+ `oasm-openapi.json`، ۲۹۴ مسیر) و `docs/research/osmedeus-api.md` (+ `osmedeus-openapi.json`). این فایل خلاصه‌ی «آنچه کد به کار می‌برد» است. برچسب ⚠ = آزموده‌نشده روی سرور واقعی.

## OASM (آزموده روی `oasm-staging.maral.cloud`، v0.12.1، ۲۰ آبان ۱۴۰۵)
**احراز هویت:** فقط کوکی نشست better-auth. `POST /api/auth/sign-in/email {email,password,rememberMe:true}` با سربرگ `Origin` ← `Set-Cookie` (نام‌ها در staging: `session` و …). Bearer و کلید API فضای کار (`/api/workspaces/api-key`) روی REST کار نمی‌کنند (فقط MCP `/api/mcp` با `x-oasm-api-key`). کد: `Oasm::session()`؛ کوکی رمزنگاری‌شده در `Kv` (`oasm:session` برای حساب سرویس، `oasm:s:<client>` برای هر مشتری)، با 401 یک بار ورود دوباره.
**جداسازی مشتری:** هر کاربر OASM حداکثر ۵ فضا دارد و فقط مالک فضا هدف می‌سازد ← حساب سرویس (نقش admin) برای هر حساب WHMCS کاربر می‌سازد: `POST /api/auth/admin/create-user {email: mcsec-c<id>@<oasm_user_domain>, name, password, role:'user'}`؛ اگر از قبل بود: `GET /api/auth/admin/list-users?searchField=email…` و `POST /api/auth/admin/set-user-password`. بعد با نشست همان کاربر: `POST /api/workspaces {name, description}` (description لازم است) و `PATCH /api/workspaces/configs {isAssetsDiscovery, isAutoEnableAssetAfterDiscovered}`. هر درخواست فضا سربرگ `X-Workspace-Id`.
| کار | endpoint | نکته |
| --- | --- | --- |
| هدف | `POST /api/targets/bulk {targets:[{value,type:DOMAIN|IP|CIDR}]}` | ساختن هدف خودش کشف را شروع می‌کند. تکراری کل درخواست را 400 می‌کند ⚠ ← `GET /api/targets?value=` |
| کشف دوباره | `POST /api/targets/{id}/re-scan` | |
| آسیب‌پذیری | `POST /api/vulnerabilities/scan {targetIds:[…]}` | workflow `vulnerability_scan_basic` (nuclei). پیش از آن `Oasm::nuclei`: nuclei در فضای تازه نصب نیست (`POST /api/tools/install {toolId}`) و اگر `availableWorkersCount` صفر باشد (staging امروز: فقط کارگر داخلی، هیچ connector) اسکن همان لحظه ناموفق می‌شود و اعتبار برمی‌گردد؛ وگرنه برای همیشه pending می‌ماند |
| پیشرفت | `GET /api/targets/{id}/runs?limit=10&sortOrder=DESC` | `isCompleted`، `status`، `jobsTotal/jobsDone`، `currentTool`، `workflowName` («Domain discovery»، «Ip address discovery»، …). شناسه‌ی اجرا برنمی‌گردد: با زمان (`since`) و نام workflow جور می‌شود |
| نتیجه | `GET /api/assets?targetIds=<id>&limit=100&page=n` | هر ردیف یک سرویس `host:port` با `httpResponses` (title، webserver، status_code، tech[]، tls). روی درگاه غیر HTTP (مثل ۲۲) `failed: true` با URL ساختگی می‌آید؛ نادیده گرفته می‌شود |
| یافته‌ها | `GET /api/vulnerabilities?targetId=<id>&limit=100&page=n` | name، severity، affectedUrl/host/ports، description، solution، references، cveId، cweId، cvssScore، epssScore، extractedResults، detectionStatus |
| لغو | `GET …/runs?active=true` ← `POST /api/jobs-registry/histories/{id}/cancel` | |
| سلامت | `GET /api/health` (متن OK)، `GET /api/metadata` (`currentVersion`) | عمومی |
صفحه‌بندی `page`/`limit` (حداکثر ۱۰۰). بیشتر POSTها 201 برمی‌گردانند. `GET /api/targets/{id}/changes` و وب‌هوک integration برای همگام‌سازی افزایشی در roadmap.

## Osmedeus v5 (از سورس v5.1.2؛ سرور ما از این ماشین در دسترس نبود ⚠)
**احراز هویت:** سربرگ `x-osm-api-key: <server.auth_api_key>` (پیشنهادی؛ `osmedeus config view server.auth_api_key`)، یا `POST /osm/api/login {username,password}` ← `{token}` (JWT ۲۴ ساعته، بی refresh) در `Authorization: Bearer`. کد: `Osmedeus::call()`.
| کار | endpoint | نکته |
| --- | --- | --- |
| شروع | `POST /osm/api/runs {flow, target, params:{space_name, tactic, exclude_modules}}` | ← 202 `{run_uuid, job_id}`. مقدارها نباید فاصله یا `;'"|&\`$(){}[]` داشته باشند (`Osmedeus::safe`). خطای نوع هدف بعداً به صورت failed می‌آید: دامنه به flowهای دامنه، IP/CIDR به `cidr` (`flowFor`) |
| پیشرفت | `GET /osm/api/runs/{uuid}` | `status` pending/running/completed/failed/cancelled؛ `completed_steps/total_steps` |
| نتیجه | `GET /osm/api/assets?workspace=<space>&limit=500&offset=n`، `GET /osm/api/vulnerabilities?workspace=…` | داده‌ی کل workspace است؛ با `last_seen_at >= شروع اجرا` جدا می‌شود. nuclei خام در `raw_vuln_json` (`matched-at`، `info.classification`) |
| لغو | `DELETE /osm/api/runs/{uuid}` | ممکن است به failed «context canceled» ختم شود ← لغو حساب شود |
| سلامت | `GET /server-info` (بی‌احراز)، `GET /osm/api/workflows?limit=1` | |
**دام‌ها:** صف ندارد (سقف `concurrency_osm`)؛ `timeout` اجرا نمی‌شود (سقف `scan_timeout_hours`)؛ فقط HTTP (پشت TLS/تونل)؛ کلید API عملاً root است (endpointهای eval و upload دارد) — فقط رمزنگاری‌شده، هرگز در رابط مشتری؛ flow `general` ماژول `enum-ipspace` دارد که از دامنه به فضای IP می‌رود — برای دامنه `exclude_modules=enum-ipspace` فرستاده می‌شود.

## چک‌لیست اپراتور (پیش از روشن کردن برای مشتری)
1. OASM: کاربر admin مخصوص WHMCS، `oasm_user_domain` (ایمیلی فرستاده نمی‌شود)، worker با nuclei آنلاین، آزمودن در «راه‌اندازی».
2. Osmedeus: فایروال IP سرور WHMCS را بپذیرد؛ TLS جلوی آن؛ کلید API؛ flowهای `fast` و `general` و `cidr` نصب باشند (`GET /osm/api/workflows`).
3. IP اسکنرها (OASM workers، Osmedeus، سرور WHMCS برای بررسی داخلی) را در فایروال‌ها و WAF خود مارال allowlist کنید و در صفحه‌ی راهنمای مشتری اعلام کنید.
4. یک دارایی آزمایشی را با هر profile اسکن کنید و نتیجه را با پنل خود موتور مقایسه کنید.
5. `php tools/selftest.php` روی سرور WHMCS.

## OASM: رفتارهای زنده‌ی ۳۰ آبان ۱۴۰۵ (staging، v0.12.1) که کد ۰٫۳٫۰ بر آن‌هاست
- **اسکن آسیب‌پذیری فقط از راه پروژه:** `POST /api/projects` با `scopeRules:[{mode:include,type:target,value:<targetId>}]` و `tools:[{toolId, category:'vulnerabilities', input:['web','host'], stage:1, config:{…}}]`؛ بعد `GET /api/projects/{id}` برای `projectWorkflows[0].id` و `POST /api/projects/{id}/workflows/{binding}/run` ← `{jobHistoryId}`. پیشرفت: `GET /api/projects/{id}/runs` (همان `id`، با `status`، `isCompleted`، `stepsTotal/Done/Failed`). تنظیم پروژه دقیقاً اعمال می‌شود. `POST /api/vulnerabilities/scan` تنظیم پیش‌فرض ورک‌فلو را می‌گذارد (۱۵۰ درخواست در ثانیه، interactsh روشن) و پروفایل ابزار فقط بخشی را عوض می‌کند: از آن استفاده نکن.
- **`availableWorkersCount` برای ابزارهای connector همیشه ۰ است**، حتی وقتی کارگر node آن‌ها را اجرا می‌کند. هرگز با آن تصمیم نگیر. شمار کارگر آنلاین: `GET /api/workers?scope=cloud` (با `X-Workspace-Id`)، فیلد `isOnline`؛ حالت کارگر (node یا cli) در پاسخ نیست.
- **`isReady` فقط پس از داشتن پروفایل تنظیم:** `POST /api/tools/{id}/config-profiles` با `{name, isDefault:true, config}`؛ طرح‌واره از `GET /api/tools/{id}/schema`. nuclei: `concurrency`، `rateLimit`، `interactsh`، `excludeTags`، `tags`، `templateIds`، `severity`، `followRedirects`.
- **هدفِ مسدودکننده:** محافظ وب سرور هدف IP اسکنر را در چند ثانیه می‌بندد (حتی با ۱۰ درخواست در ثانیه)؛ OASM اجرا را `failed` می‌کند و هر کار را تا ۴ بار دوباره می‌فرستد. دلیل در `GET /api/jobs-registry?jobHistoryId=<run>` ← `data[].errorLogs[].logMessage` («target marked unresponsive»). `Oasm::blockedByTarget` همین را می‌خواند و اسکن «ارزیابی ناقص» می‌شود.
- nuclei روی هدفی که سرویس وب ندارد هم همین پیام را می‌دهد.
- **هدف IP، بی نام دامنه اسکن می‌شود** (صفحه‌ی پیش‌فرض سرور، نه vhost). برای سرور اصلی دامنه‌ی پشت CDN هنوز راهی نداریم (نقشه‌ی راه).
- **زیرساخت staging:** OASM روی `185.165.119.147` (compose در `/opt/security-platform/oasm-docker`، درگاه gRPC `16276` فقط روی loopback) با یک کارگر node؛ کارگر دوم روی `88.198.128.141` در `/opt/oasm-worker` که با سرویس `oasm-tunnel` (تونل SSH محدود) وصل می‌شود. Docker Hub از سرور OASM 403 می‌دهد؛ imageهای connector از ghcr.io می‌آیند.
- **پایپ‌لاین چندابزاره (۰٫۴٫۰):** `tools[]` با `stage` افزایشی؛ OASM از آن `needs` می‌سازد (سنجیده: katana مرحله‌ی ۱، nuclei و zap مرحله‌ی ۲). دسته و ورودی هر ابزار باید همان `categories[]` خود ابزار باشد (`Catalog::TOOLS`): katana و gau فقط `DOMAIN` و ورودی `host`؛ nmap دو دسته دارد (`ports_scanner` و `vulnerabilities`).
- **فهرست آسیب‌پذیری هدف مشترک همه‌ی ابزارهاست** (`GET /api/vulnerabilities?targetId=`)؛ هر ردیف `tool.name` دارد. `Oasm::collect` فقط ابزارهای همان نوع اسکن را برمی‌دارد، وگرنه اسکن nuclei یافته‌ی ZAP را «رفع‌شده» می‌کرد.
- **طرح‌واره‌ی تنظیم ابزارها** (از `GET /api/tools/{id}/schema`): zap `scanMode` (baseline یا full)، katana `rateLimit/depth/maxUrls/crawlDuration/headers`، nmap `topPorts/ports/noPing`، ffuf `rate/wordlist/maxTime`، wpscan `apiToken` (اجباری) و `vhost`، acunetix `url` و `apiKey` (اجباری)، `profileId`، `maxScanTime`. رمزها در پروفایل ابزار فضای کار می‌مانند (`Oasm::profile`)، نه در پایپ‌لاین.
- **نشانی‌های katana و gau:** `GET /api/assets/url` فقط نشانی‌های گروه‌بندی‌شده می‌دهد (برای سایت آزمایشی فقط خود ریشه)؛ جای فهرست کامل نشانی‌های کشف‌شده هنوز پیدا نشده، پس نوع اسکن `urls` خاموش است.
- **اسکرین‌شات (۰٫۵٫۰):** `screenshotPath` در `GET /api/assets` یک مسیر **نسبی** امضاشده است (`/api/storage/screenshot/<hash>.png?X-Amz-…`)، بی کوکی با همان نشانی پایه‌ی OASM دانلود می‌شود و ۴۸ ساعت اعتبار دارد؛ محتوا JPEG است با `Content-Type: image/png`. امضا نام کلید ذخیره‌سازی را دارد: مسیر را هیچ‌جا ذخیره یا لاگ نکن (`Oasm::collect` آن را فقط در `shots` برمی‌گرداند و `Shots::save` همان لحظه دانلود می‌کند).
