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
| آسیب‌پذیری | `POST /api/vulnerabilities/scan {targetIds:[…]}` | workflow `vulnerability_scan_basic` (nuclei). worker با Docker لازم است، وگرنه pending می‌ماند |
| پیشرفت | `GET /api/targets/{id}/runs?limit=10&sortOrder=DESC` | `isCompleted`، `status`، `jobsTotal/jobsDone`، `currentTool`، `workflowName` («Domain discovery»، «Ip address discovery»، …). شناسه‌ی اجرا برنمی‌گردد: با زمان (`since`) و نام workflow جور می‌شود |
| نتیجه | `GET /api/assets?targetIds=<id>&limit=100&page=n` | هر ردیف یک سرویس `host:port` با `httpResponses` (title، webserver، status_code، tech[]، tls) |
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
