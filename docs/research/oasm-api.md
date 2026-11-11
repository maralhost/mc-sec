# OASM (Open Attack Surface Management) — API reference for the MC-Sec WHMCS module

Research date: 2026-11-11. Target instance: `https://oasm-staging.maral.cloud/` (staging).

Labels used below:

- **Verified (live)**: observed with an unauthenticated GET against staging.
- **Verified (spec)**: present in the staging OpenAPI document (`oasm-openapi.json`, saved next to this file).
- **Verified (source)**: read in upstream source at tag `v0.12.1`.
- **UNVERIFIED**: inferred, or depends on staging configuration that cannot be seen without credentials.

---

## 1. What OASM is and which version staging runs

| Item | Value | Evidence |
|---|---|---|
| Upstream repo | `github.com/oasm-platform/open-asm` (TypeScript monorepo, GPL-3.0-only) | `/api/metadata` returns `gitRepoUrl: https://github.com/oasm-platform/open-asm` (live) |
| Staging version | **v0.12.1** (released 2026-11-09, the latest release) | `/api/metadata` → `currentVersion: "v0.12.1"`; `/api/version/latest` → `isLatest: true` (live) |
| Backend | `core-api/`: NestJS 11, TypeORM/PostgreSQL (pgvector), Redis + BullMQ, better-auth 1.6.23, gRPC server for workers (`:16276`), in-process MCP endpoint, RustFS/S3 storage | source |
| Frontend | `console/`: React 19 + Vite, TanStack Router; talks to the same origin under `/api` | live HTML + source |
| Scanners | `worker/`: Go worker. It runs the built-in CLIs itself and starts "connector" containers (nuclei, nmap, ZAP, …) through the Docker Engine API | source |
| API docs | Scalar UI at `/api/docs` (the full OpenAPI 3.0 document is embedded in the HTML); better-auth docs at `/api/auth/docs`; better-auth schema at `/api/auth/open-api/generate-schema` | live |
| Docs/home | `https://docs.oasm.io`, `https://oasm.dev` | `/api/metadata` |
| Edge | Responses carry `Server: MizbanCloud`, so a CDN/WAF sits in front of staging | live |

`/api-json`, `/docs-json` and `/swagger` return the console SPA (HTML), not JSON. `/api/docs-json` and `/api/swagger-json` return 404. The spec is available only inside `/api/docs`. `oasm-openapi.json` was extracted from that page: 294 paths and 454 schemas. It merges the NestJS routes with the better-auth routes. Note that better-auth paths appear **without** their `/api/auth` prefix in the spec (e.g. `/sign-in/email` is really `/api/auth/sign-in/email`).

Public, unauthenticated endpoints confirmed live:

```
GET /api/health          -> 200 "OK" (text/plain)
GET /api/metadata        -> {"isInit":true,"name":"OASM","logoPath":null,"allowSignUp":false,"currentVersion":"v0.12.1","storagePresignTtlSeconds":172800,"gitRepoUrl":"https://github.com/oasm-platform/open-asm","docsUrl":"https://docs.oasm.io","homePageUrl":"https://oasm.dev"}
GET /api/version/latest  -> {"currentVersion":"0.12.1","latestVersion":"0.12.1","isLatest":true,"notes":"...","releaseDate":"2026-11-09T08:52:35Z"}
GET /api/auth/ok         -> {"ok":true}
GET /api/auth/get-session-> null            (no cookie)
GET /api/mcp             -> 401 {"message":"Missing workspace API key header","error":"Unauthorized","statusCode":401}
GET /api/workspaces      -> 401 {"message":"Unauthorized","statusCode":401}
```

On staging, `allowSignUp: false`, so public sign-up is closed. Accounts must be created by a platform admin (§3.5).

---

## 2. Conventions that apply to every call

- **Base URL**: `https://oasm-staging.maral.cloud/api`. The NestJS global prefix is `api`. better-auth is mounted at `/api/auth/*`.
- **Content type**: JSON in, JSON out. A few routes return CSV: `GET /api/targets/export` and `GET /api/assets/services/export`.
- **IDs**: UUID strings (v4). Timestamps are ISO-8601.
- **Workspace scoping**: send `X-Workspace-Id: <workspace uuid>` on **every** workspace-scoped call (verified, source). The server falls back to a `wid` cookie when the header is missing. That cookie is set by `GET /api/workspaces`. A non-UUID gives 400, and a non-member gets 403 (never 404). The OpenAPI omits the header on some routes that still need it, such as `POST /targets/{id}/re-scan`, `PATCH /targets/{id}`, `POST /assets/toggle` and `POST /tools/install`. Send it always.
  - The exceptions are `/workspaces/{id}` routes (`GET/PATCH/DELETE /workspaces/{id}`, `PATCH /workspaces/{id}/archived`, `POST /workspaces/{id}/api-key/rotate`, `GET /workspaces/{id}/audit`), where the path id is the workspace.
- **Pagination** (`GetManyBaseQueryParams`): `page` (≥1, default 1), `limit` (1–100, default **10**), `sortBy` (a bare column name matching `^[A-Za-z_][A-Za-z0-9_]*$`, default `createdAt`), `sortOrder` (`ASC|DESC`, default **ASC**). `search` exists but many services ignore it; for example targets use `value`.
  Response envelope: `{ "data": [...], "total": n, "page": n, "limit": n, "pageCount": n, "hasNextPage": bool }`.
  A few lists use keyset pagination instead: notifications and audit take `cursor`/`limit` and return `nextCursor`.
- **Arrays in query strings**: repeat the key (`?targetIds=a&targetIds=b`), the same way the console's axios serializer does. The server parses queries with `qs`, so `targetIds[]=a` also works. Most array params also accept a single value.
- **Filter trees**: several lists accept `filter=<url-encoded JSON>`:
  `{"logic":"and","items":[{"field":"severity","op":"in","value":["high","critical"]},{"logic":"or","conditions":[...]}]}`.
  The ops are `eq neq contains notContains in notIn inSubnet gt gte lt lte`. List ops (`in`, `notIn`, `inSubnet`) take an array; the others take a string. Limits: 20 conditions, 50 values, 255 characters per value.
- **Validation**: a global `ValidationPipe` runs with `whitelist: true, transform: true`. Unknown body fields are **silently dropped**, not rejected.
- **Status codes**: POST routes without `@HttpCode(200)` return **201**, even though the spec documents 200. These include `POST /workspaces`, `/targets/bulk`, `/targets/{id}/re-scan`, `/vulnerabilities/scan`, `/vulnerabilities/dismiss` and `/vulnerabilities/reopen`. Treat any 2xx as success.
- **Errors**: standard Nest shape `{"statusCode":400,"message":"..." | ["..."],"error":"Bad Request"}`. Validation errors return `message` as an array. better-auth errors return `{"statusCode":..,"message":".."}` or better-auth's own `{"code":"..","message":".."}` (UNVERIFIED for every route).
- **Tracing**: every response carries `X-Request-Id`. You may send your own, and it is propagated into the audit log.
- **CORS**: `origin: true, credentials: true`. This doesn't matter for server-to-server calls.

---

## 3. Authentication

### 3.1 The only REST credential is a better-auth session cookie

`AuthGuard` (`core-api/src/common/guards/auth.guard.ts`) runs globally and resolves every request with `auth.api.getSession(headers)`. Only routes marked `@Public()` and the `/api/mcp` subtree skip it. Verified (source):

- better-auth is configured with only the `admin` and `openAPI` plugins. There is **no `bearer` plugin and no `apiKey` plugin**, so `Authorization: Bearer <token>` does **not** work on REST routes, even though the spec lists a `bearerAuth` scheme.
- The workspace API key (`x-oasm-api-key`) is accepted **only on `/api/mcp` and `/api/mcp/message`**. Sending it to any other route has no effect. A past bypass that did this was fixed and the current code scopes it to MCP paths.
- So the WHMCS module must sign in as a user, keep the session cookie, and replay it.

**Sign in** (better-auth, verified spec + source):

```bash
curl -s -c jar.txt -H 'Content-Type: application/json' \
     -H 'Origin: https://oasm-staging.maral.cloud' \
     -d '{"email":"svc-client-123@mc-sec.example","password":"<secret>","rememberMe":true}' \
     https://oasm-staging.maral.cloud/api/auth/sign-in/email
```

Request body: `email` (req), `password` (req), `rememberMe` (opt, default true), `callbackURL` (opt).

Response 200:

```json
{
  "redirect": false,
  "token": "Qm9...raw-session-token",
  "url": null,
  "user": {
    "id": "6f1c...", "name": "MC-Sec client 123", "email": "svc-client-123@mc-sec.example",
    "emailVerified": false, "image": null, "role": "user", "banned": false,
    "createdAt": "2026-11-11T10:00:00.000Z", "updatedAt": "2026-11-11T10:00:00.000Z"
  }
}
```

And the response sets the cookie:

```
Set-Cookie: __Secure-session=<token>.<hmac>; Max-Age=604800; Path=/; HttpOnly; Secure; SameSite=Lax
```

Cookie facts:

- The configured cookie name is `session` (`advanced.cookies.session_token.name`). better-auth adds the `__Secure-` prefix when `BASE_URL` is https or `NODE_ENV=production`. On staging the name is therefore most likely `__Secure-session` (**UNVERIFIED**). Don't hard-code the name: store whatever `Set-Cookie` name ends in `session`.
- The cookie value is `token.signature`, signed with `BETTER_AUTH_SECRET`. The `token` in the JSON body alone cannot be turned into a cookie, so you must capture `Set-Cookie`.
- Lifetime follows the better-auth defaults (not overridden): 7 days, sliding refresh once a day. When a session is refreshed, `AuthGuard` copies the new `Set-Cookie` onto **any** API response. Persist the updated cookie whenever a response carries one.
- `rememberMe:false` gives a browser-session cookie plus a `dont_remember` cookie. Use `true`.
- Banned users cannot sign in. Banning also revokes their sessions (better-auth admin plugin behaviour).
- `autoSignIn` is off for sign-up. Email verification is **not** required for sign-in (`requireEmailVerification` is not set; UNVERIFIED on staging).

Other session routes (all under `/api/auth`):

| Method & path | Body | Notes |
|---|---|---|
| `GET /get-session` | – | `{session, user}` or `null`. Cheap health check for a stored cookie. |
| `POST /sign-out` | `{}` | Revokes the current session. |
| `GET /list-sessions` | – | Sessions of the user. |
| `POST /revoke-session` | `{"token": "..."}` | |
| `POST /change-password` | `{"currentPassword","newPassword","revokeOtherSessions?"}` | Needs a "fresh" session (`freshAge: 10` seconds). |

Rate limiting: better-auth has its own limiter, 100 requests per 60 s, in memory, per instance, keyed by client IP. It applies to `/api/auth/*` only. Behind the MizbanCloud proxy, client IP resolution depends on `TRUSTED_PROXIES`. If that is unset, every caller shares one bucket (UNVERIFIED on staging). Cache sessions and do not sign in per request. No other application-level throttling exists in core-api; the CDN/WAF may add its own (UNVERIFIED).

Origin header: better-auth enforces an origin/CSRF check on cookie-bearing **POSTs to `/api/auth/*`** (for example sign-out). `trustedOrigins` is `['*']`. Send `Origin: https://oasm-staging.maral.cloud` on every `/api/auth` POST to be safe. Plain Nest routes (`/api/targets`, …) are not origin-checked.

PHP sketch (cURL):

```php
function oasm_signin(string $base, string $email, string $pass): string {
    $ch = curl_init("$base/api/auth/sign-in/email");
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['email' => $email, 'password' => $pass, 'rememberMe' => true]),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Origin: ' . $base],
        CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 20,
    ]);
    $raw = curl_exec($ch);
    $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($code !== 200) { throw new RuntimeException("OASM sign-in failed: HTTP $code " . substr($raw, $hs)); }
    preg_match_all('/^set-cookie:\s*([^=;\s]+)=([^;]*)/mi', substr($raw, 0, $hs), $m, PREG_SET_ORDER);
    foreach ($m as $c) { if (preg_match('/(^|-)session$/', $c[1])) { return $c[1] . '=' . $c[2]; } }
    throw new RuntimeException('OASM sign-in: no session cookie');
}
// Then for every API call: headers "Cookie: <stored>", "X-Workspace-Id: <uuid>", "Accept: application/json".
// On 401: sign in again once and retry. Do NOT persist the `wid` cookie (see §2).
```

### 3.2 Workspace API key (MCP only)

| Method & path | Permission | Result |
|---|---|---|
| `GET /api/workspaces/api-key` (+ `X-Workspace-Id`) | `workspace.apikey` | `{"apiKey":"<36 chars>"}`. **The first call creates the key.** |
| `POST /api/workspaces/{id}/api-key/rotate` | `workspace.apikey` | `{"apiKey":"..."}`. Revokes the old key. |

- Header name: `x-oasm-api-key`. One active key per workspace. It is stored **in plaintext** in `api_keys` (equality lookup).
- It only authenticates the MCP server (§5.15), which is **read-only**.

### 3.3 Worker tokens (not for the WHMCS module)

Workers use `worker-token` (HTTP) or gRPC metadata. `POST /api/workers/join-keys` (permission `workspace.apikey`) mints a one-time join key (TTL 300 s) for a **workspace-scoped** worker. The platform-wide "cloud" worker joins with `OASM_CLOUD_APIKEY` from the server env.

### 3.4 Workspace permissions

Permission keys come from `permission-catalog.json` in the form `resource.action`. Resources and actions:

- `workspace.read|write|delete|config|apikey`
- `member.read|write`
- `invitation.read|write`
- `workflow.read|write`
- `project.read|write`
- `target.read|write`
- `asset.read|write`
- `vulnerability.read|write`
- `network.read|write`
- `integration.read|write`
- `report.read|write`
- `agent.read|write`
- `notification.read`
- `job.read|write|delete`
- `worker.read|write`
- `artifact.read|write|manage`
- `audit.read`

`x.write` implies `x.read`. The workspace owner is in the system "Admin" group, which holds `*`.

**Owner-only operations** (permissions are not enough; verified, source):

- `POST /api/targets/bulk` and `DELETE /api/targets/{id}` call `getWorkspaceByIdAndOwner`. They return 403 unless the session user is the **owner** of the workspace.

**Workspace creation limit**: `LIMIT_WORKSPACE_CREATE = 5`. A user can own at most 5 workspaces; the 6th returns `400 "You have reached the limit of workspaces"`. It is a compile-time constant with no admin bypass. Platform admins are **not** implicit members of workspaces: `WorkspacePermissionGuard` has no admin bypass.

### 3.5 User provisioning (platform admin session)

better-auth admin plugin routes, all `POST` under `/api/auth/admin/*` and requiring a session with `role=admin`:

| Path | Body | Use |
|---|---|---|
| `/admin/create-user` | `{"email","name","password?","role?":"user","data?":{}}` → `{user}` | Create the per-customer service user. |
| `/admin/set-user-password` | `{"userId","newPassword"}` | Rotate a service user's password. |
| `/admin/ban-user` / `/admin/unban-user` | `{"userId","banReason?","banExpiresIn?"}` / `{"userId"}` | Suspend/unsuspend. Bans revoke sessions. |
| `/admin/impersonate-user` / `/admin/stop-impersonating` | `{"userId"}` | Admin acts as the user. better-auth default impersonation session: 1 h (UNVERIFIED). |
| `/admin/set-role` | `{"userId","role"}` | |
| `/admin/revoke-user-sessions` | `{"userId"}` | |

These are disabled on purpose (`disabledPaths`): `/admin/remove-user`, `/admin/list-users`, `/admin/get-user`, `/delete-user`. **Users are never deleted** because `workspaces.ownerId` cascades. Use NestJS admin routes instead:

- `GET /api/admin/users?search=&workspaceId=` (paginated `AdminUserDto`)
- `GET /api/admin/users/{id}`
- `GET /api/admin/workspaces?search=&isArchived=` (every workspace with owner, targetCount, memberCount)
- `GET|PATCH /api/admin/workspaces/{id}` (name, description, isAssetsDiscovery, isAutoEnableAssetAfterDiscovered)
- `PATCH /api/admin/workspaces/{id}/archived`
- `PATCH /api/admin/workspaces/{id}/storage-quota`

---

## 4. Domain model in one picture

```
User ──owns (≤5)──> Workspace ──1:n──> Target (DOMAIN | IP | CIDR | GIT_ORG; unique per workspace)
                        │                  └─1:n─> Asset (host: subdomain or IP; isPrimary for the target itself)
                        │                              ├─1:n─> AssetService (host:port; screenshotPath)
                        │                              │          └─1:n─> HttpResponse (title, status, tech, TLS cert, IPs…)
                        │                              ├─1:n─> DNS records, IP observations
                        │                              └─1:n─> Vulnerability (fingerprint = md5(name-assetId-toolId))
                        ├─1:n─> Workflow (DAG of tool steps, jsonb)  ──> JobHistory (= "run") ──1:n──> Job (one tool on one asset/service)
                        ├─1:n─> Project (asset subset + own pipelines/schedules)
                        ├─1:n─> Issue, Integration (webhook/Slack/Discord/Telegram/Jira*, AWS/Cloudflare/Vercel, GitHub/GitLab)
                        └─1:1─> API key (MCP)
```

Everything hangs off `target.workspaceId`. Jobs and vulnerabilities have no `workspaceId` column and are tenant-scoped through `asset → target → workspace`. Deleting a target cascades to its assets, services, jobs and vulnerabilities. Deleting a workspace hard-deletes everything.

---

## 5. Endpoint reference

Permission = workspace permission key. "owner" = must be the workspace owner. Body fields marked `?` are optional.

### 5.1 Health, version, metadata (public)

| Method & path | Auth | Response |
|---|---|---|
| `GET /api/health` | none | `200 OK` (text) |
| `GET /api/metadata` | none | `{isInit, name, logoPath, allowSignUp, currentVersion, storagePresignTtlSeconds, gitRepoUrl, docsUrl, homePageUrl}` |
| `GET /api/version/latest` | none | `{currentVersion, latestVersion, isLatest, releaseDate, notes}` |
| `GET /api/auth/ok` | none | `{"ok":true}` |

### 5.2 Workspaces

| Method & path | Permission | Body / params → response |
|---|---|---|
| `POST /api/workspaces` | session; ≤5 owned | `{"name":"string","description":"string","archivedAt?":"date-time"}` (`description` is **required**, but may be `""`) → `Workspace` (201). Creates the owner membership, the Admin group and the 5 default workflows. |
| `GET /api/workspaces` | session | `page, limit, sortBy, sortOrder, search, isArchived?` → paginated `WorkspaceResponseDto{id,name,description,createdAt,updatedAt,archivedAt,isAssetsDiscovery,isAutoEnableAssetAfterDiscovered,ownerId,targetCount,memberCount}`. **Sets the `wid` cookie.** |
| `GET /api/workspaces/{id}` | `workspace.read` | `Workspace{id,name,description,archivedAt,isAssetsDiscovery,isAutoEnableAssetAfterDiscovered,settings,...}` |
| `PATCH /api/workspaces/{id}` | `workspace.write` | `{"name?","description?"}` → `{"message":"Success"}` |
| `DELETE /api/workspaces/{id}` | `workspace.delete` | Hard delete with cascade → `{"message":"Success"}` |
| `PATCH /api/workspaces/{id}/archived` | `workspace.write` | `{"isArchived":true}` → message |
| `GET /api/workspaces/configs` | `workspace.config` | `{isAssetsDiscovery:{value,...}, isAutoEnableAssetAfterDiscovered:{value,...}}` |
| `PATCH /api/workspaces/configs` | `workspace.config` | `{"isAssetsDiscovery":bool,"isAutoEnableAssetAfterDiscovered":bool}` |
| `GET /api/workspaces/current-permission` | member | `{"currentPermission":["*"]}` |
| `GET /api/workspaces/members` | `member.read` | members with permission groups |
| `PATCH /api/workspaces/members/{memberId}`, `DELETE …` | `member.write` | |
| `GET/POST /api/workspaces/permissions`, `PATCH/DELETE …/{permissionId}`, `GET …/permissions/catalog` | `member.read` / `workspace.write` | permission groups |
| `POST /api/workspaces/invitations` | `invitation.write` | Invites existing accounts only; the response returns counts |
| `GET /api/workspaces/invitations`, `POST …/{invitationId}/cancel` | `member.read` / `invitation.write` | |
| `POST /api/workspaces/invitations/accept` / `decline` | session (email must match) | token from the invite |
| `GET /api/workspaces/invitations/{token}` | public | preview |
| `GET /api/workspaces/api-key`, `POST /api/workspaces/{id}/api-key/rotate` | `workspace.apikey` | §3.2 |
| `GET /api/workspaces/{id}/audit` (+`/actions`, `/export`) | `audit.read` | Keyset audit trail: `cursor, limit, actorId, action, resourceType, outcome, from, to` |

Workspace settings that matter for scanning:

- `isAssetsDiscovery` (default true): when false, subdomain enumeration (SUBDOMAINS) steps are dropped from runs, so only the target itself is scanned.
- `isAutoEnableAssetAfterDiscovered` (default true): new assets are enabled and scanned immediately. When false, they stay disabled until toggled on.

Example:

```bash
curl -s -b jar.txt -H 'Content-Type: application/json' \
  -d '{"name":"WHMCS client 123","description":"mc-sec svc 4567"}' \
  https://oasm-staging.maral.cloud/api/workspaces
# -> {"id":"0b8e...","name":"WHMCS client 123","description":"mc-sec svc 4567","isAssetsDiscovery":true,
#     "isAutoEnableAssetAfterDiscovered":true,"settings":{},"createdAt":"...","updatedAt":"...","archivedAt":null}
```

### 5.3 Targets

| Method & path | Permission | Body / params → response |
|---|---|---|
| `POST /api/targets/bulk` | `target.write` **+ owner** | `CreateMultipleTargetsDto` → `BulkTargetResultDto` (201) |
| `GET /api/targets` | `target.read` | filters: `value` (LIKE), `type`, `status` (`pending|in_progress|completed|failed|cancelled`), `scope` (`INTERNAL|EXTERNAL`), `hasCritical`, `stale` (not discovered in 30 days), plus pagination. `sortBy` is a Target column, `totalAssetServices` or `duration`. |
| `GET /api/targets/summary` | `target.read` | `{total, scanning, withCritical, scheduled, stale, openVulnerabilities:{critical,high,medium,low,info}}` |
| `GET /api/targets/{id}` | `target.read` | `Target`. **An unknown id returns 200 with an empty body, not 404.** |
| `GET /api/targets/{id}/overview` | `target.read` | `TargetOverviewDto` (counts with 7-day deltas, `activeRuns[]`, `lastRun`, `nextScanAt`, `topVulnerabilities[]`, `exposure{ports,technologies,statusCodes}`, `insights[]`) |
| `GET /api/targets/{id}/runs` | `target.read` | `active?=true`, pagination → `TargetRunDto[]`, newest first |
| `GET /api/targets/{id}/changes` | `target.read` | `kind?=asset|service|vulnerability|fixed`, pagination → `TargetChangeDto{kind,at,id,label,assetValue?,severity?}`, newest first |
| `PATCH /api/targets/{id}` | `target.write` | `{"scanSchedule?": CronSchedule, "settings?": {includeArchived?, includeForks?}}` → `Target` |
| `POST /api/targets/{id}/re-scan` | `target.write` | no body → `{"message":"Scan started"}` (201). Re-runs **discovery** (§6). |
| `DELETE /api/targets/{id}` | `target.write` **+ owner** | cascades to assets, services, jobs and vulnerabilities |
| `GET /api/targets/export` | `target.read` | CSV |
| `GET /api/targets/{id}/repositories` | `target.read` | GIT_ORG only |

`CreateTargetDto`:

```json
{
  "targets": [
    { "value": "example.com", "type": "DOMAIN" },
    { "value": "203.0.113.10", "type": "IP" },
    { "value": "198.51.100.0/24", "type": "CIDR" },
    { "value": "github.com/acme", "type": "GIT_ORG", "integrationId": "<SOURCE_CODE integration uuid>",
      "settings": { "includeArchived": false, "includeForks": false } }
  ]
}
```

- `type?` defaults to `DOMAIN`. `integrationId?` and `settings?` apply to GIT_ORG only.
- Validation (source):
  - DOMAIN must match `^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$` and must not be an IP. Subdomains are accepted, and the value is not lower-cased, so normalise it yourself.
  - IP must be **public IPv4**. IPv6 is not supported.
  - CIDR must be public with a prefix from **/24 to /32**. It is normalised to the network address and rejected when it overlaps another CIDR in the workspace.
  - A CIDR creates **one asset per address** (a /24 creates 256 assets and 256 port-scan jobs).
- Duplicates are **rejected, not skipped**: `400 "Target already exists: …"`. `skipped`/`totalSkipped` in the response are always empty, despite the Swagger text. Uniqueness is `(workspaceId, value)`.
- Response:

```json
{
  "created": [
    { "id": "5a4c...", "value": "example.com", "type": "DOMAIN", "source": "MANUAL",
      "scanSchedule": "disabled", "lastDiscoveredAt": null, "reScanCount": 0,
      "createdAt": "...", "updatedAt": "..." }
  ],
  "skipped": [], "totalRequested": 1, "totalCreated": 1, "totalSkipped": 0
}
```

  The exact field list of `created[]` items is the raw `Target` row (UNVERIFIED which computed fields are present).

`GetManyTargetResponseDto` (list row):

```json
{
  "id": "5a4c...", "value": "example.com", "type": "DOMAIN",
  "source": { "source": "Manual", "icon": "" },
  "logo": "https://example.com/favicon.ico", "reScanCount": 1,
  "scanSchedule": "0 0 * * 0", "status": "completed",
  "totalAssetServices": 14, "totalAssets": 6, "duration": 0,
  "lastDiscoveredAt": "2026-11-11T08:00:00.000Z", "integrationId": null, "internalNetworkId": null
}
```

- `status` in the list is computed from the target's jobs as `in_progress` > `pending` > `completed` (no jobs counts as `completed`). The OpenAPI enum (`RUNNING|DONE`) is wrong.
- `openVulnerabilities`, `scanProgress`, `nextScanAt` and `projects` are documented as optional. Whether the list fills them is UNVERIFIED; `GET /targets/summary` and `/targets/{id}/overview` do.
- `search` is ignored by this list. Use `value`.

`CronSchedule` values (the only allowed `scanSchedule` values):

- `disabled`
- `0 0 * * *` (daily)
- `0 0 */3 * *` (every 3 days)
- `0 0 * * 0` (weekly, Sunday)
- `0 0 */14 * *` (bi-weekly)
- `0 0 1 * *` (monthly)

A schedule is a BullMQ repeatable job per target that calls the same code path as re-scan, with `jobRunType=scheduled`. It runs in the server's timezone (UNVERIFIED, likely UTC). **The schedule runs discovery only** (domain/IP discovery workflows), not nuclei.

`TargetRunDto` (`/targets/{id}/runs`, also `overview.activeRuns[]` and `overview.lastRun`):

```json
{
  "id": "9d2e... (jobHistoryId)", "createdAt": "...", "updatedAt": "...",
  "isCompleted": false, "status": "in_progress", "jobRunType": "manual",
  "workflowName": "Domain discovery", "projectId": null, "projectName": null,
  "jobsTotal": 12, "jobsDone": 7, "jobsFailed": 0, "jobsRunning": 2,
  "currentTool": "httpx", "newVulnerabilities": 0
}
```

- `status` is derived from the run's jobs: `cancelled` (some cancelled and none active), then `failed` (any failed), then `in_progress`, then `completed` (all completed), then `skipped`, otherwise `pending`.
- `active=true` means `NOT isCompleted AND createdAt > now - 7 days AND status IN (pending, in_progress)`.

### 5.4 Runs and jobs (`/api/jobs-registry`)

A **run** is a `JobHistory`, one execution of a workflow over a scope. A **job** is one tool invocation on one asset or service.

| Method & path | Permission | Notes |
|---|---|---|
| `GET /api/jobs-registry/histories` | `job.read` | Filters: `jobHistoryId`, `jobStatus` (`pending|in_progress|completed|failed|cancelled|skipped|all`), `jobRunType` (`manual|scheduled|event|all`), `createdFrom`, `createdTo` (ISO) → `JobHistoryResponseDto{id,createdAt,updatedAt,totalJobs,completedJobs,failedJobs,progress,status,workflowName,jobHistoryName,jobRunType}`. No target filter; use `/targets/{id}/runs`. |
| `GET /api/jobs-registry/histories/{id}` | `job.read` | `JobHistoryDetailResponseDto{tools[{id,name,logoUrl,status}], steps[], workflowName, jobHistoryName, jobRunType, activeJobsCount, progress, stepsDone, stepsTotal, etaSeconds?, failureReason?}` |
| `GET /api/jobs-registry/histories/{id}/workflow` | `job.read` | the workflow content (JSON) plus step state |
| `POST /api/jobs-registry/histories/{id}/cancel` | `job.write` | Cancels every non-terminal job and stops the DAG |
| `POST /api/jobs-registry/histories/{id}/re-run` | `job.write` | → `{"jobHistoryId":"<new run>","message":"..."}`. Same workflow and scope; **returns the new run id**. |
| `GET /api/jobs-registry` | `job.read` | Jobs: `jobHistoryId`, `jobStatus` → `JobListItemDto{id,status,category,createdAt,updatedAt,pickJobAt,completedAt,priority,workerId,retryCount,command,config(masked),tool{id,name,logoUrl},asset{id,value,targetId},assetService,errorLogs[]}` |
| `POST /api/jobs-registry/{id}/re-run`, `/{id}/cancel`, `DELETE /{id}` | `job.write` / `job.delete` | single job |
| `GET /api/jobs-registry/timeline` | `job.read` | last 30 days, grouped by tool and target |
| `GET /{workerId}/next`, `POST /{workerId}/result/*` | worker token | for workers only |

`steps[]` (`WorkflowStepStatusDto`): `{id, name, run (tool), category, needs[], status: pending|dispatched|done|failed|skipped, reason?: no-inputs|blocked-by-failure|assets-discovery-off|run-cancelled, jobs, failed?, running?, dispatchedAt?, finishedAt?}`.

Job status enum: `pending`, `in_progress`, `completed`, `failed`, `cancelled`, `skipped`.

- FAILED jobs that still have an asset are automatically requeued to PENDING by the worker sweep, up to `JOB_MAX_RETRIES = 4`. A run reported as `failed` can therefore go back to in progress.
- Jobs whose worker vanished are requeued as well.
- Terminal jobs are pruned after 180 days, but runs (`job_histories`) and results are kept.

### 5.5 Assets, services, ports, technologies, TLS, screenshots

All are `GET`, need `asset.read`, and accept the common asset filter params:

- `targetIds[]`, `value`, `ipAddresses[]`, `ports[]`, `hosts[]`, `techs[]`, `statusCodes[]`, `tlsHosts[]`, `urls[]`
- `filter` (JSON tree, fields `host|port|ip|tech|url|statusCode|tlsHost|tag|project|isNew`)
- `startDate` / `endDate` (`YYYY-MM-DD`, on asset createdAt)
- `isNew` (bool)
- pagination

| Path | Returns |
|---|---|
| `/api/assets` | **Services** (host:port rows), paginated `GetAssetsResponseDto` |
| `/api/assets/{id}` | one service (`asset_services.id`) |
| `/api/assets/host` | hosts: `{id (assets.id), host, targetId, isEnabled, assetCount, createdAt, isNew}` |
| `/api/assets/ip` | `{ip, assetCount, geoIp{country,countryCode,city,isp,org,as,asname,lat,lon,…}}` |
| `/api/assets/port` | `{port, assetCount, newCount?, isNew?}` |
| `/api/assets/tech` | `{technology{name,version?,categoryNames[],website?,icon?…}, assetCount}` |
| `/api/assets/status-code` | `{statusCode (string), assetCount}` |
| `/api/assets/url` | discovered URLs `{url, assetCount, isNew}` (needs URL discovery to have run) |
| `/api/assets/tls` | certificates `{host, sni, subject_dn, subject_cn, issuer_dn, subject_an[], not_before, not_after, tls_version, cipher, tls_connection}`; `startDate`/`endDate` filter on `not_after` |
| `/api/assets/tags` | tag facets |
| `/api/assets/graph`, `/api/assets/{assetId}/services` | topology graph |
| `/api/assets/services/export` | CSV of services (value, ports, techs, TLS) |

Writes (`asset.write`):

- `PATCH /api/assets/{id}` `{tags:[...]}` replaces a service's tags.
- `POST /api/assets/toggle` `{"assetId":"<assets.id>","isEnabled":false}` enables or disables a host. Disabled hosts are kept but not scanned.
- `POST /api/assets/url/discover` `{"targetIds":[...]}` runs gau URL discovery on DOMAIN targets.
- `POST /api/assets/service/tag/generate` returns AI tag suggestions and stores nothing.

`GetAssetsResponseDto` (one row per service):

```json
{
  "id": "c1e0... (asset_services.id)", "value": "api.example.com:443", "targetId": "5a4c...",
  "isPrimary": false, "port": 443, "isEnabled": true, "isNew": true,
  "createdAt": "...", "updatedAt": "...",
  "ipAddresses": ["203.0.113.10"],
  "dnsRecords": { "A": ["203.0.113.10"], "CNAME": ["edge.cdn.net"] },
  "tags": [ { "id": "...", "tag": "api", "tool": { "id": "...", "name": "..." } } ],
  "screenshotPath": "https://<storage>/<bucket>/...png?X-Amz-Signature=... (presigned, null if none)",
  "httpResponses": {
    "url": "https://api.example.com", "status_code": 200, "title": "API", "webserver": "nginx",
    "scheme": "https", "host": "api.example.com", "port": "443", "content_type": "application/json",
    "content_length": 512, "techList": ["Nginx:1.25"], "chain_status_codes": ["301"],
    "favicon_url": "...", "tls": { "...": "httpx tls-grab object" }, "failed": false,
    "jobHistoryId": "...", "assetServiceId": "c1e0...", "createdAt": "..."
  }
}
```

ID pitfalls:

- `GET/PATCH /assets/{id}` take an `asset_services.id`.
- `POST /assets/toggle` and `/assets/{assetId}/services` take an `assets.id` (host).

`isNew` = found by the latest **finished** run of that workflow on that target.

Screenshots:

- `screenshotPath` in list responses is already a **presigned S3/RustFS URL**. Its lifetime is `storagePresignTtlSeconds`, 172800 s (48 h) on staging.
- Whether the storage host is reachable from outside the OASM network depends on `STORAGE_URL_BASE` (UNVERIFIED).
- `GET /api/storage/presign/download?bucket=&path=&fileName=` can re-sign a path.

### 5.6 Vulnerabilities

| Method & path | Permission | Notes |
|---|---|---|
| `POST /api/vulnerabilities/scan` | `vulnerability.write` | `{"targetIds":["uuid",...]}` → `{"message":"Scanning N target(s)..."}` (201). Runs the `vulnerability_scan_basic.yaml` nuclei step on DOMAIN/IP/CIDR targets and the full `repository_scan.yaml` (gitleaks + trivy) on GIT_ORG targets. Returns **no run id**. Returns 404 when no target matches or the workflow is missing in the workspace. |
| `GET /api/vulnerabilities` | `vulnerability.read` | see filters below |
| `GET /api/vulnerabilities/{id}` | `vulnerability.read` | `VulnerabilityDetailDto` (adds `sources[]` with `evidence`, `reviewedByUser`, `fixClaimedByUser`) |
| `GET /api/vulnerabilities/{id}/timeline` | `vulnerability.read` | `{data:[{id,type,fromStatus?,toStatus?,jobHistoryId?,actor,data?,occurredAt}]}` |
| `GET /api/vulnerabilities/statistics` | `vulnerability.read` | `targetIds[]?`, `projectId?` → `{data:[{severity,count}], byDetectionStatus{new,active,resurfaced,fixed}, newLast7Days, resurfacedLast30Days, fixedLast30Days, overdue, pendingReview, mttr:[{severity,days,count}]}` |
| `GET/PUT /api/vulnerabilities/settings` | `vulnerability.read` / `workspace.config` | `{slaDays{critical,high,medium,low,info}, slaRestartOnResurface, autoCloseEnabled, autoCloseMissedScans, riskAcceptMaxDays}` |
| `POST /api/vulnerabilities/dismiss` | `vulnerability.write` | `{"ids":[..],"reason":"false_positive|used_in_test|wont_fix|risk_accepted","comment?":"..","expiresAt?":"ISO (required for risk_accepted)"}` |
| `POST /api/vulnerabilities/reopen` | `vulnerability.write` | `{"ids":[..]}` → `{"reopened":n}` |
| `POST /api/vulnerabilities/claim-fix` | `vulnerability.write` | `{"vulnerabilityIds":[..],"note?":".."}` → `{"updated":n}`. The finding stays open until a covering scan stops reporting it. |
| `GET/POST /api/vulnerabilities/{id}/comments` | comments module | |
| `POST /{id}/analyze`, `DELETE /{id}/analyze`, `/review/*` | `vulnerability.write` | AI analysis and AI-proposal review; not needed for the integration |

List filters (`GET /api/vulnerabilities`):

| Param | Meaning |
|---|---|
| `targetIds[]`, `targetId` | restrict to targets |
| `severity[]` | `info,low,medium,high,critical` |
| `status` | `open` (default: approved, detected and not dismissed), `new`, `active`, `resurfaced`, `fixed`, `dismissed`, `pending_review`, `rejected`, `all` (every approved finding) |
| `q` | ILIKE on name |
| `createdFrom` / `createdTo` | on `firstDetectedDate` |
| `tags[]`, `discoveredBy[]` | `tool|ai|ai_tool|manual` |
| `overdue` | SLA `dueAt` passed |
| `filter` | JSON tree. Fields: `name, severity, tag, host, ip, port, cve, cwe, target, tool, affectedUrl, cvssScore, epssScore` |
| `projectId`, `provenance`, `jobHistoryId` | project views |
| sorting | `sortBy` defaults to `severity` (critical first with `sortOrder=DESC`, the default). Any column name is accepted, e.g. `updatedAt`, `lastSeenDate`, `firstDetectedDate`, `cvssScore`. |

`VulnerabilityListItemDto` (all scalar fields can be null):

```json
{
  "id": "e7b1...", "createdAt": "...", "updatedAt": "2026-11-11T09:12:00Z",
  "name": "Apache Tomcat - Default Login", "severity": "high",
  "description": "...", "synopsis": null, "solution": "Change default credentials ...",
  "tags": ["default-login","tomcat"], "references": ["https://..."], "authors": ["..."],
  "affectedUrl": "https://app.example.com:8443/manager/html",
  "host": "app.example.com", "ipAddress": "203.0.113.10", "ports": [],
  "cveId": ["CVE-2009-3548"], "cweId": ["CWE-255"], "cvssScore": 9.8, "cvssMetric": "CVSS:3.1/AV:N/...",
  "epssScore": 0.97, "vprScore": null, "bidId": [], "ceaId": [], "iava": [], "cveUrl": null, "cweUrl": null,
  "extractorName": null, "extractedResults": [],
  "publicationDate": null, "modificationDate": null,
  "firstDetectedDate": "2026-11-10T22:01:00Z", "lastSeenDate": "2026-11-11T09:12:00Z",
  "detectionStatus": "active", "timesDetected": 2, "resurfacedCount": 0,
  "lastSeenJobHistoryId": "9d2e...", "fixedAt": null, "fixedByJobHistoryId": null,
  "fixClaimedAt": null, "fixClaimedById": null, "dueAt": "2026-11-17T22:01:00Z",
  "reviewStatus": "approved", "discoveredBy": "tool",
  "analyzeStatus": "not_analyzed", "analyzeResult": null,
  "tool": { "id": "...", "name": "nuclei", "type": "connector", "...": "..." },
  "asset": { "id": "...(host asset id)", "value": "app.example.com", "targetId": "5a4c...", "isPrimary": false, "isEnabled": true },
  "sources": [ { "kind": "tool", "toolName": "nuclei" } ],
  "dismissal": null, "openIssue": null,
  "filePath": null, "lineStart": null, "lineEnd": null, "commit": null,
  "packageName": null, "installedVersion": null, "fixedVersion": null
}
```

Field provenance for nuclei, verified through the nuclei connector `adapter.go` and the worker `findingToVulnerability`:

| OASM field | nuclei source |
|---|---|
| `name` | `info.name` (falls back to template-id) |
| `severity` | `info.severity` (unknown maps to `info`) |
| `description` | `info.description` |
| `solution` | `info.remediation` (this is the remediation field) |
| `affectedUrl` | `matched-at` |
| `host` | `host` |
| `ipAddress` | `ip` |
| `tags`, `references`, `authors` | `info.*` |
| `cveId`, `cweId`, `cvssScore`, `cvssMetric`, `epssScore` | `info.classification.*` |

Not populated by the nuclei connector:

- `extractedResults` / `extractorName`
- request/response evidence
- template-id as its own field

`sources[].evidence` in the detail view is filled only for AI or manual sources.

Lifecycle:

- `detectionStatus` moves `new` → `active` (seen again by a later run) → `fixed` (a covering scan with the same scope no longer reports it, after `autoCloseMissedScans`) → `resurfaced`.
- "Open" means approved, `detectionStatus` in (new, active, resurfaced), and no unexpired dismissal.
- Auto-close only happens when the **same** tool, asset, service, inputs and config scan again.

**Dedup key**: `fingerprint = md5("<name>-<assetId>-<toolId>")` for host findings. Consequences:

- One row per template name per host per tool. The same template matching on several ports or URLs of one host collapses into **one** finding, and `affectedUrl` shows the last match.
- The vulnerability `id` is stable across re-scans, because re-detection is an upsert on the fingerprint.
- Re-detection refreshes `updatedAt`, `lastSeenDate` and the scanner fields. It never resets `firstDetectedDate` or the triage state.

### 5.7 Statistics and dashboard

All `GET`, require membership, and take `X-Workspace-Id`. Counts use the "open" definition.

| Path | Response |
|---|---|
| `/api/statistic` | `{assets, targets, vuls, criticalVuls, highVuls, mediumVuls, lowVuls, infoVuls, techs, ports, services, score}` (`score` = security score) |
| `/api/statistic/timeline` | `{data: Statistic[] (daily snapshots, last 3 months), total}` |
| `/api/statistic/issues-timeline` | `{data:[{vuls, createdAt}], total}` |
| `/api/statistic/top-assets-vulnerabilities` | top 10 assets by vulnerability count |
| `/api/statistic/top-ports` | `{totalPorts, nonstandardPorts, ports:[{port,count,isStandard}]}` |
| `/api/statistic/top-technologies`, `/top-tags-assets`, `/asset-locations` | top-N lists and geo |
| `/api/statistic/tls` | `{alreadyExpired, expireInAMonth, expireIn3Months, wontExpireAnytimeSoon, newCertificatesDiscovered}` |
| `/api/targets/summary`, `/api/targets/{id}/overview` | per-workspace and per-target dashboards (§5.3) |

### 5.8 Issues (lightweight ticketing inside OASM)

- `GET /api/issues`
  - filters: `status[]` (`open|in_progress|resolved|closed`), `type[]` (`vulnerability_remediation|task|asset_review|scan_failure`), `priority[]` (`p1..p4`), `assigneeId`, `mine`, `overdue`, `resourceType`+`resourceId`
  - `sortBy` is one of `updatedAt|createdAt|dueAt|priority|no`
- `POST /api/issues`, `GET|PATCH|DELETE /api/issues/{id}`, `PATCH /api/issues/{id}/status`
- `POST /api/issues/{id}/links`, `DELETE /api/issues/{id}/links/{linkId}`
- `GET|POST /api/issues/{issueId}/comments`
- Issue rules can auto-create issues from `vulnerability.detected`:
  - `GET|POST /api/issues/rules`
  - `POST /api/issues/rules/defaults`
  - `PATCH|DELETE /api/issues/rules/{id}`

These are optional for MC-Sec, which would normally keep ticketing in WHMCS.

### 5.9 Projects (asset subsets with their own pipelines and schedules)

`POST /api/projects` (`project.write`):

```json
{
  "name": "Client 123 – web",            "hexColor?": "#78716C", "description?": "...",
  "hostIds?": ["<assets.id>"],
  "scopeRules?": [ { "mode": "include", "type": "target", "value": "<target uuid>" },
                   { "mode": "include", "type": "hostname", "value": "*.example.com" },
                   { "mode": "exclude", "type": "cidr", "value": "203.0.113.0/28" } ],
  "autoAddAssets?": true,
  "template?": "vulnerability_scan_basic.yaml",
  "tools?": [ { "toolId": "<nuclei tool id>", "config?": {}, "configProfileId?": "...", "category?": "vulnerabilities", "input?": ["web","host"], "stage?": 1 } ],
  "workflowName?": "Weekly nuclei",
  "on?": { "schedule": [ { "cron": "0 2 * * 1", "enabled": true } ],
           "events": [ { "event": "project.assets.added", "windowMinutes": 10, "maxAssets": 200 } ] },
  "runNow?": true
}
```

The response is a `Project` (with `projectWorkflows[].triggers[]`).

Other routes:

- `GET /api/projects`, `GET /api/projects/{id}`, `/overview`, `/assets`, `/runs`, `/vulnerabilities`, `/vulnerabilities/{vulnerabilityId}/timeline`
- `PUT /api/projects/{id}/scope-rules`
- `POST /api/projects/{id}/workflows/{bindingId}/run` (manual run)
- triggers CRUD
- `POST /api/projects/{id}/archive` / `unarchive`

Notes:

- **This is the only place where a cron-scheduled vulnerability scan exists natively.** Workspace-level workflows support only `on.target` triggers. `on.schedule` is honoured for project workflows only.
- Cron triggers fire in UTC.
- Event triggers fire on `project.assets.added` (new assets matched the scope), `project.run.completed` and `vulnerability.detected` (default severity filter critical/high). Chain depth is capped at 3.

### 5.10 Workflows, tools and workers

Workflows:

- `GET /api/workflows/templates` returns template file names.
- `GET /api/workflows?name=`, `GET|PATCH|DELETE /api/workflows/{id}` (`workflow.read/write`). An unknown id returns **500**, not 404.
- `POST /api/workflows` with `{"name","content":{"name","on":{"target":["domain.create"]},"jobs":{"<id>":{"name","run":"<tool>","needs":[],"config":{},"input":[]}}},"filePath?"}`.
- The default template rows are **overwritten on every server boot**. Don't edit them. A target event runs only the **first** matching workflow of the workspace (`getOne()`), so adding a second workflow on `domain.create` is not reliable.

Default workflows created in every workspace (`core-api/src/modules/workflows/templates/*.yaml`):

| File (run `workflowName`) | Trigger | Steps |
|---|---|---|
| `domain_discovery.yaml` ("Domain discovery") | `domain.create`, `domain.re-scan` | subfinder (+dnsx) → naabu → httpx → screenshot |
| `ip_address_discovery.yaml` ("Ip address discovery") | `ip.create`, `ip.re-scan`, `cidr.create`, `cidr.re-scan` | naabu → httpx → screenshot |
| `vulnerability_scan_basic.yaml` ("Vulnerability scan basic") | none (API `POST /vulnerabilities/scan`) | nuclei, `input:[web,host]`, config `severity:[info..critical], interactsh:true, concurrency:25, rateLimit:150, followRedirects:false` |
| `url_discovery.yaml` ("Url discovery") | none (API `POST /assets/url/discover`) | gau (wayback, commoncrawl, otx, urlscan) |
| `repository_scan.yaml` ("Repository scan") | `git_org.synced` | gitleaks, trivy (vuln, misconfig) in parallel |

Tools:

- `GET /api/tools` and `GET /api/tools/installed?category=` (`workspace.read`) return `Tool{id,name,type:built_in|connector|provider,categories[],isInstalled,isReady,hasConfigProfile,availableWorkersCount,...}`.
- `POST /api/tools/install` `{"toolId"}` and `POST /api/tools/uninstall` (`workspace.write`).
- Config profiles (credentials for commercial scanners and similar): `GET|POST /api/tools/{toolId}/config-profiles`, `PATCH|DELETE …/{id}`, `POST …/{id}/set-default`, `GET /api/tools/{id}/schema`.

Built-in tools (run inside the worker, always "installed"):

| Tool | Category | Command (abridged) |
|---|---|---|
| `subfinder` 2.8.0 | subdomains (DOMAIN) | `(echo {{value}} && subfinder -duc -d {{value}}) \| dnsx -a -aaaa -cname -mx -ns -soa -txt -resp` |
| `naabu` 2.3.5 | ports_scanner | `naabu -host {{value}} -silent` (naabu's default top ports) |
| `httpx` 1.7.1 | http_probe | `httpx -status-code -favicon -asn -title -web-server -irr -tech-detect -ip -cname -location -tls-grab -cdn -probe -json -follow-redirects -timeout 10 -threads 100` |
| `screenshot` 1.0.0 | screenshot | go-rod headless browser |

Connector tools from `core-api/resources/connectors/manifest.json` run as Docker containers by a worker in `node` run mode:

| Category | Connectors |
|---|---|
| vulnerabilities (host/web) | **nuclei**, nikto, zap, wpscan, acunetix (commercial, needs API key), nessus (commercial, needs credentials) |
| ports_scanner | nmap, rustscan |
| url_discovery | gau, katana, dirsearch, ffuf, arjun |
| repository (GIT_ORG) | gitleaks (secrets), trivy (dependencies/IaC) |

Workers:

- `GET /api/workers?scope=cloud|workspace&runMode=cli|node` (`worker.read`). Non-admins only see `scope=workspace`.
- `GET /api/workers/{id}`.
- A **cloud** worker (built-in type, joined with `OASM_CLOUD_APIKEY`) serves all workspaces. A **workspace** worker serves only its workspace.
- Connector jobs (nuclei, …) are claimed only by workers whose `runMode === 'node'` and that have Docker access. Without such a worker, `POST /vulnerabilities/scan` queues jobs that stay `pending` forever.

### 5.11 Notifications, live events, outbound webhooks

In-app notifications (per user, not per workspace):

- `GET /api/notifications?cursor=&limit=` (keyset) → `{data:[{id,status:sent|unread|read,createdAt,message,url,workspaceId?,ref?,refId?}], nextCursor?}`
- `GET /api/notifications/unread-count`
- `PATCH /api/notifications/mark-read|mark-unread|{id}/read|{id}/unread`
- `DELETE /api/notifications/{id}|by-ref?ref=&refId=`

Notification types:

- `ASSET_NEW_DETECT`
- `SCAN_INCOMPLETE`
- `NEW_VULNERABILITY_FOUND`
- `NEW_URL_FOUND`
- `WORKSPACE_INVITATION`
- `WORKSPACE_CREATED`
- `VULNERABILITY_ANALYSIS_COMPLETED`

Live events (SSE):

- `GET /api/events/stream` with a session cookie and `X-Workspace-Id`.
- Each event is JSON `{id, type, time, resourceType, resourceId}`, with a periodic `ping`.
- It is long-lived and not well suited to PHP cron. Prefer webhooks or polling.

**Outbound webhook integration** (recommended push channel; verified, source):

```bash
POST /api/integrations          (permission integration.write, X-Workspace-Id)
{
  "name": "MC-Sec WHMCS",
  "appType": "webhook",
  "category": "NOTIFICATION",
  "config": {
    "app_type": "webhook", "category": "NOTIFICATION",
    "url": "https://whmcs.example/modules/servers/mcsec/oasm-hook.php?k=<random-per-workspace-secret>",
    "critical": true, "high": true, "medium": true, "low": true, "info": false,
    "NEW_VULNERABILITY_FOUND": true, "ASSET_NEW_DETECT": true, "SCAN_INCOMPLETE": true, "NEW_URL_FOUND": false
  }
}
```

- The config JSON Schema has `additionalProperties:false`, with keys `app_type`, `category`, `url`, the lowercase severity toggles (defaults: critical and high true, the rest false) and the notification-type toggles (default true). Whether `app_type`/`category` must be repeated inside `config` is UNVERIFIED; they are schema `const`s.
- `POST /api/integrations/{id}/test` sends a real test message.
- Delivery: OASM POSTs JSON. There is **no HMAC signature and no custom headers** (the schema does not allow them), so authenticate the receiver with an unguessable URL token and an IP allowlist.
- Delivery is best effort: there are no retries per endpoint, and a 5xx from the receiver is only logged. Dedupe on `id`.

```json
{
  "id": "<eventId — idempotency key>", "type": "vulnerability.detected",
  "workspaceId": "...", "occurredAt": "...", "outcome": "success", "actor": "...",
  "resourceType": "vulnerability", "resourceId": "...", "changes": null, "metadata": {},
  "payload": { "jobId": "...", "targetId": "...", "assetId": "...", "assetValue": "app.example.com",
               "vulnerabilities": [ { "id": "...", "name": "...", "severity": "high", "cveId": ["..."],
                                      "cvssScore": 9.8, "host": "...", "ipAddress": "...", "affectedUrl": "..." } ] },
  "sentAt": "..."
}
```

Pushed event types:

| Event | When / payload |
|---|---|
| `vulnerability.detected` | **new** findings per job, filtered by the severity toggles |
| `vulnerability.dismissed`, `vulnerability.status.updated` | triage changes |
| `workflow.run.completed` | **only for discovery runs** (domain/IP discovery). `resourceId` is the run id. `outcome` is `failure` when steps failed, were blocked or were cancelled. Payload: `{targetId, targetValue, hosts, ports, services, techs, failedSteps[], blockedSteps[], cancelledSteps[], newHosts[], newHostsTotal}` |
| `workflow.run.failed`, `integration.sync.failed`, `integration.ticket.created` | |
| `asset.url.discovered` | URL discovery results |

Nuclei-run completion is **not** pushed. Detect it by polling (§6.3).

Other integrations:

- Notification: Slack, Discord, Telegram
- Ticketing: Jira (schema only, no connector)
- Cloud asset sync: AWS, Cloudflare, Vercel
- Source code: GitHub, GitLab, used for GIT_ORG targets
- Discover them with `GET /api/integrations/schemas`.

### 5.12 Search

`GET /api/search?value=<term>&severity[]=&isSaveHistory=false` → `{data:{assets[], targets[], vulnerabilities[]}, total, page, limit, …}`. History routes: `GET|DELETE /api/search/histories`, `DELETE /api/search/histories/{id}`.

### 5.13 Reports (PDF)

- `POST /api/reports/generate/summary`
- `POST /api/reports/generate/vulnerability` with `{"startDate?","endDate?","targetIds?":[],"vulnIds?":[],"minSeverity?":"CRITICAL|HIGH|MEDIUM|LOW|INFO"}` → `{"message":...}`. Generation is asynchronous (UNVERIFIED).
- `GET /api/reports?type=SUMMARY|VULNERABILITY` → `{id, fileName, type, createdAt, downloadUrl (presigned, 48 h), downloadExpiresIn}`.
- `GET /api/reports/preview/summary|vulnerability`, `DELETE /api/reports/{id}`.

These could serve as customer-downloadable PDFs, but branding is OASM's. MC-Sec will probably render its own.

### 5.14 Other modules (not needed for v1)

| Module | Paths |
|---|---|
| Agents / AI Studio | `/api/agents/*` (LLM configs, conversations, skills, MCP client configs) |
| Templates | `/api/templates` (custom nuclei YAML, `POST /templates/run`) |
| Internal networks | `/api/internal-networks` |
| Providers | `/api/providers` |
| Artifacts / files | `/api/artifacts`, `/api/artifact-folders` |
| Storage presign | `/api/storage/*` |
| Comments | `/api/comments/{id}` |
| System configs (admin) | `/api/admin/system-configs*` |

### 5.15 MCP server (read-only, per workspace)

- Transport: legacy MCP **SSE**.
  1. `GET /api/mcp` with header `x-oasm-api-key: <workspace key>` opens an event stream. The first event (`endpoint`) gives `/api/mcp/message?sessionId=<id>`.
  2. JSON-RPC requests are POSTed there with the same header.
  3. Responses arrive on the SSE stream.
- Sessions are in memory per core-api process: TTL 30 min, at most 100 sessions.
- Tools exposed (all read-only):
  - `enumerate_assets`, `discover_vulnerabilities`, `retrieve_targets`, `gather_statistics`
  - `inspect_asset`, `examine_target_assets`, `investigate_vulnerability`
  - `list_network_ports`, `fingerprint_technologies`, `verify_tls_settings`
  - `enumerate_open_issues`, `inspect_issue`
  - `list_active_workers`, `review_jobs`
  - `list_projects`, `inspect_project`, `list_project_assets`, `list_project_runs`, `read_project_file`
  - `list_workflow_templates`, `list_pipeline_tools`
- Usefulness for MC-Sec: it gives credential-less, per-workspace read access, for example to an AI assistant in the client area. It **cannot** create targets or start scans. For PHP back-end polling, REST with a session is simpler.

---

## 6. Scan lifecycle: trigger, completion, results

### 6.1 What starts what

| Action | OASM behaviour |
|---|---|
| `POST /targets/bulk` (DOMAIN) | emits `target.domain.create`, which starts a **Domain discovery** run (subfinder+dnsx → naabu → httpx → screenshot) |
| `POST /targets/bulk` (IP/CIDR) | **Ip address discovery** run (naabu → httpx → screenshot) |
| `POST /targets/{id}/re-scan` or the target `scanSchedule` firing | the same discovery workflow again (`jobRunType` manual or scheduled); increments `reScanCount`, sets `lastDiscoveredAt` |
| `POST /vulnerabilities/scan {targetIds}` | **one** run of nuclei over every live web service (from httpx) and host of those targets. Run discovery first, or nuclei will only see the bare target. |
| `POST /assets/url/discover {targetIds}` | gau URL discovery on hosts httpx confirmed live |
| Project workflow (cron, event or `/run`) | any pipeline of built-in and connector tools over the project's assets |

### 6.2 Correlating a trigger with its run

None of the trigger calls return a run id; only `POST /jobs-registry/histories/{id}/re-run` does. Correlate as follows:

1. Record `t0` (server clock skew allowance of about 1 min) before the trigger.
2. Poll `GET /api/targets/{id}/runs?limit=10` (newest first). Pick runs with `createdAt >= t0` and the expected `workflowName`: "Domain discovery", "Ip address discovery", "Vulnerability scan basic", "Url discovery" or "Repository scan". Template names are derived from file names: `domain_discovery.yaml` becomes "Domain discovery".
3. Store the run `id` (jobHistoryId) for detail queries: `GET /api/jobs-registry/histories/{id}` returns `steps[]`, `progress`, `etaSeconds` and `failureReason`.

### 6.3 Detecting completion

- A run is finished when `isCompleted == true`, as reported by `/targets/{id}/runs`, or when `activeJobsCount == 0 && stepsDone == stepsTotal` in the history detail.
- `GET /api/targets/{id}/runs?active=true` returning an empty `data` means nothing is running on that target (only runs from the last 7 days count).
- Final status is `status` plus `jobsFailed`. Because failed jobs are retried up to 4 times, wait for `isCompleted` and don't react to a transient `failed`.
- **Always apply a timeout.** With no suitable worker online, jobs stay `pending` indefinitely. Example timeouts: 2 h for discovery, 6 h for nuclei on large scopes (tune after measuring).
- Discovery completion is also pushed by the webhook `workflow.run.completed`.
- For nuclei runs started through `POST /vulnerabilities/scan`, whether `isCompleted` is set reliably is **UNVERIFIED**. That run is created through `createNewJob` with the workflow attached, then advanced by the run engine. Fall back to "no pending/in_progress jobs in the run" (`GET /api/jobs-registry?jobHistoryId=<id>&jobStatus=pending` and `…=in_progress`, both with `total == 0`).

### 6.4 Pulling results

| Data | Endpoint |
|---|---|
| Hosts / subdomains | `GET /api/assets/host?targetIds=<t>&limit=100&page=n` |
| Services (host:port, HTTP fingerprint, screenshot) | `GET /api/assets?targetIds=<t>&limit=100&sortBy=createdAt&sortOrder=ASC` |
| Ports | `GET /api/assets/port?targetIds=<t>` |
| IPs + geo/ASN | `GET /api/assets/ip?targetIds=<t>` |
| Technologies | `GET /api/assets/tech?targetIds=<t>` |
| TLS certificates | `GET /api/assets/tls?targetIds=<t>` |
| Vulnerabilities | `GET /api/vulnerabilities?targetIds=<t>&status=all&limit=100&sortBy=updatedAt&sortOrder=DESC` |
| Fixed findings | `GET /api/vulnerabilities?targetIds=<t>&status=fixed` |
| Per-target dashboard | `GET /api/targets/{id}/overview` |
| Workspace dashboard | `GET /api/statistic`, `GET /api/vulnerabilities/statistics` |

---

## 7. Enum cheat-sheet

| Enum | Values |
|---|---|
| TargetType | `DOMAIN`, `IP`, `CIDR`, `GIT_ORG` |
| TargetSource | `MANUAL`, `cloudflare`, `aws`, `vercel`, `github`, `gitlab`, `INTERNAL_NETWORK` |
| JobStatus | `pending`, `in_progress`, `completed`, `failed`, `cancelled`, `skipped` |
| Step status | `pending`, `dispatched`, `done`, `failed`, `skipped` |
| JobRunType | `manual`, `scheduled`, `event` |
| CronSchedule | `disabled`, `0 0 * * *`, `0 0 */3 * *`, `0 0 * * 0`, `0 0 */14 * *`, `0 0 1 * *` |
| Severity | `info`, `low`, `medium`, `high`, `critical` |
| VulnerabilityStatus (filter) | `open`, `new`, `active`, `resurfaced`, `fixed`, `dismissed`, `pending_review`, `rejected`, `all` |
| DetectionStatus | `new`, `active`, `fixed`, `resurfaced` |
| ReviewStatus | `pending_review`, `approved`, `rejected` |
| DismissReason | `false_positive`, `used_in_test`, `wont_fix`, `risk_accepted` |
| ToolCategory | `subdomains`, `http_probe`, `ports_scanner`, `vulnerabilities`, `screenshot`, `url_discovery` |
| DataKind | `target`, `host`, `service`, `web`, `url`, `repository`, `vulnerability` |
| TargetChangeKind | `asset`, `service`, `vulnerability`, `fixed` |
| IssueStatus / IssuePriority | `open`, `in_progress`, `resolved`, `closed` / `p1`–`p4` |
| Role | `admin`, `user`, `bot` |

---

## 8. Integration notes for MC-Sec

### 8.1 Customer isolation: recommendation

**Use one OASM workspace per WHMCS service (or per client), owned by a dedicated OASM service user. Do not put several customers in one shared workspace.**

Why, from the code:

1. Tenant isolation in OASM is the **workspace**, and it is enforced on every query (`target.workspaceId`). There is no finer tenant boundary. Projects are only saved asset selections. Statistics, the security score, `/targets/summary`, notifications, webhooks, settings (`isAssetsDiscovery`), the MCP API key and the audit log are all per workspace.
2. Target values are unique per workspace. In a shared workspace, two customers could not both register `example.com`, and one customer's re-scan would refresh the other's data.
3. Deleting a WHMCS service maps cleanly to `DELETE /api/workspaces/{id}`, which cascades everything. Suspension maps to an archive or user ban.
4. Constraints that shape the design:
   - **Target create and delete are owner-only**, and **a user can own at most 5 workspaces** (hard-coded). One global service account can therefore serve at most 5 customers.
   - **Option A (recommended): one OASM user per WHMCS client.** Email something like `oasm+c<clientId>@mc-sec.example`. Generate a random password and store it encrypted in a module table (`mod_mcsec_oasm_account`: whmcs_client_id, oasm_user_id, email, enc_password, session_cookie, cookie_updated_at, workspace_ids). That user owns up to 5 workspaces (one per WHMCS service). Create users with an MC-Sec **admin** session via `POST /api/auth/admin/create-user`. Suspend with `ban-user` and resume with `unban-user`. Users cannot be deleted, so ban them on termination after deleting their workspaces.
   - **Option B: a pool of service owners** (`svc-001` … each owning ≤5 workspaces). Fewer credentials, but suspension must use workspace archive instead of a user ban, and one leaked credential exposes 5 customers.
   - **Option C: impersonation.** Store only the platform-admin credential and call `POST /api/auth/admin/impersonate-user` to act as the owner per operation. This is possible but adds a session swap per call and is UNVERIFIED for long-running use (1 h impersonation sessions). Treat it as a recovery path, not the main flow.
   - **Do not** give customers direct OASM console access in v1. Invites only work for existing OASM accounts, and the console exposes AI Studio, integrations and everything else.
5. Worker sharing: a **cloud/global** worker serves all workspaces, so per-customer workspaces do not need per-customer workers. Workspace-scoped workers exist if a customer needs a dedicated scanner, for example for internal networks.

### 8.2 Mapping MC-Sec products to OASM capabilities

These are suggested mappings; adapt them to the actual MC-Sec catalogue.

| MC-Sec product idea | OASM mechanism | Notes |
|---|---|---|
| External Attack Surface Discovery | DOMAIN/IP/CIDR targets → discovery workflows (subfinder+dnsx, naabu, httpx, screenshot) | Default on create. The `isAssetsDiscovery` workspace config switches subdomain enumeration on or off. |
| Exposure / port monitoring | `scanSchedule` on targets (daily, every 3 days, weekly, bi-weekly, monthly) + `/api/assets/port`, `/api/statistic/top-ports` | Schedules re-run discovery only. |
| Vulnerability scanning (basic) | `POST /api/vulnerabilities/scan` (nuclei, all severities) | Needs a node-mode worker with Docker. Run discovery first. `interactsh: true` sends out-of-band probes to public interactsh servers. Review this for compliance, or change the config via a project pipeline. |
| Scheduled vulnerability scanning | (a) WHMCS cron calls `POST /vulnerabilities/scan`; or (b) a project per service with a nuclei pipeline and `on.schedule` cron | (a) is simpler and keeps scheduling and billing logic in WHMCS. (b) is OASM-native. |
| Web application scanning | Project pipeline with `zap` / `nikto` / `wpscan` connectors | Connector config profiles may be needed. Heavier and more intrusive, so require explicit customer consent. |
| SSL/TLS monitoring | httpx `-tls-grab` data → `/api/assets/tls`, `/api/statistic/tls` (expiry buckets) | Free with discovery. |
| Technology inventory | `/api/assets/tech`, `/api/statistic/top-technologies` | Wappalyzer-style data from httpx. |
| Website screenshots | `screenshotPath` presigned URLs in `/api/assets` | Proxy or cache the images in WHMCS. The URLs expire in 48 h and the storage host may be internal. |
| Leaked URL / historical endpoints | `POST /api/assets/url/discover` (gau) → `/api/assets/url` | |
| Code / secret scanning | GIT_ORG targets + GitHub/GitLab integration → gitleaks + trivy | Needs customer tokens. Probably later. |
| Commercial scanner add-ons | acunetix / nessus connectors with config profiles | MC-Sec supplies the licences. |
| PDF reports | `/api/reports/generate/*` | OASM-branded. MC-Sec will probably render its own. |

### 8.3 Recommended call sequence (per WHMCS service)

1. **CreateAccount**:
   1. Ensure the OASM user exists (admin session: `POST /api/auth/admin/create-user`).
   2. Sign in as that user and store the cookie.
   3. `POST /api/workspaces` and store `workspaceId`.
   4. Optionally `PATCH /api/workspaces/configs`.
   5. Optionally register a webhook integration (§5.11).
   6. `POST /api/targets/bulk` with the customer's verified domains and IPs. **Verify domain ownership in WHMCS first.** OASM performs no ownership verification, and passive subdomain discovery plus active port and nuclei scans will hit everything found.
   7. Optionally `PATCH /api/targets/{id}` with `scanSchedule`.
2. **Scan now** (client-area button): `POST /api/targets/{id}/re-scan`, then poll, then `POST /api/vulnerabilities/scan`, then poll.
3. **Cron** (every 5–15 min): for each active service, poll active runs and pull deltas (§8.4). Chain nuclei after a discovery run completes when the product includes vulnerability scanning.
4. **Suspend**: set `scanSchedule=disabled` on every target. Then either `PATCH /api/workspaces/{id}/archived {"isArchived":true}` (Option B) or `ban-user` (Option A). Whether archiving stops scheduled discovery is **UNVERIFIED**, so disable schedules explicitly.
5. **Unsuspend**: reverse the suspend steps.
6. **Terminate**: `DELETE /api/workspaces/{id}` (cascade). Once the user owns no workspace, ban it.
7. **Change package** (e.g. more targets or scan frequency): enforce target count limits in WHMCS. OASM has no per-workspace quota for targets; only storage has a quota. Adjust `scanSchedule`.

### 8.4 Incremental pulls (diff since last sync)

Keep a local mirror keyed by OASM ids. Finding ids are stable across re-scans thanks to the fingerprint upsert.

- **Vulnerabilities**: call `GET /api/vulnerabilities?targetIds=…&status=all&sortBy=updatedAt&sortOrder=DESC&limit=100`. Page until `updatedAt < last_watermark` (minus overlap), then upsert. Re-detection bumps `updatedAt` and `lastSeenDate`.
  - New: `firstDetectedDate > watermark`, or webhook `vulnerability.detected`.
  - Fixed: `status=fixed`, compared on `fixedAt`. Raw lifecycle UPDATEs may not bump `updatedAt` (UNVERIFIED), so query fixed separately.
  - Dismissed: `status=dismissed`.
  - Alternative per target: `GET /api/targets/{id}/changes?kind=vulnerability` and `kind=fixed`, newest first. Stop at the watermark `at`.
- **Assets/services**: `GET /api/targets/{id}/changes?kind=asset|service` (newest first) gives additions. `GET /api/assets?targetIds=…&isNew=true` returns rows found by the latest finished run. Removals are **not** tracked: OASM never deletes assets on re-scan. Assets only go away with their target, and there is no "last seen" for services. "Disappeared" detection needs a full snapshot diff in WHMCS (full pull after each finished run).
- **Run-scoped**: `lastSeenJobHistoryId` and `fixedByJobHistoryId` on findings, and `jobHistoryId` on `httpResponses`, tie data to a specific run.
- Use `limit=100` (the maximum). Paginate on a stable order: assets append `asset_service.id` as a tie-breaker; for vulnerabilities, sort by a timestamp. Without a stable order, offset paging can skip or repeat rows while scans write.

### 8.5 Rate limits, performance and other pitfalls

- **Sessions**: sign in rarely (better-auth limit of 100 req/min per IP on `/api/auth/*`, possibly one shared bucket behind the CDN). Cache the cookie for up to 7 days and replace it whenever a response sends `Set-Cookie`. On 401, sign in once and retry once.
- **`wid` cookie trap**: `GET /api/workspaces` sets `wid=<some workspace>`. If your cookie jar sends it back and you forget `X-Workspace-Id`, requests silently target that workspace. Never persist `wid`; always send the header.
- **Owner-only and 5-workspace limit**: see §8.1.
- **Duplicates**: `POST /targets/bulk` fails the whole request with 400 if **any** value already exists. Pre-check with `GET /api/targets?value=` or create targets one per request.
- **CIDR explosion**: a /24 creates 256 assets and hundreds of jobs. Cap CIDR sizes in WHMCS.
- **Private IPs and IPv6** are rejected for manual targets.
- **Silent field stripping**: unknown body fields are dropped without error (`whitelist: true`).
- **201 vs 200**: see §2.
- **Spec inaccuracies** in the OpenAPI document:
  - target list `status` enum
  - `skipped` in bulk results
  - missing `X-Workspace-Id` on several routes
  - `bearerAuth` advertised but not supported
  - POST status codes
- **Unknown ids**: `GET /targets/{id}` returns 200 with an empty body, and the workflow routes return 500.
- **Finding granularity**: one finding per template per host per tool (`affectedUrl` is the last match). Nuclei findings carry no request/response evidence or extracted results in OASM.
- **Connector readiness**: nuclei and other connectors need a `node`-mode worker with the Docker socket, and the first run pulls images. `GET /api/tools/installed` (`isReady`, `availableWorkersCount`) and admin `GET /api/workers?scope=cloud` tell you whether scans can run.
- **Out-of-scope scanning risk**: subdomain discovery (`isAssetsDiscovery=true`) followed by naabu, httpx and nuclei will actively probe every discovered host, including third-party SaaS CNAME targets. For strict-scope products, set `isAssetsDiscovery=false`, or `isAutoEnableAssetAfterDiscovered=false` and enable approved hosts with `POST /assets/toggle`.
- **Template workflows** are reset at every boot; don't customise them. Use projects for custom pipelines.
- **Data retention**: terminal jobs are pruned after 180 days. Findings, assets and runs persist. The event stream keeps 7 days, the audit log 90 days.
- **Secrets at rest**: workspace API keys and worker tokens are stored in plaintext in OASM's DB. Rotate keys if the DB is exposed.
- **License**: OASM is GPL-3.0-only. Talking to it over HTTP from a separate WHMCS module does not make the module a derivative work. Modifying and redistributing OASM itself would trigger GPL obligations.

### 8.6 Open questions to verify with authenticated access

1. Is a **cloud/global worker** online on staging, in `node` run mode with Docker, so that nuclei and other connector jobs actually run? Check with admin `GET /api/workers?scope=cloud`, plus `GET /api/tools/installed` (`isReady`, `availableWorkersCount`) in a test workspace.
2. Exact **session cookie name** on staging (`__Secure-session` vs `session`) and whether `TRUSTED_PROXIES` / `BASE_URL` are set behind MizbanCloud.
3. Does the MizbanCloud edge apply its own rate limiting, bot protection or WAF rules to API calls? Test sustained polling at about 1 req/s.
4. Does the run created by `POST /api/vulnerabilities/scan` reach `isCompleted=true`? Measure typical durations: discovery per domain, and nuclei per 10/100 services.
5. Are presigned **screenshot/report URLs** reachable from the WHMCS server and from the internet? What is `STORAGE_URL_BASE`?
6. Does **archiving** a workspace stop scheduled re-scans and job claims? Do banned owners' schedules keep running? (Expected: yes, schedules are user-independent.)
7. **Webhook integration**: exact accepted `config` keys (whether `app_type`/`category` are required inside `config`), delivery latency, behaviour on receiver failure.
8. Exact JSON of `BulkTargetResultDto.created[]` and of the `GET /api/targets` row (which optional fields are filled).
9. Can `/api/auth/admin/create-user` users sign in immediately without email verification on staging? Is SMTP configured?
10. Does a cookie-bearing POST to `/api/auth/*` require an `Origin` header in practice (better-auth 1.6 CSRF behaviour)?
11. Should nuclei's `interactsh` (public OAST) stay enabled for MC-Sec customers? Which severities should the basic product run? The built-in scan uses all severities including `info`.
12. Is there an upstream plan to make `LIMIT_WORKSPACE_CREATE` configurable? A small patch on our fork would remove the need for one user per 5 customers.
13. Behaviour and runtime of a /24 CIDR target on the staging worker capacity.

---

## 9. Source pointers (upstream, tag v0.12.1)

| Area | Paths |
|---|---|
| Auth | `core-api/src/modules/auth/auth.ts`, `core-api/src/common/guards/auth.guard.ts`, `core-api/src/common/constants/app.constants.ts` |
| Workspace scoping | `core-api/src/common/decorators/workspace-id.decorator.ts`, `common/guards/workspace-permission.guard.ts`, `modules/workspaces/*` (+ `AGENTS.md`) |
| Targets | `modules/targets/targets.service.ts`, `targets.controller.ts`, `target-overview.service.ts` |
| Assets | `modules/assets/assets.service.ts` |
| Vulnerabilities | `modules/vulnerabilities/*`; ingest and fingerprint in `modules/data-adapter/data-adapter.service.ts` |
| Runs and jobs | `modules/jobs-registry/*`; trigger routing in `modules/workflows/trigger-workflow.service.ts`; templates in `modules/workflows/templates/*.yaml` |
| Tools | `modules/tools/tools-provider/built-in-tools.ts`; connectors in `core-api/resources/connectors/manifest.json` and repo `oasm-platform/oasm-connectors` (`vulnerabilities/nuclei/adapter.go`) |
| Worker mapping | `worker/internal/worker/job.go` (`findingToVulnerability`) |
| Webhooks | `modules/integrations/connectors/webhook.connector.ts`, `schemas/webhook.schema.ts`, `modules/event-bridge/sinks/integrations/*` |
| MCP | `core-api/src/mcp/*`, `modules/agents/agents.tools.ts` (`MCP_TOOLS`) |
| Every module | an `AGENTS.md` with routes, permissions and gotchas, which is the most accurate prose documentation available |
