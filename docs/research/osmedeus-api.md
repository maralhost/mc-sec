# Osmedeus REST API: developer reference for the MC-Sec WHMCS module

Status: research draft, 2026-11-11.
Scope: the Osmedeus v5 ("Modern Orchestration Engine for Security", Go rewrite) REST API, as the PHP WHMCS module will call it.
Primary source: the `j3ssie/osmedeus` source code on branch `main` at commit `1c8a16c` (2026-11-06), which is the v5.1.2 release line (`internal/core/constants.go` -> `VERSION = "v5.1.2"`). Route availability was also checked against the tags `v5.0.0`, `v5.0.3` and `v5.1.0`.
Secondary sources: the official API notes in the repo (`platform/osmedeus-dashboard/backend-api-docs/*.md`), the generated Swagger file (`docs/api-swagger/swagger.json`), and docs.osmedeus.org. Where those disagree with the source, this document follows the source and lists the differences in section 12.

Labels used:
- **SOURCE**: read directly in the Go source. Treat as exact for v5.1.2.
- **UNVERIFIED**: inferred, or depends on how our server is configured. Each one says what would confirm it.

Companion file: `docs/research/osmedeus-openapi.json` is the Swagger 2.0 document from the repo (`docs/api-swagger/swagger.json`, main/v5.1.2). The server serves this same file at `GET /swagger/doc.json`. It was **not** downloaded from our server, which could not be reached (section 1).

---

## 0. Summary

| Item | Value |
|---|---|
| Product | Osmedeus v5 (Go, Fiber web framework). The v4 API is completely different (section 13). |
| Base URL (ours) | `http://OSMEDEUS_HOST:8811` (non-default port; the v5 default is 8002) |
| API prefix | `/osm/api` |
| Transport | Plain HTTP. v5 has no built-in TLS: `app.Listen(addr)` |
| Auth option 1 | `POST /osm/api/login` with `{"username","password"}`, returns `{"token":"<JWT HS256>"}`. Send `Authorization: Bearer <token>`. Default lifetime 1440 min (24 h). There is no refresh endpoint. |
| Auth option 2 (recommended for WHMCS) | Static API key in header `x-osm-api-key: <server.auth_api_key>`. Enabled by default (`server.enabled_auth_api: true`). |
| Start a scan | `POST /osm/api/runs` with `{"flow":"<name>", "target":"x"}` or `{"flow":"<name>","targets":[...],"concurrency":N}`. Returns `202` with `job_id`, `poll_url`, and `run_uuid` (single target only, v5.0.3+). |
| Poll | `GET /osm/api/jobs/{job_id}` (aggregate) or `GET /osm/api/runs/{run_uuid}`. Run statuses: `pending`, `running`, `completed`, `failed`, `cancelled`. |
| Cancel | `DELETE /osm/api/runs/{run_uuid}` |
| Results | `GET /osm/api/assets?workspace=`, `GET /osm/api/vulnerabilities?workspace=&severity=`, `GET /osm/api/runs/{uuid}/artifacts`, `GET /osm/api/artifacts/{workspace}?artifact_path=<relative>` |
| Results are keyed by | **workspace**, not run. Always set `params.space_name` (section 9.3). |
| Severity values | Taken as-is from nuclei: `critical`, `high`, `medium`, `low`, `info` (and possibly `unknown`). Lower case. |
| Built-in flows | `fast`, `domain-lite`, `domain-standard`, `general`, `domain-extensive`, `domain-list-recon`, `cidr`, `cidr-extensive`, `url` / `web-analysis`, `sast` / `repo` (section 8) |

---

## 1. Version detection and the live probe

### 1.1 Probe performed (2026-11-11)

Only unauthenticated plain GETs were sent (`curl -s -m 15`), with no credentials, to: `/`, `/health`, `/server-info`, `/api/health`, `/swagger/index.html`, `/swagger/doc.json`, `/docs`, `/openapi.json`, `/osm/api/health`. HTTPS on the same port was also tried once on `/`.

Result: **every request timed out at the TCP connect stage** ("Connection timed out after 15005 ms"). Outbound TCP 8811 from our workstation works (a control request to `portquiz.net:8811` returned 200). So the Osmedeus host is filtering our source IP (a firewall or allowlist), or the service is not listening. **The live version could not be fingerprinted.**

### 1.2 How to confirm the version (once reachable from an allowlisted host)

These endpoints need no authentication (SOURCE: `pkg/server/server.go`):

```bash
curl -s http://OSMEDEUS_HOST:8811/health          # {"status":"ok"}  (v5 only)
curl -s http://OSMEDEUS_HOST:8811/server-info     # JSON with "version":"v5.x.y"
curl -sI http://OSMEDEUS_HOST:8811/health         # header  Server: osmedeus v5.1.2 (open-source)
```

`/server-info` (aliases `/status` and `/api/info`) returns:

```json
{
  "message": "Oh dear me, how delightful ... osmedeus is ticking along quite nicely, thank you.",
  "version": "v5.1.2",
  "repo": "https://github.com/j3ssie/osmedeus",
  "author": "@j3ssie",
  "docs": "https://docs.osmedeus.org",
  "license": "open-source",
  "build": "<build time or 'unknown'>",
  "commit": "<git sha or 'unknown'>"
}
```

If instead `GET /ping` answers and `/health` does not, the server is the legacy v4 (section 13).

**UNVERIFIED: our server is v5.** The `/osm/api` path the brief mentions and the `osmedeus` default user both point to v5. A `/server-info` call will confirm it. Routes by version (SOURCE, diff of `server.go` per tag):
- v5.0.0: core API (workflows, runs, jobs, assets, vulns, artifacts, schedules, stats, snapshots, uploads). There is no `run_uuid` in the create-run response and no `/runs/{id}/start|duplicate`.
- v5.0.3: adds `/runs/{id}/duplicate`, `/runs/{id}/start`, `/logout`, `/asset-stats`, cloud, webhook-runs, `/database/*`, and `run_uuid` in the create response.
- v5.1.0 to v5.1.2: add `/orgs*` (multi-tenant grouping). Otherwise identical routes.

---

## 2. Server conventions

### 2.1 Unauthenticated endpoints (SOURCE)

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | `{"status":"ok"}` |
| GET | `/health/ready` | `{"status":"ready"}` |
| GET | `/server-info`, `/status`, `/api/info` | version JSON (see 1.2) |
| GET | `/swagger/*` | Swagger UI. `/swagger/doc.json` is the spec |
| GET | `/metrics` | Prometheus. Present when `server.enable_metrics: true` (default **true**) |
| POST | `/osm/api/login`, `/osm/api/logout` | |
| GET/POST | `/osm/api/webhook-runs/{uuid}/trigger` | only if `server.enable_trigger_via_webhook: true` (default false) |
| GET | `/ws/{workspace_prefix_key}/...` | **Static file server over the whole workspaces directory, with directory listing and no auth.** Protected only by the secrecy of the random 16-character prefix key. |
| GET | `/` (and any non-API path) | embedded web UI (SPA) |

Everything else under `/osm/api/*` requires auth.

### 2.2 Response envelope

- Success responses are usually `{"data": ..., "pagination": {"total","offset","limit"}}`. **Exceptions** (SOURCE): `POST /runs` (flat object), `GET /jobs/{id}` (flat), `GET /stats` (flat `SystemStats`), `GET /workflows/{name}` (raw YAML by default), `GET /workspace-names` (bare JSON array), `GET /workflows/tags` (`{"tags","count"}`), and the file downloads.
- Errors always have the form `{"error": true, "message": "<text>"}` with an HTTP status of 400, 401, 403, 404 or 500.
- Pagination uses `offset` (default 0) and `limit` (default 20; 50 for workflows). **The maximum limit is 10000** on every list endpoint.
- Times are RFC3339 with offset (Go `time.Time`), for example `"2026-11-11T10:00:00.123456+01:00"`. Null times are `null`.
- CORS reflects any Origin and allows credentials. This does not matter for server-side PHP.
- **No rate limiting** middleware exists (SOURCE: only recover, logger, cors and optional metrics/debug middleware).

---

## 3. Authentication (SOURCE: `pkg/server/middleware/auth.go`, `handlers/auth.go`, `internal/config/config.go`)

### 3.1 Login with a JWT

```
POST /osm/api/login
Content-Type: application/json

{"username": "osmedeus", "password": "<password>"}
```

- `200` -> `{"token": "<jwt>"}`. The server also sets a cookie `osmedeus_session=<jwt>` (Path=/, SameSite=Lax, not HttpOnly, not Secure).
- `400` -> `{"error":true,"message":"Invalid request body"}`
- `401` -> `{"error":true,"message":"Invalid credentials"}`
- The body is parsed by Fiber's `BodyParser`, so `application/x-www-form-urlencoded` also works. Use JSON.
- Credentials are a plain map `server.simple_user_map_key: {username: password}` in `~/osmedeus-base/osm-settings.yaml`, overridable by environment variables (`OSM_USERNAME` + `OSM_PASSWORD`, or `OSM_SERVER_SIMPLE_USER_MAP_KEY_<USER>`). The default user is `osmedeus` with a random 12-character password generated on first run. Run `osmedeus config view server.password` on the host to read it.
- The password is compared as plain text, and there is **no lockout or throttling**.

JWT details:
- HS256, signed with `server.jwt.secret_signing_key` (random 64 characters by default).
- Claims: `username`, `exp`, `iat`.
- Lifetime: `server.jwt.expiration_minutes`, **default 1440 (24 h)**. The repo's markdown docs say 60, which is wrong for current source.
- There is **no refresh route**. A `RefreshToken` handler exists but is not wired. Log in again on a 401.
- Send it as `Authorization: Bearer <token>`. The header must be exactly two space-separated parts, with `Bearer` capitalized. The cookie `osmedeus_session` is accepted as a fallback.

`POST /osm/api/logout` -> `{"message":"Logged out"}`. It only clears the cookie, and the JWT stays valid until it expires.

### 3.2 API key (recommended for WHMCS)

```
x-osm-api-key: <server.auth_api_key>
```

- Active when `server.enabled_auth_api: true`. This is **the default** in both `DefaultConfig()` and the example settings file. The key is a random 32-character value written on first run. Read it with `osmedeus config view server.auth_api_key`, or set `OSM_SERVER_AUTH_API_KEY`.
- Middleware `CombinedAuth`: if the header is present and matches exactly (case-sensitive, not empty or whitespace, not `null`/`undefined`/`nil`), the request passes. **Otherwise it falls through to JWT validation.** So a wrong key with no JWT gives `401 {"message":"Missing authorization header or session cookie"}`.
- If `enabled_auth_api: false`, only JWT works.
- `osmedeus serve --no-auth` disables auth entirely, and `/login` then accepts any credentials.

401 messages (SOURCE): `"Missing authorization header or session cookie"` and `"Invalid or expired token"`.

### 3.3 Security notes for our deployment

- v5 speaks **plain HTTP**. Credentials and the API key cross the network unencrypted unless we add a TLS reverse proxy (Caddy or nginx) or a WireGuard tunnel between WHMCS and Osmedeus. Keep the IP allowlist that currently blocks us.
- The API includes endpoints that execute arbitrary code by design: `/functions/eval`, `/workflow-upload`, `/registry-install`, `/settings/*`, `/database/tables/{t}/clear`, `/llm/*`, `/agent/*`, `/cloud/*`. The upstream README says so explicitly. The key is effectively root on the scanner box. Store it encrypted in WHMCS (`encrypt()`/`decrypt()` or the module config password field) and never expose it to client-area templates.

---

## 4. Endpoint reference: what the module needs

All paths below are prefixed with `/osm/api` and need auth. "Body" is JSON unless noted.

### 4.1 Workflows

#### `GET /workflows`: list (indexed in DB)

Query: `source` (`db` default | `filesystem`), `kind` (`flow`|`module`), `search` (name/description LIKE), `tags` (comma list, any match), `offset`, `limit` (default 50). Hidden workflows are excluded.

Response when `source=db` (SOURCE: `database.WorkflowMeta`):
```json
{
  "data": [
    {
      "id": 3,
      "name": "domain-lite",
      "kind": "flow",
      "description": "Quick recon - subdomain discovery and HTTP fingerprinting only",
      "file_path": "/root/osmedeus-base/workflows/domain-lite.yaml",
      "checksum": "<sha256>",
      "tags": ["recon", "domain", "lite"],
      "hidden": false,
      "step_count": 0,
      "module_count": 3,
      "hook_count": 0,
      "params_json": "[{\"Name\":\"enableDnsBruteFocing\",\"Type\":\"\",\"Default\":\"false\",\"Required\":false,\"Generator\":\"\"}]",
      "indexed_at": "...", "created_at": "...", "updated_at": "..."
    }
  ],
  "pagination": {"total": 40, "offset": 0, "limit": 50}
}
```
- `params_json` is a **string** holding a JSON array, with **capitalized keys** (`Name`, `Type`, `Default`, `Required`, `Generator`), because `core.Param` has no json tags. `json_decode` it twice.
- If nothing is indexed yet you get `{"data":[],"count":0,"message":"No workflows indexed. ... POST /osm/api/workflows/refresh ..."}`.

Response when `source=filesystem` (no DB, always fresh):
```json
{
  "data": [
    {"name":"domain-lite","kind":"flow","description":"...","tags":["recon","domain","lite"],
     "file_path":"...","params":[{"name":"enableDnsBruteFocing","default":"false","required":false,"generator":""}],
     "required_params":[],"step_count":0,"module_count":3}
  ],
  "count": 40
}
```
**Recommendation:** use `?source=filesystem` for the admin "sync workflows" screen. It needs no indexing step and gives clean lower-case params.

#### `GET /workflows/{name}`: detail

- Default: **raw YAML** (`Content-Type: text/yaml`).
- `?json=true` gives `{"name","kind","description","file_path","params":[{name,default,required,generator}],"steps":[{index,name,type,command,timeout,pre_condition,step_runner,depends_on?,exports?,parallel_steps?}],"modules":[{index,name,path,depends_on,condition}],"triggers":[{name,on,schedule,enabled}],"dependencies":{"commands":[...],"files":[...]}}`.
- `{name}` is matched against the **file base name** (`domain-lite` -> `domain-lite.yaml`, also `<name>-flow.yaml` / `<name>-module.yaml`), searched recursively under the workflows folder. It is not matched against the YAML `name:` field.
- `404 {"message":"Workflow not found"}`.

#### `GET /workflows/tags`

Returns `{"tags":["recon","domain",...],"count":N}`.

#### `POST /workflows/refresh[?force=true]`

Re-indexes the filesystem into the DB. Returns `{"message":"Workflows indexed successfully","added","updated","removed","errors":[...]}`.

### 4.2 Runs (scans)

#### `POST /runs`: create and start

Request body (SOURCE: `handlers.CreateRunRequest`; every field is optional except as noted):

| Field | Type | Notes |
|---|---|---|
| `flow` | string | Workflow name. **Either `flow` or `module` is required.** `flow` takes precedence. |
| `module` | string | Module name. Passing a flow name in `module` fails ("workflow is not a module"). Passing a module name in `flow` works, because the executor falls back to module execution. |
| `target` | string | Single target |
| `targets` | string[] | Multiple targets. Merged with `target` and `target_file`, trimmed, empty values dropped, de-duplicated (order kept). |
| `target_file` | string | **Server-side path** to a file with one target per line (`#` comments allowed). Usually the `path` returned by `/upload-file`. |
| `params` | object<string,string> | Workflow params. **Values must be strings** (`"true"`, not `true`). See the reserved params below. |
| `concurrency` | int | Parallel targets for a multi-target request. Default 1. |
| `priority` | string | `low`, `normal` (default), `medium` (normalized to `normal`), `high`, `critical`. Stored only. **Not used for scheduling in local mode.** |
| `run_mode` | string | `local` (default), `distributed` (server must run with `--master` plus Redis), `cloud` |
| `timeout` | int (minutes) | Copied to `params.timeout`. **SOURCE: nothing in the executor reads it in API mode, so it is not enforced.** Enforce timeouts ourselves. |
| `runner_type` | string | `host` (default), `docker`, `ssh`. Put into params. |
| `docker_image`, `ssh_host` | string | for `runner_type` |
| `threads_hold` | int | Overrides the thread count from the tactic (see `params.tactic`) |
| `empty_target` | bool | Run without a target |
| `repeat`, `repeat_wait_time` | bool, string | Put into params |
| `heuristics_check` | string | `none`, `basic` (executor default), `advanced`. Affects workspace naming (9.3). |
| `skip_validation` | bool | Disables the shell-metacharacter check (4.2.1). **Do not use.** |
| `schedule`, `schedule_enabled`, `notify_on_complete` | | **Echoed in the response only. No schedule is created** (SOURCE). Use `/schedules`. |
| `cloud_*` | | for `run_mode=cloud`. Not relevant here. |

Reserved or special `params` keys read by the executor (SOURCE: `internal/executor/executor.go`):

| Param | Effect |
|---|---|
| `space_name` | **Workspace name override.** Results are stored under this workspace. Strongly recommended (9.3). |
| `tactic` | `aggressive` (40 threads), `default` (10), `gently` (5). Defaults from `scan_tactic` in the settings. `{{threads}}` drives most tool concurrency. |
| `threads_hold` | numeric override of `{{threads}}` |
| `exclude_modules` | comma list of flow module names to skip (exact match), for example `"recon-spider,scan-content"` |
| `fuzzy_exclude_modules` | comma list of substrings, for example `"vuln,content"` |
| `heuristics_check` | as above |
| `org_uuid` | v5.1+: attribute the run and its workspace data to an org |
| `workspaces_folder` | override the workspaces root (avoid) |
| any workflow param | overrides that param's YAML default, for example `enableDnsBruteFocing`, `enableSYNScan`, `nucleiSeverity`, `rustscanPorts` |

Single-target response, `202 Accepted` (SOURCE):
```json
{
  "message": "Run started",
  "workflow": "domain-lite",
  "kind": "flow",
  "target": "example.com",
  "target_count": 1,
  "run_uuid": "6f0c2a8e-1b7d-4f43-9b5e-2f4d6a1c9e10",
  "priority": "normal",
  "run_mode": "local",
  "job_id": "a1b2c3d4",
  "status": "queued",
  "poll_url": "/osm/api/jobs/a1b2c3d4"
}
```
Multi-target response: the same, but instead of `target`/`run_uuid` it carries `"targets":[...]` and `"concurrency":N`.
Optional echoes: `runner_type`, `timeout`, `schedule`, `schedule_enabled`, `threads_hold`, `empty_target`, `heuristics_check`, `repeat`, `repeat_wait_time`.

Notes:
- `job_id` is the first 8 hex characters of a UUID. It is stored as `run_group_id` on every run of the request.
- `"status":"queued"` is a literal string. In local mode a single-target run record is created **synchronously with status `running`** and starts immediately in a goroutine.
- **Multi-target local mode** (SOURCE: `executeRunsConcurrently`): each target goroutine creates its run record **only after it gets a concurrency slot**. Consequences:
  1. `run_uuid`s are not returned; discover them through `GET /jobs/{job_id}`.
  2. Right after the POST, `/jobs/{id}` can return `404 "Job not found"`. Retry.
  3. `/jobs/{id}.progress.total` counts **only records created so far**. While targets are still waiting for a slot, the aggregate can briefly read `completed`. **Always compare `progress.total` with the `target_count` from the create response.**
- **There is no global queue or concurrency limit in local mode.** Every POST starts work immediately. N customers at once means N parallel scans on one box. Throttle in WHMCS (section 14.4).
- Validation errors return `400`. These are the only synchronous errors: missing workflow (`404 "Workflow not found: ..."`), bad priority, run_mode, or heuristics value, forbidden characters, no targets.
- **Target type mismatches, missing tool binaries, and every runtime error surface asynchronously**: the run becomes `failed` with `error_message` set, for example a `TargetTypeMismatchError` when a domain flow gets an IP. Pre-validate on our side.

##### 4.2.1 Input validation (SOURCE: `handlers/common.go`)

Unless `skip_validation=true`, these fields are rejected (`400 {"message":"field \"target\" contains forbidden character \" \""}` and similar) if they contain any of the characters in this string:

```
 ;'"|&`$(){}[]      (note: the first character is a SPACE)
```

The check covers `target`, `target_file`, `flow`, `module`, `ssh_host`, `docker_image`, `repeat_wait_time`, `cloud_*`, every `targets[i]`, and **every `params` value**. Allowed: `/` (CIDR, URLs), `:`, `,`, `.`, `-`, `_`, `=`, `?`, `*`, `@`, `#`.

Consequences:
- A param value cannot contain a space. For example `nmapFlags="-sC -sV"` cannot be overridden through the API, and neither can `extraNuclei` with multiple flags.
- Upload file names containing spaces produce a `target_file` path with spaces, which is rejected. Rename before upload.

#### `GET /runs`: list

Query: `offset`, `limit` (default 20, max 10000), `status`, `workflow` (exact workflow name; the markdown docs wrongly say `workflow_name`), `target` (LIKE `%x%`), `workspace` (exact), `run_mode`, `org` (v5.1+; name or UUID, `400` if unknown). Ordered by `created_at DESC`.

Response: `{"data":[Run,...],"pagination":{"total","offset","limit"}}` (Run model in 6.1).

#### `GET /runs/{run_uuid}`: get one

- `{id}` must be the **`run_uuid`**. The numeric `id` does not work (SOURCE: `WHERE run_uuid = ?`).
- Query `include_steps=true` and `include_artifacts=true` embed `steps[]` / `artifacts[]`.
- Response `{"data": Run}`, or `404 {"message":"Run not found"}`.

#### `DELETE /runs/{run_uuid}`: cancel

- Allowed only if the status is `pending` or `running`. Otherwise `400 {"message":"Cannot cancel run with status 'completed'"}`.
- Kills the tracked PIDs and tmux sessions through the in-memory control plane, falling back to `current_pid`. Then it sets `status=cancelled`.
- Response:
```json
{"message":"Run cancelled successfully","id":42,"run_uuid":"...",
 "kill_method":"control_plane","killed_pids":[1234],"processes_terminated":1,
 "killed_tmux_sessions":["..."],"tmux_sessions_terminated":1,
 "note":"No active processes found to terminate; database status updated"}
```
  `kill_method`, `killed_*`, `*_terminated` and `note` are conditional.
- **Pitfall (source-inferred, UNVERIFIED in practice):** cancelling cancels the executor context, so `ExecuteFlow` returns `ctx.Err()`. The run goroutine then writes `status=failed, error_message="context canceled"`, **overwriting `cancelled`**. Record "cancel requested" on our side and treat `failed` + `context canceled` as cancelled.
- **There is no endpoint that deletes a run record or its data.** `DELETE` means cancel.

#### `POST /runs/{run_uuid}/duplicate` (v5.0.3+)

Creates a `pending` copy and returns `201 {"message":"Run duplicated","original_run_uuid","run_uuid","workflow","target","status":"pending"}`. Start it with:

#### `POST /runs/{run_uuid}/start` (v5.0.3+)

Only works for `pending` runs. Returns `202 {"message":"Run started","run_uuid","workflow",...}`. Useful for "re-run the same scan".

#### `GET /runs/{run_uuid}/steps`

Returns `{"data":[StepResult,...]}` ordered by `created_at ASC` (model in 6.2).

#### `GET /runs/{run_uuid}/artifacts`

Returns `{"data":[Artifact,...]}` ordered by `created_at DESC` (model in 6.3). **The `workspace` field on these artifacts is the real workspace the executor wrote to.** Use it to find the run's assets and vulns when in doubt.

#### `GET /jobs/{job_id}`: aggregate status of one POST

```json
{
  "run_group_id": "a1b2c3d4",
  "status": "running",
  "runs": [ Run, Run ],
  "progress": {"total": 2, "pending": 0, "running": 1, "completed": 1, "failed": 0}
}
```
Aggregate `status` rules (SOURCE: `aggregateStatus`):
- `running` if any run is running.
- `pending` if there are only pending runs.
- `completed` if all are completed.
- `failed` if all failed.
- otherwise `partial`.

`cancelled` runs are **not counted** in any bucket. A job whose runs are all cancelled therefore reads as `partial` or `pending`.

### 4.3 File upload (for target lists)

`POST /upload-file` (multipart, field `file`):
```json
{"message":"File uploaded","filename":"1731320000000000000_targets.txt",
 "path":"/root/osmedeus-base/data/uploads/1731320000000000000_targets.txt","size":1234,"lines":57}
```
Pass `path` as `target_file` in `POST /runs`, which fans out one run per line. A flow whose target type is `file` (for example `domain-list-recon`) also accepts the path as `target`.

### 4.4 Workspaces

- `GET /workspaces?offset&limit&org` returns `{"data":[Workspace,...],"pagination":{...}}` from the `workspaces` table (model in 6.6). It holds pre-aggregated counters (`total_subdomains`, `total_vulns`, `vuln_critical`, ...) and `risk_score`.
- `GET /workspaces?filesystem=true` returns `{"data":[{"name","local_path","data_source":"filesystem","total_assets","tags":["filesystem","filesystem-only"?]}],"workspaces_dir":"/root/workspaces-osmedeus","pagination":{...}}`. Useful to learn the server's absolute workspaces path.
- `GET /workspace-names` returns a bare array `["example.com","mcsec-123-..."]`.
- There is **no workspace delete endpoint** in v5.1.2. The org delete with `purge=true` (v5.1+) and `POST /database/tables/{t}/clear` are the only API-level purge options, and both are blunt.

### 4.5 Assets (subdomains, HTTP services, IPs/ports, technologies)

`GET /assets` query: `workspace` (exact), `org` (v5.1+), `search` (LIKE on `asset_value`, `url`, `title`, `host_ip`), `status_code` (int), `offset`, `limit`. Ordered by `created_at DESC`.

Response: `{"data":[Asset,...],"pagination":{...}}` (model in 6.4).

- **There is no `asset_type` filter.** Fetch everything for the workspace (paginate with limit up to 10000) and filter in PHP by `asset_type`.
- Asset rows carry heavy columns: `raw_json_data` (the full httpx JSON), and `raw_response` / `screenshot_base64_data` when enabled. Expect large payloads, and page with `limit` 500 to 1000.

`GET /asset-stats?workspace=` returns `{"data":{"technologies":[...],"sources":[...],"remarks":[...],"asset_types":[...]}}` with distinct sorted values.

`GET /assets/diff?workspace=X&from=<RFC3339|unix>&to=<optional>` (workspace and from are required) returns `{"data":{"workspace_name","from_time","to_time","added":[Asset],"removed":[Asset],"changed":[{"asset_id","asset_value","url","changes":[{"field","old_value","new_value"}]}],"summary":{"total_added","total_removed","total_changed"}}}`.

`GET /assets/diffs?workspace&offset&limit` lists stored diff snapshots.

### 4.6 Vulnerabilities and findings

`GET /vulnerabilities` query: `workspace`, `org` (v5.1+), `severity` (exact, lower case), `confidence`, `asset_value` (LIKE), `offset`, `limit`. Ordered by `created_at DESC`.

Response: `{"data":[Vulnerability,...],"pagination":{...}}` (model in 6.5).

- **Bug (SOURCE, `database.ListVulnerabilities`):** `confidence` is applied to the count query but **not** to the data query. The returned rows are not filtered by confidence, and `pagination.total` disagrees with them. Filter confidence client-side.

`GET /vulnerabilities/summary?workspace=` returns `{"data":{"by_severity":{"critical":1,"high":3,"info":40},"total":44,"workspace":"..."}}`. Keys are whatever severity strings exist.

`GET /vulnerabilities/{id}` (numeric) returns `{"data":Vulnerability}`.

`GET /vulnerabilities/diff?workspace&from[&to]` has the same shape as the asset diff, with `added`/`removed` of type Vulnerability and `changed[{vuln_id,vuln_info,asset_value,changes[]}]`.

`POST /vulnerabilities` (manual insert; `workspace` required) and `DELETE /vulnerabilities/{id}` also exist. A manual false-positive workflow could use DELETE.

### 4.7 Artifacts, report files, screenshots

- `GET /artifacts?workspace&search&verify_exist=true&offset&limit` returns `{"data":[Artifact...],"pagination":{...}}`. `verify_exist=true` drops artifacts whose file is missing and adds `path_exists` / `path_is_dir`.
- `GET /artifacts/{workspace_name}?artifact_path=<path relative to the workspace dir>` returns the file bytes (`SendFile`). Rules:
  - The workspace name must not contain `/`, `\` or `..`.
  - `artifact_path` must be relative, without `..`, and must point at a file, not a directory.
  - Responses: `400` invalid, `403` traversal, `404` missing.
  - **`Artifact.artifact_path` in the DB is absolute** (for example `/root/workspaces-osmedeus/example.com/vulnscan/nuclei-jsonl-example.com.txt`). Strip the `<workspaces_dir>/<workspace>/` prefix to build `artifact_path`. `workspaces_dir` comes from `GET /workspaces?filesystem=true`.
- `POST /snapshots/export` with body `{"workspace":"<name>"}` streams a **zip of the whole workspace folder** (`Content-Type: application/zip`, `Content-Disposition: attachment; filename=<ws>_<UTC>.zip`, `X-Snapshot-Size`). It also leaves a copy in `{{base_folder}}/snapshot`, so clean up with `DELETE /snapshots/{name}`. `GET /snapshots` lists them, and `GET /snapshot-download/{workspace_name}` is the legacy variant.
- Screenshots (`recon-screenshot` module): `pd-httpx -screenshot -system-chrome` writes PNGs and an HTML gallery under `<ws>/screenshots/<ws>-screenshots/`. The registered artifacts are `screenshot-gallery` (html) and `screenshot-json` (jsonl index). Individual PNG paths are in the jsonl index (httpx `screenshot_path`, UNVERIFIED field name); download each one with `/artifacts/{ws}?artifact_path=...`. **UNVERIFIED:** whether `Asset.screenshot_base64_data` is filled by the default workflows. No import step writes it in the reviewed YAML, so expect it to be empty.
- Avoid `/ws/{prefix}/...` for customer delivery. It is unauthenticated, with directory listing over **all** customers' workspaces.

### 4.8 Step results and event logs (debugging and progress detail)

- `GET /step-results?run_uuid&workspace&status&step_type&offset&limit` returns `{"data":[StepResult],"pagination":{...}}`.
- `GET /event-logs?topic&name&source&workspace&run_uuid&workflow_name&processed&offset&limit` returns paginated `EventLog` rows. Topics include `run.started`, `run.completed`, `run.failed`, `step.completed`, `step.failed`, `asset.discovered`, `schedule.triggered`.

### 4.9 Schedules (built-in cron)

| Method | Path | Body / notes |
|---|---|---|
| GET | `/schedules?offset&limit` | `{"data":[Schedule],"pagination"}` |
| POST | `/schedules` | `{"name"*,"workflow_name"*,"schedule"* (cron),"workflow_kind":"flow"\|"module","target","workspace","params":{...},"trigger_type":"cron"(default)\|"event"\|"watch"\|"manual","event_topic","watch_path","enabled":true,"runner_type"}` returns `201 {"message":"Schedule created","data":Schedule}` |
| GET | `/schedules/{id}` | `{"data":Schedule}`. IDs look like `sch_1731320000000000000` |
| PUT | `/schedules/{id}` | `{"name","target","workspace","schedule","params","enabled"}` (partial update) |
| DELETE | `/schedules/{id}` | |
| POST | `/schedules/{id}/enable` and `/disable` | |
| POST | `/schedules/{id}/trigger` | runs it now, returning `202 {"message":"Schedule triggered","schedule","workflow"}` |

Caveats (SOURCE: `handlers/schedules.go`, `pkg/server/eventreceiver.go`; behaviour UNVERIFIED in practice):
- `name`, `workflow_name` and `schedule` are required even for non-cron triggers.
- Registration with the in-memory cron engine happens **only at creation time** (if the event receiver is running and `enabled=true`). At startup the event receiver registers triggers declared in workflow YAML, and the reviewed code does not reload DB schedules. **Schedules created through the API may stop firing after an Osmedeus restart.** `PUT` changes to the cron expression are DB-only and not re-registered. `enable`/`disable` toggles a DB flag that the trigger handler checks before running.
- Schedule-fired and `/trigger` runs execute **without** a pre-created DB run record (`SetDBRunUUID` is not called). They may not show up in `/runs`, and cannot be cancelled through `DELETE /runs/{id}`.
- The `cron` format is the robfig/cron style used by `internal/scheduler`. Whether it is 5-field or 6-field is UNVERIFIED; check `scheduler.go` or test.
- **Recommendation:** drive recurring scans from the WHMCS cron (`DailyCronJob` / `AfterCronJob` hooks) calling `POST /runs`, and do not use Osmedeus schedules. That gives a run record, cancellation and job tracking for every execution.

### 4.10 Statistics

`GET /stats` returns a flat JSON object:
```json
{"workflows":{"total":40,"flows":12,"modules":28},
 "runs":{"total":150,"completed":120,"running":5,"failed":10,"pending":15},
 "workspaces":{"total":50},"assets":{"total":5000},
 "vulnerabilities":{"total":150,"critical":10,"high":25,"medium":50,"low":65},
 "schedules":{"total":8,"enabled":5}}
```
`vulnerabilities.total` sums only critical, high, medium and low (info is excluded). Use `runs.running` for a capacity check before starting new scans.

### 4.11 Orgs (v5.1.0+; optional multi-tenant grouping)

- `GET /orgs`
- `POST /orgs` with `{"name"*,"description","uuid","tags":[]}`
- `GET /orgs/{uuid|name}`
- `GET /orgs/{uuid}/stats` returns `{org_uuid,org_name,total_workspaces,total_assets,total_vulns,total_runs,workspaces[]}`
- `PUT /orgs/{uuid}` with `{"name","description","tags","workspaces":[...]}` (assigning workspaces cascades the org stamp to their assets, vulns and runs)
- `DELETE /orgs/{uuid}[?purge=true]`. Without purge, data moves to the default org. **With purge, every workspace, asset, vuln and run of the org is deleted.**

The default org is `00000000-0000-0000-0000-000000000001`, which cannot be deleted or renamed. List endpoints take `?org=<name|uuid>`.

**Option:** one org per WHMCS client (named `whmcs-client-<id>`) with `params.org_uuid` on each run. That gives cleaner per-customer queries and a GDPR-style purge per customer. UNVERIFIED that `params.org_uuid` propagates to assets and vulns of a *new* workspace: the code comment says "a new workspace lands in the default org" when empty, which implies it is honoured when set. Test it.

### 4.12 Distributed mode (only if the server runs `osmedeus serve --master` with Redis)

- `GET /workers`
- `GET /workers/{id}`
- `GET /tasks`
- `GET /tasks/{id}`
- `POST /tasks` with `{"workflow_name","workflow_kind","target","params":{}}`

Runs created with `run_mode:"distributed"` are queued to Redis for `osmedeus worker` nodes. If these routes return 404, the server is not in master mode. Not needed for MVP.

### 4.13 Endpoints the module must never call

`/functions/eval`, `/workflow-upload`, `/registry-install`, `/settings/*`, `/database/*`, `/llm/*`, `/agent/*`, `/cloud/*`, `/events/emit`, `/snapshots/import`. They either run code or mutate the server globally.

---

## 5. Run lifecycle and progress

Run status values (SOURCE: `core.RunStatus` and the handlers): `pending`, `running`, `completed`, `failed`, `cancelled`. `skipped` exists in core but the API handler maps any non-error result to `completed`.

```
POST /runs --> running --(success)--------------> completed
                  |----(error / target mismatch)--> failed      (error_message set)
                  '----(DELETE /runs/{id})--------> cancelled   (may be overwritten to failed "context canceled")
POST /runs/{id}/duplicate --> pending --POST /runs/{id}/start--> running ...
```

Progress fields on Run (SOURCE):
- `total_steps`: computed at creation. For a flow it is the sum of the steps of all its modules; for a module it is `len(steps)`. Excluded modules are **still counted**.
- `completed_steps`: incremented after each step finishes, including failed or skipped steps (pre_condition false). On `completed` the server sets `completed_steps = total_steps`.
- Progress % = `min(99, floor(100 * completed_steps / max(1,total_steps)))` while running, and 100 when completed.
- `started_at`, `completed_at` (set on completed, failed or cancelled), `updated_at` (bumped on every step, useful as a heartbeat), `current_pid` (0 when idle).
- For a per-step view, use `GET /runs/{uuid}/steps` (`step_name`, `status` = `pending|running|success|failed|skipped`, `duration_ms`).

---

## 6. Data models (SOURCE: `internal/database/models.go`)

Keys are the JSON names. "opt" means `omitempty`: the key is absent when the value is empty or zero. Otherwise the key is always present (possibly `""`, `0`, `null`, `false`).

### 6.1 Run
| key | type | notes |
|---|---|---|
| `id` | int64 | internal numeric id (not usable in URLs) |
| `run_uuid` | string | **use this** |
| `workflow_name`, `workflow_kind` | string | kind `flow`\|`module` |
| `target` | string | |
| `params` | object | includes `target` and our params |
| `status` | string | see section 5 |
| `workspace` | string | computed by the handler; **may differ** from the executor's real workspace (9.3) |
| `org_uuid` | string | v5.1+ |
| `started_at`, `completed_at` | time\|null | |
| `error_message` | string | opt |
| `created_at`, `updated_at` | time | |
| `schedule_id`, `trigger_type`, `trigger_name` | string | opt; `trigger_type` is `"api"` for API runs |
| `run_group_id` | string | opt; equals `job_id` |
| `total_steps`, `completed_steps` | int | |
| `current_pid` | int | opt |
| `run_priority`, `run_mode` | string | |
| `hooks_enabled`, `is_queued`, `input_is_file` | bool | |
| `input_file_path`, `webhook_uuid`, `webhook_auth_key` | string | opt |
| `steps`, `artifacts`, `events` | arrays | opt; only with `include_*` |

### 6.2 StepResult
`id` (string), `run_id` (int64), `run_uuid` (opt), `step_name`, `step_type` (`bash`, `function`, `foreach`, `parallel-steps`, `remote-bash`, `http`, `llm`, ...), `status`, `command` (opt), `output` (opt), `error_message` (opt), `exports` (opt object), `duration_ms`, `log_file` (opt), `started_at`, `completed_at`, `created_at`.

### 6.3 Artifact
`id` (uuid string), `run_id` (int64), `workspace`, `name` (for example `nuclei-raw-json`, `final-subdomains`, `state-execution-log`), `artifact_path` (**absolute** server path), `artifact_type` (opt: `report`, `state_file`, `output`, `screenshot`), `content_type` (opt: `json`, `jsonl`, `yaml`, `html`, `md`, `log`, `pdf`, `png`, `txt`, `zip`, `folder`, `unknown`), `size_bytes`, `line_count`, `optional`, `description` (opt), `created_at`.

State files registered for each run: `run-execution.log`, `run-console.log`, `run-completed.json`, `run-state.json` and `run-workflow.yaml`, all in the workspace root.

### 6.4 Asset
| key | notes |
|---|---|
| `id`, `workspace`, `org_uuid`, `asset_value` | `asset_value` = host (httpx `host`), or the URL when the host is an IP |
| `url`, `input`, `scheme`, `method`, `path` | opt |
| `status_code`, `content_type`, `content_length`, `title`, `words`, `lines` | opt |
| `host_ip` | opt |
| `dns_records` | opt string[] (httpx `a` records) |
| `tls` | opt **string**: httpx `tls` object serialized as JSON (cert subject, issuer, not_after, SANs, version, cipher). Our SSL/TLS data source. |
| `open_ports` | opt string[], for example `["443/https","8080/http"]` or `["22/tcp", ...]` from nmap |
| `port_json_data` | opt string (nmap per-port JSON) |
| `asset_type` | opt: `http`, `url`, `domain`, `subdomain`, `ip`, `dns`, `repository`, `repo_name`, `file`, `link`, `content`, `archive`, `port`, `other`, `unknown` |
| `tech` | opt string[], technologies from httpx `-tech-detect` (Wappalyzer names, often `Name:Version`). **The JSON key is `tech`**, not `technologies`. |
| `time` | opt, response time (JSON key `time`) |
| `remarks` | opt string[] (webserver, CDN name, tags) |
| `source` | opt (`httpx`, `portscan`, `spider`, `content-discovery`, ...) |
| `raw_json_data` | opt, the full original JSON line |
| `raw_response`, `screenshot_base64_data` | opt, large |
| `is_cdn`, `is_cloud`, `is_waf` | opt bool |
| `language`, `size`, `loc`, `external_url`, `blob_content` | opt (repo/file assets) |
| `created_at`, `updated_at`, `last_seen_at` | |

### 6.5 Vulnerability
| key | notes |
|---|---|
| `id` (int64), `workspace`, `org_uuid` | |
| `vuln_info` | **finding identifier**: nuclei `template-id` (for example `CVE-2021-44228`, `tech-detect`), vigolium `module_id`, or the SARIF rule id |
| `vuln_title` | nuclei `info.name` |
| `vuln_desc` | nuclei `info.description` |
| `vuln_poc` | empty for nuclei; vigolium `matched_at` + `extracted_results` |
| `severity` | nuclei `info.severity`, verbatim: `critical`\|`high`\|`medium`\|`low`\|`info` (nuclei can also emit `unknown`) |
| `confidence` | default `firm`. Vigolium may set `certain`, `firm` or `tentative` |
| `finding_hash` | opt (vigolium) |
| `asset_type` | nuclei `type` (`http`, `dns`, `ssl`, `network`, `tcp`, `javascript`, ...) |
| `asset_value` | nuclei `host`, falling back to `matched-at` |
| `tags` | opt string[] (`info.tags`) |
| `detail_http_request`, `detail_http_response` | nuclei `request` / `response` (can be large) |
| `raw_vuln_json` | the full nuclei JSON line: parse it for `matched-at`, `extracted-results`, `curl-command`, `info.classification.{cve-id,cwe-id,cvss-score,cvss-metrics,epss-score}`, `info.reference`, `info.remediation` |
| `created_at`, `updated_at`, `last_seen_at` | |

### 6.6 Workspace
`id`, `name`, `org_uuid`, `local_path`, `data_source` (`local`|`cloud`|`imported`), `total_assets`, `total_subdomains`, `total_urls`, `total_vulns`, `total_ips`, `total_links`, `total_content`, `total_archive`, `vuln_critical`, `vuln_high`, `vuln_medium`, `vuln_low`, `vuln_potential`, `risk_score` (float), `tags`, `last_run`, `run_workflow`, `state_*` (opt), `created_at`, `updated_at`.

Workflow steps (`db_total_*`, `db_vuln_*`) update these counters from file line counts. Treat them as indicative, not exact.

### 6.7 Schedule
`id`, `name`, `workflow_name`, `workflow_kind` (opt), `target` (opt), `workspace` (opt), `params` (opt), `trigger_name`, `trigger_type`, `schedule` (opt), `event_topic` (opt), `watch_path` (opt), `is_enabled`, `last_run` (opt), `next_run` (opt), `run_count`, `created_at`, `updated_at`.

---

## 7. curl cookbook

```bash
H=http://OSMEDEUS_HOST:8811
K='x-osm-api-key: <AUTH_API_KEY>'

# version (no auth)
curl -s $H/server-info

# OR JWT login
TOKEN=$(curl -s -X POST $H/osm/api/login -H 'Content-Type: application/json' \
  -d '{"username":"osmedeus","password":"<PASSWORD>"}' | php -r 'echo json_decode(stream_get_contents(STDIN))->token;')

# list flows (filesystem, clean params)
curl -s -H "$K" "$H/osm/api/workflows?source=filesystem&kind=flow"

# start a quick recon with a deterministic workspace
curl -s -H "$K" -H 'Content-Type: application/json' -X POST $H/osm/api/runs -d '{
  "flow":"domain-lite","target":"example.com",
  "params":{"space_name":"mcsec-s123-r456","tactic":"gently"}}'

# multi-target
curl -s -H "$K" -H 'Content-Type: application/json' -X POST $H/osm/api/runs -d '{
  "flow":"domain-lite","targets":["a.com","b.com"],"concurrency":1,
  "params":{"tactic":"default"}}'

# poll
curl -s -H "$K" $H/osm/api/jobs/a1b2c3d4
curl -s -H "$K" "$H/osm/api/runs/<RUN_UUID>?include_artifacts=true"

# cancel
curl -s -H "$K" -X DELETE $H/osm/api/runs/<RUN_UUID>

# results
curl -s -H "$K" "$H/osm/api/vulnerabilities?workspace=mcsec-s123-r456&limit=1000"
curl -s -H "$K" "$H/osm/api/vulnerabilities/summary?workspace=mcsec-s123-r456"
curl -s -H "$K" "$H/osm/api/assets?workspace=mcsec-s123-r456&limit=1000"
curl -s -H "$K" -o subs.txt "$H/osm/api/artifacts/mcsec-s123-r456?artifact_path=subdomain/final-mcsec-s123-r456.txt"
curl -s -H "$K" -H 'Content-Type: application/json' -X POST $H/osm/api/snapshots/export \
  -d '{"workspace":"mcsec-s123-r456"}' -o ws.zip
```

Note on the `artifact_path` above: the file names use `{{TargetSpace}}`, which equals `space_name` when we set it.

---

## 8. Built-in workflows (osmedeus-workflow repo; the server's installed set may differ)

The server loads YAML from `{{base_folder}}/workflows` (default `~/osmedeus-base/workflows`), installed by `osmedeus install base --preset` or `osmedeus install workflow https://github.com/osmedeus/osmedeus-workflow.git`. The list below comes from `platform/osmedeus-workflow/` in the main repo, which mirrors `osmedeus/osmedeus-workflow` (pushed 2026-10-04). **Confirm the live list with `GET /workflows?source=filesystem`.**

### 8.1 Flows (top level, run with `"flow": "<file-name>"`)

| Flow (file) | Accepted target type | Modules (in dependency order) | Key param defaults | Intensity |
|---|---|---|---|---|
| `fast` | domain | enum-subdomain -> probe-dns -> recon-http-fp | `enableDnsBruteFocing=false`, `enableStoreHTTPResponse=true` | Low |
| `domain-lite` | domain | the same three modules as `fast` | `enableDnsBruteFocing=false` | Low |
| `domain-standard` | domain | enum-subdomain -> probe-dns -> recon-http-fp -> {recon-screenshot, recon-spider, util-archive, enum-ipspace, scan-vuln, probe-port, scan-content} | `enableDnsBruteFocing=false` | High |
| `general` | domain | identical module set to `domain-standard` | `enableDnsBruteFocing=true`, `enableStoreHTTPResponse=false` | High |
| `domain-extensive` | domain | domain-standard modules, minus scan-content, plus scan-vuln-thorough (Vigolium) | DNS brute force and permutations on, store responses, HTTP port probe `1-65535` | Very high |
| `domain-list-recon` | **file** (server path) | do-util-normalize -> recon-http-fp -> {screenshot, spider, archive, ipspace, scan-vuln, probe-port, scan-content} | | High |
| `cidr` | cidr, ip, file | do-probe-port -> {do-recon-spider, do-scan-vuln, do-scan-content} | `enableSYNScan=false` (true = rustscan full TCP 1-65535 + `nmap -sC -sV`) | Medium to very high |
| `cidr-extensive` | cidr, ip, file | `extends: cidr-standard` (**that file does not exist upstream**; UNVERIFIED whether it loads) and overrides the HTTP ports to `1-65535` | | Very high |
| `url` (YAML `name: web-analysis`) | url, domain | do-recon-http-fp -> {do-scan-vuln, do-scan-vuln-thorough} | | Medium |
| `web-analysis` | url, domain | alias of `url` (`extends: url`) | | Medium |
| `sast` / `repo` | string (git URL or zip URL) | do-scan-repo (semgrep, kingfisher, trivy, bearer -> SARIF import) | | Medium; not a web product |

### 8.2 Modules (`common/`, also runnable alone with `"module": "<name>"`)

| Module | Tools | What it produces | Notable params and timeouts |
|---|---|---|---|
| `enum-subdomain` | subfinder, findomain, assetfinder, amass (optional) | `subdomain/final-<ws>.txt` (artifact `final-subdomains`) | `enable_amass` |
| `probe-dns` | puredns, dnsx, pd-httpx | `dnsFile`, `httpFile` (live HTTP list) | `enableDnsBruteFocing`, `enablePermutation` |
| `recon-http-fp` | pd-httpx (title, tech-detect, CDN, TLS grab, JARM, favicon) | `fingerprint/*.jsonl`, imported into **assets** | `enableStoreHTTPResponse` |
| `recon-screenshot` | pd-httpx `-screenshot -system-chrome` | PNGs + HTML gallery | `screenTimeout=15` |
| `recon-spider` | katana, vigolium spider, trufflehog | `links/links-<ws>.txt`, `secrets/trufflehog-*.txt`, assets (source `spider`) | 2h cap, `5m` crawl time |
| `util-archive` | urlfinder (Wayback, CommonCrawl), pd-httpx | archive URLs, interesting URLs | 2h cap |
| `enum-ipspace` | metabigor, jq | `ipspace/ip-<ws>.txt`, ASN and CDN filtering | 2h cap |
| `scan-vuln` | **nuclei** (`-severity critical,high,medium,low,info`, templates `~/nuclei-templates/`) | `vulnscan/nuclei-jsonl-<ws>.txt`, markdown report, `security-report.md`, imported into **vulnerabilities** | `nucleiTimeout=8h`, `nucleiSeverity`, `nucleiThreads={{threads*10}}`, `vulnLimit=10000` input lines |
| `scan-vuln-thorough` | vigolium native scan | HTML, MD and JSONL reports, imported into vulns (with `finding_hash`) | 1h / 45m caps |
| `probe-port` | pd-httpx on a fixed list of ~120 HTTP(S) ports; optional rustscan + nmap | `portscan/open-ports-<ws>.txt`, `portscan/http-port-fingerprint-<ws>.jsonl`, `synscan/portscan-<ws>.jsonl`; assets type `ip` with `open_ports` | `enableSYNScan=false`, `rustscanPorts=1-65535`, `nmapFlags="-sC -sV"` (cannot be changed through the API because of the space), `commonHttpPorts` |
| `scan-content` | ffuf, vigolium discover | content discovery HTML/MD reports, assets (source `content-discovery`) | 30m caps |

Fragments (`fragments/do-*.yaml`) are module variants used by `cidr`, `url` and `sast`. Events (`events/*.yaml`) are examples of event triggers.

### 8.3 Runtime and resources

Upstream gives **no documented runtimes.** The upper bounds below come from the hard `timeout` values in the YAML. Everything else is UNVERIFIED; measure with test runs on our box.
- `fast` / `domain-lite`: dominated by passive subdomain enumeration and httpx. Expect minutes to under an hour for typical SMB domains (UNVERIFIED).
- `domain-standard` / `general`: several hours is plausible. Nuclei alone is capped at **8 h**; spider, archive and ipspace are each capped at 2 h; content discovery at 30 min per stage. Many steps run in parallel after `recon-http-fp`.
- `domain-extensive` / `cidr-extensive`: full-port HTTP probing (`1-65535`), DNS brute force and permutations. It can run for many hours or days on large scopes and generates heavy traffic.
- Threads: `scan_tactic.default=10`, `aggressive=40`, `gently=5`. Each module scales its tools from `{{threads}}` (for example nuclei `-c threads*10`, rustscan batch `threads*400`).
- Disk: each workspace holds raw tool output. `enableStoreHTTPResponse=true` (on in `fast` and `domain-extensive`) stores full HTTP responses. Screenshots and nuclei `-irr` responses (stored in the DB columns `detail_http_*`) grow the SQLite DB. Plan cleanup (section 14.5).
- DB: SQLite by default (`~/osmedeus-base/database-osm.sqlite`); PostgreSQL is supported. Many concurrent runs writing to SQLite will serialize.

---

## 9. Targets, workspaces, dedupe, severity

### 9.1 Passing targets
- Single target: `"target": "example.com"`.
- Many targets: `"targets": [...]` (one run per target, `concurrency` in parallel), or upload a file and use `"target_file": "<server path>"`.
- CIDR or IP: `"target": "203.0.113.0/24"` with `flow: "cidr"`. The `/` is allowed by validation, and the `cidr` type matches CIDR notation. **UNVERIFIED and important:** in `fragments/do-probe-port.yaml` the IP list file is only prepared when the target is an existing *file* (`pre_condition: file_exists('{{Target}}')`). With a bare CIDR or IP target the port-probe steps may find no input and do nothing. Test `cidr` with a bare IP **and** with an uploaded file holding the IP/CIDR, and use whichever produces results.
- Domain list as a single run: upload the list and run `domain-list-recon` with `target` = the uploaded path.
- Type validation: each flow declares `dependencies.variables[Target].type` (`domain`, `cidr,ip,file`, `url,domain`, `file`, `string`). A mismatch makes the run **fail asynchronously** with a `TargetTypeMismatchError`. The domain regex is `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`, so IDNs must be punycode and there must be no trailing dot.

### 9.2 Dedupe (SOURCE: `internal/functions/db_functions.go`)
- Targets in one request: trimmed, exact-string de-duplication.
- Vulnerabilities (nuclei import): unique per **(workspace, vuln_info = template-id, asset_value = host)**. A re-scan updates `last_seen_at`, and also updates severity, title, desc, confidence or tags if they changed. It does not insert duplicates. Vigolium findings dedupe on (workspace, finding_hash), falling back to the same triple.
- Assets (httpx import): unique per **(workspace, asset_value, url)**. A re-scan merges fields and updates `last_seen_at`.
- **Neither assets nor vulnerabilities carry a run id.** Everything accumulates per workspace across runs.

### 9.3 Workspace naming: always set `params.space_name`
- The executor's workspace (where files, assets and vulns go) is called `TargetSpace`:
  1. It starts as the target with `/\:*?"<>|` replaced by `_`. **If that is longer than 30 characters, it becomes `<first6>-<random6>-<unixtime>`**, which is unpredictable.
  2. With `heuristics_check` = `basic` (the default), a domain target is replaced by its **root domain** (`shop.example.com` -> `example.com`), and a URL by its host's root domain or repo slug.
  3. `params.space_name` overrides all of this.
- The API handler independently stores `run.workspace` = sanitized target (200-character cap, no heuristics). **The two can disagree.** For example, target `shop.example.com` gives `run.workspace = "shop.example.com"`, but the data lands in workspace `example.com` and is merged with any other scans of `example.com`.
- **Fix:** pass `params.space_name` as a short, unique, validation-safe value, for example `mcsec-s{serviceid}-r{ourRunId}`. Use only letters, digits and `-`, and keep it under 64 characters. Then `run.workspace`, the artifact paths, `/assets?workspace=` and `/vulnerabilities?workspace=` all match, and each scan's results are isolated.
- For "monitoring" products that want deltas between scans, reuse a stable `space_name` per service (for example `mcsec-s{serviceid}`). Then use `/vulnerabilities/diff?workspace=...&from=<previous run started_at>` or compare `last_seen_at`/`created_at` against the run's `started_at`.

### 9.4 Severity
- Stored verbatim from the tool. For nuclei that is `info`, `low`, `medium`, `high`, `critical` (plus the rare `unknown`). Vigolium and SARIF imports may use other casing or vocabularies (SARIF `error`/`warning`/`note`), which is UNVERIFIED. Normalize with `strtolower()` and a map, and default unknown values to `info`.
- `GET /stats` and `Workspace.vuln_*` count only critical, high, medium and low. `vuln_potential` probably means info or tentative (UNVERIFIED).
- The `severity=` filter is exact-match and case-sensitive (SQL `=`), and so is `confidence=`.

---

## 10. Push notifications instead of (or as well as) polling

The server can POST JSON to configured webhooks on workflow completion (SOURCE: `internal/notify/webhook.go`, settings `notification.webhooks[]`):

```yaml
notification:
  enabled: true            # SOURCE: REQUIRED - TriggerWebhooks returns early if notification.enabled is false
  webhooks:
    - url: "https://whmcs.example.com/modules/servers/mcsec/callback.php"
      enabled: true
      headers: { X-MCSec-Signature: "<shared secret>" }
      timeout: 30
      retry_count: 3
      skip_tls_verify: false
      events: [workflow_completed, workflow_failed, workflow_cancelled]
```

Payload: `{"event":"workflow_completed","timestamp":"...","data":{"workflow","kind","target","status","duration","run_uuid","error","artifacts","message"}}`. The executor emits it for **every** module and flow execution (`workflow_<status>`). A flow therefore produces several events, one per module plus one for the flow. Match on `data.kind == "flow"` and our `run_uuid`. Configuring it requires editing `osm-settings.yaml` on the server. Use it only as a hint to poll immediately, and keep polling as the source of truth.

---

## 11. Minimal PHP client sketch (WHMCS server module)

```php
<?php
final class OsmedeusClient
{
    public function __construct(
        private string $baseUrl,          // "http://OSMEDEUS_HOST:8811"
        private string $apiKey,           // server.auth_api_key
        private int $timeout = 30
    ) {}

    public function request(string $method, string $path, ?array $body = null, array $query = []): array
    {
        $url = rtrim($this->baseUrl, '/') . '/osm/api' . $path . ($query ? '?' . http_build_query($query) : '');
        $ch = curl_init($url);
        $headers = ['Accept: application/json', 'x-osm-api-key: ' . $this->apiKey];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_SLASHES));
        }
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => $this->timeout,
        ]);
        $raw  = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err  = curl_error($ch);
        curl_close($ch);
        if ($raw === false) throw new RuntimeException("Osmedeus unreachable: $err");
        $json = json_decode($raw, true);
        if ($code >= 400 || (is_array($json) && ($json['error'] ?? false) === true)) {
            throw new RuntimeException("Osmedeus HTTP $code: " . ($json['message'] ?? substr($raw, 0, 200)));
        }
        return is_array($json) ? $json : ['raw' => $raw];
    }

    public function startScan(string $flow, array $targets, string $spaceName, array $params = []): array
    {
        $params = array_map('strval', $params + ['space_name' => $spaceName]);
        $body = ['flow' => $flow, 'params' => $params];
        if (count($targets) === 1) {
            $body['target'] = $targets[0];
        } else {
            $body['targets'] = array_values($targets);
            $body['concurrency'] = 1;
        }
        return $this->request('POST', '/runs', $body);   // returns job_id, poll_url, run_uuid (single target, v5.0.3+)
    }

    public function job(string $jobId): array      { return $this->request('GET', "/jobs/$jobId"); }
    public function run(string $uuid): array       { return $this->request('GET', "/runs/$uuid")['data']; }
    public function cancel(string $uuid): array    { return $this->request('DELETE', "/runs/$uuid"); }

    public function vulns(string $ws, int $offset = 0, int $limit = 1000): array
    { return $this->request('GET', '/vulnerabilities', null, compact('offset', 'limit') + ['workspace' => $ws]); }

    public function assets(string $ws, int $offset = 0, int $limit = 1000): array
    { return $this->request('GET', '/assets', null, compact('offset', 'limit') + ['workspace' => $ws]); }
}
```

For multi-target scans, give each target its own `space_name`. Either submit one POST per target (simplest and recommended), or accept the shared-workspace semantics.

---

## 12. Differences between the docs and the source (trust the source)

| Topic | Markdown docs / docs site | Source (v5.1.2) |
|---|---|---|
| JWT default lifetime | 60 min | **1440 min** |
| Run identifier | `"id": "run-abc123"`, `run_id` | `run_uuid` (UUID); numeric `id`; routes take `run_uuid` |
| `GET /runs/{id}` shape | bare object | `{"data": Run}` |
| Run list filter | `workflow_name` | `workflow` |
| Create-run response | `"message":"Scan started"`, no job id | `"Run started"`, `job_id`, `poll_url`, `status:"queued"`, `run_uuid` (single) |
| Cancel response | `"Run cancellation requested"` | `"Run cancelled successfully"` + kill details |
| Run field `workspace_path` | present | not in model; `workspace` (name) only |
| docs.osmedeus.org example | `{"flow":"general","target":"example.com","distributed":true}` | there is no `distributed` field; use `"run_mode":"distributed"` |
| docs.osmedeus.org | `https://localhost:8002` | the server listens plain HTTP |
| Artifact fields | `path`, `type` | `artifact_path`, `artifact_type`, `content_type` |
| API key | "takes priority over JWT" | tried first, then falls back to JWT |

---

## 13. If the server turns out to be Osmedeus v4 (legacy)

Fingerprint: `GET /ping` answers; `/health` and `/server-info` do not. v4 (branch `osm-v4`) defaults to **HTTPS on port 8000** with a self-signed certificate. Its routes are `POST /api/login`, then `/api/osmp/{health,workspaces,workspace/:wsname/,scans,ps,raw,flows,help}` and `POST /api/osmp/{execute,upload}`. Static files are served at `/<static_prefix>/workspaces/`. It is an entirely different and much smaller API. Everything in this document assumes v5. Re-scope if `/ping` is what answers.

---

## 14. Integration notes for MC-Sec

### 14.1 Product to workflow mapping (proposal; validate with test runs)

| MC-Sec product | Target input | Osmedeus call | Params | Expected output |
|---|---|---|---|---|
| **Quick recon** | domain | `flow: domain-lite` (or `fast`, which also stores HTTP responses) | `tactic=gently`, `space_name` | subdomains (artifact `final-subdomains`), live HTTP services + tech + TLS (assets) |
| **Standard** | domain | `flow: domain-standard` | `tactic=default`, optionally `fuzzy_exclude_modules=archive` to shorten | + screenshots, crawl, nuclei findings, HTTP-port services, content discovery |
| **Deep** | domain | `flow: domain-extensive` | `tactic=default` (not aggressive on shared infrastructure) | + DNS brute force and permutations, full-port HTTP probe, Vigolium findings |
| **Ports** (IP/CIDR) | ip, cidr | `flow: cidr` | `enableSYNScan=true` (rustscan full TCP + `nmap -sC -sV`), `exclude_modules=do-recon-spider,do-scan-content` | assets of type `ip` with `open_ports` / `port_json_data`; HTTP services on open ports |
| **Ports** (domain) | domain | `flow: domain-standard` + `exclude_modules=recon-screenshot,recon-spider,util-archive,scan-vuln,scan-content` + `enableSYNScan=true` | | **UNVERIFIED:** in domain flows `probe-port` reads `portscan/ip-file-<ws>.txt` while `enum-ipspace` writes `ipspace/ip-<ws>.txt`, so the port scan may get no input. Alternative: resolve the IPs ourselves and call `cidr` on them. |
| **Web vuln** | URL or domain | `flow: url` (or `web-analysis`) | `nucleiSeverity=critical,high,medium,low` to drop info noise | nuclei + Vigolium findings for one web app |
| **Web vuln, lighter** | URL | `module: scan-vuln` alone | **UNVERIFIED:** it expects `{{Output}}/probing/http-<ws>.txt` from earlier modules, so standalone it may find no input. Prefer `url`. | |
| **SSL/TLS** | domain or host | no dedicated TLS scanner (testssl/sslyze) ships upstream. Use `domain-lite` and read `Asset.tls` (httpx `-tls-grab -ztls`) plus nuclei `ssl` templates (findings with `asset_type=ssl`) from `url`/`domain-standard` | | cert expiry, issuer, SANs, TLS version, weak cipher templates. A full TLS grading product needs a **custom workflow** (for example testssl.sh -> custom JSONL import), uploaded once via the admin, not from WHMCS. |
| **Code / SAST** (optional) | git URL | `flow: sast` | | SARIF findings imported as vulns |

General rules: always set `space_name`; never set `skip_validation`. Prefer `gently`/`default` tactics for customer targets. Make authorization to scan a hard precondition in WHMCS (domain ownership via a DNS TXT or HTTP file, IP ownership attestation), because these tools generate attack-like traffic.

### 14.2 Polling strategy

1. `POST /runs` (one POST per target so that each gets its own `run_uuid` and `space_name`). Persist `job_id`, `run_uuid`, `space_name`, our deadline, and `submitted_at`.
2. A WHMCS cron hook (`AfterCronJob`, every 5 min) polls active scans:
   - `GET /runs/{run_uuid}`. On `404` within the first ~2 min, retry. If `job_id` is known, use `GET /jobs/{job_id}` to discover the uuid.
   - Back off by age: every 1 min for the first 10 min, then every 5 min, then every 15 min after 2 h. Stagger customers.
   - Progress % from `completed_steps/total_steps`. Use `updated_at` as a liveness heartbeat: if there is no change for more than 2 h while `running` (and `current_pid` is 0), mark it stalled and alert.
   - Enforce our own deadline per product (for example Quick 2 h, Standard 12 h, Deep 48 h): `DELETE /runs/{uuid}`, then mark it timed out locally.
3. Terminal states: `completed`, then ingest results; `failed`, then store `error_message` and decide on a retry (target-type errors are not retryable); `cancelled`, or `failed` with `context canceled` after our cancel, then mark cancelled.
4. Optionally configure the outbound webhook (section 10) to trigger an immediate poll.
5. Before starting new work, check `GET /stats` -> `runs.running` against our own cap.

### 14.3 Normalizing findings (Osmedeus to MC-Sec)

- Fetch everything: `GET /vulnerabilities?workspace=<space_name>&limit=1000&offset=...` until `offset >= pagination.total`.
- Per row:
  - `fingerprint = sha1(workspace|vuln_info|asset_value|matched-at)`. `matched-at` comes from `raw_vuln_json`, because Osmedeus dedupes on host only, which merges distinct URLs of the same template on one host.
  - `title = vuln_title ?: vuln_info`
  - `severity = map(strtolower(severity))`: `critical->critical`, `high->high`, `medium->medium`, `low->low`, `info|informational|note|unknown|'' -> info`, `error->high` and `warning->medium` (SARIF; UNVERIFIED)
  - `confidence = confidence` (default `firm`)
  - `asset = asset_value`
  - `category = asset_type` (`http`, `dns`, `ssl`, `network`, ...)
  - `references`, `cve`, `cwe`, `cvss`, `remediation`, `description`: from `raw_vuln_json.info.{reference,classification,remediation,description}`
  - `evidence = matched-at`, `extracted-results`, `curl-command`. Optionally store `detail_http_request` / `detail_http_response`, truncated to a few KB.
  - `first_seen = created_at`, `last_seen = last_seen_at`
- Customer-facing view: hide `info` by default, but count it. Exclude technology-detection templates (`tech-detect`, `waf-detect`, `*-detect` under severity info) from the "findings" list and show them under "technologies".
- Assets: split by `asset_type`:
  - `http`/`url`: services (`url`, `status_code`, `title`, `tech`, `host_ip`, `tls`, `is_cdn`/`is_waf`).
  - `ip` with `open_ports`: ports.
  - Subdomains: from the `final-subdomains` artifact file. There is no per-subdomain asset row for non-HTTP hosts. Parse the text file, one per line.
- Technologies: `GET /asset-stats?workspace=` for the distinct list, and `Asset.tech` per service.
- Store our own normalized copy in WHMCS DB tables (`mod_mcsec_*`). Osmedeus data keeps accumulating, and a workspace is not immutable.

### 14.4 Pitfalls checklist

- **Concurrency:** no server-side queue in local mode. Cap concurrent runs in WHMCS (start with 2 or 3 on one box and measure CPU, RAM and network). Note that `concurrency` only applies within one multi-target POST.
- **Long runtimes:** nuclei is capped at 8 h, and extensive flows can exceed a day. The `timeout` field is not enforced, so use our own deadline plus `DELETE`.
- **Asynchronous failures:** a 202 does not mean valid. Pre-validate targets (domain regex, punycode, CIDR size limit, no private ranges unless intended) and pick the flow that matches the target type.
- **Forbidden characters:** no spaces or `;'"|&$(){}[]` and backtick in any target or param value. Some workflow params (for example `nmapFlags`) cannot be overridden through the API.
- **Workspace merging:** without `space_name`, subdomains of one root domain merge into one workspace, and long targets get random workspace names. Always set it.
- **Multi-target job race:** `/jobs` totals grow over time. Compare against `target_count`.
- **Cancel overwrite:** a cancelled run may end up `failed` with `context canceled`.
- **Schedules:** may not survive restarts, and their runs are not tracked. Prefer the WHMCS cron.
- **Rate limiting:** the API has none, so keep our polling polite. Customer targets can rate-limit or ban the scanner IP. Use `gently` for fragile customers. `enableSYNScan` and full-port flows trip cloud-provider abuse detection, as the upstream workflow comment itself warns.
- **Disk usage:** workspaces (`~/workspaces-osmedeus`), the SQLite DB with stored HTTP responses, snapshots and screenshots. There is no workspace-delete API, so housekeeping needs a server-side cron (delete `~/workspaces-osmedeus/mcsec-*` older than N days, plus a DB purge via the `osmedeus db` CLI). Alternatively use one org per customer and `DELETE /orgs/{uuid}?purge=true` on termination (v5.1+). Snapshot export leaves zips in `{{base_folder}}/snapshot`; delete them after download.
- **Large payloads:** asset and vuln rows include raw JSON and HTTP bodies. Use `limit` 500 to 1000 and longer cURL timeouts for result fetches.
- **Security:** plain HTTP, a static all-powerful API key, unauthenticated `/ws/<prefix>/` file listing, and `/metrics` exposed. Keep the IP allowlist, add TLS, and never proxy raw Osmedeus URLs to customers.
- **Tool availability:** a flow fails if a declared binary (for example `vigolium`, `rustscan`, `nuclei`) is missing. Run `osmedeus health` on the server, and test each product once.
- **Version drift:** pin the Osmedeus version on the server. Check `/server-info` on module activation and warn if the version is not one we tested.

### 14.5 Open questions to verify with authenticated access

1. Exact version (`GET /server-info`), and whether `enabled_auth_api` is on and the API key works (`GET /osm/api/stats` with `x-osm-api-key`).
2. Installed workflows and their params (`GET /workflows?source=filesystem`). Are `fast`, `domain-lite`, `domain-standard`, `general`, `domain-extensive`, `cidr`, `url` present? Does `cidr-extensive` load?
3. `GET /workspaces?filesystem=true`: the `workspaces_dir` absolute path, needed for converting `artifact_path`.
4. Test runs on an owned domain and IP for each product: real runtime, CPU, RAM, disk per run, `total_steps` behaviour, and which artifacts and asset types appear.
5. Does `cidr` with a bare IP/CIDR target actually port-scan, or does it need an uploaded file target? Does `probe-port` inside `domain-standard` get any IP input?
6. After `DELETE /runs/{uuid}`, what is the final status: `cancelled`, or `failed` with "context canceled"? Are the child processes really gone (check `ps` on the host)?
7. Does `params.org_uuid` attribute new-workspace assets and vulns to the org?
8. Do API-created schedules fire after a server restart? Do schedule-fired runs appear in `/runs`?
9. Screenshot paths: the jsonl field names in `screenshot-json`, and whether `Asset.screenshot_base64_data` is ever filled.
10. Severity vocabulary from Vigolium and SARIF imports; the meaning of `vuln_potential`.
11. Which webhook events fire per flow, and in what order? (Source already confirms `notification.enabled: true` and per-webhook `enabled: true` are both required, and that `events` filters on `workflow_<status>`.)
12. The cron syntax accepted by `/schedules` (5 or 6 fields).
13. Network path: open the allowlist for the WHMCS server IP, and decide on TLS termination in front of :8811.
