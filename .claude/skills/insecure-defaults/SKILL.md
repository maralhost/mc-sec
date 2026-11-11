---
name: insecure-defaults
description: "Audit a file, directory, or whole repo for insecure default configuration: fallback secrets, default credentials, fail-open switches, weak crypto, permissive access, debug leakage. Parallel sweeps collect candidates, then a refuting verifier traces each one to the security decision it reaches before it is reported. Runs a multi-agent workflow (about 10-25 agents, verifiers on Opus), so it is invoked only by hand."
argument-hint: "[path]"
disable-model-invocation: true
allowed-tools: Bash(ls:*) Workflow
---

<!-- Adapted from trailofbits/skills plugins/insecure-defaults/commands/audit.md (CC BY-SA 4.0) for a manual
     project install: ${CLAUDE_PLUGIN_ROOT} became this skill's base directory, the named plugin workflow
     became a scriptPath, and the PHP notes in step 4 were added for Raya (reused as-is in MC-Quality and MC-AI). -->

# Insecure defaults audit

Below, `BASE` is this skill's base directory as an absolute path with forward slashes and no trailing
slash (for example `C:/…/MC_AI/.claude/skills/insecure-defaults`).

**1. Check the corpus is there.**

```
ls -1 "BASE/references"
```

Must list `*.md` files. If it errors or lists none, **stop and say so**. Don't search
elsewhere, don't guess, don't run the audit anyway.

**2. Run it.** `Workflow` tool:

```
scriptPath: "BASE/workflows/audit.js"
args: { scope: "$ARGUMENTS" or ".", pluginRoot: "BASE" }
```

For MC-AI, prefer the scope `modules/addons/mcai` so `tests/` (fake secrets and fixtures) is not swept.
Always check the New API admin token, the WHMCS-side rate source and the credit path for fail-open defaults.

**3. Print the result**, by `status`:

- `findings`, `no-findings-confirmed`: print `report`.
- `no-candidates`: the sweeps ran and matched nothing, which is a real result. There is
  no `report`; print `note`, including its point that this is not proof of absence.
- `report-failed`: the audit completed but the write-up died. Print `note`, then present
  `findings`, `refuted` and `coverage` yourself.
- anything else: the audit **didn't complete**, so it isn't a clean result. Print `note`
  and say the run failed.

**4. PHP gap check.** The seed patterns are written for Python, JS, Java, Ruby and Go. Look at the
`seed_only_sweeps` and `patterns_run` coverage lines; if the PHP forms below were not covered, grep for
them yourself in the same scope and report any hit that reaches a security decision:

- defaults on secrets and switches: `getenv('…') ?: '…'`, `$_ENV['…'] ?? '…'`, `?? ''` on keys or tokens,
  `Settings::get('…', <non-empty default>)` for API keys, budgets, rate limits or the guest mode switch
- array config with literal secrets: `'password' => '…'`, `'api_key' => '…'`, `'token' => '…'`
- TLS off: `CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => 0`, `'verify' => false`
- leaking errors: `$e->getMessage()` or `getTraceAsString()` returned to the client API or the widget
