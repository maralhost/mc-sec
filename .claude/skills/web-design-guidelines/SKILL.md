---
name: web-design-guidelines
description: Review UI code for Web Interface Guidelines compliance. Use when asked to "review my UI", "check accessibility", "audit design", "review UX", or "check my site against best practices". For MC-Team, run mcteam-rtl-review first.
argument-hint: <file-or-pattern>
metadata:
  author: vercel
  version: "1.0.0"
---

<!-- Adapted from vercel-labs/agent-skills skills/web-design-guidelines (MIT). Upstream fetches the rules
     from the unpinned main branch on every run; here they are vendored in guidelines.md, copied from
     vercel-labs/web-interface-guidelines command.md at commit 434b7f9 (2026-10-05), MIT
     (LICENSE-web-interface-guidelines). Do not fetch them from the network. -->

# Web Interface Guidelines

Review files for compliance with Web Interface Guidelines.

## How It Works

1. Read the rules from [guidelines.md](guidelines.md) in this folder. They contain all the rules and the output format.
2. Read the specified files (or prompt user for files/pattern)
3. Check against all rules, minus the MC-Team exceptions below
4. Output findings in the terse `file:line` format

If no files specified, ask the user which files to review. MC-Team keeps CSS and JS inside the module (no CDN). Paths are under `modules/addons/mcteam/`:
- client area (Lagom2): `lib/Client/*.php`, `lib/Client/client.css`, `lib/Client/client.js`, and the client hooks in `hooks.php` and `lib/Hooks.php`
- admin pages: `lib/Admin/*.php`
- e-mail HTML: the notices sent with `SendEmail` (`lib/Notify.php`)

## MC-Team exceptions

MC-Team is vanilla JS and CSS inside WHMCS 9.0.9 and 9.1 pages (admin panel, and the Lagom2 client area), entirely in Persian (RTL). Skip or reinterpret:

- **React, Next.js and Tailwind rules:** `onKeyDown` props, `<Link>`, `htmlFor`, `spellCheck={…}`, `autoFocus`, `priority`, `virtua`, render-phase layout reads, controlled inputs, `useState`/nuqs, the whole Hydration section and Tailwind class names. Apply the underlying intent to plain DOM code where it still makes sense.
- **Host-page rules:** do not touch the host's `<html>`, `<meta>` (`color-scheme`, `theme-color`), skip links or heading hierarchy. The module is a guest on WHMCS pages. CLAUDE.md forbids editing Lagom2 template files; client-area changes go only through hooks and CSS scoped to the module (`.mct` / `mct-` classes in the client area, `.mcta` in the admin panel).
- **State in the URL:** the page route and filters may live in the URL, but never tokens, or amounts and permissions that the server must re-check.
- **Persian copy:** quotes are « », not “ ”. There is no Title Case (the script has no letter case). Write «و», not `&`. Use «…», not "...". Persian digits and Jalali dates via the module helpers; Latin digits only inside e-mail addresses, domains and host names.
- **Toasts and inline updates:** announce the result of an AJAX action (invite sent, share given, team services saved) once, not on every keystroke.
- **Simplicity first:** the founder's top priority is ease and simplicity at every level. Prefer the fix that removes a step over one that adds a control.

Direction, bidi, Persian typography, digits and RTL accessibility are not covered by these guidelines. That is what `mcteam-rtl-review` is for.
