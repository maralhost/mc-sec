# Frontend UI/UX & Design System Standards

**Version:** 1.0  
**Status:** Project policy — open-source-only phase  
**Scope:** New and existing software projects; standalone SaaS, public marketing websites, customer/admin applications and WHMCS integrations where applicable.  
**Audience:** Claude Code, frontend engineers, architects and reviewers.

## 1. Objective and applicability

Build a professional, consistent, maintainable and accessible UI using a shared, source-owned Design System and selected free, open-source libraries. Reuse components and patterns instead of rebuilding equivalent UI on each page or in each application.

This is a development standard, **not an instruction to restart, rewrite or migrate an existing project immediately**. Preserve working features and respect the project's existing stack, requirements and architecture. Apply the relevant sections only: a project without WHMCS, marketing pages, SEO or AI functionality must not acquire those features or dependencies merely because they appear in this document.

The mandatory policies are: open-source licensing, controlled migration, component reuse, accessibility, security, testing and durable project instructions. The recommended architecture and optional libraries are defaults for suitable projects, not unconditional installation requirements. If a project-specific instruction conflicts with this document, identify the conflict and request a decision before making consequential changes.

## 2. Adoption procedure for an existing project

### Phase 0 — Read-only assessment (default first task)

1. Read existing `CLAUDE.md`, `.claude/rules/`, architecture documents and repository conventions. Inspect the Git working tree, branches, manifests and lockfiles. Do not revert, stash, overwrite or commit existing user changes.
2. Identify frontend frameworks, build systems, routing, CSS frameworks and versions, UI libraries, component hierarchy, theming, authentication, API contracts, and deployment environments.
3. Inventory existing public, customer, admin and embedded surfaces, reusable components, legacy dependencies, accessibility and RTL/LTR support. Identify existing tests and known failures. Do not assume a specific WHMCS theme or version.
4. Compare the current stack with this standard. Classify existing components and pages as **Keep / Adapt / Replace / Defer**. Record license issues, duplication, compatibility risks, effort, dependencies and rollback options.
5. Propose the smallest practical migration, including the first representative vertical slice and measurable acceptance criteria. Include a list of proposed installations, replacements and removals, with reasons and licenses.
6. Return the assessment and implementation plan. **Stop and request approval before modifying files, installing packages, changing architecture or starting implementation**, unless the user explicitly authorizes a narrower action in the current request (e.g. saving this policy and linking it in `CLAUDE.md`).

### Phase 1 — Foundation (after approval)

- Establish a safe baseline and a rollback plan. Agree on a branch/checkpoint if needed. Do not commit or push changes without authorization.
- Run existing checks and record pre-existing failures. Preserve API contracts, data models, business logic, permissions, authentication, routes and service behavior.
- Integrate the core Design System into the existing framework when compatible. If the project is not React/Tailwind-based, propose a compatible adaptation or phased migration; do not install a second stack blindly.
- Establish shared tokens, UI primitives, a component inventory, documentation and lint/test conventions. Install only dependencies required for the approved scope.

### Phase 2 — Pilot and validation

Migrate or implement one representative screen first (for example a dashboard with table and charts). Where applicable, also validate one marketing page and one WHMCS embedded view. Use realistic fixtures; never expose production customer data. Test feature parity, visual consistency, performance, accessibility, RTL/LTR, responsive behavior and existing integration contracts. Obtain approval before broad rollout if the pilot reveals architectural changes or new risks.

### Phase 3 — Incremental rollout

- New features use the approved Design System by default. Existing compatible components are retained and normalized.
- Migrate legacy screens feature by feature, prioritized by user impact, risk and development activity. Avoid project-wide cosmetic churn or duplicate UI systems without a transition plan.
- Delete legacy libraries only when their last consumer has been removed and regression tests pass. Maintain lockfiles, release notes and documented rollback steps.
- Do not change backend or database architecture, auth, billing, routing or core workflows merely to implement a visual redesign. Any necessary contract change requires a separate justification and approval.

## 3. Licensing and dependency policy (mandatory)

During this phase, add only free, open-source UI code and dependencies that permit the intended commercial use, modification and distribution. Prefer MIT, Apache-2.0, BSD and ISC. Other licenses, especially reciprocal/network-copyleft or nonstandard terms, require explicit review and approval. A free trial, free commercial tier, free account, source-available package or free MCP access is not proof of an open-source license.

- No paid Pro, Premium, Enterprise, commercial-only templates, copied proprietary snippets, or license-restricted blocks without explicit owner approval. Do not bypass paywalls, registration requirements or license checks.
- Verify the actual repository, version, package and block license before installation or copying. Check applicable notices, assets, icons, fonts, examples, transitive dependencies and distribution obligations, particularly for WHMCS modules shipped to third parties.
- Record each approved dependency/component source, version or commit, SPDX license (or exact terms), purpose and notices in `docs/frontend/APPROVED_LIBRARIES.md` or the existing equivalent. Retain required copyright and attribution notices. Treat unknown or incompatible licenses as a blocker for new additions.
- If an existing dependency is outside this policy, report it; do not automatically uninstall it or break existing behavior. Propose a remediation plan.
- Prefer official repositories and package names. Review third-party registry source before running installers or importing code. Pin compatible versions and use the existing package manager and lockfile. Do not upgrade unrelated dependencies.
- Add an appropriate dependency/license check in CI when approved; include manually copied registry code in the inventory because package scanners may not detect it. Review new dependencies rather than relying on a scanner alone.
- OSS UI policy does not authorize or forbid existing business services by itself. Hosting, SEO datasets, map tiles, AI models and other external services have separate costs and terms. Do not sign up for or add a paid service without approval.

## 4. Approved core UI ecosystem

| Project | Role | Adoption rule | Official source |
|---|---|---|---|
| shadcn/ui | Primary Design System and reusable UI primitives | Default for compatible React projects; reuse source-owned components | https://ui.shadcn.com/ · https://github.com/shadcn-ui/ui |
| ReUI | Advanced UI, data grids, filters, patterns | Only verified OSS components; import selectively | https://reui.io/ · https://github.com/keenthemes/reui |
| Tailark | Marketing blocks and public SaaS pages | Only verified OSS blocks; no commercial sections | https://tailark.com/ · https://github.com/tailark/blocks |
| Shadcn Admin | Dashboard shell and implementation reference | Reference/starter only; do not overwrite existing applications or inherit unrelated auth/billing | https://github.com/satnaing/shadcn-admin |
| Tailwind CSS | Styling and responsive design | Match compatible version; avoid global collisions | https://tailwindcss.com/ |
| Lucide | Consistent icon system | Use one primary icon family | https://lucide.dev/ |

This table is a preferred-source list, not a blanket license determination for every version or artifact. Verify the actual code and license at adoption time. Maintain one compatible primitive family (e.g. Radix UI or Base UI) by default; assess any required mixing rather than indiscriminately adding both.

### Component selection hierarchy

1. Existing shared, compliant internal component or pattern.
2. shadcn/ui for foundational UI.
3. ReUI OSS for advanced application patterns, or Tailark OSS for public marketing blocks.
4. An approved specialist library when a genuine functional gap exists.
5. Custom code when available components cannot satisfy the requirement, with a brief rationale.

Before writing a component, search the existing repository and the relevant official registry. Do not duplicate components under different names, copy an entire template unnecessarily, or introduce a competing Design System (e.g. MUI, Ant Design, Bootstrap) into a shadcn-based application without approval. Existing host applications such as WHMCS may retain their own UI libraries.

## 5. Optional specialist libraries (install on demand)

| Library / tool | Intended purpose | Official reference |
|---|---|---|
| TanStack Table + TanStack Virtual | Headless data grid, filtering, virtualization | https://tanstack.com/table/latest · https://tanstack.com/virtual/latest |
| TanStack Query | API/server-state caching and mutations | https://tanstack.com/query/latest |
| Apache ECharts | Advanced charts, heatmaps, treemaps, graphs | https://echarts.apache.org/ |
| Tremor OSS | Select analytics cards/widgets; avoid redundant chart stacks | https://www.tremor.so/ |
| React Flow Core (@xyflow/react) | Interactive node graphs and workflows | https://reactflow.dev/ |
| Tiptap Core | Rich text/content editor; exclude paid extensions | https://tiptap.dev/ |
| AI Elements | UI for AI conversations, streaming and tool output | https://ai-sdk.dev/elements/overview |
| React Grid Layout | Drag/resize dashboard widgets | https://github.com/react-grid-layout/react-grid-layout |
| FullCalendar Standard | Calendar; exclude premium plugins | https://fullcalendar.io/ |
| dnd kit | Accessible drag/drop where needed | https://dndkit.com/ |
| MapLibre GL JS | Map visualization; map data/tiles are separately licensed | https://maplibre.org/ |
| React Hook Form + Zod | Forms and runtime schema validation | https://react-hook-form.com/ · https://zod.dev/ |
| Zustand | Client state only when local state is insufficient | https://zustand.docs.pmnd.rs/ |
| i18next | Internationalization; retain suitable existing solution | https://www.i18next.com/ |
| Storybook | Component documentation and interaction examples | https://storybook.js.org/ |
| Vitest + Playwright | Unit/component and end-to-end testing | https://vitest.dev/ · https://playwright.dev/ |
| Scalar | Optional API documentation UI | https://scalar.com/ |

Use the free OSS edition/code only. For each need, select the smallest viable set; for example, prefer one main chart engine, one table abstraction and one form/state strategy. Do not add a second library merely because it is listed here. OSS replacements for commercial grids or editors may require additional engineering, which must be scoped explicitly.

## 6. Architecture recommendations

For greenfield or compatible React-based multi-surface SaaS projects, prefer TypeScript, React and Tailwind, with a shared component layer. Next.js is a suitable default for public SSR/SSG pages; React + Vite is a suitable default for authenticated applications and static embedded builds. An existing Next.js application may serve both public and authenticated routes, and an existing viable stack need not be split into new apps. Choose the fewest deployable units needed.

For projects with multiple applications, use a workspace/monorepo (e.g. pnpm workspaces; Turborepo only when justified). Do not reorganize a repository solely to match this example. Preserve existing conventions and package manager unless an approved migration warrants change.

```text
apps/
  marketing/             # public site, if applicable
  dashboard/             # standalone customer app, if applicable
  admin/                 # only if a separate app is warranted
  whmcs-embed/           # optional embedded entry/build
packages/
  ui/                    # shared foundational components
  design-tokens/         # semantic themes, typography, spacing
  domain-components/     # reusable product-specific UI/features
  marketing-blocks/      # shared public blocks where useful
  api-client/            # typed API contracts and adapters
  i18n/                  # shared locales and formatting
integrations/
  whmcs/                 # optional PHP/Smarty integration
```

Keep generic UI independent of backend details, routing and WHMCS-specific APIs. Use feature components for domain logic and host adapters for authentication, routing, feature flags and theme context. Share typed API contracts, data-fetching patterns and feature screens where feasible. Keep authorization and tenant isolation enforced by the backend; UI restrictions are not security boundaries.

If a project has a single application, ordinary folders are sufficient. Extract a separate reusable package or cross-project private registry only after genuine reuse needs justify its maintenance and governance costs.

## 7. Design System and UI quality (mandatory for applicable UI)

- Centralize semantic tokens: background, surface, text, border, accent, focus, chart palette, status/severity, typography, spacing, radius and elevation. Use CSS custom properties and consistent theme mapping. Avoid hardcoded brand colors and arbitrary one-off styling except documented visual data needs.
- Provide coherent light/dark themes where required, responsive layouts, language-aware RTL/LTR, standard iconography, consistent navigation and typography. Use logical CSS properties and appropriate direction handling for numbers, URLs, IPs and mixed-language text. Localize dates, currency and numerical formatting appropriately.
- Standardize button, form, select, dialog, drawer, tooltip, tabs, table, chart, filter, date picker, notification, pagination, breadcrumb, sidebar and application-shell patterns. Define loading/skeleton, empty, partial-data, error, retry, offline/stale and success states where meaningful.
- Aim for WCAG 2.2 AA: semantic HTML, keyboard navigation, visible focus, correct labels, contrast, reduced motion, accessible dialogs and alternatives to color-only encoding. Use appropriate chart summaries or data-table alternatives.
- Design for real workflows, especially desktop data-dense applications: clear hierarchy, compact tables, predictable actions, efficient filters, sensible mobile behavior and consistent layouts. Avoid excessive gradients, animation, decorative cards and unnecessary whitespace.
- Distinguish marketing layouts from application layouts while sharing tokens and compatible primitives. Do not force marketing blocks into operational screens.
- Define brand and host theme adapters where required. Do not hardwire a particular company name or color scheme into generic components.
- Use Ahrefs/Semrush as references for information density and tool organization, Linear for navigation, Vercel for analytical clarity and Stripe for SaaS settings where relevant. Do not copy proprietary assets or exact interfaces.
- Add reusable variants through typed interfaces, not page-level forks. Document usage and examples; test key interactions and visual states. Avoid unnecessary abstractions for one-off features.

## 8. Public website / SaaS marketing (if applicable)

Use shadcn/ui with verified Tailark OSS blocks for public pages. Develop a distinct product identity, not an untouched template. Plan reusable hero, features, pricing, comparison, CTA, FAQ, testimonials, documentation/blog and integration blocks. Add pages relevant to the product: home, features/tools, solutions, pricing, integrations, resources, help, authentication and legal pages as needed. Do not invent product claims, testimonials, metrics or legal terms.

- Prefer pre-rendered or server-rendered indexable content where appropriate, semantic headings, unique metadata, canonical URLs, locale/hreflang when relevant, sitemap, robots configuration, social metadata and valid structured data.
- Protect authenticated/private routes; `noindex` is not access control.
- Optimize images, fonts, JS payload, layout stability and Core Web Vitals; lazy-load heavy application code and avoid shipping dashboard dependencies to every public page.
- Validate mobile layout, keyboard access, forms, metadata and public route behavior. Reuse actual design tokens and components across the marketing site and application.

## 9. Data-intensive applications (SEO, security, monitoring, analytics, etc.)

Use ReUI OSS/TanStack for tables and Apache ECharts for specialist visualizations when appropriate. Build a shared table/grid interface and chart conventions; choose capabilities according to the actual dataset and user workflow.

- For large datasets, support server-side pagination/cursors, sorting, filtering, search, and aggregation as needed. Use virtualization where appropriate; do not fetch millions of rows into the browser. Validate server-side filter fields and limits, prevent expensive uncontrolled queries, and preserve stable row IDs and cache isolation per tenant.
- Provide relevant column visibility, resize, pinning, saved views, date comparison, bulk actions, selection semantics and clear loading/errors. Distinguish current-page selection from selection of all matching records. Confirm destructive bulk operations.
- Use server-side jobs for large exports with access controls, quotas, auditability and safe CSV/Excel handling (including formula-injection protection). Do not claim that a headless grid provides enterprise features automatically.
- Use clear units, time zones, legends, tooltips, metric definitions, freshness/coverage and missing-data indications. Prefer backend aggregation/downsampling for high-cardinality/time-series charts. Provide alternatives for accessibility and avoid misleading axes.
- Use React Flow only for genuinely interactive graphs/workflows; use Tiptap for editor needs; use AI Elements when an AI interface is required. Sanitize untrusted content and rendered AI output, and handle streaming cancellation, errors and citations where applicable. Never put privileged API keys in frontend code.

### SEO-specific component examples (only for SEO projects)

Keyword Research / Difficulty / Search Volume; Rank Tracker and SERP History; Backlinks; Domain and Competitor Comparison; Site Health and Audit Issues; Severity Indicators; Traffic Analytics; Keyword Clusters; Internal Linking Graphs; Content Score and Editor; Project/Workspace Switcher; Advanced Filters and Saved Views; Report Builder; Usage/Quota and Subscription UI. Create these incrementally as the associated features are implemented, not as empty placeholders for the entire roadmap.

## 10. WHMCS integration (only for applicable projects)

Preserve WHMCS as a sales, billing and service lifecycle integration where this is the agreed architecture. An independent product backend retains its domain data and logic. Do not create a second copy of feature logic or business data in WHMCS solely for the embedded UI.

### Recommended presentation model

Use a shared React feature application mounted in an authorized WHMCS Addon page (PHP/Smarty supplies the shell and approved assets). Build static JS/CSS assets with Vite or the existing compatible bundler. A standalone application can reuse the same feature components via a different host adapter. Provide SSO/deep-link navigation to the full standalone application when appropriate. Consider SSO-first or iframe only after assessing the actual hosting/theme constraints; avoid duplicate native Smarty implementations of complex React features. Existing WHMCS-native simple views may remain if that is the safest approach.

### CSS, runtime and packaging

- Mount inside a dedicated root element. Scope design tokens, selectors and resets; disable or isolate Tailwind Preflight in the embedded build and consider a utility prefix. These measures alone do not fully isolate Bootstrap/theme CSS; test host rules, dialogs, focus, portals, popovers, stacking contexts and responsive widths. Configure portal containers appropriately. Evaluate Shadow DOM only if required and compatible.
- Preserve the host header/sidebar, theme and session; avoid global CSS/JS changes, conflicting Bootstrap/jQuery behavior, duplicate React roots, or leaking styles into unrelated WHMCS pages. Use a host-aware router (base path/hash or adapter) without breaking refresh/deep links or existing routes.
- Serve versioned local assets via a verified manifest and correct module paths. Load only on relevant pages. Verify content security policy, asset cache, upgrade/rollback, WHMCS version and actual Client/Admin themes. No Node.js runtime on WHMCS is needed for a purely static build, but build tools may run in CI.

### Auth, tenancy and lifecycle

- Validate the WHMCS session and service ownership server-side. Use trusted server-to-server mapping and an approved session/token exchange with short-lived, audience-scoped credentials; no privileged backend or WHMCS API secret in browser code. Do not place tokens in URLs or logs. Evaluate CSRF, cookie scope/SameSite, CORS, replay prevention, expiration and logout for the chosen deployment.
- Enforce backend RBAC, tenant/workspace isolation, entitlements, quotas and service state on every relevant request; never trust browser-supplied account IDs or role claims alone. Keep admin and client operations distinct.
- Use Addon Module for client/admin UI and integration settings where appropriate; Provisioning Module for supported lifecycle actions (create, suspend, unsuspend, terminate, package changes) where appropriate. Handle asynchronous failures, idempotency, retries, reconciliation and audit logging. Billing renewals/entitlement synchronization depend on actual WHMCS hooks and product contracts; verify rather than invent callbacks.
- Confirm module deployment on supported WHMCS/PHP versions, customer/admin permissions, theme compatibility, SSO and billing/lifecycle behavior. If no live test environment is available, report unverified items explicitly.

Official documentation: https://developers.whmcs.com/ (verify the actual supported version and APIs).

## 11. Claude Code and component registry

- Prefer official shadcn documentation/registry and the verified OSS ReUI/Tailark registries. MCP may be used if supported by the environment, necessary and approved. Consult current official installation instructions and repository/package compatibility: https://ui.shadcn.com/docs/mcp and https://ui.shadcn.com/docs/registry.
- MCP access or a registry listing does not authorize paid blocks or unreviewed code. Review source, dependencies and licenses before importing. Do not install unrelated MCP servers or grant broad permissions. Do not store credentials in tracked `.mcp.json` or other repository files.
- Maintain a local component catalog (e.g. Storybook or documentation). Use a private shadcn-compatible registry only when useful across applications/projects; protect access, review published code and version changes. Record provenance for copied registry components.
- Before generating UI, inspect shared components and use documented patterns. After changing a shared component, check its consumers. Document exceptions and avoid guessing unsupported library APIs.

## 12. Persistent repository instructions

After approval, save this file in `docs/frontend/FRONTEND_UI_STANDARDS.md` (or the project's established equivalent). Update rather than replace existing instructions. Use one canonical policy document; avoid multiple conflicting copies.

Recommended artifacts (adapt names and scope to the repository):

```text
CLAUDE.md                         # short project-wide mandatory rules + reference
.claude/rules/frontend.md         # scoped frontend conventions and policy reference
.claude/rules/whmcs.md             # only for WHMCS projects, if useful
docs/frontend/
  FRONTEND_UI_STANDARDS.md        # this canonical policy
  APPROVED_LIBRARIES.md           # real dependency/source/license inventory
  DESIGN_SYSTEM.md                # implemented tokens, components, themes
  COMPONENT_GUIDELINES.md         # usage and composition patterns
  MIGRATION_PLAN.md               # audit, phases, risks and acceptance criteria
  WHMCS_INTEGRATION.md            # only where relevant
```

Example concise rules for the root `CLAUDE.md` (merge with existing instructions; use the actual file path):

```markdown
## Frontend policy
- Follow `docs/frontend/FRONTEND_UI_STANDARDS.md` for all UI/UX work.
- Use only approved free OSS UI code; check actual licenses and component sources.
- Reuse shared internal UI first, then shadcn/ui, ReUI OSS or Tailark OSS as appropriate.
- Install specialist dependencies only when required and approved by the project policy.
- Preserve existing features and contracts; do not perform broad migrations without approval.
- Verify accessibility, theming, RTL/LTR and relevant regression/build checks.
- For WHMCS integrations, preserve CSS isolation, backend authorization and host behavior.
```

If supported, use path-scoped `.claude/rules/` for actual frontend/integration paths, and keep the mandatory policy reference in root instructions. Ensure Claude actually reads the canonical policy when working on UI (an appropriate local import or explicit read instruction may be used according to current Claude Code documentation). Do not assume that adding a Markdown file to the repository automatically makes Claude obey it. Keep instructions concise and avoid redundant context. Verify the policy is loaded in a new session; follow existing repository conventions. Official Claude Code docs: https://code.claude.com/docs/en/memory.

## 13. Quality gates and Definition of Done

For each approved UI change, as applicable:

- [ ] Existing behavior, permissions, API contracts and relevant workflows preserved.
- [ ] Shared components/tokens reused; new reusable components documented; no unjustified duplicate UI system.
- [ ] New dependencies and imported blocks verified as approved OSS, provenance and required notices recorded.
- [ ] Responsive, keyboard, accessibility, light/dark and RTL/LTR behavior checked as required by the project.
- [ ] Loading, empty, error, retry and realistic data states handled.
- [ ] Large datasets use appropriate server-side data handling; no avoidable rendering or network bottlenecks.
- [ ] No secrets or sensitive data exposed; tenant and role enforcement verified for relevant flows.
- [ ] Existing build, lint, type-check and targeted tests run; regression and integration checks run for affected paths. Report exact commands and results, including pre-existing failures and untested cases.
- [ ] Where applicable, verify public metadata/SEO or actual WHMCS theme/runtime/SSO compatibility.
- [ ] Changes are documented with migration/rollback considerations where relevant.

Do not weaken existing tests, suppress legitimate errors or claim a test was run when it was not. If a dependency, test environment, backend endpoint or supported version is unavailable, identify it as a blocker and provide a bounded next step.

## 14. Required first response from Claude Code

Unless the user explicitly approves implementation, respond with a read-only assessment in this structure:

1. Current architecture and applicable sections of this standard.
2. Inventory of existing UI, dependencies, surfaces and known license/compatibility issues.
3. Keep / Adapt / Replace / Defer matrix.
4. Proposed minimal architecture and core/optional dependencies (exact sources and verified licenses; mark unresolved items).
5. Phased implementation plan, first pilot screen, estimated relative effort, risks, regression checks and rollback strategy.
6. Decisions requiring owner approval, including any proposed migration or paid/nonstandard dependency.
7. Files to be created or modified and explicit statement that no unauthorized implementation has started.

Following approval, implement only the authorized phase and report changed files, installed/removed dependencies, verified licenses, test results, remaining limitations and next recommended action. This policy remains in effect for subsequent frontend work until the owner explicitly revises it.
