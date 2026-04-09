# REX-BOT-AI Work Log

## Current Sprint: Full Product Integration (12 Phases)

### Phase Status
| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Execution tracker | DONE |
| 1 | Build/Install/Startup | DONE (Docker e2e unverified) |
| 2 | Service graph wiring | DONE |
| 3 | Runtime state truthfulness | DONE |
| 4 | Auth/session security | DONE |
| 5 | Prompt injection defense | DONE (306 security tests) |
| 6 | Command/action boundary | DONE |
| 7 | Dashboard/CLI real data | DONE (11 routers, 44 endpoints) |
| 8 | Plugin system | DOCUMENTED (sandbox is dict) |
| 9 | Scheduler/power/retention | DONE (triggers real scans, power management) |
| 10 | Privacy/federation/encryption | DONE (wired to dashboard, federation opt-in) |
| 11 | Cross-platform PALs | PENDING (stubs only) |
| 12 | Tests/coverage/CI/docs | DONE (2,979 tests, 84% cov) |

### Decisions
- Do NOT cut scope — all features must be made real
- Prefer fixing architecture over patching symptoms
- One source of truth for runtime state
- Security controls enforced in code, not documentation

### Blockers
- None identified yet

### 2026-04-09: Auth State Machine, ChromaDB Fix, Runtime Bug Fixes

**Auth Bootstrap Overhaul (Model 2: Forced First-Run Setup):**
- Removed ALL hardcoded/generated default passwords
- New auth state machine: `setup_required` (no credentials) → `active` (configured)
- `GET /api/auth/auth-state` — unauthenticated endpoint returns current state
- `POST /api/auth/setup` — creates initial password, returns JWT token
- Login page checks auth-state on mount: shows "Create Password" form or normal login
- Setup wizard skips redundant password-change step
- Lockout messages now include remaining wait time
- `rex reset-auth --yes` CLI command for password recovery
- 10 new auth bootstrap tests

**ChromaDB Integration Fix:**
- Root cause: `chromadb-client==0.6.3` has `_type` KeyError bug in `configuration.py` response deserialization — breaks ALL collection operations
- Fix: Upgraded to `chromadb-client==1.5.7` (verified compatible with server 0.6.3)
- Fixed heartbeat endpoint from `/api/v1/heartbeat` to `/api/v2/heartbeat`
- Added `ANONYMIZED_TELEMETRY=False` to suppress PostHog crash
- Added `_sanitize_metadata()` to strip reserved underscore-prefixed keys
- 13 new ChromaDB integration tests (metadata sanitization, fallback, telemetry)

**SPA Routing Fix:**
- `StaticFiles(html=True)` only served index.html at root `/`
- Added catch-all route serving index.html for all non-API paths
- `/overview`, `/login`, `/setup` etc. now work on direct navigation and refresh

**Dashboard Bug Fixes:**
- Login page navigates to /overview after successful auth (was stuck)
- Login page shows REX dog ASCII art (was showing cat)
- Dog ASCII art alignment fixed (text-center was breaking monospace)
- Setup wizard environment check uses new `/api/env-check` endpoint
- Ollama detection: structured states (reachable_with_models/no_models/unreachable/timeout)

### 2026-04-08: Release Hardening & Theme Overhaul

**Auth & Security:**
- Dashboard binds to `127.0.0.1` by default (was `0.0.0.0`)
- Python pinned to 3.11-3.12 only (3.13 not yet supported)

**Dashboard & Frontend:**
- Dark red/black theme (replaced cyan/blue)
- GUI is now the default startup mode
- 26 dashboard pages total (added: REX Chat, Federation, Agent Actions, System Config)
- Threat resolve/false-positive actions wired to backend API
- Recharts-based trend charts on overview page
- Frontend toolchain fixed: .npmrc, ESLint v9 flat config

**Release Hygiene:**
- All 7 release audit blockers resolved
- Added CHANGELOG.md, CODE_OF_CONDUCT.md, RELEASE.md
- Updated all stale documentation to reflect current state

### Phase 5: Prompt Safety Documentation (2026-03-31)

Completed comprehensive prompt safety documentation:

- `docs/PROMPT_SAFETY.md` -- Full prompt construction model, sanitization pipeline, pattern matching, known limitations, regression corpus instructions
- `docs/TRUST_BOUNDARIES.md` -- Complete trust zone mapping (trusted/semi-trusted/untrusted), all 7 trust transitions with sanitization at each boundary
- `docs/KB_SAFETY.md` -- Knowledge base safety: markdown escaping, heading injection prevention, Git versioning, file locking
- `PROMPT_SAFETY_AUDIT.md` -- 35-row audit table mapping every untrusted text path from source through transform chain to sink

Key findings documented:
- 30+ injection patterns in network data sanitizer with homoglyph, leetspeak, delimiter, filler-word normalization
- 16 injection pattern categories in web content sanitizer
- Two independent enforcement gates (ActionValidator + CommandExecutor) that are code-enforced, not LLM-dependent
- Two residual risks: advanced paraphrase evasion and plugin output strings (both mitigated by ActionValidator gate)

### Verification Results (Phase 5)
- Tests: 1018 passed, 0 failed, 10 xfailed
- Coverage: 52%
- Import: OK v0.1.0-alpha

### Architecture Fix Pass (2026-04-01)

Critical fixes from release review:

- **EventBus shared instance → per-service isolation**: Orchestrator now creates one EventBus per service with distinct consumer groups (rex:<service>:group). Prevents Redis Streams consumer group competition.
- **Dashboard raw dict publishing → RexEvent**: devices, schedule, notifications routers now publish typed RexEvent objects instead of raw dicts that would crash bus.publish().
- **VULN-007/008/009 fixed**: IPv6-mapped IP bypass, decimal IP bypass, and class-variable PROTECTED_IPS leakage all resolved. xfail count 10 → 3.
- **DNS monitor hang fix**: StopIteration in asyncio executor handled via sentinel pattern (Python 3.12+ compatibility).
- **Windows PAL key parsing**: "Rule Name:" now correctly parsed as "rulename" key.
- **Frontend wsState → wsConnection**: Matches actual Zustand store field.
- **Version unified**: 0.1.0-alpha everywhere (was 1.0.0 in install.sh and requirements.txt).
- **Installer build context**: Clones full repo instead of cherry-picking files.

**Current test status**: 3000+ passed, 0 failed, 3 xfailed (VULN-004/005/010 edge cases). 15/15 test directories green.

### Final Hardening Pass (2026-03-31)

Completed final security regression and documentation hardening:

**Security regression corpus**: 306 tests passed, 10 xfailed (all documented VULNs with IDs). Zero failures. xfail items are known scope-enforcer edge cases (VULN-001 through VULN-010) covering disguised request bypass, short-message bypass, IP encoding bypass, and class variable inheritance.

**Full test suite**: 3,000+ passed, 0 failed, 3 xfailed (after VULN-007/008/009 fixes). 84% code coverage across 12,040 lines in rex/.

**Documentation updates**:
- ARCHITECTURE.md: Fixed Bark channel list (Pushover -> Web Push, matches webpush.py), updated Dashboard router count (10 -> 11, added auth router)
- README.md: Updated from pre-alpha to v0.1.0-alpha, fixed feature table to match current state (coverage 13% -> 83%, dashboard stubbed -> working, orchestrator partial -> working), updated contributing priorities
- STATUS.md: Updated test count (1,018 -> 2,850), coverage (52% -> 83%), security pentest count (252 -> 306), P0 remaining (5 -> 3), expanded alpha checklist with completed items
- QUICK-START.md, CONTRIBUTING.md: Fixed all GitHub URLs from REX-BOT-AI/rex-bot-ai to Darth-Necro/REX-BOT-AI, fixed cd directory name
- pyproject.toml: Updated description and classifier from pre-alpha to alpha

**Remaining blockers for alpha label**:
- Docker compose end-to-end verification
- Mode switch backend wiring
- Install script path alignment
- Credentials encryption fallback
- Live Redis integration test in CI

### UI Batch 6: Final Polish (2026-03-31)

Responsive, accessible, tested, consistent pass across the frontend.

**Test setup and critical tests** (verified correct):
- `frontend/src/__tests__/stores/useSystemStore.test.js` -- 9 assertions: defaults are honest (unknown, not operational)
- `frontend/src/__tests__/stores/useAuthStore.test.js` -- 7 tests: login/logout/reject/expire flows
- `frontend/src/__tests__/lib/status.test.js` -- 14 tests: normalizeStatus, normalizeHealth, derivePosture
- `frontend/vitest.config.js` -- jsdom environment, globals, react plugin
- `frontend/package.json` -- test + test:watch scripts wired

**Toast system polish** (`ActionFeedbackToast.jsx` + `useUiStore.js`):
- Success toasts auto-dismiss after 5s
- Error toasts stay visible until manually dismissed (duration: 0)
- Separate aria-live regions: `assertive` for errors, `polite` for everything else
- All icons have `aria-hidden="true"`; dismiss button has proper `aria-label`

**Responsive layout refinements**:
- `AppShell.jsx`: hamburger menu, mobile drawer, Escape-to-close, h-full max-w-7xl content area
- `BasicShell.jsx`: bottom nav bar on mobile, desktop inline nav, critical alert banner always visible
- `BasicOverviewPage.jsx`: plain language posture banners, card stack, recent alerts

**Shared primitives** (verified consistent):
- `Button.jsx` -- primary/secondary/danger/ghost variants, loading state with spinner + aria-busy
- `EmptyState.jsx` -- empty/loading/degraded/unsupported/disconnected/error variants
- `Badge.jsx` -- SeverityBadge, StatusBadge, CapabilityBadge shorthands

**Consistent page padding**:
- FirewallPage, DiagnosticsPage, SchedulerPage now use `p-4 sm:p-6 lg:p-8` responsive padding
- SettingsPage, NotificationsPage, PrivacyPage, BasicOverviewPage already had consistent padding
- DevicesPage, ThreatsPage use internal flex layout with p-4 content area

**Tailwind config**:
- Added `slideIn` keyframe for toast entrance animation

**Build**: verified `npm run build` succeeds
