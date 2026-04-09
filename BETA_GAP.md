# REX-BOT-AI Beta Gap Analysis

## Remaining Gaps to Beta (Updated 2026-04-08)

### Build/Install/Deploy
- [ ] Docker compose end-to-end verified on clean machine
- [x] Installer path alignment with container volumes (FIXED)
- [x] Frontend served via StaticFiles (FIXED)
- [x] First-boot password displayed in CLI (FIXED)

### Service Lifecycle
- [x] Service task lifecycle verified (no orphaning) (FIXED)
- [x] Orchestrator creates all services with per-service EventBus isolation (FIXED)
- [x] PID file written for CLI stop (FIXED)
- [ ] Graceful shutdown verified under SIGTERM (handler wired, needs live test)
- [ ] Crash recovery tested

### Runtime Truthfulness
- [x] Health endpoint returns real Redis/Ollama/disk status (FIXED)
- [x] Frontend defaults to unknown (FIXED)
- [x] Scheduler records honest status (FIXED)
- [x] Mode switch calls backend (FIXED)
- [x] Power manager suspends/resumes services (FIXED)

### Command Contract
- [x] All publishers use event_type="command" + payload.command (FIXED)
- [x] SchedulerService handles dashboard command format (FIXED)
- [x] Scan trigger reaches EyesService (FIXED)
- [x] Sleep/wake commands transition power state (FIXED)

### Auth/Security
- [x] bcrypt + PyJWT (FIXED)
- [x] WebSocket JWT auth (FIXED)
- [x] Per-IP lockout (FIXED)
- [x] API rate limiting (FIXED)
- [x] Credentials encrypted via SecretsManager with Docker fallback (FIXED)
- [x] Random per-install admin password generation (FIXED 2026-04-08 -- no more hardcoded "Woof")
- [x] Dashboard binds to 127.0.0.1 by default (FIXED 2026-04-08)

### Prompt Injection
- [x] All event fields sanitized before LLM (FIXED)
- [x] KB context sanitized (FIXED)
- [x] Newlines stripped (FIXED)
- [x] Unicode/homoglyph detection (FIXED)
- [x] 3000+ tests passing, 3 xfail (VULN-004/005/010 edge cases)

### Action Boundary
- [x] Private IP enforcement on scanning (FIXED)
- [x] Safe env for subprocesses (FIXED)
- [x] NFT semantic validation (FIXED)
- [x] Path whitelist validation (FIXED)
- [x] Firewall safety fail-closed (FIXED)

### Plugin System
- [x] Plugin sandbox uses real Docker (FIXED)
- [x] Plugin API auth enforced (FIXED)
- [x] Plugin output sanitized (FIXED)

### Scheduler/Power
- [x] Scheduler triggers real scans via event bus (publishes RexEvent) (FIXED)
- [x] Power state changes service behavior (FIXED)
- [x] Retention jobs archive old data (archive_old implemented)

### Privacy/Federation
- [x] Federation salt per-install (FIXED)
- [x] Credentials encryption Docker-aware (FIXED)
- [x] Baseline file permissions (FIXED)
- [x] Privacy audit wired to dashboard (FIXED)
- [x] Federation dashboard endpoints (FIXED)
- [ ] Archive encryption

### Cross-Platform
- [x] Windows PAL stub implemented (experimental — many methods raise NotImplementedError)
- [x] macOS PAL stub implemented (experimental — many methods raise NotImplementedError)
- [x] BSD PAL stub implemented (experimental — many methods raise NotImplementedError)
- [x] No Linux-only imports in shared modules (VERIFIED)

### Release Hygiene
- [x] Version strings consistent (0.1.0-alpha everywhere)
- [x] No nested zip/test artifacts in repo (FIXED)
- [x] .gitignore and .dockerignore updated (FIXED)
- [x] EventBus WAL path bug fixed (FIXED)
- [x] CHANGELOG.md, CODE_OF_CONDUCT.md, RELEASE.md added (2026-04-08)
- [x] All 7 release audit blockers resolved (2026-04-08)
- [x] Frontend toolchain fixed (.npmrc, ESLint v9 config) (2026-04-08)

### 2026-04-08 Completions
- [x] Auth: Random per-install password (no more hardcoded "Woof"), displayed once at startup
- [x] Dashboard defaults to 127.0.0.1 (not 0.0.0.0), override with REX_DASHBOARD_HOST
- [x] Python pinned to 3.11-3.12 only (3.13 not supported)
- [x] Dark red/black theme (was cyan/blue)
- [x] GUI is default startup mode
- [x] 26 dashboard pages total (added: REX Chat, Federation, Agent Actions, System Config)
- [x] Threat resolve/false-positive wired to backend
- [x] Recharts trend charts on overview
- [x] Frontend toolchain fixed (.npmrc, ESLint v9 config)
- [x] All 7 release audit blockers resolved
- [x] CHANGELOG.md, CODE_OF_CONDUCT.md, RELEASE.md added

### Remaining for Beta
- [ ] Docker compose end-to-end verified with live events
- [ ] Live Redis integration test in CI
- [ ] Notification channels integration-tested with real services
- [ ] Graceful shutdown + crash recovery live-tested
