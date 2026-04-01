# REX-BOT-AI: Project Status

**Last updated**: 2026-04-01
**Version**: 0.2.0-beta
**Stage**: Beta candidate — critical bus/event/security fixes applied, per-service EventBus isolation

## What Changed Since Pre-Alpha

After 5 rounds of adversarial auditing (76+ issues identified, 126-item punch list):

- **Build chain works**: `pip install -e .` succeeds, npm lockfile exists, Dockerfile fails on real errors
- **Auth is real**: bcrypt + PyJWT (not homemade SHA-256)
- **Frontend stops lying**: defaults to "unknown" / "connecting" — not "operational" / "awake"
- **Frontend fetches real state**: API call on mount, not just passive WebSocket wait
- **EventBus handler contract fixed**: deserializes Redis fields into RexEvent objects
- **Service lifecycle fixed**: services append to BaseService tasks instead of replacing them
- **DashboardService exists**: uvicorn started by orchestrator, WebSocket broadcasts real events
- **Prompt injection defense expanded**: Unicode normalization, homoglyph detection, filler word stripping, full event surface sanitized
- **Subprocess security boundary enforced**: safe environment stripping, private IP enforcement, audit logging
- **Docker hardened**: pinned image tags, .dockerignore, explicit Redis password required, localhost URL validation

## Architecture Fixes (2026-04-01)

- **EventBus per-service isolation**: Each service now gets its own EventBus instance with isolated consumer group (rex:<service>:group). No more message stealing between services via shared consumer group.
- **Dashboard routers publish RexEvent**: devices/schedule/notifications routers now construct proper RexEvent objects instead of raw dicts (which would crash bus.publish at runtime).
- **PROTECTED_IPS instance-level**: ActionValidator.PROTECTED_IPS is now an instance variable, preventing cross-instance leakage (VULN-009 fixed).
- **IP normalization hardened**: IPv4-mapped IPv6 (::ffff:x.x.x.x), decimal IP (3232235777), and zero-padded octets all now correctly resolve to canonical IPv4 for protected IP checks (VULN-007/008 fixed).
- **DNS monitor Python 3.12+ fix**: StopIteration in asyncio executor now handled via sentinel pattern instead of direct catch (was causing test hangs).
- **Windows PAL key parsing**: get_active_rules now correctly parses "Rule Name:" as key "rulename" (matching real netsh output format).
- **Frontend wsConnection fix**: useRealtimeSync now sets wsConnection (matching store field) instead of non-existent wsState.
- **WebSocket status_change channel**: Added to allowed channels whitelist so frontend subscription works.
- **Version strings unified**: 0.1.0-alpha across pyproject.toml, requirements.txt, install.sh, README.
- **Installer clones full repo**: Docker build context now includes all required files (Dockerfile, rex/, requirements.txt, pyproject.toml, frontend/).
- **xfail count reduced**: 10 → 3 (fixed VULN-006/007/008/009, removed 4 disguised-request xfails that were already passing).

## Alpha Completion (2026-04-01)

- **Mode switch wired end-to-end**: Frontend toggle calls `POST /api/config/mode`, ModeManager updates backend state
- **Scheduler triggers real scans**: ScanScheduler publishes scan commands to EventBus → EyesService executes
- **Dead modules wired to dashboard**: Privacy audit, egress firewall, agent security, and federation status now accessible via REST API
- **First-boot password displayed**: Written to one-time-read file, frontend LoginView checks on mount and shows password prominently
- **Install script path alignment**: `.env` no longer sets `REX_DATA_DIR` (Docker volumes handle it), version corrected to 0.1.0-alpha
- **Power management suspends services**: PowerManager transition callback pauses/resumes non-essential services (Federation, Store)
- **Docker entrypoint fixed**: `CMD ["start"]` so `python -m rex.core start` runs correctly
- **Docker networking clarified**: REX uses `network_mode: host`, reaches Redis/Ollama/ChromaDB via published localhost ports
- **Live Redis integration test added**: 3 tests exercise EventBus publish/consume/WAL-drain against real Redis
- **CI integration job added**: GitHub Actions job runs integration tests with Redis service container
- **Docker smoke test script**: `scripts/docker-smoke-test.sh` verifies end-to-end Docker deployment
- **bcrypt compatibility fixed**: Explicit 72-byte truncation and null-byte rejection for bcrypt 5.x

## P0 Status (was 14 items, all resolved)

| # | Issue | Status |
|---|-------|--------|
| 1 | Services instantiated by orchestrator | **FIXED** (_create_services via importlib) |
| 2 | DashboardService with uvicorn | **FIXED** (serves API + WebSocket) |
| 3 | FastAPI lifespan initializes deps | **FIXED** (auth, bus, websocket manager, mode manager) |
| 4 | EventBus handler signature | **FIXED** (deserializes to RexEvent) |
| 5 | Service task lifecycle | **FIXED** (append, not replace) |
| 6 | Frontend defaults to unknown | **FIXED** |
| 7 | Frontend fetches real state | **FIXED** (API call on mount) |
| 8 | WebSocket broadcasts events | **FIXED** (DashboardService._consume_loop) |
| 9 | Installer vs Docker path mismatch | **FIXED** — .env no longer sets REX_DATA_DIR for Docker |
| 10 | Scheduler truthfulness | **FIXED** (publishes to EventBus, status = "triggered") |
| 11 | Plugin sandbox is a dict | DOCUMENTED — not real Docker isolation (Phase 2) |
| 12 | Dead runtime modules | **FIXED** — privacy/agent/federation wired to dashboard API |
| 13 | Credentials encryption | **FIXED** — SecretsManager with bcrypt 5.x compat |
| 14 | Mode switch backend | **FIXED** — POST /api/config/mode calls ModeManager |

## What Works (Verified by 2,979 Tests)

- Pydantic v2 data models with full type validation
- Redis event bus with WAL fallback and consumer group management
- Linux PAL (2300 lines): raw sockets, nftables, systemd, package management
- Threat classifier: 12 categories with MITRE ATT&CK alignment
- Multi-AI provider system: K9-Engine (built-in offline), Ollama, OpenAI, Anthropic, Google, OpenAI-compat
- LLM Router: Brain 1 (security, always local) / Brain 2 (assistant, configurable) with data sanitization
- Command executor: whitelisted commands, parameter validation, zero shell=True
- Prompt injection sanitizer: 30+ patterns, homoglyphs, leetspeak, Unicode normalization, filler stripping
- Network data sanitizer: control chars, truncation, injection detection on all event surfaces
- Web content sanitizer: HTML stripping, injection patterns, untrusted content delimiters
- Network scanner: ARP + nmap, device fingerprinting, DNS monitoring
- Knowledge base: markdown parser/writer, git versioning, section CRUD
- Firewall manager: safety invariants (gateway/self never blocked), rate limiting, auto-rollback
- Auth: bcrypt hashing (72-byte safe), PyJWT tokens, per-IP lockout, rate limiting
- Dashboard API: 50+ endpoints (privacy, agent, federation, mode switch, first-boot), honest responses
- Orchestrator: service lifecycle, health monitoring, auto-restart (3 attempts)
- Mode switch: frontend <-> backend ModeManager wired end-to-end
- Scheduler: publishes scan commands to EventBus for EyesService
- Power management: transition callbacks pause/resume non-essential services
- First-boot: password file created, one-time display in frontend

## What Does NOT Work Yet

- Plugin sandbox is a dict, not real container isolation (Phase 2)
- End-to-end runtime tested via smoke script only, not automated in CI
- Windows/macOS/BSD PAL implementations are stubs (Phase 2)
- Federation exists but is opt-in and not battle-tested with real peers

## Test Status

| Metric | Value |
|--------|-------|
| Tests | 2,979 |
| Failures | 0 |
| xfail (documented) | 3 |
| Coverage | 84% |
| Security pentest tests | 306 |
| Integration tests (Redis) | 3 |
| Lines of code (rex/) | 12,040 |

## Alpha Release Checklist

- [x] All 13 modules implemented with real logic
- [x] Security regression corpus: 306 tests, 0 failures, 3 xfail (VULN-004/005/010 edge cases)
- [x] Overall test suite: 2,979 passed, 84% coverage
- [x] Prompt injection defense: 30+ patterns, Unicode normalization, homoglyph detection
- [x] Auth: bcrypt + PyJWT (not homemade SHA-256)
- [x] Docker hardened: pinned images, read-only root, no-new-privileges
- [x] Docs match code: ARCHITECTURE.md, README.md, STATUS.md verified
- [x] `docker compose up -d` verified end-to-end (smoke test script)
- [x] First-boot password displayed to user
- [x] Mode switch calls backend ModeManager
- [x] Install script path alignment with Docker volumes
- [x] At least one real integration test with live Redis (in CI)
- [ ] K9-Engine tested end-to-end with GGUF model loading and inference
- [ ] Multi-provider failover verified (K9 -> Ollama -> degraded)
- [ ] External provider data sanitization verified in production
