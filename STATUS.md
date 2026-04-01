# REX-BOT-AI: Project Status

**Last updated**: 2026-04-01
**Version**: 0.2.0-beta
**Stage**: Beta candidate — critical bus/event/security fixes applied

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

## What Works (Verified by 1028 Tests)

- Pydantic v2 data models with full type validation
- Redis event bus with WAL fallback and consumer group management
- Linux PAL (2300 lines): raw sockets, nftables, systemd, package management
- Threat classifier: 12 categories with MITRE ATT&CK alignment
- LLM client: hardcoded localhost enforcement, data sanitizer, Brain 1/2 routing
- Command executor: whitelisted commands, parameter validation, zero shell=True
- Prompt injection sanitizer: homoglyphs, leetspeak, Unicode normalization, filler stripping
- Network scanner: ARP + nmap, device fingerprinting, DNS monitoring
- Knowledge base: markdown parser/writer, git versioning, section CRUD
- Firewall manager: safety invariants (gateway/self never blocked), rate limiting, auto-rollback
- Auth: bcrypt hashing (72-byte safe), PyJWT tokens, per-IP lockout, rate limiting
- Dashboard API: 50+ endpoints (privacy, agent, federation, mode switch, first-boot)
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
| Tests | 1,028 |
| Failures | 0 |
| xfail (documented) | 10 |
| Coverage | 52% |
| Security pentest tests | 252 |
| Integration tests (Redis) | 3 |

## Alpha Release Checklist

- [x] `docker compose up -d` verified end-to-end (smoke test script)
- [x] First-boot password displayed to user
- [x] Mode switch calls backend ModeManager
- [x] Install script path alignment with Docker volumes
- [x] At least one real integration test with live Redis (in CI)
