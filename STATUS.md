# REX-BOT-AI: Project Status

**Last updated**: 2026-04-01
**Version**: 0.1.0-alpha
**Stage**: Alpha candidate — modules integrated, command contracts standardized

## What Changed Since Pre-Alpha

After 5 rounds of adversarial auditing (76+ issues identified, 126-item punch list):

- **Build chain works**: `pip install -e .` succeeds, npm lockfile exists, Dockerfile fails on real errors
- **Auth is real**: bcrypt + PyJWT (not homemade SHA-256)
- **Frontend stops lying**: defaults to "unknown" / "connecting" — not "operational" / "awake"
- **Frontend fetches real state**: API call on mount, not just passive WebSocket wait
- **EventBus handler contract fixed**: deserializes Redis fields into RexEvent objects
- **EventBus WAL path fixed**: all constructors pass config.data_dir instead of relying on hard-coded default
- **Service lifecycle fixed**: services append to BaseService tasks instead of replacing them
- **DashboardService exists**: uvicorn started by orchestrator, WebSocket broadcasts real events
- **Prompt injection defense expanded**: Unicode normalization, homoglyph detection, filler word stripping, full event surface sanitized
- **Subprocess security boundary enforced**: safe environment stripping, private IP enforcement, audit logging
- **Docker hardened**: pinned image tags, .dockerignore, explicit Redis password required, localhost URL validation
- **Command contract standardized**: all publishers and consumers use `event_type="command"` + `payload.command`
- **Power manager wired**: power state changes suspend/resume non-essential services via orchestrator
- **Mode switch wired**: PUT /api/config/mode publishes ModeChangeEvent to bus
- **Dashboard routers expanded**: privacy, agent, federation endpoints added
- **Interview flow connected**: dashboard calls real InterviewService methods
- **Notification channels wired**: BarkService subscribes to STREAM_BARK_NOTIFICATIONS for dashboard alerts
- **Plugin sandbox uses Docker**: real `docker create/start/stop/rm` calls with security hardening
- **CLI improved**: login command, scan parameters, proper error handling
- **Credentials encryption Docker-aware**: stable key derivation in Docker containers
- **Cross-platform PAL adapters implemented**: Windows, macOS, BSD adapters functional
- **PID file written**: orchestrator writes PID for CLI stop command

## P0 Status (all resolved)

| # | Issue | Status |
|---|-------|--------|
| 1 | Services instantiated by orchestrator | **FIXED** |
| 2 | DashboardService with uvicorn | **FIXED** |
| 3 | FastAPI lifespan initializes deps | **FIXED** |
| 4 | EventBus handler signature | **FIXED** |
| 5 | Service task lifecycle | **FIXED** |
| 6 | Frontend defaults to unknown | **FIXED** |
| 7 | Frontend fetches real state | **FIXED** |
| 8 | WebSocket broadcasts events | **FIXED** |
| 9 | Installer vs Docker path mismatch | **FIXED** (env vars aligned) |
| 10 | Scheduler truthfulness | **FIXED** |
| 11 | Plugin sandbox is a dict | **FIXED** (real Docker calls) |
| 12 | Dead runtime modules | **FIXED** (privacy, agent, federation wired to dashboard) |
| 13 | Credentials encryption | **FIXED** (Docker-aware fallback) |
| 14 | Mode switch backend | **FIXED** (publishes event to bus) |

## What Works (Verified by Tests)

- Pydantic v2 data models with full type validation
- Redis event bus with WAL fallback and consumer group management
- **EventBus WAL respects configured data_dir** (not hard-coded default)
- Linux PAL (2300 lines): raw sockets, nftables, systemd, package management
- Windows PAL: netsh advfirewall, ipconfig, arp, Task Scheduler
- macOS PAL: pfctl anchors, ifconfig, networksetup, launchd
- BSD PAL: pfctl, ifconfig, pkg, rc.d
- Threat classifier: 12 categories with MITRE ATT&CK alignment
- LLM client: hardcoded localhost enforcement, data sanitizer, Brain L1-L4 routing
- Command executor: whitelisted commands, parameter validation, zero shell=True
- Prompt injection sanitizer: 30+ patterns, homoglyphs, leetspeak, Unicode normalization, filler stripping
- Network data sanitizer: control chars, truncation, injection detection on all event surfaces
- Web content sanitizer: HTML stripping, injection patterns, untrusted content delimiters
- Network scanner: ARP + nmap, device fingerprinting, DNS monitoring
- Knowledge base: markdown parser/writer, git versioning, section CRUD
- Firewall manager: safety invariants (gateway/self never blocked), rate limiting, auto-rollback
- Auth: bcrypt hashing, PyJWT tokens, per-IP lockout, rate limiting
- Dashboard API: 14 routers, 50+ endpoints, honest responses
- **Standardized command contract**: event_type="command" + payload.command everywhere
- **Power manager suspends/resumes services** on state transitions
- **Notification channels receive dashboard-originated alerts**
- **Plugin sandbox enforces Docker security** (read-only, cap-drop ALL, no-new-privileges)
- Orchestrator: service lifecycle, health monitoring, auto-restart (3 attempts), PID file

## What Does NOT Work Yet

- End-to-end Docker compose verification (never tested with live events flowing)
- Live Redis integration test in CI
- Notification channels not integration-tested with real Discord/Telegram/SMTP services

## Test Status

| Metric | Value |
|--------|-------|
| Tests (core) | 3,848+ |
| Failures | 0 |
| xfail (documented) | 3 |
| New integration tests | 23 |
| Security pentest tests | 306 |

## Alpha Release Checklist

- [x] All 13 modules implemented with real logic
- [x] Security regression corpus: 306 tests, 0 failures
- [x] Overall test suite: 3,848+ passed, 0 failures
- [x] Prompt injection defense: 30+ patterns, Unicode normalization, homoglyph detection
- [x] Auth: bcrypt + PyJWT (not homemade SHA-256)
- [x] Docker hardened: pinned images, read-only root, no-new-privileges
- [x] Docs match code: ARCHITECTURE.md, README.md, STATUS.md verified
- [x] Command contract standardized and tested
- [x] EventBus WAL path respects configured data_dir
- [x] Mode switch calls backend ModeManager
- [x] Power manager suspends/resumes services
- [x] Cross-platform PAL adapters implemented (Windows, macOS, BSD)
- [x] Plugin sandbox uses real Docker
- [x] Credentials encryption Docker-aware
- [x] FastAPI app creation smoke test passes
- [ ] `docker compose up -d` verified end-to-end with events flowing
- [ ] At least one real integration test with live Redis (in CI)
