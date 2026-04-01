# REX-BOT-AI: Project Status

**Last updated**: 2026-03-31
**Version**: 0.1.0-alpha
**Stage**: Alpha candidate — modules integrated, not end-to-end verified

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

## P0 Status (was 14 items, now 5 remain)

| # | Issue | Status |
|---|-------|--------|
| 1 | Services instantiated by orchestrator | **FIXED** (_create_services via importlib) |
| 2 | DashboardService with uvicorn | **FIXED** (serves API + WebSocket) |
| 3 | FastAPI lifespan initializes deps | **FIXED** (auth, bus, websocket manager) |
| 4 | EventBus handler signature | **FIXED** (deserializes to RexEvent) |
| 5 | Service task lifecycle | **FIXED** (append, not replace) |
| 6 | Frontend defaults to unknown | **FIXED** |
| 7 | Frontend fetches real state | **FIXED** (API call on mount) |
| 8 | WebSocket broadcasts events | **FIXED** (DashboardService._consume_loop) |
| 9 | Installer vs Docker path mismatch | OPEN — install.sh writes host paths, Docker uses volumes |
| 10 | Scheduler truthfulness | **FIXED** (records "scheduled" not "completed") |
| 11 | Plugin sandbox is a dict | DOCUMENTED — not real Docker isolation |
| 12 | Dead runtime modules | DOCUMENTED — privacy/agent/federation not wired to dashboard |
| 13 | Credentials encryption | PARTIALLY FIXED — SecretsManager used with fallback |
| 14 | Mode switch backend | OPEN — frontend toggle doesn't call backend |

## What Works (Verified by 1018 Tests)

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
- Auth: bcrypt hashing, PyJWT tokens, per-IP lockout, rate limiting
- Dashboard API: 44 endpoints, honest responses (empty with notes, not fake success)

## What Does NOT Work Yet

- End-to-end runtime never tested (Docker compose up -> events flowing)
- Plugin sandbox is a dict, not real container isolation
- Privacy/agent modules exist but are not wired to the dashboard
- Scheduler records intervals but does not trigger real scans
- Power management flips an enum but does not suspend services
- Federation exists but is never instantiated outside tests

## Test Status

| Metric | Value |
|--------|-------|
| Tests | 1,018 |
| Failures | 0 |
| xfail (documented) | 10 |
| Coverage | 52% |
| Security pentest tests | 252 |

## Alpha Release Checklist

Before labeling this "alpha":

- [ ] `docker compose up -d` verified end-to-end with events flowing
- [ ] First-boot password displayed to user
- [ ] Mode switch calls backend ModeManager
- [ ] Install script path alignment with Docker volumes
- [ ] At least one real integration test with live Redis (in CI)
