# Changelog

All notable changes to REX-BOT-AI will be documented in this file.

## [0.1.0-alpha] - 2026-04-09

### Added
- Complete security pipeline: EYES (scan) -> BRAIN (classify) -> TEETH (block) -> BARK (notify)
- 13 service modules with real logic and Redis Streams event bus
- Linux Platform Abstraction Layer (2300+ lines)
- Dashboard with 26 pages (React 18 + Vite + Tailwind, dark red/black theme)
- REX Chat (Ollama-powered AI assistant)
- Threat classifier with 12 categories
- Prompt injection defense (44 patterns)
- Auth bootstrap state machine (Model 2: forced first-run setup)
- `rex reset-auth --yes` CLI command for password recovery
- 4 protection modes including Junkyard Dog (BITE)
- Patrol scheduling with cron support
- Federation (peer-to-peer threat sharing, experimental)
- Plugin system (SDK defined, experimental)
- Privacy audit and encryption-at-rest
- Threat trend charts (recharts) and severity breakdown on overview
- 4,289+ tests, 0 failures

### Security
- No shell=True anywhere in codebase
- LLM hardcoded to localhost only
- Auth bootstrap state machine: no hardcoded default passwords, forced first-run password creation via dashboard
- Dashboard binds to 127.0.0.1 by default (not 0.0.0.0)
- WebSocket first-message auth (no JWTs in URLs)
- Firewall safety: gateway/REX IPs untargetable
- Lockout messages include remaining wait time (no dead-end ambiguity)

### Fixed
- ChromaDB integration: upgraded chromadb-client from 0.6.3 to 1.5.7 (fixes `_type` KeyError on collection creation)
- ChromaDB heartbeat endpoint updated from /api/v1 to /api/v2
- ChromaDB telemetry crash suppressed via ANONYMIZED_TELEMETRY env var
- ChromaDB metadata sanitization: strips reserved underscore-prefixed keys
- SPA routing: added catch-all route so React Router handles /overview, /login etc. (was returning "Not Found")
- Setup wizard: removed duplicate password creation step
- Setup wizard: environment check now uses dedicated /api/env-check endpoint (was falsely reporting Ollama/ChromaDB unavailable)
- Login page: navigates to /overview after successful auth (was stuck on login)
- Login page: REX dog ASCII art replaces cat art, fixed alignment
- Ollama detection: structured logging, 5s timeout, distinct states (reachable_with_models/reachable_no_models/unreachable/timeout)
- Frontend theme: dark red/black (was cyan/blue)

### Known Limitations
- Docker deployment not verified end-to-end
- Notification channels not integration-tested
- Windows/macOS/BSD PAL stubs are experimental
- Plugin sandbox partially implemented
- Python 3.13 not yet supported
- Chroma server 0.6.3 with client 1.5.7 (cross-version, tested working)
