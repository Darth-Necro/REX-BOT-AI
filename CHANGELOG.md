# Changelog

All notable changes to REX-BOT-AI will be documented in this file.

## [0.1.0-alpha] - 2026-04-08

### Added
- Complete security pipeline: EYES (scan) -> BRAIN (classify) -> TEETH (block) -> BARK (notify)
- 13 service modules with real logic and Redis Streams event bus
- Linux Platform Abstraction Layer (2300+ lines)
- Dashboard with 26 pages (React 18 + Vite + Tailwind)
- REX Chat (Ollama-powered AI assistant)
- Threat classifier with 12 categories
- Prompt injection defense (44 patterns)
- bcrypt + PyJWT authentication
- 4 protection modes including Junkyard Dog (BITE)
- Patrol scheduling with cron support
- Federation (peer-to-peer threat sharing, experimental)
- Plugin system (SDK defined, experimental)
- Privacy audit and encryption-at-rest
- 4,289 tests, 0 failures

### Security
- No shell=True anywhere in codebase
- LLM hardcoded to localhost only
- Per-install random admin password (no more hardcoded default)
- Dashboard binds to localhost by default
- WebSocket first-message auth (no JWTs in URLs)
- Firewall safety: gateway/REX IPs untargetable

### Known Limitations
- Docker deployment not verified end-to-end
- Notification channels not integration-tested
- Windows/macOS/BSD PAL stubs are experimental
- Plugin sandbox partially implemented
- Python 3.13 not yet supported
