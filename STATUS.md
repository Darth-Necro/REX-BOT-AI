# REX-BOT-AI: Honest Project Status

**Last updated**: 2026-03-31
**Version**: 0.1.0-alpha (pre-alpha)
**Verdict**: Not shippable. Substantial modules exist but are not wired together.

## The Core Problem

REX-BOT-AI is a collection of individually well-written modules wrapped in false integration. The modules do not connect to each other at runtime. The UI lies about system state. The installer writes data the container never reads. The scheduler does not schedule. The plugin sandbox does not sandbox. The privacy system exists but is never imported.

This is not a product. It is a prototype with a product-shaped shell.

## P0 Ship Blockers (Must fix before ANY public use)

| # | Issue | Status |
|---|-------|--------|
| 1 | No services are ever instantiated (orchestrator._create_services exists but CLI never calls orchestrator.run properly) | OPEN |
| 2 | No DashboardService exists — uvicorn is never started by the orchestrator | OPEN |
| 3 | FastAPI lifespan initializes auth/bus but orchestrator doesn't start FastAPI | PARTIALLY FIXED |
| 4 | EventBus handler signature mismatch — consumers expect (event) but bus sends (stream, msg_id, fields) | OPEN |
| 5 | Services reset self._tasks in _on_start, orphaning BaseService lifecycle tasks | OPEN |
| 6 | Frontend defaults to "operational/awake/protecting" with no backend connection — operator deception | OPEN |
| 7 | Frontend never fetches real state from API — only waits for WebSocket events that never arrive | OPEN |
| 8 | WebSocket broadcast() has zero call sites — real-time dashboard is nonexistent | OPEN |
| 9 | Installer writes to host paths that Docker volumes shadow | OPEN |
| 10 | Scheduler/power/cron are state labels, not functional subsystems | DOCUMENTED |
| 11 | Plugin sandbox stores dict entries, never calls Docker APIs | DOCUMENTED |
| 12 | 13+ security/privacy/agent modules have zero instantiation sites | DOCUMENTED |
| 13 | Credentials file stores JWT secret as plaintext JSON | PARTIALLY FIXED |
| 14 | Mode switch is client-side cosmetic, not a security control | OPEN |

## P1 Security Issues (Must fix before security-conscious users)

| # | Issue | Status |
|---|-------|--------|
| 1 | Prompt injection defense does not cover full LLM input surface (event.model_dump_json leaks unsanitized fields) | OPEN |
| 2 | 6 subprocess calls bypass CommandExecutor security boundary | OPEN |
| 3 | Port scanner accepts public IPs (weaponizable) | OPEN |
| 4 | Handler exceptions create poison message queues (not acked, reprocessed forever) | OPEN |
| 5 | FirewallManager._rex_ip may be set to DNS server IP instead of REX's actual IP | OPEN |
| 6 | Behavioral baseline poisoning during learning phase has no mitigation | DOCUMENTED |
| 7 | Quarantine is L3-only, ARP bypass possible at L2 | DOCUMENTED |
| 8 | Threat log archives are plaintext JSON forever | OPEN |
| 9 | WAL database grows without bound (replayed events never deleted) | OPEN |
| 10 | No global FastAPI exception handler — tracebacks may leak in non-debug mode | OPEN |

## What Actually Works (Verified)

These modules have real implementations, pass tests, and do what they claim:

- **rex/shared/**: Models, enums, config, utils, event bus (with WAL fallback) — solid foundation
- **rex/pal/linux.py**: 2300 lines of real Linux platform operations (nftables, raw sockets, systemd, package management)
- **rex/brain/classifier.py**: 1100 lines of rule-based threat classification with 12 categories
- **rex/brain/llm.py**: Ollama client with hardcoded localhost enforcement, data sanitizer, LLM router
- **rex/core/agent/command_executor.py**: Whitelisted command execution with parameter validation, zero shell=True
- **rex/core/agent/network_data_sanitizer.py**: Prompt injection defense with homoglyph detection, leetspeak decode, filler stripping
- **rex/eyes/**: Network scanner, device fingerprinter, DNS monitor, traffic monitor — real implementations
- **rex/memory/knowledge.py**: REX-BOT-AI.md parser/writer with git versioning
- **rex/teeth/firewall.py**: Firewall management with safety invariants (gateway/self never blocked)
- **rex/dashboard/auth.py**: bcrypt + PyJWT authentication with rate limiting and lockout

## What Does NOT Work (Despite Existing in the Codebase)

- Service orchestration (services are never instantiated)
- Dashboard real-time updates (WebSocket broadcast never called)
- Frontend data (defaults to lies, never fetches truth)
- Scheduler (appends "completed" records without doing scans)
- Power management (flips an enum, does not suspend services)
- Plugin sandbox (stores dicts, does not use Docker)
- Privacy system (encryption, audit, egress firewall — never imported by anything)
- Agent control plane (MessageRouter, ConfirmationManager, FeedbackTracker — dead code)
- Federation (ThreatSharing, GossipProtocol — never wired)
- Interview (QuestionEngine exists, never triggered by any runtime path)

## Test Status

- 803 tests passing, 0 failures
- 43% code coverage
- 10 documented security findings (xfail)
- Tests verify individual modules work in isolation
- Tests do NOT verify modules work together (because they don't)

## What Needs to Happen Next

**Freeze all feature work.** The next useful work is integration, not expansion:

1. Make `rex start` actually start uvicorn + all services
2. Fix EventBus handler signature contract
3. Fix services resetting self._tasks
4. Make frontend fetch real state on mount, show "disconnected" when backend unreachable
5. Wire WebSocket broadcast to actual Redis events
6. Make installer and container use the same paths
7. Wire privacy/agent/scheduler modules into the orchestrator or honestly remove them
8. Add a global FastAPI exception handler
9. Make the mode switch call the backend

Until these are done, do not add features, do not write specs, do not market this.
