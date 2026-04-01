# REX-BOT-AI Beta Gap Analysis

## Remaining Gaps to Beta (Updated Live)

### Build/Install/Deploy
- [ ] Docker compose end-to-end verified on clean machine
- [ ] Installer path alignment with container volumes (FIXED)
- [ ] Frontend served via StaticFiles (FIXED)
- [ ] First-boot password displayed in CLI (FIXED)

### Service Lifecycle
- [ ] Service task lifecycle verified (no orphaning)
- [ ] Orchestrator creates all services (FIXED)
- [ ] Graceful shutdown verified under SIGTERM
- [ ] Crash recovery tested

### Runtime Truthfulness
- [ ] Health endpoint returns real Redis/Ollama/disk status (FIXED)
- [ ] Frontend defaults to unknown (FIXED)
- [ ] Scheduler records honest status (FIXED)
- [ ] Mode switch calls backend (FIXED)

### Auth/Security
- [ ] bcrypt + PyJWT (FIXED)
- [ ] WebSocket JWT auth (FIXED)
- [ ] Per-IP lockout (FIXED)
- [ ] API rate limiting (FIXED)
- [ ] Credentials encrypted via SecretsManager (PARTIALLY FIXED)

### Prompt Injection
- [ ] All event fields sanitized before LLM (FIXED)
- [ ] KB context sanitized (FIXED)
- [ ] Newlines stripped (FIXED)
- [ ] Unicode/homoglyph detection (FIXED)
- [ ] 1018+ pentest tests passing

### Action Boundary
- [ ] Private IP enforcement on scanning (FIXED)
- [ ] Safe env for subprocesses (FIXED)
- [ ] NFT semantic validation (FIXED)
- [ ] Path whitelist validation (FIXED)
- [ ] Firewall safety fail-closed (PARTIALLY FIXED)

### Plugin System
- [ ] Bundled plugins load and process events
- [ ] Plugin API auth enforced
- [ ] Plugin output sanitized

### Scheduler/Power
- [ ] Scheduler triggers real scans via event bus
- [ ] Power state changes service behavior
- [ ] Retention jobs prune old data

### Privacy/Federation
- [ ] Federation salt per-install (FIXED)
- [ ] Archive encryption
- [ ] Baseline file permissions (FIXED)
- [ ] Privacy audit wired to dashboard

### Cross-Platform
- [ ] Windows PAL functional (basic methods)
- [ ] macOS PAL functional (basic methods)
- [ ] BSD PAL functional (basic methods)
- [ ] No Linux-only imports in shared modules (fcntl FIXED)
