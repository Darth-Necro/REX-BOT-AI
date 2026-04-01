# REX-BOT-AI Fix Plan

## P0: Boot / Install / Runtime Truth / Security Boundaries
1. [x] Build chain works end-to-end (pip, npm, Docker)
2. [x] Orchestrator creates and starts all services (per-service EventBus)
3. [x] EventBus handler contract correct everywhere (RexEvent deserialization)
4. [x] Service lifecycle tasks not orphaned
5. [x] FastAPI lifespan initializes all dependencies
6. [x] Health/status endpoints return real data
7. [x] Frontend defaults to unknown/disconnected
8. [x] Auth uses bcrypt+PyJWT, secrets encrypted
9. [x] WebSocket requires JWT
10. [x] Prompt injection covers full LLM input surface
11. [x] All subprocess calls go through executor or have safe env
12. [x] Firewall safety fail-closed when IPs unknown
13. [x] Private IP enforcement on scanning

## P1: Full Integration of Product Surfaces
14. [x] Dashboard routers return real data from live stores
15. [x] WebSocket broadcasts real events from Redis (with event-to-channel mapping)
16. [x] CLI commands talk to real API
17. [ ] Plugin system loads and runs bundled plugins
18. [x] Scheduler executes real periodic tasks (publishes RexEvent)
19. [x] Power manager affects service behavior
20. [x] Mode switch changes runtime behavior
21. [x] Interview flow works end-to-end
22. [ ] Notification channels send real alerts (integration-tested)

## P2: Cross-Platform / Plugin Hardening / Federation
23. [ ] Windows PAL functional (basic network + firewall)
24. [ ] macOS PAL functional (basic network + pfctl)
25. [ ] BSD PAL functional (basic network + pf)
26. [x] No Linux-only imports in shared modules (fcntl guarded)
27. [x] Federation salt uses per-install secret
28. [ ] Plugin sandbox enforces declared permissions (Docker, not dict)
29. [ ] Archive/baseline encryption at rest
30. [ ] All collections bounded with retention policies
