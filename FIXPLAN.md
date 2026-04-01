# REX-BOT-AI Fix Plan

## P0: Boot / Install / Runtime Truth / Security Boundaries
1. Build chain works end-to-end (pip, npm, Docker)
2. Orchestrator creates and starts all services
3. EventBus handler contract correct everywhere
4. Service lifecycle tasks not orphaned
5. FastAPI lifespan initializes all dependencies
6. Health/status endpoints return real data
7. Frontend defaults to unknown/disconnected
8. Auth uses bcrypt+PyJWT, secrets encrypted
9. WebSocket requires JWT
10. Prompt injection covers full LLM input surface
11. All subprocess calls go through executor or have safe env
12. Firewall safety fail-closed when IPs unknown
13. Private IP enforcement on scanning

## P1: Full Integration of Product Surfaces
14. Dashboard routers return real data from live stores
15. WebSocket broadcasts real events from Redis
16. CLI commands talk to real API
17. Plugin system loads and runs bundled plugins
18. Scheduler executes real periodic tasks
19. Power manager affects service behavior
20. Mode switch changes runtime behavior
21. Interview flow works end-to-end
22. Notification channels send real alerts

## P2: Cross-Platform / Plugin Hardening / Federation
23. Windows PAL functional (basic network + firewall)
24. macOS PAL functional (basic network + pfctl)
25. BSD PAL functional (basic network + pf)
26. No Linux-only imports in shared modules
27. Federation salt uses per-install secret
28. Plugin sandbox enforces declared permissions
29. Archive/baseline encryption at rest
30. All collections bounded with retention policies
