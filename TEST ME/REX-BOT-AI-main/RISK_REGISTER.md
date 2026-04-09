# REX-BOT-AI Risk Register

## Active Risks

| ID | Risk | Likelihood | Impact | Mitigation | Status |
|----|------|-----------|--------|------------|--------|
| R1 | Default Redis password enables event injection | HIGH | CRITICAL | Require explicit password, removed default | MITIGATED |
| R2 | Prompt injection via hostnames | HIGH | HIGH | Sanitizer with homoglyphs, Unicode normalization | MITIGATED |
| R3 | Gateway blocked when IP unknown | MEDIUM | CRITICAL | Fail-closed safety check, logging | PARTIALLY MITIGATED |
| R4 | Port scanner weaponization | LOW | HIGH | is_private_ip enforcement | MITIGATED |
| R5 | Plugin escape from sandbox | LOW | HIGH | Subprocess isolation, bounded resources | IN PROGRESS |
| R6 | Federation salt reversal | MEDIUM | MEDIUM | Per-install secret in salt | MITIGATED |
| R7 | Baseline poisoning during learning | LOW | HIGH | Documented risk, no automated mitigation | ACCEPTED |
| R8 | Quarantine ARP bypass | LOW | MEDIUM | L3-only isolation documented | ACCEPTED |
| R9 | Unbounded memory growth | MEDIUM | HIGH | Collection caps added | PARTIALLY MITIGATED |
| R10 | LLM hallucination causing wrong action | MEDIUM | MEDIUM | ActionValidator final gate, confidence threshold | MITIGATED |
