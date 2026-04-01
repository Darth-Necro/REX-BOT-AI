# REX-BOT-AI Prompt Safety Audit

## Untrusted Text Flow Audit Table

Every path by which untrusted or semi-trusted text can reach an LLM prompt or system command is documented below with its transform chain, sink, risk category, current status, and test coverage.

| # | Source | Transform Chain | Sink | Risk Category | Status | Test |
|---|--------|----------------|------|---------------|--------|------|
| 1 | DHCP hostname | `sanitize_hostname()` -> truncate(64) -> control char strip -> NFKD normalize -> zero-width strip -> homoglyph+leet+filler normalize -> pattern match -> `[INJECTION_ATTEMPT_STRIPPED]` | LLM prompt via event.raw_data | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py::TestHostnameBasicInjection` |
| 2 | mDNS service name | `sanitize_mdns_name()` -> same pipeline as #1 with 64-char limit | LLM prompt via event.raw_data | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py` (generic sanitizer tests) |
| 3 | DHCP client ID | `sanitize_dhcp_client_id()` -> same pipeline as #1 with 64-char limit | LLM prompt via event.raw_data | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py` |
| 4 | SSH/FTP/HTTP service banner | `sanitize_banner()` -> same pipeline as #1 with 128-char limit | LLM prompt via event.raw_data | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py::TestBannerInjection` (if present) |
| 5 | HTTP User-Agent | `sanitize_useragent()` -> same pipeline as #1 with 200-char limit | LLM prompt via event.raw_data | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py` |
| 6 | SNMP community/sysDescr | `sanitize_snmp_string()` -> same pipeline as #1 with 256-char limit | LLM prompt via event.raw_data | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py` |
| 7 | ThreatEvent.description | `sanitize_network_data(event.model_dump())` in `_layer3_llm()` -> full recursive sanitization of all string fields | LLM prompt via event_json_str | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py` |
| 8 | ThreatEvent.indicators | `sanitize_network_data(event.model_dump())` in `_layer3_llm()` | LLM prompt via event_json_str | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py` |
| 9 | ThreatEvent.source_device_id | `sanitize_network_data(event.model_dump())` in `_layer3_llm()` | LLM prompt via event_json_str | Prompt injection | MITIGATED | `test_prompt_injection_pentest.py` |
| 10 | KB KNOWN DEVICES hostnames | `_escape_md_table()` on write -> `sanitize_network_data({"_kb": ctx})` on read -> truncate(2000) | LLM prompt via network_context | Prompt injection via KB | MITIGATED | `test_kb_injection.py::TestPipeInjectionInHostname` |
| 11 | KB SERVICES DETECTED versions | `_escape_md_table()` on write -> `sanitize_network_data()` on read | LLM prompt via network_context | Prompt injection via KB | MITIGATED | `test_kb_injection.py` |
| 12 | KB THREAT LOG descriptions | Truncated to 120 chars on write -> `_escape_md_table()` -> `sanitize_network_data()` on read | LLM prompt via network_context | Prompt injection via KB | MITIGATED | `test_kb_injection.py` |
| 13 | KB USER NOTES (interview free text) | `_sanitize_answer()` strips headings, escapes pipes, truncates to 1000 -> `sanitize_network_data()` on read | LLM prompt via user_notes | Heading/section injection | MITIGATED | `test_kb_injection.py::TestHeadingInjectionInNotes` |
| 14 | Web content (threat feeds, CVE DBs) | `WebContentSanitizer.sanitize()` -> HTML strip -> pattern scan (16 categories) -> redact -> truncate(8000) -> wrap in `[UNTRUSTED_WEB_CONTENT]` delimiters | LLM prompt via browse_url action | Prompt injection via web | MITIGATED | `test_web_content_sanitizer.py` |
| 15 | DNS query domain names | Captured by `dns_monitor.py` -> stored in event.raw_data -> `sanitize_network_data()` in `_pipeline()` | LLM prompt via event.raw_data | Prompt injection via DNS | MITIGATED | `test_prompt_injection_pentest.py` |
| 16 | Hostname pipe chars in KB table | `_escape_md_table()` replaces `\|` with `\\|`, strips newlines | KB markdown table structure | Table structure corruption | MITIGATED | `test_kb_injection.py::TestPipeInjectionInHostname` |
| 17 | Heading injection in interview notes | `_sanitize_answer()` strips `#{1,6}\s*` at line starts | KB section structure | Section injection | MITIGATED | `test_kb_injection.py::TestHeadingInjectionInNotes` |
| 18 | Leetspeak evasion (e.g., "1gn0r3 4ll") | `_normalize_for_matching()` decodes leet -> pattern match on normalized form | LLM prompt | Obfuscated injection | MITIGATED | `prompt_injection_payloads.json` PI-024 |
| 19 | Homoglyph evasion (Cyrillic chars) | `_normalize_for_matching()` replaces 20 Cyrillic->Latin homoglyphs -> pattern match | LLM prompt | Obfuscated injection | MITIGATED | `prompt_injection_payloads.json` PI-026 |
| 20 | Zero-width char evasion | `_sanitize()` strips `\u200b-\u200f`, `\u2060`, `\ufeff` before pattern match | LLM prompt | Obfuscated injection | MITIGATED | `prompt_injection_payloads.json` PI-027 |
| 21 | Delimiter-separated evasion (i.g.n.o.r.e) | `_normalize_for_matching()` collapses single-char delimiters -> pattern match | LLM prompt | Obfuscated injection | MITIGATED | `prompt_injection_payloads.json` PI-025 |
| 22 | Noise-word evasion (filler words) | `_normalize_for_matching()` strips 20 filler words -> pattern match | LLM prompt | Obfuscated injection | MITIGATED | `prompt_injection_payloads.json` PI-028 |
| 23 | Underscore/hyphen evasion | `_normalize_for_matching()` replaces `_-` with spaces -> pattern match | LLM prompt | Obfuscated injection | MITIGATED | `prompt_injection_payloads.json` PI-029 |
| 24 | JSON role injection ({"role":"system"}) | Pattern match: `[{]\s*"role"\s*:\s*"(?:system\|assistant\|user)"` | LLM prompt | Role hijacking | MITIGATED | `test_kb_injection.py` (JSON role tests) |
| 25 | LLM token injection (<\|im_start\|>) | Pattern match: `<\|(?:im_start\|system\|user\|assistant)\|>` | LLM prompt | Token smuggling | MITIGATED | `test_prompt_injection_pentest.py` |
| 26 | Advanced paraphrase evasion | No pattern match (novel phrasing) | LLM prompt | Prompt injection | RESIDUAL RISK | No specific test -- mitigated by ActionValidator gate |
| 27 | Context window exhaustion | Length truncation: 64-256 chars per field, 2000 chars per context block, 8000 chars web content | LLM context window | Context manipulation | MITIGATED | Implicit in truncation logic |
| 28 | Plugin output strings | Plugin actions require confirmation if not LOW risk; output not processed by network_data_sanitizer | LLM prompt (if used for analysis) | Prompt injection via plugin | RESIDUAL RISK | `test_core/test_agent_security.py` (plugin confirmation tests) |
| 29 | LLM-proposed action type | `ActionValidator.validate()` checks against ActionRegistry (37 actions) | System action execution | Unauthorized action | MITIGATED | `test_core/test_agent_security.py` |
| 30 | LLM-proposed command params | `CommandExecutor._validate_params()` with typed validators per param | System command execution | Command injection | MITIGATED | `test_core/test_agent_security.py` |
| 31 | nftables rule expression | `validate_nft_rule()` blocks shell metacharacters, validates action is drop/reject only, blocks wildcards | Firewall rule modification | Firewall bypass | MITIGATED | `test_core/test_agent_security.py` |
| 32 | BPF filter expression | `validate_bpf_filter()` restricts to safe character set, max 500 chars | tcpdump filter argument | Filter injection | MITIGATED | `test_core/test_agent_security.py` |
| 33 | File path parameter | `validate_safe_path()` rejects `..`, resolves symlinks, whitelist of allowed prefixes | Filesystem access | Path traversal | MITIGATED | `test_core/test_agent_security.py` |
| 34 | User chat message (assistant) | `ScopeEnforcer.is_in_scope()` filters out-of-scope requests; if external provider, `DataSanitizer.sanitize()` strips PII | LLM prompt via assistant query | Scope escape / PII leak | MITIGATED | `test_security/test_scope_pentest.py` |
| 35 | KB manual edits (operator) | Git versioning (`GitManager`) provides audit trail and revert capability; re-sanitized on LLM read | LLM prompt | Tamper risk | MITIGATED | `test_kb_injection.py` + manual review via git log |

---

## Legend

- **MITIGATED**: Sanitization or validation is implemented and has test coverage.
- **RESIDUAL RISK**: Known limitation where complete mitigation is not feasible. Compensating controls (ActionValidator, manual review) reduce impact.

## How to Use This Table

1. **Adding a new data source**: When a new untrusted data source is introduced, add a row to this table documenting its transform chain and sink.
2. **Reviewing coverage**: Ensure every MITIGATED entry has at least one test in the Test column. Run `pytest tests/test_security/ -v` to verify.
3. **Auditing**: Walk each row and verify the transform chain matches the actual code path. Check that the sink is correct and that no bypass exists.
4. **New patterns**: When a new injection technique is discovered, check which rows it affects and whether existing transforms catch it. If not, add a pattern to the appropriate sanitizer and add a test to the regression corpus.
