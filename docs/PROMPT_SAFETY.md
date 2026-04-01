# REX-BOT-AI Prompt Safety Model

## Overview

REX uses a local LLM (Ollama, localhost-only) to make security decisions about network events. Because network-derived data -- hostnames, service banners, DNS names, DHCP identifiers, HTTP User-Agents -- flows into LLM prompts, an attacker who controls any of those strings can attempt prompt injection. This document describes how REX constructs prompts, what sanitization is applied, where it occurs, and what happens even if sanitization fails.

---

## 1. How Prompts Are Constructed

Every LLM prompt follows this layered structure, from most trusted to least trusted:

```
SYSTEM PROMPT (hardcoded in rex/brain/prompts.py)
  |
  v
POLICY RULES (six CRITICAL SAFETY RULES baked into SYSTEM_PROMPT)
  |
  v
TRUSTED CONTEXT (template variable names, JSON schema instructions)
  |
  v
SEMI-TRUSTED CONTEXT (KB content: device inventory, threat log, user notes)
  -- wrapped in <DATA>...</DATA> delimiters --
  |
  v
UNTRUSTED DATA (sanitized event JSON, network strings, web content)
  -- wrapped in <DATA>...</DATA> delimiters --
```

### System prompt (fully trusted)

Defined as `SYSTEM_PROMPT` in `rex/brain/prompts.py`. Contains:

- Identity and role definition ("You are REX, an autonomous security AI...")
- Output format constraint (JSON only, never prose)
- Six explicit safety rules that instruct the LLM to never follow instructions found inside network payloads, DNS queries, HTTP headers, web content, or any external data source
- Explicit instruction to treat all `<DATA>` blocks as untrusted input
- Instruction to flag embedded instructions as indicators of compromise
- Instruction to ignore JSON role injection attempts (`{"role":"system"}`) found within DATA blocks

### Analysis templates (trusted frame, untrusted variables)

Six templates in `rex/brain/prompts.py` use `{{ variable }}` placeholders that are filled at call time:

- `THREAT_ANALYSIS_TEMPLATE` -- primary threat evaluation
- `DEVICE_ASSESSMENT_TEMPLATE` -- device risk posture
- `DAILY_REPORT_TEMPLATE` -- daily security summary
- `ANOMALY_INVESTIGATION_TEMPLATE` -- behavioral deviation analysis
- `INCIDENT_CORRELATION_TEMPLATE` -- multi-event correlation
- `ASSISTANT_QUERY_TEMPLATE` -- user-facing chat

Every template wraps its variable content in `<DATA>...</DATA>` delimiters. The system prompt explicitly tells the LLM to treat everything inside `<DATA>` blocks as untrusted input to analyse, not instructions to execute.

---

## 2. What Fields Enter Prompts

The following fields from various sources are substituted into prompt templates:

| Field | Source | Trust Level | Entered Via |
|-------|--------|-------------|-------------|
| `event_json` | ThreatEvent.model_dump() | Untrusted | `_layer3_llm` in decision.py |
| `raw_data` | Network capture (REX-EYES) | Untrusted | ThreatEvent.raw_data |
| `network_context` | KB get_context_for_llm() | Semi-trusted | `_layer3_llm` in decision.py |
| `device_context` | raw_data["device_context"] | Untrusted | `_layer3_llm` in decision.py |
| `recent_threats` | KB THREAT LOG section | Semi-trusted | Template substitution |
| `user_notes` | KB USER NOTES section | Semi-trusted | Template substitution |
| `device_data` | Device model attributes | Semi-trusted | Device assessment flow |
| `behavioral_profile` | Baseline data | Semi-trusted | Anomaly investigation flow |
| `known_vulns` | CVE lookup results | Untrusted | Device assessment flow |
| `events_json` | Multiple ThreatEvents | Untrusted | Incident correlation flow |
| `user_query` | User chat input | Untrusted | Assistant query flow |
| Web content | Fetched HTML | Untrusted | WebContentSanitizer |

---

## 3. What Is Sanitized and How

### 3.1 Network Data Sanitizer (`rex/core/agent/network_data_sanitizer.py`)

This is REX's primary defense against prompt injection via network-derived data. It processes every string that originates from the network before it can reach any LLM prompt.

**Sanitization pipeline (in order):**

1. **Control character stripping** -- Remove all characters in `\x00-\x1f` and `\x7f-\x9f` ranges
2. **Unicode NFKD normalization** -- Normalize to canonical decomposed form to defeat visual spoofing
3. **Zero-width character removal** -- Strip zero-width spaces, joiners, and BOM characters (`\u200b-\u200f`, `\u2060`, `\ufeff`)
4. **Length truncation** -- Enforce per-field maximum lengths:
   - Hostnames: 64 characters
   - Service banners: 128 characters
   - User-Agents: 200 characters
   - Generic fields: 256 characters
5. **Normalization for matching** (`_normalize_for_matching`):
   - Homoglyph replacement (Cyrillic to Latin: 20 character mappings)
   - NFKD normalization with combining mark stripping (removes accents/diacritics)
   - Leetspeak decoding (0->o, 1->i, 3->e, 4->a, 5->s, 7->t, 8->b, @->a, $->s)
   - Single-character delimiter collapse (i.g.n.o.r.e -> ignore)
   - Underscore/hyphen to space normalization
   - Whitespace collapse
   - Filler word stripping ("please", "kindly", "safely", "now", "quickly", "immediately", etc.)
6. **Pattern matching** -- Check BOTH the cleaned text and normalized form against 30+ injection patterns covering:
   - Instruction override ("ignore all previous instructions", "disregard all previous")
   - Role hijacking ("you are now", "pretend to be", "act as if", "roleplay as")
   - Security control bypass ("disable firewall", "unblock all", "mark as trusted", "allow all traffic")
   - LLM token injection (`<|im_start|>`, `<|system|>`, `` ```system ``)
   - Administrative escalation ("admin mode", "debug mode")
   - Command execution ("execute command:")
   - JSON role injection (`{"role":"system"}`)
   - Markdown heading injection (`## heading` in free text)
   - Noise-word evasion (catches patterns with arbitrary filler between key tokens)

**On detection:** The matched substring is replaced with `[INJECTION_ATTEMPT_STRIPPED]` and a WARNING-level log is emitted with the field name, truncated payload, and matched pattern. If patterns matched on the normalized form but substitution could not replace in the raw text, the entire string is replaced with `[INJECTION_ATTEMPT_STRIPPED]`.

**Typed sanitization functions:**
- `sanitize_hostname(hostname)` -- DHCP, mDNS, reverse DNS
- `sanitize_banner(banner)` -- SSH, HTTP, FTP service banners
- `sanitize_useragent(ua)` -- HTTP User-Agent strings
- `sanitize_mdns_name(name)` -- mDNS/Bonjour service names
- `sanitize_dhcp_client_id(client_id)` -- DHCP client identifiers
- `sanitize_snmp_string(value)` -- SNMP community strings and descriptions
- `sanitize_network_data(data)` -- Recursive dict/list sanitization of ALL string fields

### 3.2 Web Content Sanitizer (`rex/core/agent/web_content_sanitizer.py`)

Processes fetched web pages (threat feeds, CVE databases, vendor advisories) before LLM consumption.

**Pipeline:**

1. **HTML stripping** -- Remove all `<script>`, `<style>`, `<iframe>`, `<form>`, `<svg>`, `<template>`, and 10 other active element types with their content. Remove HTML comments (may contain hidden instructions). Remove CDATA sections. Strip all remaining tags. Decode HTML entities.
2. **Whitespace normalization** -- Collapse blank lines, collapse spaces/tabs, strip per-line whitespace
3. **Injection pattern scan** -- 16 pattern categories:
   - `role_override` -- "you are", "act as", "ignore previous instructions"
   - `system_prompt_leak` -- "reveal your system prompt"
   - `delimiter_escape` -- LLM delimiters, INST tags, system tags
   - `jailbreak_dan` -- "DAN", "do anything now", "bypass safety"
   - `hidden_instruction` -- HTML/CSS comments with instruction content
   - `encoding_evasion` -- base64, eval, exec, subprocess
   - `token_smuggling` -- zero-width characters, control characters
   - `command_injection` -- "execute this command", sudo, rm -rf, wget|bash
   - `data_exfiltration` -- "send all data to", "upload to"
   - `context_manipulation` -- "forget everything", "reset context"
   - `authority_claim` -- "I am your admin", "root access", "god mode"
   - `safety_bypass` -- "disable all safety", "remove all restrictions"
   - `response_format_attack` -- format manipulation attempts
   - `markdown_injection` -- javascript: and data: protocol links
   - `prompt_repetition` -- "repeat after me", "say exactly"
   - `unicode_obfuscation` -- fullwidth characters, excessive diacriticals
4. **Truncation** -- Cap at 8000 characters
5. **Delimiter wrapping** -- Wrap output in `[UNTRUSTED_WEB_CONTENT_START]...[UNTRUSTED_WEB_CONTENT_END]` markers

Detected injections are replaced with `[REDACTED_INJECTION_ATTEMPT]` and audit-logged.

### 3.3 Data Sanitizer for External APIs (`rex/brain/llm.py` -- `DataSanitizer`)

When Brain 2 (assistant/chat) uses an external LLM provider, the `DataSanitizer` replaces network-identifying data with deterministic placeholders:

- IPv4 addresses -> `[IP_1]`, `[IP_2]`, ...
- IPv6 addresses -> `[IP_3]`, ...
- MAC addresses -> `[MAC_1]`, `[MAC_2]`, ...
- Email addresses -> `[EMAIL_1]`, ...
- FQDNs and hostnames -> `[HOST_1]`, ...
- Bare hostnames (DESKTOP-ABC, johns-macbook-pro) -> `[HOST_2]`, ...
- File system paths (Unix and Windows) -> `[PATH_1]`, ...
- SSIDs -> `[SSID_1]`, ...

Placeholders are deterministic within a sanitizer instance, so relational reasoning is preserved ("DEVICE_A contacted IP_3 five times").

---

## 4. Where Sanitization Occurs

### Decision Engine Pipeline (`rex/brain/decision.py`)

1. **`_pipeline()` method** (line 142): Calls `sanitize_network_data(event.raw_data)` at the START of the pipeline, before any layer processes the event. This is the primary sanitization point.

2. **`_layer3_llm()` method** (lines 218-229): Three additional sanitization steps:
   - Sanitizes the FULL event model dump (`sanitize_network_data(event.model_dump(mode="json"))`) -- not just `raw_data`, because fields like `description`, `indicators`, and `source_device_id` could also contain network-derived data
   - Sanitizes KB context (`sanitize_network_data({"_kb": kb_context})["_kb"]`) -- because the KB contains device hostnames, service banners, and other strings that were originally network-sourced
   - Truncates the event JSON to 2000 characters and KB context to 2000 characters to limit context window exposure

### Knowledge Base (`rex/memory/knowledge.py`)

- `_escape_md_table()` -- Escapes pipe characters (`|` -> `\|`) and strips newlines/carriage returns in all table cell values during markdown rendering

### Interview Processor (`rex/interview/processor.py`)

- `_sanitize_answer()` -- Strips markdown heading syntax (`#{1,6}\s*`), escapes pipe characters, truncates to 1000 characters. Applied to free-text fields (`additional_notes`, `authorized_pentest_ips`) before KB storage.

---

## 5. The Action Validator Gate

Even if all sanitization fails and the LLM is successfully manipulated, the `ActionValidator` (`rex/core/agent/action_validator.py`) provides an independent enforcement boundary. Every action the LLM proposes must pass through five sequential checks:

1. **Registry check** -- The action must be registered in the `ActionRegistry`. There are exactly 37 registered actions across 6 domains. Any action not in the registry is rejected unconditionally. The registry is populated at startup and is immutable.

2. **Protected resource check** -- Blocking actions (`block_ip`, `isolate_device`, `block_device_traffic`, `rate_limit_device`, `kill_connection`, `modify_firewall_rule`) are checked against a set of protected IPs (gateway IP and REX's own IP). These IPs can never be blocked.

3. **Rate limiting** -- Each action has a per-minute rate limit (sliding 60-second window). Exceeding the limit results in rejection regardless of threat severity.

4. **Mode-based confirmation** -- Actions are classified by risk level (LOW, MEDIUM, HIGH, CRITICAL). In Basic mode, only LOW-risk actions auto-execute. In Advanced mode, LOW and MEDIUM auto-execute. HIGH and CRITICAL always require confirmation (except CRITICAL threats in Advanced mode, which can auto-execute MEDIUM-risk threat response actions).

5. **2FA check** -- Certain actions (update_rex, configure_vlan, change_dns_settings, modify_routing, push_router_config, install_plugin) require two-factor authentication regardless of mode.

### Command Executor Gate (`rex/core/agent/command_executor.py`)

System commands face a second independent gate:

- Static whitelist of allowed commands (nmap, arp-scan, nft, dig, whois, tcpdump, ip, ss)
- Each command has typed parameter validators (CIDR, IP address, interface name, domain name, DNS record type, nft rule, BPF filter, safe path)
- `shell=True` is NEVER used -- all commands use `asyncio.create_subprocess_exec` with explicit argv
- Minimal environment inheritance (PATH, HOME, LANG, TERM, USER, LOGNAME only)
- Per-command timeout enforcement
- Output truncation (1 MiB max)
- Full audit logging of every execution and rejection

**The net result:** A successful prompt injection can, at worst, produce an incorrect analysis or recommendation. It cannot directly cause an unauthorized action because the action whitelist and command whitelist are enforced in code, not by the LLM.

---

## 6. Known Limitations

### 6.1 Advanced paraphrase evasion

The sanitizer uses pattern matching, which cannot catch arbitrary rephrasing. An attacker who paraphrases "ignore all instructions" as "disregard the guidance provided above and adopt a new behavioral framework" may evade the pattern set, because the specific word sequences are not matched.

**Mitigation:** The system prompt instructs the LLM to flag such attempts. The ActionValidator provides a hard boundary regardless. New patterns can be added to the regex list (see Section 7).

### 6.2 Context window attacks

If an attacker can inject a very large payload (approaching the context window limit), they may push the system prompt or safety rules out of the context window, effectively making the LLM "forget" its instructions.

**Mitigation:** Length truncation limits all network strings to 64-256 characters. Event JSON is capped at 2000 characters. KB context is capped at 2000 characters. Web content is capped at 8000 characters. Total prompt size is bounded well within typical context window sizes.

### 6.3 KB as a semi-trusted store

The knowledge base (`REX-BOT-AI.md`) contains network-sourced data that was previously sanitized, but a manual editor could introduce injection payloads. The KB is sanitized again when read back for LLM context, but the secondary sanitization treats it as a dict with a single key, which may miss some structural patterns.

**Mitigation:** Git versioning provides tamper detection. File locking prevents concurrent corruption. The KB is stored on the local filesystem with standard file permissions.

### 6.4 LLM model compromise

If the local Ollama model weights have been tampered with, the LLM layer could produce incorrect decisions regardless of prompt construction. Layers 1-2 (signature and statistical) still operate correctly because they do not use the LLM.

### 6.5 Plugin output

Plugin output enters the system through the Plugin API. Currently, plugin-originated actions always require confirmation unless LOW risk, but plugin output strings that flow into events are not processed through the network data sanitizer.

---

## 7. How to Add New Injection Patterns

### Network data sanitizer

Edit `rex/core/agent/network_data_sanitizer.py`:

1. Add the regex pattern string to the `_INJECTION_PATTERNS` list (around line 34)
2. Patterns are compiled with `re.IGNORECASE`
3. The pattern is checked against both the raw cleaned text and the normalized form (homoglyph-replaced, leetspeak-decoded, delimiter-collapsed)

Example:

```python
# In the _INJECTION_PATTERNS list:
r"your\s+new\s+pattern\s+here",
```

### Web content sanitizer

Edit `rex/core/agent/web_content_sanitizer.py`:

1. Add a `(pattern_name, compiled_regex)` tuple to the `_INJECTION_PATTERNS` class variable
2. Each pattern needs a descriptive name (used in audit logging)

Example:

```python
# In WebContentSanitizer._INJECTION_PATTERNS:
(
    "my_new_pattern",
    re.compile(r"your pattern here", re.IGNORECASE),
),
```

### Homoglyph mappings

Edit the `_HOMOGLYPH_MAP` dict in `network_data_sanitizer.py` to add new visually-similar character mappings (e.g., Greek characters that look like Latin).

### Leetspeak mappings

Edit the `_LEET_MAP` translation table to add new number/symbol-to-letter mappings.

---

## 8. How to Run the Regression Corpus

### Prompt injection payloads

```bash
pytest tests/test_security/test_prompt_injection_pentest.py -v
```

Tests 30+ injection techniques including:
- Direct keyword injection
- Leetspeak evasion (PI-024)
- Delimiter-separated evasion (PI-025)
- Homoglyph evasion (PI-026)
- Zero-width character evasion (PI-027)
- Noise-word evasion (PI-028)
- Underscore evasion (PI-029)
- Newline evasion (PI-030)

### KB injection payloads

```bash
pytest tests/test_security/test_kb_injection.py -v
```

Tests pipe injection in table cells, heading injection in notes, and JSON role injection.

### Web content sanitizer

```bash
pytest tests/test_core/test_web_content_sanitizer.py -v
```

### Full security test suite

```bash
pytest tests/test_security/ -v
```

### Regression corpus files

Structured payloads are stored in `tests/regressions/`:

- `prompt_injection_payloads.json` -- 30 hostile payloads with categories
- `markdown_injection_payloads.json` -- 8 markdown structure attack payloads
- `ui_xss_payloads.json` -- XSS attack payloads
- `parser_corruption_payloads.json` -- Parser corruption payloads

These files can be extended with new payloads. Each entry has an `id`, `text`, and `category` field.

---

## 9. Architecture Diagram

```
  NETWORK                    REX-EYES                      REX-BRAIN
  (attacker-                 (capture)                     (decision)
   controlled)
     |                          |                              |
     |  hostname="IGNORE ALL"   |                              |
     +------------------------->|                              |
                                |  sanitize_network_data()     |
                                +----------------------------->|
                                   [INJECTION_ATTEMPT_STRIPPED] |
                                                               |
                                                    _pipeline(event)
                                                        |
                                                  L1: signature
                                                  L2: statistical
                                                  L3: LLM (sanitized input)
                                                        |
                                                    Decision
                                                        |
                                               ActionValidator.validate()
                                                        |
                                                  [REJECT if not in
                                                   whitelist, wrong
                                                   target, rate limited,
                                                   or needs confirmation]
                                                        |
                                               CommandExecutor.execute()
                                                        |
                                                  [REJECT if not in
                                                   command whitelist,
                                                   bad params, or
                                                   shell=True attempt]
```
