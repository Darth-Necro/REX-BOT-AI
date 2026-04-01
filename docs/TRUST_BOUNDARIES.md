# REX-BOT-AI Trust Boundaries

## Overview

REX processes data that ranges from fully trusted (hardcoded constants) to fully untrusted (attacker-controlled network strings). This document maps every trust zone, the transitions between them, and the sanitization or validation applied at each boundary crossing.

---

## 1. Trust Zones

### TRUSTED -- System-controlled, immutable at runtime

| Asset | Location | Why Trusted |
|-------|----------|-------------|
| System prompts | `rex/brain/prompts.py` (SYSTEM_PROMPT, ASSISTANT_SYSTEM_PROMPT) | Hardcoded Python string constants. Only changed via code review and deployment. |
| Analysis templates | `rex/brain/prompts.py` (6 templates) | Hardcoded. Variable placeholders are filled with data from lower trust zones, but the template frame itself is trusted. |
| Action registry | `rex/core/agent/action_registry.py` (ActionRegistry) | Populated at construction via `_register_all()`. Immutable after startup. 37 registered actions across 6 domains. No runtime additions possible. |
| Command whitelist | `rex/core/agent/command_executor.py` (COMMAND_WHITELIST) | Static dict populated at module load. 12 whitelisted commands with typed validators. No runtime additions. |
| Injection patterns | `rex/core/agent/network_data_sanitizer.py` (_INJECTION_PATTERNS) | Compiled regex list. Module-level constant. |
| Web injection patterns | `rex/core/agent/web_content_sanitizer.py` (_INJECTION_PATTERNS) | Class-level constant. 16 pattern categories. |
| Scope keywords | `rex/core/agent/scope_enforcer.py` (SECURITY_KEYWORDS) | Frozen set. Class-level constant. |
| Out-of-scope patterns | `rex/core/agent/scope_enforcer.py` (OUT_OF_SCOPE_PATTERNS) | Compiled regex list. Class-level constant. |
| Localhost restriction | `rex/brain/llm.py` (ALLOWED_HOSTS) | Frozen set: `{127.0.0.1, localhost, ::1}`. Enforced at OllamaClient construction. Property setter re-validates. |
| Protected IPs | `rex/core/agent/action_validator.py` (PROTECTED_IPS) | Set at startup with gateway and REX IPs. Checked before every blocking action. |
| Risk levels | `rex/core/agent/action_registry.py` (RiskLevel) | Enum. LOW, MEDIUM, HIGH, CRITICAL. Immutable. |
| Privacy level enum | `rex/brain/llm.py` (PrivacyLevel) | LOCAL or EXTERNAL. Enforced at LLMRouter construction -- Brain 1 must be LOCAL. |
| Homoglyph map | `rex/core/agent/network_data_sanitizer.py` (_HOMOGLYPH_MAP) | Static dict. 20 Cyrillic-to-Latin mappings. |
| Leetspeak map | `rex/core/agent/network_data_sanitizer.py` (_LEET_MAP) | Static translation table. 9 mappings. |

### SEMI-TRUSTED -- User-editable, could contain injection

| Asset | Location | Why Semi-Trusted |
|-------|----------|-----------------|
| Knowledge base (REX-BOT-AI.md) | `<data_dir>/REX-BOT-AI.md` | Contains network-sourced data that was sanitized on first write, but the file is user-editable. Manual edits bypass sanitization. Git versioning provides tamper detection but not prevention. |
| KB KNOWN DEVICES table | KB section | Device hostnames, vendors, IPs -- originally from network scans. Sanitized before first write. |
| KB SERVICES DETECTED table | KB section | Service names, versions -- from port scanning. Sanitized before first write. |
| KB THREAT LOG table | KB section | Threat descriptions, source IPs -- from event processing. Descriptions truncated to 120 chars. |
| KB USER NOTES section | KB section | Free-text notes from interview or dashboard. Heading syntax stripped, pipes escaped, length capped at 1000 chars. |
| KB REX OBSERVATIONS section | KB section | REX's own observations. Auto-generated but stored in the editable file. |
| KB OWNER PROFILE section | KB section | Environment type, notification channels -- from interview answers. |
| KB REX CONFIGURATION section | KB section | Protection mode, scan schedules, DNS preferences -- from interview. |
| Interview answers | `rex/interview/processor.py` | User-provided answers to onboarding questions. Free-text fields sanitized via `_sanitize_answer()`. Multiple-choice fields validated against known options. |
| Paired user records | `<data_dir>/paired_users.json` | Platform user IDs, display names. Written by the pairing flow. Stored locally. |
| Configuration file | `rex.yaml` or environment variables | Operator-provided configuration. Validated by Pydantic models at load time. |

### UNTRUSTED -- Attacker-controlled, always sanitized before use

| Asset | Source | Why Untrusted |
|-------|--------|--------------|
| Hostnames | DHCP, mDNS, reverse DNS | An attacker controls their device's hostname. Can be set to arbitrary strings including prompt injection payloads. |
| mDNS service names | Bonjour/Avahi | Attacker-controlled device advertisement. |
| DHCP client IDs | DHCP option 61 | Attacker sets their DHCP client identifier. |
| Service banners | SSH, FTP, HTTP, SMTP | Attacker runs services with crafted banner strings. |
| HTTP User-Agents | HTTP headers | Attacker controls their browser/client User-Agent string. |
| SNMP strings | SNMP community strings, sysDescr | Attacker controls their device's SNMP responses. |
| DNS queries | DNS traffic monitoring | Attacker makes DNS queries for domains containing injection text. |
| Event payloads | ThreatEvent.raw_data | Aggregated network data from REX-EYES. Contains multiple untrusted fields. |
| Event descriptions | ThreatEvent.description | Auto-generated from network data. May echo attacker-controlled strings. |
| Event indicators | ThreatEvent.indicators | IOCs extracted from network data. May contain attacker-controlled values. |
| Web content | Fetched HTML from threat feeds, CVE DBs | External web pages may contain prompt injection in visible or hidden text. |
| Plugin output | Plugin API responses | Plugins run in sandboxed containers but their output strings are not sanitized by the network data sanitizer. |

---

## 2. Trust Transitions

### Transition 1: Network -> Device Store

```
Network Packet --> REX-EYES Scanner --> DeviceStore
                   (pcap/arp-scan)      (in-memory dict keyed by MAC)
```

**What happens:** REX-EYES captures packets and extracts device attributes (MAC, IP, hostname, vendor, open ports, service banners). These are stored in the `DeviceStore` (`rex/eyes/device_store.py`) as `Device` model objects.

**Sanitization at this boundary:** None. The DeviceStore stores raw values. Sanitization happens later, when data enters LLM prompts.

**Risk:** Attacker-controlled strings are stored verbatim in the DeviceStore. This is acceptable because the DeviceStore is an internal data structure that does not directly interact with the LLM. All paths from DeviceStore to LLM pass through the sanitizer.

### Transition 2: Device Store -> Knowledge Base

```
DeviceStore --> KnowledgeBase.update_device() --> REX-BOT-AI.md
                                                  (markdown file)
```

**What happens:** The `update_device()` method writes device attributes into the KNOWN DEVICES markdown table.

**Sanitization at this boundary:**
- `_escape_md_table()` escapes pipe characters (`|` -> `\|`) to prevent table structure injection
- Newlines replaced with spaces, carriage returns removed
- This prevents an attacker from injecting extra table columns or breaking the table structure

**Risk:** Hostnames and other fields are stored in the KB with pipe escaping but without prompt injection sanitization. This is acceptable because the KB is sanitized again when read back for LLM context (Transition 3).

### Transition 3: Knowledge Base -> LLM Prompt

```
REX-BOT-AI.md --> KnowledgeBase.get_context_for_llm() --> decision._layer3_llm()
                  (read + parse + curate)                  (sanitize + template fill)
```

**What happens:** The KB is parsed into structured data, curated to a relevant subset (based on event type), formatted as markdown text, and injected into a prompt template inside `<DATA>` delimiters.

**Sanitization at this boundary:**
- `sanitize_network_data({"_kb": kb_context})["_kb"]` in `_layer3_llm()` processes the KB context through the full network data sanitizer
- KB context is truncated to 2000 characters
- The resulting text is placed inside `<DATA>...</DATA>` delimiters in the prompt template

### Transition 4: ThreatEvent -> LLM Prompt

```
ThreatEvent --> decision._pipeline() --> decision._layer3_llm() --> LLM
               (sanitize raw_data)       (sanitize full model dump)
```

**What happens:** The event passes through the four-layer pipeline. At the start of `_pipeline()`, `raw_data` is sanitized. In `_layer3_llm()`, the FULL event model dump is sanitized (not just `raw_data`), because fields like `description`, `indicators`, and `source_device_id` could contain network-derived data.

**Sanitization at this boundary (two passes):**
1. `sanitize_network_data(event.raw_data)` at pipeline start
2. `sanitize_network_data(event.model_dump(mode="json"))` in `_layer3_llm()`
3. Event JSON truncated to 2000 characters
4. Result placed inside `<DATA>...</DATA>` delimiters

### Transition 5: Web Content -> LLM Prompt

```
HTTP Response --> WebContentSanitizer.sanitize() --> LLM Prompt
                  (strip HTML, scan patterns,
                   redact injections, truncate,
                   wrap in delimiters)
```

**What happens:** Fetched web pages pass through the `WebContentSanitizer` before reaching the LLM.

**Sanitization at this boundary:**
- HTML stripped to plain text (active elements and their content removed entirely)
- 16 injection pattern categories scanned and redacted
- Truncated to 8000 characters
- Wrapped in `[UNTRUSTED_WEB_CONTENT_START]...[UNTRUSTED_WEB_CONTENT_END]` delimiters
- Injections audit-logged

### Transition 6: Interview Answers -> Knowledge Base

```
User Input --> AnswerProcessor._sanitize_answer() --> KnowledgeBase.write()
               (strip headings, escape pipes,          (markdown file)
                truncate to 1000 chars)
```

**What happens:** Free-text interview answers pass through `_sanitize_answer()` before being written to the KB. Multiple-choice answers are validated against known option sets.

**Sanitization at this boundary:**
- Markdown heading syntax stripped (`#{1,6}\s*` at start of lines)
- Pipe characters escaped (`|` -> `\|`)
- Truncated to 1000 characters
- Only applied to free-text fields (`additional_notes`, `authorized_pentest_ips`)

### Transition 7: LLM Output -> Action Execution

```
LLM Response --> _parse_llm() --> ActionValidator.validate() --> CommandExecutor.execute()
                 (JSON parse)     (5-check pipeline)             (whitelist + validate + exec)
```

**What happens:** The LLM returns JSON with a recommended action, severity, and reasoning. The response is parsed (tolerating markdown fences and partial JSON). The proposed action is validated. If approved, the corresponding system command is executed.

**Validation at this boundary (TWO independent gates):**

**Gate 1 -- ActionValidator:**
- Action must be registered in ActionRegistry (37 whitelisted actions)
- Action must not target protected IPs (gateway, REX)
- Action must not exceed rate limit
- Action may require user confirmation based on risk level and operating mode
- Action may require 2FA

**Gate 2 -- CommandExecutor:**
- Command must be in COMMAND_WHITELIST (12 whitelisted commands)
- Every parameter validated by typed validator function
- `shell=True` never used
- Minimal environment inheritance
- Per-command timeout
- Output size cap (1 MiB)
- Full audit logging

---

## 3. Trust Boundary Diagram

```
+-------------------------------------------------------------------+
|                        TRUSTED ZONE                                |
|  System prompts, action registry, command whitelist,               |
|  injection patterns, localhost restriction, risk levels            |
+-------------------------------------------------------------------+
         |                                            |
         | Template frame                             | Whitelist check
         v                                            v
+-------------------+    sanitize()    +----------------------------+
| SEMI-TRUSTED ZONE | <-------------> |    ACTION VALIDATION GATE   |
| KB content,       |   read back     | ActionValidator (5 checks)  |
| interview answers,|                 | CommandExecutor (whitelist)  |
| user config       |                 +----------------------------+
+-------------------+                              ^
         ^                                          |
         | escape_md + sanitize_answer              | LLM output
         |                                          |
+-------------------+   sanitize_network_data()  +------------------+
| UNTRUSTED ZONE    | ========================> | LLM PROMPT       |
| Network hostnames |   sanitize (web content)   | (sanitized data  |
| Service banners   | ========================> |  in <DATA> blocks)|
| DNS queries       |                            +------------------+
| DHCP IDs          |
| HTTP User-Agents  |
| Web content       |
| Plugin output     |
| Event payloads    |
+-------------------+
```

---

## 4. Failure Modes and Residual Risk

| Boundary | Failure Mode | Impact | Residual Risk |
|----------|-------------|--------|---------------|
| Network -> DeviceStore | None (no sanitization here) | Raw strings stored in memory | Acceptable -- no direct LLM exposure |
| DeviceStore -> KB | Pipe escaping bypassed | Table structure corruption in KB file | LOW -- file is self-healing on next render |
| KB -> LLM Prompt | Novel injection pattern evades sanitizer | LLM receives unsanitized KB content | MEDIUM -- ActionValidator still gates actions |
| Event -> LLM Prompt | Paraphrase evasion of all 30+ patterns | LLM receives injection in event JSON | MEDIUM -- ActionValidator still gates actions |
| Web -> LLM Prompt | Novel web-based injection | LLM manipulated via web content | MEDIUM -- ActionValidator still gates actions |
| LLM Output -> Action | ActionValidator bypass (should not happen) | Unauthorized action executed | CRITICAL -- but validator is code-enforced, not LLM-dependent |
| Action -> Command | CommandExecutor bypass (should not happen) | Arbitrary command execution | CRITICAL -- but whitelist is code-enforced, not LLM-dependent |
| Interview -> KB | Heading injection in free text | Fake KB sections created | LOW -- heading syntax stripped by _sanitize_answer() |

The key insight: the two most critical boundaries (LLM Output -> Action and Action -> Command) are enforced by deterministic code (whitelists, typed validators, rate limits), not by the LLM itself. A compromised LLM cannot bypass these gates.
