"""Answer processor -- validates, maps, and persists interview answers.

The :class:`AnswerProcessor` bridges the interview conversation and the
knowledge base.  Every answer is validated, mapped to the appropriate KB
section / key, and written through the :class:`~rex.memory.knowledge.KnowledgeBase`
API.  A human-readable summary (in REX's dog persona) is generated for
user confirmation before finalisation.
"""

from __future__ import annotations

import logging
from typing import Any

from rex.shared.utils import iso_timestamp

logger = logging.getLogger("rex.interview.processor")


class AnswerProcessor:
    """Converts interview answers to KB sections and configuration.

    The ``ANSWER_MAP`` translates each question ID into a ``(section, key)``
    tuple that tells :meth:`process_answer` where in the knowledge base the
    value should land.

    ``VALIDATORS`` provides per-question validation logic.  If a question
    is not listed, only a basic non-empty check is performed for required
    questions.
    """

    # ------------------------------------------------------------------
    # Mapping: question ID -> (KB section heading, key within section)
    # ------------------------------------------------------------------

    ANSWER_MAP: dict[str, tuple[str, str]] = {
        "environment_type":         ("OWNER PROFILE",       "Environment"),
        "protection_mode":          ("REX CONFIGURATION",   "Protection Mode"),
        "notification_channel":     ("OWNER PROFILE",       "Notification Channels"),
        "iot_scrutiny":             ("REX CONFIGURATION",   "IoT Monitoring"),
        "exposed_service":          ("REX CONFIGURATION",   "Exposed Service Flagging"),
        "additional_notes":         ("USER NOTES",          "Operator Notes"),
        "compliance_requirements":  ("REX CONFIGURATION",   "Compliance Frameworks"),
        "authorized_pentest_ips":   ("REX CONFIGURATION",   "Whitelisted IPs"),
        "scan_schedule":            ("REX CONFIGURATION",   "Deep Scan Schedule"),
        "vpn_policy":               ("REX CONFIGURATION",   "VPN Policy"),
        "guest_network":            ("REX CONFIGURATION",   "Guest Network"),
        "user_count":               ("OWNER PROFILE",       "User Count"),
        "dns_preference":           ("REX CONFIGURATION",   "DNS Mode"),
        "inspection_depth":         ("REX CONFIGURATION",   "Inspection Depth"),
        "notification_detail_level": ("REX CONFIGURATION",  "Notification Detail"),
        "messaging_platform":       ("OWNER PROFILE",       "Messaging Platform"),
    }

    # ------------------------------------------------------------------
    # Human-readable label maps (for the summary)
    # ------------------------------------------------------------------

    _LABELS: dict[str, dict[str, str]] = {
        "environment_type": {
            "home": "a home network",
            "business": "a business network",
            "both": "a mixed home/business network",
        },
        "protection_mode": {
            "auto_block_all": "auto-block everything suspicious",
            "auto_block_critical": "auto-block critical threats and alert you about the rest",
            "alert_only": "alert only -- you decide what gets blocked",
        },
        "notification_channel": {
            "dashboard": "the dashboard",
            "discord": "Discord",
            "telegram": "Telegram",
            "email": "Email",
            "multiple": "multiple channels",
        },
        "iot_scrutiny": {
            "yes": "get extra monitoring",
            "no": "be treated like everything else",
        },
        "exposed_service": {
            "yes": "flagged as suspicious",
            "no": "allowed (intentional exposure)",
        },
        "scan_schedule": {
            "every_hour": "every hour",
            "every_6h": "every 6 hours",
            "every_12h": "every 12 hours",
            "daily": "once a day",
            "weekly": "once a week",
        },
        "dns_preference": {
            "system_default": "system default",
            "doh_cloudflare": "DNS-over-HTTPS via Cloudflare",
            "doh_quad9": "DNS-over-HTTPS via Quad9 (malware blocking)",
            "dot_google": "DNS-over-TLS via Google",
            "custom": "a custom resolver",
        },
        "inspection_depth": {
            "headers_only": "headers only (lightweight)",
            "smart": "smart heuristics",
            "minimal": "minimal / passive",
        },
        "notification_detail_level": {
            "full": "full detail with evidence",
            "summary": "concise summaries",
            "alert_only": "just the alert",
        },
        "messaging_platform": {
            "discord": "Discord",
            "telegram": "Telegram",
            "signal": "Signal",
            "matrix": "Matrix",
            "slack": "Slack",
            "none": "dashboard only",
        },
        "vpn_policy": {
            "no_vpn": "No VPN / remote access",
            "wireguard": "WireGuard",
            "openvpn": "OpenVPN",
            "ipsec": "IPSec / L2TP",
            "tailscale": "Tailscale / ZeroTier",
            "other": "Other VPN",
        },
        "guest_network": {
            "yes": "active",
            "no": "not present",
            "planning": "planned",
        },
    }

    # Valid option values per question (for single-select validation)
    _VALID_OPTIONS: dict[str, set[str]] = {
        "environment_type": {"home", "business", "both"},
        "protection_mode": {"auto_block_all", "auto_block_critical", "alert_only"},
        "notification_channel": {"dashboard", "discord", "telegram", "email", "multiple"},
        "iot_scrutiny": {"yes", "no"},
        "exposed_service": {"yes", "no"},
        "scan_schedule": {"every_hour", "every_6h", "every_12h", "daily", "weekly"},
        "vpn_policy": {"no_vpn", "wireguard", "openvpn", "ipsec", "tailscale", "other"},
        "guest_network": {"yes", "no", "planning"},
        "user_count": {"1-2", "3-5", "6-10", "11-25", "25+"},
        "dns_preference": {"system_default", "doh_cloudflare", "doh_quad9", "dot_google", "custom"},
        "inspection_depth": {"headers_only", "smart", "minimal"},
        "notification_detail_level": {"full", "summary", "alert_only"},
        "messaging_platform": {"discord", "telegram", "signal", "matrix", "slack", "none"},
    }

    _MULTI_VALID_OPTIONS: dict[str, set[str]] = {
        "compliance_requirements": {"pci_dss", "hipaa", "soc2", "gdpr", "iso27001", "none"},
    }

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_answer(self, question_id: str, answer: Any) -> dict[str, Any]:
        """Validate an answer value for a given question.

        Parameters
        ----------
        question_id:
            The question identifier.
        answer:
            The user's answer value.

        Returns
        -------
        dict[str, Any]
            ``{"valid": True}`` on success, or
            ``{"valid": False, "error": "reason"}`` on failure.
        """
        # Text / free-form questions -- accept anything
        if question_id in ("additional_notes", "authorized_pentest_ips"):
            return {"valid": True}

        # Multi-select validation
        if question_id in self._MULTI_VALID_OPTIONS:
            valid_set = self._MULTI_VALID_OPTIONS[question_id]
            if isinstance(answer, str):
                answer = [answer]
            if not isinstance(answer, list):
                return {"valid": False, "error": f"Expected a list for {question_id}"}
            bad = [v for v in answer if v not in valid_set]
            if bad:
                return {
                    "valid": False,
                    "error": f"Invalid option(s) for {question_id}: {bad}. "
                             f"Valid: {sorted(valid_set)}",
                }
            return {"valid": True}

        # Single-select validation
        if question_id in self._VALID_OPTIONS:
            valid_set = self._VALID_OPTIONS[question_id]
            if answer not in valid_set:
                return {
                    "valid": False,
                    "error": f"Invalid option for {question_id}: {answer!r}. "
                             f"Valid: {sorted(valid_set)}",
                }
            return {"valid": True}

        # Unknown question -- accept (forward-compatible)
        return {"valid": True}

    # ------------------------------------------------------------------
    # Single-answer processing
    # ------------------------------------------------------------------

    async def process_answer(
        self,
        question_id: str,
        answer: Any,
        kb: Any,
    ) -> dict[str, Any]:
        """Validate and write a single answer to the knowledge base.

        Parameters
        ----------
        question_id:
            The question identifier.
        answer:
            The user's answer.
        kb:
            A :class:`~rex.memory.knowledge.KnowledgeBase` instance.

        Returns
        -------
        dict[str, Any]
            ``{"valid": True, "written": True}`` on success, or
            ``{"valid": False, "error": "..."}`` on validation failure.
        """
        validation = self.validate_answer(question_id, answer)
        if not validation["valid"]:
            return validation

        mapping = self.ANSWER_MAP.get(question_id)
        if mapping is None:
            logger.warning(
                "No KB mapping for question %s -- answer stored but not persisted",
                question_id,
            )
            return {"valid": True, "written": False}

        section_name, key = mapping

        # Format the answer value for KB storage
        display_value = self._format_for_kb(question_id, answer)

        # Read the current section, update the key, and write back
        try:
            current = await kb.read_section(section_name)

            if section_name == "USER NOTES":
                # USER NOTES is free-text, not a kv section
                await self._write_user_notes(kb, answer)
            else:
                if not isinstance(current, dict):
                    current = {}
                current[key] = display_value
                await kb.write(section_name, current)

            logger.info(
                "Persisted answer for %s -> %s.%s = %s",
                question_id, section_name, key, display_value,
            )
            return {"valid": True, "written": True}

        except Exception:
            logger.exception("Failed to persist answer for %s", question_id)
            return {"valid": True, "written": False, "error": "KB write failed"}

    # ------------------------------------------------------------------
    # Batch finalisation
    # ------------------------------------------------------------------

    async def finalize_onboarding(
        self,
        all_answers: dict[str, Any],
        kb: Any,
        git_manager: Any | None = None,
    ) -> dict[str, Any]:
        """Write all answers to the KB in one pass and optionally Git-commit.

        Parameters
        ----------
        all_answers:
            Complete mapping of question_id -> answer.
        kb:
            A :class:`~rex.memory.knowledge.KnowledgeBase` instance.
        git_manager:
            Optional :class:`~rex.memory.versioning.GitManager` for atomic
            commit of the changes.

        Returns
        -------
        dict[str, Any]
            ``{"success": True, "commit_sha": "..."}`` on success, or
            ``{"success": False, "errors": [...]}`` on failure.
        """
        errors: list[str] = []

        # Group answers by KB section to minimise write operations
        section_updates: dict[str, dict[str, str]] = {}
        user_notes_text: str | None = None

        for qid, answer in all_answers.items():
            mapping = self.ANSWER_MAP.get(qid)
            if mapping is None:
                continue

            section_name, key = mapping
            display_value = self._format_for_kb(qid, answer)

            if section_name == "USER NOTES":
                user_notes_text = str(answer) if answer else None
                continue

            if section_name not in section_updates:
                section_updates[section_name] = {}
            section_updates[section_name][key] = display_value

        # Write each section
        for section_name, updates in section_updates.items():
            try:
                current = await kb.read_section(section_name)
                if not isinstance(current, dict):
                    current = {}
                current.update(updates)
                await kb.write(section_name, current)
            except Exception as exc:
                msg = f"Failed to write {section_name}: {exc}"
                logger.exception(msg)
                errors.append(msg)

        # Write user notes if present
        if user_notes_text:
            try:
                await self._write_user_notes(kb, user_notes_text)
            except Exception as exc:
                msg = f"Failed to write USER NOTES: {exc}"
                logger.exception(msg)
                errors.append(msg)

        # Add changelog entry
        try:
            await kb.add_changelog_entry(
                "Onboarding interview completed", source="REX-INTERVIEW"
            )
        except Exception:
            logger.exception("Failed to add changelog entry")

        # Git commit if manager is available
        commit_sha: str | None = None
        if git_manager is not None:
            try:
                commit_sha = await git_manager.commit(
                    "Onboarding interview completed -- initial configuration set",
                    author="REX-INTERVIEW",
                )
            except Exception:
                logger.exception("Git commit failed after onboarding")

        if errors:
            return {"success": False, "errors": errors}

        return {"success": True, "commit_sha": commit_sha}

    # ------------------------------------------------------------------
    # Summary generation
    # ------------------------------------------------------------------

    def generate_summary(self, all_answers: dict[str, Any]) -> str:
        """Generate a human-readable summary of the interview results.

        Uses the REX dog persona to present findings conversationally.

        Parameters
        ----------
        all_answers:
            Complete mapping of question_id -> answer.

        Returns
        -------
        str
            A multi-line summary string suitable for display.
        """
        lines: list[str] = [
            "*tail wag* Here's what REX learned about your network:",
            "",
        ]

        # Environment
        env = all_answers.get("environment_type")
        if env:
            label = self._LABELS.get("environment_type", {}).get(env, env)
            lines.append(f"  - This is {label}")

        # Protection mode
        prot = all_answers.get("protection_mode")
        if prot:
            label = self._LABELS.get("protection_mode", {}).get(prot, prot)
            lines.append(f"  - REX will {label}")

        # Notifications
        notif = all_answers.get("notification_channel")
        if notif:
            label = self._LABELS.get("notification_channel", {}).get(notif, notif)
            lines.append(f"  - Notifications will go to {label}")

        # IoT
        iot = all_answers.get("iot_scrutiny")
        if iot:
            label = self._LABELS.get("iot_scrutiny", {}).get(iot, iot)
            lines.append(f"  - IoT devices will {label}")

        # Exposed services
        exposed = all_answers.get("exposed_service")
        if exposed:
            label = self._LABELS.get("exposed_service", {}).get(exposed, exposed)
            lines.append(f"  - External service access will be {label}")

        # Scan schedule
        sched = all_answers.get("scan_schedule")
        if sched:
            label = self._LABELS.get("scan_schedule", {}).get(sched, sched)
            lines.append(f"  - Deep scans will run {label}")

        # DNS
        dns = all_answers.get("dns_preference")
        if dns:
            label = self._LABELS.get("dns_preference", {}).get(dns, dns)
            lines.append(f"  - DNS will use {label}")

        # Inspection depth
        depth = all_answers.get("inspection_depth")
        if depth:
            label = self._LABELS.get("inspection_depth", {}).get(depth, depth)
            lines.append(f"  - Traffic inspection: {label}")

        # Notification detail
        detail = all_answers.get("notification_detail_level")
        if detail:
            label = self._LABELS.get("notification_detail_level", {}).get(detail, detail)
            lines.append(f"  - Alert detail level: {label}")

        # VPN
        vpn = all_answers.get("vpn_policy")
        if vpn:
            label = self._LABELS.get("vpn_policy", {}).get(vpn, vpn)
            lines.append(f"  - VPN setup: {label}")

        # Guest network
        guest = all_answers.get("guest_network")
        if guest:
            label = self._LABELS.get("guest_network", {}).get(guest, guest)
            lines.append(f"  - Guest network: {label}")

        # User count
        users = all_answers.get("user_count")
        if users:
            lines.append(f"  - Expected users: {users}")

        # Compliance
        compliance = all_answers.get("compliance_requirements")
        if compliance:
            if isinstance(compliance, list):
                if "none" not in compliance:
                    frameworks = ", ".join(c.upper().replace("_", "-") for c in compliance)
                    lines.append(f"  - Compliance frameworks: {frameworks}")
            elif compliance != "none":
                lines.append(f"  - Compliance: {compliance}")

        # Messaging
        msg_plat = all_answers.get("messaging_platform")
        if msg_plat:
            label = self._LABELS.get("messaging_platform", {}).get(msg_plat, msg_plat)
            lines.append(f"  - Agent control via {label}")

        # Pentest IPs
        pentest = all_answers.get("authorized_pentest_ips")
        if pentest and str(pentest).strip():
            lines.append(f"  - Whitelisted IPs: {pentest}")

        # Notes
        notes = all_answers.get("additional_notes")
        if notes and str(notes).strip():
            lines.append(f'  - Your notes: "{notes}"')

        lines.append("")
        lines.append("Ready to start protecting? *excited bark*")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _format_for_kb(self, question_id: str, answer: Any) -> str:
        """Format an answer value for storage in the KB markdown.

        Multi-select answers become comma-separated strings.
        Everything else is coerced to ``str``.

        Parameters
        ----------
        question_id:
            The question identifier (for context-dependent formatting).
        answer:
            The raw answer value.

        Returns
        -------
        str
            Formatted string suitable for markdown key-value storage.
        """
        if isinstance(answer, list):
            return ", ".join(str(v) for v in answer)
        return str(answer) if answer is not None else ""

    async def _write_user_notes(self, kb: Any, text: str) -> None:
        """Write free-text notes to the USER NOTES section.

        The notes are written as a block-quote with a timestamp header.

        Parameters
        ----------
        kb:
            KnowledgeBase instance.
        text:
            The user's free-text input.
        """
        if not text or not str(text).strip():
            return

        stamp = iso_timestamp()
        content = f"> Operator notes from onboarding ({stamp}):\n> {text}"
        await kb.write("USER NOTES", content)
