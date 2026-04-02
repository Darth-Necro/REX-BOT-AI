"""Centralised subprocess execution utilities for REX-BOT-AI.

Layer 0 -- no imports from other rex modules.

Provides consistent subprocess execution for platform-layer (PAL) and
scanning (eyes) modules that need to run external commands but are
**not** part of the whitelisted command-executor security boundary.

The whitelisted :class:`~rex.core.agent.command_executor.CommandExecutor`
handles user-facing security commands (nmap via CLI, nftables rules, etc.)
with argument validation and full audit trails.  This module provides a
lighter-weight boundary for *trusted platform queries* such as ``arp``,
``route``, ``ifconfig``, ``nvidia-smi``, ``docker``, etc. that:

- Must **never** use shell mode (shell argument must be False).
- Must use a **sanitised environment** (no credential leakage).
- Must enforce a **timeout**.
- Must emit **audit-grade log lines** for every invocation.
- Must normalise failures into predictable return types.

Streaming subprocesses (e.g. ``tcpdump`` packet capture via ``Popen``)
are intentionally out of scope -- they remain specialised in their
respective PAL modules because they follow a fundamentally different
read-stream pattern.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment sanitisation
# ---------------------------------------------------------------------------

_SAFE_ENV_KEYS: frozenset[str] = frozenset({
    "PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL", "LOGNAME",
})


def safe_env() -> dict[str, str]:
    """Return a minimal environment with only safe keys.

    Prevents leaking secrets, tokens, API keys, or other sensitive
    environment variables to child processes.  Matches the policy
    used by :class:`~rex.core.agent.command_executor.CommandExecutor`.
    """
    return {
        k: v for k, v in os.environ.items()
        if k in _SAFE_ENV_KEYS or k.startswith("LC_")
    }


# ---------------------------------------------------------------------------
# Synchronous runner (PAL layer)
# ---------------------------------------------------------------------------

def run_subprocess(
    cmd: list[str],
    *,
    timeout: int = 10,
    check: bool = False,
    label: str = "",
) -> subprocess.CompletedProcess[str]:
    """Run an external command synchronously with sanitised environment.

    Parameters
    ----------
    cmd:
        Command and arguments as a list of strings (never a shell string).
    timeout:
        Maximum seconds before the process is killed.
    check:
        If ``True``, raise :class:`subprocess.CalledProcessError` on
        non-zero exit.
    label:
        Human-readable label for audit logging (e.g. ``"nft add rule"``).

    Returns
    -------
    subprocess.CompletedProcess[str]
        The completed process result.  On ``FileNotFoundError`` or
        ``TimeoutExpired``, a synthetic ``CompletedProcess`` is returned
        with ``returncode`` 127 or -1 respectively.
    """
    tag = label or cmd[0]
    logger.debug("[SUBPROCESS] %s: %s", tag, " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=check,
            env=safe_env(),
        )
        if result.returncode != 0:
            logger.debug(
                "[SUBPROCESS] %s exited %d: %s",
                tag, result.returncode, result.stderr[:200],
            )
        return result
    except FileNotFoundError:
        logger.warning("[SUBPROCESS] Command not found: %s", cmd[0])
        return subprocess.CompletedProcess(
            cmd, returncode=127, stdout="", stderr=f"{cmd[0]}: not found",
        )
    except subprocess.TimeoutExpired:
        logger.warning("[SUBPROCESS] %s timed out after %ds", tag, timeout)
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr="timeout",
        )
    except subprocess.CalledProcessError:
        # Only reachable when check=True -- re-raise so callers handle it.
        raise
    except OSError as exc:
        logger.warning("[SUBPROCESS] OS error running %s: %s", tag, exc)
        return subprocess.CompletedProcess(
            cmd, returncode=1, stdout="", stderr=str(exc),
        )


# ---------------------------------------------------------------------------
# Asynchronous runner (eyes layer)
# ---------------------------------------------------------------------------

async def run_subprocess_async(
    *cmd: str,
    timeout: float = 60,
    label: str = "",
) -> tuple[int, str, str]:
    """Run an external command asynchronously with sanitised environment.

    Parameters
    ----------
    *cmd:
        Command and arguments as positional strings.
    timeout:
        Maximum seconds before the process is killed.
    label:
        Human-readable label for audit logging.

    Returns
    -------
    tuple[int, str, str]
        ``(returncode, stdout, stderr)``.  On timeout the process is
        killed and ``(-1, "", "timeout")`` is returned.  On
        ``FileNotFoundError``, ``(127, "", "<cmd>: not found")`` is
        returned.
    """
    tag = label or cmd[0]
    logger.debug("[SUBPROCESS-ASYNC] %s: %s", tag, " ".join(cmd))
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=safe_env(),
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
        rc = proc.returncode or 0
        stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
        stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
        if rc != 0:
            logger.debug(
                "[SUBPROCESS-ASYNC] %s exited %d: %s",
                tag, rc, stderr[:200],
            )
        return rc, stdout, stderr
    except TimeoutError:
        logger.warning("[SUBPROCESS-ASYNC] %s timed out after %.0fs", tag, timeout)
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()
        return -1, "", "timeout"
    except FileNotFoundError:
        logger.warning("[SUBPROCESS-ASYNC] Command not found: %s", cmd[0])
        return 127, "", f"{cmd[0]}: not found"
    except OSError as exc:
        logger.warning("[SUBPROCESS-ASYNC] OS error running %s: %s", tag, exc)
        return 1, "", str(exc)
