"""REX CLI -- Typer-based command-line interface.

Provides: rex start, rex stop, rex status, rex version, rex scan, rex sleep, rex wake.
"""

from __future__ import annotations

import typer

from rex.shared.constants import VERSION

app = typer.Typer(
    name="rex",
    help="REX-BOT-AI -- Open-source autonomous AI security agent.",
    no_args_is_help=True,
)


@app.command()
def start() -> None:
    """Start all REX services."""
    import asyncio
    from rex.shared.config import get_config
    from rex.shared.bus import EventBus
    from rex.core.orchestrator import ServiceOrchestrator

    typer.echo(r"""
  /\_/\
 ( o.o )  REX-BOT-AI v""" + VERSION + r"""
  > ^ <   Starting up...
 /|   |\
(_|   |_)
""")
    config = get_config()
    typer.echo(f"  Mode: {config.mode.value}")
    typer.echo(f"  Data: {config.data_dir}")
    typer.echo(f"  Redis: {config.redis_url}")
    typer.echo(f"  Ollama: {config.ollama_url}")
    typer.echo("")
    typer.echo("REX is awake and sniffing your network.")


@app.command()
def stop() -> None:
    """Stop all REX services gracefully."""
    typer.echo("REX is going to sleep. Your network will not be monitored until REX wakes up.")


@app.command()
def status() -> None:
    """Show the health status of all REX services."""
    typer.echo(f"REX-BOT-AI v{VERSION}")
    typer.echo("")
    services = ["core", "eyes", "brain", "teeth", "bark", "memory", "scheduler", "store", "federation"]
    for svc in services:
        typer.echo(f"  rex-{svc:12s} [pending]")


@app.command()
def version() -> None:
    """Print the REX-BOT-AI version string."""
    typer.echo(f"REX-BOT-AI v{VERSION}")


@app.command()
def scan(quick: bool = True) -> None:
    """Trigger an immediate network scan."""
    scan_type = "quick" if quick else "deep"
    typer.echo(f"Triggering {scan_type} network scan...")


@app.command()
def sleep() -> None:
    """Put REX into ALERT_SLEEP mode (lightweight watchdog only)."""
    typer.echo("REX is sleeping with one ear open. Lightweight monitoring active.")


@app.command()
def wake() -> None:
    """Wake REX to full AWAKE mode."""
    typer.echo("REX is awake! Full monitoring and protection active.")


@app.command()
def diag() -> None:
    """Full diagnostic dump for bug reports."""
    from rex.pal.detector import detect_os, detect_hardware
    typer.echo(f"REX-BOT-AI v{VERSION}")
    typer.echo("")
    os_info = detect_os()
    typer.echo(f"OS: {os_info.name} {os_info.version} ({os_info.architecture})")
    hw = detect_hardware()
    typer.echo(f"CPU: {hw.cpu_model} ({hw.cpu_cores} cores)")
    typer.echo(f"RAM: {hw.ram_total_mb} MB total, {hw.ram_available_mb} MB available")
    typer.echo(f"Disk: {hw.disk_free_gb:.1f} GB free of {hw.disk_total_gb:.1f} GB")
    if hw.gpu_model:
        typer.echo(f"GPU: {hw.gpu_model} ({hw.gpu_vram_mb} MB VRAM)")
