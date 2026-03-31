"""Host-environment detection -- OS, hardware, and deployment recommendations.

Layer 0.5 -- imports only from :mod:`rex.shared` and stdlib.

All detection functions work **without psutil**.  On Linux they read
``/proc/`` and ``/sys/`` pseudo-filesystems directly; on other
platforms they fall back to :mod:`platform`, :mod:`os`, and
:mod:`shutil`.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from rex.shared.enums import HardwareTier
from rex.shared.models import GPUInfo, OSInfo, SystemResources


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _read_file(path: str, default: str = "") -> str:
    """Read a file and return its contents, or *default* on any error."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return default


def _run_cmd(cmd: list[str], timeout: int = 10) -> str:
    """Run a subprocess and return stripped stdout, or ``""`` on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _parse_proc_meminfo() -> dict[str, int]:
    """Parse ``/proc/meminfo`` into a dict of key -> kB values."""
    info: dict[str, int] = {}
    content = _read_file("/proc/meminfo")
    if not content:
        return info
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip().split()[0]  # value before "kB"
            try:
                info[key] = int(val)
            except ValueError:
                pass
    return info


def _parse_proc_cpuinfo() -> dict[str, Any]:
    """Extract CPU model and core count from ``/proc/cpuinfo``."""
    content = _read_file("/proc/cpuinfo")
    model = "Unknown CPU"
    physical_ids: set[str] = set()
    processors = 0

    for line in content.splitlines():
        if line.startswith("model name"):
            # Take the first model name encountered
            parts = line.split(":", 1)
            if len(parts) == 2 and model == "Unknown CPU":
                model = parts[1].strip()
        elif line.startswith("processor"):
            processors += 1
        elif line.startswith("physical id"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                physical_ids.add(parts[1].strip())

    return {
        "model": model,
        "logical_cores": processors or (os.cpu_count() or 1),
    }


def _detect_gpu_nvidia() -> GPUInfo | None:
    """Attempt to detect an NVIDIA GPU via ``nvidia-smi``."""
    output = _run_cmd([
        "nvidia-smi",
        "--query-gpu=name,memory.total,driver_version",
        "--format=csv,noheader,nounits",
    ])
    if not output:
        return None

    # Take the first GPU line
    line = output.splitlines()[0]
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 3:
        return None

    model = parts[0]
    try:
        vram_mb = int(float(parts[1]))
    except (ValueError, IndexError):
        vram_mb = 0
    driver = parts[2] if len(parts) > 2 else None

    # Check CUDA availability
    cuda_available = bool(_run_cmd(["nvcc", "--version"]))

    return GPUInfo(
        model=model,
        vram_mb=vram_mb,
        driver=driver,
        cuda_available=cuda_available,
        rocm_available=False,
        metal_available=False,
    )


def _detect_gpu_amd() -> GPUInfo | None:
    """Attempt to detect an AMD GPU via ``rocm-smi``."""
    output = _run_cmd(["rocm-smi", "--showproductname"])
    if not output:
        return None

    model = "AMD GPU"
    for line in output.splitlines():
        if "GPU" in line or "Card" in line:
            # Try to extract a meaningful model name
            parts = line.split(":")
            if len(parts) >= 2:
                model = parts[-1].strip()
                break

    # Try to get VRAM
    vram_mb = 0
    vram_output = _run_cmd(["rocm-smi", "--showmeminfo", "vram"])
    if vram_output:
        for line in vram_output.splitlines():
            if "Total" in line:
                # Parse total VRAM in bytes, convert to MB
                nums = re.findall(r"(\d+)", line)
                if nums:
                    try:
                        vram_mb = int(nums[-1]) // (1024 * 1024)
                    except (ValueError, IndexError):
                        pass

    return GPUInfo(
        model=model,
        vram_mb=vram_mb,
        driver=None,
        cuda_available=False,
        rocm_available=True,
        metal_available=False,
    )


def _detect_gpu_apple() -> GPUInfo | None:
    """Detect Apple Silicon / Metal GPU on macOS."""
    if platform.system() != "Darwin":
        return None

    output = _run_cmd(["system_profiler", "SPDisplaysDataType"])
    if not output:
        return None

    model = "Apple GPU"
    vram_mb = 0

    for line in output.splitlines():
        stripped = line.strip()
        if "Chipset Model:" in stripped:
            model = stripped.split(":", 1)[1].strip()
        elif "VRAM" in stripped:
            nums = re.findall(r"(\d+)", stripped)
            if nums:
                try:
                    val = int(nums[0])
                    # Heuristic: if value < 1024 it is likely GB
                    vram_mb = val * 1024 if val < 1024 else val
                except ValueError:
                    pass

    # On Apple Silicon unified memory is shared -- report total RAM
    # as VRAM if no explicit VRAM line was found.
    if vram_mb == 0:
        try:
            import ctypes
            # Fallback: use sysctl
            mem_output = _run_cmd(["sysctl", "-n", "hw.memsize"])
            if mem_output:
                vram_mb = int(mem_output) // (1024 * 1024)
        except (ValueError, OSError):
            pass

    return GPUInfo(
        model=model,
        vram_mb=vram_mb,
        driver=None,
        cuda_available=False,
        rocm_available=False,
        metal_available=True,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_os() -> OSInfo:
    """Detect the host operating system and environment flags.

    On Linux reads ``/etc/os-release``; on other platforms uses the
    :mod:`platform` module.  Also detects WSL, Docker, VM, and
    Raspberry Pi environments.

    Returns
    -------
    OSInfo
        Fully populated OS metadata model.
    """
    system = platform.system()
    name = system
    version = platform.release()
    codename: str | None = None
    architecture = platform.machine() or "unknown"

    # --- Linux: parse /etc/os-release for richer metadata ----------------
    if system == "Linux":
        os_release = _read_file("/etc/os-release")
        if os_release:
            for line in os_release.splitlines():
                if line.startswith("NAME="):
                    name = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    version = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_CODENAME="):
                    codename = line.split("=", 1)[1].strip().strip('"')
        # Fallback if /etc/os-release was missing
        if name == "Linux":
            lsb = _run_cmd(["lsb_release", "-d", "-s"])
            if lsb:
                name = lsb

    elif system == "Darwin":
        name = "macOS"
        mac_ver = platform.mac_ver()
        if mac_ver[0]:
            version = mac_ver[0]

    elif system == "Windows":
        name = "Windows"
        win_ver = platform.version()
        if win_ver:
            version = win_ver

    elif system == "FreeBSD":
        name = "FreeBSD"

    # --- Environment flags -----------------------------------------------
    is_wsl = False
    is_docker = False
    is_vm = False
    is_raspberry_pi = False

    # WSL detection
    proc_version = _read_file("/proc/version")
    if "microsoft" in proc_version.lower() or "wsl" in proc_version.lower():
        is_wsl = True

    # Docker detection -- check multiple indicators
    cgroup = _read_file("/proc/1/cgroup")
    if "docker" in cgroup or "containerd" in cgroup:
        is_docker = True
    elif Path("/.dockerenv").exists():
        is_docker = True

    # VM detection
    is_vm = _detect_is_vm()

    # Raspberry Pi detection
    cpuinfo = _read_file("/proc/cpuinfo")
    if "BCM" in cpuinfo:
        is_raspberry_pi = True
    else:
        device_model = _read_file("/proc/device-tree/model")
        if "raspberry" in device_model.lower():
            is_raspberry_pi = True

    return OSInfo(
        name=name,
        version=version,
        codename=codename,
        architecture=architecture,
        is_wsl=is_wsl,
        is_docker=is_docker,
        is_vm=is_vm,
        is_raspberry_pi=is_raspberry_pi,
    )


def _detect_is_vm() -> bool:
    """Determine if the host is running inside a virtual machine."""
    vm_indicators = ("virtualbox", "vmware", "kvm", "qemu", "xen", "hyper-v", "bhyve")

    # Method 1: /sys/class/dmi/id/product_name (Linux, no root needed)
    product_name = _read_file("/sys/class/dmi/id/product_name").lower()
    if any(indicator in product_name for indicator in vm_indicators):
        return True

    # Method 2: /sys/class/dmi/id/sys_vendor
    sys_vendor = _read_file("/sys/class/dmi/id/sys_vendor").lower()
    if any(indicator in sys_vendor for indicator in vm_indicators):
        return True

    # Method 3: /sys/class/dmi/id/board_name
    board_name = _read_file("/sys/class/dmi/id/board_name").lower()
    if any(indicator in board_name for indicator in vm_indicators):
        return True

    # Method 4: dmidecode (requires root, best-effort)
    dmi_output = _run_cmd(["dmidecode", "-s", "system-product-name"]).lower()
    if any(indicator in dmi_output for indicator in vm_indicators):
        return True

    # Method 5: systemd-detect-virt (common on modern Linux)
    virt = _run_cmd(["systemd-detect-virt"])
    if virt and virt != "none":
        return True

    return False


def detect_hardware() -> SystemResources:
    """Detect host hardware resources without psutil.

    On Linux this reads ``/proc/meminfo``, ``/proc/cpuinfo``, and
    queries GPU information via ``nvidia-smi`` or ``rocm-smi``.
    On other platforms it falls back to :mod:`platform`, :mod:`os`,
    and :mod:`shutil`.

    Returns
    -------
    SystemResources
        Snapshot of CPU, RAM, disk, and GPU resources.
    """
    system = platform.system()

    # --- CPU -------------------------------------------------------------
    cpu_model = "Unknown CPU"
    cpu_cores = os.cpu_count() or 1

    if system == "Linux":
        cpu_data = _parse_proc_cpuinfo()
        cpu_model = cpu_data["model"]
        cpu_cores = cpu_data["logical_cores"]
    elif system == "Darwin":
        brand = _run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"])
        if brand:
            cpu_model = brand
        cores_str = _run_cmd(["sysctl", "-n", "hw.logicalcpu"])
        if cores_str:
            try:
                cpu_cores = int(cores_str)
            except ValueError:
                pass
    elif system == "Windows":
        cpu_model = platform.processor() or "Unknown CPU"

    # --- RAM -------------------------------------------------------------
    ram_total_mb = 0
    ram_available_mb = 0

    if system == "Linux":
        meminfo = _parse_proc_meminfo()
        # /proc/meminfo reports kB (kibibytes)
        ram_total_mb = meminfo.get("MemTotal", 0) // 1024
        ram_available_mb = meminfo.get("MemAvailable", 0) // 1024
        # Fallback if MemAvailable is missing (old kernels)
        if ram_available_mb == 0:
            ram_available_mb = (
                meminfo.get("MemFree", 0)
                + meminfo.get("Buffers", 0)
                + meminfo.get("Cached", 0)
            ) // 1024
    elif system == "Darwin":
        mem_str = _run_cmd(["sysctl", "-n", "hw.memsize"])
        if mem_str:
            try:
                ram_total_mb = int(mem_str) // (1024 * 1024)
            except ValueError:
                pass
        # Approximate available memory via vm_stat
        vm_stat = _run_cmd(["vm_stat"])
        if vm_stat:
            free_pages = 0
            inactive_pages = 0
            page_size = 4096  # default
            for line in vm_stat.splitlines():
                if "page size of" in line:
                    nums = re.findall(r"(\d+)", line)
                    if nums:
                        page_size = int(nums[0])
                elif "Pages free:" in line:
                    nums = re.findall(r"(\d+)", line)
                    if nums:
                        free_pages = int(nums[0])
                elif "Pages inactive:" in line:
                    nums = re.findall(r"(\d+)", line)
                    if nums:
                        inactive_pages = int(nums[0])
            ram_available_mb = (free_pages + inactive_pages) * page_size // (1024 * 1024)
    else:
        # Windows or other -- best-effort with platform
        # On Windows we can try wmic
        if system == "Windows":
            wmic_total = _run_cmd([
                "wmic", "ComputerSystem", "get", "TotalPhysicalMemory", "/value",
            ])
            for line in wmic_total.splitlines():
                if "TotalPhysicalMemory" in line:
                    parts = line.split("=")
                    if len(parts) == 2:
                        try:
                            ram_total_mb = int(parts[1].strip()) // (1024 * 1024)
                        except ValueError:
                            pass
            wmic_free = _run_cmd([
                "wmic", "OS", "get", "FreePhysicalMemory", "/value",
            ])
            for line in wmic_free.splitlines():
                if "FreePhysicalMemory" in line:
                    parts = line.split("=")
                    if len(parts) == 2:
                        try:
                            ram_available_mb = int(parts[1].strip()) // 1024  # kB -> MB
                        except ValueError:
                            pass

    # --- CPU utilization (snapshot) --------------------------------------
    cpu_percent = 0.0
    if system == "Linux":
        # Read /proc/stat for a rough idle percentage
        stat = _read_file("/proc/stat")
        if stat:
            first_line = stat.splitlines()[0]  # "cpu  user nice sys idle ..."
            parts = first_line.split()
            if len(parts) >= 5:
                try:
                    values = [int(v) for v in parts[1:]]
                    total = sum(values)
                    idle = values[3]  # idle is the 4th column
                    if total > 0:
                        cpu_percent = round((1.0 - idle / total) * 100, 1)
                except (ValueError, IndexError):
                    pass

    # --- GPU -------------------------------------------------------------
    gpu_model: str | None = None
    gpu_vram_mb: int | None = None

    gpu = _detect_gpu_nvidia()
    if gpu is None:
        gpu = _detect_gpu_amd()
    if gpu is None and system == "Darwin":
        gpu = _detect_gpu_apple()

    if gpu is not None:
        gpu_model = gpu.model
        gpu_vram_mb = gpu.vram_mb

    # --- Disk ------------------------------------------------------------
    disk_total_gb = 0.0
    disk_free_gb = 0.0
    try:
        usage = shutil.disk_usage("/")
        disk_total_gb = round(usage.total / (1024 ** 3), 2)
        disk_free_gb = round(usage.free / (1024 ** 3), 2)
    except OSError:
        pass

    return SystemResources(
        cpu_model=cpu_model,
        cpu_cores=cpu_cores,
        cpu_percent=cpu_percent,
        ram_total_mb=ram_total_mb,
        ram_available_mb=ram_available_mb,
        gpu_model=gpu_model,
        gpu_vram_mb=gpu_vram_mb,
        disk_total_gb=disk_total_gb,
        disk_free_gb=disk_free_gb,
    )


def recommend_llm_model(hw: SystemResources) -> str:
    """Recommend an Ollama model tag based on available resources.

    The recommendations are conservative -- they assume the LLM will
    share the machine with REX services, packet capture, and possibly
    Docker containers.

    Parameters
    ----------
    hw:
        Hardware snapshot from :func:`detect_hardware`.

    Returns
    -------
    str
        An Ollama model tag like ``"llama3:8b"`` or ``"phi3:mini"``.

    Thresholds
    ----------
    ========  ==================  =========================
    RAM (GB)  VRAM (GB)           Model
    ========  ==================  =========================
    < 4       --                  ``phi3:mini``
    4-8       --                  ``mistral:7b-q4``
    8-16      --                  ``llama3:8b``
    16-32     --                  ``llama3:8b-q8``
    32+       --                  ``llama3:70b-q4``
    --        >= 12               ``llama3:70b-q4``
    ========  ==================  =========================
    """
    ram_gb = hw.ram_total_mb / 1024
    vram_gb = (hw.gpu_vram_mb or 0) / 1024

    # A beefy GPU with >= 12 GB VRAM can offload to GPU regardless of RAM
    if vram_gb >= 12:
        return "llama3:70b-q4"

    if ram_gb >= 32:
        return "llama3:70b-q4"
    elif ram_gb >= 16:
        return "llama3:8b-q8"
    elif ram_gb >= 8:
        return "llama3:8b"
    elif ram_gb >= 4:
        return "mistral:7b-q4"
    else:
        return "phi3:mini"


def recommend_tier(device_count: int, has_ad: bool = False) -> HardwareTier:
    """Recommend a deployment tier based on network size.

    Parameters
    ----------
    device_count:
        Number of devices on the monitored network.
    has_ad:
        ``True`` if Active Directory / LDAP is detected (implies
        enterprise environment).

    Returns
    -------
    HardwareTier
        ``MINIMAL`` (home), ``STANDARD`` (SMB), or ``FULL``
        (enterprise).

    Thresholds
    ----------
    ===============  ===========  ====
    Device count     AD present?  Tier
    ===============  ===========  ====
    < 10             No           MINIMAL  (home)
    10 -- 50         No           STANDARD (SMB)
    > 50 *or* any    Yes          FULL     (enterprise)
    ===============  ===========  ====
    """
    if has_ad or device_count > 50:
        return HardwareTier.FULL
    elif device_count >= 10:
        return HardwareTier.STANDARD
    else:
        return HardwareTier.MINIMAL
