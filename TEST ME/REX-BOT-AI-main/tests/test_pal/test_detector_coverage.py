"""Coverage tests for rex.pal.detector -- fills gaps in OS/hardware detection."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from rex.shared.enums import HardwareTier
from rex.shared.models import GPUInfo, OSInfo, SystemResources


# =====================================================================
# Helpers
# =====================================================================

def _make_hw(
    ram_mb: int = 4096,
    gpu_vram_mb: int | None = None,
    cpu_cores: int = 4,
) -> SystemResources:
    """Build a SystemResources with sensible defaults."""
    return SystemResources(
        cpu_model="Test CPU",
        cpu_cores=cpu_cores,
        ram_total_mb=ram_mb,
        ram_available_mb=ram_mb // 2,
        gpu_model="Test GPU" if gpu_vram_mb else None,
        gpu_vram_mb=gpu_vram_mb,
        disk_total_gb=100.0,
        disk_free_gb=50.0,
    )


# =====================================================================
# _read_file
# =====================================================================

class TestReadFile:
    """Cover _read_file helper."""

    @patch("rex.pal.detector.Path")
    def test_read_file_success(self, mock_path_cls):
        from rex.pal.detector import _read_file
        mock_path_cls.return_value.read_text.return_value = "  hello world  "
        assert _read_file("/some/path") == "hello world"

    @patch("rex.pal.detector.Path")
    def test_read_file_oserror(self, mock_path_cls):
        from rex.pal.detector import _read_file
        mock_path_cls.return_value.read_text.side_effect = OSError("no file")
        assert _read_file("/bad/path") == ""

    @patch("rex.pal.detector.Path")
    def test_read_file_permission_error(self, mock_path_cls):
        from rex.pal.detector import _read_file
        mock_path_cls.return_value.read_text.side_effect = PermissionError("denied")
        assert _read_file("/secret", default="fallback") == "fallback"


# =====================================================================
# _run_cmd
# =====================================================================

class TestRunCmd:
    """Cover _run_cmd helper."""

    @patch("rex.pal.detector.subprocess.run")
    def test_run_cmd_success(self, mock_run):
        from rex.pal.detector import _run_cmd
        mock_run.return_value = subprocess.CompletedProcess(
            ["echo"], 0, stdout="  output  ", stderr="",
        )
        assert _run_cmd(["echo", "hi"]) == "output"

    @patch("rex.pal.detector.subprocess.run", side_effect=FileNotFoundError)
    def test_run_cmd_file_not_found(self, _mock):
        from rex.pal.detector import _run_cmd
        assert _run_cmd(["nonexist"]) == ""

    @patch(
        "rex.pal.detector.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["x"], timeout=10),
    )
    def test_run_cmd_timeout(self, _mock):
        from rex.pal.detector import _run_cmd
        assert _run_cmd(["slow"]) == ""

    @patch("rex.pal.detector.subprocess.run", side_effect=OSError("boom"))
    def test_run_cmd_oserror(self, _mock):
        from rex.pal.detector import _run_cmd
        assert _run_cmd(["bad"]) == ""


# =====================================================================
# _parse_proc_meminfo
# =====================================================================

class TestParseProcMeminfo:
    """Cover _parse_proc_meminfo."""

    @patch("rex.pal.detector._read_file")
    def test_parses_values(self, mock_read):
        from rex.pal.detector import _parse_proc_meminfo
        mock_read.return_value = (
            "MemTotal:       16384000 kB\n"
            "MemFree:         4096000 kB\n"
            "MemAvailable:    8192000 kB\n"
            "Buffers:          512000 kB\n"
            "Cached:          1024000 kB\n"
        )
        info = _parse_proc_meminfo()
        assert info["MemTotal"] == 16384000
        assert info["MemAvailable"] == 8192000

    @patch("rex.pal.detector._read_file", return_value="")
    def test_empty_meminfo(self, _mock):
        from rex.pal.detector import _parse_proc_meminfo
        assert _parse_proc_meminfo() == {}

    @patch("rex.pal.detector._read_file")
    def test_malformed_lines(self, mock_read):
        from rex.pal.detector import _parse_proc_meminfo
        mock_read.return_value = "nocolon_line\nGood: 42 kB\nBad: notanumber kB"
        info = _parse_proc_meminfo()
        assert info.get("Good") == 42
        assert "Bad" not in info


# =====================================================================
# _parse_proc_cpuinfo
# =====================================================================

class TestParseProcCpuinfo:
    """Cover _parse_proc_cpuinfo."""

    @patch("rex.pal.detector._read_file")
    def test_parses_cpuinfo(self, mock_read):
        from rex.pal.detector import _parse_proc_cpuinfo
        mock_read.return_value = (
            "processor\t: 0\n"
            "model name\t: Intel(R) Core(TM) i7-9700K\n"
            "physical id\t: 0\n"
            "processor\t: 1\n"
            "model name\t: Intel(R) Core(TM) i7-9700K\n"
            "physical id\t: 0\n"
        )
        data = _parse_proc_cpuinfo()
        assert data["model"] == "Intel(R) Core(TM) i7-9700K"
        assert data["logical_cores"] == 2

    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector.os.cpu_count", return_value=4)
    def test_empty_cpuinfo_falls_back(self, _cpu, _read):
        from rex.pal.detector import _parse_proc_cpuinfo
        data = _parse_proc_cpuinfo()
        assert data["model"] == "Unknown CPU"
        assert data["logical_cores"] == 4

    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector.os.cpu_count", return_value=None)
    def test_empty_cpuinfo_none_cores(self, _cpu, _read):
        from rex.pal.detector import _parse_proc_cpuinfo
        data = _parse_proc_cpuinfo()
        assert data["logical_cores"] == 1


# =====================================================================
# _detect_gpu_nvidia
# =====================================================================

class TestDetectGpuNvidia:
    """Cover _detect_gpu_nvidia."""

    @patch("rex.pal.detector._run_cmd")
    def test_nvidia_detected(self, mock_cmd):
        from rex.pal.detector import _detect_gpu_nvidia
        def side_effect(cmd, timeout=10):
            if "nvidia-smi" in cmd[0]:
                return "NVIDIA RTX 4090, 24576, 535.129.03"
            if "nvcc" in cmd[0]:
                return "nvcc: CUDA compilation tools V12.0"
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_nvidia()
        assert gpu is not None
        assert gpu.model == "NVIDIA RTX 4090"
        assert gpu.vram_mb == 24576
        assert gpu.driver == "535.129.03"
        assert gpu.cuda_available is True

    @patch("rex.pal.detector._run_cmd", return_value="")
    def test_nvidia_not_found(self, _mock):
        from rex.pal.detector import _detect_gpu_nvidia
        assert _detect_gpu_nvidia() is None

    @patch("rex.pal.detector._run_cmd")
    def test_nvidia_too_few_fields(self, mock_cmd):
        from rex.pal.detector import _detect_gpu_nvidia
        mock_cmd.return_value = "NVIDIA RTX 4090, 24576"
        gpu = _detect_gpu_nvidia()
        assert gpu is None

    @patch("rex.pal.detector._run_cmd")
    def test_nvidia_bad_vram(self, mock_cmd):
        from rex.pal.detector import _detect_gpu_nvidia
        def side_effect(cmd, timeout=10):
            if "nvidia-smi" in cmd[0]:
                return "NVIDIA RTX 4090, notanumber, 535.129"
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_nvidia()
        assert gpu is not None
        assert gpu.vram_mb == 0


# =====================================================================
# _detect_gpu_amd
# =====================================================================

class TestDetectGpuAmd:
    """Cover _detect_gpu_amd."""

    @patch("rex.pal.detector._run_cmd")
    def test_amd_detected_with_vram(self, mock_cmd):
        from rex.pal.detector import _detect_gpu_amd
        def side_effect(cmd, timeout=10):
            if "--showproductname" in cmd:
                return "GPU[0] : Card series: Radeon RX 7900 XTX"
            if "--showmeminfo" in cmd:
                return "GPU[0] : VRAM Total: 25769803776"
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_amd()
        assert gpu is not None
        assert "Radeon RX 7900 XTX" in gpu.model
        assert gpu.rocm_available is True

    @patch("rex.pal.detector._run_cmd", return_value="")
    def test_amd_not_found(self, _mock):
        from rex.pal.detector import _detect_gpu_amd
        assert _detect_gpu_amd() is None

    @patch("rex.pal.detector._run_cmd")
    def test_amd_no_vram_info(self, mock_cmd):
        from rex.pal.detector import _detect_gpu_amd
        def side_effect(cmd, timeout=10):
            if "--showproductname" in cmd:
                return "GPU[0] : Card series: Radeon RX 7900 XTX"
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_amd()
        assert gpu is not None
        assert gpu.vram_mb == 0

    @patch("rex.pal.detector._run_cmd")
    def test_amd_no_gpu_in_productname(self, mock_cmd):
        from rex.pal.detector import _detect_gpu_amd
        def side_effect(cmd, timeout=10):
            if "--showproductname" in cmd:
                return "some other line"
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_amd()
        assert gpu is not None
        assert gpu.model == "AMD GPU"


# =====================================================================
# _detect_gpu_apple
# =====================================================================

class TestDetectGpuApple:
    """Cover _detect_gpu_apple."""

    @patch("rex.pal.detector.platform.system", return_value="Linux")
    def test_not_darwin(self, _mock):
        from rex.pal.detector import _detect_gpu_apple
        assert _detect_gpu_apple() is None

    @patch("rex.pal.detector.platform.system", return_value="Darwin")
    @patch("rex.pal.detector._run_cmd")
    def test_apple_silicon_detected(self, mock_cmd, _sys):
        from rex.pal.detector import _detect_gpu_apple
        def side_effect(cmd, timeout=10):
            if "system_profiler" in cmd:
                return (
                    "      Chipset Model: Apple M2 Max\n"
                    "      VRAM (Total): 48 GB\n"
                )
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_apple()
        assert gpu is not None
        assert gpu.model == "Apple M2 Max"
        assert gpu.vram_mb == 48 * 1024
        assert gpu.metal_available is True

    @patch("rex.pal.detector.platform.system", return_value="Darwin")
    @patch("rex.pal.detector._run_cmd", return_value="")
    def test_apple_no_profiler_output(self, _cmd, _sys):
        from rex.pal.detector import _detect_gpu_apple
        assert _detect_gpu_apple() is None

    @patch("rex.pal.detector.platform.system", return_value="Darwin")
    @patch("rex.pal.detector._run_cmd")
    def test_apple_no_vram_uses_sysctl(self, mock_cmd, _sys):
        from rex.pal.detector import _detect_gpu_apple
        def side_effect(cmd, timeout=10):
            if "system_profiler" in cmd:
                return "      Chipset Model: Apple M1\n"
            if "sysctl" in cmd:
                return str(16 * 1024 * 1024 * 1024)
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_apple()
        assert gpu is not None
        assert gpu.model == "Apple M1"
        assert gpu.vram_mb == 16 * 1024

    @patch("rex.pal.detector.platform.system", return_value="Darwin")
    @patch("rex.pal.detector._run_cmd")
    def test_apple_vram_large_value(self, mock_cmd, _sys):
        from rex.pal.detector import _detect_gpu_apple
        def side_effect(cmd, timeout=10):
            if "system_profiler" in cmd:
                return (
                    "      Chipset Model: Apple M3\n"
                    "      VRAM (Total): 16384\n"
                )
            return ""
        mock_cmd.side_effect = side_effect
        gpu = _detect_gpu_apple()
        assert gpu is not None
        # 16384 >= 1024, so treated as MB directly
        assert gpu.vram_mb == 16384


# =====================================================================
# detect_os -- Darwin, Windows, FreeBSD branches
# =====================================================================

class TestDetectOSDarwin:
    """Test detect_os on a mocked Darwin environment."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_darwin(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Darwin"
        mock_plat.release.return_value = "23.1.0"
        mock_plat.machine.return_value = "arm64"
        mock_plat.mac_ver.return_value = ("14.2", ("", "", ""), "arm64")
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.name == "macOS"
        assert info.version == "14.2"

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_darwin_no_mac_ver(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Darwin"
        mock_plat.release.return_value = "23.1.0"
        mock_plat.machine.return_value = "arm64"
        mock_plat.mac_ver.return_value = ("", ("", "", ""), "")
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.name == "macOS"


class TestDetectOSWindows:
    """Test detect_os on a mocked Windows environment."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_windows(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Windows"
        mock_plat.release.return_value = "10"
        mock_plat.machine.return_value = "AMD64"
        mock_plat.version.return_value = "10.0.19041"
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.name == "Windows"
        assert info.version == "10.0.19041"


class TestDetectOSFreeBSD:
    """Test detect_os on a mocked FreeBSD environment."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_freebsd(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "FreeBSD"
        mock_plat.release.return_value = "14.0-RELEASE"
        mock_plat.machine.return_value = "amd64"
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.name == "FreeBSD"


class TestDetectOSLinuxFallback:
    """Test detect_os Linux fallback branch when /etc/os-release is empty."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_linux_lsb_fallback(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Linux"
        mock_plat.release.return_value = "5.15.0"
        mock_plat.machine.return_value = "x86_64"
        mock_cmd.return_value = "Ubuntu 22.04 LTS"
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.name == "Ubuntu 22.04 LTS"


class TestDetectOSEnvironmentFlags:
    """Test WSL, Docker, Raspberry Pi detection in detect_os."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_wsl_detected(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Linux"
        mock_plat.release.return_value = "5.15.0"
        mock_plat.machine.return_value = "x86_64"

        def read_side(path, default=""):
            if path == "/proc/version":
                return "Linux version 5.15.0 (Microsoft WSL)"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return ""
            if path == "/proc/device-tree/model":
                return ""
            return ""
        mock_read.side_effect = read_side
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.is_wsl is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_docker_detected(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Linux"
        mock_plat.release.return_value = "5.15.0"
        mock_plat.machine.return_value = "x86_64"

        def read_side(path, default=""):
            if path == "/proc/1/cgroup":
                return "12:blkio:/docker/abc123"
            return ""
        mock_read.side_effect = read_side
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.is_docker is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_raspberry_pi_bcm(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Linux"
        mock_plat.release.return_value = "6.1.0"
        mock_plat.machine.return_value = "aarch64"

        def read_side(path, default=""):
            if path == "/proc/cpuinfo":
                return "Hardware\t: BCM2835"
            return ""
        mock_read.side_effect = read_side
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.is_raspberry_pi is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_raspberry_pi_device_tree(self, mock_path, mock_vm, mock_cmd, mock_read, mock_plat):
        from rex.pal.detector import detect_os
        mock_plat.system.return_value = "Linux"
        mock_plat.release.return_value = "6.1.0"
        mock_plat.machine.return_value = "aarch64"

        def read_side(path, default=""):
            if path == "/proc/device-tree/model":
                return "Raspberry Pi 4 Model B"
            return ""
        mock_read.side_effect = read_side
        mock_path.return_value.exists.return_value = False

        info = detect_os()
        assert info.is_raspberry_pi is True


# =====================================================================
# _detect_is_vm
# =====================================================================

class TestDetectIsVm:
    """Cover the various VM detection methods."""

    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    def test_vm_via_product_name(self, mock_cmd, mock_read):
        from rex.pal.detector import _detect_is_vm
        def read_side(path, default=""):
            if "product_name" in path:
                return "VirtualBox"
            return ""
        mock_read.side_effect = read_side
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    def test_vm_via_sys_vendor(self, mock_cmd, mock_read):
        from rex.pal.detector import _detect_is_vm
        def read_side(path, default=""):
            if "sys_vendor" in path:
                return "VMware, Inc."
            return ""
        mock_read.side_effect = read_side
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    def test_vm_via_board_name(self, mock_cmd, mock_read):
        from rex.pal.detector import _detect_is_vm
        def read_side(path, default=""):
            if "board_name" in path:
                return "QEMU Virtual Machine"
            return ""
        mock_read.side_effect = read_side
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd")
    def test_vm_via_dmidecode(self, mock_cmd, _read):
        from rex.pal.detector import _detect_is_vm
        def side_effect(cmd, timeout=10):
            if "dmidecode" in cmd:
                return "VirtualBox"
            return ""
        mock_cmd.side_effect = side_effect
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd")
    def test_vm_via_systemd_detect_virt(self, mock_cmd, _read):
        from rex.pal.detector import _detect_is_vm
        def side_effect(cmd, timeout=10):
            if "systemd-detect-virt" in cmd:
                return "kvm"
            return ""
        mock_cmd.side_effect = side_effect
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd")
    def test_not_vm_virt_none(self, mock_cmd, _read):
        from rex.pal.detector import _detect_is_vm
        def side_effect(cmd, timeout=10):
            if "systemd-detect-virt" in cmd:
                return "none"
            return ""
        mock_cmd.side_effect = side_effect
        assert _detect_is_vm() is False

    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    def test_not_vm_clean(self, _cmd, _read):
        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is False


# =====================================================================
# detect_hardware -- Darwin, Windows, Linux branches
# =====================================================================

class TestDetectHardwareDarwin:
    """Cover the Darwin branch of detect_hardware."""

    @patch("rex.pal.detector.shutil.disk_usage")
    @patch("rex.pal.detector.platform.system", return_value="Darwin")
    @patch("rex.pal.detector._run_cmd")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector._detect_gpu_apple", return_value=None)
    @patch("rex.pal.detector.os.cpu_count", return_value=10)
    def test_darwin_cpu_and_ram(
        self, _cpu, _apple, _amd, _nvidia, mock_cmd, _sys, mock_disk
    ):
        from rex.pal.detector import detect_hardware
        mock_disk.return_value = MagicMock(
            total=500 * 1024**3, free=250 * 1024**3,
        )

        def side_effect(cmd, timeout=10):
            if "machdep.cpu.brand_string" in cmd:
                return "Apple M2 Max"
            if "hw.logicalcpu" in cmd:
                return "12"
            if "hw.memsize" in cmd:
                return str(32 * 1024**3)
            return ""
        mock_cmd.side_effect = side_effect

        hw = detect_hardware()
        assert hw.cpu_model == "Apple M2 Max"
        assert hw.cpu_cores == 12
        assert hw.ram_total_mb == 32 * 1024

    @patch("rex.pal.detector.shutil.disk_usage")
    @patch("rex.pal.detector.platform.system", return_value="Darwin")
    @patch("rex.pal.detector._run_cmd")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector._detect_gpu_apple", return_value=None)
    @patch("rex.pal.detector.os.cpu_count", return_value=8)
    def test_darwin_vm_stat_parsing(
        self, _cpu, _apple, _amd, _nvidia, mock_cmd, _sys, mock_disk
    ):
        from rex.pal.detector import detect_hardware
        mock_disk.return_value = MagicMock(total=500 * 1024**3, free=250 * 1024**3)

        def side_effect(cmd, timeout=10):
            if "hw.memsize" in cmd:
                return str(16 * 1024**3)
            if "vm_stat" in cmd:
                return (
                    "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
                    "Pages free:                        100000.\n"
                    "Pages inactive:                     50000.\n"
                )
            return ""
        mock_cmd.side_effect = side_effect

        hw = detect_hardware()
        expected_mb = (100000 + 50000) * 16384 // (1024 * 1024)
        assert hw.ram_available_mb == expected_mb


class TestDetectHardwareWindows:
    """Cover the Windows branch of detect_hardware."""

    @patch("rex.pal.detector.shutil.disk_usage")
    @patch("rex.pal.detector.platform.system", return_value="Windows")
    @patch("rex.pal.detector.platform.processor", return_value="Intel64 Family 6")
    @patch("rex.pal.detector._run_cmd")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector.os.cpu_count", return_value=8)
    @patch("rex.pal.detector._read_file", return_value="")
    def test_windows_wmic_ram(
        self, _read, _cpu, _amd, _nvidia, mock_cmd, _proc, _sys, mock_disk
    ):
        from rex.pal.detector import detect_hardware
        mock_disk.return_value = MagicMock(total=1000 * 1024**3, free=500 * 1024**3)

        def side_effect(cmd, timeout=10):
            if "TotalPhysicalMemory" in cmd:
                return "TotalPhysicalMemory=17179869184"
            if "FreePhysicalMemory" in cmd:
                return "FreePhysicalMemory=8388608"
            return ""
        mock_cmd.side_effect = side_effect

        hw = detect_hardware()
        assert hw.cpu_model == "Intel64 Family 6"
        assert hw.ram_total_mb == 17179869184 // (1024 * 1024)
        assert hw.ram_available_mb == 8388608 // 1024


class TestDetectHardwareLinux:
    """Cover the Linux branch of detect_hardware."""

    @patch("rex.pal.detector.shutil.disk_usage")
    @patch("rex.pal.detector.platform.system", return_value="Linux")
    @patch("rex.pal.detector._parse_proc_cpuinfo")
    @patch("rex.pal.detector._parse_proc_meminfo")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector.os.cpu_count", return_value=4)
    def test_linux_cpu_utilization(
        self, _cpu, _amd, _nvidia, mock_read, mock_meminfo, mock_cpuinfo, _sys, mock_disk,
    ):
        from rex.pal.detector import detect_hardware
        mock_disk.return_value = MagicMock(total=500 * 1024**3, free=250 * 1024**3)
        mock_cpuinfo.return_value = {"model": "AMD EPYC", "logical_cores": 16}
        mock_meminfo.return_value = {"MemTotal": 32768000, "MemAvailable": 16384000}
        mock_read.return_value = "cpu  1000 200 300 7000 100 0 0 0 0 0"

        hw = detect_hardware()
        assert hw.cpu_model == "AMD EPYC"
        assert hw.cpu_cores == 16
        assert hw.cpu_percent > 0

    @patch("rex.pal.detector.shutil.disk_usage")
    @patch("rex.pal.detector.platform.system", return_value="Linux")
    @patch("rex.pal.detector._parse_proc_cpuinfo")
    @patch("rex.pal.detector._parse_proc_meminfo")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector.os.cpu_count", return_value=4)
    def test_linux_memavailable_fallback(
        self, _cpu, _amd, _nvidia, _read, mock_meminfo, mock_cpuinfo, _sys, mock_disk,
    ):
        from rex.pal.detector import detect_hardware
        mock_disk.return_value = MagicMock(total=500 * 1024**3, free=250 * 1024**3)
        mock_cpuinfo.return_value = {"model": "x", "logical_cores": 2}
        mock_meminfo.return_value = {
            "MemTotal": 8192000,
            "MemAvailable": 0,
            "MemFree": 2048000,
            "Buffers": 512000,
            "Cached": 1024000,
        }

        hw = detect_hardware()
        assert hw.ram_available_mb == (2048000 + 512000 + 1024000) // 1024

    @patch("rex.pal.detector.shutil.disk_usage", side_effect=OSError("no disk"))
    @patch("rex.pal.detector.platform.system", return_value="Linux")
    @patch("rex.pal.detector._parse_proc_cpuinfo")
    @patch("rex.pal.detector._parse_proc_meminfo", return_value={})
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector.os.cpu_count", return_value=1)
    def test_disk_usage_error(
        self, _cpu, _amd, _nvidia, _read, _mem, mock_cpuinfo, _sys, _disk,
    ):
        from rex.pal.detector import detect_hardware
        mock_cpuinfo.return_value = {"model": "x", "logical_cores": 1}
        hw = detect_hardware()
        assert hw.disk_total_gb == 0.0
        assert hw.disk_free_gb == 0.0


class TestDetectHardwareGPU:
    """Cover GPU detection flow in detect_hardware."""

    @patch("rex.pal.detector.shutil.disk_usage")
    @patch("rex.pal.detector.platform.system", return_value="Linux")
    @patch("rex.pal.detector._parse_proc_cpuinfo")
    @patch("rex.pal.detector._parse_proc_meminfo", return_value={"MemTotal": 8192, "MemAvailable": 4096})
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._detect_gpu_nvidia")
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector.os.cpu_count", return_value=4)
    def test_nvidia_gpu_found(
        self, _cpu, _amd, mock_nvidia, _read, _mem, mock_cpuinfo, _sys, mock_disk,
    ):
        from rex.pal.detector import detect_hardware
        mock_disk.return_value = MagicMock(total=500 * 1024**3, free=250 * 1024**3)
        mock_cpuinfo.return_value = {"model": "x", "logical_cores": 4}
        mock_nvidia.return_value = GPUInfo(
            model="RTX 4090", vram_mb=24576, cuda_available=True,
        )
        hw = detect_hardware()
        assert hw.gpu_model == "RTX 4090"
        assert hw.gpu_vram_mb == 24576

    @patch("rex.pal.detector.shutil.disk_usage")
    @patch("rex.pal.detector.platform.system", return_value="Darwin")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector._detect_gpu_apple")
    @patch("rex.pal.detector.os.cpu_count", return_value=8)
    def test_apple_gpu_found(
        self, _cpu, mock_apple, _amd, _nvidia, _cmd, _sys, mock_disk,
    ):
        from rex.pal.detector import detect_hardware
        mock_disk.return_value = MagicMock(total=500 * 1024**3, free=250 * 1024**3)
        mock_apple.return_value = GPUInfo(
            model="Apple M2", vram_mb=16384, metal_available=True,
        )
        hw = detect_hardware()
        assert hw.gpu_model == "Apple M2"


# =====================================================================
# recommend_llm_model
# =====================================================================

class TestRecommendLlmModel:
    """Cover all branches of recommend_llm_model."""

    def test_high_vram(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=4096, gpu_vram_mb=12 * 1024)
        assert recommend_llm_model(hw) == "llama3:70b-q4"

    def test_32gb_ram(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=32 * 1024)
        assert recommend_llm_model(hw) == "llama3:70b-q4"

    def test_16gb_ram(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=16 * 1024)
        assert recommend_llm_model(hw) == "llama3:8b-q8"

    def test_8gb_ram(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=8 * 1024)
        assert recommend_llm_model(hw) == "llama3:8b"

    def test_4gb_ram(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=4 * 1024)
        assert recommend_llm_model(hw) == "mistral:7b-q4"

    def test_low_ram(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=2 * 1024)
        assert recommend_llm_model(hw) == "phi3:mini"


# =====================================================================
# recommend_tier
# =====================================================================

class TestRecommendTier:
    """Cover all branches of recommend_tier."""

    def test_full_with_ad(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(5, has_ad=True) == HardwareTier.FULL

    def test_full_high_device_count(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(100) == HardwareTier.FULL

    def test_standard(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(25) == HardwareTier.STANDARD

    def test_minimal(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(5) == HardwareTier.MINIMAL
