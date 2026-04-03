"""Tests for rex.pal.detector -- OS/hardware detection and model recommendations."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from rex.shared.enums import HardwareTier
from rex.shared.models import OSInfo, SystemResources

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
# detect_os -- Linux (mocked /etc/os-release)
# =====================================================================

class TestDetectOSLinux:
    """Test detect_os on a mocked Linux environment."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_linux_ubuntu(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """detect_os parses /etc/os-release for Ubuntu metadata."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "5.15.0-100-generic"
        mock_platform.machine.return_value = "x86_64"

        os_release = (
            'NAME="Ubuntu"\n'
            'VERSION_ID="22.04"\n'
            'VERSION_CODENAME=jammy\n'
        )

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return os_release
            if path == "/proc/version":
                return "Linux version 5.15.0"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return ""
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False  # /.dockerenv

        from rex.pal.detector import detect_os
        info = detect_os()

        assert isinstance(info, OSInfo)
        assert info.name == "Ubuntu"
        assert info.version == "22.04"
        assert info.codename == "jammy"
        assert info.architecture == "x86_64"
        assert info.is_wsl is False
        assert info.is_docker is False
        assert info.is_vm is False
        assert info.is_raspberry_pi is False

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_linux_debian(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """detect_os parses /etc/os-release for Debian metadata."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1.0-20-amd64"
        mock_platform.machine.return_value = "x86_64"

        os_release = (
            'NAME="Debian GNU/Linux"\n'
            'VERSION_ID="12"\n'
            'VERSION_CODENAME=bookworm\n'
        )

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return os_release
            if path == "/proc/version":
                return "Linux version 6.1.0"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return ""
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.name == "Debian GNU/Linux"
        assert info.version == "12"
        assert info.codename == "bookworm"

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_wsl_detected(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """WSL is detected via /proc/version containing 'microsoft'."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "5.15.146-microsoft"
        mock_platform.machine.return_value = "x86_64"

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return 'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            if path == "/proc/version":
                return "Linux version 5.15.146.1-microsoft-standard-WSL2"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return ""
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.is_wsl is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_docker_detected_via_cgroup(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """Docker is detected via /proc/1/cgroup containing 'docker'."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "5.15.0"
        mock_platform.machine.return_value = "x86_64"

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return 'NAME="Alpine Linux"\nVERSION_ID="3.18"\n'
            if path == "/proc/version":
                return "Linux version 5.15.0"
            if path == "/proc/1/cgroup":
                return "0::/docker/abc123\n"
            if path == "/proc/cpuinfo":
                return ""
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.is_docker is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_docker_detected_via_dockerenv(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """Docker is detected via /.dockerenv existence."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "5.15.0"
        mock_platform.machine.return_value = "x86_64"

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return 'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            if path == "/proc/version":
                return "Linux version 5.15.0"
            if path == "/proc/1/cgroup":
                return ""  # No docker in cgroup
            if path == "/proc/cpuinfo":
                return ""
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = True  # /.dockerenv exists

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.is_docker is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_linux_fallback_lsb(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """When /etc/os-release is empty, lsb_release is used as fallback."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "5.15.0"
        mock_platform.machine.return_value = "x86_64"

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return ""  # empty file
            if path == "/proc/version":
                return "Linux version 5.15.0"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return ""
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False
        mock_cmd.return_value = "Arch Linux"

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.name == "Arch Linux"


# =====================================================================
# Raspberry Pi detection
# =====================================================================

class TestDetectRaspberryPi:
    """Test Raspberry Pi detection through /proc/cpuinfo and device-tree."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_raspberry_pi_via_cpuinfo_bcm(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """RPi detected via 'BCM' in /proc/cpuinfo."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1.0-rpi"
        mock_platform.machine.return_value = "aarch64"

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return 'NAME="Raspbian"\nVERSION_ID="12"\n'
            if path == "/proc/version":
                return "Linux version 6.1.0"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return "Hardware\t: BCM2835\nmodel name\t: ARMv7 Processor\n"
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.is_raspberry_pi is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_raspberry_pi_via_device_tree(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """RPi detected via /proc/device-tree/model containing 'raspberry'."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1.0-rpi"
        mock_platform.machine.return_value = "aarch64"

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return 'NAME="Raspbian"\nVERSION_ID="12"\n'
            if path == "/proc/version":
                return "Linux version 6.1.0"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return "model name\t: ARMv8 Processor\n"  # no BCM
            if path == "/proc/device-tree/model":
                return "Raspberry Pi 4 Model B Rev 1.4"
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.is_raspberry_pi is True

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_not_raspberry_pi(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        """Non-RPi hardware is correctly identified as not RPi."""
        mock_platform.system.return_value = "Linux"
        mock_platform.release.return_value = "6.1.0"
        mock_platform.machine.return_value = "x86_64"

        def read_side_effect(path, default=""):
            if path == "/etc/os-release":
                return 'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            if path == "/proc/version":
                return "Linux version 6.1.0"
            if path == "/proc/1/cgroup":
                return ""
            if path == "/proc/cpuinfo":
                return "model name\t: Intel Core i7\n"
            if path == "/proc/device-tree/model":
                return ""
            return default

        mock_read.side_effect = read_side_effect
        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.is_raspberry_pi is False


# =====================================================================
# _detect_is_vm
# =====================================================================

class TestDetectVM:
    """Test VM detection through various DMI and command outputs."""

    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._read_file")
    def test_vm_via_product_name(self, mock_read, mock_cmd):
        """VM detected via /sys/class/dmi/id/product_name."""
        def read_side_effect(path, default=""):
            if path == "/sys/class/dmi/id/product_name":
                return "VirtualBox"
            return default

        mock_read.side_effect = read_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._read_file")
    def test_vm_via_sys_vendor(self, mock_read, mock_cmd):
        """VM detected via /sys/class/dmi/id/sys_vendor."""
        def read_side_effect(path, default=""):
            if path == "/sys/class/dmi/id/product_name":
                return "Standard PC"
            if path == "/sys/class/dmi/id/sys_vendor":
                return "QEMU"
            return default

        mock_read.side_effect = read_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._read_file")
    def test_vm_via_board_name(self, mock_read, mock_cmd):
        """VM detected via /sys/class/dmi/id/board_name."""
        def read_side_effect(path, default=""):
            if path == "/sys/class/dmi/id/product_name":
                return "Standard PC"
            if path == "/sys/class/dmi/id/sys_vendor":
                return "Unknown Vendor"
            if path == "/sys/class/dmi/id/board_name":
                return "VMware Virtual Platform"
            return default

        mock_read.side_effect = read_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._run_cmd")
    @patch("rex.pal.detector._read_file", return_value="")
    def test_vm_via_dmidecode(self, mock_read, mock_cmd):
        """VM detected via dmidecode output."""
        def cmd_side_effect(cmd, timeout=10):
            if cmd[0] == "dmidecode":
                return "KVM"
            return ""

        mock_cmd.side_effect = cmd_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._run_cmd")
    @patch("rex.pal.detector._read_file", return_value="")
    def test_vm_via_systemd_detect_virt(self, mock_read, mock_cmd):
        """VM detected via systemd-detect-virt returning a non-'none' value."""
        def cmd_side_effect(cmd, timeout=10):
            if cmd[0] == "dmidecode":
                return ""
            if cmd[0] == "systemd-detect-virt":
                return "kvm"
            return ""

        mock_cmd.side_effect = cmd_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._run_cmd")
    @patch("rex.pal.detector._read_file", return_value="")
    def test_systemd_detect_virt_none_not_vm(self, mock_read, mock_cmd):
        """systemd-detect-virt returning 'none' means not a VM."""
        def cmd_side_effect(cmd, timeout=10):
            if cmd[0] == "systemd-detect-virt":
                return "none"
            return ""

        mock_cmd.side_effect = cmd_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is False

    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._read_file", return_value="")
    def test_not_vm_when_no_indicators(self, mock_read, mock_cmd):
        """No VM indicators returns False."""
        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is False

    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._read_file")
    def test_vm_xen_via_product_name(self, mock_read, mock_cmd):
        """Xen hypervisor detected via product name."""
        def read_side_effect(path, default=""):
            if path == "/sys/class/dmi/id/product_name":
                return "HVM domU (Xen)"
            return default

        mock_read.side_effect = read_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is True

    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._read_file")
    def test_vm_hyperv_via_sys_vendor(self, mock_read, mock_cmd):
        """Hyper-V detected via sys_vendor."""
        def read_side_effect(path, default=""):
            if path == "/sys/class/dmi/id/product_name":
                return "Virtual Machine"
            if path == "/sys/class/dmi/id/sys_vendor":
                return "Microsoft Hyper-V"
            return default

        mock_read.side_effect = read_side_effect

        from rex.pal.detector import _detect_is_vm
        assert _detect_is_vm() is True


# =====================================================================
# detect_hardware -- mocked /proc
# =====================================================================

class TestDetectHardware:
    """Test detect_hardware on a mocked Linux environment."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector.shutil")
    def test_detect_hardware_linux(
        self, mock_shutil, mock_amd, mock_nvidia, mock_cmd, mock_read, mock_platform,
    ):
        """detect_hardware parses /proc/meminfo and /proc/cpuinfo on Linux."""
        mock_platform.system.return_value = "Linux"

        meminfo = (
            "MemTotal:       16384000 kB\n"
            "MemFree:         4000000 kB\n"
            "MemAvailable:    8192000 kB\n"
            "Buffers:          500000 kB\n"
            "Cached:          2000000 kB\n"
        )
        cpuinfo = (
            "processor\t: 0\n"
            "model name\t: Intel(R) Core(TM) i7-12700K\n"
            "physical id\t: 0\n"
            "\n"
            "processor\t: 1\n"
            "model name\t: Intel(R) Core(TM) i7-12700K\n"
            "physical id\t: 0\n"
            "\n"
            "processor\t: 2\n"
            "model name\t: Intel(R) Core(TM) i7-12700K\n"
            "physical id\t: 0\n"
            "\n"
            "processor\t: 3\n"
            "model name\t: Intel(R) Core(TM) i7-12700K\n"
            "physical id\t: 0\n"
        )
        stat = "cpu  100 20 30 800 10 0 0 0 0 0\n"

        def read_side_effect(path, default=""):
            if path == "/proc/meminfo":
                return meminfo
            if path == "/proc/cpuinfo":
                return cpuinfo
            if path == "/proc/stat":
                return stat
            return default

        mock_read.side_effect = read_side_effect

        usage = MagicMock()
        usage.total = 500 * 1024**3
        usage.free = 250 * 1024**3
        mock_shutil.disk_usage.return_value = usage

        from rex.pal.detector import detect_hardware
        hw = detect_hardware()

        assert isinstance(hw, SystemResources)
        assert hw.cpu_model == "Intel(R) Core(TM) i7-12700K"
        assert hw.cpu_cores == 4
        assert hw.ram_total_mb == 16384000 // 1024  # ~16 GB
        assert hw.ram_available_mb == 8192000 // 1024  # ~8 GB
        assert hw.gpu_model is None
        assert hw.disk_total_gb > 0

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_gpu_nvidia", return_value=None)
    @patch("rex.pal.detector._detect_gpu_amd", return_value=None)
    @patch("rex.pal.detector.shutil")
    def test_detect_hardware_memavailable_fallback(
        self, mock_shutil, mock_amd, mock_nvidia, mock_cmd, mock_read, mock_platform,
    ):
        """When MemAvailable is missing, fallback to MemFree+Buffers+Cached."""
        mock_platform.system.return_value = "Linux"

        # Old kernel -- no MemAvailable
        meminfo = (
            "MemTotal:       8192000 kB\n"
            "MemFree:        2000000 kB\n"
            "Buffers:         300000 kB\n"
            "Cached:         1000000 kB\n"
        )
        cpuinfo = "processor\t: 0\nmodel name\t: ARM Cortex-A72\n"

        def read_side_effect(path, default=""):
            if path == "/proc/meminfo":
                return meminfo
            if path == "/proc/cpuinfo":
                return cpuinfo
            if path == "/proc/stat":
                return ""
            return default

        mock_read.side_effect = read_side_effect

        usage = MagicMock()
        usage.total = 100 * 1024**3
        usage.free = 50 * 1024**3
        mock_shutil.disk_usage.return_value = usage

        from rex.pal.detector import detect_hardware
        hw = detect_hardware()

        expected_avail = (2000000 + 300000 + 1000000) // 1024
        assert hw.ram_available_mb == expected_avail


# =====================================================================
# recommend_llm_model -- all RAM tiers
# =====================================================================

class TestRecommendLLMModel:
    """Test recommend_llm_model for every RAM/VRAM threshold."""

    def test_below_4gb_recommends_phi3_mini(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=2048)  # 2 GB
        assert recommend_llm_model(hw) == "phi3:mini"

    def test_exactly_0gb_recommends_phi3_mini(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=0)
        assert recommend_llm_model(hw) == "phi3:mini"

    def test_4gb_recommends_mistral(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=4096)  # exactly 4 GB
        assert recommend_llm_model(hw) == "mistral:7b-q4"

    def test_6gb_recommends_mistral(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=6144)  # 6 GB
        assert recommend_llm_model(hw) == "mistral:7b-q4"

    def test_8gb_recommends_llama3_8b(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=8192)  # 8 GB
        assert recommend_llm_model(hw) == "llama3:8b"

    def test_12gb_recommends_llama3_8b(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=12288)  # 12 GB
        assert recommend_llm_model(hw) == "llama3:8b"

    def test_16gb_recommends_llama3_8b_q8(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=16384)  # 16 GB
        assert recommend_llm_model(hw) == "llama3:8b-q8"

    def test_24gb_recommends_llama3_8b_q8(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=24576)  # 24 GB
        assert recommend_llm_model(hw) == "llama3:8b-q8"

    def test_32gb_recommends_llama3_70b(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=32768)  # 32 GB
        assert recommend_llm_model(hw) == "llama3:70b-q4"

    def test_64gb_recommends_llama3_70b(self):
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=65536)  # 64 GB
        assert recommend_llm_model(hw) == "llama3:70b-q4"

    def test_12gb_vram_overrides_low_ram(self):
        """12+ GB VRAM triggers llama3:70b-q4 regardless of RAM."""
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=2048, gpu_vram_mb=12288)  # 2GB RAM, 12GB VRAM
        assert recommend_llm_model(hw) == "llama3:70b-q4"

    def test_8gb_vram_does_not_override(self):
        """8 GB VRAM alone does not trigger the GPU override."""
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=4096, gpu_vram_mb=8192)  # 4GB RAM, 8GB VRAM
        assert recommend_llm_model(hw) == "mistral:7b-q4"

    def test_no_gpu_vram_none(self):
        """None VRAM should not trigger GPU override."""
        from rex.pal.detector import recommend_llm_model
        hw = _make_hw(ram_mb=8192, gpu_vram_mb=None)
        assert recommend_llm_model(hw) == "llama3:8b"


# =====================================================================
# recommend_tier -- all device counts
# =====================================================================

class TestRecommendTier:
    """Test recommend_tier for every boundary and AD flag."""

    def test_0_devices_minimal(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=0) == HardwareTier.MINIMAL

    def test_5_devices_minimal(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=5) == HardwareTier.MINIMAL

    def test_9_devices_minimal(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=9) == HardwareTier.MINIMAL

    def test_10_devices_standard(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=10) == HardwareTier.STANDARD

    def test_25_devices_standard(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=25) == HardwareTier.STANDARD

    def test_50_devices_standard(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=50) == HardwareTier.STANDARD

    def test_51_devices_full(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=51) == HardwareTier.FULL

    def test_100_devices_full(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=100) == HardwareTier.FULL

    def test_ad_forces_full_even_few_devices(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=3, has_ad=True) == HardwareTier.FULL

    def test_ad_forces_full_medium_devices(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=25, has_ad=True) == HardwareTier.FULL

    def test_ad_false_does_not_affect(self):
        from rex.pal.detector import recommend_tier
        assert recommend_tier(device_count=5, has_ad=False) == HardwareTier.MINIMAL


# =====================================================================
# _read_file and _run_cmd helpers (edge cases)
# =====================================================================

class TestPrivateHelpers:
    """Edge-case tests for the private helper functions."""

    def test_read_file_returns_default_on_missing(self):
        from rex.pal.detector import _read_file
        result = _read_file("/nonexistent/path/that/does/not/exist", "fallback")
        assert result == "fallback"

    def test_run_cmd_returns_empty_on_bad_cmd(self):
        from rex.pal.detector import _run_cmd
        result = _run_cmd(["__nonexistent_command_12345__"])
        assert result == ""

    def test_parse_proc_meminfo_empty(self):
        """Empty /proc/meminfo returns empty dict."""
        with patch("rex.pal.detector._read_file", return_value=""):
            from rex.pal.detector import _parse_proc_meminfo
            assert _parse_proc_meminfo() == {}

    def test_parse_proc_cpuinfo_empty(self):
        """Empty /proc/cpuinfo returns Unknown CPU with fallback core count."""
        with patch("rex.pal.detector._read_file", return_value=""):
            from rex.pal.detector import _parse_proc_cpuinfo
            result = _parse_proc_cpuinfo()
            assert result["model"] == "Unknown CPU"
            assert result["logical_cores"] >= 1


# =====================================================================
# detect_os -- non-Linux platforms
# =====================================================================

class TestDetectOSOtherPlatforms:
    """Test detect_os on macOS, Windows, FreeBSD (mocked)."""

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_darwin(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        mock_platform.system.return_value = "Darwin"
        mock_platform.release.return_value = "23.0.0"
        mock_platform.machine.return_value = "arm64"
        mock_platform.mac_ver.return_value = ("14.0", ("", "", ""), "")

        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.name == "macOS"
        assert info.version == "14.0"

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_windows(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        mock_platform.system.return_value = "Windows"
        mock_platform.release.return_value = "10"
        mock_platform.machine.return_value = "AMD64"
        mock_platform.version.return_value = "10.0.19045"

        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.name == "Windows"
        assert info.version == "10.0.19045"

    @patch("rex.pal.detector.platform")
    @patch("rex.pal.detector._read_file", return_value="")
    @patch("rex.pal.detector._run_cmd", return_value="")
    @patch("rex.pal.detector._detect_is_vm", return_value=False)
    @patch("rex.pal.detector.Path")
    def test_detect_os_freebsd(
        self, mock_path, mock_vm, mock_cmd, mock_read, mock_platform,
    ):
        mock_platform.system.return_value = "FreeBSD"
        mock_platform.release.return_value = "14.0"
        mock_platform.machine.return_value = "amd64"

        mock_path.return_value.exists.return_value = False

        from rex.pal.detector import detect_os
        info = detect_os()

        assert info.name == "FreeBSD"
