"""Tests for rex.pal.detector -- OS/hardware detection and model recommendations."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from rex.shared.enums import HardwareTier
from rex.shared.models import OSInfo, SystemResources


# ------------------------------------------------------------------
# test_detect_os_returns_valid_osinfo
# ------------------------------------------------------------------

def test_detect_os_returns_valid_osinfo():
    """detect_os() should return a valid OSInfo model."""
    from rex.pal.detector import detect_os

    info = detect_os()
    assert isinstance(info, OSInfo)
    assert isinstance(info.name, str)
    assert len(info.name) > 0
    assert isinstance(info.version, str)
    assert isinstance(info.architecture, str)
    assert isinstance(info.is_wsl, bool)
    assert isinstance(info.is_docker, bool)
    assert isinstance(info.is_vm, bool)
    assert isinstance(info.is_raspberry_pi, bool)


# ------------------------------------------------------------------
# test_detect_hardware_returns_resources
# ------------------------------------------------------------------

def test_detect_hardware_returns_resources():
    """detect_hardware() should return a valid SystemResources model."""
    from rex.pal.detector import detect_hardware

    hw = detect_hardware()
    assert isinstance(hw, SystemResources)
    assert isinstance(hw.cpu_model, str)
    assert hw.cpu_cores >= 1
    assert hw.ram_total_mb >= 0
    assert hw.ram_available_mb >= 0
    assert hw.disk_total_gb >= 0.0
    assert hw.disk_free_gb >= 0.0


# ------------------------------------------------------------------
# test_recommend_llm_model_small_ram
# ------------------------------------------------------------------

def test_recommend_llm_model_small_ram():
    """< 4 GB RAM should recommend phi3:mini."""
    from rex.pal.detector import recommend_llm_model

    hw = SystemResources(
        cpu_model="Test CPU",
        cpu_cores=2,
        ram_total_mb=2048,  # 2 GB
        ram_available_mb=1024,
        disk_total_gb=50.0,
        disk_free_gb=25.0,
    )
    model = recommend_llm_model(hw)
    assert model == "phi3:mini"


def test_recommend_llm_model_4gb_ram():
    """4 GB RAM should recommend mistral:7b-q4."""
    from rex.pal.detector import recommend_llm_model

    hw = SystemResources(
        cpu_model="Test CPU",
        cpu_cores=4,
        ram_total_mb=4096,
        ram_available_mb=2048,
        disk_total_gb=100.0,
        disk_free_gb=50.0,
    )
    model = recommend_llm_model(hw)
    assert model == "mistral:7b-q4"


def test_recommend_llm_model_8gb_ram():
    """8 GB RAM should recommend llama3:8b."""
    from rex.pal.detector import recommend_llm_model

    hw = SystemResources(
        cpu_model="Test CPU",
        cpu_cores=4,
        ram_total_mb=8192,
        ram_available_mb=4096,
        disk_total_gb=100.0,
        disk_free_gb=50.0,
    )
    model = recommend_llm_model(hw)
    assert model == "llama3:8b"


# ------------------------------------------------------------------
# test_recommend_llm_model_large_ram
# ------------------------------------------------------------------

def test_recommend_llm_model_large_ram():
    """32+ GB RAM should recommend llama3:70b-q4."""
    from rex.pal.detector import recommend_llm_model

    hw = SystemResources(
        cpu_model="Test CPU",
        cpu_cores=16,
        ram_total_mb=32768,
        ram_available_mb=16384,
        disk_total_gb=500.0,
        disk_free_gb=250.0,
    )
    model = recommend_llm_model(hw)
    assert model == "llama3:70b-q4"


def test_recommend_llm_model_large_gpu():
    """12+ GB VRAM should recommend llama3:70b-q4 regardless of RAM."""
    from rex.pal.detector import recommend_llm_model

    hw = SystemResources(
        cpu_model="Test CPU",
        cpu_cores=4,
        ram_total_mb=4096,  # Only 4 GB RAM
        ram_available_mb=2048,
        gpu_model="NVIDIA RTX 4090",
        gpu_vram_mb=24576,  # 24 GB VRAM
        disk_total_gb=100.0,
        disk_free_gb=50.0,
    )
    model = recommend_llm_model(hw)
    assert model == "llama3:70b-q4"


# ------------------------------------------------------------------
# test_recommend_tier_few_devices
# ------------------------------------------------------------------

def test_recommend_tier_few_devices():
    """< 10 devices, no AD should recommend MINIMAL tier."""
    from rex.pal.detector import recommend_tier

    tier = recommend_tier(device_count=5)
    assert tier == HardwareTier.MINIMAL


def test_recommend_tier_medium_devices():
    """10-50 devices, no AD should recommend STANDARD tier."""
    from rex.pal.detector import recommend_tier

    tier = recommend_tier(device_count=25)
    assert tier == HardwareTier.STANDARD


# ------------------------------------------------------------------
# test_recommend_tier_many_devices
# ------------------------------------------------------------------

def test_recommend_tier_many_devices():
    """> 50 devices should recommend FULL tier."""
    from rex.pal.detector import recommend_tier

    tier = recommend_tier(device_count=100)
    assert tier == HardwareTier.FULL


def test_recommend_tier_with_ad():
    """AD presence should always recommend FULL tier."""
    from rex.pal.detector import recommend_tier

    tier = recommend_tier(device_count=5, has_ad=True)
    assert tier == HardwareTier.FULL
