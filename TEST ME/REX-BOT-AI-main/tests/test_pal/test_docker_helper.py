"""Tests for rex.pal.docker_helper -- Docker CLI wrapper functions.

Every test mocks subprocess.run so no real Docker is needed.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from rex.pal.docker_helper import (
    _extract_mem_limit,
    _parse_int,
    _parse_percent,
    _run_docker,
    get_container_stats,
    get_docker_version,
    is_docker_installed,
    is_docker_running,
    list_containers,
    pull_image,
    restart_container,
)


# ------------------------------------------------------------------
# _run_docker internal helper
# ------------------------------------------------------------------


class TestRunDocker:
    def test_returns_completed_process(self) -> None:
        """Normal execution returns a CompletedProcess."""
        fake = subprocess.CompletedProcess(
            args=["docker", "--version"], returncode=0,
            stdout="Docker version 24.0.7", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            result = _run_docker(["--version"])
        assert result.returncode == 0

    def test_handles_file_not_found(self) -> None:
        """Missing docker binary returns returncode 127."""
        with patch(
            "rex.pal.docker_helper.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = _run_docker(["--version"])
        assert result.returncode == 127
        assert "not found" in result.stderr

    def test_handles_timeout(self) -> None:
        """Timeout returns returncode 124."""
        with patch(
            "rex.pal.docker_helper.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=10),
        ):
            result = _run_docker(["pull", "big-image"])
        assert result.returncode == 124
        assert "timed out" in result.stderr

    def test_handles_oserror(self) -> None:
        """Generic OSError returns returncode 1."""
        with patch(
            "rex.pal.docker_helper.subprocess.run",
            side_effect=OSError("permission denied"),
        ):
            result = _run_docker(["info"])
        assert result.returncode == 1


# ------------------------------------------------------------------
# is_docker_installed
# ------------------------------------------------------------------


class TestIsDockerInstalled:
    def test_true_when_docker_version_succeeds(self) -> None:
        """Returns True when docker --version exits 0."""
        fake = subprocess.CompletedProcess(
            args=["docker", "--version"], returncode=0,
            stdout="Docker version 24.0.7", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert is_docker_installed() is True

    def test_false_when_docker_not_found(self) -> None:
        """Returns False when docker is not on PATH."""
        with patch(
            "rex.pal.docker_helper.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            assert is_docker_installed() is False

    def test_false_when_returncode_nonzero(self) -> None:
        """Returns False on non-zero exit code."""
        fake = subprocess.CompletedProcess(
            args=["docker", "--version"], returncode=1,
            stdout="", stderr="error"
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert is_docker_installed() is False


# ------------------------------------------------------------------
# is_docker_running
# ------------------------------------------------------------------


class TestIsDockerRunning:
    def test_true_when_daemon_responds(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "info"], returncode=0, stdout="OK", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert is_docker_running() is True

    def test_false_when_daemon_not_running(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "info"], returncode=1,
            stdout="", stderr="Cannot connect"
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert is_docker_running() is False


# ------------------------------------------------------------------
# get_docker_version
# ------------------------------------------------------------------


class TestGetDockerVersion:
    def test_returns_version_string(self) -> None:
        """Returns the version string when docker is available."""
        version_str = "Docker version 24.0.7, build afdd53b"
        fake = subprocess.CompletedProcess(
            args=["docker", "--version"], returncode=0,
            stdout=version_str + "\n", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            result = get_docker_version()
        assert result == version_str

    def test_returns_none_when_unavailable(self) -> None:
        """Returns None when docker is not installed."""
        with patch(
            "rex.pal.docker_helper.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            assert get_docker_version() is None

    def test_returns_none_on_failure(self) -> None:
        """Returns None on non-zero exit."""
        fake = subprocess.CompletedProcess(
            args=["docker", "--version"], returncode=1, stdout="", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert get_docker_version() is None

    def test_returns_none_on_empty_stdout(self) -> None:
        """Returns None when stdout is empty."""
        fake = subprocess.CompletedProcess(
            args=["docker", "--version"], returncode=0, stdout="", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert get_docker_version() is None


# ------------------------------------------------------------------
# list_containers
# ------------------------------------------------------------------


class TestListContainers:
    def test_returns_parsed_containers(self) -> None:
        """Parses JSON output from docker ps."""
        container_json = json.dumps({
            "ID": "abc123",
            "Names": "rex-ollama",
            "Image": "ollama/ollama:latest",
            "Status": "Up 2 hours",
            "State": "running",
            "Ports": "11434->11434/tcp",
            "Labels": "rex-bot-ai",
        })
        fake = subprocess.CompletedProcess(
            args=["docker", "ps", "-a", "--filter", "label=rex-bot-ai",
                  "--format", "{{json .}}"],
            returncode=0, stdout=container_json + "\n", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            result = list_containers()
        assert len(result) == 1
        assert result[0]["id"] == "abc123"
        assert result[0]["name"] == "rex-ollama"
        assert result[0]["image"] == "ollama/ollama:latest"
        assert result[0]["state"] == "running"

    def test_returns_empty_on_failure(self) -> None:
        """Returns empty list when docker ps fails."""
        fake = subprocess.CompletedProcess(
            args=["docker", "ps"], returncode=1, stdout="", stderr="error"
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert list_containers() == []

    def test_returns_empty_on_empty_output(self) -> None:
        """Returns empty list when no containers match."""
        fake = subprocess.CompletedProcess(
            args=["docker", "ps"], returncode=0, stdout="", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert list_containers() == []

    def test_skips_invalid_json_lines(self) -> None:
        """Invalid JSON lines are silently skipped."""
        output = "not json\n" + json.dumps({"ID": "def456", "Names": "test"}) + "\n"
        fake = subprocess.CompletedProcess(
            args=["docker", "ps"], returncode=0, stdout=output, stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            result = list_containers()
        assert len(result) == 1
        assert result[0]["id"] == "def456"

    def test_custom_label_filter(self) -> None:
        """Custom label is passed to docker ps."""
        fake = subprocess.CompletedProcess(
            args=["docker", "ps"], returncode=0, stdout="", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake) as mock_run:
            list_containers(label="custom-label")
        call_args = mock_run.call_args[0][0]
        assert "label=custom-label" in " ".join(call_args)

    def test_multiple_containers(self) -> None:
        """Multiple JSON lines produce multiple containers."""
        lines = []
        for i in range(3):
            lines.append(json.dumps({
                "ID": f"id{i}", "Names": f"name{i}", "Image": f"img{i}",
                "Status": "running", "State": "running", "Ports": "", "Labels": "",
            }))
        fake = subprocess.CompletedProcess(
            args=["docker", "ps"], returncode=0,
            stdout="\n".join(lines) + "\n", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            result = list_containers()
        assert len(result) == 3


# ------------------------------------------------------------------
# pull_image
# ------------------------------------------------------------------


class TestPullImage:
    def test_pull_image_success(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "pull"], returncode=0, stdout="Pulled", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert pull_image("ollama/ollama:latest") is True

    def test_pull_image_failure(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "pull"], returncode=1, stdout="", stderr="error"
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert pull_image("bad/image") is False


# ------------------------------------------------------------------
# restart_container
# ------------------------------------------------------------------


class TestRestartContainer:
    def test_restart_success(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "restart"], returncode=0, stdout="", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert restart_container("rex-ollama") is True

    def test_restart_failure(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "restart"], returncode=1, stdout="", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert restart_container("missing") is False


# ------------------------------------------------------------------
# get_container_stats
# ------------------------------------------------------------------


class TestGetContainerStats:
    def test_returns_parsed_stats(self) -> None:
        stats_json = json.dumps({
            "ID": "abc123",
            "Name": "rex-ollama",
            "CPUPerc": "12.5%",
            "MemUsage": "128MiB / 16GiB",
            "MemPerc": "0.78%",
            "NetIO": "1.2kB / 3.4kB",
            "BlockIO": "0B / 0B",
            "PIDs": "15",
        })
        fake = subprocess.CompletedProcess(
            args=["docker", "stats"], returncode=0,
            stdout=stats_json + "\n", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            result = get_container_stats("rex-ollama")
        assert result["cpu_percent"] == 12.5
        assert result["memory_percent"] == 0.78
        assert result["pids"] == 15
        assert result["memory_limit"] == "16GiB"

    def test_returns_empty_on_failure(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "stats"], returncode=1, stdout="", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert get_container_stats("missing") == {}

    def test_returns_empty_on_invalid_json(self) -> None:
        fake = subprocess.CompletedProcess(
            args=["docker", "stats"], returncode=0, stdout="not json", stderr=""
        )
        with patch("rex.pal.docker_helper.subprocess.run", return_value=fake):
            assert get_container_stats("missing") == {}


# ------------------------------------------------------------------
# Stat parsing helpers
# ------------------------------------------------------------------


class TestParsingHelpers:
    def test_parse_percent(self) -> None:
        assert _parse_percent("12.34%") == 12.34
        assert _parse_percent("0%") == 0.0
        assert _parse_percent("invalid") == 0.0

    def test_parse_int(self) -> None:
        assert _parse_int("42") == 42
        assert _parse_int("bad") == 0
        assert _parse_int("  15  ") == 15

    def test_extract_mem_limit(self) -> None:
        assert _extract_mem_limit("128MiB / 16GiB") == "16GiB"
        assert _extract_mem_limit("no-slash") == ""
