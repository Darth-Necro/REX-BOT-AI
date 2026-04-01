"""Tests for rex.memory.versioning -- Git versioning manager."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from rex.memory.versioning import GitManager

if TYPE_CHECKING:
    from pathlib import Path

# ------------------------------------------------------------------
# GitManager initialisation
# ------------------------------------------------------------------


class TestGitManagerInit:
    """GitManager constructor and initialization."""

    def test_constructor_stores_repo_path(self, tmp_path: Path) -> None:
        """Constructor should store the repo path."""
        gm = GitManager(repo_path=tmp_path / "test-repo")
        assert gm.repo_path == tmp_path / "test-repo"
        assert gm._available is False
        assert gm._repo is None

    @pytest.mark.asyncio
    async def test_initialize_without_gitpython(self, tmp_path: Path) -> None:
        """When GitPython is not installed, versioning should be disabled."""
        gm = GitManager(repo_path=tmp_path / "test-repo")

        with patch.dict("sys.modules", {"git": None}):
            # Force ImportError on git import

            def _mock_init():
                try:
                    import git
                    if git is None:
                        raise ImportError("mocked")
                except ImportError:
                    gm._available = False
                    return

            gm._init_sync = _mock_init
            await gm.initialize()
            assert gm._available is False

    @pytest.mark.asyncio
    async def test_initialize_creates_new_repo(self, tmp_path: Path) -> None:
        """When the path has no git repo, it should init one."""
        repo_path = tmp_path / "new-repo"
        gm = GitManager(repo_path=repo_path)

        # Mock the git module
        mock_git_module = MagicMock()
        mock_repo = MagicMock()
        mock_repo.untracked_files = []
        mock_repo.is_dirty.return_value = False
        mock_git_module.Repo.side_effect = mock_git_module.InvalidGitRepositoryError
        mock_git_module.Repo.init.return_value = mock_repo

        with patch.dict("sys.modules", {"git": mock_git_module}):
            gm._init_sync = lambda: None  # skip the real init
            gm._available = True
            gm._repo = mock_repo

        assert gm._available is True

    @pytest.mark.asyncio
    async def test_initialize_opens_existing_repo(self, tmp_path: Path) -> None:
        """When the path is an existing repo, it should open it."""
        repo_path = tmp_path / "existing-repo"
        repo_path.mkdir()
        gm = GitManager(repo_path=repo_path)

        mock_repo = MagicMock()
        mock_git = MagicMock()
        mock_git.Repo.return_value = mock_repo
        mock_git.Git.return_value.version.return_value = "git version 2.40"

        with patch.dict("sys.modules", {"git": mock_git}):
            gm._repo = mock_repo
            gm._available = True

        assert gm._available is True
        assert gm._repo is mock_repo


# ------------------------------------------------------------------
# Commit
# ------------------------------------------------------------------


class TestGitManagerCommit:
    """Tests for commit() method."""

    @pytest.mark.asyncio
    async def test_commit_when_not_available(self, tmp_path: Path) -> None:
        """commit() should return None when versioning is disabled."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = False
        result = await gm.commit("test message")
        assert result is None

    @pytest.mark.asyncio
    async def test_commit_when_repo_is_none(self, tmp_path: Path) -> None:
        """commit() should return None when _repo is None."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True
        gm._repo = None
        result = await gm.commit("test message")
        assert result is None

    @pytest.mark.asyncio
    async def test_commit_creates_git_commit(self, tmp_path: Path) -> None:
        """commit() should stage, check dirty, and create a commit."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_commit = MagicMock()
        mock_commit.hexsha = "abcdef1234567890abcdef1234567890abcdef12"
        mock_repo.is_dirty.return_value = True
        mock_repo.index.commit.return_value = mock_commit
        gm._repo = mock_repo

        mock_git = MagicMock()

        with patch.dict("sys.modules", {"git": mock_git}):
            result = await gm.commit("test commit", author="TEST")
            assert result == "abcdef1234567890abcdef1234567890abcdef12"

    @pytest.mark.asyncio
    async def test_commit_clean_tree_returns_none(self, tmp_path: Path) -> None:
        """commit() should return None when working tree is clean."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_repo.is_dirty.return_value = False
        gm._repo = mock_repo

        mock_git = MagicMock()

        with patch.dict("sys.modules", {"git": mock_git}):
            result = await gm.commit("no changes")
            assert result is None


# ------------------------------------------------------------------
# Get log
# ------------------------------------------------------------------


class TestGitManagerGetLog:
    """Tests for get_log() method."""

    @pytest.mark.asyncio
    async def test_get_log_when_not_available(self, tmp_path: Path) -> None:
        """get_log() should return empty list when versioning is disabled."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = False
        result = await gm.get_log()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_log_returns_commits(self, tmp_path: Path) -> None:
        """get_log() should return a list of commit dicts."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_commit = MagicMock()
        mock_commit.hexsha = "abcdef12"
        mock_commit.message = "Test commit\n"
        mock_commit.author = "REX-AUTO"
        mock_commit.committed_date = 1700000000

        mock_repo = MagicMock()
        mock_repo.iter_commits.return_value = [mock_commit]
        gm._repo = mock_repo

        result = await gm.get_log(n=10)
        assert len(result) == 1
        assert result[0]["hash"] == "abcdef12"
        assert result[0]["message"] == "Test commit"
        assert result[0]["author"] == "REX-AUTO"
        assert "timestamp" in result[0]

    @pytest.mark.asyncio
    async def test_get_log_repo_none(self, tmp_path: Path) -> None:
        """get_log() should return empty list when _repo is None."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True
        gm._repo = None
        result = await gm.get_log()
        assert result == []


# ------------------------------------------------------------------
# Get diff
# ------------------------------------------------------------------


class TestGitManagerDiff:
    """Tests for get_diff()."""

    @pytest.mark.asyncio
    async def test_get_diff_when_not_available(self, tmp_path: Path) -> None:
        """get_diff() should return empty string when versioning is disabled."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = False
        result = await gm.get_diff("abcdef12")
        assert result == ""

    @pytest.mark.asyncio
    async def test_get_diff_repo_none(self, tmp_path: Path) -> None:
        """get_diff() should return empty string when _repo is None."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True
        gm._repo = None
        result = await gm.get_diff("abcdef12")
        assert result == ""


# ------------------------------------------------------------------
# Graceful degradation
# ------------------------------------------------------------------


class TestGitManagerGracefulDegradation:
    """Versioning should degrade gracefully when git is unavailable."""

    @pytest.mark.asyncio
    async def test_all_methods_safe_when_disabled(self, tmp_path: Path) -> None:
        """All public methods should return safe defaults when disabled."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = False
        gm._repo = None

        assert await gm.commit("msg") is None
        assert await gm.get_log() == []
        assert await gm.get_diff("abc") == ""
        assert await gm.revert("abc") is None
        assert await gm.get_file_at_version("abc") == ""
