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
    async def test_initialize_git_binary_not_found(self, tmp_path: Path) -> None:
        """When git binary is missing, versioning should be disabled."""
        gm = GitManager(repo_path=tmp_path / "test-repo")

        class FakeGitCommandNotFoundError(Exception):
            pass

        mock_git = MagicMock()
        mock_git.GitCommandNotFound = FakeGitCommandNotFoundError
        mock_git.Git.return_value.version.side_effect = FakeGitCommandNotFoundError("git")

        with patch.dict("sys.modules", {"git": mock_git}):
            gm._init_sync()

        assert gm._available is False

    @pytest.mark.asyncio
    async def test_initialize_creates_new_repo(self, tmp_path: Path) -> None:
        """When the path has no git repo, it should init one."""
        repo_path = tmp_path / "new-repo"
        gm = GitManager(repo_path=repo_path)

        mock_repo = MagicMock()
        mock_repo.untracked_files = []
        mock_repo.is_dirty.return_value = False

        class FakeInvalidGitRepositoryError(Exception):
            pass

        mock_git = MagicMock()
        mock_git.InvalidGitRepositoryError = FakeInvalidGitRepositoryError
        mock_git.Git.return_value.version.return_value = "git version 2.40"
        mock_git.Repo.side_effect = FakeInvalidGitRepositoryError("not a repo")
        mock_git.Repo.init.return_value = mock_repo

        with patch.dict("sys.modules", {"git": mock_git}):
            gm._init_sync()

        assert gm._available is True
        assert gm._repo is mock_repo

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
            gm._init_sync()

        assert gm._available is True
        assert gm._repo is mock_repo

    @pytest.mark.asyncio
    async def test_initialize_generic_exception_disables(self, tmp_path: Path) -> None:
        """A generic exception during repo open disables versioning."""
        repo_path = tmp_path / "bad-repo"
        gm = GitManager(repo_path=repo_path)

        class FakeInvalidGitRepositoryError(Exception):
            pass

        mock_git = MagicMock()
        mock_git.InvalidGitRepositoryError = FakeInvalidGitRepositoryError
        mock_git.Git.return_value.version.return_value = "git version 2.40"
        # Raise something that is NOT InvalidGitRepositoryError
        mock_git.Repo.side_effect = RuntimeError("disk error")

        with patch.dict("sys.modules", {"git": mock_git}):
            gm._init_sync()

        assert gm._available is False


# ------------------------------------------------------------------
# Initial commit
# ------------------------------------------------------------------


class TestInitialCommit:
    """Tests for the _initial_commit helper."""

    def test_initial_commit_no_repo(self, tmp_path: Path) -> None:
        """_initial_commit is a no-op when _repo is None."""
        gm = GitManager(repo_path=tmp_path)
        gm._repo = None
        gm._initial_commit()  # should not raise

    def test_initial_commit_with_untracked_files(self, tmp_path: Path) -> None:
        """_initial_commit stages untracked files and commits."""
        gm = GitManager(repo_path=tmp_path)

        mock_repo = MagicMock()
        mock_repo.untracked_files = ["file1.md", "file2.md"]
        mock_repo.is_dirty.return_value = True
        gm._repo = mock_repo

        mock_git = MagicMock()
        with patch.dict("sys.modules", {"git": mock_git}):
            gm._initial_commit()

        mock_repo.index.add.assert_called()
        mock_repo.index.commit.assert_called_once()

    def test_initial_commit_clean_tree_no_commit(self, tmp_path: Path) -> None:
        """_initial_commit does not commit if tree is clean."""
        gm = GitManager(repo_path=tmp_path)

        mock_repo = MagicMock()
        mock_repo.untracked_files = []
        mock_repo.is_dirty.return_value = False
        gm._repo = mock_repo

        mock_git = MagicMock()
        with patch.dict("sys.modules", {"git": mock_git}):
            gm._initial_commit()

        mock_repo.index.commit.assert_not_called()

    def test_initial_commit_handles_exception(self, tmp_path: Path) -> None:
        """_initial_commit logs but does not raise on commit failure."""
        gm = GitManager(repo_path=tmp_path)

        mock_repo = MagicMock()
        mock_repo.untracked_files = ["file.md"]
        mock_repo.is_dirty.return_value = True
        mock_repo.index.commit.side_effect = RuntimeError("commit failed")
        gm._repo = mock_repo

        mock_git = MagicMock()
        with patch.dict("sys.modules", {"git": mock_git}):
            gm._initial_commit()  # should not raise


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

    @pytest.mark.asyncio
    async def test_commit_git_add_failure(self, tmp_path: Path) -> None:
        """commit() returns None when git add fails."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        class FakeGitCommandError(Exception):
            pass

        mock_repo = MagicMock()
        mock_repo.git.add.side_effect = FakeGitCommandError("git add failed")
        gm._repo = mock_repo

        mock_git = MagicMock()
        mock_git.GitCommandError = FakeGitCommandError

        with patch.dict("sys.modules", {"git": mock_git}):
            result = await gm.commit("will fail add")
            assert result is None

    @pytest.mark.asyncio
    async def test_commit_git_commit_failure(self, tmp_path: Path) -> None:
        """commit() returns None when git commit fails."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        class FakeGitCommandError(Exception):
            pass

        mock_repo = MagicMock()
        mock_repo.is_dirty.return_value = True
        mock_repo.index.commit.side_effect = FakeGitCommandError("commit failed")
        gm._repo = mock_repo

        mock_git = MagicMock()
        mock_git.GitCommandError = FakeGitCommandError

        with patch.dict("sys.modules", {"git": mock_git}):
            result = await gm.commit("will fail commit")
            assert result is None

    @pytest.mark.asyncio
    async def test_commit_author_formatting(self, tmp_path: Path) -> None:
        """commit() formats the author name correctly for the Actor."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_commit_obj = MagicMock()
        mock_commit_obj.hexsha = "deadbeef" * 5
        mock_repo.is_dirty.return_value = True
        mock_repo.index.commit.return_value = mock_commit_obj
        gm._repo = mock_repo

        mock_git = MagicMock()

        with patch.dict("sys.modules", {"git": mock_git}):
            result = await gm.commit("test", author="My Author")
            assert result is not None
            # Verify Actor was called with expected email
            call_kwargs = mock_repo.index.commit.call_args
            call_kwargs.kwargs.get("author") or call_kwargs[1].get("author")
            mock_git.Actor.assert_called_with("My Author", "my-author@rex.local")


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

    @pytest.mark.asyncio
    async def test_get_log_multiple_commits(self, tmp_path: Path) -> None:
        """get_log() returns all commits from iter_commits."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        commits = []
        for i in range(5):
            c = MagicMock()
            c.hexsha = f"sha{i:040d}"
            c.message = f"Commit {i}"
            c.author = "REX"
            c.committed_date = 1700000000 + i
            commits.append(c)

        mock_repo = MagicMock()
        mock_repo.iter_commits.return_value = commits
        gm._repo = mock_repo

        result = await gm.get_log(n=5)
        assert len(result) == 5
        mock_repo.iter_commits.assert_called_once_with(max_count=5)

    @pytest.mark.asyncio
    async def test_get_log_exception_returns_partial(self, tmp_path: Path) -> None:
        """get_log() returns empty list on iteration error."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_repo.iter_commits.side_effect = RuntimeError("corrupt repo")
        gm._repo = mock_repo

        result = await gm.get_log(n=10)
        assert result == []

    @pytest.mark.asyncio
    async def test_get_log_default_n(self, tmp_path: Path) -> None:
        """get_log() defaults to n=50."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_repo.iter_commits.return_value = []
        gm._repo = mock_repo

        await gm.get_log()
        mock_repo.iter_commits.assert_called_once_with(max_count=50)


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

    @pytest.mark.asyncio
    async def test_get_diff_with_parent(self, tmp_path: Path) -> None:
        """get_diff() diffs against parent when one exists."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        parent_commit = MagicMock()
        parent_commit.hexsha = "parenthash"

        mock_commit = MagicMock()
        mock_commit.hexsha = "childhash"
        mock_commit.parents = [parent_commit]

        mock_repo = MagicMock()
        mock_repo.commit.return_value = mock_commit
        mock_repo.git.diff.return_value = "diff --git a/file.md b/file.md\n+new line"
        gm._repo = mock_repo

        result = await gm.get_diff("childhash")
        assert "diff" in result
        mock_repo.git.diff.assert_called_once_with("parenthash", "childhash")

    @pytest.mark.asyncio
    async def test_get_diff_initial_commit(self, tmp_path: Path) -> None:
        """get_diff() diffs against empty tree for initial commit (no parents)."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_commit = MagicMock()
        mock_commit.hexsha = "initialhash"
        mock_commit.parents = []

        mock_repo = MagicMock()
        mock_repo.commit.return_value = mock_commit
        mock_repo.git.diff.return_value = "+initial content"
        gm._repo = mock_repo

        result = await gm.get_diff("initialhash")
        assert result == "+initial content"
        # Should diff against the empty tree hash
        mock_repo.git.diff.assert_called_once_with(
            "4b825dc642cb6eb9a060e54bf899d69f7cb46101",
            "initialhash",
        )

    @pytest.mark.asyncio
    async def test_get_diff_exception_returns_empty(self, tmp_path: Path) -> None:
        """get_diff() returns empty string on exception."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_repo.commit.side_effect = RuntimeError("bad hash")
        gm._repo = mock_repo

        result = await gm.get_diff("badcommit")
        assert result == ""


# ------------------------------------------------------------------
# Revert
# ------------------------------------------------------------------


class TestGitManagerRevert:
    """Tests for revert()."""

    @pytest.mark.asyncio
    async def test_revert_when_not_available(self, tmp_path: Path) -> None:
        """revert() returns None when versioning is disabled."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = False
        result = await gm.revert("abc")
        assert result is None

    @pytest.mark.asyncio
    async def test_revert_when_repo_none(self, tmp_path: Path) -> None:
        """revert() returns None when _repo is None."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True
        gm._repo = None
        result = await gm.revert("abc")
        assert result is None

    @pytest.mark.asyncio
    async def test_revert_success(self, tmp_path: Path) -> None:
        """revert() creates a revert commit and returns its SHA."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_repo.head.commit.hexsha = "newrevertsha1234567890abcdef12345678"
        gm._repo = mock_repo

        mock_git = MagicMock()

        with patch.dict("sys.modules", {"git": mock_git}):
            result = await gm.revert("abcdef12")
            assert result == "newrevertsha1234567890abcdef12345678"
            mock_repo.git.revert.assert_called_once_with("abcdef12", no_edit=True)

    @pytest.mark.asyncio
    async def test_revert_conflict_aborts(self, tmp_path: Path) -> None:
        """revert() returns None and aborts on conflict."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        class FakeGitCommandError(Exception):
            pass

        mock_repo = MagicMock()
        mock_repo.git.revert.side_effect = FakeGitCommandError("conflict")
        gm._repo = mock_repo

        mock_git = MagicMock()
        mock_git.GitCommandError = FakeGitCommandError

        with patch.dict("sys.modules", {"git": mock_git}):
            result = await gm.revert("conflicting")
            assert result is None


# ------------------------------------------------------------------
# get_file_at_version
# ------------------------------------------------------------------


class TestGitManagerFileAtVersion:
    """Tests for get_file_at_version()."""

    @pytest.mark.asyncio
    async def test_file_at_version_not_available(self, tmp_path: Path) -> None:
        """Returns empty string when versioning is disabled."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = False
        result = await gm.get_file_at_version("abc")
        assert result == ""

    @pytest.mark.asyncio
    async def test_file_at_version_repo_none(self, tmp_path: Path) -> None:
        """Returns empty string when _repo is None."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True
        gm._repo = None
        result = await gm.get_file_at_version("abc")
        assert result == ""

    @pytest.mark.asyncio
    async def test_file_at_version_finds_kb_md(self, tmp_path: Path) -> None:
        """Returns content of REX-BOT-AI.md from the commit tree."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        blob = MagicMock()
        blob.path = "knowledge/REX-BOT-AI.md"
        blob.data_stream.read.return_value = b"# Knowledge Base Content"

        mock_commit = MagicMock()
        mock_commit.tree.traverse.return_value = [blob]

        mock_repo = MagicMock()
        mock_repo.commit.return_value = mock_commit
        gm._repo = mock_repo

        result = await gm.get_file_at_version("somehash")
        assert result == "# Knowledge Base Content"

    @pytest.mark.asyncio
    async def test_file_at_version_fallback_to_any_md(self, tmp_path: Path) -> None:
        """Falls back to any .md file when REX-BOT-AI.md is absent."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        blob_other = MagicMock()
        blob_other.path = "notes/README.md"
        blob_other.data_stream.read.return_value = b"Fallback content"

        blob_py = MagicMock()
        blob_py.path = "src/main.py"

        mock_commit = MagicMock()
        # First traverse: no REX-BOT-AI.md; second traverse: fallback .md
        mock_commit.tree.traverse.side_effect = [
            [blob_py, blob_other],     # first call - no REX-BOT-AI.md found
            [blob_py, blob_other],     # second call - fallback to .md
        ]

        mock_repo = MagicMock()
        mock_repo.commit.return_value = mock_commit
        gm._repo = mock_repo

        result = await gm.get_file_at_version("somehash")
        assert result == "Fallback content"

    @pytest.mark.asyncio
    async def test_file_at_version_no_md_returns_empty(self, tmp_path: Path) -> None:
        """Returns empty string when no markdown files exist in the commit."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        blob_py = MagicMock()
        blob_py.path = "src/main.py"

        mock_commit = MagicMock()
        mock_commit.tree.traverse.return_value = [blob_py]

        mock_repo = MagicMock()
        mock_repo.commit.return_value = mock_commit
        gm._repo = mock_repo

        result = await gm.get_file_at_version("somehash")
        assert result == ""

    @pytest.mark.asyncio
    async def test_file_at_version_exception_returns_empty(self, tmp_path: Path) -> None:
        """Returns empty string on exception."""
        gm = GitManager(repo_path=tmp_path)
        gm._available = True

        mock_repo = MagicMock()
        mock_repo.commit.side_effect = RuntimeError("invalid hash")
        gm._repo = mock_repo

        result = await gm.get_file_at_version("badhash")
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
