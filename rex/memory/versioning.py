"""Git versioning manager for the REX knowledge base.

Wraps *GitPython* to auto-commit every mutation to the knowledge base so the
operator can audit, diff, or revert any change.  Degrades gracefully when
``git`` or the ``gitdb``/``GitPython`` package is not installed -- versioning
is simply disabled with a warning and all public methods become no-ops.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class GitManager:
    """Git versioning for REX-BOT-AI.md changes.

    Parameters
    ----------
    repo_path:
        Directory that will be (or already is) a Git repository.
    """

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self._repo: Any = None  # git.Repo when available
        self._available: bool = False
        self._logger = logging.getLogger("rex.memory.git")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Initialise or open the Git repository.

        If *GitPython* is not installed or ``git`` is not on PATH, versioning
        is disabled with a warning and all subsequent calls become no-ops.
        """
        await asyncio.to_thread(self._init_sync)

    def _init_sync(self) -> None:
        """Synchronous initialisation (run in a thread)."""
        try:
            import git  # type: ignore[import-untyped]
        except ImportError:
            self._logger.warning(
                "GitPython not installed -- knowledge base versioning disabled. "
                "Install with: pip install GitPython"
            )
            self._available = False
            return

        try:
            git.Git().version()
        except git.GitCommandNotFound:
            self._logger.warning(
                "git binary not found on PATH -- versioning disabled."
            )
            self._available = False
            return

        self.repo_path.mkdir(parents=True, exist_ok=True)

        try:
            self._repo = git.Repo(str(self.repo_path))
            self._logger.info("Opened existing git repo at %s", self.repo_path)
        except git.InvalidGitRepositoryError:
            self._repo = git.Repo.init(str(self.repo_path))
            self._logger.info("Initialised new git repo at %s", self.repo_path)
            # Create initial commit if the repo is empty
            self._initial_commit()
        except Exception:
            self._logger.exception("Failed to initialise git repo at %s", self.repo_path)
            self._available = False
            return

        self._available = True

    def _initial_commit(self) -> None:
        """Create an initial commit if the working tree has files to stage."""
        if self._repo is None:
            return

        import git as _git  # type: ignore[import-untyped]

        # Stage everything currently in the directory
        untracked = self._repo.untracked_files
        if untracked:
            self._repo.index.add(untracked)

        # Only commit if there is something staged
        if self._repo.is_dirty(index=True, untracked_files=True):
            self._repo.index.add("*")
            try:
                self._repo.index.commit(
                    "Initial REX knowledge base",
                    author=_git.Actor("REX-AUTO", "rex@localhost"),
                    committer=_git.Actor("REX-AUTO", "rex@localhost"),
                )
                self._logger.info("Created initial commit.")
            except Exception:
                self._logger.exception("Failed to create initial commit.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def commit(self, message: str, author: str = "REX-AUTO") -> str | None:
        """Stage all changes and create a commit.

        Skips silently if nothing changed or versioning is disabled.

        Parameters
        ----------
        message:
            Commit message.
        author:
            Author name for the commit.

        Returns
        -------
        str | None
            The hex SHA of the new commit, or ``None`` if nothing was committed.
        """
        if not self._available or self._repo is None:
            return None
        return await asyncio.to_thread(self._commit_sync, message, author)

    def _commit_sync(self, message: str, author: str) -> str | None:
        """Synchronous commit (run in a thread)."""
        import git as _git  # type: ignore[import-untyped]

        repo = self._repo
        if repo is None:
            return None

        # Stage all modified and untracked files
        try:
            # Add all changes (modified, deleted, new)
            repo.git.add(A=True)
        except _git.GitCommandError as exc:
            self._logger.warning("git add failed: %s", exc)
            return None

        # Check if there is anything to commit
        if not repo.is_dirty(index=True):
            self._logger.debug("Nothing to commit -- working tree clean.")
            return None

        try:
            actor = _git.Actor(author, f"{author.lower().replace(' ', '-')}@rex.local")
            commit = repo.index.commit(
                message,
                author=actor,
                committer=actor,
            )
            sha = commit.hexsha
            self._logger.info("Committed %s: %s", sha[:8], message)
            return sha
        except _git.GitCommandError as exc:
            self._logger.warning("git commit failed: %s", exc)
            return None

    async def get_log(self, n: int = 50) -> list[dict[str, Any]]:
        """Return the last *n* commits.

        Parameters
        ----------
        n:
            Maximum number of commits to return.

        Returns
        -------
        list[dict[str, Any]]
            Each dict contains ``hash``, ``message``, ``author``,
            ``timestamp`` keys.
        """
        if not self._available or self._repo is None:
            return []
        return await asyncio.to_thread(self._get_log_sync, n)

    def _get_log_sync(self, n: int) -> list[dict[str, Any]]:
        """Synchronous log retrieval."""
        repo = self._repo
        if repo is None:
            return []

        entries: list[dict[str, Any]] = []
        try:
            for commit in repo.iter_commits(max_count=n):
                entries.append({
                    "hash": commit.hexsha,
                    "message": commit.message.strip(),
                    "author": str(commit.author),
                    "timestamp": datetime.fromtimestamp(
                        commit.committed_date, tz=UTC
                    ).isoformat(),
                })
        except Exception:
            self._logger.exception("Failed to read git log.")

        return entries

    async def get_diff(self, commit_hash: str) -> str:
        """Return the diff for a specific commit.

        Parameters
        ----------
        commit_hash:
            The hex SHA of the commit to diff.

        Returns
        -------
        str
            Unified diff text.  Empty string if versioning is disabled
            or the commit is not found.
        """
        if not self._available or self._repo is None:
            return ""
        return await asyncio.to_thread(self._get_diff_sync, commit_hash)

    def _get_diff_sync(self, commit_hash: str) -> str:
        """Synchronous diff retrieval."""
        repo = self._repo
        if repo is None:
            return ""

        try:
            commit = repo.commit(commit_hash)
            if commit.parents:
                parent = commit.parents[0]
                return repo.git.diff(parent.hexsha, commit.hexsha)
            else:
                # Initial commit -- diff against empty tree
                return repo.git.diff(
                    "4b825dc642cb6eb9a060e54bf899d69f7cb46101",
                    commit.hexsha,
                )
        except Exception:
            self._logger.exception("Failed to get diff for %s", commit_hash)
            return ""

    async def revert(self, commit_hash: str) -> str | None:
        """Revert to a specific commit by creating a new revert commit.

        Parameters
        ----------
        commit_hash:
            The hex SHA of the commit to revert.

        Returns
        -------
        str | None
            The hex SHA of the revert commit, or ``None`` on failure.
        """
        if not self._available or self._repo is None:
            return None
        return await asyncio.to_thread(self._revert_sync, commit_hash)

    def _revert_sync(self, commit_hash: str) -> str | None:
        """Synchronous revert."""
        import git as _git  # type: ignore[import-untyped]

        repo = self._repo
        if repo is None:
            return None

        try:
            repo.git.revert(commit_hash, no_edit=True)
            sha = repo.head.commit.hexsha
            self._logger.info("Reverted %s -> new commit %s", commit_hash[:8], sha[:8])
            return sha
        except _git.GitCommandError as exc:
            self._logger.warning("git revert failed: %s", exc)
            # Abort if revert left the repo in a conflicted state
            with contextlib.suppress(Exception):
                repo.git.revert("--abort")
            return None

    async def get_file_at_version(self, commit_hash: str) -> str:
        """Return the full KB file content at a specific version.

        Parameters
        ----------
        commit_hash:
            The commit whose version of the file to retrieve.

        Returns
        -------
        str
            File content at that version.  Empty string on failure.
        """
        if not self._available or self._repo is None:
            return ""
        return await asyncio.to_thread(self._get_file_at_version_sync, commit_hash)

    def _get_file_at_version_sync(self, commit_hash: str) -> str:
        """Synchronous file-at-version retrieval."""
        repo = self._repo
        if repo is None:
            return ""

        try:
            commit = repo.commit(commit_hash)
            # Look for the KB markdown file in the commit tree
            for blob in commit.tree.traverse():
                if blob.path.endswith("REX-BOT-AI.md"):
                    return blob.data_stream.read().decode("utf-8")

            # Fallback: try all .md files
            for blob in commit.tree.traverse():
                if blob.path.endswith(".md"):
                    return blob.data_stream.read().decode("utf-8")

            self._logger.warning("No markdown file found in commit %s", commit_hash[:8])
            return ""
        except Exception:
            self._logger.exception("Failed to read file at commit %s", commit_hash)
            return ""
