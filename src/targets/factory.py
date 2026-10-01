import json
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import git

from tools import get_function_codes_with_config, truncate_large_file

# GitPython object reads are not thread-safe (concurrent `get_patch` calls hit
# "read of closed file"), so all repository reads/writes share this lock.
git_lock = threading.RLock()


class TargetFactory(ABC):
    """
    A class representing a Git repository.
    """

    _target_type = "generic"
    _build_commands = None

    def __init__(self, repo_path: str):
        self.repo = git.Repo(repo_path)

    def __str__(self):
        return f"Target Type: {self._target_type}, Repository Path: {self.repo.working_dir}"

    @abstractmethod
    def checkout_commit(self, commit_id: str, is_before: bool = False, **kwargs):
        """
        Checkout a specific commit in the repository.

        Args:
            commit_id (str): The commit ID to checkout.
            is_before (bool): Whether to checkout before the commit.
            **kwargs: Additional arguments for the checkout command.
        """
        pass

    @staticmethod
    @abstractmethod
    def get_object_name(file_name: str) -> str:
        """
        Get the object name from a file name.

        Args:
            file_name (str): The name of the file.

        Returns:
            str: The object name.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    @abstractmethod
    def get_objects_from_patch(patch: str) -> List[str]:
        """
        Get the objects to analyze from a patch.

        Args:
            patch (str): The patch to analyze.

        Returns:
            List[str]: The objects to analyze.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def get_patch(self, commit_id: str) -> str:
        """
        Get the patch for a specific commit formatted as Markdown.

        Args:
            commit_id (str): The commit ID to get the patch for.

        Returns:
            str: Formatted patch as Markdown including commit message,
                 affected functions, and diff.

        Raises:
            ValueError: If commit_id does not exist in the repository.
        """
        with git_lock:
            return self._get_patch_locked(commit_id)

    def _get_patch_locked(self, commit_id: str) -> str:
        try:
            commit = self.repo.commit(commit_id)
        except (git.exc.BadName, ValueError):
            raise ValueError(f"Commit '{commit_id}' not found in repository")

        message = commit.message.strip()

        # Get the diff between this commit and its parent
        parent_id = commit.hexsha + "^"
        diff = commit.repo.git.diff(parent_id, commit.hexsha)

        # Get affected function code
        func_code_set = get_function_codes_with_config(commit)

        # Build the markdown content in parts for better readability
        sections = []

        # Add commit description
        sections.append("## Patch Description\n\n" + message + "\n")

        # Add buggy code section
        sections.append("## Buggy Code\n")
        for file_path, func_name, func_code in func_code_set:
            # Skip if func_name is None (parsing failure)
            if func_name is None:
                continue
            if func_name.startswith("WHOLE_FILE_"):
                # Handle whole file fallback case
                file_name = func_name.replace("WHOLE_FILE_", "")

                # Truncate very large files to avoid overwhelming the prompt
                truncated_code = truncate_large_file(func_code, max_lines=500)

                sections.append(
                    f"```c\n// Complete file: {file_path} (tree-sitter fallback)\n{truncated_code}\n```\n"
                )
            else:
                # Handle normal function case
                sections.append(
                    f"```c\n// Function: {func_name} in {file_path}\n{func_code}\n```\n"
                )

        # Add patch diff
        sections.append("## Bug Fix Patch\n\n```diff\n" + diff + "\n```\n")

        # Join all sections with newlines
        return "\n".join(sections)

    @staticmethod
    def path_similarity(path1, path2):
        """Calculate the similarity of two paths based on their components."""
        path1 = str(Path(path1).resolve())
        path2 = str(Path(path2).resolve())
        components1 = path1.split(os.sep)
        components2 = path2.split(os.sep)

        # Count the common components
        common_components = len(set(components1) & set(components2))
        total_components = len(set(components1) | set(components2))

        # Simple ratio of common components to total unique components
        return common_components / total_components


@dataclass
class Checkout:
    """A configured revision: source tree + build dir + compilation database."""

    revision: str
    src: Path
    build: Path
    compile_db: Path
    _entries: Optional[List[dict]] = field(default=None, repr=False)

    def entries(self) -> List[dict]:
        if self._entries is None:
            self._entries = json.loads(self.compile_db.read_text())
        return self._entries

    def abs_file(self, entry: dict) -> Path:
        path = Path(entry["file"])
        if not path.is_absolute():
            path = Path(entry.get("directory", "")) / path
        return Path(os.path.normpath(path))

    def relpath(self, path: str) -> Optional[str]:
        """Repo-relative path of ``path`` if it lies inside this source tree."""
        path = os.path.normpath(path)
        root = str(self.src) + os.sep
        if path.startswith(root):
            return path[len(root):]
        return None

    def entry_for(self, relpath: str) -> Optional[dict]:
        target = os.path.normpath(self.src / relpath)
        for entry in self.entries():
            if str(self.abs_file(entry)) == target:
                return entry
        return None


class CompileDBTargetBase(TargetFactory):
    """A target that can produce a compilation database for any revision.

    The CSA backend analyzes such targets generically (clang --analyze per
    compile entry), so a new kind of C project only needs to implement this
    interface -- no backend changes. ``targets.compiledb.CompileDBTarget`` is
    the config-driven implementation.
    """

    source_extensions = (".c",)

    @abstractmethod
    def prepare(self, commit_id: str, is_before: bool = False) -> Checkout:
        """Check out and configure ``commit_id`` (or its parent); must be thread-safe."""

    @abstractmethod
    def relpath_of(self, path: str) -> Optional[str]:
        """Map an absolute path from any prepared revision to a repo-relative path."""

    def in_scan_scope(self, relpath: str) -> bool:
        """Whether a whole-project scan analyzes this file."""
        return relpath.endswith(self.source_extensions)

    def prefetch(self, commit_id: str):
        """Optionally start preparing both revisions of a commit in the background."""
        return None
