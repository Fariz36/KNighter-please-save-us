"""Generic C target driven by a compilation database (compile_commands.json).

Any project can be analyzed if a config can describe how to produce a
compilation database for a revision (CMake export, intercept-build around
make, meson, ...). No build-system logic lives in the code.

Every revision gets its own ``git worktree`` plus build directory, set up
once and then reused. This lets workers analyze different revisions at the
same time (no shared working tree, no global lock) and makes repeated
validations of a commit skip the (often slow) configure step.

Example config:

    target_type: compiledb
    target_options:
      name: curl
      repo_dir: /path/to/curl
      setup:
        - cmake -S {src} -B {build} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ...
      compile_db: "{build}/compile_commands.json"   # default
      source_extensions: [".c"]                    # default
      scan_exclude: ["tests/", "docs/"]            # optional
"""

import hashlib
import json
import os
import re
import shutil
import subprocess as sp
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from backends.plugin_builder import _file_lock
from targets.factory import Checkout, CompileDBTargetBase, git_lock


class TargetSetupError(RuntimeError):
    """A revision could not be checked out or configured (infrastructure, not the checker)."""


class CompileDBTarget(CompileDBTargetBase):
    """A C project described entirely by config."""

    _target_type = "compiledb"

    def __init__(
        self,
        repo_dir: str,
        setup: List[str],
        name: Optional[str] = None,
        compile_db: str = "{build}/compile_commands.json",
        work_dir: Optional[str] = None,
        source_extensions: Optional[List[str]] = None,
        scan_include: Optional[List[str]] = None,
        scan_exclude: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        llvm_bin: Optional[str] = None,
        jobs: int = 8,
        setup_timeout: int = 1800,
        reuse_revisions: bool = True,
        **unused,
    ):
        super().__init__(repo_dir)
        if unused:
            logger.warning(f"Unknown compiledb target options ignored: {sorted(unused)}")
        self.name = name or Path(repo_dir).name
        self.setup_commands = list(setup)
        self.compile_db_template = compile_db
        repo_path = Path(repo_dir).absolute()
        self.work_dir = (
            Path(work_dir).absolute()
            if work_dir
            else repo_path.parent / ".knighter-work" / self.name
        )
        self.source_extensions = tuple(source_extensions or [".c"])
        self.scan_include = scan_include or []
        self.scan_exclude = scan_exclude or []
        self.llvm_bin = Path(llvm_bin).absolute() if llvm_bin else None
        self.jobs = jobs
        self.setup_timeout = setup_timeout
        # False reproduces upstream behaviour (fresh configure on every checkout);
        # used as the baseline in speed experiments.
        self.reuse_revisions = reuse_revisions
        self.env = dict(env or {})
        if self.llvm_bin:
            self.env.setdefault("CC", str(self.llvm_bin / "clang"))
            self.env.setdefault("CXX", str(self.llvm_bin / "clang++"))

        self._setup_hash = hashlib.sha256(
            json.dumps([self.setup_commands, self.compile_db_template, self.env]).encode()
        ).hexdigest()[:12]
        self._rev_locks: Dict[str, threading.Lock] = {}
        self._rev_locks_guard = threading.Lock()
        self._checkouts: Dict[str, Checkout] = {}
        self._failures: Dict[str, str] = {}
        self.current: Optional[Checkout] = None

    def __str__(self):
        return f"Target Type: compiledb ({self.name}), Repository Path: {self.repo.working_dir}"

    # ---------------------------------------------------------------- revisions
    def resolve(self, commit_id: str, is_before: bool = False) -> str:
        revision = f"{commit_id}^" if is_before else commit_id
        with git_lock:
            return self.repo.git.rev_parse("--verify", f"{revision}^{{commit}}").strip()

    def _lock_for(self, sha: str) -> threading.Lock:
        with self._rev_locks_guard:
            return self._rev_locks.setdefault(sha, threading.Lock())

    def prepare(self, commit_id: str, is_before: bool = False) -> Checkout:
        """Return a configured checkout of the revision, creating it if needed.

        Safe to call from many threads: each revision is set up once; different
        revisions are set up concurrently.
        """
        try:
            sha = self.resolve(commit_id, is_before)
        except Exception as error:
            raise TargetSetupError(f"cannot resolve {commit_id}{'^' if is_before else ''}: {error}")
        with self._lock_for(sha), _file_lock(self.work_dir / "locks" / f"{sha}.lock"):
            if sha in self._failures:
                # Configure failures are deterministic: do not retry them per attempt.
                raise TargetSetupError(self._failures[sha])
            if not self.reuse_revisions:
                return self._setup_revision(sha, fresh=True)
            cached = self._checkouts.get(sha)
            if cached is not None:
                return cached
            try:
                checkout = self._setup_revision(sha)
            except TargetSetupError as error:
                self._failures[sha] = str(error)
                raise
            self._checkouts[sha] = checkout
            return checkout

    def _setup_revision(self, sha: str, fresh: bool = False) -> Checkout:
        src = self.work_dir / "src" / sha[:12]
        build = self.work_dir / "build" / f"{sha[:12]}-{self._setup_hash}"
        if fresh:
            build = build.with_name(f"{build.name}-{time.time_ns()}")
        compile_db = Path(self._format(self.compile_db_template, src, build))
        marker = build / ".knighter_setup.json"
        # `git worktree add` creates .git before the checkout finishes, so an
        # interrupted run could leave a partial tree; only this marker proves
        # the checkout completed.
        src_marker = self.work_dir / "src" / f".{sha[:12]}.ok"

        if not src_marker.exists():
            src.parent.mkdir(parents=True, exist_ok=True)
            with git_lock:
                if src.exists():
                    sp.run(["git", "worktree", "remove", "--force", str(src)],
                           cwd=self.repo.working_dir, capture_output=True)
                    shutil.rmtree(src, ignore_errors=True)
                # A stale registration (e.g. a deleted directory) blocks `add`.
                sp.run(
                    ["git", "worktree", "prune"],
                    cwd=self.repo.working_dir,
                    capture_output=True,
                )
                res = sp.run(
                    ["git", "worktree", "add", "--force", "--detach", str(src), sha],
                    cwd=self.repo.working_dir,
                    capture_output=True,
                    text=True,
                )
            if res.returncode != 0:
                raise TargetSetupError(f"git worktree add failed for {sha}: {res.stderr}")
            src_marker.write_text(sha)

        if marker.exists() and compile_db.exists():
            logger.info(f"[{self.name}] reuse configured revision {sha[:12]}")
            return Checkout(sha, src, build, compile_db)

        build.mkdir(parents=True, exist_ok=True)
        log_path = build / ".knighter_setup.log"
        env = {**os.environ, **self.env}
        start = time.time()
        with open(log_path, "w") as log:
            for template in self.setup_commands:
                command = self._format(template, src, build)
                log.write(f"$ {command}\n")
                log.flush()
                try:
                    res = sp.run(
                        command,
                        shell=True,
                        cwd=build,
                        env=env,
                        stdout=log,
                        stderr=sp.STDOUT,
                        timeout=self.setup_timeout,
                    )
                except sp.TimeoutExpired:
                    raise TargetSetupError(
                        f"[{self.name}] setup timed out for {sha[:12]}: {command}"
                    )
                if res.returncode != 0:
                    tail = log_path.read_text()[-2000:]
                    raise TargetSetupError(
                        f"[{self.name}] setup failed for {sha[:12]} ({command}):\n{tail}"
                    )
        if not compile_db.exists():
            raise TargetSetupError(f"[{self.name}] setup did not produce {compile_db}")
        seconds = time.time() - start
        marker.write_text(
            json.dumps({"revision": sha, "setup_seconds": round(seconds, 2)})
        )
        logger.info(f"[{self.name}] configured revision {sha[:12]} in {seconds:.1f}s")
        return Checkout(sha, src, build, compile_db)

    def _format(self, template: str, src: Path, build: Path) -> str:
        return template.format(
            src=src,
            build=build,
            jobs=self.jobs,
            clang=self.env.get("CC", "clang"),
            clangxx=self.env.get("CXX", "clang++"),
        )

    # ------------------------------------------------------ TargetFactory API
    def checkout_commit(self, commit_id: str, is_before: bool = False, **kwargs):
        """Legacy API: make ``self.current`` point at a configured revision."""
        self.current = self.prepare(commit_id, is_before)
        return self.current

    @staticmethod
    def get_object_name(file_name: str) -> str:
        # Analysis units are source files; no object-name mapping needed.
        return file_name

    def get_objects_from_patch(self, patch: str) -> List[str]:
        """Source files modified in place by the patch (present before and after).

        Added, deleted and renamed files are excluded: one side has no such file,
        so the checker could never be scored on it.
        """
        pairs = re.findall(r"^--- (\S+)\n\+\+\+ (\S+)$", patch, re.MULTILINE)
        files = [old[2:] for old, new in pairs
                 if old.startswith("a/") and new.startswith("b/") and old[2:] == new[2:]]
        return [f for f in dict.fromkeys(files) if f.endswith(self.source_extensions)]

    def prefetch(self, commit_id: str):
        """Start configuring both revisions of a commit in the background.

        Returns the thread (or None). Validation calls ``prepare`` again and
        simply waits on the per-revision lock if the setup is still running,
        so configure time overlaps with the LLM stages.
        """
        if not self.reuse_revisions:
            return None

        def run():
            for before in (True, False):
                try:
                    self.prepare(commit_id, before)
                except Exception as error:  # reported again by validation
                    logger.warning(f"[{self.name}] prefetch of {commit_id} failed: {error}")

        thread = threading.Thread(target=run, name=f"prefetch-{commit_id[:8]}", daemon=True)
        thread.start()
        return thread

    def in_scan_scope(self, relpath: str) -> bool:
        if not super().in_scan_scope(relpath):
            return False
        if self.scan_include and not any(relpath.startswith(p) for p in self.scan_include):
            return False
        return not any(relpath.startswith(p) for p in self.scan_exclude)

    def relpath_of(self, path: str) -> Optional[str]:
        """Map an absolute path from any prepared worktree to a repo-relative path."""
        path = os.path.normpath(path)
        root = str(self.work_dir / "src") + os.sep
        if path.startswith(root):
            # <work>/src/<sha12>/<relpath>
            return path[len(root):].split(os.sep, 1)[-1]
        repo_root = str(Path(self.repo.working_dir).absolute()) + os.sep
        if path.startswith(repo_root):
            return path[len(repo_root):]
        return None
