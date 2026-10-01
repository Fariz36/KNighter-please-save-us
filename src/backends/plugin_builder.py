"""Build each generated checker into its own CSA plugin, outside the LLVM tree.

The upstream flow overwrote a single ``SAGenTestChecker.cpp`` inside the LLVM
source tree and ran ``make SAGenTestPlugin``, so only one checker could exist at
a time and every validation silently depended on "whatever was built last".

Here the compile and link commands CMake generated for ``SAGenTestPlugin`` are
replayed with a different source file and output path. Plugins are
content-addressed (sha256 of checker source + build flags), so:
  * two checkers never share a ``.so``;
  * building the same checker twice is a cache hit;
  * any caller can ask for "the plugin of this code" without trusting a
    previous build step.
A precompiled header of the common analyzer headers is built once per LLVM
build and reused, which roughly halves compile time (see docs/RESEARCH_LOG.md).
"""

import fcntl
import hashlib
import json
import shlex
import subprocess as sp
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Tuple

from loguru import logger

PLUGIN_SOURCE_SUFFIX = "plugins/SAGenTestHandling/SAGenTestChecker.cpp"
PLUGIN_BUILD_SUBDIR = "tools/clang/lib/Analysis/plugins/SAGenTestHandling"
PLUGIN_OBJECT = "CMakeFiles/SAGenTestPlugin.dir/SAGenTestChecker.cpp.o"

# Headers nearly every generated checker includes. GCC only uses a PCH when it
# is the very first include, so <cstdint> (which the LLVM build force-includes
# for GCC 15 compatibility) is folded in here instead of passed via -include.
PCH_HEADERS = [
    "cstdint",
    "clang/AST/ASTContext.h",
    "clang/AST/Decl.h",
    "clang/AST/Expr.h",
    "clang/AST/ParentMapContext.h",
    "clang/AST/RecursiveASTVisitor.h",
    "clang/AST/StmtVisitor.h",
    "clang/StaticAnalyzer/Checkers/Taint.h",
    "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h",
    "clang/StaticAnalyzer/Core/BugReporter/BugType.h",
    "clang/StaticAnalyzer/Core/Checker.h",
    "clang/StaticAnalyzer/Core/CheckerManager.h",
    "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h",
    "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h",
    "clang/StaticAnalyzer/Core/PathSensitive/Environment.h",
    "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h",
    "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h",
    "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h",
    "clang/StaticAnalyzer/Core/PathSensitive/SVals.h",
    "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h",
    "clang/StaticAnalyzer/Frontend/CheckerRegistry.h",
    "llvm/ADT/SmallVector.h",
    "llvm/ADT/StringRef.h",
    "llvm/Support/raw_ostream.h",
]


@contextmanager
def _file_lock(path: Path):
    """Cross-process exclusive lock (threads must additionally hold a Lock)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class PluginBuilder:
    """Content-addressed, out-of-tree builder for generated CSA checkers."""

    def __init__(
        self,
        llvm_dir: Path,
        cache_dir: Path,
        opt_level: str = "-O1",
        use_pch: bool = True,
        timeout: int = 600,
        max_parallel: int = 4,
        cache: bool = True,
        preamble: bool = True,
    ):
        self.llvm_build = Path(llvm_dir).absolute() / "build"
        self.cache_dir = Path(cache_dir).absolute()
        self.opt_level = opt_level
        self.use_pch = use_pch
        self.timeout = timeout
        # cache=False rebuilds on every request, like upstream's per-checker
        # `make` (used for the baseline cost model in experiments).
        self.cache = cache
        # The PCH force-includes ~24 clang headers, so without it a checker that
        # forgets an #include would fail to compile where it compiles with the
        # PCH. `preamble` includes the same headers as plain text when no PCH is
        # used, so every build mode accepts exactly the same checker code and
        # only build cost differs (review item A5).
        self.preamble = preamble
        self.plugin_build_dir = self.llvm_build / PLUGIN_BUILD_SUBDIR
        # One checker compile peaks at ~1 GB RSS (measured, -O3); cap concurrency.
        self._build_slots = threading.Semaphore(max_parallel)

        self._compile_base = self._load_compile_template()
        self._link_template = self._load_link_template()
        self._flags_hash = hashlib.sha256(
            json.dumps([self._compile_base, self._link_template]).encode()
        ).hexdigest()[:16]

        self._locks_guard = threading.Lock()
        self._locks = {}
        self._pch_lock = threading.Lock()
        self._pch_dir: Optional[Path] = None
        self._pch_failed = False

    # ------------------------------------------------------------------ setup
    def _load_compile_template(self) -> List[str]:
        """Compile argv for SAGenTestChecker.cpp minus source/output/-O/-include cstdint."""
        database = self.llvm_build / "compile_commands.json"
        entries = json.loads(database.read_text())
        for entry in entries:
            if entry["file"].endswith(PLUGIN_SOURCE_SUFFIX):
                argv = entry.get("arguments") or shlex.split(entry["command"])
                break
        else:
            raise FileNotFoundError(
                f"No compile entry for {PLUGIN_SOURCE_SUFFIX} in {database}"
            )

        result = []
        skip = 0
        for index, arg in enumerate(argv):
            if skip:
                skip -= 1
                continue
            if arg in ("-o", "-c"):
                skip = 1
                continue
            if arg == "-include" and index + 1 < len(argv) and argv[index + 1] == "cstdint":
                skip = 1
                continue
            if arg.startswith("-O"):
                continue
            result.append(arg)
        return result

    def _load_link_template(self) -> List[str]:
        link_txt = self.plugin_build_dir / "CMakeFiles/SAGenTestPlugin.dir/link.txt"
        argv = shlex.split(link_txt.read_text().strip())
        result = []
        skip = 0
        for arg in argv:
            if skip:
                skip -= 1
                continue
            if arg == "-o":
                skip = 1
                continue
            if arg.startswith("-Wl,--dependency-file"):
                continue
            if arg == PLUGIN_OBJECT:
                continue
            result.append(arg)
        return result

    def _compile_argv(self, source: Path, output: Path, pch_dir: Optional[Path]) -> List[str]:
        argv = list(self._compile_base) + [self.opt_level]
        if pch_dir is not None:
            argv += [f"-I{pch_dir}", "-include", "knighter_pch.h", "-Winvalid-pch"]
        elif self.preamble:
            argv += [f"-I{self._preamble_dir()}", "-include", "knighter_pch.h"]
        else:
            argv += ["-include", "cstdint"]
        return argv + ["-o", str(output), "-c", str(source)]

    def _preamble_dir(self) -> Path:
        """Directory holding the preamble header as plain text (no .gch)."""
        directory = self.cache_dir / "preamble"
        header = directory / "knighter_pch.h"
        text = "".join(f"#include <{h}>\n" for h in PCH_HEADERS)
        if not header.exists() or header.read_text() != text:
            directory.mkdir(parents=True, exist_ok=True)
            tmp = header.with_suffix(f".{threading.get_ident()}.tmp")
            tmp.write_text(text)
            tmp.replace(header)
        return directory

    def _link_argv(self, obj: Path, output: Path) -> List[str]:
        # The template keeps its relative library paths, so run it from the
        # CMake plugin build directory.
        return [self._link_template[0], str(obj)] + self._link_template[1:] + [
            "-o",
            str(output),
        ]

    def _ensure_pch(self) -> Optional[Path]:
        """Build (once) and return the PCH directory, or None if unavailable."""
        if not self.use_pch or self._pch_failed:
            return None
        with self._pch_lock:
            if self._pch_dir is not None:
                return self._pch_dir
            pch_dir = self.cache_dir / f"pch-{self._flags_hash}{self.opt_level}"
            header = pch_dir / "knighter_pch.h"
            gch = pch_dir / "knighter_pch.h.gch"
            with _file_lock(pch_dir.with_suffix(".lock")):
                if not gch.exists():
                    pch_dir.mkdir(parents=True, exist_ok=True)
                    header.write_text(
                        "".join(f"#include <{h}>\n" for h in PCH_HEADERS)
                    )
                    argv = list(self._compile_base) + [
                        self.opt_level,
                        "-x",
                        "c++-header",
                        str(header),
                        "-o",
                        str(gch) + ".tmp",
                    ]
                    start = time.time()
                    proc = sp.run(
                        argv,
                        cwd=self.plugin_build_dir,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    if proc.returncode != 0:
                        logger.warning(
                            f"PCH build failed, building without PCH: {proc.stderr[-1000:]}"
                        )
                        self._pch_failed = True
                        return None
                    Path(str(gch) + ".tmp").rename(gch)
                    logger.info(f"Built checker PCH in {time.time() - start:.1f}s: {gch}")
            self._pch_dir = pch_dir
            return pch_dir

    # ------------------------------------------------------------------ build
    def key(self, checker_code: str) -> str:
        # Everything that decides whether `checker_code` compiles is in the key.
        mode = f"{self.opt_level}|pch={self.use_pch}|preamble={self.preamble}"
        return hashlib.sha256(
            (self._flags_hash + mode + checker_code).encode()
        ).hexdigest()[:20]

    def plugin_path(self, checker_code: str) -> Path:
        return self.cache_dir / "plugins" / self.key(checker_code) / "plugin.so"

    def _lock_for(self, key: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(key, threading.Lock())

    def build(self, checker_code: str, explicit: bool = False) -> Tuple[int, str, Path]:
        """Build (or reuse) the plugin for ``checker_code``.

        ``explicit`` marks a compile request (syntax repair) as opposed to a
        lookup before analysis. With ``cache=False`` only explicit requests
        rebuild, mirroring upstream: it recompiled on every repair attempt but
        validated with skip_build_checker=True.

        Returns (return_code, stderr, plugin_path). ``stderr`` holds compiler
        diagnostics on failure, suitable for the syntax-repair prompt.
        """
        if "clang_registerCheckers" not in checker_code:
            # An empty/truncated LLM answer compiles into a plugin that registers
            # no checker; clang then fails on every file. Report it as a build
            # error so syntax repair gets a chance to fix it.
            return 1, (
                "error: the checker does not define `extern \"C\" void "
                "clang_registerCheckers(CheckerRegistry &registry)`, so the plugin would "
                "register no checker"
            ), self.plugin_path(checker_code)
        key = self.key(checker_code)
        work = self.cache_dir / "plugins" / key
        plugin = work / "plugin.so"
        failure = work / "failure.json"

        with self._lock_for(key), _file_lock(work.with_suffix(".lock")):
            if not self.cache and explicit:
                plugin.unlink(missing_ok=True)
                failure.unlink(missing_ok=True)
            if plugin.exists():
                logger.debug(f"Plugin cache hit {key}")
                return 0, "", plugin
            if failure.exists():
                cached = json.loads(failure.read_text())
                logger.debug(f"Plugin failure cache hit {key}")
                return cached["returncode"], cached["stderr"], plugin

            work.mkdir(parents=True, exist_ok=True)
            source = work / "checker.cpp"
            source.write_text(checker_code)
            obj = work / "checker.o"
            pch_dir = self._ensure_pch()

            start = time.time()
            try:
                with self._build_slots:
                    proc = sp.run(
                        self._compile_argv(source, obj, pch_dir),
                        cwd=self.plugin_build_dir,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
            except sp.TimeoutExpired:
                return -1, f"Compilation timed out after {self.timeout}s", plugin
            compile_time = time.time() - start
            if proc.returncode != 0:
                # Short relative paths keep the repair prompt small.
                stderr = _strip_pch_noise(proc.stderr).replace(f"{work}/", "")
                if _is_deterministic_failure(proc.returncode, stderr):
                    failure.write_text(
                        json.dumps({"returncode": proc.returncode, "stderr": stderr})
                    )
                else:
                    stderr = stderr or f"compiler exited with {proc.returncode} (killed?)"
                logger.info(f"Plugin {key} compile failed ({compile_time:.1f}s)")
                return proc.returncode, stderr, plugin

            start = time.time()
            tmp_plugin = work / "plugin.so.tmp"
            try:
                with self._build_slots:
                    proc = sp.run(
                        self._link_argv(obj, tmp_plugin),
                        cwd=self.plugin_build_dir,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
            except sp.TimeoutExpired:
                return -1, f"Link timed out after {self.timeout}s", plugin
            link_time = time.time() - start
            if proc.returncode != 0:
                if _is_deterministic_failure(proc.returncode, proc.stderr):
                    failure.write_text(
                        json.dumps({"returncode": proc.returncode, "stderr": proc.stderr})
                    )
                return proc.returncode, proc.stderr or "link failed", plugin
            tmp_plugin.rename(plugin)
            obj.unlink(missing_ok=True)
            logger.info(
                f"Built plugin {key} (compile {compile_time:.1f}s, link {link_time:.1f}s)"
            )
            (work / "build.json").write_text(
                json.dumps(
                    {
                        "compile_seconds": round(compile_time, 2),
                        "link_seconds": round(link_time, 2),
                        "pch": pch_dir is not None,
                        "opt_level": self.opt_level,
                    }
                )
            )
            return 0, "", plugin


def _is_deterministic_failure(returncode: int, stderr: str) -> bool:
    """Only real diagnostics are cached; signals (OOM kill: -9) and silent
    failures may succeed on retry."""
    return returncode > 0 and bool(stderr.strip())


def _strip_pch_noise(stderr: str) -> str:
    return "\n".join(
        line for line in stderr.splitlines() if "knighter_pch.h" not in line
    )
