"""Run a CSA plugin directly on compilation-database entries (no scan-build, no make).

Also parses the metadata header clang writes into every HTML report
(``<!-- BUGFILE ... -->`` etc.). scan-build reports carry the same header, so
the parser works for every target type.

Standard library only (loguru optional): checker bundles ship this file
verbatim as their analysis runtime (see checker_bundle.py).
"""

import os
import re
import shlex
import subprocess as sp
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

try:
    from loguru import logger
except ImportError:  # shipped standalone inside checker bundles (stdlib only)
    import logging

    logger = logging.getLogger("knighter")

# Built-in checker packages disabled so only the generated checker reports.
# Same list as the scan-build path (ClangBackend._default_args).
DISABLED_CHECKERS = ["core", "cplusplus", "deadcode", "unix", "nullability", "security"]
CHECKER_NAME = "custom.SAGenTestChecker"

# Flags that take a separate value and only matter for compiling/linking.
_DROP_WITH_VALUE = {"-o", "-MF", "-MT", "-MQ", "-MJ"}
_DROP = {"-c", "-MD", "-MMD", "-MP", "-M", "-MM"}

CXX_EXTENSIONS = (".cc", ".cpp", ".cxx", ".C", ".c++")

_META = re.compile(r"<!-- (BUG[A-Z]+|FILENAME|FUNCTIONNAME|ISSUEHASH[A-Z]+) (.*?) -->")


@dataclass
class Report:
    file: str
    line: int
    column: int
    function: str
    bug_type: str
    description: str
    issue_hash: str
    html_path: str
    relpath: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class FileAnalysis:
    """Result of analyzing one compile entry."""

    source: str
    ok: bool
    crashed: bool = False
    returncode: int = 0
    seconds: float = 0.0
    reports: List[Report] = field(default_factory=list)
    error: str = ""


def parse_report_html(path: Path) -> Optional[Report]:
    """Parse the metadata header of a clang HTML report."""
    try:
        with open(path, errors="replace") as handle:
            head = handle.read(8192)
    except OSError:
        return None
    meta = dict(_META.findall(head))
    if "BUGFILE" not in meta:
        return None
    return Report(
        file=meta["BUGFILE"],
        line=int(meta.get("BUGLINE", 0) or 0),
        column=int(meta.get("BUGCOLUMN", 0) or 0),
        function=meta.get("FUNCTIONNAME", ""),
        bug_type=meta.get("BUGTYPE", ""),
        description=meta.get("BUGDESC", ""),
        issue_hash=meta.get("ISSUEHASHCONTENTOFLINEINCONTEXT", ""),
        html_path=str(path),
    )


def collect_reports(report_dir: Path, delete_duplicates: bool = False) -> List[Report]:
    """All reports under ``report_dir`` (recursive), de-duplicated by issue hash + location.

    The same header report is emitted once per translation unit that includes
    it. ``delete_duplicates`` removes the extra HTML files so that code counting
    files on disk (``extract_reports``) sees the same number.
    """
    seen = set()
    reports = []
    for html in sorted(Path(report_dir).rglob("report-*.html")):
        report = parse_report_html(html)
        if report is None:
            continue
        key = (report.issue_hash, report.file, report.line)
        if key in seen:
            if delete_duplicates:
                html.unlink(missing_ok=True)
            continue
        seen.add(key)
        reports.append(report)
    return reports


def analyzer_argv(
    clang: Path,
    plugin: Path,
    entry: dict,
    output_dir: Path,
    max_loop: int = 4,
    extra_args: Iterable[str] = (),
) -> List[str]:
    """Turn a compile-database entry into a ``clang --analyze`` command."""
    argv = entry.get("arguments") or shlex.split(entry["command"])
    source = entry["file"]
    directory = entry.get("directory") or "."
    source_abs = os.path.normpath(os.path.join(directory, source))
    cleaned = []
    skip = False
    for arg in argv[1:]:
        if skip:
            skip = False
            continue
        if arg in _DROP_WITH_VALUE:
            skip = True
            continue
        if arg in _DROP:
            continue
        # The source may be spelled relative to `directory` in the command
        # (e.g. intercept-build: file=/abs/lapi.c, command "... lapi.c"); passing it
        # twice makes clang fail with "cannot specify -o when generating multiple
        # output files".
        if not arg.startswith("-") and os.path.normpath(os.path.join(directory, arg)) == source_abs:
            continue
        if any(arg.startswith(p) and len(arg) > len(p) for p in _DROP_WITH_VALUE):
            continue  # -oFILE / -MFfile forms
        if arg.startswith("-Werror"):
            continue
        cleaned.append(arg)

    if source.endswith(CXX_EXTENSIONS):
        # The C driver would still parse .cc as C++, but only the C++ driver
        # reliably adds the C++ standard library include paths.
        clang = Path(clang).with_name("clang++")
    command = [str(clang), "--analyze", "-w"]
    command += ["-Xanalyzer", "-load", "-Xanalyzer", str(plugin)]
    command += ["-Xanalyzer", f"-analyzer-checker={CHECKER_NAME}"]
    for checker in DISABLED_CHECKERS:
        command += ["-Xanalyzer", f"-analyzer-disable-checker={checker}"]
    command += ["-Xanalyzer", "-analyzer-max-loop", "-Xanalyzer", str(max_loop)]
    command += ["-Xanalyzer", "-analyzer-output=html", "-o", str(output_dir)]
    command += list(extra_args)
    command += cleaned
    command.append(source)
    return command


def _is_crash(stderr: str) -> bool:
    return "PLEASE submit a bug report" in stderr or "Stack dump:" in stderr


def analyze_entry(
    clang: Path,
    plugin: Path,
    entry: dict,
    output_dir: Path,
    timeout: int = 600,
    max_loop: int = 4,
    roles_file: Optional[Path] = None,
) -> FileAnalysis:
    # clang runs in the entry's directory, so a relative -o would land there.
    output_dir = Path(output_dir).absolute()
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = analyzer_argv(
        Path(clang).absolute(), Path(plugin).absolute(), entry, output_dir, max_loop=max_loop
    )
    env = dict(os.environ)
    roles_file = roles_file or Path(plugin).parent / "roles.json"
    if "KNIGHTER_ROLES" not in env and Path(roles_file).exists():
        # Role-based checkers read project API names from this file (knighter/roles.h).
        env["KNIGHTER_ROLES"] = str(Path(roles_file).absolute())
    start = time.time()
    try:
        res = sp.run(
            argv,
            cwd=entry.get("directory") or None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except sp.TimeoutExpired:
        return FileAnalysis(
            source=entry["file"],
            ok=False,
            seconds=time.time() - start,
            error=f"analysis timed out after {timeout}s",
            reports=collect_reports(output_dir),
        )
    seconds = time.time() - start
    crashed = res.returncode != 0 and _is_crash(res.stderr)
    return FileAnalysis(
        source=entry["file"],
        ok=res.returncode == 0,
        crashed=crashed,
        returncode=res.returncode,
        seconds=seconds,
        reports=collect_reports(output_dir),
        error="" if res.returncode == 0 else res.stderr[-3000:],
    )


def analyze_entries(
    clang: Path,
    plugin: Path,
    entries: List[dict],
    output_dir: Path,
    jobs: int = 4,
    timeout: int = 600,
    max_loop: int = 4,
    roles_file: Optional[Path] = None,
) -> List[FileAnalysis]:
    """Analyze entries in parallel, each into ``output_dir/<file>/``.

    Separate directories keep reports attributable to the analyzed file even
    when files run concurrently. ``extract_reports`` accepts this one-level
    layout (it was added for V8).
    """

    def run(entry):
        out = Path(output_dir) / _safe_name(entry["file"])
        return analyze_entry(clang, plugin, entry, out, timeout=timeout, max_loop=max_loop,
                             roles_file=roles_file)

    if not entries:
        return []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        results = list(pool.map(run, entries))
    failed = [r for r in results if not r.ok]
    if failed:
        logger.warning(
            f"{len(failed)}/{len(results)} analyses failed "
            f"({sum(r.crashed for r in failed)} crashed); first: "
            f"{failed[0].source}: {failed[0].error[-300:]}"
        )
    return results


def _safe_name(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.normpath(path)).strip("_")[-150:]
