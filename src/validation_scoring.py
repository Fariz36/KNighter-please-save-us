"""Score a checker on a bug-fix commit from report *locations*, not report counts.

Upstream scoring (kept here as ``legacy``) gives TP when the buggy version of a
patched file has any report at all, and TN when the fixed version has zero
reports or merely fewer. A noisy checker therefore passes (e.g. 26 reports on
buggy, 17 on fixed was "valid").

Strict scoring asks the question the paper cares about: does the checker
report *the bug the patch fixes*, and stop reporting it after the fix?

* A report is on-target on the buggy side when it lies in a function the
  patch modifies (by name or line range), or within ``window`` lines of a
  changed line when the enclosing function cannot be determined.
* TP = number of patched files with >= 1 on-target report on the buggy side.
* TN = number of those files with 0 on-target reports on the fixed side.

A checker is "perfect" when TP > 0 and TN > 0, exactly as before, so callers
keep their (TP, TN) interface.
"""

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from loguru import logger

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


@dataclass
class FileChange:
    """Lines touched by the patch in one file, 1-based.

    ``old_lines`` / ``new_lines`` are the removed / added lines. A run of added
    lines with no removed lines next to it (a pure insertion) has no removed
    line on the old side, so it is recorded as an ``old_gaps`` entry
    ``(line_before, line_after)``; pure deletions likewise give ``new_gaps``.
    A gap marks a function as patched only if it lies strictly inside it, so an
    insertion right after ``}`` does not implicate the preceding function.
    """

    path: str
    old_lines: Set[int] = field(default_factory=set)
    new_lines: Set[int] = field(default_factory=set)
    old_gaps: Set[Tuple[int, int]] = field(default_factory=set)
    new_gaps: Set[Tuple[int, int]] = field(default_factory=set)
    hunk_contexts: List[str] = field(default_factory=list)


@dataclass
class Region:
    """Where on-target reports may appear for one file on one side.

    ``functions``: patched functions (name -> 1-based inclusive range).
    ``orphans``: changed lines that lie in no parsed function (macro-heavy
    code tree-sitter could not parse, file-scope code); reports within
    ``window`` lines of them also count.
    """

    functions: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    orphans: Set[int] = field(default_factory=set)
    window: int = 5

    def contains(self, function: str, line: int) -> bool:
        if function and function in self.functions:
            return True
        for start, end in self.functions.values():
            if start <= line <= end:
                return True
        return any(abs(line - anchor) <= self.window for anchor in self.orphans)


def parse_diff(diff_text: str) -> Dict[str, FileChange]:
    """Parse a unified diff into per-file changed lines (1-based)."""
    changes: Dict[str, FileChange] = {}
    current: Optional[FileChange] = None
    old_no = new_no = 0
    in_header = True  # between "diff --git" and the first "@@" of a file
    run_minus: List[int] = []  # old line numbers of the current '-' run
    run_plus: List[int] = []  # new line numbers of the current '+' run
    run_start = (0, 0)  # (old_no, new_no) where the current change run began

    def flush():
        """Close a run of consecutive -/+ lines."""
        nonlocal run_minus, run_plus
        if current is not None and (run_minus or run_plus):
            old_at, new_at = run_start
            current.old_lines.update(run_minus)
            current.new_lines.update(run_plus)
            if run_plus and not run_minus:  # pure insertion
                current.old_gaps.add((old_at - 1, old_at))
            if run_minus and not run_plus:  # pure deletion
                current.new_gaps.add((new_at - 1, new_at))
        run_minus, run_plus = [], []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush()
            in_header = True
            current = None
            continue
        if in_header and line.startswith("--- "):
            path = line[4:].strip()
            if path.startswith("a/"):
                current = changes.setdefault(path[2:], FileChange(path[2:]))
            continue
        if in_header and line.startswith("+++ "):
            continue
        match = _HUNK.match(line)
        if match:
            flush()
            in_header = False
            old_no = int(match.group(1))
            new_no = int(match.group(3))
            if current is not None:
                current.hunk_contexts.append(match.group(5).strip())
            continue
        if current is None:
            continue
        tag = line[0] if line else " "
        if tag in "-+" and not (run_minus or run_plus):
            run_start = (old_no, new_no)
        if tag == "-":
            run_minus.append(old_no)
            old_no += 1
        elif tag == "+":
            run_plus.append(new_no)
            new_no += 1
        elif tag == " ":
            flush()
            old_no += 1
            new_no += 1
        # "\ No newline at end of file" and other markers: ignore
    flush()
    return changes


def extract_diff(patch_markdown: str) -> str:
    """The ```diff block of the markdown produced by ``TargetFactory.get_patch``."""
    match = re.search(r"```diff\n(.*?)\n```", patch_markdown, re.DOTALL)
    return match.group(1) if match else patch_markdown


def function_ranges(source_file: Path) -> List[Tuple[str, int, int]]:
    """(name, start, end) of function definitions, 1-based inclusive."""
    from kparser.kfunction import KernelFunction

    try:
        functions = KernelFunction.from_file(source_file)
    except Exception as error:  # tree-sitter can fail on macro-heavy code
        logger.warning(f"Function parsing failed for {source_file}: {error}")
        return []
    ranges = []
    for func in functions:
        start, end = func.get_line_numbers()
        ranges.append((func.name, start + 1, end + 1))
    return ranges


def region_for(
    lines: Set[int],
    ranges: Sequence[Tuple[str, int, int]],
    gaps: Set[Tuple[int, int]] = frozenset(),
    window: int = 5,
) -> Region:
    """Patched functions (and orphan anchors) for one side of one file."""
    region = Region(window=window)

    def add(name, start, end):
        region.functions[name or f"<anon@{start}>"] = (start, end)

    for line in lines:
        hits = [(n, s_, e) for n, s_, e in ranges if s_ <= line <= e]
        for hit in hits:
            add(*hit)
        if not hits:
            region.orphans.add(line)
    for before, after in gaps:
        hits = [(n, s_, e) for n, s_, e in ranges if s_ <= before and after <= e]
        for hit in hits:
            add(*hit)
        if not hits and not any(s_ <= before <= e or s_ <= after <= e for _, s_, e in ranges):
            region.orphans.update((before, after))
    return region


@dataclass
class FileScore:
    path: str
    analyzed_buggy: bool
    analyzed_fixed: bool
    buggy_total: int = 0
    fixed_total: int = 0
    buggy_on_target: int = 0
    fixed_on_target: int = 0
    buggy_functions: List[str] = field(default_factory=list)
    fixed_functions: List[str] = field(default_factory=list)


@dataclass
class ValidationScore:
    tp: int
    tn: int
    legacy_tp: int
    legacy_tn: int
    scoring: str
    files: List[FileScore]

    def to_dict(self):
        return asdict(self)

    @property
    def selected(self) -> Tuple[int, int]:
        if self.scoring == "legacy":
            return self.legacy_tp, self.legacy_tn
        return self.tp, self.tn


def legacy_tn_delta(buggy_count: int, fixed_count: int) -> int:
    """Upstream rule from ``_validate_checker_linux``."""
    if fixed_count == 0:
        return 1
    if fixed_count < buggy_count and fixed_count < 5:
        return 1
    if fixed_count > buggy_count:
        return -1
    return 0


def score(
    changes: Dict[str, FileChange],
    buggy_reports: Dict[str, list],
    fixed_reports: Dict[str, list],
    buggy_regions: Dict[str, Region],
    fixed_regions: Dict[str, Region],
    analyzed_buggy: Set[str],
    analyzed_fixed: Set[str],
    scoring: str = "strict",
) -> ValidationScore:
    """Score reports per patched file.

    ``*_reports[path]`` are the reports produced while analyzing ``path`` (they
    may point into headers; only reports whose ``relpath == path`` can be
    on-target). Reports need ``relpath``, ``function`` and ``line`` attributes.
    """
    tp = tn = legacy_tp = legacy_tn = 0
    files = []
    for path in changes:
        file_score = FileScore(
            path=path,
            analyzed_buggy=path in analyzed_buggy,
            analyzed_fixed=path in analyzed_fixed,
        )
        buggy = buggy_reports.get(path, [])
        fixed = fixed_reports.get(path, [])
        file_score.buggy_total = len(buggy)
        file_score.fixed_total = len(fixed)

        b_region = buggy_regions.get(path, Region())
        f_region = fixed_regions.get(path, Region())
        file_score.buggy_functions = sorted(b_region.functions)
        file_score.fixed_functions = sorted(f_region.functions)
        file_score.buggy_on_target = sum(
            1 for r in buggy if r.relpath == path and b_region.contains(r.function, r.line)
        )
        file_score.fixed_on_target = sum(
            1 for r in fixed if r.relpath == path and f_region.contains(r.function, r.line)
        )

        if file_score.analyzed_buggy and file_score.buggy_on_target > 0:
            tp += 1
            if file_score.analyzed_fixed and file_score.fixed_on_target == 0:
                tn += 1

        if file_score.analyzed_buggy and file_score.buggy_total > 0:
            legacy_tp += 1
        if file_score.analyzed_fixed:
            legacy_tn += legacy_tn_delta(file_score.buggy_total, file_score.fixed_total)
        files.append(file_score)

    return ValidationScore(tp, tn, legacy_tp, legacy_tn, scoring, files)
