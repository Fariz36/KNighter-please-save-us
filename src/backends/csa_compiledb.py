"""Validation and scanning for ``CompileDBTarget`` (any C project with a compile DB)."""

import json
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from loguru import logger

from backends.direct_analysis import analyze_entries, collect_reports
from targets.compiledb import TargetSetupError
from validation_scoring import (
    extract_diff,
    function_ranges,
    parse_diff,
    region_for,
    score,
)


class CompileDBMixin:
    """Mixed into ``ClangBackend``; relies on ``self.plugin_for`` and config attrs."""

    # Return codes (TP, TN) besides real scores:
    #   (-2, -2) the checker crashed clang (checker bug; try the next attempt)
    #   (-3, -3) the checker plugin could not be built/loaded (checker bug; next attempt)
    # Infrastructure problems raise TargetSetupError instead: every attempt of the
    # commit would fail the same way.
    CHECKER_FAILED = (-3, -3)

    def _validate_checker_compiledb(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target,
        details_out: Optional[Path] = None,
    ) -> Tuple[int, int]:
        start = time.time()
        plugin = self.plugin_for(checker_code)
        if plugin is None:
            return self.CHECKER_FAILED
        plugin_seconds = time.time() - start

        files = target.get_objects_from_patch(patch)
        if not files:
            raise TargetSetupError(
                f"Patch of {commit_id} changes no analyzable source files "
                f"({', '.join(target.source_extensions)})"
            )

        # Both revisions are independent: set them up concurrently.
        setup_start = time.time()
        with ThreadPoolExecutor(max_workers=2) as pool:
            buggy_future = pool.submit(target.prepare, commit_id, True)
            fixed_future = pool.submit(target.prepare, commit_id, False)
            buggy_co, fixed_co = buggy_future.result(), fixed_future.result()
        setup_seconds = time.time() - setup_start

        changes = {
            path: change
            for path, change in parse_diff(extract_diff(patch)).items()
            if path in files
        }
        base = Path("tmp") / "validation" / commit_id[:12] / uuid.uuid4().hex[:8]

        side_reports = {}
        side_analyzed = {}
        side_errors = {}
        analysis_seconds = {}
        for side, checkout in (("buggy", buggy_co), ("fixed", fixed_co)):
            entries = {}
            for path in files:
                entry = checkout.entry_for(path)
                if entry is None:
                    logger.warning(f"No compile entry for {path} at {checkout.revision[:12]}")
                else:
                    entries[path] = entry
            t0 = time.time()
            results = analyze_entries(
                self.clang_path,
                plugin,
                list(entries.values()),
                base / side,
                jobs=self.analysis_jobs,
                timeout=self.analysis_timeout,
                max_loop=self.max_loop,
            )
            analysis_seconds[side] = round(time.time() - t0, 2)
            by_source = {entry["file"]: path for path, entry in entries.items()}
            # A patched file outside the build (e.g. an extension not compiled into the
            # library) is a setup problem, not a checker failure.
            reports, analyzed = {}, set()
            errors = {path: "no compile entry" for path in files if path not in entries}
            for result in results:
                path = by_source[result.source]
                if result.crashed:
                    logger.error(f"Checker crashed on {side} {path}")
                    self._write_details(
                        details_out,
                        {"commit_id": commit_id, "error": "checker crash", "file": path,
                         "side": side, "stderr": result.error[-2000:]},
                    )
                    return -2, -2
                if not result.ok:
                    errors[path] = result.error[-1000:]
                    continue
                for report in result.reports:
                    report.relpath = target.relpath_of(report.file)
                reports[path] = result.reports
                analyzed.add(path)
            side_reports[side], side_analyzed[side], side_errors[side] = reports, analyzed, errors

        if not side_analyzed["buggy"] and not side_analyzed["fixed"]:
            all_errors = " ".join(e for errs in side_errors.values() for e in errs.values())
            self._write_details(
                details_out,
                {"commit_id": commit_id, "error": "no file analyzable", "errors": side_errors},
            )
            checker_errors = ("unable to load plugin", "no analyzer checkers or packages are associated")
            if any(e in all_errors for e in checker_errors) or not all_errors:
                logger.error(f"Checker plugin failed on every file of {commit_id}")
                return self.CHECKER_FAILED
            raise TargetSetupError(
                f"No patched file of {commit_id} could be analyzed: {all_errors[-500:]}"
            )

        buggy_regions, fixed_regions = {}, {}
        for path, change in changes.items():
            buggy_regions[path] = region_for(
                change.old_lines, function_ranges(buggy_co.src / path), change.old_gaps
            )
            fixed_regions[path] = region_for(
                change.new_lines, function_ranges(fixed_co.src / path), change.new_gaps
            )

        result = score(
            changes,
            side_reports["buggy"],
            side_reports["fixed"],
            buggy_regions,
            fixed_regions,
            side_analyzed["buggy"],
            side_analyzed["fixed"],
            scoring=self.validation_scoring,
        )
        tp, tn = result.selected
        logger.info(
            f"Validation {commit_id[:12]}: TP={tp} TN={tn} ({self.validation_scoring}); "
            f"strict={result.tp}/{result.tn} legacy={result.legacy_tp}/{result.legacy_tn}"
        )
        self._write_details(
            details_out,
            {
                "commit_id": commit_id,
                "plugin": str(plugin),
                "scoring": self.validation_scoring,
                "selected": [tp, tn],
                "score": result.to_dict(),
                "reports": {
                    side: {p: [r.to_dict() for r in rs] for p, rs in reps.items()}
                    for side, reps in side_reports.items()
                },
                "errors": side_errors,
                "timing": {
                    "plugin_seconds": round(plugin_seconds, 2),
                    "setup_seconds": round(setup_seconds, 2),
                    "analysis_seconds": analysis_seconds,
                    "total_seconds": round(time.time() - start, 2),
                },
                "report_dir": str(base),
            },
        )
        return tp, tn

    @staticmethod
    def _write_details(details_out: Optional[Path], data: dict):
        if details_out is None:
            return
        details_out = Path(details_out)
        details_out.parent.mkdir(parents=True, exist_ok=True)
        details_out.write_text(json.dumps(data, indent=2))

    def _run_checker_compiledb(
        self,
        checker_code: str,
        commit_id: str,
        target,
        object_to_analyze: Optional[str] = None,
        jobs: Optional[int] = None,
        output_dir="tmp",
        **kwargs,
    ) -> int:
        """Scan the whole project (or one source file). Returns the report count.

        Negative values mean "no answer", never "no bug" (refinement treats 0 as
        a killed false positive): -999 the checker cannot be built or every
        analysis failed; -2 the checker crashed on the requested file; -1 the
        requested file has no compile entry or its analysis failed.
        """
        plugin = self.plugin_for(checker_code)
        if plugin is None:
            return -999
        checkout = target.prepare(commit_id)

        if object_to_analyze:
            entry = checkout.entry_for(object_to_analyze)
            if entry is None:
                logger.warning(f"No compile entry for {object_to_analyze}")
                return -1
            entries = [entry]
        else:
            entries = []
            for entry in checkout.entries():
                relpath = checkout.relpath(str(checkout.abs_file(entry)))
                if relpath is not None and target.in_scan_scope(relpath):
                    entries.append(entry)

        # extract_reports() reads the newest subdirectory of output_dir.
        run_dir = Path(output_dir) / time.strftime("%Y-%m-%d-%H%M%S")
        run_dir = run_dir.with_name(run_dir.name + f"-{uuid.uuid4().hex[:4]}")
        start = time.time()
        results = analyze_entries(
            self.clang_path,
            plugin,
            entries,
            run_dir,
            jobs=jobs or self.analysis_jobs,
            timeout=self.analysis_timeout,
            max_loop=self.max_loop,
        )
        reports = collect_reports(run_dir, delete_duplicates=True)
        failed = [r for r in results if not r.ok]
        crashed = [r for r in results if r.crashed]
        summary = {
            "commit": checkout.revision,
            "plugin": str(plugin),
            "files": len(entries),
            "failed": len(failed),
            "crashed": len(crashed),
            "reports": len(reports),
            "seconds": round(time.time() - start, 2),
            "jobs": jobs or self.analysis_jobs,
        }
        (run_dir.parent / f"{run_dir.name}-summary.json").write_text(
            json.dumps(summary, indent=2)
        )
        logger.info(f"Scan {summary}")
        if object_to_analyze:
            result = results[0]
            if result.crashed:
                return -2
            if not result.ok:
                logger.warning(f"Analysis of {object_to_analyze} failed: {result.error[-300:]}")
                return -1
        elif results and len(failed) == len(results):
            logger.error(f"Every analysis failed; first error: {failed[0].error[-300:]}")
            return -999
        if crashed:
            logger.warning(f"Checker crashed on {len(crashed)} file(s), e.g. {crashed[0].source}")
        return len(reports)

    @staticmethod
    def _objects_from_report_compiledb(report: str, target) -> List[str]:
        paths = re.findall(r"File:\| (.+)", report)
        objects = []
        for path in paths:
            relpath = target.relpath_of(path.strip())
            if relpath and relpath.endswith(target.source_extensions):
                objects.append(relpath)
        return objects
