import ast
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from agent import patch2checker, patch2pattern, pattern2plan, plan2checker
from checker_data import CheckerData
from checker_repair import repair_checker
from global_config import global_config, logger
from targets.compiledb import TargetSetupError
from targets.factory import CompileDBTargetBase
from tools import extract_checker_code

# Ranking scores besides TP/TN: -10 no compilable checker; -20 target setup failed.
SETUP_FAILED = -20


@dataclass
class GenerationProgress:
    """Track progress of checker generation."""

    total_steps: int = 6
    current_step: int = 0
    step_names: List[str] = field(
        default_factory=lambda: [
            "🔍 Pattern Extraction",
            "📋 Plan Generation",
            "💻 Code Generation",
            "🔧 Syntax Repair",
            "✅ Validation",
            "📊 Summary",
        ]
    )
    start_time: datetime = field(default_factory=datetime.now)
    step_times: Dict[str, float] = field(default_factory=dict)

    def start_step(self, step_name: str = None):
        """Start a new step."""
        if step_name is None:
            step_name = self.step_names[self.current_step]

        self.current_step += 1
        progress = (self.current_step / self.total_steps) * 100

        logger.info(f"[{progress:5.1f}%] {step_name}")
        print(f"⏳ [{progress:5.1f}%] {step_name}...")

        self.step_times[step_name] = time.time()
        return step_name

    def complete_step(self, step_name: str, details: str = ""):
        """Complete the current step."""
        if step_name in self.step_times:
            duration = time.time() - self.step_times[step_name]
            self.step_times[step_name] = duration
        else:
            duration = 0

        print(f"✅ {step_name} ({duration:.1f}s)")
        if details:
            print(f"   └── {details}")
        logger.info(f"Completed: {step_name} in {duration:.1f}s - {details}")

    def fail_step(self, step_name: str, error: str):
        """Mark step as failed."""
        if step_name in self.step_times:
            duration = time.time() - self.step_times[step_name]
        else:
            duration = 0

        print(f"❌ {step_name} ({duration:.1f}s)")
        print(f"   └── Error: {error}")
        logger.error(f"Failed: {step_name} in {duration:.1f}s - {error}")

    def get_total_time(self) -> float:
        """Get total elapsed time."""
        return (datetime.now() - self.start_time).total_seconds()

    def new_attempt(self):
        """Restart the step counter for the next checker attempt."""
        self.current_step = 0


def load_ranking(ranking_file: Path) -> List[tuple]:
    """Read ranking.txt: JSON (current) or a Python literal (older runs). Never eval()."""
    text = ranking_file.read_text().strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = ast.literal_eval(text)
    return [tuple(item) for item in data]


def parse_commit_line(line: str):
    """``sha,Type`` -> (sha, type); None for blank/comment lines. Extra fields are ignored."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Expected 'sha,Type', got: {line!r}")
    return parts[0], parts[1]


@dataclass
class GenerationSummary:
    """Summary of checker generation results."""

    commit_id: str
    commit_type: str
    total_checkers: int
    successful_checkers: int
    perfect_checkers: int
    best_tp: int
    best_tn: int
    total_time: float
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "commit_type": self.commit_type,
            "total_checkers": self.total_checkers,
            "successful_checkers": self.successful_checkers,
            "perfect_checkers": self.perfect_checkers,
            "best_tp": self.best_tp,
            "best_tn": self.best_tn,
            "total_time": self.total_time,
            "errors": self.errors,
            "success_rate": self.successful_checkers / max(self.total_checkers, 1),
            "timestamp": datetime.now().isoformat(),
        }

    def print_summary(self):
        """Print a formatted summary."""
        print("\n" + "=" * 60)
        print(f"🎯 GENERATION SUMMARY")
        print("=" * 60)
        print(f"📋 Commit: {self.commit_id} ({self.commit_type})")
        print(f"⏱️  Total Time: {self.total_time:.1f}s")
        print(f"🔢 Checkers Generated: {self.total_checkers}")
        print(f"✅ Successful: {self.successful_checkers}/{self.total_checkers}")
        print(f"🎉 Perfect: {self.perfect_checkers}")
        print(f"🏆 Best Scores: TP={self.best_tp}, TN={self.best_tn}")

        if self.errors:
            print(f"⚠️  Errors: {len(self.errors)}")
            for i, error in enumerate(self.errors[:3], 1):
                print(f"   {i}. {error}")
            if len(self.errors) > 3:
                print(f"   ... and {len(self.errors) - 3} more")

        success_rate = self.successful_checkers / max(self.total_checkers, 1)
        if success_rate >= 0.8:
            print("🌟 Excellent generation rate!")
        elif success_rate >= 0.5:
            print("👍 Good generation rate")
        else:
            print("⚠️  Low generation rate - consider reviewing parameters")
        print("=" * 60)


def gen_checker(
    commit_file="commits.txt",
    result_file=None,
    use_multi=True,
    use_general=False,
    no_utility=False,
    sample_examples=False,
    retry_failed=False,
    workers=None,
):
    """Generate checkers for multiple commits with improved output format.

    Args:
        retry_failed: For commits whose earlier run used up all attempts without
            a perfect checker, generate ``checker_nums`` more attempts instead of
            skipping them.
        workers: Commits processed concurrently (default: config ``gen_workers``, 1).
    """

    workers = int(workers or global_config.get("gen_workers", 1))
    if workers > 1 and global_config.get("plugin_build", "standalone") == "legacy":
        # Legacy builds share one in-tree plugin: concurrent commits would
        # validate each other's checkers.
        logger.warning("plugin_build=legacy: forcing gen workers to 1")
        workers = 1
    if workers > 1 and not isinstance(global_config.target, CompileDBTargetBase):
        # Linux/V8 check out and build in one shared working tree.
        logger.warning(
            f"target {global_config.target._target_type}: forcing gen workers to 1"
        )
        workers = 1

    print("🚀 Starting Checker Generation")
    print(
        f"📁 Config: multi={use_multi}, general={use_general}, utility={not no_utility}, "
        f"workers={workers}, retry_failed={retry_failed}"
    )
    logger.info(f"Starting batch generation with multi={use_multi}, workers={workers}")

    content = Path(commit_file).read_text()
    result_dir = Path(global_config.result_dir)
    result_dir.mkdir(parents=True, exist_ok=True)

    result_content = ""
    if result_file:
        result_content = Path(result_file).read_text()

    # Init example checkers if needed
    if sample_examples:
        print("📚 Initializing example checkers...")
        from checker_example import init_example  # imports torch

        init_example()

    # Setup output files
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_file = result_dir / f"generation_log_{timestamp}.log"
    result_file = result_dir / f"generation_results_{timestamp}.txt"
    summary_file = result_dir / f"generation_summary_{timestamp}.json"

    batch_summary = {
        "start_time": datetime.now().isoformat(),
        "total_commits": 0,
        "successful_commits": 0,
        "workers": workers,
        "results": [],
    }
    stats_lock = threading.Lock()

    jobs = []
    for line_num, line in enumerate(content.splitlines(), 1):
        if result_content and line in result_content:
            done_markers = [",True"] if retry_failed else [",False", ",True"]
            if any(line + marker in result_content for marker in done_markers):
                print(f"⏭️  Skipping {line} (already processed)")
                logger.info(f"Skip {line}")
                continue
        try:
            parsed = parse_commit_line(line)
        except ValueError as e:
            logger.error(f"Line {line_num}: {e}")
            with open(result_file, "a") as fres:
                fres.write(f"{line.strip()},InvalidLine\n")
            continue
        if parsed is not None:
            jobs.append((line_num, *parsed))

    def process(job):
        line_num, commit_id, commit_type = job
        print(f"\n📦 Processing commit {line_num}: {commit_id} ({commit_type})")
        try:
            checker_results, summary = gen_checker_worker(
                commit_id,
                commit_type,
                use_multi=use_multi,
                use_general=use_general,
                no_utility=no_utility,
                sample_examples=sample_examples,
                retry_failed=retry_failed,
            )
            with stats_lock:
                batch_summary["total_commits"] += 1
                with open(log_file, "a") as flog:
                    flog.write(f"{commit_id} {commit_type} {checker_results}\n")
                with open(result_file, "a") as fres:
                    correct = any([TP > 0 and TN > 0 for _, TP, TN in checker_results])
                    fres.write(f"{commit_id},{commit_type},{correct}\n")
                batch_summary["results"].append(summary.to_dict())
                if summary.perfect_checkers > 0:
                    batch_summary["successful_commits"] += 1
                summary.print_summary()

        except Exception as e:
            error_msg = str(e).replace("\n", " ")
            print(f"❌ Error processing {commit_id}: {error_msg}")
            logger.exception(f"Error processing {commit_id}: {e}")
            with stats_lock:
                batch_summary["total_commits"] += 1
                with open(log_file, "a") as flog:
                    flog.write(f"{commit_id} {commit_type} ERROR: {error_msg}\n")
                with open(result_file, "a") as fres:
                    fres.write(f"{commit_id},{commit_type},Exception\n")

    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(process, jobs))
    else:
        for job in jobs:
            process(job)

    # Save batch summary
    batch_summary["end_time"] = datetime.now().isoformat()
    batch_summary["success_rate"] = batch_summary["successful_commits"] / max(
        batch_summary["total_commits"], 1
    )

    with open(summary_file, "w") as f:
        json.dump(batch_summary, f, indent=2)

    print(f"\n🎊 Batch Complete!")
    print(
        f"📊 Success Rate: {batch_summary['successful_commits']}/{batch_summary['total_commits']}"
    )
    print(f"📄 Summary saved to: {summary_file}")


def gen_checker_worker(
    commit_id,
    commit_type,
    use_multi=True,
    use_plan_feedback=False,
    use_general=False,
    no_utility=False,
    sample_examples=False,
    retry_failed=False,
):
    """Generate checkers for one commit with improved progress tracking."""

    progress = GenerationProgress()
    analysis_backend = global_config.backend
    target = global_config.target

    checker_results = []
    checker_data_list: List[CheckerData] = []
    checker_nums = global_config.get("checker_nums")

    id = f"AllGen-{commit_type}-{commit_id}"
    result_dir = Path(global_config.result_dir)

    # Build directory structure
    _build_directory(id)

    # Create organized output structure
    output_dir = result_dir / id
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save metadata
    metadata = {
        "commit_id": commit_id,
        "commit_type": commit_type,
        "generation_config": {
            "use_multi": use_multi,
            "use_general": use_general,
            "no_utility": no_utility,
            "sample_examples": sample_examples,
            "checker_nums": checker_nums,
        },
        "start_time": datetime.now().isoformat(),
    }

    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    patch = target.get_patch(commit_id)
    (output_dir / "commit_id.txt").write_text(commit_id)
    (output_dir / "patch.md").write_text(patch)

    if not target.get_objects_from_patch(patch):
        # No checker can ever be validated on this commit: fail before any LLM call.
        raise ValueError(f"Patch of {commit_id} touches no analyzable source file")
    if isinstance(target, CompileDBTargetBase):
        # Configure commit^ and commit while the LLM stages run.
        target.prefetch(commit_id)

    # Check for existing results
    ranking_file = output_dir / "ranking.txt"
    attempts_end = checker_nums
    if ranking_file.exists():
        checker_results = load_ranking(ranking_file)
        has_perfect = any([TP > 0 and TN > 0 for _, TP, TN in checker_results])
        done = max((i for i, _, _ in checker_results), default=-1) + 1
        if not has_perfect and done >= checker_nums:
            if retry_failed:
                attempts_end = done + checker_nums
                logger.info(
                    f"{id}: {done} attempts without a perfect checker; "
                    f"retrying attempts {done}..{attempts_end - 1}"
                )
            else:
                # Upstream silently regenerated nothing here (range(n, n) is empty).
                print(f"⏭️  {id}: all {done} attempts done, none perfect (use --retry_failed)")
                logger.warning(f"{id}: skipped, {done} attempts without a perfect checker")
        if has_perfect:
            print("🎉 Perfect checker already exists!")
            logger.info(f"Perfect checker found for {id}")

            summary = GenerationSummary(
                commit_id=commit_id,
                commit_type=commit_type,
                total_checkers=len(checker_results),
                successful_checkers=len(
                    [r for r in checker_results if r[1] > 0 or r[2] > 0]
                ),
                perfect_checkers=len(
                    [r for r in checker_results if r[1] > 0 and r[2] > 0]
                ),
                best_tp=max([r[1] for r in checker_results], default=0),
                best_tn=max([r[2] for r in checker_results], default=0),
                total_time=0,
            )
            return checker_results, summary

    # Generate checkers
    errors = []
    first_attempt = max((i for i, _, _ in checker_results), default=-1) + 1
    for i in range(first_attempt, attempts_end):
        print(f"\n🔄 Generating checker {i+1}/{attempts_end} for {commit_id[:12]}")
        progress.new_attempt()

        checker_data = CheckerData(commit_id, commit_type, result_dir, i, patch)

        # Create organized intermediate directory
        intermediate_dir = output_dir / "generation" / f"checker_{i:02d}"
        intermediate_dir.mkdir(parents=True, exist_ok=True)

        try:
            if use_multi:
                # Step 1: Pattern Extraction
                step_name = progress.start_step("🧩 Pattern Extraction")
                pattern = patch2pattern(id, i, patch, use_general=use_general)
                progress.complete_step(step_name, f"Extracted {len(pattern)} chars")

                # Step 2: Plan Generation
                step_name = progress.start_step("📋 Plan Generation")
                plan = pattern2plan(
                    id,
                    i,
                    pattern,
                    patch,
                    no_utility=no_utility,
                    sample_examples=sample_examples,
                )
                refined_plan = plan
                progress.complete_step(
                    step_name, f"Generated {len(plan.splitlines())} line plan"
                )

                # Step 3: Code Generation
                step_name = progress.start_step("💻 Code Generation")
                checker_code = plan2checker(
                    id,
                    i,
                    pattern,
                    refined_plan,
                    patch,
                    no_utility=no_utility,
                    sample_examples=sample_examples,
                )
                progress.complete_step(
                    step_name, f"Generated {len(checker_code.splitlines())} lines"
                )
            else:
                step_name = progress.start_step("💻 Direct Code Generation")
                pattern = ""
                plan = ""
                refined_plan = ""
                checker_code = patch2checker(id, i, patch)
                progress.complete_step(
                    step_name, f"Generated {len(checker_code.splitlines())} lines"
                )

            checker_code = extract_checker_code(checker_code)

            # Update checker data
            checker_data.pattern = pattern
            checker_data.plan = plan
            checker_data.initial_checker_code = checker_code

            # Save intermediate files with clear naming
            (intermediate_dir / "01_pattern.txt").write_text(pattern)
            (intermediate_dir / "02_plan.txt").write_text(plan)
            (intermediate_dir / "03_refined_plan.txt").write_text(refined_plan)
            (intermediate_dir / "04_initial_code.cpp").write_text(checker_code)

            # Step 4: Syntax Repair
            step_name = progress.start_step("🔧 Syntax Repair")
            ret, repaired_checker_code = repair_checker(
                id=id,
                repair_name=f"syntax-repair-{i:02d}",
                max_idx=4,
                intermediate_dir=intermediate_dir,
                checker_code=checker_code,
            )

            if not ret:
                error_msg = f"Failed to generate compilable checker {i}"
                progress.fail_step(step_name, error_msg)
                _dump_step_times(progress, intermediate_dir, failed_step=step_name)
                errors.append(error_msg)
                checker_results.append((i, -10, -10))
                checker_data_list.append(checker_data)
                continue

            progress.complete_step(step_name, "Compilation successful")
            checker_data.repaired_checker_code = repaired_checker_code

            # Save repaired code
            (intermediate_dir / "05_repaired_code.cpp").write_text(
                repaired_checker_code
            )

            # Also save in checkers directory for compatibility
            checkers_dir = output_dir / "checkers"
            checkers_dir.mkdir(parents=True, exist_ok=True)
            (checkers_dir / f"checker_{i:02d}.cpp").write_text(repaired_checker_code)

            # Step 5: Validation
            step_name = progress.start_step("✅ Validation")
            # The backend resolves the plugin built from exactly this code
            # (content-addressed), so a concurrent build cannot be validated here.
            TP, TN = analysis_backend.validate_checker(
                repaired_checker_code,
                commit_id,
                patch,
                target,
                skip_build_checker=True,
                details_out=intermediate_dir / "06_validation_details.json",
            )

            # Update checker data
            checker_data.tp_score = TP
            checker_data.tn_score = TN
            checker_results.append((i, TP, TN))
            checker_data_list.append(checker_data)

            progress.complete_step(step_name, f"TP: {TP}, TN: {TN}")

            # Save validation results
            validation_result = {
                "checker_id": i,
                "tp_score": TP,
                "tn_score": TN,
                "is_perfect": TP > 0 and TN > 0,
                "timestamp": datetime.now().isoformat(),
            }
            (intermediate_dir / "06_validation.json").write_text(
                json.dumps(validation_result, indent=2)
            )
            _dump_step_times(progress, intermediate_dir)

            if TP > 0 and TN > 0:
                print(f"🎉 Perfect checker {i} found!")
                logger.info(f"Perfect checker {i} found: TP={TP}, TN={TN}")
                break
            elif TP == -1 and TN == -1:
                error_msg = f"Failed to evaluate checker {i}"
                errors.append(error_msg)
                logger.error(error_msg)
                break

        except TargetSetupError as e:
            # Infrastructure (checkout/configure) failure: every further attempt
            # would fail identically, so stop instead of spending LLM calls.
            error_msg = f"Target setup failed for {commit_id}: {e}"
            errors.append(error_msg)
            logger.error(error_msg)
            _dump_step_times(progress, intermediate_dir, failed_step="target_setup")
            checker_results.append((i, SETUP_FAILED, SETUP_FAILED))
            break
        except Exception as e:
            error_msg = f"Error generating checker {i}: {str(e)}"
            errors.append(error_msg)
            logger.exception(error_msg)
            _dump_step_times(progress, intermediate_dir, failed_step=f"exception: {e}"[:200])
            checker_results.append((i, -10, -10))
            continue

    # Step 6: Summary Generation
    step_name = progress.start_step("📊 Summary Generation")

    # Save all checker data
    for checker_data in checker_data_list:
        checker_data.dump()
        checker_data.dump_dir()

    # Sort and save results
    checker_results = sorted(checker_results, key=lambda x: (x[1], x[2]), reverse=True)
    ranking_file.write_text(json.dumps(checker_results))

    # Create comprehensive summary
    summary = GenerationSummary(
        commit_id=commit_id,
        commit_type=commit_type,
        total_checkers=len(checker_results),
        successful_checkers=len([r for r in checker_results if r[1] > 0 or r[2] > 0]),
        perfect_checkers=len([r for r in checker_results if r[1] > 0 and r[2] > 0]),
        best_tp=max([r[1] for r in checker_results], default=0),
        best_tn=max([r[2] for r in checker_results], default=0),
        total_time=progress.get_total_time(),
        errors=errors,
    )

    # Save summary
    (output_dir / "summary.json").write_text(json.dumps(summary.to_dict(), indent=2))

    progress.complete_step(
        step_name, f"Generated summary for {len(checker_results)} checkers"
    )

    return checker_results, summary


def _dump_step_times(progress: GenerationProgress, intermediate_dir: Path, failed_step=None):
    """Save this attempt's step durations (seconds) for speed analysis."""
    now = time.time()
    times = {}
    for name, value in progress.step_times.items():
        # Completed steps hold a duration; a step still running holds its start time.
        times[name] = round(now - value if value > 1e9 else value, 2)
    (intermediate_dir / "07_step_times.json").write_text(
        json.dumps({"steps": times, "failed_step": failed_step}, indent=2)
    )
    progress.step_times.clear()


def _build_directory(id: str):
    """Build the directory structure for the result."""
    basedir = Path(global_config.result_dir) / id
    basedir.mkdir(parents=True, exist_ok=True)

    # Create organized subdirectories
    subdirs = [
        "generation",  # Individual checker generation steps
        "checkers",  # Final checker files
        "build_logs",  # Compilation logs
        "prompt_history",  # LLM interaction history
        "validation",  # Validation results
    ]

    for subdir in subdirs:
        (basedir / subdir).mkdir(parents=True, exist_ok=True)
