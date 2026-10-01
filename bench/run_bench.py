"""Run one benchmark variant of `gen` and summarize it.

Usage:
  python bench/run_bench.py RUN_NAME BASE_CONFIG COMMIT_FILE VARIANT [key=value ...]

VARIANT is "baseline" or "optimized" (see VARIANTS). Every run gets a fresh
result dir and a fresh (cold) target work dir under bench/runs/RUN_NAME/, so
runs never share cached revisions or plugins.

Output: bench/runs/RUN_NAME/{config.yaml, gen.log, time.txt, summary.json}
"""

import json
import os
import subprocess as sp
import sys
import time
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PYTHON = str(Path(__file__).resolve().parent.parent / ".venv" / "bin" / "python")
# The code that runs: a frozen snapshot (see bench/run_all.sh) so that editing
# the working tree during a multi-hour benchmark cannot change later runs.
CODE_ROOT = Path(os.environ.get("KNIGHTER_CODE_ROOT", ROOT)).resolve()

# Only infrastructure differs between variants; LLM settings and scoring are
# identical so wall-time differences are attributable to the pipeline.
VARIANTS = {
    # Upstream-equivalent behaviour on the generic target.
    "baseline": {
        # Upstream build cost: same compile+link commands at the original -O3,
        # no PCH, rebuilt on every request. (The in-tree `make SAGenTestPlugin`
        # itself is unusable here: the shared LLVM tree is stale and make would
        # rebuild 1068 LLVM objects; see docs/RESEARCH_LOG.md.)
        "plugin_build": "standalone",
        "plugin_opt_level": "-O3",
        "plugin_pch": False,
        "plugin_cache": False,
        "gen_workers": 1,  # upstream gen is sequential
        "analysis_jobs": 1,  # previous attempt's CMake path analyzed serially
        "target_options": {"reuse_revisions": False},  # configure on every checkout
    },
    "optimized": {
        "plugin_build": "standalone",
        "gen_workers": 4,
        "analysis_jobs": 8,
        "target_options": {"reuse_revisions": True},
    },
}


def merge(base, overlay):
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = value
    return out


def parse_value(text):
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return text


def summarize(run_dir: Path, result_dir: Path, wall: float) -> dict:
    llm = defaultdict(lambda: {"calls": 0, "failed": 0, "seconds": 0.0,
                               "prompt_tokens": 0, "completion_tokens": 0,
                               "reasoning_tokens": 0})
    calls_file = result_dir / "llm_calls.jsonl"
    if calls_file.exists():
        for line in calls_file.read_text().splitlines():
            call = json.loads(line)
            stage = llm[call["stage"]]
            stage["calls"] += 1
            stage["failed"] += 0 if call["ok"] else 1
            stage["seconds"] += call.get("seconds", 0)
            for key in ("prompt_tokens", "completion_tokens", "reasoning_tokens"):
                stage[key] += call.get(key) or 0

    commits = []
    step_totals = defaultdict(float)
    validation = defaultdict(list)
    for commit_dir in sorted(result_dir.glob("AllGen-*")):
        summary_file = commit_dir / "summary.json"
        summary = json.loads(summary_file.read_text()) if summary_file.exists() else None
        attempts = []
        for attempt in sorted((commit_dir / "generation").glob("checker_*")):
            info = {"attempt": attempt.name}
            steps = attempt / "07_step_times.json"
            if steps.exists():
                data = json.loads(steps.read_text())
                info["steps"] = data["steps"]
                info["failed_step"] = data["failed_step"]
                for name, sec in data["steps"].items():
                    step_totals[name] += sec
            details = attempt / "06_validation_details.json"
            if details.exists():
                data = json.loads(details.read_text())
                score = data.get("score", {})
                info["strict"] = [score.get("tp"), score.get("tn")]
                info["legacy"] = [score.get("legacy_tp"), score.get("legacy_tn")]
                info["error"] = data.get("error")
                timing = data.get("timing", {})
                info["validation_timing"] = timing
                for key in ("plugin_seconds", "setup_seconds", "total_seconds"):
                    if key in timing:
                        validation[key].append(timing[key])
            attempts.append(info)
        commits.append({
            "id": commit_dir.name,
            "summary": summary,
            "attempts": attempts,
        })

    perfect = sum(1 for c in commits if c["summary"] and c["summary"]["perfect_checkers"] > 0)
    llm_seconds = sum(s["seconds"] for s in llm.values())
    return {
        "run": run_dir.name,
        "wall_seconds": round(wall, 1),
        "commits": len(commits),
        "commits_with_perfect_checker": perfect,
        "llm_calls_total": sum(s["calls"] for s in llm.values()),
        "llm_seconds_sum": round(llm_seconds, 1),
        "llm_by_stage": {k: {**v, "seconds": round(v["seconds"], 1)} for k, v in llm.items()},
        "step_seconds_sum": {k: round(v, 1) for k, v in step_totals.items()},
        "validation_seconds": {
            k: {"n": len(v), "sum": round(sum(v), 1), "mean": round(sum(v) / len(v), 2)}
            for k, v in validation.items() if v
        },
        "per_commit": commits,
    }


def main():
    run_name, base_config, commit_file, variant, *overrides = sys.argv[1:]
    run_dir = ROOT / "bench" / "runs" / run_name
    if run_dir.exists():
        sys.exit(f"{run_dir} exists; pick a new run name (runs are never overwritten)")
    run_dir.mkdir(parents=True)

    config = yaml.safe_load((ROOT / base_config).read_text())
    config = merge(config, VARIANTS[variant])
    for item in overrides:
        key, value = item.split("=", 1)
        config[key] = parse_value(value)
    result_dir = run_dir / "results"
    config["result_dir"] = str(result_dir)
    config["plugin_cache_dir"] = str(run_dir / "plugin-cache")
    config.setdefault("target_options", {})["work_dir"] = str(run_dir / "work")
    config_path = run_dir / "config.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    (run_dir / "commits.txt").write_text((ROOT / commit_file).read_text())

    cmd = [
        "/usr/bin/time", "-v", "-o", str(run_dir / "time.txt"),
        PYTHON, "src/main.py", "gen",
        f"--config_file={config_path}",
        f"--commit_file={run_dir / 'commits.txt'}",
    ]
    (run_dir / "command.txt").write_text(" ".join(cmd) + "\n")
    start = time.time()
    start_mono = time.monotonic()  # does not advance while the machine is suspended
    (run_dir / "code_root.txt").write_text(str(CODE_ROOT) + "\n")
    with open(run_dir / "gen.log", "w") as log:
        proc = sp.run(cmd, cwd=CODE_ROOT, stdout=log, stderr=sp.STDOUT,
                      env={**os.environ, "PYTHONUNBUFFERED": "1"})
    wall = time.time() - start
    awake = time.monotonic() - start_mono

    summary = summarize(run_dir, result_dir, wall)
    # A laptop suspend inflates wall time (r6-A-lua: +5.6 h). Flag such runs.
    summary["awake_seconds"] = round(awake, 1)
    summary["suspended_seconds"] = round(wall - awake, 1)
    summary["suspended"] = wall - awake > 60
    summary["variant"] = variant
    summary["exit_code"] = proc.returncode
    summary["overrides"] = overrides
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in (
        "run", "variant", "exit_code", "wall_seconds", "suspended_seconds", "commits",
        "commits_with_perfect_checker", "llm_calls_total", "llm_seconds_sum",
        "step_seconds_sum", "validation_seconds")}, indent=2))


if __name__ == "__main__":
    main()
