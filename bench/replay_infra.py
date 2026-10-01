"""Deterministic infrastructure benchmark: same checkers, same commits, two pipelines.

For every (commit, checker) pair this does what gen does after the LLM stages:
one explicit plugin build (the successful syntax-repair compile) followed by
validation on commit^ and commit. LLM time is excluded by construction, so the
difference between modes is purely build/setup/analysis cost.

Usage:
  python bench/replay_infra.py RUN_NAME BASE_CONFIG PAIRS_FILE MODE

PAIRS_FILE lines: <commit_sha> <path/to/checker.cpp>
MODE: baseline | optimized   (same settings as bench/run_bench.py VARIANTS)
Output: bench/replay/RUN_NAME/{config.yaml, results.jsonl, summary.json}
"""

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "bench"))

from run_bench import VARIANTS, merge  # noqa: E402


def main():
    run_name, base_config, pairs_file, mode = sys.argv[1:5]
    run_dir = ROOT / "bench" / "replay" / run_name
    if run_dir.exists():
        sys.exit(f"{run_dir} exists; runs are never overwritten")
    run_dir.mkdir(parents=True)

    config = merge(yaml.safe_load((ROOT / base_config).read_text()), VARIANTS[mode])
    config["result_dir"] = str(run_dir / "results")
    config["plugin_cache_dir"] = str(run_dir / "plugin-cache")
    config["target_options"]["work_dir"] = str(run_dir / "work")
    config_path = run_dir / "config.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))

    from global_config import global_config

    global_config.setup(str(config_path))
    target, backend = global_config.target, global_config.backend
    workers = int(config.get("gen_workers", 1))

    pairs = []
    for line in (ROOT / pairs_file).read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            commit, checker = line.split()
            pairs.append((commit, Path(checker)))
    patches = {commit: target.get_patch(commit) for commit, _ in pairs}

    def run(index_pair):
        index, (commit, checker) = index_pair
        code = checker.read_text()
        t0 = time.time()
        rc, _ = backend.build_checker(code, run_dir / "build_logs" / str(index))
        build = time.time() - t0
        t1 = time.time()
        details = run_dir / "details" / f"{index}.json"
        tp, tn = backend.validate_checker(code, commit, patches[commit], target,
                                          skip_build_checker=True, details_out=details)
        validate = time.time() - t1
        timing = json.loads(details.read_text()).get("timing", {}) if details.exists() else {}
        return {"index": index, "commit": commit, "checker": str(checker), "build_rc": rc,
                "build_seconds": round(build, 2), "validate_seconds": round(validate, 2),
                "tp": tp, "tn": tn, "validation_timing": timing}

    start = time.time()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run, enumerate(pairs)))
    wall = time.time() - start

    with open(run_dir / "results.jsonl", "w") as handle:
        for item in results:
            handle.write(json.dumps(item) + "\n")
    summary = {
        "run": run_name, "mode": mode, "pairs": len(pairs), "workers": workers,
        "wall_seconds": round(wall, 1),
        "build_seconds_sum": round(sum(r["build_seconds"] for r in results), 1),
        "validate_seconds_sum": round(sum(r["validate_seconds"] for r in results), 1),
        "scores": [(r["commit"][:10], r["tp"], r["tn"]) for r in results],
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
