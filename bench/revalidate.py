"""Re-validate every validated attempt of a run with the CURRENT code (no LLM).

Used after a change to the checker-side headers (e.g. roles.h matching macros and
function pointers), which changes every plugin: each attempt's 05_repaired_code.cpp
is rebuilt and validated again on its own commit, and the new strict TP/TN is
compared with the recorded 06_validation.json.

Usage: python bench/revalidate.py RUN_DIR CONFIG OUT_JSON
"""
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from global_config import global_config  # noqa: E402

run_dir, config, out_json = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
global_config.setup(config)
backend, target = global_config.backend, global_config.target

attempts = []
for commit_dir in sorted((run_dir / "results").glob("AllGen-*")):
    sha = commit_dir.name.rsplit("-", 1)[-1]
    for attempt in sorted((commit_dir / "generation").glob("checker_*")):
        if (attempt / "06_validation.json").exists() and (attempt / "05_repaired_code.cpp").exists():
            attempts.append((sha, attempt))
patches = {sha: target.get_patch(sha) for sha in {s for s, _ in attempts}}


def run(item):
    sha, attempt = item
    old = json.loads((attempt / "06_validation.json").read_text())
    details = out_json.parent / f"{out_json.stem}-details" / f"{sha[:8]}-{attempt.name}.json"
    details.parent.mkdir(parents=True, exist_ok=True)
    try:
        tp, tn = backend.validate_checker((attempt / "05_repaired_code.cpp").read_text(), sha,
                                          patches[sha], target, details_out=details)
    except Exception as error:
        tp, tn = None, str(error)[-200:]
    row = {"commit": sha[:8], "attempt": attempt.name, "old_tp": old.get("tp_score"),
           "old_tn": old.get("tn_score"), "old_perfect": old.get("is_perfect"), "tp": tp, "tn": tn,
           "perfect": bool(isinstance(tp, int) and tp > 0 and isinstance(tn, int) and tn > 0)}
    print(json.dumps(row), flush=True)
    return row


with ThreadPoolExecutor(4) as pool:
    rows = list(pool.map(run, attempts))
summary = {
    "run": run_dir.name, "attempts": len(rows),
    "unchanged": sum((r["old_tp"], r["old_tn"]) == (r["tp"], r["tn"]) for r in rows),
    "perfect_before": sum(bool(r["old_perfect"]) for r in rows),
    "perfect_after": sum(r["perfect"] for r in rows),
    "commits_perfect_before": len({r["commit"] for r in rows if r["old_perfect"]}),
    "commits_perfect_after": len({r["commit"] for r in rows if r["perfect"]}),
}
out_json.parent.mkdir(parents=True, exist_ok=True)
out_json.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
print(json.dumps(summary))
