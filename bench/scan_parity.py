"""1.4 evidence: a parallel whole-project scan finds exactly the reports of a serial one.

Usage: python bench/scan_parity.py CONFIG CHECKER.cpp OUT_DIR
Runs the checker over the configured scan_commit with jobs=1, then jobs=8.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from backends.direct_analysis import collect_reports  # noqa: E402
from global_config import global_config  # noqa: E402

config, checker, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
global_config.setup(config)
backend, target = global_config.backend, global_config.target
code = checker.read_text()
backend.plugin_for(code)                      # build outside the timed region
target.prepare(global_config.scan_commit)     # configure outside the timed region

results = {}
for jobs in (1, 8):
    run_dir = out / f"jobs{jobs}"
    start = time.monotonic()
    count = backend.run_checker(code, global_config.scan_commit, target, jobs=jobs,
                                output_dir=str(run_dir))
    seconds = time.monotonic() - start
    reports = {(target.relpath_of(r.file), r.line, r.issue_hash) for r in collect_reports(run_dir)}
    results[jobs] = {"count": count, "seconds": round(seconds, 1), "reports": sorted(map(list, reports))}
summary = {
    "checker": str(checker), "commit": global_config.scan_commit,
    "serial": {k: v for k, v in results[1].items() if k != "reports"},
    "parallel": {k: v for k, v in results[8].items() if k != "reports"},
    "identical_report_sets": results[1]["reports"] == results[8]["reports"],
    "speedup": round(results[1]["seconds"] / results[8]["seconds"], 2),
    "reports": results[8]["reports"],
}
(out / "parity.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({k: v for k, v in summary.items() if k != "reports"}, indent=2))
