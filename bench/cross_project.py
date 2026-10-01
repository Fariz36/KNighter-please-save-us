"""3.4: run portable checkers from other projects on one target project.

Usage: python bench/cross_project.py TARGET_CONFIG OUT_DIR BUNDLE_DIR [BUNDLE_DIR ...]
For each bundle whose source project differs from the target:
  port its roles to the target (LLM, 3.1-B) -> scan the target at scan_commit with
  the ported roles -> triage up to N reports (LLM). Writes OUT_DIR/<target>.json.
"""
import json
import os
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from global_config import global_config  # noqa: E402

config, out_dir, bundles = sys.argv[1], Path(sys.argv[2]), [Path(b) for b in sys.argv[3:]]
global_config.setup(config)

from agent import check_report  # noqa: E402
from backends.direct_analysis import collect_reports  # noqa: E402
from model import init_llm  # noqa: E402
from role_porting import port_roles  # noqa: E402

init_llm()
target = (global_config.get("target_options") or {}).get("name")
backend, tgt = global_config.backend, global_config.target
max_triage = int(os.environ.get("CROSS_MAX_TRIAGE", "5"))
results = []
for bundle in bundles:
    manifest = yaml.safe_load((bundle / "manifest.yaml").read_text())
    if manifest["source"]["project"] == target or not manifest.get("roles"):
        continue
    entry = {"bundle": bundle.name, "source": manifest["source"]["project"], "target": target}
    start = time.monotonic()
    mapping = port_roles(bundle)
    entry["mapping"] = mapping
    entry["unmapped_roles"] = [r for r, names in mapping.items() if not names]
    if all(not names for names in mapping.values()):
        entry["status"] = "no equivalent roles in target"
        results.append(entry)
        continue
    os.environ["KNIGHTER_ROLES"] = str((bundle / "roles" / f"{target}.json").resolve())
    scan_dir = out_dir / target / bundle.name
    count = backend.run_checker((bundle / "checker.cpp").read_text(), global_config.scan_commit, tgt,
                                output_dir=str(scan_dir))
    del os.environ["KNIGHTER_ROLES"]
    entry["reports"] = count
    verdicts = []
    patch = (bundle / "patch.md").read_text() if (bundle / "patch.md").exists() else ""
    for report in collect_reports(scan_dir)[:max_triage]:
        md = f"File: {tgt.relpath_of(report.file)}:{report.line} in {report.function}\n\n{report.description}\n\n"
        md += Path(report.html_path).read_text(errors="replace")[:20000]
        answer = check_report(f"cross-{target}-{bundle.name}", 0, report.issue_hash or "r", md,
                              manifest.get("pattern", ""), patch)
        verdicts.append({"file": tgt.relpath_of(report.file), "line": report.line,
                         "function": report.function, "description": report.description,
                         "verdict": "NotABug" if "NotABug" in (answer or "") else "Bug"})
    entry["triage"] = verdicts
    entry["status"] = "scanned"
    entry["seconds"] = round(time.monotonic() - start, 1)
    results.append(entry)
    print(json.dumps({k: entry[k] for k in ("bundle", "source", "target", "status", "reports")
                      if k in entry}), flush=True)

out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / f"{target}.json").write_text(json.dumps(results, indent=2))
