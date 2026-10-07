"""3.4 (known bugs): do checkers from other projects detect the target's KNOWN bugs?

For each bundle whose source project differs from the target:
  port its roles to the target once (LLM, 3.1-B, at scan_commit), then validate the
  unchanged plugin with the ported roles on every benchmark commit of the target,
  scored exactly like generation (strict TP on commit^, TN on commit).
Complements bench/cross_project.py, which scans the target's HEAD for new bugs.

Usage: python bench/cross_known.py TARGET_CONFIG COMMITS_FILE OUT_JSON BUNDLE_DIR [BUNDLE_DIR ...]
"""
import json
import os
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from global_config import global_config  # noqa: E402

config, commits_file, out_json = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
bundles = [Path(b) for b in sys.argv[4:]]
global_config.setup(config)
from checker_gen import parse_commit_line  # noqa: E402
from model import init_llm  # noqa: E402
from role_porting import port_roles  # noqa: E402

init_llm()
target = (global_config.get("target_options") or {}).get("name")
backend, tgt = global_config.backend, global_config.target
commits = [c for c in map(parse_commit_line, commits_file.read_text().splitlines()) if c]
patches = {sha: tgt.get_patch(sha) for sha, _ in commits}
details_dir = out_json.parent / f"{target}-details"
details_dir.mkdir(parents=True, exist_ok=True)

results = []
for bundle in bundles:
    manifest = yaml.safe_load((bundle / "manifest.yaml").read_text())
    if manifest["source"]["project"] == target or not manifest.get("roles"):
        continue
    entry = {"bundle": bundle.name, "source": manifest["source"]["project"], "target": target,
             "bug_type": manifest.get("bug_type"), "commits": []}
    start = time.monotonic()
    mapping = port_roles(bundle)
    entry["mapping"] = mapping
    entry["roles_mapped"] = sum(1 for names in mapping.values() if names)
    entry["roles_total"] = len(mapping)
    os.environ["KNIGHTER_ROLES"] = str((bundle / "roles" / f"{target}.json").resolve())
    code = (bundle / "checker.cpp").read_text()
    for sha, bug_type in commits:
        details = details_dir / f"{bundle.name}__{sha[:8]}.json"
        try:
            tp, tn = backend.validate_checker(code, sha, patches[sha], tgt, details_out=details)
        except Exception as error:  # setup failures: record, keep going
            tp, tn = None, None
            entry.setdefault("errors", []).append(f"{sha[:8]}: {error}")
        entry["commits"].append({"commit": sha, "bug_type": bug_type, "tp": tp, "tn": tn,
                                 "perfect": bool(tp and tp > 0 and tn and tn > 0)})
    del os.environ["KNIGHTER_ROLES"]
    entry["detected"] = [c["commit"][:8] for c in entry["commits"] if c["tp"] and c["tp"] > 0]
    entry["perfect"] = [c["commit"][:8] for c in entry["commits"] if c["perfect"]]
    entry["seconds"] = round(time.monotonic() - start, 1)
    results.append(entry)
    print(json.dumps({k: entry[k] for k in ("bundle", "source", "target", "roles_mapped", "roles_total",
                                            "detected", "perfect")}), flush=True)
    out_json.write_text(json.dumps(results, indent=2))

out_json.write_text(json.dumps(results, indent=2))
