"""Positive control for 3.1-B porting: port a bundle's roles back to its OWN project
and check the checker still detects its original bug.

For each bundle from the configured (source) project:
  1. scan the patched files at commit^ with the original roles  -> reports_original
  2. port_roles to the same project from scratch (LLM, out_name "<project>-selfport")
  3. scan the same files at commit^ with the ported roles        -> reports_ported
Detection is preserved when the ported roles still yield >= 1 on-target report
wherever the original roles did.

Usage: python bench/self_port.py CONFIG OUT_JSON BUNDLE_DIR [BUNDLE_DIR ...]
"""
import json
import os
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from global_config import global_config  # noqa: E402

config, out_json, bundles = sys.argv[1], Path(sys.argv[2]), [Path(b) for b in sys.argv[3:]]
global_config.setup(config)
from backends.direct_analysis import collect_reports  # noqa: E402
from model import init_llm  # noqa: E402
from role_porting import port_roles  # noqa: E402

init_llm()
project = (global_config.get("target_options") or {}).get("name")
backend, target = global_config.backend, global_config.target
results = []
for bundle in bundles:
    manifest = yaml.safe_load((bundle / "manifest.yaml").read_text())
    if manifest["source"]["project"] != project:
        continue
    commit = manifest["source"]["commit"]
    patch = (bundle / "patch.md").read_text() if (bundle / "patch.md").exists() else ""
    files = target.get_objects_from_patch(patch)
    code = (bundle / "checker.cpp").read_text()
    entry = {"bundle": bundle.name, "commit": commit, "files": files}
    port_roles(bundle, commit=commit + "^", out_name=f"{project}-selfport")
    for label, roles_file in (("original", bundle / "roles" / f"{project}.json"),
                              ("ported", bundle / "roles" / f"{project}-selfport.json")):
        os.environ["KNIGHTER_ROLES"] = str(roles_file.resolve())
        count, on_files = 0, []
        for f in files:
            out = Path(out_json).parent / "selfport" / bundle.name / label / re.sub(r"\W", "_", f)
            n = backend.run_checker(code, commit + "^", target, object_to_analyze=f, output_dir=str(out))
            count += max(n, 0)
            on_files += [(f, r.line, r.function) for r in collect_reports(out)]
        del os.environ["KNIGHTER_ROLES"]
        entry[f"reports_{label}"] = count
        entry[f"locations_{label}"] = on_files
    entry["mapping_original"] = json.loads((bundle / "roles" / f"{project}.json").read_text())
    entry["mapping_ported"] = json.loads((bundle / "roles" / f"{project}-selfport.json").read_text())
    entry["preserved"] = entry["reports_original"] == 0 or entry["reports_ported"] > 0
    results.append(entry)
    print(json.dumps({k: entry[k] for k in ("bundle", "reports_original", "reports_ported", "preserved")}), flush=True)
out_json.parent.mkdir(parents=True, exist_ok=True)
out_json.write_text(json.dumps(results, indent=2))
