"""0.2 audit: every validation used the plugin compiled from exactly the scored checker.

For each attempt with 06_validation_details.json, the recorded plugin's directory
holds the checker.cpp it was built from; it must equal 05_repaired_code.cpp.
Usage: python bench/audit_plugins.py bench/runs/r7-*
"""
import json
import sys
from pathlib import Path

total = match = mismatch = missing = 0
for run in map(Path, sys.argv[1:]):
    for details in sorted(run.glob("results/AllGen-*/generation/checker_*/06_validation_details.json")):
        data = json.loads(details.read_text())
        plugin = data.get("plugin")
        repaired = details.parent / "05_repaired_code.cpp"
        if not plugin or not repaired.exists():
            continue
        total += 1
        built_from = Path(plugin).parent / "checker.cpp"
        if not built_from.exists():
            missing += 1
        elif built_from.read_text() == repaired.read_text():
            match += 1
        else:
            mismatch += 1
            print("MISMATCH", details)
print(json.dumps({"validations": total, "exact_match": match, "mismatch": mismatch,
                  "plugin_source_missing": missing}))
