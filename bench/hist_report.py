"""Summarise historical replay (bench/historical_replay.py) per bundle set.

For each set: scanned (bundle, target) pairs, pairs that report, functions reported,
hits (functions later changed by a small fix), the hits EXPECTED by chance
(sum over pairs of functions_reported x the target's base rate), and LLM-judged positives.

Usage: python bench/hist_report.py OUT_DIR SET [SET ...]   (e.g. e2e/hist-v1 r9 r8)
"""
import json
import sys
from pathlib import Path

out_dir, sets = Path(sys.argv[1]), sys.argv[2:]
for name in sets:
    rows = {"set": name, "pairs": 0, "scanned": 0, "firing": 0, "functions_reported": 0, "hits": 0,
            "expected_hits": 0.0, "judged_positive": 0, "per_target": {}, "positives": []}
    for f in sorted((out_dir / name).glob("*.json")):
        if f.name.endswith(("-fixes.json", "-base.json")):
            continue
        data = json.loads(f.read_text())
        rate = data["base_rate"]["rate"] or 0
        target = f.stem
        per = rows["per_target"].setdefault(target, {"tag": data["tag"], "base_rate": rate, "functions": 0,
                                                     "hits": 0, "expected": 0.0})
        for entry in data["results"]:
            rows["pairs"] += 1
            if entry.get("status") != "scanned":
                continue
            rows["scanned"] += 1
            n = entry.get("functions_reported") or 0
            rows["firing"] += n > 0
            rows["functions_reported"] += n
            rows["hits"] += entry["hits"]
            rows["expected_hits"] += n * rate
            per["functions"] += n
            per["hits"] += entry["hits"]
            per["expected"] += n * rate
            for p in entry.get("judged_positive", []):
                rows["judged_positive"] += 1
                rows["positives"].append(f"{entry['source']}->{target} {entry['bundle']} {p['file']}:{p['line']} "
                                         f"{p['function']} fixed by {p['commit'][:8]}")
    rows["expected_hits"] = round(rows["expected_hits"], 1)
    for per in rows["per_target"].values():
        per["expected"] = round(per["expected"], 1)
    print(json.dumps(rows, indent=2))
