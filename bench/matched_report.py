"""Summarise matched-pair results (bench/matched_pairs.py) per bundle set.

Per set (e.g. r9, r8): bundles x targets, pairs with API-matched candidates, validated
pairs (setup ok), detections (strict TP > 0 on commit^), perfect (TP and TN), and how
often the checker reported anything at all in the patched files (fires) versus was
silent. Old-code -3 results with "no file analyzable" count as not validated.

Usage: python bench/matched_report.py OUT_DIR SET [SET ...]   (e.g. e2e/matched-v1 r9 r8)
"""
import json
import sys
from pathlib import Path

out_dir, sets = Path(sys.argv[1]), sys.argv[2:]
for name in sets:
    entries = []
    for f in sorted((out_dir / name).glob("*.json")):
        if f.name.endswith("-candidates.json"):
            continue
        entries += json.loads(f.read_text())
    stats = {"set": name, "bundle_target_pairs": len(entries), "with_candidates": 0, "validated": 0,
             "setup_skipped": 0, "fires": 0, "detected": 0, "perfect": 0, "detections": []}
    for entry in entries:
        stats["with_candidates"] += entry["api_matched_candidates"] > 0
        for pair in entry["pairs"]:
            details = out_dir / name / f"{entry['target']}-details" / f"{entry['bundle']}__{pair['commit'][:8]}.json"
            info = json.loads(details.read_text()) if details.exists() else {}
            if pair["error"] or pair["tp"] is None or info.get("error") == "no file analyzable":
                stats["setup_skipped"] += 1
                continue
            stats["validated"] += 1
            files = (info.get("score") or {}).get("files") or []
            stats["fires"] += any(f.get("buggy_total", 0) > 0 for f in files)
            if pair["tp"] and pair["tp"] > 0:
                stats["detected"] += 1
                stats["detections"].append(f"{entry['source']}->{entry['target']} {entry['bundle']} "
                                           f"{pair['commit'][:8]} tp={pair['tp']} tn={pair['tn']} "
                                           f"| {pair['subject'][:70]}")
            stats["perfect"] += bool(pair["perfect"])
    print(json.dumps(stats, indent=2))
