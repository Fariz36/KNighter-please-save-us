"""Per-project A/B table and totals for a benchmark tag (e.g. r7).

Usage: python bench/aggregate.py r7 > out.md
Numbers come only from bench/runs/<tag>-{A,B}-<project>/ artifacts.
"""

import json
import sys
from pathlib import Path

RUNS = Path(__file__).resolve().parent / "runs"
PROJECTS = ["lua", "re2", "yaml-cpp", "libxml2", "sqlite", "curl", "libgit2"]


def load(tag, variant, project):
    d = RUNS / f"{tag}-{variant}-{project}"
    s = d / "summary.json"
    if not s.exists():
        return None
    data = json.loads(s.read_text())
    calls = [json.loads(l) for l in (d / "results" / "llm_calls.jsonl").read_text().splitlines()]
    data["_calls"] = calls
    data["_repair"] = sum(c["stage"] == "repair_syntax" for c in calls)
    data["_failed"] = sum(not c["ok"] for c in calls)
    data["_llm_s"] = sum(c["seconds"] for c in calls)
    data["_tokens"] = sum((c.get("prompt_tokens") or 0) + (c.get("completion_tokens") or 0) for c in calls)
    return data


def main():
    tag = sys.argv[1]
    rows, tot = [], {"A": [0, 0, 0, 0, 0, 0.0], "B": [0, 0, 0, 0, 0, 0.0]}
    print("| Project | Commits | Wall A (min) | Wall B (min) | Speedup | Perfect A | Perfect B | "
          "LLM calls A / B | Repair calls A / B | Suspended (s) A / B |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for p in PROJECTS:
        a, b = load(tag, "A", p), load(tag, "B", p)
        if not a or not b:
            print(f"| {p} | – | {'done' if a else 'pending'} | {'done' if b else 'pending'} | | | | | | |")
            continue
        speed = a["wall_seconds"] / b["wall_seconds"]
        print(f"| {p} | {a['commits']} | {a['wall_seconds']/60:.1f} | {b['wall_seconds']/60:.1f} | "
              f"{speed:.1f}× | {a['commits_with_perfect_checker']}/{a['commits']} | "
              f"{b['commits_with_perfect_checker']}/{b['commits']} | {len(a['_calls'])} / {len(b['_calls'])} | "
              f"{a['_repair']} / {b['_repair']} | {a.get('suspended_seconds')} / {b.get('suspended_seconds')} |")
        for v, d in (("A", a), ("B", b)):
            t = tot[v]
            t[0] += d["wall_seconds"]; t[1] += d["commits_with_perfect_checker"]; t[2] += d["commits"]
            t[3] += len(d["_calls"]); t[4] += d["_repair"]; t[5] += d["_llm_s"]
    a, b = tot["A"], tot["B"]
    if a[0] and b[0]:
        print(f"| **total** | {a[2]} | {a[0]/60:.1f} | {b[0]/60:.1f} | **{a[0]/b[0]:.1f}×** | "
              f"{a[1]}/{a[2]} | {b[1]}/{b[2]} | {a[3]} / {b[3]} | {a[4]} / {b[4]} | |")
        print(f"\nSummed LLM time: A {a[5]/60:.1f} min, B {b[5]/60:.1f} min (B overlaps calls across 4 workers).")


if __name__ == "__main__":
    main()
