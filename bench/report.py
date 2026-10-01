"""Turn benchmark artifacts into evidence tables (markdown).

Usage:
  python bench/report.py RUN_DIR [RUN_DIR ...] > out.md

Every number is computed from files in the run directories (summary.json,
llm_calls.jsonl, 06_validation_details.json, 07_step_times.json, time.txt), so
the tables can be regenerated and audited.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, median


def peak_rss_mb(run_dir: Path):
    time_txt = run_dir / "time.txt"
    if not time_txt.exists():
        return None
    match = re.search(r"Maximum resident set size \(kbytes\): (\d+)", time_txt.read_text())
    return round(int(match.group(1)) / 1024) if match else None


def llm_stats(run_dir: Path):
    calls = []
    path = run_dir / "results" / "llm_calls.jsonl"
    if path.exists():
        calls = [json.loads(line) for line in path.read_text().splitlines()]
    by_stage = defaultdict(list)
    for call in calls:
        by_stage[call["stage"]].append(call)
    return calls, by_stage


def attempts(run_dir: Path):
    rows = []
    for commit_dir in sorted((run_dir / "results").glob("AllGen-*")):
        for attempt in sorted((commit_dir / "generation").glob("checker_*")):
            row = {"commit": commit_dir.name.split("-")[-1][:10],
                   "type": "-".join(commit_dir.name.split("-")[1:-1]),
                   "attempt": attempt.name}
            details = attempt / "06_validation_details.json"
            if details.exists():
                data = json.loads(details.read_text())
                score = data.get("score") or {}
                row["strict"] = (score.get("tp"), score.get("tn"))
                row["legacy"] = (score.get("legacy_tp"), score.get("legacy_tn"))
                row["error"] = data.get("error")
                row["timing"] = data.get("timing", {})
            steps = attempt / "07_step_times.json"
            if steps.exists():
                row["steps"] = json.loads(steps.read_text())
            rows.append(row)
    return rows


def fmt(value, digits=1):
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def run_table(run_dirs):
    out = ["| Run | Variant | Wall (min) | Commits | Perfect (strict) | LLM calls | Failed calls | "
           "LLM time sum (min) | Repair calls | Peak RSS (MB) |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for run_dir in run_dirs:
        summary = json.loads((run_dir / "summary.json").read_text())
        calls, by_stage = llm_stats(run_dir)
        out.append(
            f"| {run_dir.name} | {summary.get('variant')} | {summary['wall_seconds'] / 60:.1f} | "
            f"{summary['commits']} | {summary['commits_with_perfect_checker']} | {len(calls)} | "
            f"{sum(not c['ok'] for c in calls)} | {sum(c['seconds'] for c in calls) / 60:.1f} | "
            f"{len(by_stage.get('repair_syntax', []))} | {fmt(peak_rss_mb(run_dir))} |"
        )
    return "\n".join(out)


def stage_table(run_dirs):
    stages = ["patch2pattern", "pattern2plan", "plan2checker", "repair_syntax"]
    out = ["| Run | " + " | ".join(f"{s} n / median s / max s" for s in stages) + " |",
           "|---|" + "---|" * len(stages)]
    for run_dir in run_dirs:
        _, by_stage = llm_stats(run_dir)
        cells = []
        for stage in stages:
            ok = [c["seconds"] for c in by_stage.get(stage, []) if c["ok"]]
            cells.append(f"{len(ok)} / {fmt(median(ok)) if ok else '–'} / {fmt(max(ok)) if ok else '–'}")
        out.append(f"| {run_dir.name} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def infra_table(run_dirs):
    out = ["| Run | Validations | Setup s (mean / median) | Analysis s per side (mean) | "
           "Plugin build s (Syntax Repair step, median) |",
           "|---|---|---|---|---|"]
    for run_dir in run_dirs:
        rows = attempts(run_dir)
        setup = [r["timing"]["setup_seconds"] for r in rows if r.get("timing", {}).get("setup_seconds") is not None]
        analysis = [v for r in rows for v in r.get("timing", {}).get("analysis_seconds", {}).values()]
        repair = [r["steps"]["steps"].get("🔧 Syntax Repair") for r in rows if r.get("steps")]
        repair = [v for v in repair if v is not None]
        out.append(
            f"| {run_dir.name} | {len(setup)} | "
            f"{fmt(mean(setup)) if setup else '–'} / {fmt(median(setup)) if setup else '–'} | "
            f"{fmt(mean(analysis), 2) if analysis else '–'} | {fmt(median(repair)) if repair else '–'} |"
        )
    return "\n".join(out)


def scoring_table(run_dirs):
    out = ["| Run | Commit | Type | Attempt | Strict TP/TN | Legacy TP/TN |", "|---|---|---|---|---|---|"]
    counts = defaultdict(int)
    for run_dir in run_dirs:
        for row in attempts(run_dir):
            if "strict" not in row:
                continue
            strict, legacy = row["strict"], row["legacy"]
            if row.get("error"):  # e.g. "checker crash": scored (-2,-2), no TP/TN
                out.append(f"| {run_dir.name} | {row['commit']} | {row['type']} | {row['attempt']} | "
                           f"{row['error']} | {row['error']} |")
                continue
            out.append(f"| {run_dir.name} | {row['commit']} | {row['type']} | {row['attempt']} | "
                       f"{strict[0]}/{strict[1]} | {legacy[0]}/{legacy[1]} |")
            s_ok = (strict[0] or 0) > 0 and (strict[1] or 0) > 0
            l_ok = (legacy[0] or 0) > 0 and (legacy[1] or 0) > 0
            counts[(l_ok, s_ok)] += 1
    out.append("")
    out.append(f"Attempts valid under legacy but not strict: **{counts[(True, False)]}**; "
               f"valid under both: {counts[(True, True)]}; strict-only: {counts[(False, True)]}; "
               f"neither: {counts[(False, False)]}.")
    return "\n".join(out)


def main():
    run_dirs = [Path(p) for p in sys.argv[1:]]
    print("## Runs\n")
    print(run_table(run_dirs))
    print("\n## LLM latency per stage (successful calls)\n")
    print(stage_table(run_dirs))
    print("\n## Infrastructure per operation\n")
    print(infra_table(run_dirs))
    print("\n## Strict vs legacy scoring, per validated attempt\n")
    print(scoring_table(run_dirs))


if __name__ == "__main__":
    main()
