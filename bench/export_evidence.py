"""Copy the small, auditable artifacts behind every reported number into bench/evidence/.

bench/runs, bench/replay and e2e/ hold gigabytes (worktrees, builds, report
HTML) and are not committed; this keeps the JSON/text files the report cites.

Usage: python bench/export_evidence.py
"""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "bench" / "evidence"

SECTION3_DIRS = {"selfport-r8", "selfport-r8-v1", "cross", "cross-v1", "cross-v3", "cross-known-r8",
                 "matched-v1", "revalidate", "compiled-out", "lua-len-recheck"}
RUN_FILES = ["summary.json", "time.txt", "config.yaml", "commits.txt", "code_root.txt",
             "results/llm_calls.jsonl", "results/generation_results_*.txt",
             "results/generation_summary_*.json"]
ATTEMPT_FILES = ["06_validation.json", "06_validation_details.json", "07_step_times.json",
                 "08_roles.json", "01_pattern.txt", "05_repaired_code.cpp"]


def copy(src: Path, dst: Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def export_run(run: Path, dst: Path):
    for pattern in RUN_FILES:
        for f in run.glob(pattern):
            copy(f, dst / f.relative_to(run))
    for commit_dir in sorted((run / "results").glob("AllGen-*")):
        rel = commit_dir.relative_to(run)
        for name in ("summary.json", "ranking.txt", "metadata.json"):
            if (commit_dir / name).exists():
                copy(commit_dir / name, dst / rel / name)
        for attempt in sorted((commit_dir / "generation").glob("checker_*")):
            for name in ATTEMPT_FILES:
                if (attempt / name).exists():
                    copy(attempt / name, dst / attempt.relative_to(run) / name)


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    runs = sorted(p for p in (ROOT / "bench" / "runs").iterdir()
                  if p.is_dir() and (p / "summary.json").exists() and p.name.startswith(("r5-", "r7-", "r8-", "r9-", "smoke-02")))
    for run in runs:
        export_run(run, OUT / "runs" / run.name)
    for replay in sorted((ROOT / "bench" / "replay").glob("*")):
        for name in ("summary.json", "results.jsonl", "config.yaml"):
            if (replay / name).exists():
                copy(replay / name, OUT / "replay" / replay.name / name)
        for f in sorted((replay / "details").glob("*.json")):
            copy(f, OUT / "replay" / replay.name / "details" / f.name)
    for f in sorted((ROOT / "bench").glob("precheck*.jsonl")):
        copy(f, OUT / "precheck" / f.name)
    e2e = ROOT / "e2e"
    if e2e.exists():
        for f in sorted(e2e.rglob("*")):
            if not f.is_file():
                continue
            rel = f.relative_to(e2e)
            # Section 3 experiments keep their result JSON (small; HTML reports and worktrees are not kept).
            section3 = rel.parts[0] in SECTION3_DIRS and f.suffix in (".json", ".jsonl") \
                and not f.name.endswith("-candidates.json")
            # Exported bundles: manifest, roles/ports JSON and checker source, not plugin.so.
            section3 = section3 or (rel.parts[0] in ("bundles-r8h2", "bundles-r9h2")
                                    and (f.suffix == ".json" or f.name in ("checker.cpp", "patch.md")))
            keep = (f.suffix in (".log", ".yaml", ".csv", ".txt", ".patch")
                    or f.name in ("parity.json", "scan_summary.json", "summary.json", "ranking.txt")
                    or f.name.endswith(("-summary.json", "_metadata.yaml")) or section3)
            if keep and "prompt_history" not in rel.parts and f.stat().st_size < 2_000_000:
                copy(f, OUT / "e2e" / rel)
    size = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file())
    print(f"evidence: {sum(1 for _ in OUT.rglob('*') if _.is_file())} files, {size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
