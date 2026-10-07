"""Section 3.1 metrics for role-based runs (e.g. r8 vs r9).

Per run: commits with a perfect checker, attempts, hardcoded identifiers left in
the checker logic (lint), roles per attempt, share of roles from the standard
vocabulary, and share of role names that are callable (called as `name(` or
defined as a macro at the buggy revision) rather than variables, fields, types
or constants (which no other project has).

Usage: python bench/role_stats.py RUN_TAG [RUN_TAG ...]    (e.g. r8 r9)
"""
import json
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from checker_lint import standard_names  # noqa: E402

VOCABULARY = {
    "allocator", "deallocator", "reallocator", "duplicator", "null_on_failure", "error_setter",
    "aborting_assert", "length_of", "buffer_copy", "bounded_copy", "lock", "unlock", "ref_get",
    "ref_put", "init", "cleanup", "container_insert", "container_remove", "parser_input",
    "untrusted_size",
}
STDLIB = standard_names()


@lru_cache(maxsize=None)
def is_callable(repo: str, revision: str, name: str) -> bool:
    if name in STDLIB:
        return True
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return False
    pattern = rf"(\b{name}\s*\(|#\s*define\s+{name}\b)"
    result = subprocess.run(["git", "-C", repo, "grep", "-q", "-E", pattern, revision, "--"],
                            capture_output=True)
    return result.returncode == 0


def run_stats(run: Path):
    config = yaml.safe_load((run / "config.yaml").read_text())
    repo = config["target_options"]["repo_dir"]
    stats = {"run": run.name, "commits": 0, "perfect_commits": 0, "attempts": 0, "role_attempts": 0,
             "hardcoded_attempts": 0, "roles": 0, "vocabulary_roles": 0, "names": 0,
             "callable_names": 0, "non_callable_examples": []}
    for commit_dir in sorted((run / "results").glob("AllGen-*")):
        sha = commit_dir.name.rsplit("-", 1)[-1]
        stats["commits"] += 1
        perfect = False
        for attempt in sorted((commit_dir / "generation").glob("checker_*")):
            validation = attempt / "06_validation.json"
            if validation.exists():
                perfect |= bool(json.loads(validation.read_text()).get("is_perfect"))
            roles_file = attempt / "08_roles.json"
            if not roles_file.exists():
                continue
            stats["attempts"] += 1
            record = json.loads(roles_file.read_text())
            stats["hardcoded_attempts"] += bool(record.get("final_findings"))
            roles = record.get("roles") or {}
            if not roles:
                continue
            stats["role_attempts"] += 1
            for role, value in roles.items():
                stats["roles"] += 1
                stats["vocabulary_roles"] += role in VOCABULARY
                for name in value.get("names", []):
                    stats["names"] += 1
                    if is_callable(repo, f"{sha}^", name):
                        stats["callable_names"] += 1
                    elif len(stats["non_callable_examples"]) < 12:
                        stats["non_callable_examples"].append(f"{role}={name}")
        stats["perfect_commits"] += perfect
    for key, total in (("vocabulary_roles", "roles"), ("callable_names", "names")):
        stats[f"{key}_pct"] = round(100 * stats[key] / stats[total], 1) if stats[total] else None
    stats["roles_per_attempt"] = round(stats["roles"] / stats["role_attempts"], 2) if stats["role_attempts"] else None
    return stats


def main():
    rows = []
    for tag in sys.argv[1:]:
        for run in sorted((ROOT / "bench" / "runs").glob(f"{tag}-*")):
            if (run / "config.yaml").exists():
                rows.append(run_stats(run))
    total = {}
    for row in rows:
        print(json.dumps(row))
        tag = row["run"].split("-")[0]
        agg = total.setdefault(tag, {})
        for key, value in row.items():
            if isinstance(value, int):
                agg[key] = agg.get(key, 0) + value
    for tag, agg in total.items():
        agg["vocabulary_roles_pct"] = round(100 * agg["vocabulary_roles"] / max(agg["roles"], 1), 1)
        agg["callable_names_pct"] = round(100 * agg["callable_names"] / max(agg["names"], 1), 1)
        agg["roles_per_attempt"] = round(agg["roles"] / max(agg["role_attempts"], 1), 2)
        print(json.dumps({"total": tag, **agg}))


if __name__ == "__main__":
    main()
