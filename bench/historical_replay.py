"""3.4 historical replay: do ported checkers report bugs that the target fixed LATER?

Ground truth without a hand-built benchmark:
  * old release T of target Q: the latest tag that is an ancestor of HEAD and is at least
    HIST_MONTHS (default 12) months older than HEAD (override: HIST_TAG);
  * later fixes: non-merge commits in T..HEAD whose subject has bug keywords, that change only
    source files (tests/docs/headers aside) and at most HIST_MAX_LINES (40) source lines; for each, the functions it changes on its old side (strict-scoring regions);
  * scan Q at T (whole scan scope) with every foreign bundle, roles ported at T (one LLM call);
  * a report is a HIT when its (file, function) was later changed by such a fix;
  * BASE RATE: share of all functions in the scanned files that were later changed by a fix,
    i.e. the hit rate of a checker reporting in random functions;
  * each hit is judged by the LLM with the report and the fix's diff ("does this later commit
    fix the reported problem?"); every positive verdict is then checked by hand.

Usage: python bench/historical_replay.py TARGET_CONFIG OUT_DIR BUNDLE_DIR [BUNDLE_DIR ...]
Env: HIST_TAG, HIST_MONTHS (12), HIST_MAX_JUDGE (10 hits judged per bundle).
"""
import datetime as dt
import json
import os
import re
import subprocess as sp
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "bench"))
from global_config import global_config  # noqa: E402

config, out_dir = sys.argv[1], Path(sys.argv[2])
bundles = [Path(b) for b in sys.argv[3:]]
global_config.setup(config)
from backends.direct_analysis import collect_reports  # noqa: E402
from mine_commits import BUG_WORDS, guess_type  # noqa: E402
from model import init_llm, invoke_llm  # noqa: E402
from role_porting import port_roles  # noqa: E402
from tools import extract_json_block  # noqa: E402
from validation_scoring import function_ranges, parse_diff, region_for  # noqa: E402

options = global_config.get("target_options") or {}
name, repo = options["name"], options["repo_dir"]
extensions = tuple(options.get("source_extensions") or [".c"])
backend, tgt = global_config.backend, global_config.target
MAX_JUDGE = int(os.environ.get("HIST_MAX_JUDGE", "10"))
MAX_LINES = int(os.environ.get("HIST_MAX_LINES", "40"))
out_dir.mkdir(parents=True, exist_ok=True)


def git(*args, check=True):
    return sp.run(["git", "-C", repo, *args], capture_output=True, text=True, check=check).stdout


def pick_tag():
    if os.environ.get("HIST_TAG"):
        return os.environ["HIST_TAG"]
    head = dt.date.fromisoformat(git("log", "-1", "--format=%cs", "HEAD").strip())
    months = int(os.environ.get("HIST_MONTHS", "12"))
    cutoff = (head - dt.timedelta(days=round(months * 30.44))).isoformat()
    for line in git("for-each-ref", "--sort=-creatordate", "--format=%(refname:short) %(creatordate:short)",
                    "refs/tags").splitlines():
        tag, date = line.split()
        if date > cutoff:
            continue
        if sp.run(["git", "-C", repo, "merge-base", "--is-ancestor", tag, "HEAD"]).returncode == 0:
            return tag
    raise SystemExit("no suitable tag")


def functions_of(sha, path):
    """(name, start, end) of functions in `path` at revision `sha`."""
    try:
        text = git("show", f"{sha}:{path}")
    except sp.CalledProcessError:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=Path(path).suffix, delete=False) as handle:
        handle.write(text)
    try:
        return function_ranges(Path(handle.name))
    finally:
        os.unlink(handle.name)


def small_source_fix(sha):
    """Same criteria as matched pairs: source-only, at most MAX_LINES changed source lines."""
    lines, files = 0, 0
    for row in git("show", "--numstat", "--format=", sha).splitlines():
        parts = row.split("\t")
        if len(parts) != 3 or parts[0] == "-":
            continue
        path = parts[2]
        if path.endswith(extensions):
            if re.search(r"(^|/)(tests?|fuzz\w*|examples?|docs?)/", path):
                continue
            lines += int(parts[0]) + int(parts[1])
            files += 1
        elif not re.search(r"(test|doc|\.h$|\.hh$|\.hpp$|\.md$|NEWS|ChangeLog|manifest|RELEASE)", path,
                           re.IGNORECASE):
            return False
    return files > 0 and lines <= MAX_LINES


def later_fixes(tag):
    cache = out_dir / f"{name}-fixes.json"
    if cache.exists():
        return json.loads(cache.read_text())
    fixes = defaultdict(list)  # "path::function" -> [{commit, subject, type}]
    for line in git("log", "--no-merges", f"{tag}..HEAD", "--format=%H%x09%s").splitlines():
        sha, subject = line.split("\t", 1)
        if not re.search(BUG_WORDS, subject, re.IGNORECASE) or not small_source_fix(sha):
            continue
        diff = git("show", "--format=", "--unified=0", sha)
        message = git("log", "-1", "--format=%B", sha)
        for path, change in parse_diff(diff).items():
            if not path.endswith(extensions) or not change.old_lines and not change.old_gaps:
                continue
            region = region_for(change.old_lines, functions_of(f"{sha}^", path), change.old_gaps)
            for function in region.functions:
                if not function.startswith("<anon"):
                    fixes[f"{path}::{function}"].append(
                        {"commit": sha, "subject": subject, "type": guess_type(message)})
    cache.write_text(json.dumps(fixes))
    return fixes


def base_rate(checkout, fixes):
    cache = out_dir / f"{name}-base.json"
    if cache.exists():
        return json.loads(cache.read_text())
    total = fixed = 0
    for entry in checkout.entries():
        rel = checkout.relpath(str(checkout.abs_file(entry)))
        if rel is None or not tgt.in_scan_scope(rel):
            continue
        for function, _, _ in function_ranges(checkout.src / rel):
            total += 1
            fixed += f"{rel}::{function}" in fixes
    result = {"functions": total, "later_fixed": fixed, "rate": round(fixed / total, 4) if total else None}
    cache.write_text(json.dumps(result))
    return result


JUDGE = """A static-analysis checker reported a possible bug in {project} at release {tag}. Later, the project
committed the change below to the same function. Decide whether that later commit fixes **the problem the
report describes** (not merely touches the same function).

## Checker's bug pattern
{pattern}

## Report
{file}:{line} in `{function}`: {description}

## Later commit {commit}: {subject}
```diff
{diff}
```

Answer with one ```json block: {{"fixes_reported_issue": true|false, "reason": "<one sentence>"}}"""


def judge(bundle_pattern, report, fix):
    diff = git("show", "--format=", fix["commit"], "--", report["file"])[:12000]
    prompt = JUDGE.format(project=global_config.project_description, tag=TAG, pattern=bundle_pattern[:4000],
                          file=report["file"], line=report["line"], function=report["function"],
                          description=report["description"], commit=fix["commit"][:10],
                          subject=fix["subject"], diff=diff)
    answer = extract_json_block(invoke_llm(prompt, stage="hist_judge", temperature=0.01) or "")
    return bool(answer.get("fixes_reported_issue")), answer.get("reason", "")


TAG = pick_tag()
checkout = tgt.prepare(TAG)
fixes = later_fixes(TAG)
base = base_rate(checkout, fixes)
print(json.dumps({"target": name, "tag": TAG, "revision": checkout.revision, "fixed_functions": len(fixes),
                  "base_rate": base}), flush=True)
init_llm()
results = []
for bundle in bundles:
    manifest = yaml.safe_load((bundle / "manifest.yaml").read_text())
    if manifest["source"]["project"] == name or not manifest.get("roles"):
        continue
    start = time.monotonic()
    entry = {"bundle": bundle.name, "source": manifest["source"]["project"], "target": name, "tag": TAG,
             "bug_type": manifest.get("bug_type")}
    mapping = port_roles(bundle, commit=TAG, out_name=f"{name}-hist")
    entry["mapping"] = mapping
    if not any(mapping.values()):
        entry["status"] = "no equivalent roles"
        results.append(entry)
        continue
    os.environ["KNIGHTER_ROLES"] = str((bundle / "roles" / f"{name}-hist.json").resolve())
    scan = out_dir / name / bundle.name
    count = backend.run_checker((bundle / "checker.cpp").read_text(), TAG, tgt, output_dir=str(scan))
    del os.environ["KNIGHTER_ROLES"]
    reports, seen = [], set()
    for report in collect_reports(scan):
        rel = tgt.relpath_of(report.file)
        key = (rel, report.function)
        if key in seen:
            continue
        seen.add(key)
        reports.append({"file": rel, "line": report.line, "function": report.function,
                        "description": report.description,
                        "later_fixes": fixes.get(f"{rel}::{report.function}", [])})
    hits = [r for r in reports if r["later_fixes"]]
    for report in hits[:MAX_JUDGE]:
        verdicts = []
        for fix in report["later_fixes"][:3]:
            ok, reason = judge(manifest.get("pattern") or "", report, fix)
            verdicts.append({"commit": fix["commit"], "fixes": ok, "reason": reason})
        report["judged"] = verdicts
    entry.update({"status": "scanned", "reports": count, "functions_reported": len(reports),
                  "hits": len(hits), "hit_rate": round(len(hits) / len(reports), 4) if reports else None,
                  "judged_positive": [
                      {"file": r["file"], "line": r["line"], "function": r["function"],
                       "commit": v["commit"], "reason": v["reason"]}
                      for r in hits for v in r.get("judged", []) if v["fixes"]],
                  "report_list": reports, "seconds": round(time.monotonic() - start, 1)})
    results.append(entry)
    print(json.dumps({k: entry[k] for k in ("bundle", "source", "target", "reports", "functions_reported", "hits",
                                            "hit_rate") if k in entry} | {"positive": len(entry["judged_positive"])}),
          flush=True)
    (out_dir / f"{name}.json").write_text(json.dumps({"tag": TAG, "base_rate": base, "results": results}, indent=2))
(out_dir / f"{name}.json").write_text(json.dumps({"tag": TAG, "base_rate": base, "results": results}, indent=2))
