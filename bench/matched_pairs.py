"""3.4 matched pairs: does a checker from project P detect SAME-CLASS bugs fixed in project Q?

Ground truth = real fix commits of Q, selected deterministically (no LLM picks commits):
  1. mine Q's history once: non-merge bug-fix commits (keywords), small source-only diffs
     (bench/mine_commits.py criteria), cached in OUT_DIR/<Q>-candidates.json;
  2. per foreign bundle: port its roles to Q (LLM, 3.1-B, the only LLM step), then keep the
     candidates whose keyword-guessed bug type equals the bundle's AND whose diff mentions at
     least one name the roles were ported to (the fix touches the checker's API); rank by the
     number of distinct ported names hit, then recency; take the top N;
  3. validate the UNCHANGED plugin with the ported roles on each selected commit, scored like
     generation (strict TP on commit^, TN on commit).
Q's benchmark commits are excluded (they were already used by cross_known.py).

Usage: python bench/matched_pairs.py TARGET_CONFIG OUT_DIR BUNDLE_DIR [BUNDLE_DIR ...]
Env: MATCHED_N (default 3), MATCHED_SINCE (default 2019-01-01), MATCHED_MAX_LINES (default 40),
MATCHED_MAX_TRIES (default N + 6: candidates whose revisions cannot be set up are skipped).
Optional config key target_options.build_marker (e.g. meson.build): only commits whose parent
contains it are mined, since older revisions predate the build system the setup commands use.
"""
import json
import os
import re
import subprocess as sp
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "bench"))
from global_config import global_config  # noqa: E402

config, out_dir = sys.argv[1], Path(sys.argv[2])
bundles = [Path(b) for b in sys.argv[3:]]
global_config.setup(config)
from mine_commits import BUG_WORDS, guess_type  # noqa: E402
from model import init_llm  # noqa: E402
from role_porting import port_roles  # noqa: E402

N = int(os.environ.get("MATCHED_N", "3"))
SINCE = os.environ.get("MATCHED_SINCE", "2019-01-01")
MAX_LINES = int(os.environ.get("MATCHED_MAX_LINES", "40"))
options = global_config.get("target_options") or {}
target_name, repo = options["name"], options["repo_dir"]
extensions = tuple(options.get("source_extensions") or [".c"])
build_marker = options.get("build_marker")
MAX_TRIES = int(os.environ.get("MATCHED_MAX_TRIES", str(N + 6)))
backend, tgt = global_config.backend, global_config.target
out_dir.mkdir(parents=True, exist_ok=True)


def git(*args):
    return sp.run(["git", "-C", repo, *args], capture_output=True, text=True, check=True).stdout


def mine():
    cache = out_dir / f"{target_name}-candidates.json"
    if cache.exists():
        return json.loads(cache.read_text())
    benchmark = {line.split(",")[0] for line in (ROOT / f"bench/commits-{target_name}.txt").read_text().split()
                 if line and not line.startswith("#")}
    rows = []
    for line in git("log", "--no-merges", f"--since={SINCE}", "--format=%H%x09%ct%x09%s").splitlines():
        sha, stamp, subject = line.split("\t", 2)
        if sha in benchmark or not re.search(BUG_WORDS, subject, re.IGNORECASE):
            continue
        source_lines, files, other = 0, [], False
        for row in git("show", "--numstat", "--format=", sha).splitlines():
            parts = row.split("\t")
            if len(parts) != 3 or parts[0] == "-":
                continue
            path = parts[2]
            if path.endswith(extensions):
                if re.search(r"(^|/)(tests?|fuzz\w*|examples?|docs?)/", path):
                    continue
                source_lines += int(parts[0]) + int(parts[1])
                files.append(path)
            elif not re.search(r"(test|doc|\.h$|\.hh$|\.hpp$|\.md$|NEWS|ChangeLog|manifest|RELEASE)", path,
                               re.IGNORECASE):
                other = True
        if not files or other or source_lines > MAX_LINES:
            continue
        if build_marker and sp.run(["git", "-C", repo, "cat-file", "-e", f"{sha}^:{build_marker}"],
                                   capture_output=True).returncode != 0:
            continue
        message = git("log", "-1", "--format=%B", sha)
        diff = git("show", "--format=", "--unified=0", sha, "--", *files)
        changed = "\n".join(l for l in diff.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---")))
        rows.append({"commit": sha, "time": int(stamp), "subject": subject, "files": files,
                     "lines": source_lines, "bug_type": guess_type(message), "changed": changed})
    cache.write_text(json.dumps(rows))
    return rows


candidates = mine()
print(f"{target_name}: {len(candidates)} mined fix candidates", flush=True)
init_llm()
results = []
for bundle in bundles:
    manifest = yaml.safe_load((bundle / "manifest.yaml").read_text())
    source = manifest["source"]["project"]
    if source == target_name or not manifest.get("roles"):
        continue
    bug_type = manifest.get("bug_type")
    start = time.monotonic()
    mapping = port_roles(bundle)
    ported = sorted({n for names in mapping.values() for n in names})
    selected = []
    for cand in candidates:
        if cand["bug_type"] != bug_type:
            continue
        hits = sorted(n for n in ported if re.search(rf"\b{re.escape(n)}\b", cand["changed"]))
        if hits:
            selected.append((len(hits), cand["time"], cand, hits))
    selected.sort(key=lambda x: (-x[0], -x[1]))
    entry = {"bundle": bundle.name, "source": source, "target": target_name, "bug_type": bug_type,
             "mapping": mapping, "same_type_candidates": sum(c["bug_type"] == bug_type for c in candidates),
             "api_matched_candidates": len(selected), "pairs": []}
    os.environ["KNIGHTER_ROLES"] = str((bundle / "roles" / f"{target_name}.json").resolve())
    code = (bundle / "checker.cpp").read_text()
    tries = 0
    for _, _, cand, hits in selected:
        if sum(p["error"] is None for p in entry["pairs"]) >= N or tries >= MAX_TRIES:
            break
        tries += 1
        sha = cand["commit"]
        details = out_dir / f"{target_name}-details" / f"{bundle.name}__{sha[:8]}.json"
        details.parent.mkdir(parents=True, exist_ok=True)
        try:
            tp, tn = backend.validate_checker(code, sha, tgt.get_patch(sha), tgt, details_out=details)
            error = None
        except Exception as exc:  # revision cannot be set up, no analyzable file, ...
            tp, tn, error = None, None, str(exc)[-300:]
        entry["pairs"].append({"commit": sha, "subject": cand["subject"], "files": cand["files"],
                               "api_hits": hits, "tp": tp, "tn": tn, "error": error,
                               "detected": bool(tp and tp > 0),
                               "perfect": bool(tp and tp > 0 and tn and tn > 0)})
    del os.environ["KNIGHTER_ROLES"]
    entry["seconds"] = round(time.monotonic() - start, 1)
    results.append(entry)
    print(json.dumps({"bundle": entry["bundle"], "source": source, "target": target_name,
                      "api_matched": entry["api_matched_candidates"],
                      "pairs": [(p["commit"][:8], p["tp"], p["tn"]) for p in entry["pairs"]]}), flush=True)
    (out_dir / f"{target_name}.json").write_text(json.dumps(results, indent=2))
(out_dir / f"{target_name}.json").write_text(json.dumps(results, indent=2))
