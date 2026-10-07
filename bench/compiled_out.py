"""Find benchmark commits whose patched functions are compiled out (#if'd away) in our build.

Such commits compile and "analyze" fine, but no checker can ever report on them, so
they are unsolvable rather than generation failures (e.g. curl c4cb6769: lib/smb.c
is guarded by CURL_ENABLE_SMB, off by default).

For each commit: run the preprocessor (clang -E, the file's own compile command) on
every patched file of the buggy revision and check that each patched function name
survives. Function names come from the strict-scoring regions (validation_scoring).

Usage: python bench/compiled_out.py CONFIG COMMITS_FILE
"""
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from global_config import global_config  # noqa: E402

config, commits_file = sys.argv[1], Path(sys.argv[2])
global_config.setup(config)
from checker_gen import parse_commit_line  # noqa: E402
from validation_scoring import extract_diff, function_ranges, parse_diff, region_for  # noqa: E402

target, backend = global_config.target, global_config.backend
DROP_VALUE = {"-o", "-MF", "-MT", "-MQ"}
DROP = {"-c", "-MD", "-MMD", "-MP"}


def preprocess(entry, clang):
    argv = entry.get("arguments") or shlex.split(entry["command"])
    out, skip = [str(clang)], False
    for arg in argv[1:]:
        if skip:
            skip = False
            continue
        if arg in DROP_VALUE:
            skip = True
            continue
        if arg in DROP:
            continue
        out.append(arg)
    out += ["-E", "-P", "-w"]
    result = subprocess.run(out, cwd=entry.get("directory") or ".", capture_output=True, text=True)
    return result.returncode, result.stdout


for sha, _ in (c for c in map(parse_commit_line, commits_file.read_text().splitlines()) if c):
    patch = target.get_patch(sha)
    checkout = target.prepare(sha, True)
    changed = parse_diff(extract_diff(patch))
    row = {"commit": sha[:8], "files": {}}
    for path in target.get_objects_from_patch(patch):
        entry = checkout.entry_for(path)
        if entry is None:
            row["files"][path] = "no compile entry"
            continue
        change = changed.get(path)
        region = region_for(change.old_lines, function_ranges(checkout.src / path), change.old_gaps) \
            if change else None
        names = sorted(n for n in region.functions if not n.startswith("<anon")) if region else []
        code, text = preprocess(entry, backend.clang_path if path.endswith(".c") else
                                Path(str(backend.clang_path) + "++"))
        if code != 0:
            row["files"][path] = "preprocess failed"
            continue
        missing = [n for n in names if not re.search(rf"\b{re.escape(n.split('::')[-1].lstrip('~'))}\s*\(", text)]
        row["files"][path] = {"functions": names, "compiled_out": missing,
                              "preprocessed_lines": text.count("\n")}
    row["unsolvable"] = bool(row["files"]) and all(
        isinstance(v, dict) and v["functions"] and len(v["compiled_out"]) == len(v["functions"])
        for v in row["files"].values())
    print(json.dumps(row), flush=True)
