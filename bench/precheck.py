"""Check candidate commits are analyzable: both revisions configure, every
patched source file has a compile entry on both sides, and clang --analyze
actually succeeds on it (with a no-op checker)."""
import sys, time, json
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "src")
from global_config import global_config

config, commits = sys.argv[1], sys.argv[2:]
global_config.setup(config)
t = global_config.target
b = global_config.backend

from pathlib import Path  # noqa: E402

from backends.direct_analysis import analyze_entries  # noqa: E402

PLUGIN = b.plugin_for((Path(__file__).parent / "minimal_checker.cpp").read_text())
assert PLUGIN is not None, "minimal checker does not build"

def check(commit):
    start = time.time()
    try:
        patch = t.get_patch(commit)
        files = t.get_objects_from_patch(patch)
        if not files:
            return commit, "NO_FILES", [], 0
        sides, failed = {}, {}
        for side, before in (("buggy", True), ("fixed", False)):
            co = t.prepare(commit, before)
            sides[side] = [f for f in files if co.entry_for(f) is None]
            # Actually run the analyzer (no-op checker) on every patched file
            # that has an entry: an entry existing does not mean it analyzes.
            entries = [co.entry_for(f) for f in files if co.entry_for(f) is not None]
            results = analyze_entries(b.clang_path, PLUGIN, entries,
                                      Path("tmp/precheck") / commit[:12] / side, jobs=4)
            failed[side] = {Path(r.source).name: r.error[-200:] for r in results if not r.ok}
        if failed["buggy"] or failed["fixed"]:
            return commit, f"ANALYSIS_FAILED {failed}", files, round(time.time() - start)
        ok = not sides["buggy"] and not sides["fixed"]
        return commit, "OK" if ok else f"MISSING {sides}", files, round(time.time() - start)
    except Exception as e:
        return commit, f"ERROR {str(e)[-300:]}", [], round(time.time() - start)

with ThreadPoolExecutor(4) as pool:
    for commit, status, files, sec in pool.map(check, commits):
        print(json.dumps({"commit": commit, "status": status, "files": files, "seconds": sec}), flush=True)
