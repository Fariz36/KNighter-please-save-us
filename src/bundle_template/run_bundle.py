#!/usr/bin/env python3
"""Run this KNighter checker bundle on any C/C++ project (no KNighter needed).

  python3 run_bundle.py --compile-db path/to/compile_commands.json \
      --roles roles/<project>.json --out reports/ [--clang /path/to/clang] [--jobs 8]

Requirements: Python 3.8+, and the clang the plugin was built for (see
manifest.yaml: clang_version), or rebuild plugin.so with CMakeLists.txt.
The roles file maps the checker's roles to the target project's API names;
`roles/` holds the source project's file (and any ported ones).
"""

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from knighter_analysis import analyze_entries, collect_reports  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--compile-db", required=True, help="compile_commands.json of the project to scan")
    ap.add_argument("--roles", help="roles JSON for the target project (default: none -> role queries are false)")
    ap.add_argument("--out", default="knighter-reports", help="output directory for HTML reports")
    ap.add_argument("--clang", default="clang", help="clang binary matching the plugin")
    ap.add_argument("--plugin", default=str(HERE / "plugin.so"))
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--timeout", type=int, default=600, help="per-file analysis timeout (s)")
    ap.add_argument("--files", nargs="*",
                    help="only analyze entries whose path contains one of these (e.g. lib/ or src/foo.c)")
    args = ap.parse_args()

    entries = json.loads(Path(args.compile_db).read_text())
    entries = [e for e in entries if e["file"].endswith((".c", ".cc", ".cpp", ".cxx"))]
    if args.files:
        entries = [e for e in entries if any(f in e["file"] for f in args.files)]
    if not entries:
        sys.exit("no compile entries selected (check --compile-db and --files)")
    if args.roles:
        os.environ["KNIGHTER_ROLES"] = str(Path(args.roles).resolve())

    clang = Path(args.clang)
    if not clang.is_absolute():
        from shutil import which
        found = which(args.clang)
        if not found:
            sys.exit(f"clang not found: {args.clang}")
        clang = Path(found)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results = analyze_entries(clang, Path(args.plugin), entries, out, jobs=args.jobs,
                              timeout=args.timeout)
    reports = collect_reports(out, delete_duplicates=True)
    failed = [r for r in results if not r.ok]
    summary = {
        "files": len(results),
        "failed": len(failed),
        "crashed": sum(r.crashed for r in results),
        "reports": [r.to_dict() for r in reports],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    for r in reports:
        print(f"{r.file}:{r.line}: [{r.function}] {r.description}")
    print(f"{len(reports)} report(s) in {len(results)} file(s); {len(failed)} failed analyses",
          file=sys.stderr)
    if failed:
        print(f"first failure: {failed[0].source}: {failed[0].error[-300:]}", file=sys.stderr)
    return 1 if failed and len(failed) == len(results) else 0


if __name__ == "__main__":
    sys.exit(main())
