"""List candidate bug-fix commits for the benchmark.

Criteria (all from git metadata, nothing project-specific):
  * non-merge, after --since;
  * message matches bug keywords;
  * touches at least one source file under --dirs with an allowed extension,
    and nothing outside source/header/test/doc files;
  * at most --max-lines changed lines in source files.

A keyword-based first guess of the bug type is printed; every selected commit is
then checked by reading its diff (the guess is only a sorting aid).

Usage:
  python bench/mine_commits.py REPO --dirs src/ lib/ --ext .c --since 2023-01-01
"""

import argparse
import re
import subprocess as sp

TYPES = [
    ("Use-After-Free", r"use[- ]after[- ]free|\buaf\b|dangling"),
    ("Double-Free", r"double[- ]free"),
    ("Null-Pointer-Dereference", r"null[- ]?(pointer|ptr|deref)|nullptr|segfault|\bNULL\b"),
    ("Memory-Leak", r"\bleak"),
    ("Integer-Overflow", r"integer overflow|signed overflow|shift overflow|wrap ?around|overflow in .*(size|length|count)"),
    ("Buffer-Overflow", r"buffer overflow|heap[- ]overflow|stack[- ]overflow|overrun|overwrite"),
    ("Out-of-Bound", r"out[- ]of[- ]bound|\boob\b|over-?read|past the end|one byte past|index"),
    ("Use-Before-Initialization", r"uninit|initiali[sz]"),
    ("Concurrency", r"race|deadlock|data race|lock"),
]
BUG_WORDS = r"fix|bug|crash|overflow|leak|null|uninit|free|bound|overrun|overread|assert|ubsan|asan|oss-fuzz|cve"


def git(repo, *args):
    return sp.run(["git", "-C", repo, *args], capture_output=True, text=True, check=True).stdout


def guess_type(message):
    for name, pattern in TYPES:
        if re.search(pattern, message, re.IGNORECASE):
            return name
    return "Misuse"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--dirs", nargs="+", default=[""])
    ap.add_argument("--ext", nargs="+", default=[".c"])
    ap.add_argument("--since", default="2022-01-01")
    ap.add_argument("--max-lines", type=int, default=30)
    ap.add_argument("--limit", type=int, default=60)
    args = ap.parse_args()

    log = git(args.repo, "log", "--no-merges", f"--since={args.since}", "--format=%H%x09%s")
    shown = 0
    for line in log.splitlines():
        sha, subject = line.split("\t", 1)
        if not re.search(BUG_WORDS, subject, re.IGNORECASE):
            continue
        numstat = git(args.repo, "show", "--numstat", "--format=", sha)
        source_lines, source_files, other = 0, [], False
        for row in numstat.splitlines():
            parts = row.split("\t")
            if len(parts) != 3 or parts[0] == "-":
                continue
            added, deleted, path = int(parts[0]), int(parts[1]), parts[2]
            if path.endswith(tuple(args.ext)) and path.startswith(tuple(args.dirs)):
                source_lines += added + deleted
                source_files.append(path)
            elif not re.search(r"(test|doc|\.h$|\.hpp$|\.md$|NEWS|ChangeLog|manifest)", path, re.IGNORECASE):
                other = True
        if not source_files or other or source_lines > args.max_lines:
            continue
        message = git(args.repo, "log", "-1", "--format=%B", sha)
        print(f"{sha[:10]}\t{source_lines}\t{guess_type(message)}\t{subject[:80]}\t{' '.join(source_files)}")
        shown += 1
        if shown >= args.limit:
            break


if __name__ == "__main__":
    main()
