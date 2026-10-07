# KNighter-please-save-us — Research Log

Append-only log of every decision, action, and measurement, kept as context for the
research paper and for future sessions. Newest entries at the bottom. Never rewrite past
entries; if something turns out wrong, add a correction entry that references it.

Conventions:
- Timestamps are local (UTC+07:00).
- "Upstream" = this tree at commit `f4e834b` (clean KNighter main).
- "Previous attempt" = `/home/faris/RA-MrYudis/Knight/KNighter` (same base commit, plus
  ~674 lines of uncommitted changes, an untracked `src/targets/cmake.py`, and libgit2
  run artifacts under `result-libgit2-debug/`, `logs/`, `demo-scans/`).
- Tags: **[M]** measured/observed directly, **[I]** inferred.

---

## 2026-09-30 ~15:40 — Session start: supervisor goals

Supervisor goals for this fork:
1. Make it faster.
2. Make it target general C projects.
3. Make generated checkers usable across projects.
4. Accept a CVE as input.

Changes go into `KNighter-please-save-us/`. The previous attempt is evidence only.

## 2026-09-30 ~15:45 — Analysis of the previous attempt (4 parallel read-only investigations + spot checks)

### Cross-cutting problems (found in upstream code, which the previous attempt inherited)
- **Weak TP/TN** [M]: `src/backends/csa.py:540-590`. TP = any report in a patched object
  on the buggy version; TN also given when the fixed-version count merely drops.
  The previous attempt's UBI checker `d6486af3` was "valid" with 26 reports on buggy and 17 on fixed
  (`KNighter/docs/context_global_scan.md` §4).
- **Plugin race under parallel gen** [M, previous attempt only]: repair builds the shared
  `SAGenTestPlugin.so`, and validation later runs with `skip_build_checker=True` (`checker_gen.py:456`
  in the previous attempt, `:427` upstream). `logs/gen_all_v3.log`: a worker's repair succeeded at
  17:23:21, another worker rebuilt at 17:23:59, and the first worker validated at 17:24:29, so it scored the
  wrong plugin.
- **Silent no-op rerun** [M]: `checker_gen.py:295-321` upstream. With a full, non-perfect
  `ranking.txt`, `range(len(results), checker_nums)` is empty. `KNighter/logs/gen_all_full.log`
  finished in ~1 s. `ranking.txt` is also loaded with `eval()`.

### Goal 1 — speed [M from previous-attempt logs; scripts by the investigation agent]
- LLM latency is 55–98% of wall time. `gen_all_v3.log`: 74 min wall, 103 calls, ~170 s/call
  (deepseek-v4-flash + `thinking_effort: max`). 33/50 plugin builds failed, which caused 31
  syntax-repair calls (~30% of calls). Earlier pro-model runs without max thinking: 53–69 s/call.
- The global `backend_lock` (previous attempt) serialized builds (18–30 s) and validations (13–21 s, two
  checkouts + full CMake reconfigure). The lock was busy 72–78% of wall time in pro runs.
- Upstream Linux: `make clean` + `allyesconfig` on every checkout, twice per checker
  (`targets/linux.py:33-47`, `csa.py:519,562`) [M code; no kernel logs].
- The CMake scan (previous attempt) is sequential and ignores `jobs`: 11–14 min for ~221 files (`logs/head-scan-*.log`).
- Refine: "Failed to validate on objects!" 12/12 and 15/15 times (`refine-libgit2-20260809*.log`).

### Goal 2 — general C [M]
- `global_config.py:46-58` handles linux/v8 only and silently falls back to linux. `csa.py` dispatch raises
  `NotImplementedError` otherwise (`:421-432`, `:461-486`).
- The target interface (`targets/factory.py`) has no configure/build/compile-DB/scan-scope hooks.
- Kernel wording in `patch2pattern*.md:3`, `patch2checker.md:3`. All 3 few-shot examples use `devm_*`.
- Kernel-scale thresholds: `extract_reports` needs ≥5 reports, and ≤10 reports counts as "Perfect".
- The previous attempt's CMake target is libgit2-specific (`cmake.py:19-37` hardcodes USE_SSH/NTLM/SHA1, key
  `libgit2_dir`, `target_type: libgit2`). Its per-entry `clang --analyze` idea is reusable.

### Goal 3 — cross-project [M]
- 11/22 generated libgit2 checkers contain libgit2 identifiers (e.g. `"git_fs_path_prettify_dir"`
  in Memory-Leak `checker_01.cpp:96`, `"short_oid"` in Out-of-Bound `checker_00.cpp:59`).
- The pattern prompt asks for "specific and accurate" patterns (`patch2pattern.md:6`). The general variant is off
  by default (`checker_gen.py:140`).
- There is one shared plugin source/`.so` inside the LLVM tree (`csa.py:53-105`), and no exportable artifact.
- UBI checker on the whole libgit2 tree: 942 reports, 214 in vendored pcre/xdiff/llhttp (`demo-scans/`).

### Goal 4 — CVE input [M]
- There is no CVE handling anywhere. The input is `sha,Type`, split at `checker_gen.py:189` outside the per-commit try.
- The fix must be a single commit in the one configured repo (`factory.py:80-88`).
- CVE text never reaches the prompts (`factory.py:97-122`). Type only names folders.
- The paper (docs/2503.09002v3.pdf) used hand-picked commits. CVEs appear only as results (30 assigned).

### Previous-attempt result numbers [M]
- Per-commit `summary.json` in `KNighter/result-libgit2-debug/`: **7/11** commits with TP=1,TN=1
  (2fb89b6d, f9e05546, c0a4ef05, 36b88791, 6d63f4b6, 967b28f0, d6486af3). `4e6b4937` has no
  summary (crashed on a file the patch adds). The general-C investigation agent reported 8/11. Corrected
  to 7 by direct check: it double-counted 2fb89b6d.
- The 3→7 improvement came with prompt changes and a manual move of old result dirs to work
  around the no-op rerun bug (`KNighter/docs/gen-improvement-20260809.md`).

## 2026-09-30 ~15:55 — Plan agreed with user

The plan has 21 items across sections 0–4, each with a change, difficulty, size, expected result,
and acceptance criteria (see conversation; summary here):
- 0.1 stronger TP/TN (report location inside patched hunk/function)
- 0.2 validate exactly the checker that was built
- 0.3 reruns actually rerun; no `eval`
- 1.1 fewer/faster LLM calls
- 1.2 per-checker plugin + per-worker worktree + cached build dirs, no global lock
- 1.3 no `make clean`/`allyesconfig` per checkout (Linux)
- 1.4 parallel scan
- 1.5 fix refine "Failed to validate on objects"
- 2.x generic target, 3.x cross-project, 4.x CVE — later

User instruction: **do sections 0 and 1 first**.

## 2026-09-30 16:00 — Decision: add a generic compile-DB target before 0/1

- Problem [M]: this machine has no Linux kernel tree and no V8 tree. It has only libgit2 (in the
  previous attempt) and a built LLVM 18.1.8 at `KNighter/llvm`. Upstream only supports linux/v8, so
  0/1 cannot be tested end to end here.
- Options presented: (a) pull a minimal generic target (plan items 2.1 + 2.2) forward; (b) Linux/V8-only
  changes with unit tests; (c) clone and build a kernel.
- **User chose (a).**

## 2026-09-30 16:04 — Decision: LLM provider = OpenCode Go, model `deepseek-v4.1-flash`

- User instruction: use DeepSeek V4.1 Flash via OpenCode Go and check it works first.
- Endpoint: `https://opencode.ai/zen/go/v1/chat/completions` (OpenAI-compatible), model id
  `deepseek-v4.1-flash`.
- Provider requirements (from the OpenCode Go docs the user pasted): the client should send its own
  User-Agent (not a generic SDK name) and a stable `x-opencode-session` header per conversation.
- Key stored in `llm_keys.yaml` (gitignored by `.gitignore:20`, file mode 600). Never printed or logged.
- Probe [M]: a 64-token request returned `"pong"` with a `reasoning_content` field (reasoning model),
  36 prompt / 13 completion tokens.
- Pricing noted [from provider docs]: $0.15/$0.60 per 1M input/output tokens off-peak, $0.30/$1.20 at peak
  (peak = 01–04 and 06–10 UTC, Mon–Fri).

## 2026-09-30 16:06 — Measurement: out-of-tree per-checker plugin build is feasible

- Upstream builds every checker by overwriting
  `llvm/clang/lib/Analysis/plugins/SAGenTestHandling/SAGenTestChecker.cpp` and running
  `make SAGenTestPlugin` in the LLVM build dir (`csa.py:53-105`). This forces one checker at a time.
- The plugin's exact compile command is in `llvm/build/compile_commands.json` and its link command in
  `tools/clang/lib/Analysis/plugins/SAGenTestHandling/CMakeFiles/SAGenTestPlugin.dir/link.txt`
  (compiled with system `/usr/bin/c++` GCC 15.2, `-O3`, statically linked against clang libs).
- Replaying those two commands with a different source/output path produces a working standalone
  `.so` (8.8 MB) [M]. Each checker can therefore get its own `.so` outside the LLVM tree, so there is
  no shared file and no lock.
- Compile time for one generated checker (`AllGen-Misuse-c0a4ef05/checkers/checker_00.cpp`) [M]:

  | Variant | Time |
  |---|---|
  | as configured (`-O3`) | 35.9 s compile + 3.3 s link |
  | `-O0` | 31.5 s |
  | `-O1` | 18.6 s |
  | `-fsyntax-only` (parse only) | 12.5 s |
  | `-O1` + GCC precompiled header (first attempt) | 18.1 s (PCH silently not used) |
  | `-O1` + PCH, fixed | **10.1 s** |
  | `-O0` + PCH | 11.9 s |
  | clang++ 18 instead of GCC, `-O1` | 27.6 s |

- Why the first PCH attempt failed: GCC only uses a PCH if it is the first include. The build's own
  `-include cstdint` came first. Fix: drop `-include cstdint` from the command and put `#include <cstdint>`
  as the first line of the PCH header.
- One-time PCH build: 26–33 s, 480 MB `.gch`.
- **Decision:** per-checker plugins built out of tree from the replayed commands, `-O1` + PCH
  (~10 s + ~3 s link vs ~36 s + 3 s today, about 3× faster per build). The PCH is built once per
  LLVM build and cached.

## 2026-09-30 16:08 — Decision: test targets = curl (first) and SQLite (second)

- User request: move testing from libgit2 to SQLite and/or curl, "maybe both".
- **Decision:** curl first. It builds with CMake and exports `compile_commands.json` directly. SQLite
  second: autotools + generated headers (`parse.h`, `opcodes.h`, `sqlite3.h`), and the default build
  compiles a generated amalgamation, not `src/*.c`. That makes it a good check that the generic
  target really is generic.
- Clones [M]: `/home/faris/RA-MrYudis/Knight/targets/curl` (163 MB, HEAD `bb348b35e8`,
  2026-09-29) and `/home/faris/RA-MrYudis/Knight/targets/sqlite` (GitHub mirror, 675 MB, HEAD
  `1f7010d4ec`, 2026-09-29).
- Note: the first sqlite clone never ran because of a shell backgrounding mistake in my command. It was
  re-run successfully.

## 2026-09-30 16:14 — Decision: keep this research log

- User instruction: log every decision/action as future context for the research paper, always
  append. This file is that log.
- Environment [M]: WSL2 Linux 6.18, 16 cores, 15 GB RAM, GCC 15.2.0, CMake 4.2.3, Python 3.14.4,
  LLVM/Clang 18.1.8 (custom build in `KNighter/llvm`).

## 2026-09-30 16:20 — Environment: parser + Python env

- `git submodule update --init` fetched `src/kparser/tree-sitter-cpp` @ `e5cea0ec`. The tree-sitter
  grammar builds and parses C [M].
- Python env: reuse the previous attempt's venv `/home/faris/RA-MrYudis/Knight/KNighter/venv`
  (Python 3.14, same requirements). Always invoke it by absolute path; a relative path makes
  `site` warn about `sys.prefix`.

## 2026-09-30 16:22 — Finding: shared plugin coupling also exists in refine

- `checker_refine.py:1352` (`_validate_on_commit`) and `:1398` (`_scan_objects`) both call the backend
  with `skip_build_checker=True`. They trust the plugin most recently built by `repair_checker`. The
  same hidden coupling as gen (`checker_gen.py:427`).
- **Decision (for 0.2):** content-address plugins. The plugin path is derived from sha256(checker source +
  build flags). Every validate/run call resolves the plugin for *its own* checker code, building it
  only on a cache miss. `skip_build_checker` stops being a correctness hazard.

## 2026-09-30 16:25 — Finding: clang HTML reports carry machine-readable location metadata

- Running `clang --analyze -Xanalyzer -analyzer-output=html -o DIR` directly (no scan-build) writes
  `DIR/report-<hash>.html` [M]. Each report has header comments: `BUGFILE`, `FILENAME`,
  `FUNCTIONNAME`, `BUGLINE`, `BUGCOLUMN`, `BUGTYPE`, `BUGDESC`, `ISSUEHASHCONTENTOFLINEINCONTEXT`,
  `BUGPATHLENGTH`. scan-build HTML reports have the same header.
- **Decision (for 0.1):** read report locations from these comments. One parser then works for Linux
  (scan-build), V8, and the new compile-DB target, and the issue hash dedups reports from headers
  analyzed in several translation units.
- Known limitation [I]: `FUNCTIONNAME` is where the report *ends*. With inlining, a bug whose fix is in
  caller `f` may be reported inside callee `g`. Scoring will therefore also match by line range, and
  the limitation will be measured, not assumed.
- `sarif-html` / `plist-html` add no extra files next to the HTML when `-o` is a directory [M], so plain
  `html` is used.

## 2026-09-30 16:21 — Result: out-of-tree plugin builder works (`src/backends/plugin_builder.py`)

- Replays CMake's compile/link commands for `SAGenTestPlugin` with `-O1` + a GCC PCH. Plugins are
  content-addressed by sha256(flags + opt level + checker source) under a cache dir. Compile failures
  are cached too, since the same code gives the same errors.
- Measured on `AllGen-Misuse-c0a4ef05/checker_00.cpp` [M]: first use 40.9 s (27.2 s one-time PCH),
  new checker 13.7 s (11.4 compile + 2.3 link), cache hit 0.0 s, compile error reported in 6.0 s.
  The resulting `.so` loads in clang 18 with `-Xanalyzer -load`.
- Legacy build for comparison: ~36 s compile + ~3 s link, as measured on the same checker at 16:06.
- Added a semaphore capping concurrent plugin compiles (default 4). Reason: ~1 GB peak RSS per compile
  [M at -O3] on a 15 GB machine.
- Compiler errors are rewritten to relative `checker.cpp:LINE` paths so the repair prompt doesn't carry
  long cache paths.

## 2026-09-30 16:35 — Build recipes for test targets (measured)

- Tools available [M]: `intercept-build` (scan-build-py), make, pkg-config. `bear` is absent, Tcl is absent,
  and there is no passwordless sudo. Libraries: openssl 3.5.5, zlib, libpsl, nghttp2, brotli present; libidn2,
  libssh2, zstd, tcl missing.
- **SQLite HEAD** (`1f7010d4ec`): autosetup `configure --disable-tcl` 9.0 s (uses the bundled jimsh, no
  system Tcl needed). `intercept-build make USE_AMALGAMATION=0 -j16 libsqlite3.a` takes 12.8 s and gives
  102 per-file compile entries (src/*.c, ext/fts3, ext/rtree, ...; some generated files such as
  `parse.c`, `opcodes.c`, `ctime.c` live in the build dir).
  - Caveat [I]: older SQLite revisions (pre-autosetup) need a real `tclsh` to build. Benchmark commits
    must be picked from revisions that configure here; if needed, jimsh0 can be offered as `TCLSH_CMD`.
- **curl HEAD** (`bb348b35e8`): CMake configure with `CC=<LLVM>/bin/clang` takes **49.1 s** (feature
  probes) and gives 194 compile entries. Options: tests/exe/examples/docs off; libssh2, libidn2, zstd off;
  OpenSSL on, so `lib/vtls/openssl.c` gets a compile entry.
- **Decision:** configure each target with LLVM's own clang as CC so the compile database only has
  clang-compatible flags, which avoids GCC-only flags breaking `clang --analyze`.
- **Implication for speed (1.2):** with curl, upstream-style "reconfigure on every checkout" costs ~100 s
  per validation (2 sides). Caching one configured worktree per revision is the biggest non-LLM saving.

## 2026-09-30 16:30 — Implemented: generic compile-DB target + direct analysis + strict scoring

Files (all new unless noted):
- `src/targets/compiledb.py` — `CompileDBTarget`, configured entirely by YAML (`target_options`):
  shell `setup` commands with `{src}` `{build}` `{jobs}` `{clang}` placeholders, compile-DB path, source
  extensions, scan include/exclude.
  - Each revision gets its own `git worktree` + build dir under `work_dir`.
  - A marker file records successful setup, so reuse works across processes too.
  - Per-revision locks: the same revision is set up once; different revisions set up concurrently.
- `src/backends/direct_analysis.py` — per compile entry, runs `clang --analyze` with `-Xanalyzer -load
  <plugin>`, the same disabled built-in checker list as scan-build, `-analyzer-max-loop 4`, and HTML output
  into a per-file dir. Runs in a thread pool (`analysis_jobs`). Detects crashes via "PLEASE submit a bug
  report"/"Stack dump:". Parses the report HTML metadata.
- `src/validation_scoring.py` — diff parser (state-based headers, so a deleted line starting with `-- `
  isn't a header), 1-based function ranges via tree-sitter, `Region` matching (function name, line
  range, or ±5-line window fallback), `score()` computing strict and legacy together.
- `src/backends/csa_compiledb.py` — `CompileDBMixin` for `ClangBackend`: validate (both revisions
  prepared concurrently; details JSON with every report + timing) and run/scan (all in-scope entries or
  one file; returns -1 for a file with no compile entry so refine doesn't mistake it for "bug killed").
- `src/backends/csa.py` (modified) — constructor options (`plugin_build`, `validation_scoring`, jobs,
  timeouts); `plugin_for(code)`; `build_checker` uses the standalone builder; dispatch for `compiledb`;
  Linux validate/run load the per-checker plugin via `-load-plugin <path>`.
- `src/global_config.py` (modified) — `TARGET_BUILDERS` registry. An unknown `target_type` now raises
  instead of silently becoming linux. Backend options from config; `min_reports_for_triage` /
  `perfect_report_threshold` properties.
- `src/targets/factory.py` (modified) — module-level `git_lock` around `get_patch` (GitPython is not
  thread-safe; previous attempt observed "read of closed file").
- `src/tools.py` (modified) — skip files added by the commit instead of crashing on
  `git show sha^:path`. This was the previous attempt's `4e6b4937` failure.
- `src/tests/test_validation_scoring.py` — 10 unit tests, all pass [M], including the plan's acceptance
  cases (report outside patched function → TP=0; 26→17 on-target reports → TN=0).
- `configs/curl.yaml` — curl recipe.

Decisions:
- **V8 stays on the legacy in-tree plugin build.** Its analysis helpers hardcode
  `lib/SAGenTestPlugin.so` and never receive the checker code, and no V8 tree exists here to test a
  refactor. `global_config` forces `plugin_build=legacy` for V8 with a warning.
- **Linux gets the per-checker plugin** (small change: `-load-plugin <path>`). It keeps legacy
  count-based scoring for now, because strict scoring there needs per-run scan-build output dirs and
  no kernel tree exists to test it. [Open item]
- The user config key for the generic target is `target_options`, not `target`, because `_config["target"]`
  holds the constructed target object.

Bugs found while smoke-testing (fixed):
1. **Relative report dir.** clang runs with the compile entry's directory as cwd, so `-o tmp/...` wrote
   reports into the *build* dir and validation saw 0 reports. The first smoke run printed TP/TN 0/0 with
   0 reports while a manual run of the same command showed 2 warnings. Fix: absolute output and plugin
   paths in `analyze_entry`. Stray dirs removed from the build dirs.
2. `setup_seconds` included the plugin build. It's now split into `plugin_seconds` / `setup_seconds`.

Smoke test [M] — curl `f7d4e11f4b` ("setopt: return error if received `curl_blob->data` is NULL",
patched function `Curl_setblobopt`), with the previous attempt's UBI checker `d6486af3/checker_00.cpp`:
- First-ever run: 88.3 s, of which PCH 28.7 s + plugin 6.6 s (compile 4.3 s with PCH, link 2.3 s), then
  both revisions configured **in parallel** (47.5 s and 47.1 s, finishing 1.5 s apart).
- The same validation again, and later in a new process: **1.9 s** (setup 0.01 s, analysis 0.9 s per side).
- Scores: buggy 2 reports / 0 on-target, fixed 2 / 0 → **strict 0/0, legacy TP=1 TN=0**. The 2 reports
  are "uninitialized `protos`" at setopt.c:2373/2384, unrelated to the patched function. This is exactly
  the false credit strict scoring removes.

## 2026-09-30 16:40 — Implemented: LLM layer, gen (0.2/0.3/parallel), refine (1.5), Linux incremental (1.3)

LLM layer (`src/model.py`, `src/agent.py`, `llm_keys.yaml`):
- Probe of OpenCode Go `deepseek-v4.1-flash` reasoning controls [M, n=1 each, so indicative only]:
  - default: 230 reasoning tokens, 3.1 s
  - `reasoning_effort` low/high (via `extra_body`; SDK 1.56.1 has no kwarg): 285 / 395 reasoning
    tokens, 3.0 / 3.6 s. **No clear effect.**
  - `thinking: {type: disabled}`: 0 reasoning tokens, 1.4–1.7 s. **Works.**
  - → Per-stage control is generic `extra_body`; thinking on/off is the lever that actually works.
- Every `invoke_llm` call carries a `stage` tag (patch2pattern, pattern2plan, plan2checker, repair_syntax,
  check_report, repair_FP, ...). Config `stage_options[stage]` can override model / temperature /
  max_tokens / extra_body.
- Providers from `llm_keys.yaml: providers:` get `User-Agent: knighter/0.2` plus a stable per-process
  session header (`x-opencode-session`), as the OpenCode Go docs require. Keys file restructured
  (still mode 600, gitignored).
- Client timeout `llm_timeout` (default 900 s; upstream had none). SDK retries off; our loop retries 6×
  with exponential backoff 2..60 s (upstream: fixed 2 s).
- Empty/whitespace content is retried rather than returned. The previous attempt hit a 495 s code
  generation that returned `None` ("data must be str, not NoneType").
- Every call appends one JSON line to `<result_dir>/llm_calls.jsonl`: stage, model, ok, attempt,
  seconds, prompt/completion/reasoning/cached tokens, session. Verified with a live call [M]:
  2.0 s, 36 prompt / 17 completion / 14 reasoning tokens.

Generation (`src/checker_gen.py`):
- 0.3: `ranking.txt` is written as JSON and read with json → `ast.literal_eval` fallback, never `eval`
  (a test proves `__import__('os')...` is rejected). A complete-but-imperfect ranking is no longer a silent
  no-op: it logs "skipped ... use --retry_failed", and `--retry_failed` generates `checker_nums` more
  attempts continuing the attempt index.
- 0.2: validation passes `details_out=generation/checker_NN/06_validation_details.json`. The backend
  resolves the plugin from the checker code (content-addressed), so a concurrent build can't be scored.
- 1.1/1.2: `gen_workers` (config) / `--workers` processes commits concurrently. It is forced to 1 with
  `plugin_build: legacy`, where the in-tree plugin is shared.
- Commit lines parsed by `parse_commit_line`: strips spaces, skips blank and `#` lines, ignores extra
  fields, and records an invalid line in the results file instead of aborting the batch (upstream:
  unpacking `line.split(",")` outside the try).
- Fail fast before any LLM call when the patch touches no analyzable source file.
- Progress counter reset per attempt (upstream showed e.g. "[233.3%]").

Refinement (`src/checker_refine.py`, `src/backends/csa.py`):
- Kernel thresholds are now config: `min_reports_for_triage` (default 5) and `perfect_report_threshold`
  (default 10). Removed `stop_num = max(sampled_num, stop_num)` in `extract_reports`, which silently
  overrode a smaller configured value.
- Report triage runs LLM calls in parallel (`triage_workers`, default 4) and tallies in report order,
  so results don't depend on completion order.

Linux (`src/targets/linux.py`, `src/backends/csa.py`) — plan item 1.3, **UNTESTED (no kernel tree)**:
- Opt-in `linux_incremental: true`. Validation checks out without `make clean`, reuses an existing
  `.config`, and deletes only the patched `.o` files so scan-build still analyzes them. Full-tree
  scans still clean. Default off, so upstream behaviour is unchanged unless enabled.

Tests: `src/tests/test_gen_helpers.py` (3) + `test_validation_scoring.py` (10) → 13/13 pass [M]. All
modified modules byte-compile. Upstream `src/tests/test_backend.py` needs a kernel `config.yaml` and was
not run.

## 2026-09-30 16:55 — Benchmark design (Step 0) and commit selection

Pre-check (`bench/precheck.py`, results `bench/precheck-{curl,sqlite}.jsonl`) [M]: for each candidate,
both revisions configure and every patched `.c` has a compile entry on both sides.
- curl: 7/8 fully OK. `466c06cf70`'s `tests/libtest/lib1560.c` has no entry (tests disabled);
  `lib/urlapi.c` is OK.
- SQLite: 8/8 OK.
- Wall per commit with 4 commits in parallel and cold setup: curl 128–220 s, SQLite 88–141 s.

Selected benchmark (11 commits, same count as the previous attempt's libgit2 set). Bug types were
labelled by reading each message and diff, as the paper's authors did:
- curl (`bench/commits-curl.txt`):
  - f2a1535712 NPD (`curl_easy_send/recv` missing `!n` check)
  - f7d4e11f4b NPD (`blob->data` NULL)
  - a0f08d6975 Memory-Leak (`Curl_peer_unlink` on the wrong path)
  - 6f1dfab6a2 Out-of-Bound (EPSV read past NUL)
  - bc440a89d4 Integer-Overflow (base64 size)
  - c53420e427 Misuse (`strlen` on a non-NUL-terminated `ASN1_STRING`)
- SQLite (`bench/commits-sqlite.txt`):
  - 7b60ed803b Memory-Leak (OOM path)
  - a7200804eb Buffer-Overflow (`szBufNeeded` +8→+10)
  - d87f8c4965 Integer-Overflow (mprintf length clamp)
  - 1bc183a935 Misuse (missing `TK_ILLEGAL` check before `sqlite3Dequote`)
  - 97467fa8fa Integer-Overflow (kvvfs decode)
- Excluded: SQLite `ffbfc27fab`. Its fix is under `#if SQLITE_MAX_LENGTH>2147483645`, compiled out in
  the default build, so no analyzer run can observe it. SQLite library fixes since the autosetup
  switch include no NULL-dereference commits outside the CLI (`shell.c.in`), so SQLite has no NPD case.

**Finding: the legacy in-tree plugin build is unusable on this machine.** `make SAGenTestPlugin` timed
out at 300 s. `make -n SAGenTestPlugin` shows it would rebuild **1068** LLVM objects plus tablegen
outputs, because the shared LLVM build tree (`KNighter/llvm/build`) is stale relative to its build files.
It would also mutate the previous attempt's LLVM tree. No leftover compiler processes remained.

**Decision: the baseline models upstream build cost** instead of running the in-tree make:
- the identical CMake compile+link commands at the original `-O3`, no PCH;
- `plugin_cache: false`, so every explicit build (each syntax-repair compile) recompiles;
- validation reuses the plugin just built, mirroring upstream's `skip_build_checker=True`
  (`PluginBuilder.build(explicit=...)`).

This excludes make's dependency-scan overhead, which upstream also pays, so the baseline slightly
**understates** upstream cost and the measured speedup is conservative.

Variants (`bench/run_bench.py`). Only infrastructure differs; model, prompts, temperature,
`checker_nums: 3`, and strict scoring are identical:
- **baseline**: `-O3`, no PCH, no plugin cache; `gen_workers 1`; `analysis_jobs 1`;
  `reuse_revisions false` (fresh configure per checkout, as upstream Linux does `make clean` +
  `allyesconfig`).
- **optimized**: `-O1` + PCH, content-addressed cache; `gen_workers 4`; `analysis_jobs 8`; cached revisions.
- Scoring is strict in both because it decides early stopping (first perfect attempt ends a commit);
  legacy scores are still recorded per attempt in `06_validation_details.json` for the 0.1 comparison.
- Each run gets a fresh result dir, plugin cache, and target work dir under `bench/runs/<name>/`
  (cold start). Runs execute one at a time on an otherwise idle machine. `/usr/bin/time -v` records wall
  time and peak RSS. `llm_calls.jsonl` gives per-stage LLM time and tokens; `07_step_times.json` gives
  per-attempt step durations.
- Known confounder: LLM output is stochastic, so the two variants generate different checkers.
  Infrastructure cost is therefore also reported per operation (plugin build, setup, analysis
  seconds), which does not depend on which checker was generated.

## 2026-09-30 17:00 — Smoke gen run `smoke-01` (curl f7d4e11f4b, 1 attempt, optimized): output budget exhausted by reasoning

- `patch2pattern` 5.7 s (547 reasoning tokens) and `pattern2plan` 93.2 s (**11,965 reasoning** / 12,674
  completion tokens) succeeded. `plan2checker` failed **4 times in a row** (68–112 s each): every call used
  `completion_tokens = reasoning_tokens = 16000` and returned empty content [M, `llm_calls.jsonl`].
- Cause: upstream `max_tokens` default 16000 is the output cap *including reasoning* for this model. The
  model thought until the cap and never wrote the answer. This is likely also the previous attempt's
  "Code Generation 495.6 s returned None" [I].
- The new empty-content retry turned it into a visible, logged error instead of a `None` crash, but it
  can't fix it. The run was stopped manually (it would have retried the same budget twice more).
- Probe [M]: the endpoint accepts `max_completion_tokens` of 32768 / 65536 / 131072 / 393216; `/models`
  publishes no limit.
- **Decision:** `max_tokens: 65536` and `llm_timeout: 1200` in `configs/{curl,sqlite}.yaml`. Speed
  implication to track: at ~110 s per 16k reasoning tokens, one unconstrained stage can take minutes.
  Whether to turn thinking off for `plan2checker`/`repair_syntax` is a separate quality/speed experiment,
  not part of the A/B infrastructure comparison.
- Side note: my `pkill -f <pattern>` also matched the invoking shell (exit 144). Use PIDs from `pgrep`
  in future.

## 2026-09-30 17:05 — Smoke gen run `smoke-02` succeeded end to end (max_tokens 65536)

curl f7d4e11f4b, 1 attempt, optimized variant, cold caches [M, `bench/runs/smoke-02/`]:
- Wall **223.4 s**. LLM calls: patch2pattern 8.4 s (489 reasoning tokens), pattern2plan 92.8 s (11,722
  reasoning), plan2checker 27.9 s (5,945 reasoning). All succeeded, no retries.
- Syntax repair 34.8 s: compiled on the first try (no repair LLM call); includes the one-time PCH build.
- Validation 51.5 s: setup 49.8 s (cold configure of both revisions, in parallel) + analysis ~1.7 s.
- Score: strict TP=1 TN=0 (legacy the same). The checker reports inside the patched `Curl_setblobopt`
  (line 111, "Missing NULL check for blob->data") on the buggy revision. It also reports on the same
  line on the fixed revision, so it doesn't recognise the added `!blob->data` guard. A genuine miss,
  correctly scored.
- Report paths verified: `relpath` maps worktree paths to `lib/setopt.c`, and function names come from
  report metadata.

Added `bench/replay_infra.py`: deterministic infrastructure replay (same checkers + commits, baseline vs
optimized; build + validate only, no LLM). It also serves as the 1.2 determinism check (identical
TP/TN required in both modes).

## 2026-09-30 17:07 — Launched benchmark (4 sequential runs)

Order interleaved to spread provider-load drift: `A-curl` (baseline), `B-curl` (optimized),
`A-sqlite`, `B-sqlite`. Driver: `bench/run_all.sh`, output `bench/run_all.out`. Start time is 17:07 local
= 10:07 UTC, which is off-peak for the provider (peak 01–04 and 06–10 UTC Mon–Fri).

- Correction to the 17:07 entry: the benchmark actually started at **17:02:45** local (see `bench/run_all.out`); the log entry was written before launch.

## 2026-09-30 17:10 — Independent code review → benchmark r1 aborted, 10 fixes

A read-only review agent examined all uncommitted changes. Its findings would bias the benchmark,
and each benchmark run starts a fresh process that loads the *current* source, so code can't change
mid-benchmark. **r1 was aborted ~6 min in** during `r1-A-curl` (kept as
`bench/runs/r1-A-curl-ABORTED`, not used for any number).

Fixes (review finding → change):
1. HIGH — refine counted a crashed/failed analysis as "no bug" (0 → object "killed"):
   `_run_checker_compiledb` now returns -2 (crash) / -1 (failed or no entry) for single-file runs and
   -999 when every file fails. It never returns 0 for "no answer".
2. `--retry_failed` was defeated by the `result_file` skip (lines recorded `,False` were skipped
   first). With `retry_failed` only `,True` lines are skipped.
3. Parallel gen workers were unsafe on Linux/V8 (one shared working tree). Workers are forced to 1
   unless the target is `compiledb`.
4. (-1,-1) ended the whole commit even when a single checker's plugin failed to load. `compiledb`
   validation now returns **(-3,-3)** for per-checker failures (plugin build/load), so gen continues with
   the next attempt, and (-2,-2) for crashes.
5. Infrastructure failures (checkout/configure, no analyzable file) were scored as "does not
   compile" (-10) and every later attempt re-ran all LLM stages. New `TargetSetupError`; failures are
   cached per revision within the process. Gen aborts the commit with ranking marker **-20**.
6. The plugin failure cache stored transient failures (OOM kill -9, empty stderr) forever. It now caches
   only `returncode > 0` with non-empty diagnostics, and the link step handles its timeout.
8. Scoring anchors could implicate neighbouring functions (insertion after `bar()`'s `}` marked
   `bar` as patched; mixed hunks added cross-side anchors). New model: removed/added lines per side;
   pure insertions/deletions become *gaps* `(before, after)` that implicate a function only if strictly
   inside it. The ±5-line window now applies per changed line outside every parsed function
   (`Region.orphans`), not only when a file has no parsed function at all.
9. A partial worktree after an interrupted run was trusted (`.git` is written before checkout finishes).
   There is now a per-revision completion marker, with remove + re-add otherwise, plus a cross-process
   `flock` per revision.
10. Report counts differed between `run_checker` (deduped) and `extract_reports` (raw files).
    Duplicate report HTML files are now deleted after a scan so both agree.
11. `07_step_times.json` was not written when an attempt raised, and stale entries leaked into the
    next attempt; both fixed. Added/deleted/renamed files are excluded from the validated file set
    (one side has no such file, so TN could never be earned).

Not changed, disclosed instead:
- **#7 PCH confound.** The optimized build force-includes a PCH with ~24 clang headers, so a checker
  missing an `#include` compiles in the optimized variant but not in the baseline (no PCH). This can
  change syntax-repair counts between variants. The replay benchmark (identical checkers) is unaffected.
  For the end-to-end A/B, repair calls per variant are reported so the effect is visible.
- Validation report dirs under `tmp/validation/` are kept (debug value; disk use is small).
- The review's unverified point (relative source path in `arguments` given twice) does not apply to our
  targets. curl (CMake) and SQLite (intercept-build `command`) entries use absolute source paths [M].

Also:
- SQLite configure now gets `CC={clang}` explicitly. Verified [M]: the generated Makefile has `CC =
  <LLVM>/bin/clang`, `T.cc = $(CC)`. Note: intercept-build records the compiler as `cc` in
  `compile_commands.json` regardless; the analyzer ignores argv[0], so this is cosmetic.
- New speed optimization: `CompileDBTarget.prefetch(commit)` configures commit^ and commit in a
  background thread at the start of each commit, overlapping configure (~50 s for curl) with the LLM
  stages (~2+ min). Enabled only when `reuse_revisions` is true, so it is part of the *optimized*
  variant only.
- Tests: 16/16 unit tests pass (3 new scoring regression tests for the review's scenarios).

## 2026-09-30 17:13 — Relaunched benchmark as r2 (same design as r1)

## 2026-09-30 17:18 — Benchmark runs from a frozen code snapshot (r2 → r3)

- Problem: each benchmark run is a new process that loads the *current* working-tree source and prompts,
  so continuing development during a multi-hour benchmark would silently change later runs.
- `bench/run_all.sh` now copies `src/`, `prompt_template/`, `checker_database/`, and the keys file to
  `bench/snapshots/<tag>/` once. It records a sha256 over all `.py`/`.md` files (`<tag>.sha256`) and runs
  every job with `cwd` = snapshot (`KNIGHTER_CODE_ROOT`). `code_root.txt` in each run dir records it.
- r2 was stopped ~5 min in (`r2-A-curl-ABORTED`) and relaunched as r3 from snapshot `affd56de4b67ba00`.

## 2026-09-30 17:43 — r3 aborted: LLM request stall; switched to streaming + idle-stall detection

- r3-A-curl, first commit [M, `bench/runs/r3-A-curl-ABORTED/results/llm_calls.jsonl`]: a `pattern2plan`
  request **hung for the full 1200 s timeout** and returned nothing. The retry succeeded in 64.3 s. Other
  calls: patch2pattern 6.6 s, plan2checker 106.8 s (15,180 reasoning tokens). The commit
  (f2a1535712, NPD) got a perfect checker (strict).
- Upstream had no timeout, so this request would have blocked the pipeline indefinitely.
- A single stall adds ~20 min of random delay, which would swamp the A/B comparison. **r3 was stopped**
  (~25 min in) to fix it first.
- A fixed total timeout is the wrong tool: healthy reasoning calls take minutes. The signal is *silence*.
  - Probe [M]: with `stream=True` the endpoint streams reasoning as `reasoning_content` deltas (50 chunks
    for a 4 s answer; largest gap 2.46 s = time to first byte), and `stream_options.include_usage` returns
    usage including `reasoning_tokens` in the last chunk.
- **Change (`src/model.py`):** provider (OpenAI-compatible) calls now stream. The httpx `read` timeout
  (`llm_stall_timeout`, default 180 s) is the maximum silence between chunks. `llm_timeout` remains
  an overall cap, checked while streaming. Upstream providers (openai/claude/google SDK clients) are
  unchanged.
  - Verified [M] against a fake SSE server that sends one chunk then goes silent: with a 3 s stall
    timeout, `ReadTimeout` after 3.0 s → normal retry path.
  - Verified [M] live: probe call through the config streams, returns content, and records usage.
- Relaunched as **r4** (new snapshot). Both variants share the fix, so the comparison stays fair.

## 2026-09-30 19:36 — r4 aborted: 1 h 43 min stall defeated the streaming timeouts; watchdog deadline added

- r4-A-curl [M, `bench/runs/r4-A-curl-ABORTED/results/llm_calls.jsonl`]: commit 1 (f2a1535712) finished
  normally (perfect, strict), with calls of 5.3 / 44.0 / 89.8 s. On commit 2, `pattern2plan` attempt 1 started
  17:48:53 and failed at 19:31:37 after **6164 s** with "LLM call exceeded 1200s". Attempt 2 failed
  on the 180 s idle timeout ("The read operation timed out", 240 s).
- Root cause (my bug in the 17:43 change): the overall `llm_timeout` was checked *inside the chunk loop*.
  The stream evidently kept the connection alive with SSE keep-alive comments. These reset the httpx
  read (idle) timeout but are not yielded as chunks by the SDK, so the check never ran. [I: the
  keep-alive mechanism is inferred from the behaviour; reproduced below.]
- Fix (`src/model.py::_stream_completion`): a watchdog `threading.Timer` closes the HTTP response at the
  deadline regardless of what arrives, and the resulting error is reported as `TimeoutError`.
  - Verified [M] against a fake SSE server that sends one chunk and then only `: keep-alive` comments every
    1 s (which defeats a 3 s idle timeout): the deadline fires at 5.1 s with a 5 s cap.
  - Live probe through the config still OK.
- `llm_timeout` lowered 1200 → **600 s** in all configs. The slowest healthy call observed so far is
  110 s for ~16k reasoning tokens, so 600 s covers the 65,536-token budget with margin.
- Provider reliability, as far as observed: 3 abnormal calls out of ~20 in the r3/r4 attempts (a 1200 s
  hang, a 6164 s keep-alive hang, a 180 s idle stall). This is itself a speed factor worth reporting:
  without the watchdog, a single bad call dominates a run's wall time.
- r4 stopped; relaunching as **r5** from a new snapshot.

## 2026-09-30 19:40 — Section 2 work done while r4 ran (dev only; not in the r4 snapshot)

- 2.3: `targets/factory.py` has `Checkout` and the abstract `CompileDBTargetBase` (prepare,
  relpath_of, in_scan_scope, prefetch). `CompileDBTarget` implements it. `csa.py` dispatch, gen worker
  gating, and prefetch now use `isinstance(target, CompileDBTargetBase)`. The only remaining
  `"compiledb"` string is the registry key. A new target kind needs no backend edits.
- 2.4: prompts no longer hardcode the kernel:
  - `patch2pattern.md`, `patch2pattern-general.md`, `patch2checker.md`, `label_commit.md` use
    `{{project_description}}`; `check_report.md` uses `{{project_description}}` +
    `{{project_feasibility}}`.
  - Kernel NULL-feasibility guidance (DT/ACPI/probe/RCU) moved verbatim to
    `knowledge/feasibility-linux.md`; new `knowledge/feasibility-generic.md` covers C libraries.
  - `global_config.project_description` / `project_feasibility`: config `project.description` /
    `project.feasibility`, else a default by target type (linux → "the Linux kernel" + linux
    feasibility, so kernel runs keep kernel wording).
  - Few-shot examples carry `meta.yaml` (`project: the Linux kernel`) and are labelled
    "(from the Linux kernel; its functions and APIs are specific to that project)".
  - Before the change [M]: no kernel API names in any generated curl checker (9 files) and no
    "kernel"/"linux" in any generated pattern/plan. The kernel framing did not visibly leak into
    generation; its expected impact is on *triage* feasibility reasoning (refine), to be measured.
- Upstream bug fixed: refine's triage passed `patch=checker_data.pattern`, so `check_report` never saw
  the fix patch. `reduce_report` read its template via a cwd-relative path; now uses
  `prompt_template_dir`.
- Generic scan: `checker_scan.scan()` for compile-DB targets (`scan_compiledb`) scans the whole project
  with each checker (refined `checker1.cpp`, else the best perfect gen attempt from `ranking.txt`). It
  writes `scan-reports-<n>/main-report`, the layout `triage_report` reads, plus `scan_summary.json`.
  The kernel path is unchanged.
- Third build system for 2.2: **Lua** (plain hand-written Makefile, in-source build) — `configs/lua.yaml`:
  `make -C {src} clean` then `intercept-build ... make -C {src} CC={clang} lua`. Verified [M] on Lua
  HEAD `0b29f408`: 34 compile entries in 7.6 s. (Cloned at `targets/lua`; setup ran briefly while r4
  was in an LLM wait.)
- Tests: `src/tests/test_prompts.py` (4) — generic prompts have no "Linux kernel" outside the labelled
  examples, and no unfilled placeholders; linux keeps kernel wording + DT/ACPI guidance; explicit
  description; example labels. **20/20 unit tests pass** [M].

- Note: the r5 snapshot (`617958dc3ebefc42`) includes the section 2 changes above (project-aware prompts,
  capability dispatch, generic scan), so both r5 variants use the new prompts.
- 19:40: Lua pre-check ran concurrently with r5-A-curl (~1 min of light `make` on 8 revisions, during
  the run's LLM phase). Disclosed as a minor timing disturbance.

## 2026-09-30 21:00 — Review decisions (user)

The user reviewed `docs/REVIEW_CHECKLIST.md` after a per-item explanation of options and effects:
- **All items follow my recommendations**, except as noted:
  - A1: strict scoring is the main metric, legacy reported alongside.
  - A2: measure the callee blind spot before fixing it.
  - A4: upstream-style baseline (fresh configure).
  - A6: report end-to-end + replay + per-operation timings.
  - A8: keep settings for the A/B; thinking-off as a separate experiment.
  - A9: keep thresholds, marked unvalidated.
  - B1–B7 accepted; B6 means a local venv + lock file before committing.
  - C: commit on a branch after review; rotate the key after the benchmark.
- **A3 (baseline build cost model): accepted** as is. The conservative-speedup caveat goes in the paper.
- **A5 (PCH confound): neutralise ASAP.**
- **A7 (benchmark set): grow it, including other C/C++ projects** ("I still have a lot of time left").

## 2026-09-30 21:02 — r5 preliminary result (curl only) and r5 stopped for A5

r5 finished both curl runs before being stopped [M, `bench/report.py bench/runs/r5-A-curl bench/runs/r5-B-curl`]:

| | baseline (A) | optimized (B) |
|---|---|---|
| wall | **59.9 min** | **13.8 min** (4.3× faster) |
| commits with perfect checker (strict) | 5/6 | 4/6 |
| LLM calls / summed LLM time | 41 / 43.4 min | 46 / 40.5 min |
| syntax-repair LLM calls | 11 | 7 |
| setup per validation (mean) | 56.5 s | 0.0 s (cached/prefetched) |
| plugin build (Syntax Repair step, median) | 24.3 s | 9.7 s |
| analysis per side (mean) | 7.56 s | 7.88 s |
| peak RSS | 969 MB | 1229 MB |

- Scoring: across 22 validated attempts, 0 were valid under legacy but not strict. 9 valid under both,
  13 under neither. On curl so far, strict scoring changed no verdict: the checkers that pass hit the
  patched function.
- One B attempt (c53420e427 checker_00) crashed clang, correctly scored (-2,-2), and the next attempt
  succeeded.
- **The repair-call gap (11 vs 7) is where the A5 PCH confound would show**, so the numbers above are
  preliminary. r5-A-sqlite (a confounded baseline) was stopped ~12 min in (`r5-A-sqlite-ABORTED`).

## 2026-09-30 21:05 — A5 neutralised: text preamble for non-PCH builds

- `PluginBuilder(preamble=True)` (default; config `plugin_preamble`): when no PCH is used, the compile
  `-include`s the *same* header list as plain text. Every build mode therefore accepts exactly the same
  checker code, and only build cost differs. `preamble=False` reproduces upstream's literal behaviour.
  The cache key now includes opt level, PCH, and preamble mode.
- Verified [M]: a real generated checker with **all its `#include` lines stripped**:
  - baseline (-O3, no PCH, preamble): compiles (rc 0, 31 s);
  - optimized (-O1, PCH): compiles (rc 0);
  - upstream-literal (no PCH, no preamble): fails (rc 1).
- The baseline variant uses the default (`preamble: true`), so repair behaviour is identical across
  variants.

## 2026-09-30 21:08 — B6: local venv; torch made optional (startup 5.6 s → 2.8 s)

- torch was imported on every run (`agent.py` → `checker_example.py`), but is only needed for
  embedding-based example sampling (`--sample_examples`, off by default). The imports are now lazy,
  at the two call sites. Measured [M]: `import agent` 5.75 / 5.46 s → 2.88 / 2.76 s; `torch` is no
  longer in `sys.modules`.
- torch moved to `requirements-optional.txt`. Added `pyyaml`, `httpx`, `pydantic` (imported directly),
  and `setuptools` (tree-sitter 0.21.3 builds grammars via distutils, removed from the stdlib in Python 3.12).
- Local env: `.venv/` (Python 3.14.4, **128 MB** vs the previous attempt's 4.8 GB venv) plus
  `requirements-lock.txt` (61 pinned packages). Verified [M]: 20/20 unit tests pass and a live LLM probe
  works in it. The benchmark scripts now use `.venv/bin/python`.
- Consequence: benchmark runs from now on (r6+) use the new env. r5's curl pair used the old venv; the
  difference is ~3 s of import time per run.

## 2026-09-30 21:40 — A7: benchmark grown to 45 commits in 7 projects, including C++; C++ support

New projects (cloned to `/home/faris/RA-MrYudis/Knight/targets/`), each with a config-only recipe:

| Project | Language | Build system (recipe) | Commits | Notes |
|---|---|---|---|---|
| curl | C | CMake | 8 (+2) | +466c06cf70 NPD (urlapi), +c4cb67692d IO (smb) |
| SQLite | C | autosetup + make via intercept-build | 7 (+2) | +720d3afa7e IO (btree), +2f5d281796 IO (func) |
| Lua | C | plain Makefile, in-source, intercept-build | 4 | UAF, UBI, IO (shift), Misuse |
| libxml2 | C | **Meson** (`meson setup` only; config.h/xmlversion.h generated at setup) | 7 | ML, NPD×2, Double-Free, UAF, OOB (in a macro), Misuse (div-by-zero) |
| libgit2 | C | CMake (the previous attempt's options) | 11 | **Exactly the previous attempt's commit list**, for direct comparison |
| re2 | **C++** | CMake + `CMAKE_POLICY_VERSION_MINIMUM=3.5` | 4 | NPD×3, OOB. Pre-2023-05 revisions (no abseil installed) |
| yaml-cpp | **C++** | CMake | 3 | OOB (empty-stack `top()`), Buffer-Overflow, Misuse |

- 5 build systems in total: CMake, autosetup+make, plain Makefile, Meson, plus C++ CMake projects.
- Candidates come from `bench/mine_commits.py`: generic git-metadata criteria (keyword in subject,
  source files only under given dirs, ≤ N changed source lines) with a keyword-based type guess. Every
  selected commit's diff was read and the label checked (e.g. re2 `fadc34500b` "DFA destructor bug" →
  NPD: destructor loop on NULL storage).
- Excluded:
  - re2 `969c3bd5a8`: fix only under `#ifdef RE2_HAVE_THREAD_LOCAL`.
  - yaml-cpp/re2 commits that are logic-only (formatting, parsing semantics) and so not in the paper's
    bug-type taxonomy.
- Pre-check [M] (`bench/precheck-*.jsonl`): every commit's library source file has compile entries on
  both sides. Test files have none (tests disabled in every recipe), which affects 1 curl, 3 yaml-cpp,
  and 1 libgit2 commit (an extra test file each) plus libgit2 d6486af3's `src/cli/opt_usage.c`
  (CLI disabled). Those files are simply not validated.
- Setup issues found and fixed:
  - Old re2 revisions fail with CMake 4.2 ("Compatibility with CMake < 3.5 has been removed").
    Fix: `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`, after which all 4 configure (15 s each).
  - libgit2 runs from a fresh local clone (`targets/libgit2`, cloned from the previous attempt's
    `target_example/libgit2`), so worktrees never touch the previous attempt's repo.
- Tooling: Meson 1.12.1 + Ninja in `.venv` (`requirements-targets.txt`, build tools for targets only).

C++ support (code):
- `tools.py`: patch context (buggy function code for the prompt) now covers
  `.c .h .cc .cpp .cxx .hh .hpp .hxx`; before, only `.c`/`.h`, so C++ patches got no function context.
- `direct_analysis.py`: C++ sources are analyzed with the `clang++` driver (reliable libstdc++ include
  paths).
- `kparser/kfunction.py`: function names for C++ declarators (`qualified_identifier`,
  `field_identifier`, `destructor_name`, `operator_name`, reference declarators). Before, C++ methods
  were unnamed (`<anon@646>` in the re2 smoke test). New test: `Prefilter::FromRegexp`,
  `DFA::~DFA`, `Counter::get`, `operator==` extracted. **21/21 unit tests pass.**
- Smoke [M]: re2 ca11026a03 validation with an existing checker; both `.cc` files analyzed on both
  sides with no errors, ~8.3 s per side.

## 2026-09-30 21:45 — Deterministic replay started (curl, 22 checkers from r5)

- Input: all 22 compiled checkers from r5-A-curl and r5-B-curl (`bench/replay-pairs-curl.txt`). Each is
  built once (explicit, as the successful repair compile) and validated, in baseline mode, then in
  optimized mode (`bench/replay/replay-curl-{A,B}`).
- Runs from the working tree (single process per mode), so no code edits until both finish.

## 2026-09-30 21:50 — Deterministic replay result (curl, 22 checkers): 5.4× faster, identical verdicts

Same 22 compiled checkers (all of r5's curl attempts), each built once and validated on its commit
[M, `bench/replay/replay-curl-{A,B}/`]:

| | baseline (A) | optimized (B) |
|---|---|---|
| workers | 1 | 4 |
| wall | **1698.8 s** | **312.4 s** (5.4×) |
| sum of build time | 402.9 s | 473.4 s (4 concurrent builds + one-time PCH) |
| sum of validation time | 1295.7 s | 749.9 s |
| median plugin build | 16.9 s (-O3, text preamble) | 7.6 s (-O1 + PCH) |
| median validation | 57.6 s | 19.9 s |
| median setup inside validation | 44.9 s (fresh configure) | 0.01 s (cached revision) |

- **All 22 (TP, TN) verdicts are identical between modes** (1.2 acceptance: parallel + cached ==
  serial + fresh). This includes a checker crash (-2,-2), which is reproduced in both.
- The summed build time is *higher* in B: concurrent builds share CPU and the first build pays the
  PCH. Wall time is what improves. The per-build median still halves.
- The baseline uses the A5-neutralised preamble, so both modes compile identical code.

## 2026-09-30 21:52 — Refine E2E on curl started (plan 1.5)

- Input: copy of r5-B-curl results (`e2e/refine-curl/`, 13 `KN-*` checkers; 4 valid under strict:
  bc440a89-0 IO, a0f08d69-2 ML, c53420e4-1 Misuse, f2a15357-0 NPD). Config `e2e/refine-curl.yaml`
  (= `configs/curl.yaml` with this result dir).
- Command: `.venv/bin/python src/main.py refine --config_file=e2e/refine-curl.yaml
  --checker_dir=e2e/refine-curl --max_tries=3`. Scans curl HEAD `lib/`, triages, and repairs FPs.

## 2026-09-30 22:05 — Refine E2E pass 1 (curl, default thresholds): 4/4 "Perfect", triage not exercised

[M, `e2e/refine-curl.log`] The 4 valid checkers were refined. The 9 invalid ones (strict TP/TN not both > 0)
were skipped by refine's validity filter.
- Every refine scan covered curl HEAD `bb348b35e8` `lib/`: **194 files, 0 failed, 0 crashed,
  62.7–65.5 s per whole-project scan** (8 jobs). The previous attempt's serial CMake scan took 11–14 min
  for ~221 libgit2 files → plan 1.4 evidence.
- Reports at HEAD: f2a15357 NPD 0, a0f08d69-2 ML **1**, c53420e4-1 Misuse 0, bc440a89 IO 0. All are
  ≤ `perfect_report_threshold` (3) → status "Perfect", no triage/repair. Zero or near-zero reports at HEAD
  is expected: HEAD contains every fix.
- So pass 1 does not exercise the triage → FP-repair → re-validation path, which is what plan 1.5 is about.

## 2026-09-30 22:12 — Refine E2E pass 2 (threshold 0): reproduced "Failed to validate on objects"; root cause found

Setup: only KN-Memory-Leak-a0f08d69-2 (fresh copy), `perfect_report_threshold: 0`, `max_tries 2`
(`e2e/refine-curl-t0*`).
- Flow [M, `e2e/refine-curl-t0.log`]: scan (1 report, `lib/cf-socket.c:1048` "Resource cleanup after
  struct clear may leak") → triage `check_report` 35.2 s → FP → `repair_FP` 104.1 s → syntax check OK →
  **"Failed to validate on objects!"**. Attempt 2 is the same (16.8 s triage, 115.0 s repair, same failure).
  This is exactly the previous attempt's 12/12 and 15/15 failure mode.
- Root cause [M]: `extract_reports` converts report HTML with `html2text(html)`, which wraps lines at
  78 columns. The long worktree path was split:
  `File:| /home/.../targets/.knighter-` / `work/curl/src/bb348b35e84c/lib/cf-socket.c`. The regex
  `File:\| (.+)` then captured a truncated path that maps to no source file, so the re-scan object
  list was empty, `_validate_on_objects` found no "killed" object, and it reported failure. No object was
  ever re-scanned (no scan between repair and failure in the log).
- The previous attempt most likely failed the same way: its libgit2 paths (`.../target_example/libgit2/
  src/libgit2/...`) are long enough to wrap. [I: not verifiable from its logs.]
- Fix: `html2text(html, bodywidth=0)` (no wrapping) in `ClangBackend.extract_reports` and
  `checker_scan.collect_reports`. Verified on the same report HTML [M]: objects `[]` → `['lib/cf-socket.c']`.
  Side benefit: report markdown sent to the LLM no longer has paths and code lines broken mid-token.
- Pass 2 rerun with the fix: `e2e/refine-curl-t0-run2*`.

## 2026-09-30 22:22 — Refine E2E pass 2 rerun with the fix: full refine loop works (plan 1.5 ✔)

[M, `e2e/refine-curl-t0-run2.log`, `e2e/refine-curl-t0-run2/KN-Memory-Leak-a0f08d69-2/`]
1. Whole-curl scan at HEAD: 194 files, 0 failed, 1 report (`lib/cf-socket.c`), 85.5 s.
2. Triage `check_report`: FP (16.8 s).
3. `repair_FP`: new checker code (93.2 s), which compiles.
4. **Re-scan of the report's object `lib/cf-socket.c`**: 1 file, 0 reports (8.6 s) → "Object lib/cf-socket.c
   doesn't have bug!" (killed FP).
5. Re-validation on the original commit a0f08d6975: **strict TP=1 TN=1** (legacy 1/1). The refined
   checker still detects its bug.
6. Status **Refined (code changed)**. Attempt 2 rescans all of curl: 0 reports → Perfect.
- The refinement is semantic, not cosmetic (`refinements/attempt_1_diff.patch`): it adds a base-symbol
  helper and treats `Curl_peer_link()` after the struct clear as re-initialisation, so a later
  `Curl_peer_unlink()` is no longer "cleanup after clear". Note (section 3): the checker names curl APIs
  directly.
- Before the fix, the identical flow failed twice with "Failed to validate on objects!" (22:09, 22:12).
- Observed tooling issue: my shell watchers used `pgrep -f <pattern>`, which also matched the watcher's
  own command line, so they never exited (one was stopped by the 30 min background limit). No effect on
  results.

## 2026-09-30 22:47 — Generic scan + triage E2E on curl

Checkers: the 4 valid curl checkers (bc440a89 IO, c53420e4-1 Misuse, f2a15357 NPD, and the *refined*
a0f08d69-2 ML) plus the invalid f7d4e11f-0 (TP1/TN0) as a negative control (`e2e/scan-curl/`).

Bugs found and fixed while doing it:
1. `scan_compiledb` picked `checker-final.cpp`, which gen leaves **empty (0 bytes)** until refinement
   writes it. The empty file compiled into a plugin that registers no checker, and all 194 analyses then
   failed with "no analyzer checkers or packages are associated with 'custom.SAGenTestChecker'".
   The -999 sentinel (review fix #1) reported this; upstream semantics would have silently
   reported 0 bugs. Fix: use the non-empty final checker, else `checker-repaired.cpp` (the validated
   code). The log of the bad run is kept as `e2e/scan-curl-head-emptyfile-bug.log`.
2. Defence in depth: `PluginBuilder.build` now rejects code without `clang_registerCheckers` as a build
   error (goes to syntax repair) [M: empty checker → rc 1 with that message]. Validation classifies
   "no analyzer checkers ... associated" as a per-checker failure (-3), not an infrastructure error.
3. Scan passed no `jobs`, so the analysis used run_checker's default of 32 threads on 16 cores. It now uses
   `analysis_jobs` (8).

Results [M]:
- **curl HEAD** (`e2e/scan-curl-head.log`): each checker 194 files, 0 failed, **0 reports** (51 s per
  checker, whole run 208 s). Expected, since HEAD contains every fix. f7d4e11f-0 was correctly skipped (invalid).
- **curl 8.10.0** (Sep 2024; predates all these fixes) (`e2e/scan-curl-8_10_0.log`; revision configured
  on demand in 57.7 s): 169 files per checker, 0 failed. Reports: IO 1, ML 0, Misuse 1, NPD 3.
- **Triage** (`main.py triage`, 109 s, `e2e/scan-curl/triage_report.csv`): 3 files triaged (triage takes
  the first report per file). **All 3 judged "Bug"**, and each lies in the function the later fix changed:

  | Checker | Report (8.10.0) | Triage | Later fix changed |
  |---|---|---|---|
  | bc440a89 IO | `lib/mime.c:523` "integer overflow in base64 size calculation" (FUNCTIONNAME "unknown") | Bug | `encoder_base64_size` (bc440a89d4) |
  | c53420e4 Misuse | `lib/vtls/openssl.c:2192` in `ossl_verifyhost`, "ASN1 data used as NUL-terminated string" | Bug | `ossl_verifyhost` (c53420e427) |
  | f2a15357 NPD | `lib/easy.c:1240` in `curl_easy_recv`, "Missing NULL check for argument 'n'" | Bug | `curl_easy_recv` (f2a1535712) |

  Given only the older release, the generic scan + triage **rediscovered the three real bugs that curl
  later fixed** (all true positives). This is end-to-end evidence for scan mode and the generalised triage
  prompt on a non-kernel project. Caveat: these are the same bugs the checkers were generated from, so
  this shows the pipeline works, not that it finds *new* bugs.

## 2026-09-30 23:00 — Launched benchmark r6: 45 commits, 7 projects, both variants

- Snapshot `bench/snapshots/r6` (`35b04b2d0c6993a7`). It includes: A5 preamble neutralisation, local
  `.venv`, lazy torch, C++ support, the html2text no-wrap fix, the empty-checker guard, and scan jobs.
- 14 sequential runs, per project baseline then optimized (adjacent so provider-load drift affects
  both): lua, re2, yaml-cpp, libxml2, sqlite, curl, libgit2. `checker_nums: 3`, strict scoring, same
  model/settings in both variants. Driver output: `bench/run_all_r6.out`.
- Estimated duration ~9 h (r5 curl: baseline ~10 min/commit, optimized ~2.3 min/commit).
- r5 remains as the preliminary (A5-confounded) curl pair. The r6 curl numbers supersede it.

## 2026-10-01 04:49 — r6 aborted: 5.6 h machine suspend + Lua analysis bug; fixes

r6 status at 04:49 [M]: still in its first run (r6-A-lua), 1 commit done. The gen process had only
**11 min 47 s** of elapsed process time (`ps etime`), but the log stopped at 23:09:58 and the wall clock
read 04:49. **The machine (WSL VM) was suspended for ~5.6 h**, most likely a laptop/Windows sleep. An LLM
request open at the time was dead after resume. r6-A-lua's wall-clock timings include the sleep and are
unusable. r6 stopped; kept as `bench/runs/r6-A-lua-ABORTED`.

**Bug: Lua analysis always failed** ("clang: fatal error: cannot specify -o when generating multiple
output files"). The first Lua commit therefore ended as TargetSetupError (-20) after its LLM stages.
- Cause [M]: intercept-build entries for Lua have an absolute `file` but a *relative* source in
  `command` (`... -o lapi.o lapi.c`, `directory` = source dir). `analyzer_argv` dropped the source only
  when the argument equalled `entry["file"]` verbatim, so clang got `lapi.c` twice.
- This is the code review's "uncertain" item from 17:10. I wrongly dismissed it after checking only curl
  and SQLite, whose entries use absolute paths. Correction to that log entry: it does apply, to Lua.
- Fix: drop any non-flag argument that resolves (relative to `directory`) to the entry's source file.
  New `src/tests/test_direct_analysis.py` (4 tests: Lua-style relative source, absolute arguments,
  relative `file`, C++ driver). **25/25 unit tests pass.**

**The pre-check was too weak.** It only checked that compile entries *exist*. `bench/precheck.py` now also
runs `clang --analyze` with a do-nothing checker (`bench/minimal_checker.cpp`) on every patched file on
both sides (`ANALYSIS_FAILED` status). Re-run on all 7 projects [M, `bench/precheck2-*.jsonl`]:
- Lua 4/4 analyzable (after the fix); curl, SQLite, libxml2, re2 all analyzable; yaml-cpp analyzable
  (only test files missing).
- **libgit2 `93b16df1`: the buggy parent does not compile** — `revparse.c:961`
  `git_object_free(revparse->from)` "... is not a structure or union". The "fix" commit corrects the
  identifier to `revspec`. No checker can ever be validated on it, since the buggy side cannot be
  analyzed. **This explains the previous attempt's TP=0 / -10 on 93b16df1 as unanalyzable, not a
  generation-quality failure.** Removed from the benchmark (libgit2 10 commits; total **44**).

Suspend handling:
- Prevention: `bench/keep_awake.ps1`, started by `bench/run_all.sh` via `powershell.exe` for the whole
  benchmark and killed on exit (trap). It calls `SetThreadExecutionState(ES_CONTINUOUS |
  ES_SYSTEM_REQUIRED)` every 60 s: Windows' equivalent of `caffeinate`; no admin rights, released when
  the process exits. Does **not** prevent lid-close or manual sleep. Verified it starts and stays alive.
- Detection: `run_bench.py` records `awake_seconds` (monotonic, which does not advance during suspend),
  `suspended_seconds` = wall − awake, and `suspended: true` when > 60 s. Such runs are excluded from speed
  claims.
- `model.py` measures call durations and the watchdog deadline with `time.monotonic()`. Wall-clock `ts`
  stays as the timestamp.
- 05:00: relaunched as **r7** (44 commits, snapshot in bench/run_all_r7.out).
- Correction to the line above: r7 actually started at **07:18:01** (`bench/run_all_r7.out`), not 05:00. About 2.5 h passed between the 04:49 investigation and the launch with little process time used, probably another suspend before the keep-awake helper existed. [I]

## 2026-10-01 07:36 — r7 health check (after a Claude session restart)

- r7 survived the agent session restart (nohup). Run 1/14 (r7-A-lua) at 18 min: process elapsed time ==
  wall time (no suspend), keep-awake helper alive.
- Lua analysis fix confirmed in production [M]: 22974326 UAF perfect (strict 1/1, attempt checker_02),
  efddc230 UBI perfect (checker_00). 22 LLM calls, 0 failed, 868 s summed LLM time. No TargetSetupError.
- 08:37 health [M]: r7-A-lua 41.7 min 3/4, r7-B-lua 7.6 min 4/4 (suspended 0 s both). r7-A-re2 running, 3 commits, 28 calls, 0 failed, 0 setup failures. 2 failed calls so far (1 stall "read operation timed out", 1 "empty response content"), both retried successfully. Keep-awake helper alive.
- 09:38 health [M]: done: lua A 41.7m 3/4, lua B 7.6m 4/4, re2 A 31.9m 3/4, re2 B 12.4m 3/4, yaml-cpp A 44.0m 2/3; r7-B-yaml-cpp running. 0 s suspended in all, 0 setup failures, 2 failed-then-retried calls total. C++ projects work end to end (re2 3/4 in both variants).
- 10:40 health [M]: yaml-cpp B done 15.3m 1/3 (A was 44.0m 2/3). r7-A-libxml2 running (Meson), 5/7 commits, 45 calls, 0 failed, 0 setup failures. All finished runs 0 s suspended; keep-awake alive.
- 11:41 health [M]: libxml2 (Meson) done: A 65.7m 4/7, B 25.7m 5/7 (B: 2 failed calls, retried). r7-A-sqlite running (2/7). 8/14 runs done, all 0 s suspended, 0 setup failures; keep-awake alive.
- 12:42 health [M]: sqlite A done 73.4m 3/7 (82 calls). r7-B-sqlite running. 9/14 done, all 0 s suspended, 0 setup failures; keep-awake alive.
- 13:50 health [M]: sqlite B done 26.1m 2/7 (A 73.4m 3/7). r7-A-curl running 4/8. 11/14 runs started, all finished runs 0 s suspended, 0 setup failures; keep-awake alive.

## 2026-10-01 13:55 — Interim r7 aggregate (5/7 projects) + commit preparation

`bench/aggregate.py r7` (new; numbers only from run artifacts) [M]:

| Project | Commits | Wall A (min) | Wall B (min) | Speedup | Perfect A | Perfect B | LLM calls A/B | Repair calls A/B |
|---|---|---|---|---|---|---|---|---|
| lua | 4 | 41.7 | 7.6 | 5.5× | 3/4 | 4/4 | 44/21 | 19/5 |
| re2 (C++) | 4 | 31.9 | 12.4 | 2.6× | 3/4 | 3/4 | 30/40 | 6/10 |
| yaml-cpp (C++) | 3 | 44.0 | 15.3 | 2.9× | 2/3 | 1/3 | 51/43 | 27/22 |
| libxml2 (Meson) | 7 | 65.7 | 25.7 | 2.6× | 4/7 | 5/7 | 59/61 | 14/12 |
| sqlite | 7 | 73.4 | 26.1 | 2.8× | 3/7 | 2/7 | 82/85 | 34/34 |
| **subtotal** | 25 | 256.7 | 87.0 | **3.0×** | 15/25 | 15/25 | 266/250 | 100/83 |

- Success is equal across variants (15/25 each), so the speedup does not trade off quality.
- With the A5 preamble neutralisation, repair calls are now similar (100 vs 83). In r5, with the
  confound, they were 11 vs 7 on 6 commits.

Commit preparation [M]: what will be committed is 240 KB (scripts, configs, commit lists, prechecks, docs).
Ignored: `bench/runs` 11 GB, `bench/replay` 1.7 GB, `bench/snapshots` 347 MB (contains key copies),
`llm_keys.yaml`, `.venv/`. Secret scan (exact key string) over all untracked files and the full diff:
**0 hits**. Disk: 818 GB free. Plan: also commit a slim evidence bundle (per-run summary,
llm_calls.jsonl, per-attempt 06/07 JSON, rankings) so every reported number is auditable from the repo.

## 2026-10-01 15:30 — Sections 0–2 committed locally (branch general-c-speed, not pushed)

- Verified the working tree is identical to the r7 snapshot (`diff -rq` of `src/` and `prompt_template/`: no
  differences), so the commits are exactly the benchmarked code.
- 7 commits on `general-c-speed` (e3174ef..e07b55f): backend/plugins, targets, strict scoring,
  pipeline, LLM layer + prompts, requirements, bench + docs. Secret scan of `git log -p main..HEAD`
  for the key string and an `oc_sk_` pattern: 0 hits. Push waits for the results report (user decision).
- User decision (15:2x): section 3.1 via **A** (role-based checkers through the existing stages + a
  deterministic hardcoded-identifier check) **and B** (one new LLM step that ports roles to a target
  project). 3.3 bundles need no LLM. Section 3 work proceeds on top of these commits; CPU-heavy runs wait
  for r7 to finish.

## 2026-10-01 15:45 — 3.1-A building blocks: roles header, roles block, hardcoded-identifier check

- `src/knighter_include/knighter/roles.h` (header-only): `knighter::callIsRole(Call, role)`,
  `isRole`, `declIsRole`, `roleNames`. Reads `{role: [names]}` JSON from `$KNIGHTER_ROLES`, loaded
  once; without a file every query is false (the checker is inert, not crashing).
- Roles travel *inside* the checker source as a `/* KNIGHTER_ROLES {...} */` block, so no pipeline
  plumbing is needed: `PluginBuilder` extracts it to `roles.json` next to the plugin (an invalid block is
  a build error for syntax repair) and adds `-I src/knighter_include`. The header contents are part of
  the cache key. `direct_analysis` exports `KNIGHTER_ROLES` from the plugin dir (an explicit env or
  `roles_file` wins). Porting = supplying another roles file.
- `src/checker_lint.py` (deterministic): string literals outside comments and the roles block that are
  identifier-shaped, not standard names, and carry `_`, camelCase or digits. Role-name arguments of
  `knighter::` queries are exempt. The standard-name allowlist (`knighter_include/stdlib_names.txt`,
  3488 names) comes from `clang -E` of 36 libc/POSIX headers + 18 libstdc++ headers.
- **Baseline measurement [M]:** **14/22** previous-attempt libgit2 checkers and **89/123** r7 checkers so far
  hardcode project identifiers (e.g. `git_vector_insert`, `Curl_peer_unlink`, `ASN1_STRING_get0_data`,
  `curl_url_dup`). This is the metric 3.1-A must reduce.
- Tests: `src/tests/test_checker_lint.py` (5). Suite total 30.

## 2026-10-01 16:00 — Section 3 code (3.1-A, 3.1-B, 3.3) written; unit-tested only (no CPU-heavy runs during r7)

3.1-A role-based generation (`role_based_checkers: true`, default off, so r7-style runs are unchanged):
- `knowledge/roles-pattern.md` (patch2pattern: state the pattern in roles + list each role's names in
  this patch) and `knowledge/roles-checker.md` (pattern2plan, plan2checker, repair_FP, repair_syntax:
  `#include "knighter/roles.h"`, the query API, no project names in logic, and a `KNIGHTER_ROLES` block with
  a project-independent description per role). `agent._roles()` inserts the guidance before
  `# Formatting`; verified that it is inserted when enabled and changes nothing when disabled.
- Roles block format extended: each role is `[names]` or `{"names": [...], "description": "..."}`
  (descriptions are what porting needs). `parse_roles_block` normalises; `roles.json` stays
  `{role: [names]}`.
- New LLM stage `repair_roles` (`prompt_template/repair_roles.md`). In gen, after a successful syntax
  repair, `_enforce_roles` always records `08_roles.json` (initial/final hardcoded identifiers + roles),
  and for role-based runs does up to `roles_repair_attempts` (2) rounds of repair_roles → compile →
  re-check. It never rejects a working checker; leftovers are recorded.

3.3 bundles (`src/checker_bundle.py`, `main.py export --checker_dir=... [--out_dir=...]`), no LLM:
- Per valid KN-* checker: `checker.cpp`, `plugin.so` (KNighter's clang), `roles/<source>.json`,
  `manifest.yaml` (source project/commit, scores, pattern, roles with descriptions,
  `hardcoded_identifiers`, `portable` flag, clang version, KNighter revision), `run_bundle.py` +
  `knighter_analysis.py`, rebuild kit (`CMakeLists.txt` with `find_package(Clang)` for shared
  libclang-cpp or static component libs, `include/knighter/roles.h`, `utility.{h,cpp}` vendored from
  `llvm_utils`, identical to the LLVM-tree copies [M]), README.
- `direct_analysis.py` is now stdlib-only (loguru optional) and ships verbatim as the bundle runtime, so
  the bundle and KNighter build identical analyzer commands. Verified importable without loguru.

3.1-B roles porting (`src/role_porting.py`, `main.py port_roles --bundle_dir=...` with the *target's*
config), one new LLM stage `port_roles` (temperature 0.01):
- Deterministic candidate extraction from the target's headers (function declarations + function-like
  macros; test/doc/example/fuzz dirs and standard names excluded) and per-role ranking by word overlap
  with role name, description, and source names (source project prefixes ignored). Top 40 per role go to
  the LLM, which must choose only from the candidates or return none.
- Validation: names not among the candidates are dropped and reported. Output: `roles/<target>.json` plus
  `ports/<target>.{json,prompt.md}` (offered candidates, mapping, dropped, rationale).
- New `tools.extract_json_block`.
- Tests: `test_role_porting.py` (3; extraction skips tests/standard/definitions; allocator and
  deallocator rank first on a libxml2-style header), `test_checker_lint.py` (5). **Suite: 33/33 pass.**

Pending E2E (after r7, CPU): compile+run a role-based checker (roles.h + env), export curl bundles and
run one standalone on another project, a role-based gen run to measure hardcoded-identifier reduction and
success rate vs r7, then port roles and scan a different project (3.4).

## 2026-10-01 16:05 — Evidence that needs no CPU: 0.2 audit, 2.1, 2.3, 2.5

- **0.2 [M]** `bench/audit_plugins.py` over every finished r7 run (12 runs, libgit2 still running): for
  each validated attempt, the plugin recorded in `06_validation_details.json` was built from a
  `checker.cpp` byte-identical to the attempt's `05_repaired_code.cpp`: **114/114 exact matches, 0
  mismatches, 0 missing**, including the 4-worker optimized runs.
- **2.1 [M]** `src/tests/test_target_registry.py`: a misspelled `target_type` raises
  `ValueError: Unknown target_type ...`; registry = {linux, v8, compiledb}.
- **2.3 [M]** no `_target_type ==` / `"compiledb"` branches in `csa_compiledb.py`, `checker_gen.py`, or
  `checker_scan.py` (dispatch is `isinstance(target, CompileDBTargetBase)`).
- **2.5 [M]** `grep -rni libgit2 src --include=*.py` (excluding tests): **0 hits**.
- Unit suite: 35/35.

## 2026-10-01 16:55 — r7 complete (43 commits, 7 projects) + audits

Correction: the r7 benchmark has **43** commits, not 44 (curl 8 + sqlite 7 + lua 4 + libxml2 7 + libgit2 10
+ re2 4 + yaml-cpp 3).

`bench/aggregate.py r7` [M]:

| Project | Commits | Wall A (min) | Wall B (min) | Speedup | Perfect A | Perfect B | LLM calls A/B | Repair calls A/B |
|---|---|---|---|---|---|---|---|---|
| lua | 4 | 41.7 | 7.6 | 5.5× | 3/4 | 4/4 | 44/21 | 19/5 |
| re2 | 4 | 31.9 | 12.4 | 2.6× | 3/4 | 3/4 | 30/40 | 6/10 |
| yaml-cpp | 3 | 44.0 | 15.3 | 2.9× | 2/3 | 1/3 | 51/43 | 27/22 |
| libxml2 | 7 | 65.7 | 25.7 | 2.6× | 4/7 | 5/7 | 59/61 | 14/12 |
| sqlite | 7 | 73.4 | 26.1 | 2.8× | 3/7 | 2/7 | 82/85 | 34/34 |
| curl | 8 | 90.5 | 22.9 | 3.9× | 5/8 | 6/8 | 62/57 | 11/9 |
| libgit2 | 10 | 93.8 | 25.3 | 3.7× | 6/10 | 6/10 | 79/81 | 19/18 |
| **total** | 43 | **441.0** | **135.2** | **3.3×** | **26/43** | **27/43** | 407/388 | 130/110 |

- All 14 runs: `suspended_seconds` 0 (keep-awake worked; the helper exited with the driver).
- Summed LLM time A 321.9 min, B 334.1 min. The LLM work is the same; B overlaps it across 4 workers.
- **0.2 audit, all r7 runs [M]: 152/152** validations used the plugin built from exactly the scored checker.
- **Strict vs legacy over 152 attempts [M]:** 51 valid under both, **5 legacy-only**, 2 strict-only, 94 neither.
  - The 5 legacy-only cases are all "still reports in the patched function after the fix" (curl 466c06cf70
    14→1 and 14→1, re2 ca11026a03 2→2/4→2 twice, lua 22974326 1→1). Legacy credited TN because the count
    dropped below 5. In the lua case, legacy credited TN from *another* patched file (`lapi.c`) that never
    had reports. **None is the A2 callee blind spot**: every one has on-target reports.
  - The 2 strict-only cases (libgit2 f9e05546: on-target 3→0 among 75→72 reports; libgit2 6d63f4b6: 1→0
    among 9→8): the checker detects the bug and stops after the fix, but is noisy elsewhere. Strict judges
    this bug, not noise; noise is refine's job. **This property must be stated in the paper.**

## 2026-10-01 17:05 — 1.4 scan parity [M] (`e2e/scan-parity/parity.json`)

Previous attempt's UBI checker over curl HEAD `lib/` (194 files), plugin built and revision configured
before timing: serial `jobs=1` **484.0 s**, parallel `jobs=8` **88.0 s** (5.5×, 18% of serial; the criterion
is ≤40%). **1029 reports in both, identical sets** (keyed by file, line, issue hash).

- 17:07: launched 1.5 refine (threshold 0, `max_tries 2`) on the 21 strict-valid r7-B checkers of 6
  projects (`e2e/refine-t0-*`; libgit2 B finished after the copies were made), plus 0.3 retry
  (`e2e/retry-curl*`: curl 6f1dfab6 with a complete, non-perfect ranking [[0,0,0],[1,0,0],[2,0,0]],
  `checker_nums 1`: first without the flag, then with `--retry_failed`).

## 2026-10-01 17:40 — 0.3 and 1.5 E2E results

- **0.3 [M]** (`e2e/retry-curl-{noflag,flag}.log`): curl 6f1dfab6 with a complete, non-perfect ranking and
  `checker_nums 1`. Without the flag: "skipped, 3 attempts without a perfect checker" logged at 17:05:43,
  with no LLM calls (upstream: silent no-op). With `--retry_failed`: "3 attempts without a perfect
  checker; retrying". `generation/checker_03` was created and the ranking became
  `[[0,0,0],[1,0,0],[2,0,0],[3,0,0]]` (the new attempt also scored 0/0).
- **1.5 [M]** refine, threshold 0, `max_tries 2`, on 21 strict-valid r7-B checkers (curl 6, libxml2 5, lua 4,
  re2 3, sqlite 2, yaml-cpp 1):
  - All 21 end "Perfect". At HEAD (all fixes present) 19 checkers produce 0 reports.
  - curl KN-Memory-Leak-a0f08d69-1 (2 reports: `lib/cf-socket.c`, `lib/cf-ip-happy.c`) and libxml2
    KN-Memory-Leak-ddcb79dc-0 (2 reports: `HTMLparser.c`, `parserInternals.c`): all 4 triaged FP → 4
    `repair_FP` (48–126 s) → **4/4 FP objects re-scanned clean and re-validation strict 1/1** →
    "Refined", and attempt 2 found 0 reports. **Validation-failure rate 0/4** (criterion < 20%; previous
    attempt 12/12 and 15/15 failures).
  - Parallel triage [M]: both `check_report` calls of a checker start within 13 ms and finish at the
    slowest call: curl 42.2 s + 55.1 s → 55.1 s wall; libxml2 13.9 + 14.2 s → 14.2 s wall.
  - Caveat: n=4 repairs. Most curl/libxml2/... checkers are silent at HEAD, so the triage/repair path is
    exercised only where a checker over-reports.
- `docs/RESULTS_SECTIONS_0_2.md` written: every acceptance criterion with its result and evidence path.

## 2026-10-01 17:50 — Sections 0–2 pushed

- Commit `3d2489a` (results report + 2,059-file / 4.1 MB evidence bundle `bench/evidence/`) on top of the 7
  section 0–2 commits. Pushed `general-c-speed` to `origin` (Fariz36/KNighter-please-save-us).
  Secret scan: staged diff and `git log -p main..HEAD` have 0 hits for the key; the only `oc_sk_`
  occurrence is this log's sentence describing the scan.
- `.gitignore` fixes found while staging: the upstream `result*` rule silently dropped every `results/`
  folder and `results.jsonl` in the evidence (negations added for `bench/evidence/**`), and my `e2e/`
  rule matched `bench/evidence/e2e/` (anchored to `/e2e/`).

## 2026-10-01 18:00 — 3.1-A checks and the role-based run r8

- **Roles mechanism E2E [M]** (`tmp/roles-e2e/watched.cpp`, hand-written role-based checker reporting every
  call to role `watched`): built with block `{"watched": ["memcpy"]}` → `roles.json` extracted → **1 report**
  on curl `lib/sendf.c`; the same code with an empty role list → **0 reports**. `roles.h` compiles in the
  plugin, and the env plumbing and runtime lookup work.
- Lint false positive fixed: words in natural-language literals ("roles E2E test") were flagged.
  Literals containing whitespace are now skipped. Re-measured baseline [M]: previous attempt **14/22
  (64%)**, r7 all **101/153 (66%)**, r7-B on curl+libxml2+lua+sqlite **35/46 (76%)** checkers hardcode
  project identifiers. (Supersedes the 15:45 numbers.)
- Launched **r8**: optimized variant + `role_based_checkers=true` on curl, libxml2, lua, sqlite (26 commits),
  frozen snapshot, keep-awake. Compare with r7-B on the same 26 commits: perfect 17/26, hardcoding 76%.

## 2026-10-01 18:20 — 3.3 bundle E2E [M]

- `main.py export` on the 6 curl checkers of `e2e/refine-t0-curl` → `e2e/bundles-curl/`. The refined code
  (`refinements/latest_refined.cpp`) is picked for the refined checker, the full commit is resolved from
  the 8-char prefix, and `portable: false` with `hardcoded_identifiers: [Curl_peer_link, Curl_peer_unlink]`
  (r7 checkers predate role-based generation).
- **Standalone run** of bundle KN-Integer-Overflow-bc440a89-0 copied outside the repo, under `env -i
  PATH=/usr/bin:/bin` with **system Python 3.14** (no venv, no KNighter): curl 8.10.0 compile DB, 169
  files, 0 failures, 57.4 s, **1 report `lib/mime.c:523` [encoder_base64_size]**, the same report
  KNighter's own scan found (22:47 yesterday).
- Runner bug fixed: `--files lib/` used `endswith`, so it selected nothing, and the output dir was not created
  (crash writing the summary). It now uses substring match, always creates the out dir, and exits with a clear
  message on an empty selection.
- **Rebuild kit** (`CMakeLists.txt`, `find_package(Clang)` against `KNighter/llvm/build/lib/cmake`):
  1. The first build failed. KNighter's LLVM *declares* the `clang-cpp` target without building
     `libclang-cpp.so`. Fix: use shared only if the imported library file exists, else the static
     component libraries.
  2. The second build linked (80 MB) but **crashed clang** on load. It exported every statically linked
     Clang/LLVM symbol, which interposed on clang's own. Fix: the same version script as LLVM's in-tree
     plugin (`global: clang_registerCheckers; clang_analyzerAPIVersionString; local: *`) + `-z nodelete`
     + section GC.
  3. Result: 8.8 MB `plugin.so` (same as the in-tree build), 2 exported symbols, 11 s build. Rerun over 169
     files: **identical single report, 0 failures**.

- 18:30: bundles now include `patch.md` (needed by triage on other projects). Wrote `bench/cross_project.py`
  (3.4): per (bundle from P, target Q≠P): `port_roles` → scan Q at HEAD with `KNIGHTER_ROLES` = ported
  file → triage up to 5 reports. Runs after r8 provides role-based perfect checkers.
- r8 early [M]: the first 3 role-based curl checkers have **0 hardcoded identifiers before any
  repair_roles round** (roles e.g. `cleanup`, `link_detach`, `allocator`, `length_of`, `substring_finder`).
  a0f08d6975 (ML) perfect.

## 2026-10-01 20:20 — r8 (role-based, 3.1-A) results [M]

r8 = optimized variant + `role_based_checkers=true`, 26 commits (curl 8, libxml2 7, lua 4, sqlite 7), snapshot
`213af69c343ffa57`, 17:43–19:52, 0 s suspended in all runs. (The follow-up steps were delayed by an agent
session restart.)

| | r7-B (same commits, no roles) | r8 role-based |
|---|---|---|
| checkers hardcoding project identifiers (`checker_lint`) | 35/46 (76%) | **0/45 (0%)** |
| commits with a perfect checker (strict) | 17/26 | **18/26** |
| per project curl / libxml2 / lua / sqlite | 6/8, 5/7, 4/4, 2/7 | 6/8, 5/7, 3/4, 4/7 |
| wall (min) curl / libxml2 / lua / sqlite | 22.9 / 25.7 / 7.6 / 26.1 | 39.1 / 41.2 / 17.9 / 31.1 |

- Verification that the 0% is real: all 45 compiled checkers `#include "knighter/roles.h"`, call the
  `knighter::` role API, and carry a `KNIGHTER_ROLES` block; **204/204 roles have a project-independent
  description**. Role names that also occur in the logic are generic identifiers (`data`, `n`, `string`,
  `capacity`) used as ordinary variables/fields, not name comparisons.
- **`repair_roles` never ran**: initial findings were empty for every checker, so the prompts alone achieved it.
- Success did not drop (18 vs 17 of 26; within run-to-run variance). Wall time was higher (the role
  guidance makes prompts longer and plans more elaborate), to be broken down per stage in the section 3
  report.
- 20:25: exported r8 bundles (`e2e/bundles-r8/<project>/`): curl 6, libxml2 5, lua 3, sqlite 4 = 18, **all `portable: true`**. Launched 3.4 cross-project (`bench/cross_project.py`, 4 target processes in parallel, 14 foreign bundles each = 54 pairs, triage ≤ 5 reports per pair), output `e2e/cross/`.
- Correction: the cross-project processes started at **20:47** (first log lines), not 20:25 as written above; the 20:25 time was written before launching, and the bundle export took longer than assumed. Candidate API names from headers [M]: curl 1806, lua 689.

## 2026-10-01 22:10 — 3.4 first cross-project result: ported checkers find nothing; two causes diagnosed

First cross-project run (r8 bundles, 3 of 4 targets finished; lua still running) [M, `e2e/cross/*.json`]:
- curl target 12 pairs, libxml2 13, sqlite 14 = 39 pairs. **17 got no role mapping at all** (not scanned).
  **All 22 scanned pairs produced 0 reports.** Even basic roles were unmapped (`deallocator` → SQLite,
  which has `sqlite3_free`/`sqlite3DbFree`).
- Diagnosis on `KN-Double-Free-26dfab2f-1` (libxml2) → SQLite (`ports/sqlite.json`):
  1. **Candidate extraction/ranking (3.1-B).** SQLite's public API (`sqlite3_free`, `sqlite3_malloc`) is
     declared in `src/sqlite.h.in`, which was skipped (suffix `.in`). `sqlite3DbFree` *was* extracted and
     ranks #1 for a generic description ("frees an object"), but the role's real description was
     bug-specific, its words dominated the score, and the offered top 12 were `fts5BufferFree`,
     `sqlite3ParserFree`, `S_ISDIR`, ... `sqlite3ExprListDelete`/`sqlite3SelectDelete` could not match
     "free" at all (no synonyms).
  2. **Roles too specific (3.1-A).** The LLM refused the mapping with the rationale "the deallocators for
     the plausible resources (e.g. ExprList, Select) are not present". The generated roles describe the
     bug instance (`ownership_consumer_frees_on_failure`, `gc_root_anchor`, `dequote_helper`,
     `caller_ignoring_sentinel`), not reusable API categories, so other projects have no equivalent.
- Fixes (commit after this entry):
  - 3.1-B: template headers (`*.h.in`) are included. Synonym groups (free~delete~release~destroy~unref,
    alloc~new~create~dup, len~size~count, ...). Weighted ranking: role name + source names ×3,
    description words ×1. New test: `sqlite3_free` (from `.h.in`) and `sqlite3ExprListDelete` are the top 2
    for a bug-specific deallocator description; `sqlite3ExprCompare` is not offered. 4/4 porting tests pass.
  - 3.1-A: both roles prompts now give a **standard role vocabulary** (allocator, deallocator,
    reallocator, duplicator, null_on_failure, error_setter, aborting_assert, length_of, buffer_copy,
    bounded_copy, lock/unlock, ref_get/ref_put, init/cleanup, container_insert/remove, parser_input,
    untrusted_size), require roles to be API categories most projects have with generic descriptions, and
    allow at most 6 roles. **Needs a regeneration run to measure** (r8 bundles predate it).

## 2026-10-01 22:45 — Cross-project v1 totals; v2 (porting fix only) launched

- **v1 [M]** (all 4 targets, `e2e/cross-v1/`): 54 pairs, **87/264 roles mapped (33%)**, 21 pairs with no
  mapping, 33 scanned, **0 reports in all scanned pairs** (so 0 triaged).
- User decision: "both, porting first". v2 = the same r8 bundles + fixed porting (3.1-B fix only), output
  `e2e/cross/`; afterwards regenerate with the generic-role prompts (r9) and run cross v3.
  v1 bundle state archived in `e2e/bundles-r8-after-cross-v1/`.

- 23:50: cross v2 interim: mapping improved, still 0 reports; added positive control bench/self_port.py.
  (Full version of the line above.) Cross v2 interim [M], curl and lua targets done: mapping clearly improved
  (e.g. libxml2 Double-Free → curl 5/6 roles vs 0/6 in v1), but **still 0 reports in every scanned pair**,
  including near-complete mappings (curl f7d4e11f → lua 6/8). Ambiguous: either no such bugs exist at the
  targets' HEAD, or ported checkers cannot fire. Positive control `bench/self_port.py`: port each bundle back to its
  *own* project from scratch (LLM; `out_name <project>-selfport` keeps the original roles file) and scan the
  patched files at the *buggy* parent with original vs ported roles. Detection is preserved when the ported
  roles still report wherever the original did.

## 2026-10-02 12:40 — State check; presentation summary written

- Cross v2 was **interrupted by an agent session restart**: libxml2, curl, and lua targets finished;
  sqlite did not (no processes running). Partial v2 [M]: 40 pairs, roles mapped 79/202 (**39%**,
  v1: 33%), 28 scanned, **0 reports**. Self-port control and r9 not run yet.
- Wrote `docs/PROGRESS_SUMMARY.md` for the user's presentation: goals vs status, sprint scope, problems
  found, changes in plain words, headline evidence, section 3 status incl. the open cross-project
  problem, findings, caveats, next steps, questions for the supervisor, and a glossary.

- 12:55: wrote `docs/PROGRESS_QA.md` (question-and-answer companion to the summary, 12 topics). LLM cost
  measured for it [M]: r7-A 407 calls, 2.72M prompt / 3.58M completion (3.09M reasoning) tokens; r7-B 388
  calls, 2.68M / 3.74M (3.35M); r8 275 calls, 1.97M / 3.23M (2.80M). At OpenCode Go prices ≈ $2.5–5.3 per
  run (upper bound, ignores cheaper cached input).

## 2026-10-07 — Finishing section 3: self-port control, r9, cross v3

- User: "please proceed on finishing section 3". Plan [I]: (1) self-port positive control on the r8 bundles
  (`bench/self_port.py`, one process per project, output `e2e/selfport-r8/`); (2) concurrently, **r9** =
  optimized + `role_based_checkers=true` on the same 26 commits as r8 (curl, libxml2, lua, sqlite) with the
  generic-role vocabulary prompts (commit 3dc9c0a); r9 measures quality/roles, not speed, so CPU sharing with
  the self-port run is acceptable; (3) export r9 bundles, cross-project v3 on all 4 targets, self-port on r9;
  (4) `docs/RESULTS_SECTION_3.md`.

- 14:42: launched self-port control v1 (r8 bundles, 4 processes) and r9.
- **Self-port control v1 [M]** (`e2e/selfport-r8-v1/`, stopped after 8 of 18 bundles): original roles
  report on the buggy parent in **8/8**, ported roles in **0/8**, so detection was preserved in 0/8. Porting
  to the *same* project loses detection, so the 0-report cross-project results say nothing about other
  projects yet. Two causes, from the per-role mapping diffs:
  1. **Porting bug [M]:** the LLM chose the right names but validation rejected them as "not in target",
     because the header scan never extracted them: Lua declares `LUALIB_API void (luaL_setfuncs) (...)`
     (parenthesised name), libxml2 puts the return type on the previous line
     (`XMLPUBFUN xmlParserInputPtr\n\t\txmlNewIOInputStream(...)`). All 6 libxml2 and 4 Lua roles were
     lost this way.
  2. **r8 roles are bug-site details, not APIs [M]:** many roles bind local variables (`bufpt`, `zOut`,
     `nPayload`, `datasize`, `iIdx`, `c`, `count`), struct fields (`maxAmpl`, `dest`), types (`int`,
     `u32`, `Table`), constants (`-1`, `BASE64_MAX_INPUT_SIZE`), string keys (`__mode`), a pattern
     (`_UBOX*`) and a libc function (`memset`). No other project has them, and porting cannot recover
     them; the porting LLM even put a function (`curl_mime_data`) into the variable role `input_length`.
- Fixes [I]:
  - Porting: two more declaration patterns (parenthesised name; name at line start with the return
    type on the previous line). Every chosen name is validated against **all identifiers in the target's
    C/C++ sources** (not only the header candidates), so static functions/macros are accepted when they
    exist. Standard-library names are carried over unchanged (no LLM). The prompt allows non-listed
    names, which are then checked. New regression test (Lua and libxml2 styles); 37/37 non-kernel tests
    pass (upstream `test_backend` needs a kernel config, as before).
  - Prompts (`roles-pattern.md`, `roles-checker.md`): **roles bind functions and macros only**; variables,
    parameters, fields, types, constants, keys and literals must be recognised structurally ("size
    argument of a `buffer_copy` call", "integer narrower than 64 bits").
- r9 was **aborted after ~10 min** (curl only, first attempts) so it uses the new prompts; archived in
  `bench/aborted/r9a-*`. Relaunched r9 with a fresh snapshot, and self-port control v2 (same r8 bundles,
  fixed porting; `e2e/selfport-r8/`). The v1 port reports were copied to `e2e/selfport-r8-v1/ports/`.
- Correction: r9 was aborted after ~7 min (14:42 → 14:49), not ~10. r9 relaunched 14:49:54, snapshot `6929653da9b3d22d`.

## 2026-10-07 15:20 — Self-port control v2: porting preserves detection 18/18

- **Self-port v2 [M]** (`e2e/selfport-r8/*.json`, r8 bundles, fixed porting): original roles report on the
  buggy parent in 18/18; ported roles in **18/18 (detection preserved in all)**, with the same report
  counts (incl. 14 = 14 and 2 = 2). The ported mapping equals the original in 11/18; in 7/18 the LLM chose
  different/extra names and detection still held. v1 → v2 difference is the porting fix only, so the 0/8 in
  v1 was the porting bug.
- **Caveat [I]:** in a self-port the LLM sees the source names, which also exist in the target, so this
  control shows the **porting machinery** (prompt, candidates, validation, roles plumbing) is sound; it
  does **not** show that bug-specific roles (variables, fields) have counterparts in *other* projects.
- Added `bench/cross_known.py` (3.4, known bugs): port each foreign bundle once to the target, then run
  the **unchanged plugin** with the ported roles through normal validation on every benchmark commit of the
  target (strict TP on commit^, TN on commit). This is a direct measure of cross-project detection of
  real bugs, unlike HEAD scans, where "0 reports" could also mean "no such bug". Smoke test (libxml2
  Double-Free → curl, 2 commits): runs end to end; 4/6 roles mapped, not detected.
- Launched cross-known on the r8 bundles with fixed porting ("cross-known-r8", all 4 targets
  sequentially, 26 known-bug commits), to separate the porting fix from the r9 prompt change.

## 2026-10-07 15:45 — Finding: 4 of 43 benchmark commits are compiled out in our builds

- While checking cross-known timings (curl `lib/smb.c` analyzed in 0.06 s), found that curl `c4cb6769`'s
  patched file is entirely under `#if defined(CURL_ENABLE_SMB) && defined(USE_CURL_NTLM_CORE)`, and
  `CURL_ENABLE_SMB` is OFF by default in curl's CMake. The file compiles to an empty TU, so the precheck
  ("compiles and analyzes with a no-op checker") passed it, but **no checker can ever report there**.
- New `bench/compiled_out.py` [M] (`e2e/compiled-out/*.jsonl`): runs `clang -E` with each patched file's
  own compile command on the buggy revision and checks the strict-scoring patched function names survive
  preprocessing. Compiled out in our configs: **curl c4cb6769** (`smb_request_state`, SMB off),
  **libgit2 0bc19591** (`load_known_hosts`, libssh2 transport), **libgit2 ef086bc3**
  (`verify_server_cert`, OpenSSL stream), **sqlite 97467fa8** (`kvvfsDecode`, `os_kv.c`). Cross-check: all
  4 have TP=0 in **every** r7 attempt of both variants; no commit with a perfect checker is flagged. (The
  first version wrongly flagged re2 `DFA::~DFA`: the regex could not match `~`; fixed.)
- Effect on reported numbers [I]: these 4 commits are unsolvable for *both* variants, so the r7 A/B
  comparison is unchanged in kind; the effective success rates are **26/39 (A) vs 27/39 (B)** instead of
  /43. r8/r9 (26 commits) contain 2 of them (curl c4cb6769, sqlite 97467fa8): effective /24. This
  repeats the libgit2 93b16df1 lesson (unanalyzable ≠ generation failure) at a subtler level: a patched
  file can compile and still not contain the patched code. A precheck should test the functions, not
  the file. Options: enable the features in the configs (curl `-DCURL_ENABLE_SMB=ON -DCURL_ENABLE_NTLM=ON`,
  libgit2 with libssh2/OpenSSL, sqlite KV VFS) or drop the commits; decision deferred to the user.
- Correction: the two headings above were timestamped wrongly (estimated, not read from the clock). Actual: self-port v2 finished ~15:03 and cross-known-r8 launched right after; the compiled-out finding was written ~15:10.
- Correction to the correction: self-port v2 finished at **14:59** (file times: lua 14:52, sqlite 14:55, libxml2 14:58, curl 14:59); compiled_out.py curl result 15:09.
- 15:44: cross-known-r8 targets libxml2, lua, sqlite started in parallel (`run_rest.sh`); curl continues alone. (A first attempt killed its own shell via `pgrep -f` self-match, the r6 lesson again; the sequential driver was stopped by it, the curl process survived.)

- 16:20: worked example for the user of why v2 HEAD scans gave 0 reports [M]: curl checker `f7d4e11f`
  gates its report on `containsFieldAccess(Cond, "length_field")` (a `MemberExpr` whose field decl is
  bound to the role). In curl the role is the field `len`; ported to Lua (v2) it became
  `luaZ_sizebuffer`, a macro `((buff)->buffsize)`. CSA analyses preprocessed code and sees the field
  `buffsize`, never the macro name, so the gate is always false and the report is unreachable in all
  34 Lua files. Lua *has* the equivalent field (`Mbuffer.buffsize`); the porting LLM gave the wrong
  **kind** of name (a macro for a field role). In v2, only 3/40 pairs had every role mapped (12 none,
  25 partial). Design note [I]: r9's function/macro-only roles avoid kind mismatches (calls map to calls), at
  the cost of recognising fields structurally. Possible later alternative: keep field roles, record each
  role's kind in the roles block, and have porting resolve macro wrappers to the fields they expand to.
- 16:30: **Re-check with corrected field roles [M]** (`e2e/lua-len-recheck/`): curl `f7d4e11f` on all Lua
  HEAD files with v2-ported roles → 0 reports; with `length_field: [buffsize, n]`,
  `data_pointer: [buffer]` (only roles.json changed, same plugin) → **still 0**. Manual check: Lua's
  code does not have the pattern's shape. Only 2 `if` conditions on `buffsize` (lobject.c:521, llex.c:64), neither returns
  an error, and there is no `memcpy` from `->buffer`. The checker also requires `return <error constant>` (a `DeclRefExpr`, as with
  curl's `CURLE_*` enum), whereas Lua reports errors via calls (`return luaL_error(...)`) or integer macros.
  So for this pair, the 0 is plausibly genuine once the mapping is right.
- Conceptual point raised by the user ("isn't cross-project very dependent on source and target?") [I]:
  porting is plug-in (the plugin never changes; only the roles file does). Roles absorb **name** differences,
  not **code-shape** differences (error constants vs error calls, field vs accessor), which are encoded
  in the checker logic. Transfer is therefore pattern-dependent: generic API-level patterns (allocator→NULL
  check, deallocator→use, length→copy) should transfer, while project-shaped ones (curl blob guard, Lua GC
  barrier) should not. The research claim should be "which checker kinds transfer, measured on matched
  same-class bugs", not "all checkers transfer". This also argues against per-target LLM rewriting of the
  checker logic, which would re-introduce exactly the dependence and need validation per target.

## 2026-10-07 16:50 — Matched-pair experiment prepared (3.4, same-class real bugs)

- User question: for good research we must show "a ported checker found a vuln". Agreed [I]: neither HEAD
  scans (no ground truth) nor cross-known (target's benchmark bugs are mostly other classes) test
  this. Plan: matched pairs + historical replay, porting design unchanged (plug-in, roles only).
- `bench/matched_pairs.py` [I]: ground truth = real fix commits of the target, chosen **deterministically**
  (no LLM chooses commits): mine target history since 2019 (bug keywords in the subject, ≤ 40 changed
  source lines, source-only, tests/fuzz/docs ignored, benchmark commits excluded), keep commits whose
  keyword-guessed type equals the bundle's bug type **and** whose changed lines mention ≥ 1 name the
  roles were ported to; rank by distinct names hit, then recency; validate the unchanged plugin on the
  top 3 with strict TP/TN. The only LLM step is porting.
- Mined pools [M] (`e2e/matched/<target>-candidates.json`): lua 96, curl 1455, libxml2 644, sqlite 2805
  candidates. Type guesses are keyword-based and noisy (e.g. NULL-pointer via `\bNULL\b`); a pair's real
  class is checked by reading the diff for any detection we report.
- 16:55: exported r9 bundles for curl (5), libxml2 (4), lua (2), all portable (`e2e/bundles-r9/`). Launched matched pairs batch 1 (these 11 bundles × 4 targets, sequential targets; `e2e/matched-r9/batch1/`). r9 sqlite still running.

## 2026-10-07 17:05 — Role API bug: macro wrappers and function pointers never matched a role

- First matched-pair results (libxml2 Double-Free → curl, 0 API-matched candidates) led to two findings [M]:
  1. **The porting LLM maps the bug instance, not the category**: offered `curlx_free`, `curl_free`, ... for
     `deallocator`, it chose `Curl_cf_ngtcp2_h3_stream_ctx_free`, `Curl_vquic_ctx_free` ("the specific
     filter contexts that Curl_cf_create consumes"). Fix [I]: `port_roles.md` now says the checker scans the
     whole project, so roles must be mapped to their category across the project (general-purpose
     wrappers first); macro wrappers and function-pointer variables are valid names.
  2. **`roles.h` bug**: `callIsRole` compared only `Call.getCalleeIdentifier()`, i.e. the resolved callee of
     the *preprocessed* code. A call through a **macro wrapper** (curl `curlx_free(p)` → `Curl_cfree`/`free`)
     or a **function-pointer variable** (libxml2 `xmlFree`, curl `Curl_cfree`) can therefore never match.
     Measured with the role-reporting test checker (`tmp/roles-macro/`), old header (r9 snapshot) vs new:
     curl `lib/sendf.c` role=`curlx_free` **0 → 6**, role=`Curl_cfree` **0 → 6**; libxml2 `tree.c`
     role=`xmlFree` **0 → 52**. (`free` alone: 0 in both, since curl's build routes `curlx_free` to
     `Curl_cfree`.)
     Fix [I]: new `callExprIsRole(CE, Role, Ctx)` and `macroIsRole(Loc, Ctx, Role)`; `callIsRole` now matches
     the callee function, the variable/field holding the called function pointer (incl. `(*fp)(...)`), or any
     macro in the call's expansion chain (macro-argument expansions skipped, so `CHECK(foo(x))` does not
     make `foo` a `CHECK` call).
- Consequences [I]: the header is part of the plugin hash, so every role-based checker builds a new plugin;
  r8/r9 source-project scores were measured with the old header and must be re-validated (no LLM). The
  header changed at 16:58:27 while matched batch 1 and cross-known-r8 were running from the live tree; both
  were stopped at ~17:03. Cross-known-r8 partial [M]: 42/54 pairs, **0 detections** (r8 bundles, target
  benchmark commits of mostly other bug classes; mixed headers after 16:58, so it is reported only as a
  pre-fix control). Matched batch 1 had done 2 bundles with 0 API-matched candidates and no
  validations; it is discarded and will be rerun after re-validation.
- 17:10: `bench/revalidate.py` (re-validate every validated attempt with current code, no LLM). r9 lua [M]: 5/5 attempts unchanged (2 perfect before and after). Launched for r9 curl/libxml2 and r8 all 4 (`e2e/revalidate/`); r9 sqlite after r9 ends.
- Re-validation [M]: r9 curl 13/13 attempts unchanged (5 perfect commits before/after). r9 libxml2 15/16 unchanged; **ddcb79dc checker_01 0/0 → 1/1 (now perfect)**: its roles are `allocator: xmlMalloc`, `deallocator: xmlFree` queried with `callIsRole`. Both are libxml2 function-pointer variables, so under the old header the correctly written checker was silently inert on its own project. r9 libxml2 perfect commits 4/7 → **5/7** (= r8).
- Re-validation [M]: r8 curl 13/13 unchanged (6 perfect). r8 libxml2 15/16 unchanged; again **ddcb79dc (checker_02) 0/0 → 1/1**, r8 libxml2 5/7 → 6/7. The role API bug hid a correct checker for the same libxml2 commit in both runs.
- Re-validation [M]: r8 lua 6/6 unchanged (3 perfect); r8 sqlite 10/10 unchanged (4 perfect). Total r8 with the fixed header: **19/26** perfect commits (was 18/26).

## 2026-10-07 17:50 — r9 finished; r8 vs r9 with the fixed header; matched pairs v1 launched

- r9 ended 17:46:24. Re-validation r9 sqlite [M]: 14/14 unchanged (2 perfect).
- **r8 vs r9, same 26 commits, both re-validated with the fixed roles.h [M]** (`bench/role_stats.py`,
  `e2e/revalidate/`):

  | | r8 (free-form roles) | r9 (vocabulary, function/macro-only) |
  |---|---|---|
  | perfect commits | **19/26** (curl 6, libxml2 6, lua 3, sqlite 4) | **14/26** (curl 5, libxml2 5, lua 2, sqlite 2) |
  | roles from the standard vocabulary | 21.1% | **85.2%** |
  | role names callable (function/macro) | ≤ 84.5% (upper bound) | **100%** |
  | roles per attempt | 4.53 | 2.96 |
  | attempts with hardcoded identifiers | 0/45 | 0/48 |

  (Effective denominators are /24: curl c4cb6769 and sqlite 97467fa8 are compiled out.) Reading [I]: the
  generic roles cost detection on the source project in every project (−5 commits in total, one run each).
  Generic/portable roles trade source-project detection for portability; whether they transfer better is what
  matched pairs measure, so matched pairs run on **both** r8 and r9 bundles.
- Re-exported bundles with the fixed header: `e2e/bundles-r9h2/` (13, all portable) and `e2e/bundles-r8h2/`
  (18, all portable); bundles contain the new `roles.h`. Only gen-accepted (KN-*) checkers are exported, so
  the re-validated ddcb79dc checkers (perfect only after the header fix) are not included.
- Launched **matched pairs v1** (`e2e/matched-v1/{r9,r8}/`): 4 target processes in parallel, each runs the
  r9 bundles and then the r8 bundles; top 3 API-matched same-type fix commits per (bundle, target).
- 18:05: matched pairs v1 **restarted**. First attempt [M]: curl Memory-Leak → libxml2 had 54 API-matched
  candidates, but all 3 selected commits failed setup: libxml2 revisions from before 2024-04 have no
  `meson.build` (the config uses meson). Fixes [I]: optional `target_options.build_marker` (libxml2
  `meson.build`, introduced 2024-04-04; sqlite `autosetup`, 2024-09-24); mining keeps only commits whose
  parent contains it; validation skips candidates that still fail setup (recorded with the error) until 3
  validations succeed or N+6 tries. Re-mined pools [M]: libxml2 205, sqlite 719, curl 1455, lua 96. (Again
  `pkill -f` killed its own shell; processes were then stopped by PID via `tmp/stop_jobs.sh`.)
- 18:20 observation [M]: after the port-prompt change, libxml2 Double-Free → curl still maps `deallocator` to filter-context frees (`Curl_vquic_ctx_free`, ...) and `parser_input`/`null_on_failure` to `Curl_cf_create`. The r9 role description itself is narrow ("frees a parser input buffer") and the pattern is project-shaped (constructor consumes its buffer and frees it on failure), so this is a faithful port of a specific pattern rather than a porting error; curl's 10 Double-Free fixes touch none of these functions (0 API-matched). The r9 vocabulary prompt fixed role *names* and *kinds* but not always the *descriptions*.
- 18:25 sentinel bug [M]: sqlite 1af26071 changes only `ext/misc/fileio.c` (not in libsqlite3, no compile entry). Validation analyzed nothing with no errors and returned **-3 (checker plugin failure)** instead of a setup error. Fix [I]: missing compile entries are recorded as errors ("no compile entry"), so the case raises `TargetSetupError`. Running matched processes still use the old code: their -3 results with details `error: no file analyzable` and empty errors are counted as 'not analyzable' in the analysis. Gen was not affected in practice (the precheck requires compile entries).
- 18:35: matched pairs v1 restarted again (old code still returned -3 for files without compile entries, which used up the 3 slots); aborted partial run kept in `e2e/matched-v1-aborted/`.

## 2026-10-07 19:00 — First cross-project detections of real bugs (matched pairs v1, r9)

- **sqlite Memory-Leak checker (r9 `KN-Memory-Leak-7b60ed80-1`) → libxml2 [M]**, roles ported by one LLM call
  (allocator/duplicator/null_on_failure/container_insert/deallocator → 57/15/72/10/38 libxml2 names), plugin
  unchanged. Of 3 validated same-class fixes: **c1342946 TP=1 TN=0**, **98194640 TP=1 TN=0**, ef44c240 0/0
  (0bef1704 and 28da8549 could not be set up).
  - c1342946 "fix memory leak in issue 1054" (xmlwriter.c, xmlTextWriterStartAttributeNS): on the buggy parent the checker
    reports at **line 1804**, the `return -1` inside `if (p == 0)`. Its path tracks `buf` ("Assuming 'buf' is not equal to
    NULL"), and `buf` leaks there; the fix inserts exactly `xmlFree(buf);` at that line. Manual reading confirms
    it is the fixed bug (CWE-401).
  - 98194640 "Fix memory leak of prefix in xmlTextWriterStartElementNS()": buggy report at **line 1055**, the
    `return -1` in the `p->uri == 0` branch where `p->prefix` leaks; the fix adds `xmlFree(p->prefix)` there.
  - Imprecision (why TN=0): after the fix the checker still reports at the same returns (fixed lines 1815,
    1056/1063): it does not model a pointer stored into a field (`p->prefix = buf`) and freed through
    it (`xmlFree(p->prefix)`). It also reports 9 other locations in xmlwriter.c on both sides (noise).
  - Reading [I]: this is the first evidence that a checker generated from one project (SQLite) detects a
    real, later-fixed bug in another project (libxml2) through role porting alone; the detection is exact
    at the fix line, but the checker is imprecise (strict TN fails, noisy). This is consistent with the
    hypothesis that generic API-level patterns (allocator → must be freed or inserted on every path) transfer.

## 2026-10-07 20:15 — Matched pairs v1 complete

- [M] (`bench/matched_report.py e2e/matched-v1 r9 r8`, `e2e/matched-v1/summary.txt`):

  | | r9 (13 checkers × 3 targets) | r8 (18 × 3) |
  |---|---|---|
  | pairs with ≥ 1 API-matched same-type fix | 15/39 | 30/54 |
  | validated fix commits (setup ok) | 27 (24 skipped) | 56 (28 skipped) |
  | checker reports anything in the patched files | 4/27 | 2/56 |
  | detected (strict TP > 0) | **2/27** | **0/56** |
  | perfect | 0 | 0 |

- Both detections: r9 SQLite Memory-Leak 7b60ed80 → libxml2 c1342946 and 98194640 (see 19:00). Not a clean
  r8-vs-r9 comparison: r8 has no perfect checker for 7b60ed80. The dominant outcome is **silence**: ported
  checkers report nothing in the patched files of 77/83 validated same-class fixes.
- Wrote `docs/RESULTS_SECTION_3.md` (design, 3.1-A, 3.3, 3.1-B self-port, 3.4 three experiments, bugs found
  and fixed, interpretation, limits).
- 20:20: launched **cross v3** (`e2e/cross-v3/`): HEAD scans of every target with the foreign r9 bundles (final porting + roles.h), triage ≤ 5 reports per pair; 4 targets in parallel.

## 2026-10-07 21:50 — Cross v3 (HEAD scans, r9 bundles, final porting): checkers fire; 0 confirmed new bugs

- [M] curl, libxml2, lua targets finished (28 pairs; sqlite still running). Unlike v1/v2 (0 reports
  everywhere), ported checkers now **fire**: 12/28 pairs report, 395 reports in total (sqlite Memory-Leak
  7b60ed80: libxml2 283, curl 25, lua 16; curl f2a15357 NPD: lua 30, libxml2 10; curl c53420e4: lua 11;
  libxml2 26dfab2f Double-Free: curl 7; ...). Roles fully mapped in most pairs (e.g. 5/5, 6/6); 3 pairs
  still had no mapping (lua UAF 0/2 twice, libxml2 c8eaf223 → lua 0/1).
- LLM triage (≤ 5 per pair) labelled **2 reports "Bug"**; manual review [M] found both are **false
  positives**:
  1. curl `lib/mime.c:1668` `Curl_mime_add_header` (libxml2 Double-Free checker): `curlx_free(s)` after
     `Curl_slist_append_nodup` fails. curl documents and implements that the function does **not** release the
     string on error (lib/slist.c:51–64), so the free is correct. The checker carries libxml2's
     "consuming constructor" assumption; the ported `parser_input`/`null_on_failure` role is wrong for curl.
  2. libxml2 `parser.c:11782` `xmlCtxtParseContentInternal` (curl Memory-Leak checker, "container_remove
     after cleanup zeroed the object"): the 39-event path contains no cleanup call before `nodePop(ctxt)`, and
     `nodePop` (pops the parser's node stack) was mis-mapped to `container_remove`.
- Reading [I]: with the fixes, porting produces checkers that run and fire in other projects, but the HEAD reports
  sampled so far contain no confirmed new bug, and the LLM triage's positive verdicts were wrong in 2/2 cases.
  Triage cannot replace manual confirmation for cross-project reports.
- 22:05: cross v3 sqlite done [M]: 0 Bug verdicts (reports: curl 466c06cf 17, curl f2a15357 33, libxml2 962bd10d 13). **Cross v3 totals: 39 pairs, 15 fire, 458 reports, 63 triaged, 2 'Bug' verdicts, both manually confirmed false positives → 0 confirmed new bugs.**
- 22:15: extended `bench/export_evidence.py` to section 3 (r8/r9 runs, self-port, cross v1/v3, cross-known, matched-v1, revalidate, compiled-out, lua recheck, bundle metadata without plugin.so): 4083 files, 9.0 MB. Secret scan of the staged diff: 0 key values. Committed section 3 work locally (not pushed).
- 22:32: pushed `general-c-speed` (section 3 commits e70d562..2fbce9c) to origin after user approval.

## 2026-10-07 22:40 — Overnight: historical replay (3.4) and r9 repeat (r9b)

- User approved both ("i will let my device on the whole night").
- `bench/historical_replay.py` [I]: old release T per target = latest tag that is an ancestor of HEAD and
  ≥ 12 months older (curl-8_16_0, libxml2 v2.15.0, lua v5.5-beta, sqlite version-3.50.4; branch-only
  tags such as sqlite 3.42.1 are excluded by the ancestor rule). Later fixes = non-merge commits in T..HEAD
  with bug keywords; their old-side changed functions (strict-scoring regions). Scan Q at T with
  each foreign bundle (roles ported at T, out_name `<Q>-hist`). Report = hit if its (file, function) was later
  fixed. **Base rate** = share of all functions in the scan scope that were later fixed (a checker reporting
  in random functions has this hit rate). Hits are judged by the LLM against the fix diff (`hist_judge`, ≤ 10
  hits per bundle, ≤ 3 fixes each); every positive verdict gets a manual check.
- Dry run lua [M]: tag v5.5-beta (cfce6f4b), 22 later-fixed functions, base rate 21/1273 = **1.65%**.
- Launched hist-v1 (`e2e/hist-v1/{r9,r8}/`, 4 targets in parallel, r9 then r8 bundles) and **r9b** = r9
  repeated (same 26 commits, optimized + role_based_checkers, fresh snapshot). Differences from r9:
  final roles.h (macro/function-pointer matching) and the `callExprIsRole` lines in roles-checker.md.
  Compare r9b with the **re-validated** r9 (14/26).
- 23:05: hist-v1 first launch stopped: with bug keywords only, curl's base rate was **40.7%** (1366/3354
  functions "later fixed"; most curl subjects contain "fix", some are large refactors), so hits would mean
  nothing. Ground truth is now the matched-pairs rule: source-only fixes with ≤ 40 changed source lines.
  Base rates [M]: lua 14/1273 = **1.1%**, libxml2 45/3080 = **1.5%**, curl 327/3354 = **9.75%**, sqlite
  268/3846 = **7.0%**. Tag for sqlite resolved to version-3.50.0 (3.50.x patch tags are not ancestors of trunk).
  Relaunched (r9 then r8 bundles per target).
- 23:40: correction: the 23:05 relaunch silently failed (run.sh recreated without the exec bit after `rm -rf e2e/hist-v1`); actually relaunched at 23:40. r9b curl [M]: 5/8 perfect (r9: 5/8).

## 2026-10-08 01:15 — Historical replay: SQLite-born checker finds 2 real leaks in libxml2 2.15.0 (whole-project scan)

- [M] r9 SQLite Memory-Leak `7b60ed80` → libxml2 at **v2.15.0** (0bea77c8, released 2025-09-15), whole scan
  scope, roles ported at the tag: 234 reports in 127 functions; **9 functions later fixed (7.1% vs base rate
  1.5%, ≈ 4.7×)**. The LLM judge marked 4 (function, fix) pairs positive; manual review:
  - **xmlwriter.c:1055 `xmlTextWriterStartElementNS` — confirmed.** Path: `p` allocated (`Assuming 'p' is
    not equal to null`), `p->prefix = buf`, `p->uri == NULL` → `xmlFree(p); return -1` leaks `p->prefix`.
    Fixed by **98194640** (2025-12-12) "Fix memory leak of prefix in xmlTextWriterStartElementNS()".
  - **xmlwriter.c:1798 `xmlTextWriterStartAttributeNS` — confirmed.** Path: `buf` non-NULL, `p == NULL`
    → `return -1` leaks `buf`. Fixed by **c1342946** (2026-02-11) "fix memory leak in issue 1054", which inserts
    `xmlFree(buf)` there.
  - xmlwriter.c:1062 (`return sum`, judged fixed by cee7107a "extra NULL checks"): **not confirmed**; the path does
    not take the `nsstack == NULL` branch that cee7107a guards, so the judge over-matched (likely the
    field-store imprecision seen before).
  - The other 6 hits (c14n type confusion, SGML catalog stack overflow, URI integer overflow, xmllint NULL
    checks, xmlreader `Free input`) were judged unrelated; xmlreader 00cec2be (a leak fix) is to be reviewed
    by hand.
  - The scan made only 3 reports in xmlwriter.c; 2 are these real leaks.
- Reading [I]: unlike matched pairs (commits chosen by API overlap), this is a **blind whole-project scan of an
  old release**: a checker generated from a SQLite bug fix and ported by renaming roles flagged two real
  memory leaks in libxml2 2.15.0 at the exact lines libxml2 fixed 3 and 5 months later. It also produced
  232 other reports (precision is low); this is not a "new" bug (already fixed upstream), but it is
  cross-project detection of real bugs not known at scan time.
  - xmlreader.c:5089 `xmlReaderForFd` (fix 00cec2be) manual review: the report is at `return(NULL)` taken when `input == NULL` (nothing allocated → false positive); 00cec2be is about a dup'ed fd close callback, unrelated. Judge's 'false' was correct.
- 01:27: **r9b finished [M]** (`bench/role_stats.py r9b`): perfect commits **12/26** (curl 5, libxml2 4, lua 1,
  sqlite 2); vocabulary roles 90.8%, callable names 98.7%, hardcoded 0/47. Two generic-role runs: r9 14/26
  (re-validated), r9b 12/26 (mean 13) vs r8 19/26 (one run): the detection cost of generic roles is
  reproducible. (r9b ran with the final roles.h, so no re-validation is needed.)

## 2026-10-08 02:00 — Historical replay complete

- [M] `bench/hist_report.py e2e/hist-v1 r9 r8` (`e2e/hist-v1/summary.txt`); tags curl-8_16_0, libxml2 v2.15.0,
  lua v5.5-beta, sqlite version-3.50.0; base rates 9.75% / 1.46% / 1.1% / 6.97%.

  | | r9 checkers | r8 checkers |
  |---|---|---|
  | pairs scanned (with ≥ 1 mapped role) | 37/39 | 50/54 |
  | pairs that report | 14 | 6 |
  | distinct functions reported | 252 | 17 |
  | hits (function later changed by a small fix) | **13** | 0 |
  | hits expected by chance (Σ functions × base rate) | 5.6 | 0.5 |
  | LLM-judged positive (function, fix) pairs | 4 | 0 |
  | **manually confirmed real bugs** | **2** | 0 |

- Hits by checker: SQLite Memory-Leak 7b60ed80 gives 12/13 (libxml2 9/127 functions, curl 2/7, lua 1/38); curl NPD
  f2a15357 → libxml2 1/8. Per target, r9 is enriched only in libxml2 (10 vs 2.0 expected); curl 2 vs 0.9, lua 1 vs
  0.9, sqlite 0 vs 1.8. Confirmed bugs: libxml2 2.15.0 xmlwriter.c:1055 (fixed 98194640) and :1798 (fixed
  c1342946); the 4 judged positives collapse to these 2 functions (the summary lists the first report per
  function, line 1062; the confirmed report in that function is line 1055).
- Reading [I]: generic-role checkers (r9) fire far more often on other projects than free-form ones (r8:
  252 vs 17 functions) and find later-fixed bugs above chance, but the signal comes from one generic checker
  (memory leak: allocation must be freed or inserted on every path), and precision is low (2 confirmed among
  252 reported functions). r8 checkers are almost silent across projects.
- 02:20: updated `docs/RESULTS_SECTION_3.md` (r9b, historical replay, revised headline/meaning/limits),
  `docs/PROGRESS_SUMMARY.md` (goal 3 done with caveats, section 3 results table, next steps, supervisor
  question) and `docs/PROGRESS_QA.md` (section 3 Q&A rewritten). Evidence export now includes `e2e/hist-v1`
  (without the large `-fixes.json` caches) and the r9b runs. Committed locally; push awaits user confirmation.
