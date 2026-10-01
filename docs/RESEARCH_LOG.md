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
