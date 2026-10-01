# Results: sections 0–2 (correctness, speed, general C/C++)

Evidence report for the KNighter fork, checked against the acceptance criteria set in the plan. All
numbers come from committed artifacts under `bench/evidence/` (regenerable with
`bench/aggregate.py`, `bench/report.py`, `bench/audit_plugins.py`). The full chronology, including
failed runs and corrections, is in `docs/RESEARCH_LOG.md`.

Setup: WSL2 on a 16-core / 15 GB laptop; LLVM/Clang 18.1.8 (KNighter build); LLM `deepseek-v4.1-flash`
via OpenCode Go (temperature 1.0, 65,536-token budget, 600 s deadline, 180 s stall timeout);
`checker_nums: 3`; strict scoring.

## Headline

| | Baseline (upstream-equivalent) | Optimized | |
|---|---|---|---|
| Wall time, 43 commits / 7 projects | 441.0 min | **135.2 min** | **3.3× faster** |
| Commits with a perfect checker (strict) | 26/43 | 27/43 | same quality |
| Same checkers, build + validate only (replay, 22 checkers) | 1698.8 s | 312.4 s | 5.4×, **identical verdicts** |
| Whole-project scan, 194 curl files | 484.0 s (`jobs=1`) | 88.0 s (`jobs=8`) | 5.5×, **identical 1029 reports** |

Per project (`bench/aggregate.py r7`; no run lost time to machine suspend):

| Project | Language / build | Commits | Wall A → B (min) | Speedup | Perfect A / B |
|---|---|---|---|---|---|
| Lua | C / plain Makefile | 4 | 41.7 → 7.6 | 5.5× | 3/4 · 4/4 |
| re2 | C++ / CMake | 4 | 31.9 → 12.4 | 2.6× | 3/4 · 3/4 |
| yaml-cpp | C++ / CMake | 3 | 44.0 → 15.3 | 2.9× | 2/3 · 1/3 |
| libxml2 | C / Meson | 7 | 65.7 → 25.7 | 2.6× | 4/7 · 5/7 |
| SQLite | C / autosetup + make | 7 | 73.4 → 26.1 | 2.8× | 3/7 · 2/7 |
| curl | C / CMake | 8 | 90.5 → 22.9 | 3.9× | 5/8 · 6/8 |
| libgit2 | C / CMake | 10 | 93.8 → 25.3 | 3.7× | 6/10 · 6/10 |

Baseline = what upstream does, on the same generic target: sequential commits, a fresh configure on every
checkout, serial analysis, and an uncached `-O3` plugin rebuild per compile. The in-tree `make` could
not be run (stale LLVM tree), so the baseline replays the same compile/link commands and **understates**
upstream cost (no make overhead). Optimized = 4 parallel workers, cached per-revision worktrees with
background prefetch, parallel analysis, `-O1` + PCH content-addressed plugins. Both variants accept
identical checker code (text preamble, review item A5) and use identical LLM settings.

## Section 0 — correctness

| Item | Acceptance criterion | Result | Evidence |
|---|---|---|---|
| 0.1 Strict TP/TN | Unit tests: a report outside the patched function gives TP=0; fewer-but-nonzero on-target reports after the fix give TN=0 | ✅ | `src/tests/test_validation_scoring.py` (13 tests incl. C++ names, gap anchors) |
| | List which previously "valid" checkers truly hit the bug | ✅ | 152 r7 attempts: 51 valid under both rules, **5 valid only under the old rule** (all still report in the patched function after the fix; one credited by an unrelated file), 2 strict-only (noisy checkers that do hit and clear the patched function) |
| 0.2 Right checker scored | In parallel runs, the plugin used matches the scored checker in 100% of validations | ✅ | `bench/audit_plugins.py`: **152/152** byte-identical (incl. 4-worker runs) |
| 0.3 Reruns rerun | Complete non-perfect ranking + `--retry_failed` creates new attempts; without the flag "skipped" is logged; `eval` gone | ✅ | curl 6f1dfab6 (ranking `[[0,0,0],[1,0,0],[2,0,0]]`, `checker_nums 1`): no flag → "skipped, 3 attempts without a perfect checker" in seconds; `--retry_failed` → attempt `checker_03` generated (ranking now 4 entries). `e2e/retry-curl-*.log`; `test_gen_helpers.py` (`eval` payload rejected) |

## Section 1 — speed

| Item | Acceptance criterion | Result | Evidence |
|---|---|---|---|
| 1.1 LLM calls | Wall time ≥ 30% lower; build failures ≤ 1/4; valid count not below baseline | ✅ wall −69% (3.3×); ⚠️ see note; ✅ 27 vs 26 | r7 aggregate |
| 1.2 No global lock | No global lock; TP/TN identical to 1-worker; repeat validation skips configure | ✅ | Replay: 22/22 identical verdicts; median setup 44.9 s → 0.01 s; no lock in code |
| 1.3 Linux checkout | Second validation of a kernel commit skips `make clean`/`allyesconfig` | ⛔ not testable | Implemented opt-in (`linux_incremental`); no kernel tree on this machine |
| 1.4 Parallel scan | Same report set as serial; wall ≤ 40% of serial | ✅ 18% | `e2e/scan-parity/parity.json`: 1029 = 1029 reports, 484 s → 88 s |
| 1.5 Refine | Validation-failure rate < 20%; triage of N reports ≈ slowest call | ✅ 0/4 failures; triage = slowest call | 21 strict-valid r7-B checkers, 6 projects, threshold 0 (`e2e/refine-t0-*.log`): 4 FP reports (curl 2, libxml2 2) → 4 repairs, **4/4 killed the FP and re-validated strict 1/1** (0 object / 0 commit failures; previous attempt 12/12 and 15/15 failed: wrapped-path bug). Triage of 2 reports ran concurrently: 55.1 s vs 97.3 s serial (curl), 14.2 vs 28.1 s (libxml2) |

Note on 1.1: syntax-repair calls were 130 (baseline) / 110 (optimized) for 152 attempts; the "≤ 1/4 build
failures" target is about first-try compile success, which is a prompt-quality property not addressed
in section 1 (both variants share prompts). The measured speedup comes from infrastructure; the
thinking-off experiment for LLM latency remains a separate follow-up.

Other speed facts (r7 and earlier logs): per-checker plugin build 36 s → 10–14 s (`-O1` + PCH);
curl configure 47–64 s per revision paid once instead of per validation; whole-curl scans 50–65 s
(previous attempt's serial libgit2 scan: 11–14 min); LLM stalls bounded by streaming + watchdog
(one pre-fix request hung 6164 s).

## Section 2 — general C/C++

| Item | Acceptance criterion | Result | Evidence |
|---|---|---|---|
| 2.1 Target lookup | Unknown `target_type` fails clearly; Linux/V8 still work | ✅ / ⛔ | `src/tests/test_target_registry.py`; Linux/V8 untestable here (no trees) |
| 2.2 Generic target | Gen + validation end to end on ≥ 3 projects with different build systems, config only | ✅ 7 projects, 4 build systems + C++ | `configs/*.yaml`; r7 runs; `bench/evidence/precheck/` (real analysis of every patched file) |
| 2.3 Interface | No `target_type` branches in the generic path | ✅ | `CompileDBTargetBase`; grep of `csa_compiledb.py`, `checker_gen.py`, `checker_scan.py` |
| 2.4 Prompts | No "Linux kernel" in generic prompts; kernel config keeps kernel wording; thresholds from config | ✅ | `src/tests/test_prompts.py` (4) |
| 2.5 No libgit2 code | `grep -ri libgit2 src/` finds nothing; libgit2 runs from config | ✅ | 0 hits; r7 libgit2 6/10 · 6/10 |

End-to-end beyond gen: refine loop on curl works after fixing wrapped report paths (1 FP triaged,
repaired, killed, re-validated strict 1/1); generic scan + triage on curl 8.10.0 re-discovered the 3 bugs
later fixed in the patched functions (`curl_easy_recv`, `ossl_verifyhost`, base64 size in `mime.c`).

## Findings worth reporting

- **Unanalyzable commits look like generation failures.** libgit2 `93b16df1` (previous attempt: TP=0)
  does not compile at its buggy parent; no checker could ever be validated. The precheck now runs real
  analysis on every patched file.
- **Report-path wrapping broke refinement** (`html2text` line wrapping split long paths): the cause of the
  previous attempt's 12/12 and 15/15 "Failed to validate on objects".
- **Reasoning models need large output budgets**: at 16k tokens `plan2checker` spent the entire budget on
  reasoning and returned nothing (likely the previous attempt's "Code Generation returned None").
- **Strict scoring rejects 5 checkers the old rule accepted** and is insensitive to noise outside the
  patched function (noise is refinement's job).

## Not achieved / limits

- 1.3 and Linux/V8 regressions are untested (no kernel or V8 tree).
- 43 commits is enough for the speed claim and a coarse quality comparison, not for a precise
  success-rate estimate (one run per variant; LLM output is stochastic).
- Strict scoring cannot credit a report that ends in a callee outside the patched function (A2); it
  was not observed in r7.
