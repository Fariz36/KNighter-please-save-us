# KNighter fork: progress summary

*Status as of 8 Oct 2026. Branch `general-c-speed` on `Fariz36/KNighter-please-save-us`.*

> **In one sentence:** KNighter now runs on any C/C++ project from a config file, generates and
> validates checkers **3.3× faster with the same success rate**, and judges checkers by whether they
> hit the actual bug. Checkers can be exported as standalone bundles and ported to other projects by
> renaming roles only; a checker generated from a SQLite fix found **2 real memory leaks in libxml2**
> that libxml2 fixed months later, but such transfer is rare and noisy.

---

## 1. Goals from the supervisor and where we stand

| # | Goal | Status | Short version |
|---|---|---|---|
| 1 | Make it faster | ✅ **Done** | 3.3× faster end to end (441 → 135 min on 43 commits), same quality |
| 2 | Target general C (not just Linux kernel) | ✅ **Done** | 7 real projects, 4 build systems, C and C++, config only |
| 3 | Checkers usable across projects | ✅ **Done (with caveats)** | Portable, standalone, ported by role renaming; 2 real cross-project bugs found; transfer is rare and pattern-dependent |
| 4 | Accept a CVE as input | ⬜ **Not started** | Planned after goal 3 |

Plan sections: **0** = correctness fixes (needed so the numbers mean something), **1** = speed,
**2** = general C, **3** = cross-project, **4** = CVE input.

---

## 2. This sprint's scope

- **Done and pushed:** sections 0, 1, 2 (every acceptance criterion checked, evidence committed).
- **Done and pushed:** section 3 (portable checkers, role-based generation, role porting, cross-project
  evaluation). Details: `docs/RESULTS_SECTION_3.md`.
- **Out of scope for now:** section 4 (CVE input), Linux-kernel/V8 regression testing (no kernel or V8
  source on this machine).

---

## 3. What was wrong with the previous attempt (the starting point)

1. **The success metric was too generous.** A checker counted as "valid" if it reported *anything*
   in the patched file, or merely fewer reports after the fix (e.g. 26 → 17 reports was "valid").
2. **Parallel runs scored the wrong checker.** All checkers shared one plugin file; one worker could
   overwrite it while another was validating.
3. **Reruns silently did nothing.** A finished-but-failed commit was never retried.
4. **Slow.** LLM calls had no timeouts (one request hung for 1 h 43 min), every validation
   re-configured the project from scratch, scans ran one file at a time.
5. **Only Linux/V8 were supported.** The libgit2 support was hardcoded for libgit2.
6. **Refinement never worked:** 12/12 and 15/15 attempts failed with "Failed to validate on objects".
7. **Checkers were tied to one project:** 64% hardcoded that project's function names.

---

## 4. What we changed, in plain words

### Correctness (section 0)
- **Checkers are now judged on the real bug.** A checker passes only if it reports *inside the function
  the fix changed* on the buggy version, and stops reporting there after the fix.
- **Every checker gets its own plugin**, identified by a fingerprint of its code. Validation can no
  longer use somebody else's checker.
- **Reruns work.** `--retry_failed` generates new attempts; without it, skipped commits are logged.

### Speed (section 1)
- **Commits run in parallel** (4 workers) instead of one by one.
- **Each project version is configured once and reused**, and the configuring starts in the
  background while the LLM is still thinking.
- **Checker plugins build ~3× faster** (built outside the LLVM tree, with a precompiled header, and cached).
- **Files are analyzed in parallel**, and LLM calls now stream with stall detection and hard deadlines.
- **Refinement's triage asks the LLM about several reports at the same time.**

### General C/C++ (section 2)
- **A new "compile database" target**: any project is added with a YAML file that says how to configure
  it. curl (CMake), SQLite (autotools), Lua (plain Makefile), libxml2 (Meson), libgit2, and two C++
  projects (re2, yaml-cpp) all work, with **no project-specific code**.
- **Prompts name the actual project** instead of always saying "Linux kernel", and the bug triage uses
  generic C reasoning instead of driver/kernel reasoning.
- **Refinement and whole-project scanning now work** on these projects (they were kernel-only or broken).

### Cross-project (section 3)
- **Role-based checkers.** Instead of hardcoding names like `git_error_set` or `xmlMalloc`, checkers ask
  "is this call an *allocator*?". The real names live in a small roles file that can be swapped per
  project.
- **Portable bundles.** Each checker can be exported as a folder (plugin, source, roles, manifest, run
  script) that runs on any project with plain Python and clang, and can be rebuilt for another clang.
- **Role porting.** One LLM step proposes the target project's names for each role; every name is checked
  against the target's source. The checker plugin itself never changes.
- **Role matching fixed for real C code:** calls through macro wrappers (`curlx_free`) and function
  pointers (`xmlFree`) now match their role (before, they silently never did).

---

## 5. Evidence (headline numbers)

| What | Before | After | How measured |
|---|---|---|---|
| End-to-end time, 43 commits / 7 projects | 441.0 min | **135.2 min (3.3×)** | Same commits, same LLM settings, baseline vs optimized |
| Commits with a working checker | 26/43 | **27/43** | Strict scoring, both variants |
| Same 22 checkers, build + validate only | 1699 s | **312 s (5.4×)** | **Identical verdicts on all 22** |
| Whole-project scan of curl | 484 s | **88 s (5.5×)** | **Identical 1,029 reports** |
| Validations using the correct plugin | not guaranteed | **152/152** | Byte-identical source check |
| Refinement repairs that validate | 0% (12/12 failed) | **100% (4/4)** | Root cause: wrapped file paths |
| Checkers hardcoding project names | 64–76% | **0% (0/45)** | Role-based generation |
| Commits solved with role-based checkers | 17/26 | **19/26** (free-form roles) / 14 and 12/26 (generic roles) | Same 26 commits |
| Real bugs found in another project by a ported checker | – | **2** (libxml2 2.15.0, fixed 3 and 5 months later) | Blind scan of an old release + manual review |

**Per project** (baseline → optimized wall time, perfect checkers):

| Project | Type | Time | Speedup | Success |
|---|---|---|---|---|
| Lua | C, plain Makefile | 41.7 → 7.6 min | 5.5× | 3/4 → 4/4 |
| re2 | C++, CMake | 31.9 → 12.4 min | 2.6× | 3/4 → 3/4 |
| yaml-cpp | C++, CMake | 44.0 → 15.3 min | 2.9× | 2/3 → 1/3 |
| libxml2 | C, Meson | 65.7 → 25.7 min | 2.6× | 4/7 → 5/7 |
| SQLite | C, autotools | 73.4 → 26.1 min | 2.8× | 3/7 → 2/7 |
| curl | C, CMake | 90.5 → 22.9 min | 3.9× | 5/8 → 6/8 |
| libgit2 | C, CMake | 93.8 → 25.3 min | 3.7× | 6/10 → 6/10 |

**End-to-end demonstrations**
- **Scan + triage on an old curl release (8.10.0):** 3 checkers flagged 3 real bugs, each exactly in
  the function curl fixed later (`curl_easy_recv`, `ossl_verifyhost`, base64 size in `mime.c`).
  *(These are the bugs the checkers came from, so this shows the pipeline works, not that it finds new bugs.)*
- **Refinement loop on curl:** report → LLM says false positive → checker rewritten → the false report
  disappears → checker still catches its original bug.
- **Portable bundle:** run with plain system Python outside the repo, it finds the same report as KNighter;
  rebuilt from source with CMake, it still finds the same report.

**Where the evidence is:** `docs/RESULTS_SECTIONS_0_2.md` (every acceptance criterion),
`bench/evidence/` (raw numbers, 2,059 files), `docs/RESEARCH_LOG.md` (full chronology, including
failures and corrections).

---

## 6. Section 3: results

**Works**
- 0 hardcoded project names in role-based checkers; bundles run standalone and rebuild from source.
- Porting a checker back to its own project from scratch keeps detection in **18/18** cases.
- **Real cross-project detection:** a checker generated from a SQLite memory-leak fix, ported to libxml2 by
  renaming roles, found 2 real leaks in libxml2 2.15.0 (`xmlwriter.c:1055` and `:1798`) at the exact lines
  libxml2 fixed 3 and 5 months later, both in a blind whole-project scan and on the fix commits.

**Limits (honest version)**

| Test | Result |
|---|---|
| Same-type real fixes in other projects (r9) | 2/27 detected; most ported checkers stay silent |
| Old-release scan (historical replay, r9) | 13 later-fixed functions hit vs 5.6 by chance; 2 confirmed bugs; 12/13 hits from one checker |
| Whole-project scan at HEAD (r9) | 458 reports; the LLM triage's 2 "bugs" were both false positives |

**Why transfer is rare:** roles fix *naming* differences between projects, but not differences in *how the
code is written* (e.g. curl returns error constants, Lua calls `luaL_error`). Generic patterns (memory must be
freed on every path) transfer; project-specific ones don't. Generic roles also cost detection on the source
project (19 → 14 and 12/26).

## 7. Interesting findings (useful for the paper)

- **The old success rule gave false credit:** 5 checkers it called "valid" still fire on the fixed code.
- **One "failed" commit was never solvable:** libgit2 `93b16df1`'s buggy version doesn't compile at all.
  The previous attempt counted it as a generation failure.
- **Refinement failures came from a text-formatting detail:** report paths were line-wrapped, so the
  file couldn't be found again.
- **Reasoning models need big output budgets:** with 16k tokens, the model spent everything "thinking"
  and returned nothing (likely the previous attempt's "Code Generation returned None").
- **LLM provider stalls are a real speed factor:** one request hung for 1 h 43 min until streaming
  watchdogs were added.

---

## 8. Caveats (be upfront about these)

- One run per variant: success-rate differences of ±1–2 commits are within noise.
- The baseline cannot use the original in-tree build (stale LLVM tree), so it replays the same commands
  without `make` overhead. **The speedup is therefore conservative.**
- Linux-kernel and V8 paths are untested (no source trees here); item 1.3 (faster kernel checkout) is
  implemented but unverified.
- Strict scoring only judges *this* bug, not noise elsewhere (noise is refinement's job).

---

## 9. Next steps

1. Decide with the supervisor how to frame section 3 (see questions below).
2. **Section 4: CVE as input** (CVE ID → fix commit(s) → existing pipeline; libxml2 is a good test bed).
3. Optional section 3 follow-ups: a larger matched-pair set, a manually reviewed sample of HEAD-scan reports,
   and making checkers model "pointer stored in a struct field and freed through it" (the main false-positive
   source).

## 10. Questions for the supervisor

1. Is "3.3× faster at equal success" (plus the 5.4× deterministic replay) the right speed claim?
2. Is function-level strict scoring acceptable as the main metric, with the old metric alongside?
3. For cross-project: is "2 real bugs found in another project's old release (already fixed upstream)" plus
   the measured trade-off enough, or do we need a confirmed *new* (unfixed) bug?
4. Should section 4 (CVE input) start before cross-project detection is solved?

---

## Glossary

- **Checker:** a Clang Static Analyzer plugin generated by the LLM from one bug-fix commit.
- **TP / TN (strict):** TP = reports inside the fixed function on the buggy version;
  TN = no such report after the fix. "Perfect" = both.
- **Baseline / optimized:** upstream-style pipeline vs. this fork, same LLM and settings.
- **Replay:** re-running the same checkers through build + validation only, to measure speed without LLM randomness.
- **Role:** an API category (allocator, deallocator, error setter …) a checker asks about instead of a name.
- **Bundle:** an exported checker folder that runs without KNighter.
- **Porting:** mapping a bundle's roles to another project's function names.
