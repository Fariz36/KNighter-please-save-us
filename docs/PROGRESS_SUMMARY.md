# KNighter fork: progress summary

*Status as of 2 Oct 2026. Branch `general-c-speed` on `Fariz36/KNighter-please-save-us`.*

> **In one sentence:** KNighter now runs on any C/C++ project from a config file, generates and
> validates checkers **3.3× faster with the same success rate**, and judges checkers by whether they
> hit the actual bug. Checkers can now be exported as standalone, project-independent bundles, but
> using them **on other projects does not find anything yet**; that is the current open problem.

---

## 1. Goals from the supervisor and where we stand

| # | Goal | Status | Short version |
|---|---|---|---|
| 1 | Make it faster | ✅ **Done** | 3.3× faster end to end (441 → 135 min on 43 commits), same quality |
| 2 | Target general C (not just Linux kernel) | ✅ **Done** | 7 real projects, 4 build systems, C and C++, config only |
| 3 | Checkers usable across projects | 🟡 **In progress** | Checkers are now portable and standalone, but they don't find bugs in other projects yet |
| 4 | Accept a CVE as input | ⬜ **Not started** | Planned after goal 3 |

Plan sections: **0** = correctness fixes (needed so the numbers mean something), **1** = speed,
**2** = general C, **3** = cross-project, **4** = CVE input.

---

## 2. This sprint's scope

- **Done and pushed:** sections 0, 1, 2 (every acceptance criterion checked, evidence committed).
- **Built, tested, not pushed:** section 3 (portable checkers, role-based generation, role porting).
- **In progress:** section 3.4, making ported checkers actually find bugs in other projects.
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

### Cross-project (section 3, not pushed yet)
- **Role-based checkers.** Instead of hardcoding names like `git_error_set` or `xmlMalloc`, checkers ask
  "is this call an *allocator*?". The real names live in a small roles file that can be swapped per
  project.
- **Portable bundles.** Each checker can be exported as a folder (plugin, source, roles, manifest, run
  script) that runs on any project with plain Python and clang, and can be rebuilt for another clang.
- **Role porting.** One LLM step proposes the target project's names for each role, choosing only from
  names that really exist in the target's headers.

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
| Commits solved with role-based checkers | 17/26 | **18/26** | Same 26 commits |

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

## 6. Section 3: what works and what doesn't yet

**Works**
- 45/45 role-based checkers use roles correctly, with 204 role descriptions; 0 hardcoded project names.
- Success rate didn't drop because of roles (18/26 vs 17/26).
- Bundles export, run standalone, and rebuild from source.

**Doesn't work yet: checkers find nothing in *other* projects**

| Cross-project run | Pairs (checker × other project) | Roles mapped | Reports found |
|---|---|---|---|
| v1 (first try) | 54 | 33% | **0** |
| v2 (fixed porting; 3 of 4 targets, interrupted) | 40 | 39% | **0** |

**Why (diagnosed):**
1. **Roles are too specific.** Generated roles describe the bug itself (e.g. "consumer frees on
   failure", "GC root anchor") instead of reusable API categories ("deallocator"), so other projects have
   no equivalent. *Fix written (standard role vocabulary in the prompts), needs a regeneration run.*
2. **Porting missed real APIs.** SQLite's public API lives in a `.h.in` file that was skipped, and
   "free" did not match "delete"/"destroy". *Fixed (v2): mapping went 33% → 39%.*
3. **Open question:** with zero reports we can't yet tell "no such bug exists there" from "ported
   checkers can't fire". A **positive control** is ready: port a checker back to its *own* project
   from scratch and check it still catches its original bug.

---

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

1. **Positive control** (self-port): does porting preserve detection? (~30 min)
2. **Regenerate with generic roles** (r9, ~2 h), then **cross-project v3**, to see if checkers find
   anything in other projects.
3. Write `docs/RESULTS_SECTION_3.md`; push section 3 after review.
4. **Section 4: CVE as input** (CVE ID → fix commit(s) → existing pipeline; libxml2 is a good test bed).

## 10. Questions for the supervisor

1. Is "3.3× faster at equal success" (plus the 5.4× deterministic replay) the right speed claim?
2. Is function-level strict scoring acceptable as the main metric, with the old metric alongside?
3. For cross-project: is "the checker runs on another project and its reports are triaged" enough, or
   do we need confirmed new bugs?
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
