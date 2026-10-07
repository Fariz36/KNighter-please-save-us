# Results: section 3 (checkers usable across projects)

Evidence report for the cross-project part of the KNighter fork. Every number comes from artifacts under
`e2e/` and `bench/runs/` (scripts named per row). The full chronology, including failed runs and
corrections, is in `docs/RESEARCH_LOG.md` (entries of 2026-10-01, 2026-10-07 and 2026-10-08).

Setup as in sections 0–2 (WSL2, 16 cores; LLVM/Clang 18.1.8; `deepseek-v4.1-flash` via OpenCode Go;
strict scoring). Projects: curl, libxml2, Lua, SQLite (26 benchmark commits).

## Headline

- **Design:** a checker is a compiled plugin plus a **roles file**. The checker asks "is this call a
  `deallocator`?" and the roles file names the project's functions for each role. Porting to another
  project = one LLM call that proposes the target's names from candidates found in its source; **the
  plugin itself never changes.**
- **Portability achieved:** role-based checkers hardcode **0** project identifiers (0/45 in r8, 0/48 in
  r9; plain generation: 64–76% do), export as standalone bundles, run with plain system Python, and
  rebuild from source.
- **Porting machinery works:** porting each checker back to its own project from scratch preserves
  detection in **18/18** cases.
- **Cross-project detection of real bugs exists, but is rare and imprecise.** A checker generated from a
  **SQLite** memory-leak fix, ported to libxml2 by renaming roles only, found **2 real memory leaks** in
  libxml2 at the exact lines the libxml2 developers later fixed. It did so twice, independently: on
  pre-selected same-class fix commits (matched pairs), and in a **blind whole-project scan of the old release
  libxml2 2.15.0** (historical replay), where the leaks were fixed 3 and 5 months after the release. In that
  scan it also reported 125 other functions, and in matched pairs it still reports after the fix.
- **Generic roles fire more and find more, at a price.** Historical replay: r9 checkers report in 252
  functions of other projects, with 13 hits on later-fixed functions vs 5.6 expected by chance; r8 checkers
  report in 17, with 0 hits. On the source project, generic roles cost detection (r9 14/26, repeat r9b 12/26,
  vs r8 19/26).

## 3.1-A Role-based generation

| | plain (r7-B) | r8: free-form roles | r9: vocabulary, functions/macros only |
|---|---|---|---|
| attempts hardcoding project identifiers (lint) | 35/46 (76%) | **0/45** | **0/48** |
| commits with a perfect checker (26) | 17/26 | **19/26** | **14/26** (repeat r9b: 12/26) |
| roles from the standard vocabulary | – | 21.1% | **85.2%** |
| role names that are functions/macros | – | ≤ 84.5% | **100%** |
| roles per attempt | – | 4.53 | 2.96 |

Per project (perfect commits) r8 → r9 / r9b: curl 6 → 5 / 5, libxml2 6 → 5 / 4, Lua 3 → 2 / 1, SQLite 4 → 2 / 2.
r9b repeats r9 (same commits and settings, final `roles.h`): the drop reproduces in every project (r9b vocabulary
roles 90.8%, callables 98.7%, 0/47 hardcoded). Effective denominators are /24: curl `c4cb6769` and SQLite
`97467fa8` patch code that is compiled out in our builds (`bench/compiled_out.py`).

Scripts/evidence: `bench/role_stats.py r8 r9 r9b`, `src/checker_lint.py`, `e2e/revalidate/` (all r8/r9 numbers
re-validated with the final `roles.h`, below).

## 3.3 Portable bundles

`main.py export` writes a folder per checker: `plugin.so`, `checker.cpp`, `roles/<project>.json`,
`manifest.yaml`, `patch.md`, a stdlib-only runner (`run_bundle.py`), and a CMake rebuild kit.

| Check | Result |
|---|---|
| Bundles exported (r8 / r9, final header) | 18 / 13, **all `portable: true`** (`e2e/bundles-r8h2`, `e2e/bundles-r9h2`) |
| Standalone run outside the repo, `env -i`, system Python 3.14, curl 8.10.0 (169 files) | same single report as KNighter (`lib/mime.c:523`), 0 failures |
| Rebuild from source with CMake | 8.8 MB plugin, 2 exported symbols, identical report |

## 3.1-B Role porting

One LLM call per (checker, target): candidates are extracted from the target's headers and ranked per
role; the LLM picks names; every name is validated against **all identifiers in the target's
sources**; standard-library names carry over unchanged.

**Positive control (self-port)**, `bench/self_port.py`, `e2e/selfport-r8/`: port each r8 checker to its
**own** project from scratch and scan the buggy revision.

| | detection preserved |
|---|---|
| v1 (original porting) | **0/8** |
| v2 (porting fixes below) | **18/18** (same report counts; mapping identical in 11/18) |

Caveat: in a self-port the LLM sees the source names, which exist in the target, so this shows the
machinery is sound, not that roles have counterparts in other projects.

## 3.4 Cross-project evaluation

Five experiments; matched pairs and historical replay have ground truth for "found a real bug".

| Experiment | What is analysed in target Q | Result |
|---|---|---|
| HEAD scan v1/v2 (`bench/cross_project.py`, r8, pre-fix porting) | the whole project at HEAD (curl 194, libxml2 68, Lua 34 files) | 0 reports in all scanned pairs; **invalid as evidence**: in v2 only 3/40 pairs had every role mapped, and several roles were bound to names the checker can never match (below) |
| Known bugs (`bench/cross_known.py`, r8, partial) | Q's own benchmark commits (mostly other bug classes) | 0 detections in 42/54 pairs (pre-fix header; reported only as a control) |
| **Matched pairs** (`bench/matched_pairs.py`) | real **same-class** fix commits of Q that touch the ported API, selected deterministically | below |
| **Historical replay** (`bench/historical_replay.py`) | the whole project at a release ≥ 12 months before HEAD; ground truth = functions later changed by small fix commits | below |
| HEAD scan v3 (`bench/cross_project.py`, r9, final porting + `roles.h`) | the whole project at HEAD | checkers now **fire**: 15/39 pairs, 458 reports; LLM triage of 63 → 2 "Bug", **both false positives** on manual review (curl `Curl_mime_add_header`: the callee does not free on error; libxml2 `nodePop` mis-mapped to `container_remove`) → 0 confirmed new bugs |

**Matched pairs v1** (`e2e/matched-v1/`, `bench/matched_report.py`). Ground truth: Q's history since 2019,
bug keywords in the subject, ≤ 40 changed source lines, same keyword-guessed bug type as the checker, and the
fix's changed lines mention ≥ 1 ported name; top 3 by API overlap; unbuildable revisions skipped. Scoring: strict
TP on the buggy parent, TN on the fix.

| | r9 checkers (13 × 3 targets) | r8 checkers (18 × 3 targets) |
|---|---|---|
| (checker, target) pairs with ≥ 1 matched fix | 15/39 | 30/54 |
| validated fix commits | 27 | 56 |
| ported checker reports anything in the patched files | 4/27 | 2/56 |
| **detected (TP > 0)** | **2/27** | **0/56** |
| perfect (TP and TN) | 0/27 | 0/56 |

Candidate commits that could not be set up (dev revisions that do not build, files outside the library
build) were skipped: 24 (r9) and 28 (r8). The r8 vs r9 difference is **not** a clean comparison of role
styles: the checker behind both detections (SQLite `7b60ed80`, memory leak) exists only in r9; r8 produced
no perfect checker for that commit.

The two detections (r9 SQLite memory-leak checker → libxml2), checked by reading the diffs and report paths:

- `c1342946` "fix memory leak in issue 1054" (`xmlTextWriterStartAttributeNS`): report at **line 1804**, the
  `return -1` where `buf` leaks; the report's path tracks `buf`; the fix inserts `xmlFree(buf);` at that line.
- `98194640` "Fix memory leak of prefix in xmlTextWriterStartElementNS()": report at **line 1055**, the
  `return -1` where `p->prefix` leaks; the fix adds `xmlFree(p->prefix)` there.
- Both TN = 0: after the fix the checker still reports at the same returns. It does not model a pointer
  stored into a field and freed through it (`p->prefix = buf; … xmlFree(p->prefix)`), and it reports 9 other
  places in `xmlwriter.c` on both revisions.
- For contrast, the r8 curl memory-leak checker (pattern specific to curl's `cf_h2_proxy` context cleanup)
  was validated on the same two libxml2 commits: 0/0.

**Historical replay v1** (`e2e/hist-v1/`, `bench/hist_report.py`). Old release = latest tag that is an ancestor
of HEAD and ≥ 12 months older: curl-8_16_0, libxml2 v2.15.0, Lua v5.5-beta, SQLite 3.50.0. Ground truth = non-merge
commits in tag..HEAD with bug keywords, source-only, ≤ 40 changed lines, and the functions they change. **Base rate** =
share of all functions in the scan scope that were later fixed: curl 9.75%, libxml2 1.46%, Lua 1.1%, SQLite 6.97%
(a checker reporting in random functions hits at this rate). Hits are judged by the LLM against the fix diff;
every positive verdict was checked by hand.

| | r9 checkers | r8 checkers |
|---|---|---|
| pairs scanned (≥ 1 role mapped) | 37/39 | 50/54 |
| pairs that report | 14 | 6 |
| distinct functions reported | 252 | 17 |
| **hits** (function later fixed) | **13** | 0 |
| hits expected by chance | 5.6 | 0.5 |
| **manually confirmed real bugs** | **2** | 0 |

12 of the 13 r9 hits come from one checker, SQLite memory leak `7b60ed80` (libxml2 9/127 functions, curl 2/7,
Lua 1/38). The enrichment is in libxml2 only (10 hits vs 2.0 expected; curl 2 vs 0.9, Lua 1 vs 0.9, SQLite 0 vs
1.8). Confirmed in libxml2 2.15.0 (released 2025-09-15):

- `xmlwriter.c:1055` `xmlTextWriterStartElementNS`: path `p` allocated → `p->prefix = buf` → `p->uri == NULL` →
  `xmlFree(p); return -1` leaks the prefix. Fixed 2025-12-12 by `98194640`.
- `xmlwriter.c:1798` `xmlTextWriterStartAttributeNS`: `buf` allocated → `p == NULL` → `return -1` leaks `buf`. Fixed
  2026-02-11 by `c1342946`.
- Rejected on review: `xmlwriter.c:1062` (the LLM judge matched it to `cee7107a`'s `nsstack == NULL` guard, but the
  path does not take that branch) and `xmlreader.c:5089` (report at the `input == NULL` return; nothing leaks).
  The checker made only 3 reports in `xmlwriter.c`; 2 are these leaks.

## Bugs found and fixed along the way (all affect cross-project results)

| Bug | Effect | Fix | Evidence |
|---|---|---|---|
| Header scan missed declaration styles: Lua `LUA_API int (lua_gettop) (…)`, libxml2 return type on the previous line | the LLM's correct names were rejected as "not in target": self-port 0/8 | two more declaration patterns; validate names against every identifier in the target's sources | `test_role_porting.py`; self-port 18/18 |
| `roles.h` matched only the resolved callee of preprocessed code | calls through **macro wrappers** (curl `curlx_free`) or **function-pointer variables** (libxml2 `xmlFree`, curl `Curl_cfree`) never matched a role | `callIsRole`/`callExprIsRole` also match the function-pointer variable/field and every macro in the call's expansion chain | `bench/roles_matching.py`: curl `curlx_free` 0 → 6 calls, `Curl_cfree` 0 → 6, libxml2 `xmlFree` 0 → 52; a correct libxml2 checker (`ddcb79dc`) went 0/0 → perfect in both r8 and r9 |
| r8 roles bound bug-site details (fields `len`, locals `bufpt`, types, constants) | untransferable; porting put a macro (`luaZ_sizebuffer`) into a field role, so the gate can never be true | r9 prompts: standard vocabulary, functions/macros only | 100% callables in r9 |
| Porting mapped the bug instance, not the category | e.g. `deallocator` → one object's free function | port prompt: map the role's category across the whole project | `ports/*.json` rationales |
| Missing compile entry reported as checker failure (-3) | unbuildable files counted as validations | recorded as a setup error | log 2026-10-07 18:25 |
| 4/43 benchmark commits are compiled out (`#if` disabled features) | unsolvable for every variant | `bench/compiled_out.py` precheck | curl c4cb6769, libgit2 0bc19591 and ef086bc3, sqlite 97467fa8 |

## What this means

- **Plug-in porting works mechanically** (0 hardcoded names, 18/18 self-port, standalone bundles), and it
  can carry a checker's detection to another project: SQLite → libxml2, 2 real leaks at the fix lines, found
  both on selected fix commits and in a blind scan of an old release.
- **Transfer is pattern-dependent.** Roles absorb *name* differences, not *code-shape* differences (error
  constants vs error calls, fields vs accessors). Generic API patterns (allocation must be freed or stored on
  every path) transfer; project-shaped patterns (curl blob guard, Lua GC barrier, libxml2 consuming
  constructors) do not. Example: curl `f7d4e11f` on Lua finds nothing even with hand-corrected roles,
  because Lua contains no code of that shape (`e2e/lua-len-recheck/`).
- **Firing is not finding.** After the fixes, ported checkers fire on whole projects (15/39 pairs, 458
  reports), but no new bug was confirmed, and the LLM triage's two positive verdicts were both wrong:
  cross-project reports need manual confirmation.
- **Most ported checkers are silent in other projects** (no report in the patched files in 23/27 r9 and
  54/56 r8 validated pairs), and the detections that happen are imprecise. The cross-project signal comes
  from one generic checker (allocation must be freed or stored on every path).
- **Generic vs free-form roles is a real trade-off:** generic roles cost source-project detection (19 →
  14 and 12/26 in two runs) but make checkers fire on other projects (252 vs 17 functions) and find
  later-fixed bugs above chance (13 vs 5.6 expected); free-form roles are nearly silent elsewhere.

## Limits

- One r8 run and two r9 runs; small numbers (27 validated r9 pairs, 13 historical hits, 2 confirmed bugs, all from
  one checker).
- Historical ground truth is "function later changed by a small fix"; a hit is not a confirmed bug until reviewed.
- Bug types of mined fixes are keyword guesses; every reported detection was checked by hand, but
  misses may include commits of a different real class.
- Candidate selection requires the fix to mention a ported name, which favours checkers whose roles map
  broadly.
- Linux/V8 untested (no trees).
