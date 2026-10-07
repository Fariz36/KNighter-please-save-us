# Results: section 3 (checkers usable across projects)

Evidence report for the cross-project part of the KNighter fork. Every number comes from artifacts under
`e2e/` and `bench/runs/` (scripts named per row). The full chronology, including failed runs and
corrections, is in `docs/RESEARCH_LOG.md` (entries of 2026-10-01 and 2026-10-07).

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
- **Cross-project detection of real bugs exists, but is rare:** in the matched-pair experiment
  (checker from P validated on same-class bug fixes of Q), a checker generated from a **SQLite**
  memory-leak fix flagged **2 real libxml2 memory leaks at the exact lines the libxml2 developers later
  fixed**. Both detections are imprecise (the checker still reports after the fix), and in 23 of 27
  validated pairs the ported checker reported nothing in the patched files.
- **Trade-off:** forcing generic, function-only roles (r9) makes roles portable (85% standard
  vocabulary, 100% callables) but lowers detection on the source project (14/26 vs 19/26 commits).

## 3.1-A Role-based generation

| | plain (r7-B) | r8: free-form roles | r9: vocabulary, functions/macros only |
|---|---|---|---|
| attempts hardcoding project identifiers (lint) | 35/46 (76%) | **0/45** | **0/48** |
| commits with a perfect checker (26) | 17/26 | **19/26** | **14/26** |
| roles from the standard vocabulary | – | 21.1% | **85.2%** |
| role names that are functions/macros | – | ≤ 84.5% | **100%** |
| roles per attempt | – | 4.53 | 2.96 |

Per project (perfect commits) r8 → r9: curl 6 → 5, libxml2 6 → 5, Lua 3 → 2, SQLite 4 → 2. One run per
variant; the drop occurs in every project. Effective denominators are /24: curl `c4cb6769` and SQLite
`97467fa8` patch code that is compiled out in our builds (`bench/compiled_out.py`).

Scripts/evidence: `bench/role_stats.py r8 r9`, `src/checker_lint.py`, `e2e/revalidate/` (all r8/r9 numbers
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

Four experiments; only matched pairs has ground truth for "found a real bug".

| Experiment | What is analysed in target Q | Result |
|---|---|---|
| HEAD scan v1/v2 (`bench/cross_project.py`, r8, pre-fix porting) | the whole project at HEAD (curl 194, libxml2 68, Lua 34 files) | 0 reports in all scanned pairs; **invalid as evidence**: in v2 only 3/40 pairs had every role mapped, and several roles were bound to names the checker can never match (below) |
| Known bugs (`bench/cross_known.py`, r8, partial) | Q's own benchmark commits (mostly other bug classes) | 0 detections in 42/54 pairs (pre-fix header; reported only as a control) |
| **Matched pairs** (`bench/matched_pairs.py`) | real **same-class** fix commits of Q that touch the ported API, selected deterministically | below |
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
  can carry a checker's detection to another project: SQLite → libxml2, 2 real leaks at the fix lines.
- **Transfer is pattern-dependent.** Roles absorb *name* differences, not *code-shape* differences (error
  constants vs error calls, fields vs accessors). Generic API patterns (allocation must be freed or stored on
  every path) transfer; project-shaped patterns (curl blob guard, Lua GC barrier, libxml2 consuming
  constructors) do not. Example: curl `f7d4e11f` on Lua finds nothing even with hand-corrected roles,
  because Lua contains no code of that shape (`e2e/lua-len-recheck/`).
- **Firing is not finding.** After the fixes, ported checkers fire on whole projects (15/39 pairs, 458
  reports), but no new bug was confirmed, and the LLM triage's two positive verdicts were both wrong:
  cross-project reports need manual confirmation.
- **Most ported checkers are silent in other projects** (no report in the patched files in 23/27 r9 and
  54/56 r8 validated pairs), and the detections that happen are imprecise. Generic roles cost source-project
  detection (19 → 14/26).

## Limits

- One generation run per variant; small numbers (27 validated r9 pairs).
- Bug types of mined fixes are keyword guesses; every reported detection was checked by hand, but
  misses may include commits of a different real class.
- Candidate selection requires the fix to mention a ported name, which favours checkers whose roles map
  broadly.
- Linux/V8 untested (no trees).
