# KNighter fork: questions and answers

A companion to `docs/PROGRESS_SUMMARY.md`. Each answer gives the facts, the numbers, and where to check
them. "Upstream" means the original KNighter code (commit `f4e834b`); "previous attempt" means the earlier
libgit2 work in `/home/faris/RA-MrYudis/Knight/KNighter`.

**Contents:** A. The big picture · B. How speed was measured · C. Where the speedup comes from ·
D. The plugin / ".so" story · E. The LLM: model, cost, hangs · F. Scoring: what "perfect" means ·
G. The benchmark runs (r1–r8) · H. General C/C++ · I. Refinement, scan, triage ·
J. Section 3: roles, bundles, porting · K. Limitations and honesty · L. Practical: where things are

---

## A. The big picture

**Q: What is KNighter, in one paragraph?**
It takes a bug-fix commit (the patch), asks an LLM to describe the bug pattern, plan a checker, and write
a Clang Static Analyzer checker in C++. It compiles that checker into a plugin (`.so`), runs it on the
code *before* the fix (it should report the bug) and *after* the fix (it should be quiet). A checker that
does both is "perfect". Good checkers can then scan whole projects for similar bugs, and "refinement"
uses LLM triage to remove false positives.

**Q: What did the supervisor ask for?**
1. Make it faster. 2. Make it work on general C (not only the Linux kernel). 3. Make checkers usable
across projects. 4. Accept a CVE as input.
[]
**Q: What is done?**
Goals 1 and 2 are done, tested end to end, and pushed (plan sections 0, 1, 2). Goal 3 is built but its
main result (finding bugs in *other* projects) does not work yet. Goal 4 is not started.

**Q: What is "section 0"? It's not one of the four goals.**
Correctness fixes that had to come first, otherwise speed and quality numbers would be meaningless:
a stricter success rule, making sure each validation uses the right checker, and making reruns work.

**Q: What was the single most important problem in the previous attempt?**
Its success metric. A checker counted as "valid" if it reported anything at all in the patched file
and slightly fewer reports after the fix (26 → 17 reports passed). So "7/11 valid" did not mean
"7 checkers find their bug".

---

## B. How speed was measured

**Q: Does the time measurement only cover CPU work, or are LLM calls included?**
**LLM calls are included.** The headline (441 → 135 min) is **wall-clock time of the whole `gen`
command**, from start to finish: LLM calls, compiling checkers, configuring projects, and analysis.
It is measured with `time.time()` around the process in `bench/run_bench.py` (plus `/usr/bin/time -v`).

**Q: Then how can the speedup be fair if the LLM is random?**
Two ways:
1. Both variants use the **same model, prompts and settings**, on the **same 43 commits**, run back to
   back per project (baseline then optimized), so provider slowdowns hit both alike.
2. A separate **deterministic replay** re-runs the *same 22 checkers* through build + validation only
   (no LLM): **1699 s → 312 s (5.4×), with identical verdicts on all 22.**

**Q: How much of the time is the LLM?**
Most of it. Summed over all calls in the 43-commit runs: baseline 321.9 min of LLM time, optimized
334.1 min, about the same amount of LLM work. The optimized run finishes in 135 min because 4 commits
are processed **at the same time**, so LLM calls overlap.

**Q: Isn't 3.3× then "just parallelism"?**
Parallelism is the biggest part, but it was only *possible* after removing the shared plugin and the
shared working tree (see section D). The other gains are real per-operation savings, measured without
the LLM:
- configuring curl for a validation: ~45–65 s → **0.01 s** (configured once, reused);
- building a checker plugin: ~17–36 s → **~8–14 s**;
- scanning all of curl: **484 s → 88 s** (parallel files).

**Q: How long is one LLM call?**
Median per stage in the 43-commit runs: pattern extraction ~5–25 s, planning ~45–70 s, code
generation ~55–95 s, syntax repair ~15–55 s. Slowest single calls: 150–210 s.

**Q: What machine?**
A laptop with WSL2 on Windows, 16 cores, 15 GB RAM. LLVM/Clang 18.1.8 (KNighter's own build).

**Q: What if the laptop went to sleep during a benchmark?**
It did once (r6, 5.6 hours lost), so now each run records how long the machine was asleep
(`suspended_seconds`: wall time minus monotonic time) and runs with sleep are excluded. **All 14
runs used in the results have 0 seconds suspended.** A small PowerShell helper also keeps Windows
from idle-sleeping during benchmarks (it cannot prevent sleep when the lid is closed).

**Q: What exactly is the "baseline"?**
Upstream behaviour, but on the same new generic target (upstream can't run curl/SQLite at all):
- commits one at a time;
- a **fresh configure of the project on every checkout** (like upstream's `make clean` + `allyesconfig` for the kernel);
- each file analyzed one after another;
- the checker plugin recompiled at `-O3` on every compile, no cache.

**Q: Why not run the real upstream build command for the baseline?**
Upstream builds the plugin with `make SAGenTestPlugin` inside the LLVM build tree. On this machine
that tree is stale: `make` would rebuild **1068 LLVM files** (hours) and modify the previous attempt's
LLVM. So the baseline replays the *same compile and link commands* without `make`'s own overhead.
That makes the baseline slightly *faster* than real upstream, so **the reported speedup is
conservative**.

**Q: Was anything unfair to the baseline?**
One thing was, and it was fixed: the optimized build pre-included ~24 clang headers (precompiled
header), so a checker that forgot an `#include` would compile there but not in the baseline, which would
add LLM repair calls to the baseline only. Now both variants pre-include the same headers (as text in the
baseline). Test: a checker with all its `#include`s removed compiles in both variants.

---

## C. Where the speedup comes from (component by component)

**Q: List the speed changes.**
| Change | What it means | Measured effect |
|---|---|---|
| Parallel commits | 4 commits processed at once | the main contributor to 3.3× |
| Per-revision worktrees | each project version gets its own checkout + build folder, configured once | curl setup per validation 45–65 s → 0.01 s |
| Background prefetch | configuring starts while the LLM is still thinking | setup hidden behind LLM time |
| Out-of-tree plugin builds | `-O1` + precompiled header + cache | build ~36 s → ~10–14 s |
| Parallel analysis | analyze many files at once | curl scan 484 s → 88 s |
| LLM streaming + watchdog | stalled requests detected and retried | prevents hours-long hangs |
| Parallel triage | refinement asks about several reports at once | 97 s → 55 s for 2 reports |

**Q: Did being faster cost quality?**
No measurable loss: 26/43 (baseline) vs 27/43 (optimized) commits got a perfect checker.

---

## D. The plugin / ".so" story

**Q: So in the vanilla version, there's only one `.so`, which means no more than one checker at a time?**
Yes. Upstream writes every checker into the **same source file** inside the LLVM tree
(`clang/lib/Analysis/plugins/SAGenTestHandling/SAGenTestChecker.cpp`), runs `make SAGenTestPlugin`, and
gets **one** `lib/SAGenTestPlugin.so`. Building a new checker overwrites the previous one. That is
fine when everything runs one at a time (upstream `gen` is sequential), but it makes parallelism
impossible.

**Q: The previous attempt ran 6 workers in parallel. How did that work?**
With a global lock around building and validating, so the expensive parts still ran one at a time
(the lock was busy 72–78% of the time), and it had a **race**: a worker built its checker, released the
lock, and validated *later*; in between another worker could overwrite the shared `.so`. The logs show
this happening once (17:23:21 build → 17:23:59 overwritten → 17:24:29 validated with the wrong plugin).

**Q: What does it look like now?**
Each checker is compiled into **its own `.so`**, stored in a folder named after a fingerprint
(hash) of its source code. Two different checkers can never share a plugin, and building the same
checker twice is instant (cache). Validation asks for "the plugin of *this* code", so it cannot use
somebody else's.

**Q: How do you know validation really used the right plugin?**
An audit (`bench/audit_plugins.py`): for every validation, the plugin's folder contains the exact
source it was built from; we compare it byte for byte with the checker that was scored.
**152/152 matched**, including the 4-worker runs.

**Q: Does upstream's "batch scan" mode use more than one `.so`?**
Yes, it creates one plugin folder per checker by renaming classes, then rebuilds LLVM. It was
kernel-only and is not used for the generic target; the new scan mode uses the per-checker plugins.

---

## E. The LLM: model, cost, hangs

**Q: Which model and provider?**
`deepseek-v4.1-flash` through OpenCode Go (an OpenAI-compatible API), temperature 1.0 (upstream
default), up to 65,536 output tokens per call. The previous attempt used `deepseek-v4-pro` and
`deepseek-v4-flash` directly from DeepSeek.

**Q: How much does a run cost?**
Very little. One full 43-commit run: ~400 calls, ~2.7 M prompt tokens, ~3.6 M completion tokens (of which
~3.1–3.4 M are the model's *reasoning*). At OpenCode Go's prices ($0.15–0.30 per 1M input,
$0.60–1.20 per 1M output) that is **about $2.50–5 per run** (an upper bound; cached input is cheaper).

**Q: Why was the output limit raised to 65,536 tokens?**
With upstream's default of 16,000, the code-generation step spent **all 16,000 tokens on reasoning**
and returned an empty answer, 4 times in a row (smoke test, 30 Sep 16:49–16:56). The previous attempt
likely hit the same thing ("Code Generation took 495 s and returned None").

**Q: Why did an LLM call hang for 1 hour 43 minutes? What version, what model, when?**
- **When:** 30 Sep 2026, benchmark run **r4**, curl baseline, second commit; the `pattern2plan` call
  started at **17:48:53** and failed at **19:31:37** (**6164 s**).
- **Model:** `deepseek-v4.1-flash` via OpenCode Go.
- **Code version:** our own code *at that time*. Upstream had **no timeout at all**; a run before that
  (r3) already lost 1200 s to a hang, so I had just switched to streaming with a 180 s "no data" timeout
  and a 1200 s overall limit. But the overall limit was checked **only when a new piece of text
  arrived**. The provider apparently kept the connection alive with "keep-alive" messages that carry no
  text: the no-data timer kept being reset, and the overall check never ran.
- **Fix:** a separate watchdog timer that closes the connection at the deadline whatever happens;
  deadline lowered to 600 s (the slowest healthy call is ~210 s). Verified against a fake server that
  only sends keep-alives: cut off after exactly the deadline.
- **Since then:** a few failed calls (stalls, empty answers), all caught and retried within minutes.

**Q: Was the keep-alive explanation proven?**
It is inferred from the behaviour (the no-data timeout didn't fire for 1 h 43 min), and the fix was
tested against a simulated keep-alive stream. We did not capture the raw network traffic.

**Q: Is the model the same in every run?**
Yes, from r5 onwards everything uses `deepseek-v4.1-flash` with the same settings. The baseline and
optimized variants never differ in LLM settings.

---

## F. Scoring: what "perfect" means

**Q: What are TP and TN now?**
- **TP:** on the buggy version (`commit^`), the checker reports **inside a function the patch
  changes** (or within 5 lines of a changed line that isn't in any parsed function).
- **TN:** among those files, **no such report** on the fixed version.
- **Perfect** = TP > 0 and TN > 0.

**Q: And the old (upstream) rule?**
TP: any report anywhere in a patched file. TN: zero reports after the fix, or *fewer* reports (if below
5). It is still computed alongside ("legacy") for comparison.

**Q: Does the strict rule change verdicts in practice?**
Yes. In 152 attempts: 51 valid under both rules, **5 valid only under the old rule** (all still report
in the fixed function after the fix; one was "credited" by an unrelated file with no reports), 2 valid
only under the strict rule (noisy checkers that do catch and clear the bug, but report elsewhere too).

**Q: Can strict scoring miss a real detection?**
In principle yes: if the analyzer reports the bug inside a *called helper* instead of the patched
function. This was not observed in the 152 attempts, but it is a known limitation.

**Q: Does strict scoring punish noisy checkers?**
No. It judges "does it catch *this* bug and stop after the fix". Noise elsewhere is handled by
refinement. Worth stating in the paper.

---

## G. The benchmark runs (r1–r8)

**Q: Why are there so many runs?**
Each was stopped when a problem was found, rather than producing misleading numbers:
| Run | What happened |
|---|---|
| r1 | stopped after 6 min: a code review found bugs that would skew results |
| r2 | stopped: switched to running from a frozen copy of the code, so editing during a run can't change it |
| r3 | stopped: an LLM call hung for 1200 s → switched to streaming |
| r4 | stopped: the 1 h 43 min hang → watchdog deadline |
| r5 | curl finished (preliminary 4.3×), stopped to fix the precompiled-header unfairness |
| r6 | stopped: laptop slept 5.6 h, and Lua analysis was broken (a file passed twice to clang) |
| **r7** | **the main result: 43 commits, 7 projects, both variants** |
| **r8** | role-based checkers (section 3), 26 commits |

**Q: Why 43 commits and these projects?**
To cover different build systems and C++: curl 8, SQLite 7, Lua 4, libxml2 7, libgit2 10 (the previous
attempt's list, minus one that can't compile), re2 4, yaml-cpp 3. Commits were found by a script
(keywords + small diffs) and every one was checked by reading its diff and labelling the bug type.

**Q: Why was one libgit2 commit removed?**
`93b16df1`: its buggy version **does not compile** (it uses a variable `revparse` that doesn't exist; the
"fix" just renames it). No checker could ever be validated on it. The previous attempt reported it as a
failure of checker generation; it was never solvable.

**Q: How do I know a commit is usable before spending LLM calls on it?**
A pre-check (`bench/precheck.py`) configures both versions and actually runs the analyzer (with a
do-nothing checker) on every patched file. Only commits that pass are used.

---

## H. General C/C++

**Q: How is a new project added now?**
With a YAML file only. Example (curl): the repo path and the configure command (`cmake ... -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`).
KNighter checks out each needed version in its own folder, runs that command once, and reads
`compile_commands.json` (the list of exact compiler commands for every file).

**Q: What if the project doesn't use CMake?**
Any build system works as long as it can produce `compile_commands.json`:
- CMake / Meson produce it directly;
- for Makefile/autotools projects, the recipe wraps the build with `intercept-build`, which records the compiler commands.

**Q: Which build systems were actually tested?**
CMake (curl, libgit2, re2, yaml-cpp), autosetup + make (SQLite), plain Makefile (Lua), Meson (libxml2).

**Q: Does C++ work?**
Yes: re2 and yaml-cpp (3/4 and 1–2/3 perfect). C++ needed three fixes: patched functions from C++
files are now shown to the LLM, C++ files are analyzed with `clang++`, and C++ method names
(`Class::method`, destructors, operators) are recognised.

**Q: Did the prompts change?**
They no longer say "a patch in Linux kernel". They name the actual project (e.g. "curl, the C library
for transferring data with URLs"), and the triage prompt's NULL-pointer reasoning is generic C instead of
driver/device-tree/ACPI. For the kernel the old wording is kept.

**Q: Is any project-specific code left?**
No: `grep -ri libgit2 src/` finds nothing; projects differ only in their YAML files.

---

## I. Refinement, scan, triage

**Q: What is refinement?**
After a checker is perfect on its commit, KNighter scans a whole project with it. The LLM triages the
reports ("real bug or false positive?"), and for false positives asks the LLM to fix the checker, then
checks that (a) the false report is gone and (b) the checker still catches its original bug.

**Q: Why did refinement always fail before?**
"Failed to validate on objects" in 12/12 and 15/15 attempts. The real cause: report HTML was converted
to text **with line wrapping**, so long file paths were split across two lines and the file could not be
found again. The list of files to re-check was empty, so validation always "failed".

**Q: Does it work now?**
Yes, **4/4 repairs** validated (refine on 21 checkers in 6 projects). Example: a curl checker's false
report in `lib/cf-socket.c` was fixed by teaching the checker that `Curl_peer_link()` re-initialises a
field.

**Q: Why so few repairs (only 4)?**
Refinement scans the *current* version of each project, where the original bugs are fixed, so most
checkers report nothing. Repairs only happen when a checker over-reports.

**Q: What did the scan + triage on an old curl release show?**
On curl 8.10.0 (before the fixes), 3 checkers reported, and triage said "real bug" for all 3, each in the
exact function curl later fixed. Caveat: these are the bugs the checkers were made from, so this shows
the pipeline works, **not** that it finds new bugs.

---

## J. Section 3: roles, bundles, porting

**Q: What is a "role"?**
An API category instead of a function name. The checker asks "is this call an `allocator`?" instead of
"is this call `xmlMalloc`?". A small roles file lists the names, e.g. `{"allocator": ["xmlMalloc"]}`.
To use the checker on curl you give it curl's names instead.

**Q: Where do the roles live?**
Inside the checker source, in a comment block at the end (`/* KNIGHTER_ROLES {...} */`). The build turns
it into `roles.json`; the analyzer reads it through an environment variable. So the rest of the pipeline
didn't need to change.

**Q: Did role-based generation work?**
Yes for the code: **0/45** generated checkers hardcode project names (before: 76% on the same commits),
all 204 roles have a description, and success did not drop (**19/26** vs 17/26, after the `roles.h` fix below). The LLM did it right
the first time; the automatic "move names into roles" repair was never needed.

**Q: What is a bundle?**
A folder per checker: the compiled plugin, its source, the roles of its original project, a manifest
(origin, scores, roles, portability), a run script that needs only Python + clang, and a CMake file to
rebuild it for another clang. Tested: it runs outside the repo with system Python and gives the same
report as KNighter; rebuilt from source it gives the same report too.

**Q: What is porting?**
Mapping a checker's roles to another project's names. KNighter collects function names from the target
project's headers, ranks the likely ones per role, and asks the LLM to pick. Every name is checked against
all identifiers in the target's source; invented names are rejected. **The compiled checker never changes;
only its roles file does.**

**Q: So do checkers work on other projects?**
**Sometimes, for generic patterns.** A checker generated from a SQLite memory-leak fix, ported to libxml2
by renaming roles, found **2 real memory leaks in libxml2 2.15.0** (`xmlwriter.c:1055`, `:1798`) at the exact
lines libxml2 fixed 3 and 5 months later. It found them in a blind scan of the whole old release and also on
the fix commits. But most ported checkers stay silent in other projects, and those that fire are noisy.

**Q: Why did the first attempts find nothing (0 reports everywhere)?**
Three bugs, all fixed and measured:
1. **Porting rejected correct names.** Lua and libxml2 declare functions in styles the header scanner
   missed. Porting a checker back to its own project kept detection in 0/8 cases before the fix, 18/18 after.
2. **Roles never matched calls through macros or function pointers** (curl `curlx_free`, libxml2
   `xmlFree`). In libxml2's `tree.c`, `xmlFree` went from 0 to 52 matched calls; one correct libxml2 checker was
   wrongly scored as a failure because of it.
3. **Roles described bug-site details** (a struct field `len`, a local `bufpt`) that other projects
   don't have. New prompts restrict roles to standard API categories (allocator, deallocator, …), functions
   and macros only.

**Q: Could "0 reports" mean the bugs just aren't there?**
For a single pair, yes: e.g. a curl checker on Lua finds nothing even with hand-corrected roles, because Lua
has no code of that shape. That's why transfer is **pattern-dependent**: roles fix *naming* differences, not
differences in *how the code is written*.

**Q: How was "found a real bug" measured?**
Two ways with ground truth:
- **Matched pairs:** run the ported checker on real same-type fix commits of the other project, with the
  same strict TP/TN rule. r9: 2/27 detected; r8: 0/56.
- **Historical replay:** scan an old release (≥ 12 months old) and check whether reports land in functions
  the project fixed later, against a random-chance base rate. r9: 13 hits vs 5.6 expected, 2 confirmed bugs;
  r8: 0 hits. Every claimed bug was checked by hand: the LLM's verdicts on cross-project reports were often
  wrong.

**Q: Is there a trade-off?**
Yes. Generic roles make checkers fire on other projects (252 vs 17 reported functions) but find fewer bugs on
their own project (14 and 12/26 in two runs vs 19/26 with free-form roles).

---

## K. Limitations and honesty

**Q: What hasn't been tested?**
- The Linux kernel and V8 paths (no source trees on this machine), including item 1.3 (faster kernel checkout).
- Cross-project detection works only rarely (2 confirmed bugs, both from one checker), and no *new* (unfixed)
  bug has been confirmed.

**Q: How reliable are the success numbers?**
One run per variant. Differences of 1–2 commits (e.g. 26 vs 27) are within run-to-run randomness. The
speed numbers are much more stable (and the replay/scan results are deterministic).

**Q: Were mistakes made along the way?**
Yes, and they are logged with corrections in `docs/RESEARCH_LOG.md`, e.g. a timeout bug that allowed the
1 h 43 min hang, a dismissed review warning that later broke Lua, and wrong timestamps that were
corrected.

**Q: Is the API key safe?**
It is only in a git-ignored file. Every push was scanned (0 hits in the whole branch history). It was
pasted in chat, so **rotating it is still recommended**.

---

## L. Practical: where things are

**Q: What is pushed and what isn't?**
- **Pushed** (branch `general-c-speed`): sections 0–3, the evidence, and these documents.
- Section 3 (role-based generation) is **off by default** (`role_based_checkers: true` enables it).

**Q: Which documents should I read?**
- `PROGRESS_SUMMARY.md` for the overview;
- this file for understanding;
- `RESULTS_SECTIONS_0_2.md` and `RESULTS_SECTION_3.md` for the evidence;
- `RESEARCH_LOG.md` for the full history;
- `REVIEW_CHECKLIST.md` for the decisions you approved.

**Q: Where are the raw numbers?**
`bench/evidence/` (committed): per-run summaries, every LLM call with timing and tokens, every
validation with its reports. `bench/aggregate.py r7` regenerates the main table.

**Q: How do I run it on a project myself?**
```sh
.venv/bin/python src/main.py gen --config_file=configs/curl.yaml --commit_file=bench/commits-curl.txt
.venv/bin/python src/main.py export --config_file=configs/curl.yaml --checker_dir=results/curl
```

**Q: What are the next steps?**
1. Agree with the supervisor on how to frame section 3.
2. Section 4: CVE as input.
3. Optional: larger cross-project sets, and checkers that model "stored in a field, freed through it".
