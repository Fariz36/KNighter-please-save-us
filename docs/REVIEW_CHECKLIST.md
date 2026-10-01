# Review checklist

These items need a human decision or check before the numbers go into a paper or the code is
committed. Details and evidence for each are in `docs/RESEARCH_LOG.md`; the log section is given as
"Log: <timestamp>".

Mark each item ✅ accepted, ✏️ change requested, or ❓ discuss.

Status: work in progress.

**Decisions (2026-09-30 21:00, user):** every item follows the recommendation given in the review
discussion, except: **A3 accepted as is**; **A5 neutralise now** (done 21:05: text preamble for
non-PCH builds); **A7 grow the set and add other C/C++ projects**. See RESEARCH_LOG 21:00–21:05.

---

## A. Methodology decisions (affect what the paper can claim)

| # | Decision | Why it needs you | Log |
|---|---|---|---|
| A1 | **Strict TP/TN definition.** TP = the checker reports inside a function the patch modifies (by name or line range), or within ±5 lines of a changed line outside any parsed function. TN = among those files, no such report on the fixed version. | This replaces the paper's count-based rule. Choices to confirm: function-level granularity, the ±5 window, and counting TN only over files that earned TP. | 16:25, 16:30, 17:10 (#8) |
| A2 | **Known strict-scoring blind spot.** A report whose final location is in a *callee* (e.g. inlined helper, another file) is not credited, even if the bug is in the patched caller. | Will under-count some true detections. It can be measured on r4 by comparing strict and legacy per attempt. | 16:25 |
| A3 | **Baseline cost model.** The baseline does not run upstream's in-tree `make SAGenTestPlugin`, because the shared LLVM tree is stale (make would rebuild 1068 objects). It replays the identical compile+link commands at `-O3`, without cache or PCH. | Understates upstream cost (no make overhead), so the speedup is conservative. Confirm this is acceptable, or rebuild a clean LLVM (hours) for a literal baseline. | 16:55 |
| A4 | **Baseline = "fresh configure on every checkout"** (`reuse_revisions: false`). This mirrors upstream Linux (`make clean` + `allyesconfig`). The previous attempt's CMake path re-ran cmake in an existing build dir (cheaper). | Which baseline do you want to compare against: upstream or previous attempt? | 16:55 |
| A5 | **PCH confound.** The optimized build force-includes a precompiled header with ~24 clang headers, so a checker missing an `#include` compiles in optimized but not in baseline. This can change syntax-repair counts between variants. | Disclose it or neutralise it (e.g. also give the baseline the headers via `-include`). The replay benchmark is unaffected. | 17:10 (#7) |
| A6 | **Same LLM settings in both variants**, so the A/B isolates infrastructure. Stochastic LLM output means the two variants generate different checkers. Infrastructure cost is therefore also reported per operation and in the deterministic replay. | Confirm this framing for the speed claim. | 16:55 |
| A7 | **Benchmark commit set** (11 commits: 6 curl, 5 SQLite) and their **bug-type labels**, which I assigned from the message + diff. SQLite `ffbfc27fab` was excluded (fix compiled out by `#if`). SQLite has no NULL-dereference case. | The labels are my judgement; please verify them (`bench/commits-*.txt`). Is the set representative enough, or should it grow? | 16:55 |
| A8 | **Model and budget.** `deepseek-v4.1-flash` via OpenCode Go, temperature 1.0 (upstream default), `max_tokens: 65536` (16000 was exhausted by reasoning alone), `llm_timeout 1200`, stall timeout 180 s. | Record these in the paper's setup. Temperature and budget affect both speed and quality. | 17:00, 17:43 |
| A9 | **Small-project thresholds** for refinement: `min_reports_for_triage: 1`, `perfect_report_threshold: 3` (kernel defaults 5 / 10). | These values are judgement calls, not tuned. | 16:40 |

## B. Engineering decisions (affect the code)

| # | Decision | Log |
|---|---|---|
| B1 | Per-checker plugins are built **outside the LLVM tree** by replaying CMake's compile/link commands for `SAGenTestPlugin` (`src/backends/plugin_builder.py`). This depends on the LLVM build dir containing `compile_commands.json` and `link.txt` for that plugin. | 16:06, 16:21 |
| B2 | **V8 keeps the legacy in-tree plugin build** (its helpers hardcode the plugin path). There is no V8 tree to test a refactor. | 16:30 |
| B3 | **Linux changes are untested**: per-checker plugin via `-load-plugin <path>`, opt-in `linux_incremental`, workers forced to 1. Linux keeps legacy scoring. | 16:30, 16:40, 17:10 |
| B4 | The generic target runs user-supplied **shell commands** from the config (`target_options.setup`). Configs must be trusted input. | 16:30 |
| B5 | Worktrees + build dirs live in `targets/.knighter-work/<name>/` and are **never pruned** (curl ~50 MB per revision). | 16:30 |
| B6 | Uses the previous attempt's venv (`KNighter/venv`, Python 3.14). There is no separate environment for this tree yet. | 16:20 |
| B7 | The `target_options` config key replaces the per-target `linux_dir` / `v8_dir` style for the generic target. Old configs still work. | 16:30 |

## C. Security / housekeeping (action needed)

- [ ] **Rotate the OpenCode Go API key.** It was pasted into the chat. It is stored only in the gitignored
      `llm_keys.yaml` (mode 600) and in benchmark snapshot copies under `bench/snapshots/` (gitignored).
- [ ] Decide what to do with the previous attempt's stale LLVM build tree (`KNighter/llvm/build`). It is
      used read-only here, and a rebuild would enable a literal upstream baseline (A3).
- [ ] Nothing is committed yet. Choose a branch name and commit granularity.

## D. Code to review (uncommitted, `git status`)

New:
- `src/backends/plugin_builder.py` — content-addressed out-of-tree plugin builds, PCH, failure cache
- `src/backends/direct_analysis.py` — `clang --analyze` per compile entry, HTML metadata parser
- `src/backends/csa_compiledb.py` — validation (strict + legacy scoring) and scanning for the generic target
- `src/targets/compiledb.py` — config-driven target, per-revision worktrees, setup cache, prefetch
- `src/validation_scoring.py` — diff parsing, function regions, scoring
- `src/tests/test_validation_scoring.py`, `src/tests/test_gen_helpers.py`
- `configs/curl.yaml`, `configs/sqlite.yaml`
- `bench/` — precheck, benchmark runner, replay, commit lists

Modified: `src/backends/csa.py`, `src/checker_gen.py`, `src/checker_refine.py`, `src/model.py`,
`src/agent.py`, `src/global_config.py`, `src/targets/{factory,linux}.py`, `src/tools.py`, `.gitignore`.

## E. Open questions for your supervisor

1. Is function-level strict scoring (A1) the metric to report, with legacy scoring shown alongside for
   comparability with the paper?
2. Should the speed claim be end-to-end wall time (A/B, noisy), infrastructure-only (replay,
   deterministic), or both?
3. Are curl and SQLite enough for "general C", or should a third build system (plain Make, Meson) be
   added as evidence?
