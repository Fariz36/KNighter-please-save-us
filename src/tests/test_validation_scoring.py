import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from validation_scoring import (
    Region,
    extract_diff,
    function_ranges,
    parse_diff,
    region_for,
    score,
)

DIFF = """diff --git a/lib/foo.c b/lib/foo.c
index 111..222 100644
--- a/lib/foo.c
+++ b/lib/foo.c
@@ -10,6 +10,8 @@ static int parse(char *p)
 int parse(char *p)
 {
   int n;
+  if(!p)
+    return -1;
   n = *p;
   return n;
 }
@@ -40,3 +42,2 @@ void other(void)
 {
-  -- deleted line that looks like a header
   x();
diff --git a/lib/new.c b/lib/new.c
new file mode 100644
--- /dev/null
+++ b/lib/new.c
@@ -0,0 +1,2 @@
+int f(void)
+{ return 0; }
"""

SOURCE_BUGGY = """int helper(int x)
{
  return x;
}
int parse(char *p)
{
  int n;
  n = *p;
  return n;
}
"""


@dataclass
class R:
    relpath: str
    function: str
    line: int


class ParseDiffTest(unittest.TestCase):
    def test_lines_and_files(self):
        changes = parse_diff(DIFF)
        self.assertEqual(list(changes), ["lib/foo.c"])  # new file has no buggy side
        foo = changes["lib/foo.c"]
        # pure insertion between old lines 12 and 13 -> new lines 13,14
        self.assertIn((12, 13), foo.old_gaps)
        self.assertEqual({13, 14}, foo.new_lines)
        # pure deletion of old line 41; the "-- " content is not a file header
        self.assertEqual({41}, foo.old_lines)
        self.assertIn((42, 43), foo.new_gaps)

    def test_replacement_has_no_cross_side_anchors(self):
        diff = """diff --git a/x.c b/x.c
--- a/x.c
+++ b/x.c
@@ -5,3 +5,3 @@
 a;
-b;
+c;
 d;
"""
        change = parse_diff(diff)["x.c"]
        self.assertEqual(({6}, {6}), (change.old_lines, change.new_lines))
        self.assertEqual((set(), set()), (change.old_gaps, change.new_gaps))

    def test_extract_from_markdown(self):
        md = "## Bug Fix Patch\n\n```diff\n" + DIFF + "\n```\n"
        self.assertIn("--- a/lib/foo.c", extract_diff(md))


class FunctionRangeTest(unittest.TestCase):
    def test_one_based_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.c"
            path.write_text(SOURCE_BUGGY)
            ranges = function_ranges(path)
        self.assertIn(("helper", 1, 4), ranges)
        self.assertIn(("parse", 5, 10), ranges)
        region = region_for({8}, ranges)
        self.assertEqual({"parse": (5, 10)}, region.functions)

    def test_insertion_after_closing_brace_does_not_implicate_function(self):
        # New helper inserted between helper()'s "}" (line 4) and parse() (line 5).
        ranges = [("helper", 1, 4), ("parse", 5, 10)]
        region = region_for(set(), ranges, gaps={(4, 5)})
        self.assertEqual({}, region.functions)
        # Insertion inside parse() (between lines 7 and 8) does implicate it.
        region = region_for(set(), ranges, gaps={(7, 8)})
        self.assertEqual({"parse": (5, 10)}, region.functions)

    def test_unparsed_changed_line_is_orphan_even_if_other_hunk_parsed(self):
        ranges = [("parse", 5, 10)]
        region = region_for({8, 100}, ranges)
        self.assertEqual({"parse": (5, 10)}, region.functions)
        self.assertEqual({100}, region.orphans)
        self.assertTrue(region.contains("macro_fn", 103))
        self.assertFalse(region.contains("macro_fn", 50))


class CxxFunctionNameTest(unittest.TestCase):
    def test_cxx_names(self):
        code = """namespace re2 {
Prefilter* Prefilter::FromRegexp(Regexp* re) {
  return nullptr;
}
DFA::~DFA() {
}
int& Counter::get() { return n_; }
bool operator==(const A& a, const A& b) { return true; }
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.cc"
            path.write_text(code)
            names = [name for name, _, _ in function_ranges(path)]
        self.assertIn("Prefilter::FromRegexp", names)
        self.assertIn("DFA::~DFA", names)
        self.assertIn("Counter::get", names)
        self.assertIn("operator==", names)


class ScoreTest(unittest.TestCase):
    def setUp(self):
        self.changes = parse_diff(DIFF)
        self.b_region = {"lib/foo.c": Region(functions={"parse": (10, 16)})}
        self.f_region = {"lib/foo.c": Region(functions={"parse": (10, 18)})}
        self.both = {"lib/foo.c"}

    def run_score(self, buggy, fixed):
        return score(
            self.changes,
            {"lib/foo.c": buggy},
            {"lib/foo.c": fixed},
            self.b_region,
            self.f_region,
            self.both,
            self.both,
        )

    def test_on_target_and_silent_after_fix_is_perfect(self):
        s = self.run_score([R("lib/foo.c", "parse", 13)], [])
        self.assertEqual((1, 1), (s.tp, s.tn))

    def test_report_outside_patched_function_is_not_tp(self):
        s = self.run_score([R("lib/foo.c", "unrelated", 200)], [])
        self.assertEqual(0, s.tp)
        self.assertEqual(1, s.legacy_tp)  # legacy counted it

    def test_fewer_but_nonzero_on_target_after_fix_is_not_tn(self):
        buggy = [R("lib/foo.c", "parse", 13)] * 26
        fixed = [R("lib/foo.c", "parse", 15)] * 17
        s = self.run_score(buggy, fixed)
        self.assertEqual((1, 0), (s.tp, s.tn))

    def test_legacy_rule_matches_upstream(self):
        # upstream: fixed < buggy and fixed < 5 -> TN
        s = self.run_score([R("lib/foo.c", "x", 1)] * 6, [R("lib/foo.c", "x", 1)] * 4)
        self.assertEqual((1, 1), (s.legacy_tp, s.legacy_tn))
        # fixed > buggy -> TN - 1
        s = self.run_score([R("lib/foo.c", "x", 1)], [R("lib/foo.c", "x", 1)] * 3)
        self.assertEqual(-1, s.legacy_tn)

    def test_header_report_is_not_on_target(self):
        s = self.run_score([R("lib/foo.h", "parse", 13)], [])
        self.assertEqual(0, s.tp)

    def test_unanalyzed_fixed_side_gives_no_tn(self):
        s = score(
            self.changes,
            {"lib/foo.c": [R("lib/foo.c", "parse", 13)]},
            {},
            self.b_region,
            self.f_region,
            self.both,
            set(),
        )
        self.assertEqual((1, 0), (s.tp, s.tn))

    def test_window_fallback_when_no_function_found(self):
        region = Region(orphans={100}, window=5)
        self.assertTrue(region.contains("", 104))
        self.assertFalse(region.contains("", 106))


if __name__ == "__main__":
    unittest.main()
