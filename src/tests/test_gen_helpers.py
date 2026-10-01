import tempfile
import unittest
from pathlib import Path

from checker_gen import load_ranking, parse_commit_line


class RankingTest(unittest.TestCase):
    def test_json_and_legacy_literal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ranking.txt"
            path.write_text("[[1, 1, 1], [0, 0, 1]]")
            self.assertEqual([(1, 1, 1), (0, 0, 1)], load_ranking(path))
            path.write_text("[(2, -10, -10), (0, 1, 0)]")  # upstream str(list of tuples)
            self.assertEqual([(2, -10, -10), (0, 1, 0)], load_ranking(path))

    def test_no_eval(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ranking.txt"
            path.write_text("__import__('os').getcwd()")
            with self.assertRaises(ValueError):
                load_ranking(path)


class CommitLineTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(("abc", "NPD"), parse_commit_line(" abc , NPD \n"))
        self.assertEqual(("abc", "NPD"), parse_commit_line("abc,NPD,CVE-2024-1"))
        self.assertIsNone(parse_commit_line("   "))
        self.assertIsNone(parse_commit_line("# comment"))
        with self.assertRaises(ValueError):
            parse_commit_line("abc")


if __name__ == "__main__":
    unittest.main()
