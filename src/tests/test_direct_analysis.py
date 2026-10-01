import unittest
from pathlib import Path

from backends.direct_analysis import analyzer_argv


class AnalyzerArgvTest(unittest.TestCase):
    def argv(self, entry):
        return analyzer_argv(Path("/llvm/bin/clang"), Path("/p.so"), entry, Path("/out"))

    def sources(self, argv, name):
        return [a for a in argv if a.endswith(name)]

    def test_relative_source_in_command_is_not_duplicated(self):
        # intercept-build style: absolute `file`, relative source in `command` (Lua).
        entry = {"directory": "/w/src", "file": "/w/src/lapi.c",
                 "command": "cc -c -O2 -std=c99 -o lapi.o lapi.c"}
        argv = self.argv(entry)
        self.assertEqual(["/w/src/lapi.c"], self.sources(argv, "lapi.c"))
        self.assertNotIn("lapi.o", argv)

    def test_absolute_source_in_arguments(self):
        entry = {"directory": "/b", "file": "/s/lib/easy.c",
                 "arguments": ["clang", "-DX", "-c", "/s/lib/easy.c", "-o", "easy.o"]}
        self.assertEqual(["/s/lib/easy.c"], self.sources(self.argv(entry), "easy.c"))

    def test_relative_file_field(self):
        entry = {"directory": "/b/lib", "file": "../../s/x.c", "command": "cc -c ../../s/x.c -o x.o"}
        self.assertEqual(["../../s/x.c"], self.sources(self.argv(entry), "x.c"))

    def test_cxx_uses_cxx_driver(self):
        entry = {"directory": "/b", "file": "/s/re2/re2.cc", "command": "c++ -c /s/re2/re2.cc -o re2.o"}
        self.assertTrue(self.argv(entry)[0].endswith("clang++"))
