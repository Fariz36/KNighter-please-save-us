import tempfile
import unittest
from pathlib import Path

from role_porting import extract_candidates, identifier_index, rank_candidates, split_words
from tools import extract_json_block

HEADER = """
#define XML_ALLOC(n) xmlMalloc(n)
XMLPUBFUN void * xmlMalloc(size_t size);
XMLPUBFUN void * xmlMallocAtomic(size_t size);
XMLPUBFUN void * xmlRealloc(void *ptr, size_t size);
XMLPUBFUN void xmlFree(void *ptr);
int xmlStrlen(const xmlChar *str);
static int helper(int x) { return x; }
void *malloc(size_t n);
"""


class PortingTest(unittest.TestCase):
    def test_split_words(self):
        self.assertEqual(["xml", "malloc", "atomic"], split_words("xmlMallocAtomic"))
        self.assertEqual(["git", "free"], split_words("git__free"))

    def test_extract_and_rank(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "include" / "libxml").mkdir(parents=True)
            (root / "include" / "libxml" / "xmlmemory.h").write_text(HEADER)
            (root / "tests").mkdir()
            (root / "tests" / "t.h").write_text("void testOnlyAlloc(void);\n")
            cands = extract_candidates(root)
        self.assertIn("xmlMalloc", cands)
        self.assertIn("xmlFree", cands)
        self.assertIn("XML_ALLOC", cands)
        self.assertNotIn("malloc", cands)          # standard name
        self.assertNotIn("helper", cands)          # definition, not a declaration
        self.assertNotIn("testOnlyAlloc", cands)   # tests/ skipped
        ranked = rank_candidates("allocator", "returns newly allocated heap memory",
                                 ["git__malloc"], cands)
        # Ranking only pre-selects for the LLM: both allocator spellings lead.
        self.assertEqual({"xmlMalloc", "XML_ALLOC"}, set(ranked[:2]))
        self.assertNotIn("xmlStrlen", ranked)
        free_ranked = rank_candidates("deallocator", "releases heap memory", ["git__free"], cands)
        self.assertEqual("xmlFree", free_ranked[0])

    def test_synonyms_and_template_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "sqlite.h.in").write_text("SQLITE_API void sqlite3_free(void*);\n")
            (root / "src" / "sqliteInt.h").write_text(
                "void sqlite3ExprListDelete(sqlite3*, ExprList*);\nint sqlite3ExprCompare(Expr*, Expr*);\n")
            cands = extract_candidates(root)
        self.assertIn("sqlite3_free", cands)
        ranked = rank_candidates("deallocator",
                                 "frees an owned resource that a consumer was supposed to release on failure",
                                 ["xmlFreeDoc"], cands)
        self.assertEqual({"sqlite3_free", "sqlite3ExprListDelete"}, set(ranked[:2]))
        self.assertNotIn("sqlite3ExprCompare", ranked)

    def test_lua_and_libxml2_declaration_styles(self):
        # Both styles were missed before: the LLM's correct picks were then rejected as
        # "not in target" in the self-port control (lua luaL_setfuncs, libxml2 xmlNewIOInputStream).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lauxlib.h").write_text(
                "LUALIB_API void (luaL_setfuncs) (lua_State *L, const luaL_Reg *l, int nup);\n"
                "LUA_API int   (lua_gettop) (lua_State *L);\n")
            (root / "parserInternals.h").write_text(
                "XMLPUBFUN xmlParserInputPtr\n\t\txmlNewIOInputStream\t(xmlParserCtxtPtr ctxt,\n"
                "\t\t\t\t\t xmlParserInputBufferPtr buf);\n")
            (root / "lauxlib.c").write_text("static int newbox (lua_State *L) { return 0; }\n")
            cands = extract_candidates(root)
            known = identifier_index(root)
        self.assertIn("luaL_setfuncs", cands)
        self.assertIn("lua_gettop", cands)
        self.assertIn("xmlNewIOInputStream", cands)
        self.assertIn("newbox", known)            # static function: validated by existence
        self.assertNotIn("luaL_doesNotExist", known)

    def test_extract_json_block(self):
        text = 'Here:\n```json\n{"allocator": {"names": ["xmlMalloc"]}}\n```\n'
        self.assertEqual({"allocator": {"names": ["xmlMalloc"]}}, extract_json_block(text))
        self.assertEqual({"a": [1]}, extract_json_block('prefix {"a": [1]} suffix'))
        self.assertEqual({}, extract_json_block("no json"))


if __name__ == "__main__":
    unittest.main()
