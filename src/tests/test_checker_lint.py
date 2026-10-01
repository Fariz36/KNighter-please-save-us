import unittest

from backends.plugin_builder import extract_roles
from checker_lint import find_hardcoded_identifiers, looks_project_specific

ROLE_BASED = '''
#include "knighter/roles.h"
// Detect use of "git_error_set" with a NULL format argument (comment: ignored)
void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "error_setter")) return;
  if (isCallTo(Call, "memcpy", C) || isCallTo(Call, "strlen", C)) return;
  BT.reset(new BugType(this, "Misuse", "Logic error"));
  report("roles E2E test: sqlite3_free called twice");
}
/* KNIGHTER_ROLES
{"error_setter": ["git_error_set"], "deallocator": ["git__free"]}
*/
'''


class LintTest(unittest.TestCase):
    def test_role_based_checker_is_clean(self):
        self.assertEqual([], find_hardcoded_identifiers(ROLE_BASED))

    def test_hardcoded_project_names_found(self):
        code = '''
  if (isCallTo(Call, "git_fs_path_prettify_dir", C)) {}
  if (DRE->getDecl()->getName() != "short_oid") return;
  if (Name.startswith("Curl_")) {}
  if (Fn == "xmlMalloc" || Fn == "sqlite3_free") {}
'''
        names = {f.name for f in find_hardcoded_identifiers(code)}
        self.assertEqual({"git_fs_path_prettify_dir", "short_oid", "Curl_", "xmlMalloc", "sqlite3_free"}, names)

    def test_standard_names_and_words_are_allowed(self):
        for name in ("malloc", "pthread_mutex_lock", "snprintf", "push_back", "make_unique", "Misuse", "error"):
            self.assertFalse(looks_project_specific(name), name)

    def test_roles_block_parsed(self):
        self.assertEqual({"error_setter": ["git_error_set"], "deallocator": ["git__free"]},
                         extract_roles(ROLE_BASED))

    def test_invalid_roles_block(self):
        with self.assertRaises(ValueError):
            extract_roles('/* KNIGHTER_ROLES {"a": "not a list"} */')


if __name__ == "__main__":
    unittest.main()
