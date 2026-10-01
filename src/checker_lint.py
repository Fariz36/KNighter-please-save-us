"""Find project-specific identifiers hardcoded in checker code (section 3.1-A).

A checker that compares against "git_error_set" or "Curl_peer_link" only works
on the project it was generated from. Role-based checkers keep such names in
their `KNIGHTER_ROLES` block and query them through knighter/roles.h; this
check finds names that leaked into the checker logic instead.

Deterministic, no LLM: string literals outside comments and outside the roles
block that look like C/C++ identifiers and are not standard library names.
"""

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import List

from backends.plugin_builder import extract_roles, strip_roles_block

ALLOWLIST_FILE = Path(__file__).parent / "knighter_include" / "stdlib_names.txt"

_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Comments (string-aware enough for generated checkers: strings are matched
# first so "//" inside a literal is not treated as a comment).
_TOKENS = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/', re.DOTALL)


@dataclass
class Finding:
    name: str
    line: int


@lru_cache(maxsize=1)
def standard_names() -> frozenset:
    names = set()
    for line in ALLOWLIST_FILE.read_text().splitlines():
        if line and not line.startswith("#"):
            names.add(line.strip())
    return frozenset(names)


def looks_project_specific(name: str) -> bool:
    """Identifier-shaped and not a standard library name.

    Plain words ("Misuse", "error") are ignored: project APIs nearly always
    carry a prefix/underscore, mixed case or digits (git_error_set,
    xmlMalloc, sqlite3_free, short_oid).
    """
    if not _IDENT.match(name) or name in standard_names():
        return False
    if name.startswith("__builtin"):
        return False
    has_underscore = "_" in name.strip("_")
    camel = bool(re.search(r"[a-z][A-Z]", name))
    digit = any(c.isdigit() for c in name)
    return has_underscore or camel or digit


def _strip_comments(code: str) -> str:
    def keep_strings(match):
        token = match.group(0)
        if token.startswith('"'):
            return token
        return "\n" * token.count("\n")  # keep line numbers stable

    return _TOKENS.sub(keep_strings, code)


# Role names are arguments of knighter role queries, e.g. callIsRole(Call, "allocator").
_ROLE_QUERY = re.compile(
    r'knighter::(?:callIsRole|isRole|roleNames|declIsRole)\s*\([^"]*"([^"]*)"'
)


def find_hardcoded_identifiers(checker_code: str) -> List[Finding]:
    try:
        role_names = set((extract_roles(checker_code) or {}).keys())
    except ValueError:
        role_names = set()
    code = _strip_comments(strip_roles_block(checker_code))
    role_names |= set(_ROLE_QUERY.findall(code))
    findings = []
    for match in _STRING.finditer(code):
        literal = match.group(1)
        if literal in role_names:
            continue
        # "git_" prefixes and "a|b" alternatives are split into candidate names.
        for part in re.split(r"[|,\s]+", literal):
            candidate = part.rstrip("_") if part.endswith("_") and len(part) > 1 else part
            if candidate and (looks_project_specific(candidate) or (part != candidate and _IDENT.match(candidate))):
                line = code.count("\n", 0, match.start()) + 1
                findings.append(Finding(part, line))
    return findings
