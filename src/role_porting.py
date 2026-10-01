"""Port a checker bundle's roles to another project (section 3.1-B).

The only new LLM step for cross-project use. Deterministic parts around it:
candidate extraction from the target's headers, ranking by word overlap with
each role, and validation that every chosen name really exists in the target.

    main.py port_roles --config_file=<target.yaml> --bundle_dir=<bundle>
"""

import json
import re
import time
from pathlib import Path
from typing import Dict, List

import yaml

from checker_lint import standard_names
from global_config import global_config, logger
from model import invoke_llm
from tools import extract_json_block

PROMPT = Path(__file__).resolve().parent.parent / "prompt_template" / "port_roles.md"
HEADER_EXTENSIONS = (".h", ".hh", ".hpp", ".hxx")
# Template headers generated at build time (e.g. SQLite's public API in sqlite.h.in).
HEADER_TEMPLATE_SUFFIXES = (".h.in", ".hpp.in")

# Words that name the same API category; a role about "free" must also find
# "delete"/"release"/"destroy" functions.
SYNONYMS = [
    {"free", "release", "delete", "destroy", "dispose", "unref", "drop", "dealloc", "deallocate", "cleanup", "clear", "finalize", "close"},
    {"alloc", "malloc", "calloc", "new", "create", "make", "dup", "strdup", "allocate", "init", "open"},
    {"realloc", "resize", "grow", "expand", "reserve"},
    {"err", "error", "fail", "failf", "raise", "report", "set"},
    {"lock", "mutex", "acquire", "enter"},
    {"unlock", "leave", "exit"},
    {"len", "length", "size", "count", "num"},
    {"copy", "cpy", "memcpy", "dup", "clone"},
    {"assert", "check", "verify", "ensure", "require"},
    {"ref", "incref", "retain", "hold", "get"},
    {"put", "decref", "unref"},
    {"str", "string", "text"},
    {"buf", "buffer"},
]
SKIP_DIRS = ("test", "tests", "testing", "doc", "docs", "example", "examples", "fuzz", "fuzzing")

_FUNC_DECL = re.compile(
    r"^[ \t]*(?:[A-Za-z_][\w \t\*&:<>,]*?[\s\*&])([A-Za-z_]\w*)[ \t]*\(([^;{]*?)\)[ \t]*(?:;|$)",
    re.MULTILINE,
)
_MACRO = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(([^)]*)\)", re.MULTILINE)
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "defined", "else", "do"}


def split_words(name: str) -> List[str]:
    """xmlMallocAtomic -> [xml, malloc, atomic]; git__free -> [git, free]."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w]


def extract_candidates(root: Path) -> Dict[str, str]:
    """{name: one-line signature} for functions/macros declared in the target's headers."""
    candidates: Dict[str, str] = {}
    stdlib = standard_names()
    for header in sorted(root.rglob("*")):
        if not header.is_file() or not (
            header.suffix in HEADER_EXTENSIONS or header.name.endswith(HEADER_TEMPLATE_SUFFIXES)
        ):
            continue
        rel = header.relative_to(root)
        if any(part.lower() in SKIP_DIRS for part in rel.parts[:-1]) or rel.parts[0].startswith("."):
            continue
        try:
            text = header.read_text(errors="replace")
        except OSError:
            continue
        for regex, kind in ((_FUNC_DECL, "function"), (_MACRO, "macro")):
            for match in regex.finditer(text):
                name = match.group(1)
                if name in _KEYWORDS or name in stdlib or name in candidates:
                    continue
                signature = " ".join(match.group(0).split())[:160]
                candidates[name] = f"{kind} in {rel}: {signature}"
    return candidates


def _expand(words):
    expanded = set(words)
    for group in SYNONYMS:
        if expanded & group:
            expanded |= group
    return expanded


def rank_candidates(role: str, description: str, source_names: List[str],
                    candidates: Dict[str, str], top_k: int = 40) -> List[str]:
    """Candidates sharing the most words with the role (weighted highest), the
    source project's names for it, and its description (weighted lowest).

    Role and source-name words are expanded with synonyms (free ~ delete ~
    release ...). Source project prefixes (git, xml, curl, sqlite3) are ignored.
    """
    prefixes = {split_words(name)[0] for name in source_names if split_words(name)}
    core = _expand(set(split_words(role)) | {w for n in source_names for w in split_words(n)[1:]})
    core -= prefixes
    described = {w for w in split_words(description) if len(w) > 3} - core - prefixes

    def matches(part, words):
        return part in words or any(len(w) > 3 and len(part) > 3 and (w in part or part in w) for w in words)

    scored = []
    for name in candidates:
        parts = split_words(name)
        score = 3 * sum(matches(p, core) for p in parts) + sum(matches(p, described) for p in parts)
        if score:
            scored.append((-score, len(name), name))
    return [name for _, _, name in sorted(scored)[:top_k]]


def _target_name() -> str:
    return (global_config.get("target_options") or {}).get("name") or global_config.get("target_type")


def port_roles(bundle_dir, commit=None, top_k: int = 40, out_name=None):
    """Map the bundle's roles to the configured target; writes roles/<out_name>.json.

    ``out_name`` defaults to the target name; use another name to avoid
    overwriting a bundle's own roles file (e.g. self-port experiments).
    """
    bundle = Path(bundle_dir)
    manifest = yaml.safe_load((bundle / "manifest.yaml").read_text())
    roles = manifest.get("roles") or {}
    target = _target_name()
    out_name = out_name or target
    if not roles:
        raise ValueError(f"{bundle.name} has no roles: nothing to port (not role-based)")

    checkout = global_config.target.prepare(commit or global_config.scan_commit)
    candidates = extract_candidates(checkout.src)
    logger.info(f"{target}: {len(candidates)} candidate API names from headers")

    sections, offered = [], {}
    for role, value in roles.items():
        ranked = rank_candidates(role, value.get("description", ""), value.get("names", []),
                                 candidates, top_k)
        offered[role] = ranked
        listing = "\n".join(f"  - `{n}` ({candidates[n]})" for n in ranked) or "  - (no candidates)"
        sections.append(
            f"## `{role}`\n\n- Meaning: {value.get('description') or '(none given)'}\n"
            f"- Names in {manifest['source']['project']}: "
            f"{', '.join(f'`{n}`' for n in value.get('names', [])) or '(none)'}\n"
            f"- Candidates in {target}:\n{listing}\n"
        )
    prompt = (
        PROMPT.read_text()
        .replace("{{source_project}}", manifest["source"].get("description") or manifest["source"]["project"])
        .replace("{{target_project}}", global_config.project_description)
        .replace("{{pattern}}", manifest.get("pattern") or "(not recorded)")
        .replace("{{roles}}", "\n".join(sections))
    )
    out = bundle / "ports"
    out.mkdir(exist_ok=True)
    (out / f"{out_name}.prompt.md").write_text(prompt)

    start = time.monotonic()
    response = invoke_llm(prompt, stage="port_roles", temperature=0.01)
    answer = extract_json_block(response or "")
    mapping, dropped, rationale = {}, {}, {}
    for role in roles:
        entry = answer.get(role) or {}
        names = entry.get("names", []) if isinstance(entry, dict) else entry
        valid = [n for n in names if n in offered[role] or n in candidates]
        mapping[role] = valid
        dropped[role] = [n for n in names if n not in valid]
        rationale[role] = entry.get("rationale", "") if isinstance(entry, dict) else ""

    (bundle / "roles" / f"{out_name}.json").write_text(json.dumps(mapping, indent=2))
    report = {
        "target": target,
        "commit": checkout.revision,
        "candidates": len(candidates),
        "offered": offered,
        "mapping": mapping,
        "dropped_not_in_target": dropped,
        "rationale": rationale,
        "llm_seconds": round(time.monotonic() - start, 1),
    }
    (out / f"{out_name}.json").write_text(json.dumps(report, indent=2))
    logger.info(f"Ported {bundle.name} roles to {target}: {mapping}")
    return mapping
