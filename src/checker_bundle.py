"""Export validated checkers as standalone bundles (section 3.3).

A bundle is everything needed to run a checker on any C/C++ project without
KNighter: the plugin built for KNighter's clang, its source plus a CMake file
to rebuild it against another clang, the roles file of the project it came
from, a stdlib-only runner, and a manifest describing provenance and scores.

    main.py export --config_file=<project.yaml> --checker_dir=<results> [--out_dir=...]
"""

import json
import re
import shutil
import subprocess as sp
import time
from pathlib import Path
from typing import Optional

import yaml

from backends.plugin_builder import KNIGHTER_INCLUDE, parse_roles_block
from checker_lint import find_hardcoded_identifiers
from checker_scan import _checker_file
from global_config import global_config, logger

SRC = Path(__file__).resolve().parent
REPO = SRC.parent
TEMPLATE = SRC / "bundle_template"


def _project_name() -> str:
    options = global_config.get("target_options") or {}
    return options.get("name") or global_config.get("target_type", "project")


def _clang_version() -> str:
    clang = global_config.backend.clang_path
    try:
        out = sp.run([str(clang), "--version"], capture_output=True, text=True, timeout=30)
        return out.stdout.splitlines()[0].strip()
    except Exception as error:  # pragma: no cover - informational only
        return f"unknown ({error})"


def _knighter_revision() -> str:
    try:
        return sp.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                      text=True, timeout=30).stdout.strip()
    except Exception:
        return "unknown"


def _full_commit(prefix: str) -> str:
    try:
        return global_config.target.resolve(prefix)
    except Exception:
        return prefix


def _scores(checker_dir: Path) -> dict:
    score = checker_dir / "score.txt"
    if not score.exists():
        return {}
    values = dict(re.findall(r"(TP|TN): (-?\d+)", score.read_text()))
    return {"tp": int(values.get("TP", 0)), "tn": int(values.get("TN", 0)),
            "scoring": global_config.get("validation_scoring", "strict")}


def export_bundle(checker_dir: Path, out_dir: Path) -> Optional[Path]:
    checker_dir = Path(checker_dir)
    checker_file = _checker_file(checker_dir)
    if checker_file is None:
        logger.info(f"{checker_dir.name}: no valid checker, not exported")
        return None
    code = checker_file.read_text()

    plugin = global_config.backend.plugin_for(code)
    if plugin is None:
        logger.error(f"{checker_dir.name}: checker does not build, not exported")
        return None

    bundle = Path(out_dir) / checker_dir.name
    if bundle.exists():
        shutil.rmtree(bundle)
    (bundle / "roles").mkdir(parents=True)
    (bundle / "include" / "knighter").mkdir(parents=True)
    (bundle / "include" / "clang" / "StaticAnalyzer" / "Checkers").mkdir(parents=True)

    (bundle / "checker.cpp").write_text(code)
    if (checker_dir / "patch.txt").exists():
        # The fix the checker was generated from; triage on other projects compares against it.
        shutil.copy2(checker_dir / "patch.txt", bundle / "patch.md")
    shutil.copy2(plugin, bundle / "plugin.so")
    shutil.copy2(SRC / "backends" / "direct_analysis.py", bundle / "knighter_analysis.py")
    shutil.copy2(TEMPLATE / "run_bundle.py", bundle / "run_bundle.py")
    shutil.copy2(TEMPLATE / "CMakeLists.txt", bundle / "CMakeLists.txt")
    shutil.copy2(KNIGHTER_INCLUDE / "knighter" / "roles.h", bundle / "include" / "knighter" / "roles.h")
    shutil.copy2(REPO / "llvm_utils" / "utility.h",
                 bundle / "include" / "clang" / "StaticAnalyzer" / "Checkers" / "utility.h")
    shutil.copy2(REPO / "llvm_utils" / "utility.cpp", bundle / "utility.cpp")

    project = _project_name()
    roles = parse_roles_block(code)
    if roles:
        (bundle / "roles" / f"{project}.json").write_text(
            json.dumps({role: value["names"] for role, value in roles.items()}, indent=2)
        )

    parts = checker_dir.name.split("-")  # KN-<Type...>-<sha8>-<index>
    commit = parts[-2] if checker_dir.name.startswith("KN-") and len(parts) >= 4 else ""
    pattern_file = checker_dir / "pattern.txt"
    hardcoded = sorted({f.name for f in find_hardcoded_identifiers(code)})
    manifest = {
        "id": checker_dir.name,
        "bug_type": "-".join(parts[1:-2]) if commit else "",
        "source": {
            "project": project,
            "description": global_config.project_description,
            "commit": _full_commit(commit) if commit else "",
        },
        "checker_file": checker_file.name,
        "scores": _scores(checker_dir),
        "pattern": pattern_file.read_text().strip() if pattern_file.exists() else "",
        "roles": roles or {},
        "portable": bool(roles) and not hardcoded,
        "hardcoded_identifiers": hardcoded,
        "plugin": {"clang_version": _clang_version(), "checker_name": "custom.SAGenTestChecker"},
        "knighter_revision": _knighter_revision(),
        "exported": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (bundle / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False, width=100))
    (bundle / "README.md").write_text(_readme(manifest))
    logger.info(f"Exported {checker_dir.name} -> {bundle} (portable={manifest['portable']})")
    return bundle


def _readme(manifest: dict) -> str:
    roles = "\n".join(
        f"- `{role}`: {value.get('description') or '(no description)'}"
        for role, value in manifest["roles"].items()
    ) or "- (none: this checker does not use project roles)"
    warning = ""
    if manifest["hardcoded_identifiers"]:
        warning = ("\n**Not fully portable:** the checker logic still names "
                   + ", ".join(f"`{n}`" for n in manifest["hardcoded_identifiers"]) + ".\n")
    return f"""# {manifest['id']}

{manifest['bug_type']} checker generated by KNighter from {manifest['source']['project']} commit
`{manifest['source']['commit']}`.
{warning}
## Run

```sh
python3 run_bundle.py --compile-db /path/to/compile_commands.json \\
    --roles roles/<project>.json --out reports/ --clang /path/to/clang
```

`plugin.so` was built for `{manifest['plugin']['clang_version']}`. For another clang, rebuild:
`cmake -S . -B build -DClang_DIR=<llvm>/lib/cmake/clang && cmake --build build`, then pass
`--plugin build/plugin.so`.

## Roles

To use the checker on another project, give it that project's names for these roles
(a JSON object `{{"role": ["name", ...]}}`; `main.py port_roles` can propose one):

{roles}

## Bug pattern

{manifest['pattern']}
"""


def export_bundles(checker_dir, out_dir=None):
    checker_dir = Path(checker_dir)
    out_dir = Path(out_dir) if out_dir else checker_dir / "bundles"
    out_dir.mkdir(parents=True, exist_ok=True)
    exported = []
    for sub in sorted(p for p in checker_dir.iterdir() if p.is_dir() and p.name.startswith("KN-")):
        bundle = export_bundle(sub, out_dir)
        if bundle:
            exported.append(bundle.name)
    (out_dir / "index.json").write_text(json.dumps(exported, indent=2))
    logger.info(f"Exported {len(exported)} bundle(s) to {out_dir}")
    return exported
