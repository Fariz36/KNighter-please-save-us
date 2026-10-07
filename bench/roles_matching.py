"""roles.h matching on real code: function name vs macro wrapper vs function pointer.

Usage: [CODE_SRC=<snapshot>/src TAG=old] python bench/roles_matching.py CONFIG FILE NAME [NAME ...]
Reports how many calls the role-reporting test checker (bench/fixtures/role_watch_checker.cpp) flags when the
role "watched" is bound to each NAME."""
import os, sys, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.environ.get("CODE_SRC", str(ROOT / "src")))
from global_config import global_config
config, file, names = sys.argv[1], sys.argv[2], sys.argv[3:]
global_config.setup(str(ROOT / config))
code = (ROOT / "bench/fixtures/role_watch_checker.cpp").read_text()
out = {}
for name in names:
    roles = ROOT / "tmp/roles-macro" / f"roles-{name}.json"
    roles.write_text(json.dumps({"watched": [name]}))
    os.environ["KNIGHTER_ROLES"] = str(roles)
    n = global_config.backend.run_checker(code, "HEAD", global_config.target, object_to_analyze=file,
                                          output_dir=str(ROOT / "tmp/roles-macro" / f"out-{os.environ.get('TAG','new')}-{name}"))
    out[name] = n
print(json.dumps({"file": file, **out}))
