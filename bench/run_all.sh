#!/bin/bash
# Sequential benchmark driver (runs must not overlap: they compete for CPU).
# Runs from a frozen code snapshot so development can continue meanwhile.
cd "$(dirname "$0")/.."
PY=$(pwd)/.venv/bin/python
TAG=${1:-r1}
SNAP=bench/snapshots/$TAG
if [ ! -d "$SNAP" ]; then
  mkdir -p "$SNAP"
  cp -a src prompt_template checker_database llm_keys.yaml "$SNAP"/
  rm -rf "$SNAP"/src/__pycache__ "$SNAP"/src/*/__pycache__
  (cd "$SNAP" && find src prompt_template -type f \( -name '*.py' -o -name '*.md' \) | sort | xargs sha256sum | sha256sum) > "$SNAP.sha256"
fi
export KNIGHTER_CODE_ROOT=$(realpath "$SNAP")
# Keep Windows awake for the whole benchmark (r6 lost 5.6 h to a sleep).
if command -v powershell.exe > /dev/null; then
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w bench/keep_awake.ps1)" > /dev/null 2>&1 &
  AWAKE_PID=$!
  trap 'kill $AWAKE_PID 2>/dev/null' EXIT
  echo "keep-awake helper pid $AWAKE_PID"
fi
echo "code snapshot: $KNIGHTER_CODE_ROOT ($(cut -c1-16 "$SNAP.sha256"))"
# Per project: baseline then optimized (adjacent, so provider-load drift hits both alike).
for spec in "A-lua:configs/lua.yaml:bench/commits-lua.txt:baseline" \
            "B-lua:configs/lua.yaml:bench/commits-lua.txt:optimized" \
            "A-re2:configs/re2.yaml:bench/commits-re2.txt:baseline" \
            "B-re2:configs/re2.yaml:bench/commits-re2.txt:optimized" \
            "A-yaml-cpp:configs/yaml-cpp.yaml:bench/commits-yaml-cpp.txt:baseline" \
            "B-yaml-cpp:configs/yaml-cpp.yaml:bench/commits-yaml-cpp.txt:optimized" \
            "A-libxml2:configs/libxml2.yaml:bench/commits-libxml2.txt:baseline" \
            "B-libxml2:configs/libxml2.yaml:bench/commits-libxml2.txt:optimized" \
            "A-sqlite:configs/sqlite.yaml:bench/commits-sqlite.txt:baseline" \
            "B-sqlite:configs/sqlite.yaml:bench/commits-sqlite.txt:optimized" \
            "A-curl:configs/curl.yaml:bench/commits-curl.txt:baseline" \
            "B-curl:configs/curl.yaml:bench/commits-curl.txt:optimized" \
            "A-libgit2:configs/libgit2.yaml:bench/commits-libgit2.txt:baseline" \
            "B-libgit2:configs/libgit2.yaml:bench/commits-libgit2.txt:optimized"; do
  IFS=: read name cfg commits variant <<< "$spec"
  echo "=== $(date -Is) start $TAG-$name"
  $PY bench/run_bench.py "$TAG-$name" "$cfg" "$commits" "$variant"
  echo "=== $(date -Is) end $TAG-$name"
done
