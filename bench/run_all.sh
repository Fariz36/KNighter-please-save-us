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
# Run list: $SPECS (space-separated name:config:commits:variant), default the full A/B set.
# Extra key=value overrides for every run: $OVERRIDES (e.g. "role_based_checkers=true").
DEFAULT_SPECS=""
for proj in lua re2 yaml-cpp libxml2 sqlite curl libgit2; do
  DEFAULT_SPECS="$DEFAULT_SPECS A-$proj:configs/$proj.yaml:bench/commits-$proj.txt:baseline B-$proj:configs/$proj.yaml:bench/commits-$proj.txt:optimized"
done
for spec in ${SPECS:-$DEFAULT_SPECS}; do
  IFS=: read name cfg commits variant <<< "$spec"
  echo "=== $(date -Is) start $TAG-$name"
  $PY bench/run_bench.py "$TAG-$name" "$cfg" "$commits" "$variant" $OVERRIDES
  echo "=== $(date -Is) end $TAG-$name"
done
