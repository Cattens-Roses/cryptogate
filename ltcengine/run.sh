#!/usr/bin/env bash
# Build (unless --no-build) then run ltcengine on Linux / WSL.
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--no-build" ]]; then
  shift
  if [[ ! -x bin/ltcengine ]]; then
    echo "error: bin/ltcengine not found — run ./build.sh first" >&2
    exit 1
  fi
else
  ./build.sh
fi

echo "Starting ltcengine..."
exec ./bin/ltcengine "$@"
