#!/usr/bin/env bash
# Build ltcengine for Linux / WSL.
# Uses build-linux/ so it does not clash with the Windows MSVC build/ tree.
set -euo pipefail
cd "$(dirname "$0")"

BUILD_DIR="${BUILD_DIR:-build-linux}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: '$1' not found on PATH" >&2
    echo "On Ubuntu/Debian WSL: sudo apt update && sudo apt install -y build-essential cmake git" >&2
    exit 1
  fi
}

need cmake
need g++
need git

if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  echo "Configuring (${BUILD_DIR}, Release)..."
  cmake -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release
fi

echo "Building Release (-j${JOBS})..."
cmake --build "${BUILD_DIR}" --config Release --target ltcengine -j"${JOBS}"

if [[ ! -x bin/ltcengine ]]; then
  echo "error: bin/ltcengine missing after build" >&2
  exit 1
fi

echo "Build OK: bin/ltcengine"
