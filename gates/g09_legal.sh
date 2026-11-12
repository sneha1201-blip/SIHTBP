#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${VIRTUAL_ENV:-$DIR/.venv}/Scripts/python.exe"
if [[ ! -f "$PYTHON_BIN" ]]; then
    PYTHON_BIN="${VIRTUAL_ENV:-$DIR/.venv}/bin/python"
fi
if [[ ! -f "$PYTHON_BIN" ]]; then
    PYTHON_BIN="python"
fi

exec "$PYTHON_BIN" "$DIR/gates/g09_legal.py"
