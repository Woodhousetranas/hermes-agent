#!/usr/bin/env bash
# Canonical test runner for hermes-agent. Run this instead of calling
# `pytest` directly to guarantee your local run matches CI behavior.
#
# What this script enforces:
#   * Per-file isolation via scripts/run_tests_parallel.py — each test
#     file runs in its own freshly-spawned `python -m pytest <file>`
#     subprocess. No xdist, no shared workers, no module-level leakage
#     between files.
#   * TZ=UTC, LANG=C.UTF-8, PYTHONHASHSEED=0 (deterministic)
#   * Env vars blanked (conftest.py also does this, but this
#     is belt-and-suspenders for anyone running pytest outside our
#     conftest path — e.g. on a single file)
#   * Proper venv activation (probes .venv, venv, then ~/.hermes/...)
#
# Usage:
#   scripts/run_tests.sh                            # full suite
#   scripts/run_tests.sh -j 4                       # cap parallelism
#   scripts/run_tests.sh tests/agent/               # discover only here
#   scripts/run_tests.sh tests/agent/ tests/acp/    # multiple roots
#   scripts/run_tests.sh tests/foo.py               # single file
#   scripts/run_tests.sh tests/foo.py -- --tb=long  # path + pytest args
#   scripts/run_tests.sh -- -v --tb=long            # pytest args only
#
# Everything after a literal '--' is passed through to each per-file
# pytest invocation. Positional path arguments before '--' override
# the default discovery root (tests/).

set -euo pipefail

# ── Locate repo root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Activate venv ───────────────────────────────────────────────────────────
python_for_venv() {
  local candidate="$1"
  if [ -x "$candidate/bin/python" ]; then
    printf "%s\n" "$candidate/bin/python"
    return 0
  fi
  if [ -x "$candidate/Scripts/python.exe" ]; then
    printf "%s\n" "$candidate/Scripts/python.exe"
    return 0
  fi
  if [ -x "$candidate/Scripts/python" ]; then
    printf "%s\n" "$candidate/Scripts/python"
    return 0
  fi
  return 1
}

VENV=""
PYTHON=""
for candidate in "$REPO_ROOT/.venv" "$REPO_ROOT/venv" "$HOME/.hermes/hermes-agent/venv"; do
  if [ -f "$candidate/bin/activate" ] || [ -f "$candidate/Scripts/activate" ]; then
    candidate_python="$(python_for_venv "$candidate" || true)"
    if [ -z "$candidate_python" ]; then
      continue
    fi
    if "$candidate_python" -c "import pytest" >/dev/null 2>&1; then
      VENV="$candidate"
      PYTHON="$candidate_python"
      break
    fi
    if [ -z "$VENV" ]; then
      VENV="$candidate"
      PYTHON="$candidate_python"
    fi
  fi
done

if [ -z "$VENV" ]; then
  echo "error: no virtualenv found in $REPO_ROOT/.venv or $REPO_ROOT/venv" >&2
  exit 1
fi

if ! "$PYTHON" -c "import pytest" >/dev/null 2>&1; then
  echo "error: no pytest found in probed virtualenvs under $REPO_ROOT/.venv or $REPO_ROOT/venv" >&2
  exit 1
fi


# ── Live-gateway plugin (computed before we drop env) ───────────────────────
EXTRA_PYTHONPATH=""
EXTRA_PYTEST_PLUGINS=""
if [ -f "$HOME/.hermes/pytest_live_guard.py" ]; then
  EXTRA_PYTHONPATH="$HOME/.hermes"
  EXTRA_PYTEST_PLUGINS="pytest_live_guard"
fi


# ── Run in hermetic env ──────────────────────────────────────────────────────
# env -i: start with empty environment, opt-in only what we need.
# No credential var can leak — you'd have to explicitly add it here.
echo "▶ running per-file parallel test suite via run_tests_parallel.py"
echo "  (TZ=UTC LANG=C.UTF-8 PYTHONHASHSEED=0; clean env)"

cd "$REPO_ROOT"

WINDOWS_USERPROFILE="${USERPROFILE:-}"
if [ -z "$WINDOWS_USERPROFILE" ] && command -v cygpath >/dev/null 2>&1; then
  WINDOWS_USERPROFILE="$(cygpath -w "$HOME" 2>/dev/null || true)"
fi
WINDOWS_HOMEDRIVE="${HOMEDRIVE:-}"
WINDOWS_HOMEPATH="${HOMEPATH:-}"
WINDOWS_TEMP="${TEMP:-${TMP:-/tmp}}"
WINDOWS_TMP="${TMP:-$WINDOWS_TEMP}"

exec env -i \
  PATH="$PATH" \
  HOME="$HOME" \
  ${WINDOWS_USERPROFILE:+USERPROFILE="$WINDOWS_USERPROFILE"} \
  ${WINDOWS_HOMEDRIVE:+HOMEDRIVE="$WINDOWS_HOMEDRIVE"} \
  ${WINDOWS_HOMEPATH:+HOMEPATH="$WINDOWS_HOMEPATH"} \
  TEMP="$WINDOWS_TEMP" \
  TMP="$WINDOWS_TMP" \
  TZ=UTC \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  PYTHONHASHSEED=0 \
  PYTHONUTF8=1 \
  PYTHONIOENCODING=utf-8 \
  PYTHONDONTWRITEBYTECODE=1 \
  ${EXTRA_PYTHONPATH:+PYTHONPATH="$EXTRA_PYTHONPATH"} \
  ${EXTRA_PYTEST_PLUGINS:+PYTEST_PLUGINS="$EXTRA_PYTEST_PLUGINS"} \
  "$PYTHON" "$SCRIPT_DIR/run_tests_parallel.py" "$@"
