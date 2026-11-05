#!/usr/bin/env bash
# =============================================================================
# setup-pre-commit.sh -- install DCC pre-commit checks in an isolated venv.
#
# Design:
#   * Keep the host clean: tools are installed under .pre-commit-venv/.
#   * Use the pip mirror only for this script invocation.
#   * Be idempotent: safe to run repeatedly.
#
# Usage:
#   bash setup-pre-commit.sh
#   PIP_MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple bash setup-pre-commit.sh
#
# Requirements: git, python>=3.7, access to gitcode.com.
# =============================================================================
set -euo pipefail

PIP_MIRROR="${PIP_MIRROR:-https://mirrors.aliyun.com/pypi/simple/}"
PIP_HOST="$(printf '%s' "$PIP_MIRROR" | sed -E 's#^https?://([^/]+)/?.*#\1#')"
VENV_DIR=".pre-commit-venv"

log() { printf '\033[1;32m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git not found"
git rev-parse --show-toplevel >/dev/null 2>&1 || die "run this script inside the DCC git repository"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
[ -f .pre-commit-config.yaml ] || die ".pre-commit-config.yaml not found"

PY=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    version="$("$candidate" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo 0.0)"
    major="${version%%.*}"
    minor="${version##*.}"
    if [ "${major:-0}" -eq 3 ] && [ "${minor:-0}" -ge 7 ]; then
      PY="$candidate"
      break
    fi
  fi
done
[ -n "$PY" ] || die "python>=3.7 is required"

log "python: $PY ($("$PY" --version 2>&1))"
log "temporary pip mirror: $PIP_MIRROR"

if [ ! -d "$VENV_DIR" ]; then
  log "create isolated environment: $VENV_DIR/"
  "$PY" -m venv "$VENV_DIR" || die "failed to create venv"
else
  log "reuse isolated environment: $VENV_DIR/"
fi

VENV_PY="$VENV_DIR/bin/python"
log "install pre-commit into isolated environment"
"$VENV_PY" -m pip install --disable-pip-version-check -q \
  -i "$PIP_MIRROR" --trusted-host "$PIP_HOST" --upgrade pip
"$VENV_PY" -m pip install --disable-pip-version-check \
  -i "$PIP_MIRROR" --trusted-host "$PIP_HOST" \
  pre-commit

PRE_COMMIT="$VENV_DIR/bin/pre-commit"

log "install git hook"
"$PRE_COMMIT" install

log "pre-install hook environments from gitcode and the pip mirror"
PIP_INDEX_URL="$PIP_MIRROR" PIP_TRUSTED_HOST="$PIP_HOST" \
  "$PRE_COMMIT" install-hooks

if ! grep -qxF "$VENV_DIR/" .gitignore 2>/dev/null && ! grep -qxF "$VENV_DIR" .gitignore 2>/dev/null; then
  warn "add $VENV_DIR/ to .gitignore to avoid committing the local environment"
fi

log "done. Future git commit commands will run pre-commit automatically."
log "manual run: $PRE_COMMIT run --files <file>"
log "uninstall:  $PRE_COMMIT uninstall && rm -rf $VENV_DIR/"
