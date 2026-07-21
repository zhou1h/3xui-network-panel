#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$APP_DIR"

if [[ ! -d .git ]]; then
  printf 'ERROR: update.sh requires a Git clone. Download the new release and run install.sh --update instead.\n' >&2
  exit 1
fi

git diff --quiet && git diff --cached --quiet || {
  printf 'ERROR: local source changes exist; commit or stash them before updating.\n' >&2
  exit 1
}

git pull --ff-only
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  exec bash "$APP_DIR/install.sh" --update "$@"
fi
exec sudo bash "$APP_DIR/install.sh" --update "$@"
