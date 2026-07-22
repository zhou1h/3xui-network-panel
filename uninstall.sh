#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DATA_DIR="$APP_DIR/data"
CRON_FILE="/etc/cron.d/3xui-network-panel"
PURGE_DATA=0

if [[ "${1:-}" == "--purge-data" ]]; then
  PURGE_DATA=1
elif [[ $# -gt 0 ]]; then
  printf 'Usage: sudo bash uninstall.sh [--purge-data]\n' >&2
  exit 1
fi

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { printf 'ERROR: run as root.\n' >&2; exit 1; }
  exec sudo bash "$0" "$@"
fi

rm -f -- "$CRON_FILE"

if [[ "$PURGE_DATA" -eq 1 ]]; then
  if [[ ! -d "$DATA_DIR" ]]; then
    printf 'Runtime data is already absent: %s\n' "$DATA_DIR"
    printf 'Cron integration removed. Shared PHP/system packages were left installed.\n'
    exit 0
  fi
  APP_REAL="$(realpath -e "$APP_DIR")"
  DATA_REAL="$(realpath -e "$DATA_DIR")"
  [[ "$DATA_REAL" == "$APP_REAL/data" && "$DATA_REAL" != "/" ]] || {
    printf 'ERROR: refusing to purge unexpected data path: %s\n' "$DATA_REAL" >&2
    exit 1
  }
  rm -rf -- "$DATA_REAL"
  printf 'Runtime data removed: %s\n' "$DATA_REAL"
else
  printf 'Runtime data preserved: %s\n' "$DATA_DIR"
fi

printf 'Cron integration removed. Shared PHP/system packages were left installed.\n'
printf 'Delete the source directory manually after backing up anything you need.\n'
