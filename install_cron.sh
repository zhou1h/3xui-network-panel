#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app="$script_dir/cron.php"
tmp="$(mktemp)"
{
  crontab -l 2>/dev/null | grep -v "$app" || true
  echo "* * * * * /usr/bin/php $app >/dev/null 2>&1 # XUI_SWITCHER"
} > "$tmp"
crontab "$tmp"
rm -f "$tmp"
crontab -l | tail -n 8
