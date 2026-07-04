#!/usr/bin/env bash
set -euo pipefail

conf="${1:-}"
block_var="${2:-block_client}"

if [[ -z "$conf" || ! -f "$conf" ]]; then
  echo "Usage: bash allow_subpath.sh /path/to/nginx-site.conf [block_variable_name]" >&2
  echo "Example: bash allow_subpath.sh /www/server/panel/vhost/nginx/example.com.conf block_client" >&2
  exit 1
fi

bak="${conf}.bak-xui-switcher-$(date +%Y%m%d%H%M%S)"
cp -a "$conf" "$bak"

if ! grep -q "xui-switcher allow" "$conf"; then
  awk -v block_var="$block_var" '
    { print }
    /if \(\$uri = \/robots\.txt\)/ { inrobots=1 }
    inrobots && /^    }$/ {
      print "    # xui-switcher allow"
      print "    if ($uri ~* \"^/xui-switcher(/|$)\") {"
      print "        set $" block_var " 0;"
      print "    }"
      inrobots=0
    }
  ' "$bak" > "$conf"
fi

nginx -t
systemctl reload nginx
echo "BACKUP=$bak"
grep -n "xui-switcher allow" -A4 "$conf"
