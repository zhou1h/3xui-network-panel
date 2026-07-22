#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_URL="${REPOSITORY_URL:-https://github.com/zhou1h/3xui-network-panel.git}"
APP_ROOT="${APP_ROOT:-/opt/control-plane}"
APP_DIR="$APP_ROOT/app"
CONFIG_DIR="/etc/control-plane"
PATH_FILE="$CONFIG_DIR/web-path"
NGINX_SITE="/etc/nginx/sites-available/control-plane"
NGINX_LINK="/etc/nginx/sites-enabled/control-plane"

log() { printf '[control-plane-deploy] %s\n' "$*"; }
fail() { printf '[control-plane-deploy] ERROR: %s\n' "$*" >&2; exit 1; }

generate_path() {
  php -r '
    $first = "abcdefghjkmnpqrstuvwyz";
    echo "/", $first[random_int(0, strlen($first) - 1)], bin2hex(random_bytes(24)), "/\n";
  '
}

if [[ "${1:-}" == "--generate-path" ]]; then
  command -v php >/dev/null 2>&1 || fail 'PHP is required to generate the path'
  generate_path
  exit 0
fi
[[ $# -eq 0 ]] || fail 'usage: sudo bash deploy.sh'
[[ ${EUID:-$(id -u)} -eq 0 ]] || fail 'run this deployer as root'
[[ -r /etc/os-release ]] || fail 'cannot identify this Linux distribution'

# shellcheck disable=SC1091
. /etc/os-release
DISTRO="${ID:-unknown}"
case "$DISTRO" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates cron curl git nginx openssh-client php-cli php-curl php-fpm \
      php-mbstring php-sqlite3 php-xml sqlite3 sshpass sudo unzip
    ;;
  rhel|rocky|almalinux|centos|fedora)
    package_manager=dnf
    command -v dnf >/dev/null 2>&1 || package_manager=yum
    if [[ "$DISTRO" =~ ^(rhel|rocky|almalinux|centos)$ ]]; then
      "$package_manager" install -y epel-release || true
    fi
    "$package_manager" install -y \
      ca-certificates cronie curl git nginx openssh-clients php-cli php-common \
      php-fpm php-mbstring php-pdo php-process php-xml sqlite sshpass sudo unzip
    ;;
  *) fail "unsupported Linux distribution: $DISTRO" ;;
esac

if [[ ! -d /etc/nginx/sites-available ]]; then
  NGINX_SITE="/etc/nginx/conf.d/control-plane.conf"
  NGINX_LINK="$NGINX_SITE"
fi

if [[ -e "$APP_DIR" && ! -d "$APP_DIR/.git" ]]; then
  fail "refusing to overwrite a non-Git application directory: $APP_DIR"
fi
mkdir -p "$APP_ROOT" "$CONFIG_DIR"
chmod 0700 "$CONFIG_DIR"

if [[ ! -d "$APP_DIR/.git" ]]; then
  git clone --depth 1 --branch main "$REPOSITORY_URL" "$APP_DIR"
else
  git -c safe.directory="$APP_DIR" -C "$APP_DIR" diff --quiet
  git -c safe.directory="$APP_DIR" -C "$APP_DIR" diff --cached --quiet
  git -c safe.directory="$APP_DIR" -C "$APP_DIR" pull --ff-only
fi

if [[ ! -f "$PATH_FILE" ]]; then
  umask 077
  generate_path > "$PATH_FILE"
fi
PANEL_PATH="$(tr -d '\r\n' < "$PATH_FILE")"
[[ "$PANEL_PATH" =~ ^/[abcdefghjkmnpqrstuvwyz][a-f0-9]{48}/$ ]] \
  || fail "invalid management path stored in $PATH_FILE"
chmod 0600 "$PATH_FILE"

WEB_USER=www-data
if ! id "$WEB_USER" >/dev/null 2>&1; then
  WEB_USER=nginx
fi
id "$WEB_USER" >/dev/null 2>&1 || fail 'cannot find the Nginx/PHP service account'
bash "$APP_DIR/install.sh" --web-user "$WEB_USER"

if command -v systemctl >/dev/null 2>&1; then
  while IFS= read -r service_name; do
    [[ -n "$service_name" ]] || continue
    systemctl enable --now "$service_name"
  done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
    | awk '$1 ~ /^php.*-fpm\.service$/ {print $1}')
  systemctl enable --now nginx.service
fi

FPM_SOCKET="$(
  for socket_root in /run/php /run/php-fpm; do
    [[ -d "$socket_root" ]] || continue
    find "$socket_root" -maxdepth 1 -type s \( -name 'php*-fpm.sock' -o -name 'www.sock' \)
  done | sort -V | tail -n 1
)"
[[ -n "$FPM_SOCKET" ]] || fail 'PHP-FPM socket was not found after installation'

TOKEN="${PANEL_PATH#/}"
TOKEN="${TOKEN%/}"
cat > "$NGINX_SITE" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;

    add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "same-origin" always;

    location = /$TOKEN {
        return 302 /$TOKEN/;
    }

    location = /$TOKEN/ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $APP_DIR/index.php;
        fastcgi_param SCRIPT_NAME /$TOKEN/index.php;
        fastcgi_pass unix:$FPM_SOCKET;
    }

    location ~ ^/$TOKEN/(index|qr)\\.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $APP_DIR/\$1.php;
        fastcgi_param SCRIPT_NAME /$TOKEN/\$1.php;
        fastcgi_pass unix:$FPM_SOCKET;
    }

    location ^~ /$TOKEN/data/ {
        return 404;
    }

    location /$TOKEN/ {
        return 404;
    }

    location / {
        return 404;
    }
}
EOF
chmod 0600 "$NGINX_SITE"
if [[ -d /etc/nginx/sites-enabled ]]; then
  rm -f /etc/nginx/sites-enabled/default
  ln -sfn "$NGINX_SITE" "$NGINX_LINK"
fi
nginx -t
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload nginx.service
else
  nginx -s reload
fi

PUBLIC_IP="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
[[ -n "$PUBLIC_IP" ]] || PUBLIC_IP='<server-ip>'
log 'deployment completed'
printf 'Management path (store securely): %s\n' "$PANEL_PATH"
printf 'Temporary HTTP URL: http://%s%s\n' "$PUBLIC_IP" "$PANEL_PATH"
printf 'The path is preserved in %s and is not regenerated during updates.\n' "$PATH_FILE"
