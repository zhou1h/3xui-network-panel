#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_URL="${REPOSITORY_URL:-https://github.com/zhou1h/3xui-network-panel.git}"
APP_ROOT="${APP_ROOT:-/opt/control-plane}"
APP_DIR="$APP_ROOT/app"
CONFIG_DIR="/etc/control-plane"
PATH_FILE="$CONFIG_DIR/web-path"
NGINX_SITE="/etc/nginx/sites-available/control-plane"
NGINX_LINK="/etc/nginx/sites-enabled/control-plane"
TLS_DIR="$CONFIG_DIR/tls"
TLS_CERT="$TLS_DIR/origin.crt"
TLS_KEY="$TLS_DIR/origin.key"
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
PANEL_TLS_CERT_FILE="${PANEL_TLS_CERT_FILE:-}"
PANEL_TLS_KEY_FILE="${PANEL_TLS_KEY_FILE:-}"

log() { printf '[control-plane-deploy] %s\n' "$*"; }
fail() { printf '[control-plane-deploy] ERROR: %s\n' "$*" >&2; exit 1; }

generate_path() {
  php -r '
    $first = "abcdefghjkmnpqrstuvwyz";
    echo "/", $first[random_int(0, strlen($first) - 1)], bin2hex(random_bytes(24)), "/\n";
  '
}

validate_tls_pair() {
  local cert_file="$1"
  local key_file="$2"
  local domain_name="${3:-}"
  local cert_public_key
  local private_public_key

  [[ -r "$cert_file" ]] || fail "TLS certificate is not readable: $cert_file"
  [[ -r "$key_file" ]] || fail "TLS private key is not readable: $key_file"
  openssl x509 -in "$cert_file" -noout >/dev/null 2>&1 \
    || fail "invalid TLS certificate: $cert_file"
  openssl pkey -in "$key_file" -check -noout >/dev/null 2>&1 \
    || fail "invalid TLS private key: $key_file"
  openssl x509 -in "$cert_file" -checkend 86400 -noout >/dev/null 2>&1 \
    || fail 'TLS certificate is expired or expires within 24 hours'

  cert_public_key="$(
    openssl x509 -in "$cert_file" -pubkey -noout \
      | openssl pkey -pubin -outform DER 2>/dev/null \
      | openssl dgst -sha256 | awk '{print $2}'
  )"
  private_public_key="$(
    openssl pkey -in "$key_file" -pubout -outform DER 2>/dev/null \
      | openssl dgst -sha256 | awk '{print $2}'
  )"
  [[ -n "$cert_public_key" && "$cert_public_key" == "$private_public_key" ]] \
    || fail 'TLS certificate and private key do not match'

  if [[ -n "$domain_name" ]]; then
    LC_ALL=C openssl x509 -in "$cert_file" -noout -checkhost "$domain_name" 2>/dev/null \
      | grep -q ' does match certificate$' \
      || fail "TLS certificate does not cover PANEL_DOMAIN: $domain_name"
  fi
}

if [[ "${1:-}" == "--generate-path" ]]; then
  command -v php >/dev/null 2>&1 || fail 'PHP is required to generate the path'
  generate_path
  exit 0
fi
if [[ "${1:-}" == "--validate-tls" ]]; then
  [[ $# -ge 3 && $# -le 4 ]] \
    || fail 'usage: bash deploy.sh --validate-tls CERT_FILE KEY_FILE [DOMAIN]'
  command -v openssl >/dev/null 2>&1 || fail 'OpenSSL is required to validate TLS files'
  validate_tls_pair "$2" "$3" "${4:-}"
  log 'TLS certificate and private key are valid and match'
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
      php-mbstring php-sqlite3 php-xml openssl sqlite3 sshpass sudo unzip
    ;;
  rhel|rocky|almalinux|centos|fedora)
    package_manager=dnf
    command -v dnf >/dev/null 2>&1 || package_manager=yum
    if [[ "$DISTRO" =~ ^(rhel|rocky|almalinux|centos)$ ]]; then
      "$package_manager" install -y epel-release || true
    fi
    "$package_manager" install -y \
      ca-certificates cronie curl git nginx openssh-clients openssl php-cli php-common \
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
if [[ -n "$PANEL_DOMAIN" && ! "$PANEL_DOMAIN" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$ ]]; then
  fail 'PANEL_DOMAIN must be a valid DNS hostname'
fi
if [[ -n "$PANEL_TLS_CERT_FILE" || -n "$PANEL_TLS_KEY_FILE" ]]; then
  [[ -n "$PANEL_TLS_CERT_FILE" && -n "$PANEL_TLS_KEY_FILE" ]] \
    || fail 'PANEL_TLS_CERT_FILE and PANEL_TLS_KEY_FILE must be provided together'
fi

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

mkdir -p "$TLS_DIR"
chmod 0700 "$TLS_DIR"
if [[ -n "$PANEL_TLS_CERT_FILE" ]]; then
  validate_tls_pair "$PANEL_TLS_CERT_FILE" "$PANEL_TLS_KEY_FILE" "$PANEL_DOMAIN"
  install -o root -g root -m 0600 "$PANEL_TLS_CERT_FILE" "$TLS_CERT"
  install -o root -g root -m 0600 "$PANEL_TLS_KEY_FILE" "$TLS_KEY"
  log "installed supplied TLS certificate for ${PANEL_DOMAIN:-the configured origin}"
elif [[ -s "$TLS_CERT" && -s "$TLS_KEY" ]]; then
  validate_tls_pair "$TLS_CERT" "$TLS_KEY" "$PANEL_DOMAIN"
  log 'preserved the existing origin TLS certificate'
elif [[ -e "$TLS_CERT" || -e "$TLS_KEY" ]]; then
  fail "incomplete TLS certificate pair in $TLS_DIR"
else
  CERT_NAME="${PANEL_DOMAIN:-control-plane.local}"
  openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 825 \
    -subj "/CN=$CERT_NAME" \
    -addext "subjectAltName=DNS:$CERT_NAME" \
    -keyout "$TLS_KEY" -out "$TLS_CERT" >/dev/null 2>&1
  validate_tls_pair "$TLS_CERT" "$TLS_KEY" "$PANEL_DOMAIN"
  log 'generated a local origin TLS certificate; replace it before enabling Cloudflare Full (strict)'
fi
chmod 0600 "$TLS_KEY" "$TLS_CERT"

TOKEN="${PANEL_PATH#/}"
TOKEN="${TOKEN%/}"
SERVER_NAME="${PANEL_DOMAIN:-_}"
cat > "$NGINX_SITE" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name $SERVER_NAME;
    server_tokens off;

    ssl_certificate $TLS_CERT;
    ssl_certificate_key $TLS_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;

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
PUBLIC_HOST="${PANEL_DOMAIN:-$PUBLIC_IP}"
log 'deployment completed'
printf 'Management path (store securely): %s\n' "$PANEL_PATH"
printf 'HTTPS URL: https://%s%s\n' "$PUBLIC_HOST" "$PANEL_PATH"
printf 'The path is preserved in %s and is not regenerated during updates.\n' "$PATH_FILE"
