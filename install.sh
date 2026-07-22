#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DATA_DIR="$APP_DIR/data"
CRON_FILE="/etc/cron.d/3xui-network-panel"
ORIGINAL_ARGS=("$@")
MODE="install"
RESET_ADMIN=0
CHECK_ONLY=0
WEB_USER="${WEB_USER:-}"

log() { printf '[3x-ui-network-panel] %s\n' "$*"; }
fail() { printf '[3x-ui-network-panel] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo bash install.sh [--update] [--reset-admin] [--check] [--web-user USER]

  --update          Reinstall dependencies and cron without changing the password.
  --reset-admin     Generate a new cryptographically random administrator password.
  --check           Only check the operating system and required runtime.
  --web-user USER   PHP/Nginx/Apache service account that owns runtime data.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --update) MODE="update" ;;
    --reset-admin) RESET_ADMIN=1 ;;
    --check) CHECK_ONLY=1 ;;
    --web-user)
      shift
      [[ $# -gt 0 ]] || fail '--web-user requires an account name'
      WEB_USER="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift
done

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "${ORIGINAL_ARGS[@]}"
  fi
  fail 'run this installer as root or install sudo first'
fi

[[ -r /etc/os-release ]] || fail 'cannot identify this Linux distribution (/etc/os-release is missing)'
# shellcheck disable=SC1091
. /etc/os-release
DISTRO="${ID:-unknown}"
VERSION="${VERSION_ID:-0}"
MAJOR="${VERSION%%.*}"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64|aarch64|arm64) ;;
  *) fail "unsupported CPU architecture: $ARCH" ;;
esac

case "$DISTRO" in
  ubuntu)
    [[ "$MAJOR" =~ ^[0-9]+$ && "$MAJOR" -ge 22 ]] || fail "Ubuntu 22.04 or newer is required (found $VERSION)"
    PKG_FAMILY="apt"
    ;;
  debian)
    [[ "$MAJOR" =~ ^[0-9]+$ && "$MAJOR" -ge 12 ]] || fail "Debian 12 or newer is required (found $VERSION)"
    PKG_FAMILY="apt"
    ;;
  rhel|rocky|almalinux|centos)
    [[ "$MAJOR" =~ ^[0-9]+$ && "$MAJOR" -ge 9 ]] || fail "RHEL/Rocky/AlmaLinux 9 or newer is required (found $VERSION)"
    PKG_FAMILY="rpm"
    ;;
  fedora)
    [[ "$MAJOR" =~ ^[0-9]+$ && "$MAJOR" -ge 39 ]] || fail "Fedora 39 or newer is required (found $VERSION)"
    PKG_FAMILY="rpm"
    ;;
  *) fail "unsupported Linux distribution: $DISTRO $VERSION" ;;
esac

install_packages() {
  if [[ "$PKG_FAMILY" == "apt" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates cron curl openssh-client php-cli php-curl php-mbstring \
      php-sqlite3 php-xml sqlite3 sshpass sudo unzip
    return
  fi

  local pm="dnf"
  command -v dnf >/dev/null 2>&1 || pm="yum"
  if [[ "$DISTRO" =~ ^(rhel|rocky|almalinux|centos)$ ]]; then
    "$pm" install -y epel-release || true
  fi
  "$pm" install -y \
    ca-certificates cronie curl openssh-clients php-cli php-curl php-mbstring \
    php-pdo php-xml sqlite sshpass sudo unzip
}

if [[ "$CHECK_ONLY" -eq 0 ]]; then
  install_packages
fi

PHP_BIN="$(command -v php || true)"
[[ -n "$PHP_BIN" ]] || fail 'PHP CLI was not installed successfully'
"$PHP_BIN" -r 'exit(version_compare(PHP_VERSION, "8.0.0", ">=") ? 0 : 1);' \
  || fail "PHP 8.0 or newer is required (found $("$PHP_BIN" -r 'echo PHP_VERSION;'))"
for extension in curl mbstring sqlite3; do
  "$PHP_BIN" -r 'exit(extension_loaded($argv[1]) ? 0 : 1);' -- "$extension" \
    || fail "required PHP extension is missing: $extension"
done
for command_name in sqlite3 sshpass sudo curl; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is missing: $command_name"
done

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  log "preflight passed: $PRETTY_NAME, $("$PHP_BIN" -r 'echo "PHP ".PHP_VERSION;')"
  exit 0
fi

install_composer() {
  if command -v composer >/dev/null 2>&1; then
    return
  fi
  local work installer expected
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  installer="$work/composer-setup.php"
  expected="$(curl -fsSL https://composer.github.io/installer.sig)"
  curl -fsSL https://getcomposer.org/installer -o "$installer"
  EXPECTED_CHECKSUM="$expected" INSTALLER="$installer" "$PHP_BIN" -r '
    $actual = hash_file("sha384", getenv("INSTALLER"));
    if (!hash_equals(getenv("EXPECTED_CHECKSUM"), $actual)) {
        fwrite(STDERR, "Composer installer signature mismatch\n");
        exit(1);
    }
  '
  "$PHP_BIN" "$installer" --quiet --install-dir=/usr/local/bin --filename=composer
  trap - RETURN
  rm -rf "$work"
}

install_composer
COMPOSER_ALLOW_SUPERUSER=1 composer install \
  --working-dir="$APP_DIR" --no-dev --prefer-dist --no-interaction --optimize-autoloader

detect_web_user() {
  if [[ -n "$WEB_USER" ]]; then
    id "$WEB_USER" >/dev/null 2>&1 || fail "web user does not exist: $WEB_USER"
    return
  fi
  local owner
  owner="$(stat -c '%U' "$APP_DIR" 2>/dev/null || true)"
  if [[ -n "$owner" && "$owner" != "root" ]] && id "$owner" >/dev/null 2>&1; then
    WEB_USER="$owner"
    return
  fi
  for candidate in www-data nginx apache http; do
    if id "$candidate" >/dev/null 2>&1; then
      WEB_USER="$candidate"
      return
    fi
  done
  fail 'cannot detect the PHP web account; rerun with --web-user USER'
}

detect_web_user
WEB_GROUP="$(id -gn "$WEB_USER")"

mkdir -p "$DATA_DIR/job-secrets" "$DATA_DIR/firewall-sessions"
if [[ ! -f "$DATA_DIR/index.php" ]]; then
  printf '%s\n' '<?php' 'http_response_code(404);' > "$DATA_DIR/index.php"
fi

# Remove obsolete secrets from an existing installation while preserving all other settings.
if [[ -f "$DATA_DIR/config.php" ]]; then
  APP_DIR="$APP_DIR" "$PHP_BIN" <<'PHP'
<?php
$file = getenv('APP_DIR') . '/data/config.php';
define('XSW_INTERNAL', true);
$config = include $file;
if (!is_array($config)) {
    fwrite(STDERR, "Invalid data/config.php\n");
    exit(1);
}
unset($config['app_secret']);
$body = "<?php\nif (!defined('XSW_INTERNAL')) { http_response_code(404); exit; }\nreturn "
    . var_export($config, true) . ";\n";
$temporary = $file . '.tmp-' . bin2hex(random_bytes(4));
if (file_put_contents($temporary, $body, LOCK_EX) === false || !rename($temporary, $file)) {
    @unlink($temporary);
    fwrite(STDERR, "Unable to update data/config.php\n");
    exit(1);
}
chmod($file, 0600);
PHP
fi

ADMIN_PASSWORD=''
if [[ ! -f "$DATA_DIR/config.php" || "$RESET_ADMIN" -eq 1 ]]; then
  ADMIN_PASSWORD="$("$PHP_BIN" -r '
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%+=_-";
    $password = "";
    for ($i = 0; $i < 28; $i++) {
        $password .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }
    echo $password;
  ')"
  ADMIN_HASH="$(printf '%s' "$ADMIN_PASSWORD" | "$PHP_BIN" -r '
    $password = stream_get_contents(STDIN);
    echo password_hash($password, PASSWORD_DEFAULT);
  ')"
  umask 077
  CONFIG_FILE="$DATA_DIR/config.php" ADMIN_HASH="$ADMIN_HASH" "$PHP_BIN" <<'PHP'
<?php
$file = getenv('CONFIG_FILE');
$config = ['password_hash' => getenv('ADMIN_HASH')];
$body = "<?php\nif (!defined('XSW_INTERNAL')) { http_response_code(404); exit; }\nreturn "
    . var_export($config, true) . ";\n";
if (file_put_contents($file, $body, LOCK_EX) === false) {
    fwrite(STDERR, "Unable to initialize administrator credentials\n");
    exit(1);
}
chmod($file, 0600);
PHP
fi

# Code is readable by the web server; runtime state and credentials stay private.
find "$APP_DIR" -path "$APP_DIR/.git" -prune -o -path "$DATA_DIR" -prune -o -type d -exec chmod 0755 {} +
find "$APP_DIR" -path "$APP_DIR/.git" -prune -o -path "$DATA_DIR" -prune -o -type f -exec chmod 0644 {} +
chmod 0755 "$APP_DIR/deploy.sh" "$APP_DIR/install.sh" "$APP_DIR/update.sh" "$APP_DIR/uninstall.sh"
chown -R "$WEB_USER:$WEB_GROUP" "$DATA_DIR"
find "$DATA_DIR" -type d -exec chmod 0700 {} +
find "$DATA_DIR" -type f -exec chmod 0600 {} +

[[ "$APP_DIR" != *$'\n'* && "$APP_DIR" != *"'"* ]] \
  || fail "application path must not contain a newline or single quote"
cat > "$CRON_FILE" <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * $WEB_USER $PHP_BIN '$APP_DIR/cron.php' >/dev/null 2>&1
EOF
chown root:root "$CRON_FILE"
chmod 0644 "$CRON_FILE"

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^cron\.service'; then
    systemctl enable --now cron.service
  else
    systemctl enable --now crond.service
  fi
else
  service cron restart 2>/dev/null || service crond restart
fi

log "$MODE completed on $PRETTY_NAME"
log "runtime user: $WEB_USER"
log "cron installed: $CRON_FILE"
if [[ -n "$ADMIN_PASSWORD" ]]; then
  printf '\nAdministrator password (shown once): %s\n' "$ADMIN_PASSWORD"
  printf 'Store it securely now. It is not written to logs or repository files.\n\n'
else
  log 'existing administrator password preserved'
fi
