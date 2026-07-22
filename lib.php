<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Shanghai');

const XSW_VERSION = '0.3.1';
const XSW_PREFIX = 'xsw_';
const XSW_LEGACY_PREFIX = 'jd_';
const XSW_DATA_DIR = __DIR__ . '/data';
const XSW_SECRET_DIR = XSW_DATA_DIR . '/job-secrets';
const XSW_STATE_FILE = XSW_DATA_DIR . '/state.php';
const XSW_CONFIG_FILE = XSW_DATA_DIR . '/config.php';
const XSW_LOG_FILE = XSW_DATA_DIR . '/logs.php';
const XSW_LOGIN_ATTEMPTS_FILE = XSW_DATA_DIR . '/login-attempts.php';
const XSW_SESSION_TTL = 43200;
const XSW_FIREWALL_SESSION_DIR = XSW_DATA_DIR . '/firewall-sessions';

if (!defined('XSW_INTERNAL')) {
    define('XSW_INTERNAL', true);
}

function xsw_bootstrap(): void
{
    xsw_configure_session();
    if (!is_dir(XSW_DATA_DIR)) {
        mkdir(XSW_DATA_DIR, 0700, true);
    }
    if (!is_dir(XSW_SECRET_DIR)) {
        mkdir(XSW_SECRET_DIR, 0700, true);
    }
    if (!is_dir(XSW_FIREWALL_SESSION_DIR)) {
        mkdir(XSW_FIREWALL_SESSION_DIR, 0700, true);
    }
    if (!is_file(XSW_LOG_FILE)) {
        file_put_contents(XSW_LOG_FILE, "<?php http_response_code(404); exit; ?>\n");
        @chmod(XSW_LOG_FILE, 0600);
    }
    if (!is_file(XSW_STATE_FILE)) {
        xsw_save_state(xsw_default_state());
    }
}

function xsw_configure_session(): void
{
    if (PHP_SAPI === 'cli' || headers_sent() || session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    @ini_set('session.gc_maxlifetime', (string)XSW_SESSION_TTL);
    @ini_set('session.cookie_lifetime', (string)XSW_SESSION_TTL);
    $params = session_get_cookie_params();
    session_set_cookie_params([
        'lifetime' => XSW_SESSION_TTL,
        'path' => $params['path'] ?: '/',
        'domain' => $params['domain'] ?? '',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function xsw_refresh_session_cookie(): void
{
    if (PHP_SAPI === 'cli' || headers_sent() || session_status() !== PHP_SESSION_ACTIVE || session_id() === '') {
        return;
    }
    $params = session_get_cookie_params();
    setcookie(session_name(), session_id(), [
        'expires' => time() + XSW_SESSION_TTL,
        'path' => $params['path'] ?: '/',
        'domain' => $params['domain'] ?? '',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function xsw_default_state(): array
{
    return [
        'version' => XSW_VERSION,
        'servers' => [],
        'lines' => [],
        'settings' => [
            'entry_port' => 33000,
            'base_port' => 33100,
            'verify_tls' => false,
            'reality_auto_target' => true,
            'reality_candidates' => [
                'www.microsoft.com',
                'www.apple.com',
                'www.cloudflare.com',
                'www.amazon.com',
                'www.mozilla.org',
            ],
            'reality_sni' => 'www.cloudflare.com',
            'reality_dest' => 'www.cloudflare.com:443',
            'reality_fingerprint' => 'chrome',
            'reality_spider_x' => '/',
            'ws_path_prefix' => '/xsw',
        ],
        'scheduler' => [
            'enabled' => false,
            'active_line_id' => '',
            'last_switch_at' => 0,
            'next_switch_at' => 0,
        ],
        'managed' => [
            'entry_uuid' => '',
            'entries' => [],
            'links' => [],
        ],
        'standalone' => [
            'entries' => [],
        ],
        'firewall' => [
            'active_session_id' => '',
            'sessions' => [],
            'reads' => [],
            'applies' => [],
            'policy' => [
                'enabled' => true,
                'deny_ping' => false,
                'rules' => [],
                'persist' => true,
            ],
        ],
        'last_results' => [],
        'jobs' => [],
    ];
}

function xsw_load_config(): array
{
    if (!is_file(XSW_CONFIG_FILE)) {
        return ['password_hash' => ''];
    }
    $config = include XSW_CONFIG_FILE;
    return is_array($config) ? $config : ['password_hash' => ''];
}

function xsw_save_config(array $config): void
{
    unset($config['app_secret']);
    $body = "<?php\nif (!defined('XSW_INTERNAL')) { http_response_code(404); exit; }\nreturn " . var_export($config, true) . ";\n";
    file_put_contents(XSW_CONFIG_FILE, $body, LOCK_EX);
    @chmod(XSW_CONFIG_FILE, 0600);
}

function xsw_login_attempts_load(): array
{
    if (!is_file(XSW_LOGIN_ATTEMPTS_FILE)) {
        return [];
    }
    $rows = include XSW_LOGIN_ATTEMPTS_FILE;
    return is_array($rows) ? $rows : [];
}

function xsw_login_attempts_save(array $rows): void
{
    if (!is_dir(XSW_DATA_DIR)) {
        mkdir(XSW_DATA_DIR, 0700, true);
    }
    $body = "<?php\nif (!defined('XSW_INTERNAL')) { http_response_code(404); exit; }\nreturn " . var_export($rows, true) . ";\n";
    file_put_contents(XSW_LOGIN_ATTEMPTS_FILE, $body, LOCK_EX);
    @chmod(XSW_LOGIN_ATTEMPTS_FILE, 0600);
}

function xsw_client_ip(): string
{
    return preg_replace('/[^0-9a-fA-F:.]/', '', (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown')) ?: 'unknown';
}

function xsw_login_attempt_key(): string
{
    return hash('sha256', xsw_client_ip() . '|' . (string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
}

function xsw_login_lock_seconds(): int
{
    $rows = xsw_login_attempts_load();
    $key = xsw_login_attempt_key();
    $row = $rows[$key] ?? [];
    $lockedUntil = (int)($row['locked_until'] ?? 0);
    return max(0, $lockedUntil - time());
}

function xsw_record_login_failure(): void
{
    $now = time();
    $rows = xsw_login_attempts_load();
    foreach ($rows as $key => $row) {
        if ((int)($row['last_at'] ?? 0) < $now - 86400) {
            unset($rows[$key]);
        }
    }
    $key = xsw_login_attempt_key();
    $row = $rows[$key] ?? ['count' => 0, 'first_at' => $now, 'last_at' => 0, 'locked_until' => 0];
    if ((int)($row['first_at'] ?? 0) < $now - 900) {
        $row = ['count' => 0, 'first_at' => $now, 'last_at' => 0, 'locked_until' => 0];
    }
    $row['count'] = (int)($row['count'] ?? 0) + 1;
    $row['last_at'] = $now;
    if ($row['count'] >= 8) {
        $row['locked_until'] = $now + 900;
    }
    $rows[$key] = $row;
    xsw_login_attempts_save($rows);
}

function xsw_clear_login_failures(): void
{
    $rows = xsw_login_attempts_load();
    $key = xsw_login_attempt_key();
    unset($rows[$key]);
    xsw_login_attempts_save($rows);
}

function xsw_require_login(): void
{
    if (PHP_SAPI === 'cli') {
        return;
    }
    xsw_configure_session();
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $config = xsw_load_config();
    if (empty($config['password_hash'])) {
        http_response_code(503);
        echo 'The panel is not initialized. Run: sudo bash install.sh';
        exit;
    }
    if (!empty($_SESSION['xsw_ok'])) {
        $_SESSION['xsw_seen_at'] = time();
        xsw_refresh_session_cookie();
        return;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
        $locked = xsw_login_lock_seconds();
        if ($locked > 0) {
            $GLOBALS['xsw_login_error'] = '登录失败次数过多，请 ' . max(1, (int)ceil($locked / 60)) . ' 分钟后再试';
            return;
        }
        $password = (string)($_POST['password'] ?? '');
        if (password_verify($password, (string)$config['password_hash'])) {
            xsw_clear_login_failures();
            $_SESSION['xsw_ok'] = true;
            $_SESSION['xsw_seen_at'] = time();
            xsw_refresh_session_cookie();
            header('Location: ' . strtok((string)$_SERVER['REQUEST_URI'], '?'));
            exit;
        }
        xsw_record_login_failure();
        $GLOBALS['xsw_login_error'] = '密码不对';
        return;
    }
    xsw_render_login();
    exit;
}

function xsw_render_login(): void
{
    $error = $GLOBALS['xsw_login_error'] ?? '';
    ?><!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>3x-ui Network Panel</title>
  <style>
    :root { color-scheme: light; --ink:#111827; --muted:#5b6472; --line:#d7dde5; --bg:#f4f6f8; --panel:#fff; --primary:#1f4e79; --red:#b42318; }
    * { box-sizing: border-box; }
    html { -webkit-text-size-adjust:100%; text-size-adjust:100%; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:var(--bg); color:var(--ink); }
    main { width:min(420px, calc(100vw - 32px)); background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:28px; box-shadow:0 18px 50px rgba(17,24,39,.10); }
    h1 { margin:0 0 18px; font-size:22px; letter-spacing:0; }
    label { display:block; font-size:13px; color:var(--muted); margin-bottom:7px; }
    input { width:100%; height:44px; border:1px solid var(--line); border-radius:6px; padding:0 12px; font-size:16px; }
    button { width:100%; height:42px; border:0; border-radius:6px; margin-top:16px; background:var(--primary); color:#fff; font-weight:700; cursor:pointer; touch-action:manipulation; -webkit-tap-highlight-color:transparent; }
    @media (max-width: 980px) { input, button { font-size:16px; } }
    .error { color:var(--red); margin:12px 0 0; font-size:14px; }
  </style>
</head>
<body>
<main>
  <h1>3x-ui Network Panel</h1>
  <form method="post">
    <input type="hidden" name="action" value="login">
    <label for="password">管理密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus>
    <button type="submit">进入</button>
    <?php if ($error): ?><p class="error"><?= xsw_h($error) ?></p><?php endif; ?>
  </form>
</main>
</body>
</html><?php
}

function xsw_h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function xsw_load_state(): array
{
    xsw_bootstrap();
    $state = include XSW_STATE_FILE;
    $default = xsw_default_state();
    if (!is_array($state)) {
        return $default;
    }
    return array_replace_recursive($default, $state);
}

function xsw_save_state(array $state): void
{
    if (!is_dir(XSW_DATA_DIR)) {
        mkdir(XSW_DATA_DIR, 0700, true);
    }
    $state['version'] = XSW_VERSION;
    $body = "<?php\nif (!defined('XSW_INTERNAL')) { http_response_code(404); exit; }\nreturn " . var_export($state, true) . ";\n";
    file_put_contents(XSW_STATE_FILE, $body, LOCK_EX);
    @chmod(XSW_STATE_FILE, 0600);
}

function xsw_log(string $level, string $message, array $context = []): void
{
    xsw_bootstrap();
    $row = [
        'id' => 'log_' . date('YmdHis') . '_' . bin2hex(random_bytes(3)),
        'ts' => date('c'),
        'level' => $level,
        'message' => $message,
        'context' => $context,
        'read_at' => 0,
    ];
    file_put_contents(XSW_LOG_FILE, json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
}

function xsw_log_header(): string
{
    return "<?php http_response_code(404); exit; ?>\n";
}

function xsw_normalize_log_row(array $row, int $index): array
{
    if (empty($row['id'])) {
        $row['id'] = 'log_' . substr(sha1(json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . '|' . $index), 0, 16);
    }
    $row['read_at'] = (int)($row['read_at'] ?? 0);
    return $row;
}

function xsw_read_log_rows(): array
{
    if (!is_file(XSW_LOG_FILE)) {
        return [];
    }
    $lines = file(XSW_LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) {
        return [];
    }
    $rows = [];
    $index = 0;
    foreach ($lines as $line) {
        if (str_starts_with($line, '<?php')) {
            continue;
        }
        $decoded = json_decode($line, true);
        if (is_array($decoded)) {
            $rows[] = xsw_normalize_log_row($decoded, $index);
        }
        $index++;
    }
    return $rows;
}

function xsw_write_log_rows(array $rows): void
{
    if (!is_dir(XSW_DATA_DIR)) {
        mkdir(XSW_DATA_DIR, 0700, true);
    }
    $body = xsw_log_header();
    foreach (array_values($rows) as $index => $row) {
        if (!is_array($row)) {
            continue;
        }
        $body .= json_encode(xsw_normalize_log_row($row, $index), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    }
    file_put_contents(XSW_LOG_FILE, $body, LOCK_EX);
    @chmod(XSW_LOG_FILE, 0600);
}

function xsw_recent_logs(int $limit = 80): array
{
    $rows = xsw_read_log_rows();
    if (!$rows) {
        return [];
    }
    $rows = array_slice($rows, -$limit);
    return array_reverse($rows);
}

function xsw_log_stats(): array
{
    $rows = xsw_read_log_rows();
    $unread = 0;
    foreach ($rows as $row) {
        if (empty($row['read_at'])) {
            $unread++;
        }
    }
    return ['total' => count($rows), 'unread' => $unread];
}

function xsw_mark_all_logs_read(): int
{
    $rows = xsw_read_log_rows();
    $now = time();
    $changed = 0;
    foreach ($rows as &$row) {
        if (empty($row['read_at'])) {
            $row['read_at'] = $now;
            $changed++;
        }
    }
    unset($row);
    xsw_write_log_rows($rows);
    return $changed;
}

function xsw_set_log_read(string $logId, bool $read): void
{
    $rows = xsw_read_log_rows();
    foreach ($rows as &$row) {
        if ((string)($row['id'] ?? '') === $logId) {
            $row['read_at'] = $read ? time() : 0;
            xsw_write_log_rows($rows);
            return;
        }
    }
    unset($row);
    throw new RuntimeException('找不到日志：' . $logId);
}

function xsw_delete_log(string $logId): void
{
    $rows = xsw_read_log_rows();
    $next = array_values(array_filter($rows, fn($row) => (string)($row['id'] ?? '') !== $logId));
    if (count($next) === count($rows)) {
        throw new RuntimeException('找不到日志：' . $logId);
    }
    xsw_write_log_rows($next);
}

function xsw_delete_read_logs(): int
{
    $rows = xsw_read_log_rows();
    $next = array_values(array_filter($rows, fn($row) => empty($row['read_at'])));
    xsw_write_log_rows($next);
    return count($rows) - count($next);
}

function xsw_clear_logs(): int
{
    $rows = xsw_read_log_rows();
    xsw_write_log_rows([]);
    return count($rows);
}

function xsw_uuid(): string
{
    $data = random_bytes(16);
    $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
    $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function xsw_normalize_server(array $input): array
{
    $code = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', trim((string)($input['code'] ?? ''))));
    $name = trim((string)($input['name'] ?? ''));
    $accessUrl = rtrim(trim((string)($input['access_url'] ?? '')), '/');
    $token = trim((string)($input['api_token'] ?? ''));
    $proxyHost = trim((string)($input['proxy_host'] ?? ''));

    if ($code === '') {
        throw new RuntimeException('资源编号不能为空');
    }
    if ($accessUrl === '') {
        throw new RuntimeException("资源 {$code} 缺少 Access URL");
    }
    $parts = parse_url($accessUrl);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
        throw new RuntimeException("资源 {$code} 的 Access URL 不正确");
    }
    if (!in_array(strtolower((string)$parts['scheme']), ['http', 'https'], true)) {
        throw new RuntimeException("资源 {$code} 的 Access URL 只能是 http 或 https");
    }
    if ($token === '') {
        throw new RuntimeException("资源 {$code} 缺少 API Token");
    }
    if ($proxyHost === '') {
        $proxyHost = (string)$parts['host'];
    }

    return [
        'code' => $code,
        'name' => $name !== '' ? $name : $code,
        'access_url' => $accessUrl,
        'api_token' => $token,
        'proxy_host' => $proxyHost,
    ];
}

function xsw_clean_ssh_host(string $host): string
{
    $host = trim($host);
    if ($host === '' || !preg_match('/^[A-Za-z0-9.\-:\[\]]+$/', $host)) {
        throw new RuntimeException('SSH 主机不正确');
    }
    return trim($host, '[]');
}

function xsw_job_secret_file(string $jobId): string
{
    $safe = preg_replace('/[^A-Za-z0-9_-]/', '', $jobId);
    if ($safe === '') {
        throw new RuntimeException('任务ID不正确');
    }
    return XSW_SECRET_DIR . '/' . $safe . '.php';
}

function xsw_save_job_secret(string $jobId, array $secret): void
{
    if (!is_dir(XSW_SECRET_DIR)) {
        mkdir(XSW_SECRET_DIR, 0700, true);
    }
    $body = "<?php\nreturn " . var_export($secret, true) . ";\n";
    file_put_contents(xsw_job_secret_file($jobId), $body, LOCK_EX);
    @chmod(xsw_job_secret_file($jobId), 0600);
}

function xsw_load_job_secret(string $jobId): array
{
    $file = xsw_job_secret_file($jobId);
    if (!is_file($file)) {
        return [];
    }
    $secret = include $file;
    return is_array($secret) ? $secret : [];
}

function xsw_delete_job_secret(string $jobId): void
{
    $file = xsw_job_secret_file($jobId);
    if (is_file($file)) {
        @unlink($file);
    }
}

function xsw_firewall_session_file(string $sessionId): string
{
    $safe = preg_replace('/[^A-Za-z0-9_-]/', '', $sessionId);
    if ($safe === '') {
        throw new RuntimeException('防火墙管理会话不正确');
    }
    return XSW_FIREWALL_SESSION_DIR . '/' . $safe . '.php';
}

function xsw_firewall_session_id(string $host, int $sshPort, string $sshUser): string
{
    return 'fw_' . substr(hash('sha256', strtolower($sshUser . '@' . $host . ':' . $sshPort)), 0, 18);
}

function xsw_ensure_firewall_state(array &$state): void
{
    if (!isset($state['firewall']) || !is_array($state['firewall'])) {
        $state['firewall'] = [];
    }
    foreach (['sessions', 'reads', 'applies'] as $key) {
        if (!isset($state['firewall'][$key]) || !is_array($state['firewall'][$key])) {
            $state['firewall'][$key] = [];
        }
    }
    if (!isset($state['firewall']['active_session_id']) || !is_string($state['firewall']['active_session_id'])) {
        $state['firewall']['active_session_id'] = '';
    }
    if (!isset($state['firewall']['policy']) || !is_array($state['firewall']['policy'])) {
        $state['firewall']['policy'] = xsw_firewall_default_policy();
    }
    $state['firewall']['policy'] = xsw_normalize_firewall_policy($state['firewall']['policy']);
    foreach ($state['firewall']['sessions'] as $sessionId => $session) {
        if (!is_array($session)) {
            unset($state['firewall']['sessions'][$sessionId]);
            continue;
        }
        if (isset($session['policy']) && is_array($session['policy'])) {
            $state['firewall']['sessions'][$sessionId]['policy'] = xsw_normalize_firewall_policy($session['policy']);
        }
    }
    foreach ($state['firewall']['applies'] as $sessionId => $apply) {
        if (isset($apply['payload']) && is_array($apply['payload'])) {
            $state['firewall']['applies'][$sessionId]['payload'] = xsw_normalize_firewall_policy($apply['payload']);
        }
    }
    $activeId = preg_replace('/[^A-Za-z0-9_-]/', '', $state['firewall']['active_session_id']);
    if ($activeId === '' || !isset($state['firewall']['sessions'][$activeId]) || !xsw_firewall_session_has_secret($activeId)) {
        $state['firewall']['active_session_id'] = '';
    } else {
        $state['firewall']['active_session_id'] = $activeId;
    }
}

function xsw_firewall_default_policy(): array
{
    return [
        'enabled' => true,
        'deny_ping' => false,
        'rules' => [],
        'persist' => true,
    ];
}

function xsw_normalize_firewall_policy(array $policy): array
{
    return [
        'enabled' => array_key_exists('enabled', $policy) ? (bool)$policy['enabled'] : true,
        'deny_ping' => !empty($policy['deny_ping']),
        'rules' => xsw_firewall_rules_from_policy($policy),
        'persist' => array_key_exists('persist', $policy) ? (bool)$policy['persist'] : true,
    ];
}

function xsw_firewall_policy_for_session(array $state, string $sessionId): array
{
    $sessionId = preg_replace('/[^A-Za-z0-9_-]/', '', $sessionId);
    $firewall = is_array($state['firewall'] ?? null) ? $state['firewall'] : [];
    $sessions = is_array($firewall['sessions'] ?? null) ? $firewall['sessions'] : [];
    if ($sessionId !== '' && isset($sessions[$sessionId]['policy']) && is_array($sessions[$sessionId]['policy'])) {
        return xsw_normalize_firewall_policy($sessions[$sessionId]['policy']);
    }
    $applies = is_array($firewall['applies'] ?? null) ? $firewall['applies'] : [];
    if ($sessionId !== '' && isset($applies[$sessionId]['payload']) && is_array($applies[$sessionId]['payload'])) {
        return xsw_normalize_firewall_policy($applies[$sessionId]['payload']);
    }
    return xsw_firewall_default_policy();
}

function xsw_firewall_session_has_secret(string $sessionId): bool
{
    return is_file(xsw_firewall_session_file($sessionId));
}

function xsw_save_firewall_session_secret(string $sessionId, array $secret): void
{
    if (!is_dir(XSW_FIREWALL_SESSION_DIR)) {
        mkdir(XSW_FIREWALL_SESSION_DIR, 0700, true);
    }
    $body = "<?php\nreturn " . var_export($secret, true) . ";\n";
    file_put_contents(xsw_firewall_session_file($sessionId), $body, LOCK_EX);
    @chmod(xsw_firewall_session_file($sessionId), 0600);
}

function xsw_load_firewall_session_secret(string $sessionId): array
{
    $file = xsw_firewall_session_file($sessionId);
    if (!is_file($file)) {
        return [];
    }
    $secret = include $file;
    return is_array($secret) ? $secret : [];
}

function xsw_delete_firewall_session_secret(string $sessionId): void
{
    $file = xsw_firewall_session_file($sessionId);
    if (is_file($file)) {
        @unlink($file);
    }
}

function xsw_upsert_firewall_session(array &$state, string $host, int $sshPort, string $sshUser, array $secret, string $label = ''): array
{
    xsw_ensure_firewall_state($state);
    $host = xsw_clean_ssh_host($host);
    $sshPort = max(1, min(65535, $sshPort));
    $sshUser = preg_replace('/[^A-Za-z0-9_.-]/', '', $sshUser);
    if ($sshUser === '') {
        throw new RuntimeException('SSH 用户名不正确');
    }
    $normalizedSecret = [
        'ssh_password' => (string)($secret['ssh_password'] ?? ''),
        'ssh_private_key' => xsw_normalize_ssh_private_key((string)($secret['ssh_private_key'] ?? '')),
    ];
    if (trim($normalizedSecret['ssh_password']) === '' && $normalizedSecret['ssh_private_key'] === '') {
        throw new RuntimeException('请填写 SSH 密码或私钥');
    }
    $verified = false;
    if (xsw_process_available()) {
        xsw_verify_ssh_secret($host, $sshPort, $sshUser, $normalizedSecret);
        $verified = true;
    }
    $id = xsw_firewall_session_id($host, $sshPort, $sshUser);
    $now = time();
    $current = is_array($state['firewall']['sessions'][$id] ?? null) ? $state['firewall']['sessions'][$id] : [];
    $session = array_replace($current, [
        'id' => $id,
        'label' => trim($label) !== '' ? trim($label) : $host,
        'host' => $host,
        'ssh_port' => $sshPort,
        'ssh_user' => $sshUser,
        'created_at' => (int)($current['created_at'] ?? $now),
        'last_used_at' => $now,
        'last_status' => $verified ? '已接入' : '待后台校验',
        'updated_at' => $now,
    ]);
    $state['firewall']['sessions'][$id] = $session;
    xsw_save_firewall_session_secret($id, $normalizedSecret);
    xsw_save_state($state);
    if (!$verified) {
        xsw_enqueue_unique_firewall_verify_job($state, $session, $normalizedSecret);
    }
    xsw_log('info', '接入防火墙管理', ['host' => $host, 'session' => $id]);
    return $session;
}

function xsw_enqueue_unique_firewall_verify_job(array &$state, array $session, array $secret): ?array
{
    $sessionId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($session['id'] ?? ''));
    if ($sessionId === '') {
        return null;
    }
    if (trim((string)($secret['ssh_password'] ?? '')) === '' && xsw_normalize_ssh_private_key((string)($secret['ssh_private_key'] ?? '')) === '') {
        return null;
    }
    foreach (($state['jobs'] ?? []) as $job) {
        if (($job['type'] ?? '') !== 'verify_firewall_ssh' || !in_array((string)($job['status'] ?? ''), ['pending', 'running'], true)) {
            continue;
        }
        $payload = is_array($job['payload'] ?? null) ? $job['payload'] : [];
        if (preg_replace('/[^A-Za-z0-9_-]/', '', (string)($payload['session_id'] ?? '')) === $sessionId) {
            return $job;
        }
    }
    $job = xsw_enqueue_job($state, 'verify_firewall_ssh', xsw_firewall_payload_from_session($session));
    xsw_save_job_secret((string)$job['id'], [
        'ssh_password' => (string)($secret['ssh_password'] ?? ''),
        'ssh_private_key' => xsw_normalize_ssh_private_key((string)($secret['ssh_private_key'] ?? '')),
    ]);
    return $job;
}

function xsw_ensure_pending_firewall_verify_jobs(array &$state): int
{
    xsw_ensure_firewall_state($state);
    $created = 0;
    foreach (($state['firewall']['sessions'] ?? []) as $sessionId => $session) {
        if (!is_array($session) || (string)($session['last_status'] ?? '') !== '待后台校验') {
            continue;
        }
        if (!xsw_firewall_session_has_secret((string)$sessionId)) {
            continue;
        }
        $job = xsw_enqueue_unique_firewall_verify_job($state, $session, xsw_load_firewall_session_secret((string)$sessionId));
        if ($job !== null) {
            $created++;
        }
    }
    return $created;
}

function xsw_firewall_selected_ids(array $rawIds): array
{
    $ids = [];
    foreach ($rawIds as $id) {
        $safe = preg_replace('/[^A-Za-z0-9_-]/', '', (string)$id);
        if ($safe !== '') {
            $ids[] = $safe;
        }
    }
    return array_values(array_unique($ids));
}

function xsw_firewall_selected_sessions(array $state, array $ids): array
{
    $sessions = [];
    $firewall = is_array($state['firewall'] ?? null) ? $state['firewall'] : [];
    $known = is_array($firewall['sessions'] ?? null) ? $firewall['sessions'] : [];
    foreach (xsw_firewall_selected_ids($ids) as $id) {
        if (!isset($known[$id]) || !is_array($known[$id])) {
            continue;
        }
        if (!xsw_firewall_session_has_secret($id)) {
            throw new RuntimeException('服务器 ' . (string)($known[$id]['host'] ?? $id) . ' 的 SSH 凭据已失效，请重新接入');
        }
        $sessions[] = $known[$id];
    }
    if (!$sessions) {
        throw new RuntimeException('请选择要管理的服务器');
    }
    return $sessions;
}

function xsw_forget_firewall_sessions(array &$state, array $ids): int
{
    xsw_ensure_firewall_state($state);
    $count = 0;
    foreach (xsw_firewall_selected_ids($ids) as $id) {
        if (isset($state['firewall']['sessions'][$id])) {
            unset($state['firewall']['sessions'][$id], $state['firewall']['reads'][$id], $state['firewall']['applies'][$id]);
            $count++;
        }
        xsw_delete_firewall_session_secret($id);
        if ((string)($state['firewall']['active_session_id'] ?? '') === $id) {
            $state['firewall']['active_session_id'] = '';
        }
    }
    xsw_save_state($state);
    if ($count > 0) {
        xsw_log('info', '退出防火墙管理', ['count' => $count]);
    }
    return $count;
}

function xsw_firewall_payload_from_session(array $session, array $extra = []): array
{
    return array_merge([
        'session_id' => (string)($session['id'] ?? ''),
        'host' => (string)($session['host'] ?? ''),
        'ssh_port' => (int)($session['ssh_port'] ?? 22),
        'ssh_user' => (string)($session['ssh_user'] ?? 'root'),
    ], $extra);
}

function xsw_server_host(array $server): string
{
    $host = trim((string)($server['proxy_host'] ?? ''));
    if ($host !== '') {
        return $host;
    }
    $parts = parse_url((string)($server['access_url'] ?? ''));
    return is_array($parts) ? (string)($parts['host'] ?? '') : '';
}

function xsw_server_ip_tail(array $server): string
{
    $host = xsw_server_host($server);
    if ($host === '') {
        return '';
    }
    if (preg_match('/(\d{1,3})$/', $host, $match)) {
        return $match[1];
    }
    $host = trim($host, '[]');
    $parts = preg_split('/[.\-:]+/', $host);
    if (!$parts) {
        return '';
    }
    return (string)end($parts);
}

function xsw_server_label(array $server): string
{
    $code = (string)($server['code'] ?? '');
    $name = (string)($server['name'] ?? $code);
    $tail = xsw_server_ip_tail($server);
    return trim($code . ' · ' . $name . ($tail !== '' ? ' · ' . $tail : ''));
}

function xsw_ensure_standalone_state(array &$state): void
{
    if (!isset($state['standalone']) || !is_array($state['standalone'])) {
        $state['standalone'] = [];
    }
    if (!isset($state['standalone']['entries']) || !is_array($state['standalone']['entries'])) {
        $state['standalone']['entries'] = [];
    }
}

function xsw_next_standalone_id(array $entries): string
{
    $used = [];
    foreach ($entries as $entry) {
        $used[(string)($entry['id'] ?? '')] = true;
    }
    for ($i = 1; $i < 1000; $i++) {
        $id = 'single' . $i;
        if (empty($used[$id])) {
            return $id;
        }
    }
    return 'single' . time();
}

function xsw_next_standalone_port(array $state): int
{
    xsw_ensure_standalone_state($state);
    $used = [];
    foreach (($state['standalone']['entries'] ?? []) as $entry) {
        $port = (int)($entry['port'] ?? 0);
        if ($port > 0) {
            $used[$port] = true;
        }
    }
    foreach (($state['managed']['entries'] ?? []) as $entry) {
        $port = (int)($entry['port'] ?? 0);
        if ($port > 0) {
            $used[$port] = true;
        }
    }
    foreach (($state['managed']['links'] ?? []) as $link) {
        $port = (int)($link['port'] ?? 0);
        if ($port > 0) {
            $used[$port] = true;
        }
    }
    for ($port = 36000; $port <= 65535; $port++) {
        if (empty($used[$port])) {
            return $port;
        }
    }
    throw new RuntimeException('没有可用的单节点入口端口');
}

function xsw_standalone_remark(array $entry): string
{
    if (!empty($entry['remark'])) {
        return (string)$entry['remark'];
    }
    return trim((string)($entry['name'] ?? $entry['id'] ?? 'entry'));
}

function xsw_new_standalone_remark(array $entry): string
{
    $name = trim((string)($entry['name'] ?? 'entry'));
    $id = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($entry['id'] ?? ''));
    return ($name !== '' ? $name : 'entry') . ($id !== '' ? ' · ' . $id : '');
}

function xsw_standalone_delete_remarks(array $entry): array
{
    $name = trim((string)($entry['name'] ?? $entry['id'] ?? 'entry'));
    return array_values(array_unique(array_filter([
        xsw_standalone_remark($entry),
        $name,
        'JD Single ' . $name,
        'XSW Single ' . $name,
    ])));
}

function xsw_code_from_index(int $index): string
{
    $letters = range('A', 'Z');
    if ($index < count($letters)) {
        return $letters[$index];
    }
    return 'S' . ($index + 1);
}

function xsw_next_server_code(array $servers): string
{
    $used = [];
    foreach ($servers as $code => $server) {
        $used[strtoupper((string)($server['code'] ?? $code))] = true;
    }
    for ($i = 0; $i < 26; $i++) {
        $code = xsw_code_from_index($i);
        if (empty($used[$code])) {
            return $code;
        }
    }
    for ($i = 1; $i < 1000; $i++) {
        $code = 'S' . $i;
        if (empty($used[$code])) {
            return $code;
        }
    }
    return 'S' . time();
}

function xsw_parse_3xui_import(string $text, array $existingServers = []): array
{
    $blocks = [];
    $current = null;
    foreach (preg_split('/\R/u', trim($text)) as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        if (preg_match('/^([A-Za-z ]+):\s*(.*)$/u', $line, $match)) {
            if ($current === null) {
                $current = ['name' => 'server', 'fields' => []];
            }
            $key = strtolower(str_replace(' ', '', trim($match[1])));
            $current['fields'][$key] = trim($match[2]);
            continue;
        }
        if ($current !== null && (!empty($current['fields']['accessurl']) || !empty($current['fields']['apitoken']))) {
            $blocks[] = $current;
        }
        $current = ['name' => $line, 'fields' => []];
    }
    if ($current !== null && (!empty($current['fields']['accessurl']) || !empty($current['fields']['apitoken']))) {
        $blocks[] = $current;
    }

    $servers = [];
    foreach ($blocks as $block) {
        $fields = $block['fields'] ?? [];
        $accessUrl = rtrim((string)($fields['accessurl'] ?? ''), '/');
        $token = (string)($fields['apitoken'] ?? '');
        if ($accessUrl === '' || $token === '') {
            throw new RuntimeException('导入失败：' . ($block['name'] ?? 'server') . ' 缺少 Access URL 或 API Token');
        }
        $code = '';
        foreach ($existingServers as $existingCode => $existingServer) {
            if (rtrim((string)($existingServer['access_url'] ?? ''), '/') === $accessUrl) {
                $code = strtoupper((string)($existingServer['code'] ?? $existingCode));
                break;
            }
        }
        if ($code === '') {
            $code = xsw_next_server_code($existingServers + $servers);
        }
        $host = '';
        $parts = parse_url($accessUrl);
        if (is_array($parts) && !empty($parts['host'])) {
            $host = (string)$parts['host'];
        }
        $server = xsw_normalize_server([
            'code' => $code,
            'name' => (string)($block['name'] ?? $code),
            'access_url' => $accessUrl,
            'api_token' => $token,
            'proxy_host' => $host,
        ]);
        $servers[$server['code']] = $server;
    }
    if (!$servers) {
        throw new RuntimeException('没有识别到资源。需要包含 Access URL: 和 API Token:');
    }
    return $servers;
}

function xsw_codes_from_path_text(string $pathText): array
{
    return array_values(array_filter(array_map(
        fn($item) => strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', trim($item))),
        preg_split('/\s*>\s*/', trim($pathText))
    )));
}

function xsw_server_usage(array $state, string $code): array
{
    $code = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', $code));
    $usage = [];
    foreach (($state['lines'] ?? []) as $line) {
        if (in_array($code, $line['path'] ?? [], true)) {
            $usage[] = '链路 ' . (string)($line['name'] ?? $line['id'] ?? $code);
        }
    }
    foreach (($state['standalone']['entries'] ?? []) as $entry) {
        if (strtoupper((string)($entry['server'] ?? '')) === $code) {
            $usage[] = '单节点 ' . (string)($entry['name'] ?? $entry['id'] ?? $code);
        }
    }
    foreach (($state['jobs'] ?? []) as $job) {
        if (($job['status'] ?? '') !== 'pending') {
            continue;
        }
        $payload = $job['payload'] ?? [];
        if (!is_array($payload)) {
            continue;
        }
        if (!empty($payload['path']) && in_array($code, xsw_codes_from_path_text((string)$payload['path']), true)) {
            $usage[] = '计划 ' . (string)($job['id'] ?? '');
        }
        if (strtoupper((string)($payload['server'] ?? '')) === $code) {
            $usage[] = '计划 ' . (string)($job['id'] ?? '');
        }
    }
    return array_values(array_filter($usage));
}

function xsw_line_exists(array $state, string $lineId): bool
{
    foreach (($state['lines'] ?? []) as $line) {
        if ((string)($line['id'] ?? '') === $lineId) {
            return true;
        }
    }
    return false;
}

function xsw_line_delete_job(array $state, string $lineId): ?array
{
    foreach (($state['jobs'] ?? []) as $job) {
        if (($job['type'] ?? '') !== 'delete_line') {
            continue;
        }
        if (!in_array((string)($job['status'] ?? ''), ['pending', 'running'], true)) {
            continue;
        }
        $payload = is_array($job['payload'] ?? null) ? $job['payload'] : [];
        if ((string)($payload['line_id'] ?? '') === $lineId) {
            return $job;
        }
    }
    return null;
}

function xsw_parse_lines(string $text): array
{
    $lines = [];
    foreach (preg_split('/\R/u', trim($text)) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $parts = array_map('trim', explode('|', $line));
        if (count($parts) < 3) {
            throw new RuntimeException('链路格式需要：链路ID | 链路名称 | A>B>C>D');
        }
        [$id, $name, $pathText] = $parts;
        $id = strtolower(preg_replace('/[^A-Za-z0-9_-]/', '', $id));
        $path = xsw_codes_from_path_text($pathText);
        if ($id === '' || count($path) < 2) {
            throw new RuntimeException('链路ID不能为空，路径至少需要两台资源');
        }
        $lines[] = ['id' => $id, 'name' => $name !== '' ? $name : $id, 'path' => $path];
    }
    return $lines;
}

function xsw_lines_to_text(array $lines): string
{
    return implode("\n", array_map(
        fn($line) => implode(' | ', [$line['id'] ?? '', $line['name'] ?? '', implode('>', $line['path'] ?? [])]),
        $lines
    ));
}

function xsw_validate_topology(array $state): void
{
    $servers = $state['servers'];
    if (!$servers) {
        throw new RuntimeException('先填资源');
    }
    $lineIds = [];
    foreach ($state['lines'] as $line) {
        if (empty($line['id'])) {
            throw new RuntimeException('链路ID不能为空');
        }
        if (isset($lineIds[$line['id']])) {
            throw new RuntimeException('链路ID重复：' . $line['id']);
        }
        $lineIds[$line['id']] = true;
        if (count($line['path']) < 2) {
            throw new RuntimeException("链路 {$line['name']} 至少需要 2 台资源");
        }
        foreach ($line['path'] as $code) {
            if (!isset($servers[$code])) {
                throw new RuntimeException("链路 {$line['name']} 里找不到资源 {$code}");
            }
        }
    }
}

function xsw_build_plan(array &$state): array
{
    xsw_validate_topology($state);
    $settings = $state['settings'];
    $entryPort = (int)$settings['entry_port'];
    $basePort = (int)$settings['base_port'];
    if ($entryPort < 1 || $entryPort > 65535 || $basePort < 1 || $basePort > 65535) {
        throw new RuntimeException('端口范围不正确');
    }

    if (!isset($state['managed']['entries']) || !is_array($state['managed']['entries'])) {
        $state['managed']['entries'] = [];
    }
    if (!isset($state['managed']['links']) || !is_array($state['managed']['links'])) {
        $state['managed']['links'] = [];
    }

    $entries = [];
    $edges = [];
    $edgeIndex = 0;
    foreach ($state['lines'] as $lineIndex => $line) {
        $path = $line['path'];
        $lineId = $line['id'];
        if (empty($state['managed']['entries'][$lineId]['uuid'])) {
            $state['managed']['entries'][$lineId]['uuid'] = xsw_uuid();
        }
        if (empty($state['managed']['entries'][$lineId]['port'])) {
            $state['managed']['entries'][$lineId]['port'] = $entryPort + $lineIndex;
        }
        if (empty($state['managed']['entries'][$lineId]['short_id'])) {
            $state['managed']['entries'][$lineId]['short_id'] = xsw_random_hex(4);
        }
        if (empty($state['managed']['entries'][$lineId]['sni']) || empty($state['managed']['entries'][$lineId]['dest'])) {
            $target = xsw_select_reality_target($settings);
            $state['managed']['entries'][$lineId]['sni'] = $target['sni'];
            $state['managed']['entries'][$lineId]['dest'] = $target['dest'];
            $state['managed']['entries'][$lineId]['target_latency_ms'] = $target['latency_ms'];
        }
        if (empty($state['managed']['entries'][$lineId]['fingerprint'])) {
            $state['managed']['entries'][$lineId]['fingerprint'] = (string)($settings['reality_fingerprint'] ?? 'chrome');
        }
        if (!array_key_exists('spider_x', $state['managed']['entries'][$lineId])) {
            $state['managed']['entries'][$lineId]['spider_x'] = (string)($settings['reality_spider_x'] ?? '/');
        }
        $entryLinePort = (int)$state['managed']['entries'][$lineId]['port'];
        $entries[$lineId] = [
            'line_id' => $lineId,
            'line_name' => $line['name'],
            'server' => $path[0],
            'port' => $entryLinePort,
            'uuid' => $state['managed']['entries'][$lineId]['uuid'],
            'private_key' => $state['managed']['entries'][$lineId]['private_key'] ?? '',
            'public_key' => $state['managed']['entries'][$lineId]['public_key'] ?? '',
            'short_id' => $state['managed']['entries'][$lineId]['short_id'],
            'sni' => $state['managed']['entries'][$lineId]['sni'],
            'dest' => $state['managed']['entries'][$lineId]['dest'],
            'fingerprint' => $state['managed']['entries'][$lineId]['fingerprint'],
            'spider_x' => $state['managed']['entries'][$lineId]['spider_x'],
            'inbound_tag' => 'inbound-' . $entryLinePort,
            'remark' => $line['name'] . ' · entry',
        ];
        for ($i = 0; $i < count($path) - 1; $i++) {
            $from = $path[$i];
            $to = $path[$i + 1];
            $key = $line['id'] . ':' . $from . '>' . $to;
            if (empty($state['managed']['links'][$key]['uuid'])) {
                $state['managed']['links'][$key]['uuid'] = xsw_uuid();
            }
            if (empty($state['managed']['links'][$key]['port'])) {
                $state['managed']['links'][$key]['port'] = $basePort + $edgeIndex;
            }
            if (empty($state['managed']['links'][$key]['ws_path'])) {
                $prefix = '/' . trim((string)($settings['ws_path_prefix'] ?? '/xsw'), '/');
                $state['managed']['links'][$key]['ws_path'] = $prefix . '/' . $line['id'] . '/' . strtolower($from) . '-' . strtolower($to) . '-' . xsw_random_hex(3);
            }
            $port = (int)$state['managed']['links'][$key]['port'];
            if ($port === $entryLinePort) {
                throw new RuntimeException('入口端口和中继端口冲突');
            }
            $edges[$key] = [
                'key' => $key,
                'line_id' => $line['id'],
                'line_name' => $line['name'],
                'from' => $from,
                'to' => $to,
                'port' => $port,
                'uuid' => $state['managed']['links'][$key]['uuid'],
                'ws_path' => $state['managed']['links'][$key]['ws_path'],
                'inbound_tag' => 'inbound-' . $port,
                'outbound_tag' => xsw_tag('to_' . $line['id'] . '_' . $from . '_' . $to),
                'remark' => $line['name'] . ' · ' . $from . '→' . $to,
            ];
            $edgeIndex++;
        }
    }

    return ['entries' => $entries, 'entry' => reset($entries), 'edges' => $edges, 'lines' => $state['lines']];
}

function xsw_tag(string $raw): string
{
    return XSW_PREFIX . strtolower(preg_replace('/[^A-Za-z0-9_]+/', '_', $raw));
}

function xsw_is_managed_tag(string $tag): bool
{
    return str_starts_with($tag, XSW_PREFIX) || str_starts_with($tag, XSW_LEGACY_PREFIX);
}

function xsw_is_managed_remark(string $remark): bool
{
    return str_starts_with($remark, 'JD')
        || str_starts_with($remark, 'XSW')
        || preg_match('/ · (?:entry|single\d+)$/i', $remark) === 1
        || preg_match('/ · [A-Z0-9_-]+→[A-Z0-9_-]+$/u', $remark) === 1;
}

function xsw_random_hex(int $bytes): string
{
    return bin2hex(random_bytes($bytes));
}

function xsw_reality_candidate_hosts(array $settings): array
{
    $configured = is_array($settings['reality_candidates'] ?? null)
        ? $settings['reality_candidates']
        : [];
    $configured[] = (string)($settings['reality_sni'] ?? 'www.cloudflare.com');
    $hosts = [];
    foreach ($configured as $candidate) {
        $candidate = strtolower(trim((string)$candidate));
        $candidate = preg_replace('#^https?://#', '', $candidate);
        $candidate = preg_replace('#[:/].*$#', '', (string)$candidate);
        if ($candidate === '' || filter_var($candidate, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            continue;
        }
        $hosts[$candidate] = true;
    }
    return array_keys($hosts);
}

function xsw_probe_reality_candidate(string $host): ?float
{
    if (!function_exists('curl_init')) {
        return null;
    }
    $ch = curl_init('https://' . $host . '/');
    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT_MS => 1800,
        CURLOPT_TIMEOUT_MS => 3500,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; 3x-ui-network-panel/0.2)',
    ];
    if (defined('CURL_SSLVERSION_TLSv1_3')) {
        $options[CURLOPT_SSLVERSION] = CURL_SSLVERSION_TLSv1_3;
    }
    curl_setopt_array($ch, $options);
    $result = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $time = (float)curl_getinfo($ch, CURLINFO_APPCONNECT_TIME);
    if ($time <= 0) {
        $time = (float)curl_getinfo($ch, CURLINFO_CONNECT_TIME);
    }
    $error = curl_errno($ch);
    curl_close($ch);
    if ($result === false || $error !== 0 || $status === 0 || $time <= 0) {
        return null;
    }
    return $time;
}

function xsw_select_reality_target(array $settings): array
{
    $fallbackHost = strtolower(trim((string)($settings['reality_sni'] ?? 'www.cloudflare.com')));
    if (filter_var($fallbackHost, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        $fallbackHost = 'www.cloudflare.com';
    }
    if (empty($settings['reality_auto_target'])) {
        return ['sni' => $fallbackHost, 'dest' => $fallbackHost . ':443', 'latency_ms' => null];
    }

    $scores = [];
    foreach (xsw_reality_candidate_hosts($settings) as $host) {
        $score = xsw_probe_reality_candidate($host);
        if ($score !== null) {
            $scores[$host] = $score;
        }
    }
    if (!$scores) {
        return ['sni' => $fallbackHost, 'dest' => $fallbackHost . ':443', 'latency_ms' => null];
    }
    asort($scores, SORT_NUMERIC);
    $host = (string)array_key_first($scores);
    return [
        'sni' => $host,
        'dest' => $host . ':443',
        'latency_ms' => (int)round((float)$scores[$host] * 1000),
    ];
}

function xsw_client_email(string $prefix, string $identity, int $port): string
{
    $safe = strtolower(trim(preg_replace('/[^A-Za-z0-9_-]+/', '-', $identity), '-'));
    if ($safe === '') {
        $safe = 'client';
    }
    return substr($prefix . '-' . $safe . '-' . $port, 0, 64);
}

function xsw_public_host(array $server): string
{
    if (!empty($server['proxy_host'])) {
        return (string)$server['proxy_host'];
    }
    $parts = parse_url((string)$server['access_url']);
    if (!empty($parts['host'])) {
        return (string)$parts['host'];
    }
    return (string)$server['access_url'];
}

function xsw_api(array $server, string $method, string $endpoint, ?array $data = null, bool $form = false, int $timeout = 25): array
{
    $url = rtrim((string)$server['access_url'], '/') . '/' . ltrim($endpoint, '/');
    $ch = curl_init($url);
    $headers = [
        'Authorization: Bearer ' . (string)$server['api_token'],
        'Accept: application/json',
    ];
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
    ]);
    if ($data !== null) {
        if ($form) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        } else {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            $headers[] = 'Content-Type: application/json';
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    $body = curl_exec($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($body === false) {
        throw new RuntimeException('请求失败：' . $err);
    }
    $decoded = json_decode((string)$body, true);
    if (!is_array($decoded)) {
        throw new RuntimeException("HTTP {$code} 非 JSON 响应：" . substr((string)$body, 0, 180));
    }
    if ($code >= 400 || (array_key_exists('success', $decoded) && !$decoded['success'])) {
        $msg = $decoded['msg'] ?? ('HTTP ' . $code);
        throw new RuntimeException((string)$msg);
    }
    return $decoded;
}

function xsw_test_server(array $server): array
{
    $started = microtime(true);
    $res = xsw_api($server, 'GET', '/panel/api/server/status', null, false, 15);
    return [
        'ok' => true,
        'ms' => (int)round((microtime(true) - $started) * 1000),
        'summary' => $res['obj'] ?? $res,
    ];
}

function xsw_reality_keypair(array $server): array
{
    $res = xsw_api($server, 'GET', '/panel/api/server/getNewX25519Cert');
    $obj = xsw_decode_maybe($res['obj'] ?? []);
    if (!is_array($obj) || empty($obj['privateKey']) || empty($obj['publicKey'])) {
        throw new RuntimeException('Reality keypair generation failed');
    }
    return ['private_key' => (string)$obj['privateKey'], 'public_key' => (string)$obj['publicKey']];
}

function xsw_prepare_reality_entries(array &$state): void
{
    xsw_build_plan($state);
    foreach ($state['lines'] as $line) {
        $lineId = $line['id'];
        if (!empty($state['managed']['entries'][$lineId]['private_key']) && !empty($state['managed']['entries'][$lineId]['public_key'])) {
            continue;
        }
        $entryServer = $state['servers'][$line['path'][0]];
        $keys = xsw_reality_keypair($entryServer);
        $state['managed']['entries'][$lineId]['private_key'] = $keys['private_key'];
        $state['managed']['entries'][$lineId]['public_key'] = $keys['public_key'];
    }
}

function xsw_sniffing_settings(): array
{
    return [
        'enabled' => true,
        'destOverride' => ['http', 'tls', 'quic'],
        'metadataOnly' => false,
        'routeOnly' => true,
        'ipsExcluded' => [],
        'domainsExcluded' => [],
    ];
}

function xsw_vless_reality_inbound(array $entry): array
{
    return [
        'enable' => true,
        'remark' => $entry['remark'],
        'listen' => '',
        'port' => (int)$entry['port'],
        'protocol' => 'vless',
        'expiryTime' => 0,
        'total' => 0,
        'settings' => [
            'clients' => [[
                'id' => $entry['uuid'],
                'email' => xsw_client_email('xsw-entry', (string)$entry['line_id'], (int)$entry['port']),
                'flow' => 'xtls-rprx-vision',
                'enable' => true,
            ]],
            'decryption' => 'none',
            'fallbacks' => [],
        ],
        'streamSettings' => [
            'network' => 'tcp',
            'security' => 'reality',
            'tcpSettings' => ['header' => ['type' => 'none']],
            'realitySettings' => [
                'show' => false,
                'xver' => 0,
                'target' => $entry['dest'],
                'serverNames' => [$entry['sni']],
                'privateKey' => $entry['private_key'],
                'minClientVer' => '',
                'maxClientVer' => '',
                'maxTimediff' => 0,
                'shortIds' => [$entry['short_id']],
                'mldsa65Seed' => '',
                'settings' => [
                    'publicKey' => (string)($entry['public_key'] ?? ''),
                    'fingerprint' => (string)($entry['fingerprint'] ?? 'chrome'),
                    'serverName' => '',
                    'spiderX' => (string)($entry['spider_x'] ?? '/'),
                    'mldsa65Verify' => '',
                ],
            ],
        ],
        'sniffing' => xsw_sniffing_settings(),
    ];
}

function xsw_vmess_ws_inbound(int $port, string $uuid, string $remark, string $wsPath): array
{
    return [
        'enable' => true,
        'remark' => $remark,
        'listen' => '',
        'port' => $port,
        'protocol' => 'vmess',
        'expiryTime' => 0,
        'total' => 0,
        'settings' => [
            'clients' => [[
                'id' => $uuid,
                'alterId' => 0,
                'email' => xsw_client_email('xsw-relay', $remark, $port),
                'enable' => true,
            ]],
            'disableInsecureEncryption' => false,
        ],
        'streamSettings' => [
            'network' => 'ws',
            'security' => 'none',
            'wsSettings' => [
                'acceptProxyProtocol' => false,
                'path' => $wsPath,
                'host' => '',
                'headers' => (object)[],
            ],
        ],
        'sniffing' => xsw_sniffing_settings(),
    ];
}

function xsw_socks5_inbound(array $entry): array
{
    return [
        'enable' => true,
        'remark' => xsw_standalone_remark($entry),
        'listen' => '',
        'port' => (int)$entry['port'],
        'protocol' => 'mixed',
        'expiryTime' => 0,
        'total' => 0,
        'settings' => [
            'auth' => 'password',
            'accounts' => [[
                'user' => (string)$entry['username'],
                'pass' => (string)$entry['password'],
            ]],
            'udp' => false,
            'userLevel' => 0,
        ],
        'streamSettings' => [
            'network' => 'tcp',
            'security' => 'none',
            'tcpSettings' => ['header' => ['type' => 'none']],
        ],
        'sniffing' => xsw_sniffing_settings(),
    ];
}

function xsw_vmess_ws_outbound(string $tag, string $host, int $port, string $uuid, string $wsPath): array
{
    return [
        'tag' => $tag,
        'protocol' => 'vmess',
        'settings' => [
            'vnext' => [[
                'address' => $host,
                'port' => $port,
                'users' => [[
                    'id' => $uuid,
                    'alterId' => 0,
                    'security' => 'auto',
                ]],
            ]],
        ],
        'streamSettings' => [
            'network' => 'ws',
            'security' => 'none',
            'wsSettings' => [
                'path' => $wsPath,
                'headers' => ['Host' => $host],
            ],
        ],
    ];
}

function xsw_ensure_inbound(array $server, array $payload): string
{
    $list = xsw_api($server, 'GET', '/panel/api/inbounds/list');
    $items = $list['obj'] ?? [];
    if (!is_array($items)) {
        $items = [];
    }
    foreach ($items as $item) {
        $itemPort = (int)($item['port'] ?? 0);
        $itemRemark = (string)($item['remark'] ?? '');
        $itemId = (int)($item['id'] ?? 0);
        if ($itemPort === (int)$payload['port']) {
            if ($itemRemark !== (string)$payload['remark']) {
                if ($itemId > 0 && xsw_is_managed_remark($itemRemark) && xsw_is_managed_remark((string)$payload['remark'])) {
                    xsw_api($server, 'POST', '/panel/api/inbounds/update/' . $itemId, $payload);
                    return 'updated';
                }
                throw new RuntimeException("端口 {$payload['port']} 已被 {$itemRemark} 使用");
            }
            if ($itemId > 0) {
                xsw_api($server, 'POST', '/panel/api/inbounds/update/' . $itemId, $payload);
                return 'updated';
            }
            return 'exists';
        }
        if ($itemRemark === (string)$payload['remark']) {
            if ($itemId > 0) {
                xsw_api($server, 'POST', '/panel/api/inbounds/update/' . $itemId, $payload);
                return 'updated';
            }
            return 'exists';
        }
    }
    xsw_api($server, 'POST', '/panel/api/inbounds/add', $payload);
    return 'created';
}

function xsw_delete_inbound(array $server, int $port, string $remark): string
{
    $list = xsw_api($server, 'GET', '/panel/api/inbounds/list');
    $items = $list['obj'] ?? [];
    if (!is_array($items)) {
        $items = [];
    }
    foreach ($items as $item) {
        $itemId = (int)($item['id'] ?? 0);
        if ($itemId <= 0) {
            continue;
        }
        $itemPort = (int)($item['port'] ?? 0);
        $itemRemark = (string)($item['remark'] ?? '');
        if ($itemPort === $port && $itemRemark === $remark) {
            xsw_api($server, 'POST', '/panel/api/inbounds/del/' . $itemId);
            return 'deleted';
        }
    }
    foreach ($items as $item) {
        $itemId = (int)($item['id'] ?? 0);
        $itemRemark = (string)($item['remark'] ?? '');
        if ($itemId > 0 && $itemRemark === $remark) {
            xsw_api($server, 'POST', '/panel/api/inbounds/del/' . $itemId);
            return 'deleted_by_remark';
        }
    }
    return 'not_found';
}

function xsw_actual_inbound_tag(array $server, int $port, string $remark): string
{
    $list = xsw_api($server, 'GET', '/panel/api/inbounds/list');
    $items = $list['obj'] ?? [];
    if (!is_array($items)) {
        $items = [];
    }
    foreach ($items as $item) {
        $itemId = (int)($item['id'] ?? 0);
        $itemPort = (int)($item['port'] ?? 0);
        $itemRemark = (string)($item['remark'] ?? '');
        if ($itemId > 0 && $itemPort === $port && $itemRemark === $remark) {
            $tag = (string)($item['tag'] ?? '');
            if ($tag !== '') {
                return $tag;
            }
            return 'inbound-' . $itemId;
        }
    }
    foreach ($items as $item) {
        $itemId = (int)($item['id'] ?? 0);
        $itemRemark = (string)($item['remark'] ?? '');
        if ($itemId > 0 && $itemRemark === $remark) {
            $tag = (string)($item['tag'] ?? '');
            if ($tag !== '') {
                return $tag;
            }
            return 'inbound-' . $itemId;
        }
    }
    return 'inbound-' . $port;
}

function xsw_fetch_xray(array $server): array
{
    $res = xsw_api($server, 'POST', '/panel/api/xray/');
    $obj = xsw_decode_maybe($res['obj'] ?? []);
    $testUrl = 'https://www.google.com/generate_204';
    if (is_array($obj) && isset($obj['outboundTestUrl'])) {
        $testUrl = (string)$obj['outboundTestUrl'];
    }
    $setting = is_array($obj) && array_key_exists('xraySetting', $obj) ? $obj['xraySetting'] : $obj;
    $config = xsw_decode_maybe($setting);
    if (!is_array($config)) {
        throw new RuntimeException('无法解析 Xray JSON 模板');
    }
    return [$config, $testUrl];
}

function xsw_decode_maybe(mixed $value): mixed
{
    for ($i = 0; $i < 4; $i++) {
        if (!is_string($value)) {
            return $value;
        }
        $decoded = json_decode($value, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return $value;
        }
        $value = $decoded;
    }
    return $value;
}

function xsw_empty_array_to_object(mixed $value): mixed
{
    return is_array($value) && $value === [] ? (object)[] : $value;
}

function xsw_normalize_xray_config(array $config): array
{
    foreach (['log', 'api', 'dns', 'routing', 'policy', 'stats', 'metrics', 'transport', 'reverse', 'observatory', 'burstObservatory'] as $key) {
        if (array_key_exists($key, $config)) {
            $config[$key] = xsw_empty_array_to_object($config[$key]);
        }
    }

    foreach (['inbounds', 'outbounds'] as $section) {
        if (empty($config[$section]) || !is_array($config[$section])) {
            continue;
        }
        foreach ($config[$section] as &$item) {
            if (!is_array($item)) {
                continue;
            }
            if (array_key_exists('settings', $item)) {
                $item['settings'] = xsw_empty_array_to_object($item['settings']);
            }
            if (($item['streamSettings']['network'] ?? '') !== 'ws') {
                continue;
            }
            if (isset($item['streamSettings']['wsSettings']['headers'])) {
                $item['streamSettings']['wsSettings']['headers'] = xsw_empty_array_to_object($item['streamSettings']['wsSettings']['headers']);
            }
        }
        unset($item);
    }

    return $config;
}

function xsw_save_xray(array $server, array $config, string $testUrl): void
{
    $config = xsw_normalize_xray_config($config);
    xsw_api($server, 'POST', '/panel/api/xray/update', [
        'xraySetting' => json_encode($config, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
        'outboundTestUrl' => $testUrl,
    ], true, 30);
}

function xsw_restart_xray(array $server): void
{
    xsw_api($server, 'POST', '/panel/api/server/restartXrayService', null, false, 45);
}

function xsw_restart_panel(array $server): void
{
    xsw_api($server, 'POST', '/panel/api/setting/restartPanel', null, false, 45);
}

function xsw_strip_managed_rules(array $rules, array $managedInboundTags): array
{
    $keep = [];
    foreach ($rules as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        $outTag = (string)($rule['outboundTag'] ?? '');
        if (xsw_is_managed_tag($outTag)) {
            continue;
        }
        $inTags = $rule['inboundTag'] ?? [];
        if (is_string($inTags)) {
            $inTags = [$inTags];
        }
        if (is_array($inTags) && array_intersect($inTags, $managedInboundTags)) {
            continue;
        }
        if (is_array($inTags)) {
            $hasManagedInbound = false;
            foreach ($inTags as $tag) {
                if (is_string($tag) && xsw_is_managed_tag($tag)) {
                    $hasManagedInbound = true;
                    break;
                }
            }
            if ($hasManagedInbound) {
                continue;
            }
        }
        $keep[] = $rule;
    }
    return $keep;
}

function xsw_apply_xray_for_server(array $state, array $plan, string $serverCode, ?string $activeLineId = null): array
{
    $server = $state['servers'][$serverCode];
    [$config, $testUrl] = xsw_fetch_xray($server);
    if (empty($config['outbounds']) || !is_array($config['outbounds'])) {
        $config['outbounds'] = [
            ['protocol' => 'freedom', 'tag' => 'direct'],
            ['protocol' => 'blackhole', 'tag' => 'blocked'],
        ];
    }
    if (empty($config['routing']) || !is_array($config['routing'])) {
        $config['routing'] = ['rules' => []];
    }
    if (empty($config['routing']['rules']) || !is_array($config['routing']['rules'])) {
        $config['routing']['rules'] = [];
    }

    $managedOutTags = [];
    foreach ($plan['edges'] as $edge) {
        if ($edge['from'] === $serverCode) {
            $managedOutTags[] = $edge['outbound_tag'];
        }
    }
    $config['outbounds'] = array_values(array_filter(
        $config['outbounds'],
        fn($out) => !is_array($out) || !xsw_is_managed_tag((string)($out['tag'] ?? ''))
    ));
    foreach ($plan['edges'] as $edge) {
        if ($edge['from'] !== $serverCode) {
            continue;
        }
        $toServer = $state['servers'][$edge['to']];
        $config['outbounds'][] = xsw_vmess_ws_outbound(
            $edge['outbound_tag'],
            xsw_public_host($toServer),
            (int)$edge['port'],
            (string)$edge['uuid'],
            (string)$edge['ws_path']
        );
    }

    $managedInboundTags = [];
    foreach ($plan['entries'] as $entry) {
        $managedInboundTags[] = $entry['inbound_tag'];
    }
    foreach ($plan['edges'] as $edge) {
        $managedInboundTags[] = $edge['inbound_tag'];
    }
    $existingRules = xsw_strip_managed_rules($config['routing']['rules'], array_values(array_unique($managedInboundTags)));
    $managedRules = xsw_managed_rules_for_server($state, $plan, $serverCode, $activeLineId);
    $config['routing']['rules'] = array_merge($managedRules, $existingRules);

    xsw_save_xray($server, $config, $testUrl);
    return [
        'server' => $serverCode,
        'outbounds' => count($managedOutTags),
        'rules' => count($managedRules),
    ];
}

function xsw_managed_rules_for_server(array $state, array $plan, string $serverCode, ?string $activeLineId): array
{
    $rules = [];
    foreach ($plan['lines'] as $line) {
        $path = $line['path'];
        for ($i = 0; $i < count($path) - 1; $i++) {
            $from = $path[$i];
            $to = $path[$i + 1];
            if ($from !== $serverCode) {
                continue;
            }
            $outEdge = $plan['edges'][$line['id'] . ':' . $from . '>' . $to] ?? null;
            if (!$outEdge) {
                continue;
            }
            if ($i === 0) {
                $entry = $plan['entries'][$line['id']] ?? null;
                if ($entry) {
                    $rules[] = [
                        'type' => 'field',
                        'inboundTag' => [$entry['inbound_tag']],
                        'outboundTag' => $outEdge['outbound_tag'],
                    ];
                }
                continue;
            }
            $prev = $path[$i - 1];
            $inEdge = $plan['edges'][$line['id'] . ':' . $prev . '>' . $from] ?? null;
            if ($inEdge) {
                $rules[] = [
                    'type' => 'field',
                    'inboundTag' => [$inEdge['inbound_tag']],
                    'outboundTag' => $outEdge['outbound_tag'],
                ];
            }
        }
    }
    return $rules;
}

function xsw_deploy(array &$state): array
{
    xsw_prepare_reality_entries($state);
    $plan = xsw_build_plan($state);
    xsw_save_state($state);
    $results = [];
    foreach ($plan['entries'] as $lineId => $entry) {
        $entryServer = $state['servers'][$entry['server']];
        $ensureResult = xsw_ensure_inbound($entryServer, xsw_vless_reality_inbound($entry));
        $plan['entries'][$lineId]['inbound_tag'] = xsw_actual_inbound_tag($entryServer, (int)$entry['port'], (string)$entry['remark']);
        $results[] = [
            'step' => 'entry vless reality inbound',
            'server' => $entry['server'],
            'line' => $entry['line_id'],
            'result' => $ensureResult,
            'inbound_tag' => $plan['entries'][$lineId]['inbound_tag'],
        ];
    }
    foreach ($plan['edges'] as $key => $edge) {
        $target = $state['servers'][$edge['to']];
        $ensureResult = xsw_ensure_inbound($target, xsw_vmess_ws_inbound((int)$edge['port'], (string)$edge['uuid'], (string)$edge['remark'], (string)$edge['ws_path']));
        $plan['edges'][$key]['inbound_tag'] = xsw_actual_inbound_tag($target, (int)$edge['port'], (string)$edge['remark']);
        $results[] = [
            'step' => 'relay vmess ws inbound',
            'server' => $edge['to'],
            'edge' => $edge['from'] . '->' . $edge['to'],
            'result' => $ensureResult,
            'inbound_tag' => $plan['edges'][$key]['inbound_tag'],
        ];
    }

    $serverCodes = [];
    foreach ($state['lines'] as $line) {
        foreach ($line['path'] as $code) {
            $serverCodes[$code] = true;
        }
    }
    foreach (array_keys($serverCodes) as $code) {
        $results[] = ['step' => 'xray template', 'result' => xsw_apply_xray_for_server($state, $plan, $code)];
    }
    foreach (array_keys($serverCodes) as $code) {
        xsw_restart_xray($state['servers'][$code]);
        $results[] = ['step' => 'restart xray', 'server' => $code, 'result' => 'ok'];
    }
    foreach (array_keys($serverCodes) as $code) {
        xsw_restart_panel($state['servers'][$code]);
        $results[] = ['step' => 'restart panel', 'server' => $code, 'result' => 'ok'];
    }
    $state['last_results']['deploy'] = ['at' => time(), 'results' => $results];
    xsw_save_state($state);
    xsw_log('info', '发布完成', ['results' => $results]);
    return $results;
}

function xsw_create_standalone_and_deploy(array &$state, string $name, string $serverCode, string $protocol, int $port): array
{
    xsw_ensure_standalone_state($state);
    $name = trim($name);
    if ($name === '') {
        throw new RuntimeException('请填写入口名称');
    }
    $serverCode = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', $serverCode));
    if ($serverCode === '' || empty($state['servers'][$serverCode])) {
        throw new RuntimeException('找不到资源：' . $serverCode);
    }
    $protocol = $protocol === 'socks5' ? 'socks5' : 'vless';
    if ($port <= 0) {
        $port = xsw_next_standalone_port($state);
    }
    if ($port < 1 || $port > 65535) {
        throw new RuntimeException('单节点入口端口不正确');
    }
    foreach (($state['standalone']['entries'] ?? []) as $entry) {
        if ((string)($entry['server'] ?? '') === $serverCode && (int)($entry['port'] ?? 0) === $port) {
            throw new RuntimeException('这台资源已经存在相同端口的单节点入口');
        }
    }

    $id = xsw_next_standalone_id($state['standalone']['entries'] ?? []);
    $entry = [
        'id' => $id,
        'name' => $name,
        'server' => $serverCode,
        'protocol' => $protocol,
        'port' => $port,
        'created_at' => time(),
    ];
    $entry['remark'] = xsw_new_standalone_remark($entry);
    if ($protocol === 'socks5') {
        $entry['username'] = 'xui_' . strtolower($id);
        $entry['password'] = xsw_random_hex(8);
        $payload = xsw_socks5_inbound($entry);
        $stepName = 'standalone socks5 inbound';
    } else {
        $settings = $state['settings'] ?? [];
        $keys = xsw_reality_keypair($state['servers'][$serverCode]);
        $entry['uuid'] = xsw_uuid();
        $entry['private_key'] = $keys['private_key'];
        $entry['public_key'] = $keys['public_key'];
        $entry['short_id'] = xsw_random_hex(4);
        $target = xsw_select_reality_target($settings);
        $entry['sni'] = $target['sni'];
        $entry['dest'] = $target['dest'];
        $entry['target_latency_ms'] = $target['latency_ms'];
        $entry['fingerprint'] = (string)($settings['reality_fingerprint'] ?? 'chrome');
        $entry['spider_x'] = (string)($settings['reality_spider_x'] ?? '/');
        $payload = xsw_vless_reality_inbound([
            'line_id' => $id,
            'line_name' => $entry['name'],
            'uuid' => $entry['uuid'],
            'private_key' => $entry['private_key'],
            'public_key' => $entry['public_key'],
            'short_id' => $entry['short_id'],
            'sni' => $entry['sni'],
            'dest' => $entry['dest'],
            'fingerprint' => $entry['fingerprint'],
            'spider_x' => $entry['spider_x'],
            'port' => $entry['port'],
            'remark' => xsw_standalone_remark($entry),
        ]);
        $stepName = 'standalone vless reality inbound';
    }

    $server = $state['servers'][$serverCode];
    $ensureResult = xsw_ensure_inbound($server, $payload);
    $entry['inbound_tag'] = xsw_actual_inbound_tag($server, $port, xsw_standalone_remark($entry));
    $state['standalone']['entries'][] = $entry;
    xsw_save_state($state);
    xsw_restart_xray($server);
    xsw_restart_panel($server);
    $results = [
        ['step' => $stepName, 'server' => $serverCode, 'entry' => $id, 'result' => $ensureResult, 'inbound_tag' => $entry['inbound_tag']],
        ['step' => 'restart xray', 'server' => $serverCode, 'result' => 'ok'],
        ['step' => 'restart panel', 'server' => $serverCode, 'result' => 'ok'],
    ];
    $state['last_results']['standalone'] = ['at' => time(), 'entry' => $id, 'results' => $results];
    xsw_save_state($state);
    xsw_log('info', '创建单节点入口', ['entry' => $id, 'server' => $serverCode, 'protocol' => $protocol, 'port' => $port]);
    return ['entry_id' => $id, 'results' => $results];
}

function xsw_delete_standalone_inbound_best_effort(array $server, array $entry, string $serverCode, string $entryId): array
{
    try {
        $lastResult = 'not_found';
        foreach (xsw_standalone_delete_remarks($entry) as $remark) {
            $lastResult = xsw_delete_inbound($server, (int)$entry['port'], $remark);
            if ($lastResult !== 'not_found') {
                return [
                    'step' => 'delete standalone inbound',
                    'server' => $serverCode,
                    'entry' => $entryId,
                    'remark' => $remark,
                    'result' => $lastResult,
                ];
            }
        }
        return [
            'step' => 'delete standalone inbound',
            'server' => $serverCode,
            'entry' => $entryId,
            'result' => $lastResult,
        ];
    } catch (Throwable $e) {
        xsw_log('error', '单节点远程下线失败，已继续释放本地占用：' . $e->getMessage(), ['entry' => $entryId, 'server' => $serverCode]);
        return [
            'step' => 'delete standalone inbound',
            'server' => $serverCode,
            'entry' => $entryId,
            'error' => $e->getMessage(),
            'local_state' => 'removed',
        ];
    }
}

function xsw_delete_standalone_and_cleanup(array &$state, string $entryId): array
{
    xsw_ensure_standalone_state($state);
    $entry = null;
    $index = -1;
    foreach (($state['standalone']['entries'] ?? []) as $i => $candidate) {
        if ((string)($candidate['id'] ?? '') === $entryId) {
            $entry = $candidate;
            $index = (int)$i;
            break;
        }
    }
    if (!$entry || $index < 0) {
        throw new RuntimeException('找不到单节点入口：' . $entryId);
    }
    $serverCode = (string)($entry['server'] ?? '');
    if (empty($state['servers'][$serverCode])) {
        array_splice($state['standalone']['entries'], $index, 1);
        $results = [
            ['step' => 'remove stale standalone entry', 'server' => $serverCode, 'entry' => $entryId, 'result' => 'removed local state; server missing'],
        ];
        $state['last_results']['standalone_delete'] = ['at' => time(), 'entry' => $entryId, 'results' => $results];
        xsw_save_state($state);
        xsw_log('info', '删除失效单节点入口', ['entry' => $entryId, 'server' => $serverCode]);
        return $results;
        throw new RuntimeException('找不到资源：' . $serverCode);
    }
    $server = $state['servers'][$serverCode];
    $results = [
        xsw_delete_standalone_inbound_best_effort($server, $entry, $serverCode, $entryId),
    ];
    array_splice($state['standalone']['entries'], $index, 1);
    xsw_save_state($state);
    try {
        xsw_restart_xray($server);
        $results[] = ['step' => 'restart xray', 'server' => $serverCode, 'result' => 'ok'];
    } catch (Throwable $e) {
        $results[] = ['step' => 'restart xray', 'server' => $serverCode, 'error' => $e->getMessage(), 'local_state' => 'removed'];
        xsw_log('error', '单节点下线后重启失败，已释放本地占用：' . $e->getMessage(), ['entry' => $entryId, 'server' => $serverCode]);
    }
    try {
        xsw_restart_panel($server);
        $results[] = ['step' => 'restart panel', 'server' => $serverCode, 'result' => 'ok'];
    } catch (Throwable $e) {
        $results[] = ['step' => 'restart panel', 'server' => $serverCode, 'error' => $e->getMessage(), 'local_state' => 'removed'];
        xsw_log('error', '单节点下线后面板重启失败，已释放本地占用：' . $e->getMessage(), ['entry' => $entryId, 'server' => $serverCode]);
    }
    $state['last_results']['standalone_delete'] = ['at' => time(), 'entry' => $entryId, 'results' => $results];
    xsw_save_state($state);
    xsw_log('info', '删除单节点入口', ['entry' => $entryId, 'server' => $serverCode]);
    return $results;
}

function xsw_shell_command(array $parts): string
{
    return implode(' ', array_map(static fn($part) => escapeshellarg((string)$part), $parts));
}

function xsw_process_available(): bool
{
    return function_exists('proc_open') || function_exists('exec');
}

function xsw_normalize_ssh_private_key(string $value): string
{
    $value = str_replace(["\r\n", "\r"], "\n", $value);
    $value = str_replace('\n', "\n", $value);
    $value = trim($value);
    return $value === '' ? '' : $value . "\n";
}

function xsw_run_process(string $command, string $stdin = '', array $env = []): array
{
    if (!function_exists('proc_open')) {
        if (!function_exists('exec')) {
            throw new RuntimeException('服务器禁用了 proc_open/exec，无法执行 SSH 校验或后台命令');
        }
        $stdinFile = '';
        $envPrefix = '';
        foreach ($env as $key => $value) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', (string)$key)) {
                continue;
            }
            $envPrefix .= (string)$key . '=' . escapeshellarg((string)$value) . ' ';
        }
        if ($stdin !== '') {
            $stdinFile = XSW_SECRET_DIR . '/stdin-' . xsw_random_hex(8);
            file_put_contents($stdinFile, $stdin, LOCK_EX);
            @chmod($stdinFile, 0600);
        }
        $fallbackCommand = $envPrefix . $command . ($stdinFile !== '' ? ' < ' . escapeshellarg($stdinFile) : '') . ' 2>&1';
        $output = [];
        $code = 1;
        try {
            exec($fallbackCommand, $output, $code);
        } finally {
            if ($stdinFile !== '' && is_file($stdinFile)) {
                @unlink($stdinFile);
            }
        }
        return ['code' => (int)$code, 'stdout' => implode("\n", $output), 'stderr' => ''];
    }

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($command, $descriptors, $pipes, null, $env ?: null);
    if (!is_resource($process)) {
        throw new RuntimeException('无法启动后台命令');
    }
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $code = proc_close($process);
    return ['code' => $code, 'stdout' => (string)$stdout, 'stderr' => (string)$stderr];
}

function xsw_run_ssh_script(array $payload, array $secret, string $remoteScript, int $timeout = 900): array
{
    $host = xsw_clean_ssh_host((string)($payload['host'] ?? ''));
    $sshPort = max(1, min(65535, (int)($payload['ssh_port'] ?? 22)));
    $sshUser = preg_replace('/[^A-Za-z0-9_.-]/', '', (string)($payload['ssh_user'] ?? 'root'));
    if ($sshUser === '') {
        throw new RuntimeException('SSH 用户名不正确');
    }
    $password = (string)($secret['ssh_password'] ?? '');
    $privateKey = xsw_normalize_ssh_private_key((string)($secret['ssh_private_key'] ?? ''));
    if ($password === '' && $privateKey === '') {
        throw new RuntimeException('请填写 SSH 密码或私钥');
    }

    $keyFile = '';
    $env = [];
    $cmd = [is_file('/usr/bin/timeout') ? '/usr/bin/timeout' : 'timeout', (string)$timeout];
    if ($privateKey !== '') {
        $keyFile = XSW_SECRET_DIR . '/ssh-key-' . xsw_random_hex(8);
        file_put_contents($keyFile, $privateKey, LOCK_EX);
        @chmod($keyFile, 0600);
    } else {
        $cmd[] = is_file('/usr/bin/sshpass') ? '/usr/bin/sshpass' : 'sshpass';
        $cmd[] = '-e';
        $env['SSHPASS'] = $password;
    }
    $cmd[] = is_file('/usr/bin/ssh') ? '/usr/bin/ssh' : 'ssh';
    array_push(
        $cmd,
        '-p',
        (string)$sshPort,
        '-o',
        'BatchMode=' . ($privateKey !== '' ? 'yes' : 'no'),
        '-o',
        'ConnectTimeout=20',
        '-o',
        'ServerAliveInterval=15',
        '-o',
        'ServerAliveCountMax=4',
        '-o',
        'StrictHostKeyChecking=no',
        '-o',
        'UserKnownHostsFile=/dev/null'
    );
    if ($keyFile !== '') {
        array_push($cmd, '-i', $keyFile);
    }
    $cmd[] = $sshUser . '@' . $host;
    $cmd[] = 'bash -s';

    try {
        return xsw_run_process(xsw_shell_command($cmd), $remoteScript, $env);
    } finally {
        if ($keyFile !== '' && is_file($keyFile)) {
            @unlink($keyFile);
        }
    }
}

function xsw_verify_ssh_secret(string $host, int $sshPort, string $sshUser, array $secret): void
{
    $host = xsw_clean_ssh_host($host);
    $sshPort = max(1, min(65535, $sshPort));
    $sshUser = preg_replace('/[^A-Za-z0-9_.-]/', '', $sshUser);
    if ($sshUser === '') {
        throw new RuntimeException('SSH 用户名不正确');
    }
    $password = (string)($secret['ssh_password'] ?? '');
    $privateKey = xsw_normalize_ssh_private_key((string)($secret['ssh_private_key'] ?? ''));
    if ($password === '' && $privateKey === '') {
        throw new RuntimeException('请填写 SSH 密码或私钥');
    }
    if ($privateKey !== '') {
        $keyFile = XSW_SECRET_DIR . '/ssh-verify-' . xsw_random_hex(8);
        file_put_contents($keyFile, $privateKey, LOCK_EX);
        @chmod($keyFile, 0600);
        try {
            $check = xsw_run_process('ssh-keygen -y -f ' . escapeshellarg($keyFile) . ' >/dev/null', '', []);
            if ((int)$check['code'] !== 0) {
                $msg = xsw_safe_install_tail($check['stderr'] . "\n" . $check['stdout']);
                throw new RuntimeException('SSH 私钥格式不正确，请粘贴完整私钥' . ($msg !== '' ? '：' . $msg : ''));
            }
        } finally {
            if (is_file($keyFile)) {
                @unlink($keyFile);
            }
        }
    } elseif (!is_file('/usr/bin/sshpass') && !is_file('/usr/local/bin/sshpass')) {
        if (!function_exists('exec')) {
            throw new RuntimeException('服务器缺少 sshpass，密码方式无法校验；请改用 SSH 私钥');
        }
        $out = [];
        $code = 1;
        exec('command -v sshpass 2>/dev/null', $out, $code);
        if ($code !== 0 || empty($out)) {
            throw new RuntimeException('服务器缺少 sshpass，密码方式无法校验；请改用 SSH 私钥');
        }
    }

    $payload = [
        'host' => $host,
        'ssh_port' => $sshPort,
        'ssh_user' => $sshUser,
    ];
    $process = xsw_run_ssh_script($payload, $secret, "echo JD_SSH_OK\n", 25);
    if ((int)$process['code'] !== 0 || !str_contains((string)$process['stdout'], 'JD_SSH_OK')) {
        $tail = xsw_safe_install_tail($process['stderr'] . "\n" . $process['stdout']);
        if (str_contains($tail, 'Permission denied')) {
            throw new RuntimeException('SSH 登录失败：用户名、密码或私钥不正确');
        }
        if (str_contains($tail, 'error in libcrypto') || str_contains($tail, 'invalid format')) {
            throw new RuntimeException('SSH 私钥格式不正确，请粘贴完整私钥');
        }
        throw new RuntimeException('SSH 连接校验失败' . ($tail !== '' ? '：' . $tail : ''));
    }
}

function xsw_verify_firewall_session(array &$state, array $payload, array $secret): array
{
    xsw_ensure_firewall_state($state);
    $sessionId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($payload['session_id'] ?? ''));
    if ($sessionId === '' || !isset($state['firewall']['sessions'][$sessionId]) || !is_array($state['firewall']['sessions'][$sessionId])) {
        throw new RuntimeException('找不到要校验的防火墙服务器');
    }
    $session = $state['firewall']['sessions'][$sessionId];
    $host = (string)($payload['host'] ?? $session['host'] ?? '');
    $sshPort = (int)($payload['ssh_port'] ?? $session['ssh_port'] ?? 22);
    $sshUser = (string)($payload['ssh_user'] ?? $session['ssh_user'] ?? 'root');
    xsw_verify_ssh_secret($host, $sshPort, $sshUser, $secret);
    $state['firewall']['sessions'][$sessionId]['last_status'] = '已接入';
    $state['firewall']['sessions'][$sessionId]['verified_at'] = time();
    $state['firewall']['sessions'][$sessionId]['last_used_at'] = time();
    $state['firewall']['sessions'][$sessionId]['updated_at'] = time();
    xsw_save_state($state);
    xsw_log('info', 'SSH 校验通过', ['host' => $host, 'session' => $sessionId]);
    return [
        ['step' => 'ssh verify', 'host' => $host, 'result' => 'ok'],
    ];
}

function xsw_safe_install_tail(string $text): string
{
    $lines = preg_split('/\R/', $text) ?: [];
    $safe = [];
    foreach ($lines as $line) {
        if (preg_match('/(Username|Password|API Token|apiToken|Access URL|WebBasePath|XUI_|token|password)/i', $line)) {
            continue;
        }
        $line = trim($line);
        if ($line !== '') {
            $safe[] = $line;
        }
    }
    return implode(' | ', array_slice($safe, -12));
}

function xsw_parse_install_result(string $stdout): array
{
    if (!preg_match('/(?:JD|XSW)_INSTALL_RESULT_BEGIN\s*(.*?)\s*(?:JD|XSW)_INSTALL_RESULT_END/s', $stdout, $match)) {
        throw new RuntimeException('没有读到 3x-ui 安装结果');
    }
    $result = [];
    foreach (preg_split('/\R/', trim($match[1])) ?: [] as $line) {
        if (!preg_match('/^([A-Z0-9_]+)=(.*)$/', trim($line), $parts)) {
            continue;
        }
        $decoded = base64_decode($parts[2], true);
        $result[$parts[1]] = $decoded === false ? '' : $decoded;
    }
    foreach (['XUI_USERNAME', 'XUI_PASSWORD', 'XUI_PANEL_PORT', 'XUI_WEB_BASE_PATH', 'XUI_ACCESS_URL', 'XUI_API_TOKEN'] as $key) {
        if (trim((string)($result[$key] ?? '')) === '') {
            throw new RuntimeException('安装结果缺少 ' . $key);
        }
    }
    return $result;
}

function xsw_format_panel_info(array $panel): string
{
    return
        'Username:    ' . (string)($panel['username'] ?? '') . "\n" .
        'Password:    ' . (string)($panel['password'] ?? '') . "\n" .
        'Port:        ' . (string)($panel['port'] ?? '') . "\n" .
        'WebBasePath: ' . (string)($panel['web_base_path'] ?? '') . "\n" .
        'Database:    ' . (string)($panel['database'] ?? 'SQLite (/etc/x-ui/x-ui.db)') . "\n" .
        'Access URL:  ' . (string)($panel['access_url'] ?? '') . "\n" .
        'API Token:   ' . (string)($panel['api_token'] ?? '');
}

function xsw_install_panel_public(array $panel): array
{
    return [
        'code' => (string)($panel['code'] ?? ''),
        'name' => (string)($panel['name'] ?? ''),
        'host' => (string)($panel['host'] ?? ''),
        'ssh_port' => (int)($panel['ssh_port'] ?? 22),
        'ssh_user' => (string)($panel['ssh_user'] ?? ''),
        'port' => (int)($panel['port'] ?? 0),
        'database' => (string)($panel['database'] ?? ''),
        'installed_at' => (int)($panel['installed_at'] ?? 0),
    ];
}

function xsw_mark_install_result_copied(array &$state, string $jobId): void
{
    $jobId = preg_replace('/[^A-Za-z0-9_-]/', '', $jobId);
    if ($jobId === '') {
        throw new RuntimeException('任务ID不正确');
    }
    if (empty($state['jobs']) || !is_array($state['jobs'])) {
        throw new RuntimeException('找不到任务：' . $jobId);
    }
    foreach ($state['jobs'] as &$job) {
        if ((string)($job['id'] ?? '') !== $jobId) {
            continue;
        }
        if (($job['type'] ?? '') !== 'install_3xui') {
            throw new RuntimeException('不是面板安装任务');
        }
        if (empty($job['install_text']) && !empty($job['install_copied_at'])) {
            return;
        }
        if (!empty($job['install_result']) && is_array($job['install_result'])) {
            $job['install_result'] = xsw_install_panel_public($job['install_result']);
        }
        unset($job['install_text']);
        $job['install_copied_at'] = time();
        xsw_save_state($state);
        xsw_log('info', '面板安装信息已复制并隐藏', ['jobId' => $jobId]);
        return;
    }
    unset($job);
    throw new RuntimeException('找不到任务：' . $jobId);
}

function xsw_install_3xui_and_import(array &$state, array $payload, array $secret): array
{
    $host = xsw_clean_ssh_host((string)($payload['host'] ?? ''));
    $sshPort = max(1, min(65535, (int)($payload['ssh_port'] ?? 22)));
    $sshUser = preg_replace('/[^A-Za-z0-9_.-]/', '', (string)($payload['ssh_user'] ?? 'root'));
    if ($sshUser === '') {
        throw new RuntimeException('SSH 用户名不正确');
    }
    $name = trim((string)($payload['name'] ?? ''));
    $code = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($payload['code'] ?? '')));
    if ($code === '' || isset($state['servers'][$code])) {
        $code = xsw_next_server_code($state['servers'] ?? []);
    }
    $panelPort = (int)($payload['panel_port'] ?? 0);
    $sslMode = (string)($payload['ssl_mode'] ?? 'ip');
    if (!in_array($sslMode, ['ip', 'none'], true)) {
        $sslMode = 'ip';
    }

    $password = (string)($secret['ssh_password'] ?? '');
    $privateKey = xsw_normalize_ssh_private_key((string)($secret['ssh_private_key'] ?? ''));
    if ($password === '' && $privateKey === '') {
        throw new RuntimeException('请填写 SSH 密码或私钥');
    }

    $keyFile = '';
    $env = [];
    $cmd = ['/usr/bin/timeout', '1200'];
    if (!is_file('/usr/bin/timeout')) {
        $cmd = ['timeout', '1200'];
    }
    if ($privateKey !== '') {
        $keyFile = XSW_SECRET_DIR . '/ssh-key-' . xsw_random_hex(8);
        file_put_contents($keyFile, $privateKey, LOCK_EX);
        @chmod($keyFile, 0600);
    } else {
        $sshpass = is_file('/usr/bin/sshpass') ? '/usr/bin/sshpass' : 'sshpass';
        $cmd[] = $sshpass;
        $cmd[] = '-e';
        $env['SSHPASS'] = $password;
    }
    $cmd[] = is_file('/usr/bin/ssh') ? '/usr/bin/ssh' : 'ssh';
    array_push(
        $cmd,
        '-p',
        (string)$sshPort,
        '-o',
        'BatchMode=' . ($privateKey !== '' ? 'yes' : 'no'),
        '-o',
        'ConnectTimeout=20',
        '-o',
        'ServerAliveInterval=15',
        '-o',
        'ServerAliveCountMax=4',
        '-o',
        'StrictHostKeyChecking=no',
        '-o',
        'UserKnownHostsFile=/dev/null'
    );
    if ($keyFile !== '') {
        array_push($cmd, '-i', $keyFile);
    }
    $cmd[] = $sshUser . '@' . $host;
    $cmd[] = 'bash -s';

    $exports = [
        'export DEBIAN_FRONTEND=noninteractive',
        'export XUI_NONINTERACTIVE=1',
        'export XUI_DB_TYPE=sqlite',
        'export XUI_ENABLE_FAIL2BAN=true',
        'export XUI_SSL_MODE=' . escapeshellarg($sslMode),
        'export SSL_HOST=' . escapeshellarg($host),
    ];
    if ($panelPort > 0) {
        $exports[] = 'export XUI_PANEL_PORT=' . escapeshellarg((string)$panelPort);
    }
    $remoteScript = <<<'BASH'
set -e
if ! command -v curl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache curl ca-certificates
  else echo "curl is required" >&2; exit 12
  fi
fi
BASH;
    $remoteScript .= "\n" . implode("\n", $exports) . "\n";
    $remoteScript .= <<<'BASH'
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
if [ ! -r /etc/x-ui/install-result.env ]; then
  echo "missing /etc/x-ui/install-result.env" >&2
  exit 44
fi
set -a
. /etc/x-ui/install-result.env
set +a
b64() { printf '%s' "$1" | base64 | tr -d '\n'; printf '\n'; }
echo JD_INSTALL_RESULT_BEGIN
for key in XUI_USERNAME XUI_PASSWORD XUI_PANEL_PORT XUI_WEB_BASE_PATH XUI_ACCESS_URL XUI_API_TOKEN XUI_DB_TYPE; do
  eval "value=\${$key:-}"
  printf '%s=' "$key"
  b64 "$value"
done
echo JD_INSTALL_RESULT_END
BASH;

    try {
        $process = xsw_run_process(xsw_shell_command($cmd), $remoteScript, $env);
    } finally {
        if ($keyFile !== '' && is_file($keyFile)) {
            @unlink($keyFile);
        }
    }
    if ((int)$process['code'] !== 0) {
        $tail = xsw_safe_install_tail($process['stderr'] . "\n" . $process['stdout']);
        throw new RuntimeException('安装失败，SSH/安装脚本退出码 ' . (int)$process['code'] . ($tail !== '' ? '：' . $tail : ''));
    }

    $raw = xsw_parse_install_result($process['stdout']);
    $accessUrl = rtrim((string)$raw['XUI_ACCESS_URL'], '/');
    $dbType = strtolower((string)($raw['XUI_DB_TYPE'] ?? 'sqlite'));
    $panel = [
        'code' => $code,
        'name' => $name !== '' ? $name : $host,
        'host' => $host,
        'ssh_port' => $sshPort,
        'ssh_user' => $sshUser,
        'username' => (string)$raw['XUI_USERNAME'],
        'password' => (string)$raw['XUI_PASSWORD'],
        'port' => (int)$raw['XUI_PANEL_PORT'],
        'web_base_path' => (string)$raw['XUI_WEB_BASE_PATH'],
        'database' => $dbType === 'postgres' ? 'PostgreSQL' : 'SQLite (/etc/x-ui/x-ui.db)',
        'access_url' => $accessUrl,
        'api_token' => (string)$raw['XUI_API_TOKEN'],
        'installed_at' => time(),
    ];

    $state['servers'][$code] = xsw_normalize_server([
        'code' => $code,
        'name' => $panel['name'],
        'access_url' => $panel['access_url'],
        'api_token' => $panel['api_token'],
        'proxy_host' => $host,
    ]);
    $results = [
        ['step' => 'ssh install 3x-ui', 'server' => $host, 'result' => 'ok'],
        ['step' => 'read install result', 'server' => $host, 'result' => 'ok'],
        ['step' => 'add resource', 'server' => $code, 'result' => 'ok'],
    ];
    try {
        $test = xsw_test_server($state['servers'][$code]);
        $results[] = ['step' => 'test 3x-ui api', 'server' => $code, 'result' => 'ok', 'ms' => $test['ms'] ?? 0];
    } catch (Throwable $e) {
        $results[] = ['step' => 'test 3x-ui api', 'server' => $code, 'error' => $e->getMessage()];
    }
    $state['last_results']['install'] = ['at' => time(), 'panel' => xsw_install_panel_public($panel), 'results' => $results];
    xsw_save_state($state);
    xsw_log('info', '安装 3x-ui 并导入资源', ['server' => $code, 'host' => $host]);
    return ['panel' => $panel, 'panel_text' => xsw_format_panel_info($panel), 'results' => $results];
}

function xsw_parse_firewall_ports(string $text): array
{
    $ports = [];
    foreach (preg_split('/[\s,，]+/', trim($text)) ?: [] as $item) {
        $item = trim($item);
        if ($item === '') {
            continue;
        }
        if (preg_match('/^(\d{1,5})-(\d{1,5})$/', $item, $match)) {
            $start = (int)$match[1];
            $end = (int)$match[2];
            if ($start < 1 || $end > 65535 || $start > $end) {
                throw new RuntimeException('端口范围不正确：' . $item);
            }
            $ports[] = $start . ':' . $end;
            continue;
        }
        if (!preg_match('/^\d{1,5}$/', $item)) {
            throw new RuntimeException('端口不正确：' . $item);
        }
        $port = (int)$item;
        if ($port < 1 || $port > 65535) {
            throw new RuntimeException('端口不正确：' . $item);
        }
        $ports[] = (string)$port;
    }
    return array_values(array_unique($ports));
}

function xsw_parse_firewall_sources(string $text): array
{
    $text = trim($text);
    if ($text === '' || in_array(strtolower($text), ['all', 'any', '所有ip', '所有IP'], true)) {
        return ['0.0.0.0/0'];
    }
    return xsw_parse_ipv4_cidrs($text, true);
}

function xsw_firewall_port_label(array $ports): string
{
    return implode(',', array_map(fn($port) => str_replace(':', '-', (string)$port), $ports));
}

function xsw_firewall_rule_id(array $rule, int $index = 0): string
{
    $id = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($rule['id'] ?? ''));
    if ($id !== '') {
        return $id;
    }
    return 'fw_rule_' . substr(hash('sha256', json_encode($rule, JSON_UNESCAPED_SLASHES) . ':' . $index), 0, 12);
}

function xsw_normalize_firewall_rules(array $rules): array
{
    $normalized = [];
    foreach ($rules as $index => $rule) {
        if (!is_array($rule)) {
            continue;
        }

        if (isset($rule['whitelist']) || isset($rule['blacklist'])) {
            $ports = array_values(array_filter((array)($rule['ports'] ?? []), 'strlen'));
            foreach (['allow' => (array)($rule['whitelist'] ?? []), 'deny' => (array)($rule['blacklist'] ?? [])] as $policy => $sources) {
                $sources = array_values(array_filter($sources, 'strlen'));
                if (!$ports || !$sources) {
                    continue;
                }
                $normalized[] = [
                    'id' => xsw_firewall_rule_id($rule, $index) . '_' . $policy,
                    'protocol' => 'tcp',
                    'ports' => $ports,
                    'policy' => $policy,
                    'direction' => 'in',
                    'sources' => $sources,
                    'remark' => (string)($rule['remark'] ?? ''),
                    'enabled' => array_key_exists('enabled', $rule) ? !empty($rule['enabled']) : true,
                    'created_at' => (int)($rule['created_at'] ?? time()),
                    'updated_at' => (int)($rule['updated_at'] ?? time()),
                ];
            }
            continue;
        }

        $protocol = strtolower((string)($rule['protocol'] ?? 'tcp'));
        if (!in_array($protocol, ['tcp', 'udp'], true)) {
            $protocol = 'tcp';
        }
        $ports = array_values(array_filter((array)($rule['ports'] ?? []), 'strlen'));
        if (!$ports) {
            continue;
        }
        $policy = strtolower((string)($rule['policy'] ?? 'allow'));
        if (!in_array($policy, ['allow', 'deny'], true)) {
            $policy = 'allow';
        }
        $sources = array_values(array_filter((array)($rule['sources'] ?? ['0.0.0.0/0']), 'strlen'));
        if (!$sources) {
            $sources = ['0.0.0.0/0'];
        }
        $normalized[] = [
            'id' => xsw_firewall_rule_id($rule, $index),
            'protocol' => $protocol,
            'ports' => $ports,
            'policy' => $policy,
            'direction' => 'in',
            'sources' => $sources,
            'remark' => trim((string)($rule['remark'] ?? '')),
            'enabled' => array_key_exists('enabled', $rule) ? !empty($rule['enabled']) : true,
            'created_at' => (int)($rule['created_at'] ?? time()),
            'updated_at' => (int)($rule['updated_at'] ?? time()),
        ];
        if (count($normalized) > 300) {
            throw new RuntimeException('安全组规则太多');
        }
    }
    return $normalized;
}

function xsw_firewall_rules_from_policy(array $policy): array
{
    if (isset($policy['rules']) && is_array($policy['rules'])) {
        return xsw_normalize_firewall_rules($policy['rules']);
    }
    if (isset($policy['port_rules']) && is_array($policy['port_rules'])) {
        return xsw_normalize_firewall_rules($policy['port_rules']);
    }
    return [];
}

function xsw_format_firewall_port_rules(array $rules): array
{
    $rows = [];
    foreach (xsw_normalize_firewall_rules($rules) as $rule) {
        $rows[] = strtoupper((string)$rule['protocol']) . ' ' . xsw_firewall_port_label((array)$rule['ports']) . ' / ' . ((string)$rule['policy'] === 'deny' ? '阻止 ' : '放行 ') . implode(',', (array)$rule['sources']);
    }
    return $rows;
}

function xsw_firewall_port_rule_script(array $rules): string
{
    $rules = xsw_normalize_firewall_rules($rules);
    $lines = [];
    $allowPorts = [];
    foreach ($rules as $rule) {
        if (empty($rule['enabled'])) {
            continue;
        }
        $protocol = (string)$rule['protocol'];
        $target = (string)$rule['policy'] === 'deny' ? 'DROP' : 'ACCEPT';
        foreach ((array)$rule['ports'] as $port) {
            $qPort = escapeshellarg((string)$port);
            if ($target === 'ACCEPT') {
                $allowPorts[$protocol . '|' . (string)$port] = ['protocol' => $protocol, 'port' => (string)$port];
            }
            foreach ((array)$rule['sources'] as $src) {
                $qSrc = escapeshellarg((string)$src);
                if ($target === 'DROP') {
                    $lines[] = 'if [ -n "$CLIENT_IP" ] && { [ ' . $qSrc . ' = "$CLIENT_IP" ] || [ ' . $qSrc . ' = "$CLIENT_IP/32" ]; }; then :; else "$IPT" -w -A "$CHAIN" -p ' . $protocol . ' -s ' . $qSrc . ' --dport ' . $qPort . ' -j DROP; fi';
                } else {
                    $lines[] = '"$IPT" -w -A "$CHAIN" -p ' . $protocol . ' -s ' . $qSrc . ' --dport ' . $qPort . ' -j ACCEPT';
                }
            }
        }
    }
    foreach ($allowPorts as $item) {
        $protocol = $item['protocol'];
        $qPort = escapeshellarg($item['port']);
        $lines[] = 'if [ -n "$CLIENT_IP" ]; then "$IPT" -w -A "$CHAIN" -p ' . $protocol . ' -s "$CLIENT_IP/32" --dport ' . $qPort . ' -j ACCEPT; fi';
        $lines[] = '"$IPT" -w -A "$CHAIN" -p ' . $protocol . ' --dport ' . $qPort . ' -j DROP';
    }
    return $lines ? implode("\n", $lines) : ':';
}

function xsw_parse_ipv4_cidrs(string $text, bool $allowAny = false): array
{
    $cidrs = [];
    foreach (preg_split('/[\s,，]+/', trim($text)) ?: [] as $item) {
        $item = trim($item);
        if ($item === '') {
            continue;
        }
        $ip = $item;
        $prefix = '32';
        if (str_contains($item, '/')) {
            [$ip, $prefix] = explode('/', $item, 2);
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new RuntimeException('IP/CIDR 不正确：' . $item);
        }
        if (!preg_match('/^\d{1,2}$/', $prefix) || (int)$prefix < 0 || (int)$prefix > 32) {
            throw new RuntimeException('CIDR 掩码不正确：' . $item);
        }
        $cidr = $ip . '/' . (int)$prefix;
        if (!$allowAny && $cidr === '0.0.0.0/0') {
            throw new RuntimeException('黑名单不能填写 0.0.0.0/0');
        }
        $cidrs[] = $cidr;
    }
    return array_values(array_unique($cidrs));
}

function xsw_firewall_payload_summary(array $payload): string
{
    $mode = (string)($payload['mode'] ?? 'apply');
    $host = (string)($payload['host'] ?? '');
    $ruleCount = count(is_array($payload['rules'] ?? null) ? $payload['rules'] : (is_array($payload['port_rules'] ?? null) ? $payload['port_rules'] : []));
    if (($payload['read'] ?? false) || $mode === 'read') {
        return '读取 · ' . $host;
    }
    return ($mode === 'clear' ? '清除' : '应用') . ' · ' . $host . ($ruleCount > 0 ? ' · ' . $ruleCount . ' 条端口规则' : '');
}

function xsw_firewall_sections_from_stdout(string $stdout): array
{
    $sections = [];
    if (preg_match_all('/(?:JD|XSW)_FW_SECTION_BEGIN:([A-Za-z0-9_-]+)\R(.*?)\R(?:JD|XSW)_FW_SECTION_END:\1/s', $stdout, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $match) {
            $text = trim((string)$match[2]);
            if (strlen($text) > 30000) {
                $text = substr($text, 0, 30000) . "\n... output truncated ...";
            }
            $sections[(string)$match[1]] = $text;
        }
    }
    return $sections;
}

function xsw_read_firewall_state(array &$state, array $payload, array $secret): array
{
    xsw_ensure_firewall_state($state);
    $host = xsw_clean_ssh_host((string)($payload['host'] ?? ''));
    $sessionId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($payload['session_id'] ?? ''));
    $remoteScript = <<<'BASH'
set -e
section() {
  name="$1"
  shift
  echo "JD_FW_SECTION_BEGIN:$name"
  "$@" 2>&1 || true
  echo "JD_FW_SECTION_END:$name"
}
section meta sh -c 'printf "hostname=%s\n" "$(hostname 2>/dev/null || true)"; printf "kernel=%s\n" "$(uname -sr 2>/dev/null || true)"; printf "date=%s\n" "$(date "+%F %T %z" 2>/dev/null || true)"'
section iptables-input sh -c 'if command -v iptables >/dev/null 2>&1; then iptables -L INPUT -n -v --line-numbers; else echo "iptables not installed"; fi'
section jd-fw sh -c 'if command -v iptables >/dev/null 2>&1; then iptables -S JD_FW 2>/dev/null || echo "JD_FW not installed"; iptables -S XSW_FW 2>/dev/null || true; else echo "iptables not installed"; fi'
section iptables-save sh -c 'if command -v iptables-save >/dev/null 2>&1; then iptables-save | sed -n "1,260p"; else echo "iptables-save not installed"; fi'
section ufw sh -c 'if command -v ufw >/dev/null 2>&1; then ufw status verbose; else echo "ufw not installed"; fi'
section firewalld sh -c 'if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state; firewall-cmd --list-all; else echo "firewalld not installed"; fi'
section nftables sh -c 'if command -v nft >/dev/null 2>&1; then nft list ruleset | sed -n "1,260p"; else echo "nft not installed"; fi'
section xsw-service sh -c 'if command -v systemctl >/dev/null 2>&1; then systemctl is-enabled xsw-firewall.service 2>/dev/null || true; systemctl is-active xsw-firewall.service 2>/dev/null || true; else echo "systemctl not installed"; fi'
BASH;
    $process = xsw_run_ssh_script($payload, $secret, $remoteScript, 300);
    if ((int)$process['code'] !== 0) {
        $tail = xsw_safe_install_tail($process['stderr'] . "\n" . $process['stdout']);
        throw new RuntimeException('读取防火墙失败，退出码 ' . (int)$process['code'] . ($tail !== '' ? '：' . $tail : ''));
    }
    $sections = xsw_firewall_sections_from_stdout($process['stdout']);
    if (!$sections) {
        throw new RuntimeException('没有读取到防火墙输出');
    }
    $results = [
        ['step' => 'ssh read firewall', 'server' => $host, 'result' => 'ok'],
        ['step' => 'collect firewall rules', 'server' => $host, 'result' => 'ok'],
    ];
    $state['last_results']['firewall_read'] = [
        'at' => time(),
        'host' => $host,
        'sections' => $sections,
        'results' => $results,
    ];
    if ($sessionId !== '') {
        $state['firewall']['reads'][$sessionId] = [
            'at' => time(),
            'host' => $host,
            'sections' => $sections,
            'results' => $results,
        ];
        if (isset($state['firewall']['sessions'][$sessionId]) && is_array($state['firewall']['sessions'][$sessionId])) {
            $state['firewall']['sessions'][$sessionId]['last_read_at'] = time();
            $state['firewall']['sessions'][$sessionId]['last_used_at'] = time();
            $state['firewall']['sessions'][$sessionId]['last_status'] = '读取成功';
        }
    }
    xsw_save_state($state);
    xsw_log('info', '读取防火墙状态', ['host' => $host]);
    return $results;
}

function xsw_apply_firewall_policy(array &$state, array $payload, array $secret): array
{
    xsw_ensure_firewall_state($state);
    $host = xsw_clean_ssh_host((string)($payload['host'] ?? ''));
    $sessionId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($payload['session_id'] ?? ''));
    $sshPort = max(1, min(65535, (int)($payload['ssh_port'] ?? 22)));
    $mode = (string)($payload['mode'] ?? 'apply');
    if (!in_array($mode, ['apply', 'clear'], true)) {
        $mode = 'apply';
    }
    $enabled = array_key_exists('enabled', $payload) ? !empty($payload['enabled']) : true;
    if (!$enabled && $mode === 'apply') {
        $mode = 'clear';
    }
    $rules = xsw_normalize_firewall_rules(is_array($payload['rules'] ?? null) ? $payload['rules'] : (array)($payload['port_rules'] ?? []));
    if ($mode === 'apply' && !$rules && empty($payload['deny_ping'])) {
        throw new RuntimeException('请至少新增一条安全组规则，或开启禁 ping');
    }
    $ruleScript = xsw_firewall_port_rule_script($rules);
    if (!empty($payload['deny_ping'])) {
        $ruleScript .= "\n" . '"$IPT" -w -A "$CHAIN" -p icmp --icmp-type echo-request -j DROP';
    }
    $ipv6PingScript = !empty($payload['deny_ping'])
        ? 'if [ -n "$IP6T" ]; then "$IP6T" -w -A "$CHAIN6" -p ipv6-icmp --icmpv6-type echo-request -j DROP; fi'
        : ':';
    $persist = !empty($payload['persist']) ? '1' : '0';
    $denyPing = !empty($payload['deny_ping']) ? '1' : '0';
    $remoteScript = <<<'BASH'
set -e
MODE='__MODE__'
SSH_PORT='__SSH_PORT__'
PERSIST='__PERSIST__'
DENY_PING='__DENY_PING__'

if ! command -v iptables >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then apt-get update -y >/dev/null && apt-get install -y iptables >/dev/null
  elif command -v dnf >/dev/null 2>&1; then dnf install -y iptables >/dev/null
  elif command -v yum >/dev/null 2>&1; then yum install -y iptables >/dev/null
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache iptables >/dev/null
  else echo "iptables is required" >&2; exit 12
  fi
fi
IPT="$(command -v iptables)"
IP6T="$(command -v ip6tables 2>/dev/null || true)"
CHAIN="JD_FW"
CHAIN6="JD_FW6"
OLD_CHAIN="XSW_FW"
OLD_CHAIN6="XSW_FW6"
SCRIPT="/usr/local/sbin/xsw-firewall-apply.sh"
SERVICE="/etc/systemd/system/xsw-firewall.service"
SYSCTL_CONF="/etc/sysctl.d/99-xsw-firewall.conf"

remove_rules() {
  while "$IPT" -w -C INPUT -j "$CHAIN" 2>/dev/null; do "$IPT" -w -D INPUT -j "$CHAIN"; done
  "$IPT" -w -F "$CHAIN" 2>/dev/null || true
  "$IPT" -w -X "$CHAIN" 2>/dev/null || true
  while "$IPT" -w -C INPUT -j "$OLD_CHAIN" 2>/dev/null; do "$IPT" -w -D INPUT -j "$OLD_CHAIN"; done
  "$IPT" -w -F "$OLD_CHAIN" 2>/dev/null || true
  "$IPT" -w -X "$OLD_CHAIN" 2>/dev/null || true
  if [ -n "$IP6T" ]; then
    while "$IP6T" -w -C INPUT -j "$CHAIN6" 2>/dev/null; do "$IP6T" -w -D INPUT -j "$CHAIN6"; done
    "$IP6T" -w -F "$CHAIN6" 2>/dev/null || true
    "$IP6T" -w -X "$CHAIN6" 2>/dev/null || true
    while "$IP6T" -w -C INPUT -j "$OLD_CHAIN6" 2>/dev/null; do "$IP6T" -w -D INPUT -j "$OLD_CHAIN6"; done
    "$IP6T" -w -F "$OLD_CHAIN6" 2>/dev/null || true
    "$IP6T" -w -X "$OLD_CHAIN6" 2>/dev/null || true
  fi
}

if [ "$MODE" = "clear" ]; then
  remove_rules
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now xsw-firewall.service >/dev/null 2>&1 || true
    rm -f "$SERVICE"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$SCRIPT"
  if [ -f "$SYSCTL_CONF" ]; then
    rm -f "$SYSCTL_CONF"
    sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.icmp.echo_ignore_all=0 >/dev/null 2>&1 || true
  fi
  echo "JD_FIREWALL_RESULT_BEGIN"
  echo "MODE=clear"
  echo "CHAIN=$CHAIN"
  echo "JD_FIREWALL_RESULT_END"
  exit 0
fi

CLIENT_IP="$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')"

cat > "$SCRIPT" <<EOF
#!/bin/sh
set -e
IPT="\$(command -v iptables)"
IP6T="\$(command -v ip6tables 2>/dev/null || true)"
CHAIN="JD_FW"
CHAIN6="JD_FW6"
OLD_CHAIN="XSW_FW"
OLD_CHAIN6="XSW_FW6"
CLIENT_IP="$CLIENT_IP"
SSH_PORT="$SSH_PORT"
PERSIST="$PERSIST"
DENY_PING="$DENY_PING"
SYSCTL_CONF="$SYSCTL_CONF"
"\$IPT" -w -N "\$CHAIN" 2>/dev/null || true
"\$IPT" -w -F "\$CHAIN"
while "\$IPT" -w -C INPUT -j "\$CHAIN" 2>/dev/null; do "\$IPT" -w -D INPUT -j "\$CHAIN"; done
while "\$IPT" -w -C INPUT -j "\$OLD_CHAIN" 2>/dev/null; do "\$IPT" -w -D INPUT -j "\$OLD_CHAIN"; done
"\$IPT" -w -F "\$OLD_CHAIN" 2>/dev/null || true
"\$IPT" -w -X "\$OLD_CHAIN" 2>/dev/null || true
"\$IPT" -w -I INPUT 1 -j "\$CHAIN"
"\$IPT" -w -A "\$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
if [ -n "\$CLIENT_IP" ]; then "\$IPT" -w -A "\$CHAIN" -p tcp -s "\$CLIENT_IP/32" --dport "\$SSH_PORT" -j ACCEPT; fi
__RULES__
"\$IPT" -w -A "\$CHAIN" -j RETURN
if [ -n "\$IP6T" ]; then
  "\$IP6T" -w -N "\$CHAIN6" 2>/dev/null || true
  "\$IP6T" -w -F "\$CHAIN6"
  while "\$IP6T" -w -C INPUT -j "\$CHAIN6" 2>/dev/null; do "\$IP6T" -w -D INPUT -j "\$CHAIN6"; done
  while "\$IP6T" -w -C INPUT -j "\$OLD_CHAIN6" 2>/dev/null; do "\$IP6T" -w -D INPUT -j "\$OLD_CHAIN6"; done
  "\$IP6T" -w -F "\$OLD_CHAIN6" 2>/dev/null || true
  "\$IP6T" -w -X "\$OLD_CHAIN6" 2>/dev/null || true
  "\$IP6T" -w -I INPUT 1 -j "\$CHAIN6"
  __IPV6_PING_RULES__
  "\$IP6T" -w -A "\$CHAIN6" -j RETURN
fi
if [ "\$DENY_PING" = "1" ]; then
  sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.icmp.echo_ignore_all=1 >/dev/null 2>&1 || true
  if [ "\$PERSIST" = "1" ]; then
    cat > "\$SYSCTL_CONF" <<SYSCTLEOF
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1
SYSCTLEOF
  fi
elif [ -f "\$SYSCTL_CONF" ]; then
  rm -f "\$SYSCTL_CONF"
  sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.icmp.echo_ignore_all=0 >/dev/null 2>&1 || true
fi
EOF
chmod 700 "$SCRIPT"
"$SCRIPT"

if [ "$PERSIST" = "1" ] && command -v systemctl >/dev/null 2>&1; then
  cat > "$SERVICE" <<EOF
[Unit]
Description=3x-ui Network Panel managed firewall rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable xsw-firewall.service >/dev/null 2>&1 || true
fi

echo "JD_FIREWALL_RESULT_BEGIN"
echo "MODE=apply"
echo "CHAIN=$CHAIN"
echo "PERSIST=$PERSIST"
echo "JD_FIREWALL_RESULT_END"
BASH;
    $replacements = [
        '__MODE__' => $mode,
        '__SSH_PORT__' => (string)$sshPort,
        '__RULES__' => $ruleScript,
        '__IPV6_PING_RULES__' => $ipv6PingScript,
        '__PERSIST__' => $persist,
        '__DENY_PING__' => $denyPing,
    ];
    $remoteScript = strtr($remoteScript, $replacements);
    $process = xsw_run_ssh_script($payload, $secret, $remoteScript, 900);
    if ((int)$process['code'] !== 0) {
        $tail = xsw_safe_install_tail($process['stderr'] . "\n" . $process['stdout']);
        throw new RuntimeException('防火墙任务失败，退出码 ' . (int)$process['code'] . ($tail !== '' ? '：' . $tail : ''));
    }
    $policyState = [
        'enabled' => $mode === 'apply',
        'deny_ping' => !empty($payload['deny_ping']),
        'rules' => $rules,
        'persist' => !empty($payload['persist']),
    ];
    $state['firewall']['policy'] = $policyState;
    $results = [
        ['step' => 'ssh firewall', 'server' => $host, 'result' => 'ok'],
        ['step' => $mode === 'clear' ? 'clear managed firewall' : 'apply managed firewall', 'server' => $host, 'result' => 'ok'],
    ];
    $state['last_results']['firewall'] = ['at' => time(), 'host' => $host, 'mode' => $mode, 'payload' => $policyState, 'results' => $results];
    if ($sessionId !== '') {
        $state['firewall']['applies'][$sessionId] = [
            'at' => time(),
            'host' => $host,
            'mode' => $mode,
            'status' => 'done',
            'payload' => $policyState,
            'results' => $results,
        ];
        if (isset($state['firewall']['sessions'][$sessionId]) && is_array($state['firewall']['sessions'][$sessionId])) {
            $state['firewall']['sessions'][$sessionId]['policy'] = $policyState;
            $state['firewall']['sessions'][$sessionId]['last_apply_at'] = time();
            $state['firewall']['sessions'][$sessionId]['last_used_at'] = time();
            $state['firewall']['sessions'][$sessionId]['last_status'] = $mode === 'clear' ? '已清除托管策略' : '策略已应用';
        }
    }
    xsw_save_state($state);
    xsw_log('info', '应用防火墙策略', ['host' => $host, 'mode' => $mode]);
    return $results;
}

function xsw_clean_xray_managed_for_server(array $state, string $serverCode, array $managedInboundTags = []): array
{
    $server = $state['servers'][$serverCode];
    [$config, $testUrl] = xsw_fetch_xray($server);
    if (!empty($config['outbounds']) && is_array($config['outbounds'])) {
        $config['outbounds'] = array_values(array_filter(
            $config['outbounds'],
            fn($out) => !is_array($out) || !xsw_is_managed_tag((string)($out['tag'] ?? ''))
        ));
    }
    if (!empty($config['routing']['rules']) && is_array($config['routing']['rules'])) {
        $config['routing']['rules'] = xsw_strip_managed_rules($config['routing']['rules'], $managedInboundTags);
    }
    xsw_save_xray($server, $config, $testUrl);
    return ['server' => $serverCode, 'cleaned' => true];
}

function xsw_parse_path_input(string $pathText, array $servers): array
{
    $path = xsw_codes_from_path_text($pathText);
    if (count($path) < 2) {
        throw new RuntimeException('链路至少需要连接 2 台资源');
    }
    foreach ($path as $code) {
        if (!isset($servers[$code])) {
            throw new RuntimeException('找不到资源：' . $code);
        }
    }
    if (count(array_unique($path)) !== count($path)) {
        throw new RuntimeException('一条链路里不要重复使用同一台资源');
    }
    return $path;
}

function xsw_next_created_line_id(array $lines): string
{
    $used = array_fill_keys(array_column($lines, 'id'), true);
    for ($i = 1; $i < 1000; $i++) {
        $id = 'line' . $i;
        if (empty($used[$id])) {
            return $id;
        }
    }
    return 'line' . time();
}

function xsw_create_line_and_deploy(array &$state, string $name, string $pathText): array
{
    $path = xsw_parse_path_input($pathText, $state['servers']);
    foreach ($state['lines'] as $line) {
        if (($line['path'] ?? []) === $path) {
            throw new RuntimeException('这条链路已经存在');
        }
    }
    $id = xsw_next_created_line_id($state['lines']);
    $state['lines'][] = [
        'id' => $id,
        'name' => $name !== '' ? $name : ('链路' . (count($state['lines']) + 1)),
        'path' => $path,
    ];
    $results = xsw_deploy($state);
    xsw_log('info', '新建链路并发布', ['line' => $id, 'path' => $path]);
    return ['line_id' => $id, 'results' => $results];
}

function xsw_find_line_index(array $state, string $lineId): int
{
    foreach (($state['lines'] ?? []) as $index => $line) {
        if (($line['id'] ?? '') === $lineId) {
            return (int)$index;
        }
    }
    throw new RuntimeException('找不到链路：' . $lineId);
}

function xsw_update_line_and_deploy(array &$state, string $lineId, string $name, string $pathText, bool $keepEntry = false): array
{
    $index = xsw_find_line_index($state, $lineId);
    $path = xsw_parse_path_input($pathText, $state['servers']);
    $oldPlan = xsw_build_plan($state);
    $oldLine = $state['lines'][$index];
    $results = [];
    $affectedServers = [];
    $oldFirst = (string)($oldLine['path'][0] ?? '');
    $newFirst = (string)($path[0] ?? '');
    if ($keepEntry && $oldFirst !== $newFirst) {
        throw new RuntimeException('入口资源变了，不能保持 VLESS Reality 入口链接。请取消勾选后再提交变更。');
    }
    $newEdgeKeys = [];
    for ($i = 0; $i < count($path) - 1; $i++) {
        $newEdgeKeys[$lineId . ':' . $path[$i] . '>' . $path[$i + 1]] = true;
    }

    $entry = $oldPlan['entries'][$lineId] ?? null;
    if ($entry && !$keepEntry) {
        $affectedServers[$entry['server']] = true;
        $results[] = [
            'step' => 'delete old entry inbound',
            'server' => $entry['server'],
            'line' => $lineId,
            'result' => xsw_delete_inbound($state['servers'][$entry['server']], (int)$entry['port'], (string)$entry['remark']),
        ];
    } elseif ($entry) {
        $affectedServers[$entry['server']] = true;
        $results[] = [
            'step' => 'keep entry inbound',
            'server' => $entry['server'],
            'line' => $lineId,
            'result' => 'kept',
        ];
    }
    foreach ($oldPlan['edges'] as $edge) {
        if ($edge['line_id'] !== $lineId) {
            continue;
        }
        $edgeKey = (string)($edge['key'] ?? ($lineId . ':' . $edge['from'] . '>' . $edge['to']));
        $affectedServers[$edge['from']] = true;
        $affectedServers[$edge['to']] = true;
        if ($keepEntry && isset($newEdgeKeys[$edgeKey])) {
            $results[] = [
                'step' => 'keep relay inbound',
                'server' => $edge['to'],
                'edge' => $edge['from'] . '->' . $edge['to'],
                'result' => 'kept',
            ];
            continue;
        }
        $results[] = [
            'step' => 'delete old relay inbound',
            'server' => $edge['to'],
            'edge' => $edge['from'] . '->' . $edge['to'],
            'result' => xsw_delete_inbound($state['servers'][$edge['to']], (int)$edge['port'], (string)$edge['remark']),
        ];
        unset($state['managed']['links'][$edgeKey]);
    }

    if (!$keepEntry) {
        unset($state['managed']['entries'][$lineId]);
    }
    foreach (array_keys($state['managed']['links'] ?? []) as $key) {
        if (str_starts_with($key, $lineId . ':') && (!$keepEntry || !isset($newEdgeKeys[$key]))) {
            unset($state['managed']['links'][$key]);
        }
    }

    $state['lines'][$index] = [
        'id' => $lineId,
        'name' => $name !== '' ? $name : (string)($oldLine['name'] ?? $lineId),
        'path' => $path,
    ];

    foreach ($path as $code) {
        $affectedServers[$code] = true;
    }
    $deployResults = xsw_deploy($state);
    $results = array_merge($results, $deployResults);
    $state['last_results']['update'] = ['at' => time(), 'line' => $lineId, 'results' => $results];
    xsw_save_state($state);
    xsw_log('info', '拓扑变更并发布', ['line' => $lineId, 'oldPath' => $oldLine['path'] ?? [], 'newPath' => $path, 'keepEntry' => $keepEntry]);
    return $results;
}

function xsw_delete_line_and_cleanup(array &$state, string $lineId): array
{
    if (!$state['lines']) {
        throw new RuntimeException('没有可下线的链路');
    }
    $oldPlan = xsw_build_plan($state);
    $line = null;
    foreach ($state['lines'] as $candidate) {
        if ($candidate['id'] === $lineId) {
            $line = $candidate;
            break;
        }
    }
    if (!$line) {
        unset($state['managed']['entries'][$lineId]);
        foreach (array_keys($state['managed']['links'] ?? []) as $key) {
            if (str_starts_with($key, $lineId . ':')) {
                unset($state['managed']['links'][$key]);
            }
        }
        $results = [
            ['step' => 'delete line', 'line' => $lineId, 'result' => 'already removed'],
        ];
        $state['last_results']['delete'] = ['at' => time(), 'line' => $lineId, 'results' => $results];
        xsw_save_state($state);
        xsw_log('info', '链路已不存在，重复下线按完成处理', ['line' => $lineId]);
        return $results;
        throw new RuntimeException('找不到链路：' . $lineId);
    }

    $results = [];
    $affectedServers = [];
    $managedInboundTags = [];
    foreach ($oldPlan['entries'] as $entry) {
        $managedInboundTags[] = $entry['inbound_tag'];
    }
    foreach ($oldPlan['edges'] as $edge) {
        $managedInboundTags[] = $edge['inbound_tag'];
    }

    $entry = $oldPlan['entries'][$lineId] ?? null;
    if ($entry) {
        $affectedServers[$entry['server']] = true;
        $results[] = [
            'step' => 'delete entry inbound',
            'server' => $entry['server'],
            'line' => $lineId,
            'result' => xsw_delete_inbound($state['servers'][$entry['server']], (int)$entry['port'], (string)$entry['remark']),
        ];
    }

    foreach ($oldPlan['edges'] as $edge) {
        if ($edge['line_id'] !== $lineId) {
            continue;
        }
        $affectedServers[$edge['from']] = true;
        $affectedServers[$edge['to']] = true;
        $results[] = [
            'step' => 'delete relay inbound',
            'server' => $edge['to'],
            'edge' => $edge['from'] . '->' . $edge['to'],
            'result' => xsw_delete_inbound($state['servers'][$edge['to']], (int)$edge['port'], (string)$edge['remark']),
        ];
    }

    $state['lines'] = array_values(array_filter(
        $state['lines'],
        fn($candidate) => $candidate['id'] !== $lineId
    ));
    unset($state['managed']['entries'][$lineId]);
    foreach (array_keys($state['managed']['links'] ?? []) as $key) {
        if (str_starts_with($key, $lineId . ':')) {
            unset($state['managed']['links'][$key]);
        }
    }
    foreach ($state['lines'] as $remainingLine) {
        foreach ($remainingLine['path'] as $code) {
            $affectedServers[$code] = true;
        }
    }

    if ($state['lines']) {
        $newPlan = xsw_build_plan($state);
        foreach (array_keys($affectedServers) as $code) {
            if (isset($state['servers'][$code])) {
                $results[] = ['step' => 'xray template cleanup', 'result' => xsw_apply_xray_for_server($state, $newPlan, $code)];
            }
        }
    } else {
        foreach (array_keys($affectedServers) as $code) {
            if (isset($state['servers'][$code])) {
                $results[] = ['step' => 'xray template cleanup', 'result' => xsw_clean_xray_managed_for_server($state, $code, array_values(array_unique($managedInboundTags)))];
            }
        }
    }

    foreach (array_keys($affectedServers) as $code) {
        if (isset($state['servers'][$code])) {
            xsw_restart_xray($state['servers'][$code]);
            $results[] = ['step' => 'restart xray', 'server' => $code, 'result' => 'ok'];
        }
    }
    foreach (array_keys($affectedServers) as $code) {
        if (isset($state['servers'][$code])) {
            xsw_restart_panel($state['servers'][$code]);
            $results[] = ['step' => 'restart panel', 'server' => $code, 'result' => 'ok'];
        }
    }

    $state['last_results']['delete'] = ['at' => time(), 'line' => $lineId, 'results' => $results];
    xsw_save_state($state);
    xsw_log('info', '链路下线并清理配置', ['line' => $lineId, 'results' => $results]);
    return $results;
}

function xsw_purge_all_managed(array &$state): array
{
    $results = [];
    $oldPlan = ['entries' => [], 'edges' => []];
    try {
        if (!empty($state['lines']) && !empty($state['servers'])) {
            $oldPlan = xsw_build_plan($state);
        }
    } catch (Throwable $e) {
        $results[] = ['step' => 'build old plan', 'error' => $e->getMessage()];
    }
    $managedInboundTags = [];
    foreach ($oldPlan['entries'] as $entry) {
        $managedInboundTags[] = $entry['inbound_tag'];
    }
    foreach ($oldPlan['edges'] as $edge) {
        $managedInboundTags[] = $edge['inbound_tag'];
    }
    $managedInboundTags = array_values(array_unique($managedInboundTags));

    foreach (($state['servers'] ?? []) as $code => $server) {
        try {
            $list = xsw_api($server, 'GET', '/panel/api/inbounds/list');
            foreach (($list['obj'] ?? []) as $item) {
                $remark = (string)($item['remark'] ?? '');
                $id = (int)($item['id'] ?? 0);
                if ($id > 0 && xsw_is_managed_remark($remark)) {
                    xsw_api($server, 'POST', '/panel/api/inbounds/del/' . $id);
                    $results[] = ['step' => 'delete managed inbound', 'server' => $code, 'remark' => $remark, 'result' => 'deleted'];
                }
            }
            $results[] = ['step' => 'clean xray template', 'result' => xsw_clean_xray_managed_for_server($state, (string)$code, $managedInboundTags)];
            xsw_restart_xray($server);
            $results[] = ['step' => 'restart xray', 'server' => $code, 'result' => 'ok'];
            xsw_restart_panel($server);
            $results[] = ['step' => 'restart panel', 'server' => $code, 'result' => 'ok'];
        } catch (Throwable $e) {
            $results[] = ['step' => 'purge server', 'server' => $code, 'error' => $e->getMessage()];
            xsw_log('error', '清理资源失败：' . $e->getMessage(), ['server' => $code]);
        }
    }
    $state['lines'] = [];
    $state['managed']['entries'] = [];
    $state['managed']['links'] = [];
    xsw_ensure_standalone_state($state);
    $state['standalone']['entries'] = [];
    $state['scheduler']['active_line_id'] = '';
    $state['scheduler']['enabled'] = false;
    $state['scheduler']['next_switch_at'] = 0;
    if (!empty($state['jobs']) && is_array($state['jobs'])) {
        foreach ($state['jobs'] as &$job) {
            if (($job['status'] ?? '') === 'pending') {
                $job['status'] = 'cancelled';
                $job['progress'] = '已取消';
                $job['cancelled_at'] = time();
            }
        }
        unset($job);
    }
    $state['last_results']['purge'] = ['at' => time(), 'results' => $results];
    xsw_save_state($state);
    xsw_log('info', '清空托管节点', ['results' => $results]);
    return $results;
}

function xsw_results_error_count(array $results): int
{
    $count = 0;
    array_walk_recursive($results, function ($value, $key) use (&$count): void {
        if ($key === 'error' && $value !== '') {
            $count++;
        }
    });
    return $count;
}

function xsw_job_step_results(mixed $result): array
{
    if (is_array($result) && isset($result['results']) && is_array($result['results'])) {
        return $result['results'];
    }
    return is_array($result) ? $result : [];
}

function xsw_add_job(array &$state, string $type, int $runAt, array $payload, string $source): array
{
    if (!isset($state['jobs']) || !is_array($state['jobs'])) {
        $state['jobs'] = [];
    }
    $job = [
        'id' => 'job_' . date('YmdHis') . '_' . xsw_random_hex(3),
        'type' => $type,
        'run_at' => $runAt,
        'status' => 'pending',
        'payload' => $payload,
        'source' => $source,
        'progress' => $runAt <= time() ? '等待调度执行' : '等待计划时间',
        'created_at' => time(),
    ];
    $state['jobs'][] = $job;
    xsw_save_state($state);
    xsw_log('info', $source === 'manual' ? '新增执行任务' : '新增计划任务', ['job' => $job]);
    return $job;
}

function xsw_enqueue_job(array &$state, string $type, array $payload): array
{
    return xsw_add_job($state, $type, time(), $payload, 'manual');
}

function xsw_enqueue_unique_firewall_job(array &$state, array $payload): array
{
    if (!isset($state['jobs']) || !is_array($state['jobs'])) {
        $state['jobs'] = [];
    }
    $sessionId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($payload['session_id'] ?? ''));
    if ($sessionId === '') {
        return ['job' => xsw_enqueue_job($state, 'apply_firewall', $payload), 'updated' => false];
    }

    $pendingIndex = null;
    foreach ($state['jobs'] as $index => $job) {
        if (($job['type'] ?? '') !== 'apply_firewall' || ($job['status'] ?? '') !== 'pending') {
            continue;
        }
        $candidatePayload = is_array($job['payload'] ?? null) ? $job['payload'] : [];
        if (preg_replace('/[^A-Za-z0-9_-]/', '', (string)($candidatePayload['session_id'] ?? '')) !== $sessionId) {
            continue;
        }
        if ($pendingIndex === null) {
            $pendingIndex = $index;
            continue;
        }
        $state['jobs'][$index]['status'] = 'cancelled';
        $state['jobs'][$index]['progress'] = '已合并到最新防火墙任务';
        $state['jobs'][$index]['cancelled_at'] = time();
        xsw_delete_job_secret((string)($job['id'] ?? ''));
    }
    if ($pendingIndex !== null) {
        $state['jobs'][$pendingIndex]['payload'] = $payload;
        $state['jobs'][$pendingIndex]['run_at'] = time();
        $state['jobs'][$pendingIndex]['progress'] = '等待调度执行，已更新为最新规则';
        $state['jobs'][$pendingIndex]['updated_at'] = time();
        xsw_save_state($state);
        xsw_log('info', '更新等待中的防火墙任务', ['job' => $state['jobs'][$pendingIndex]['id'] ?? '', 'session' => $sessionId]);
        return ['job' => $state['jobs'][$pendingIndex], 'updated' => true];
    }

    return ['job' => xsw_enqueue_job($state, 'apply_firewall', $payload), 'updated' => false];
}

function xsw_schedule_job(array &$state, string $type, int $runAt, array $payload): array
{
    if ($runAt <= time()) {
        throw new RuntimeException('计划时间必须晚于现在');
    }
    return xsw_add_job($state, $type, $runAt, $payload, 'scheduled');
}

function xsw_kick_worker(): void
{
    $php = '/usr/bin/php';
    if (!is_file($php)) {
        $php = PHP_BINARY;
    }
    $cron = __DIR__ . '/cron.php';
    if (!is_file($cron) || !function_exists('exec')) {
        return;
    }
    $cmd = 'nohup ' . escapeshellarg($php) . ' ' . escapeshellarg($cron) . ' >/dev/null 2>&1 &';
    try {
        @exec($cmd);
    } catch (Throwable $e) {
        xsw_log('error', '调度唤醒失败：' . $e->getMessage());
    }
}

function xsw_parse_schedule_time(string $value): int
{
    $value = trim($value);
    if ($value === '') {
        throw new RuntimeException('请填写计划时间');
    }
    $ts = strtotime($value);
    if ($ts === false) {
        throw new RuntimeException('计划时间格式不正确');
    }
    return $ts;
}

function xsw_cancel_job(array &$state, string $jobId): void
{
    if (empty($state['jobs']) || !is_array($state['jobs'])) {
        throw new RuntimeException('找不到任务：' . $jobId);
    }
    foreach ($state['jobs'] as &$job) {
        if (($job['id'] ?? '') === $jobId) {
            if (($job['status'] ?? '') !== 'pending') {
                throw new RuntimeException('只能取消等待中的任务');
            }
            $job['status'] = 'cancelled';
            $job['progress'] = '已取消';
            $job['cancelled_at'] = time();
            xsw_delete_job_secret($jobId);
            xsw_save_state($state);
            xsw_log('info', '取消任务', ['jobId' => $jobId]);
            return;
        }
    }
    unset($job);
    throw new RuntimeException('找不到任务：' . $jobId);
}

function xsw_run_job(array &$state, array $job): array
{
    $payload = $job['payload'] ?? [];
    return match ((string)($job['type'] ?? '')) {
        'create_line' => xsw_create_line_and_deploy($state, (string)($payload['name'] ?? ''), (string)($payload['path'] ?? '')),
        'update_line' => xsw_update_line_and_deploy($state, (string)($payload['line_id'] ?? ''), (string)($payload['name'] ?? ''), (string)($payload['path'] ?? ''), !empty($payload['keep_entry'])),
        'delete_line' => xsw_delete_line_and_cleanup($state, (string)($payload['line_id'] ?? '')),
        'create_standalone' => xsw_create_standalone_and_deploy($state, (string)($payload['name'] ?? ''), (string)($payload['server'] ?? ''), (string)($payload['protocol'] ?? 'vless'), (int)($payload['port'] ?? 0)),
        'delete_standalone' => xsw_delete_standalone_and_cleanup($state, (string)($payload['entry_id'] ?? '')),
        'install_3xui' => xsw_install_3xui_and_import($state, is_array($payload) ? $payload : [], xsw_load_job_secret((string)($job['id'] ?? ''))),
        'read_firewall' => xsw_read_firewall_state($state, is_array($payload) ? $payload : [], xsw_load_job_secret((string)($job['id'] ?? ''))),
        'verify_firewall_ssh' => xsw_verify_firewall_session($state, is_array($payload) ? $payload : [], xsw_load_job_secret((string)($job['id'] ?? ''))),
        'apply_firewall' => xsw_apply_firewall_policy($state, is_array($payload) ? $payload : [], xsw_load_job_secret((string)($job['id'] ?? ''))),
        default => throw new RuntimeException('未知任务类型：' . (string)($job['type'] ?? '')),
    };
}

function xsw_cron_tick(): array
{
    $state = xsw_load_state();
    $ran = [];
    $now = time();
    foreach (($state['jobs'] ?? []) as $index => $job) {
        if (($job['status'] ?? '') !== 'pending' || (int)($job['run_at'] ?? 0) > $now) {
            continue;
        }
        $state['jobs'][$index]['status'] = 'running';
        $state['jobs'][$index]['started_at'] = time();
        $jobType = (string)($job['type'] ?? '');
        $state['jobs'][$index]['progress'] = match ($jobType) {
            'install_3xui' => '执行中：正在 SSH 安装 3x-ui',
            'verify_firewall_ssh' => '执行中：正在 SSH 校验',
            'read_firewall' => '执行中：正在 SSH 读取防火墙',
            'apply_firewall' => '执行中：正在 SSH 应用防火墙策略',
            default => '执行中：正在调用 3x-ui API',
        };
        xsw_save_state($state);
        try {
            $result = xsw_run_job($state, $job);
            $steps = xsw_job_step_results($result);
            $errors = xsw_results_error_count($steps);
            $state['jobs'][$index]['status'] = 'done';
            $state['jobs'][$index]['finished_at'] = time();
            $state['jobs'][$index]['result_count'] = count($steps);
            $state['jobs'][$index]['result_errors'] = $errors;
            $state['jobs'][$index]['progress'] = '完成：' . count($steps) . ' 个步骤' . ($errors ? '，' . $errors . ' 个失败' : '');
            if ((string)($job['type'] ?? '') === 'install_3xui' && is_array($result) && isset($result['panel']) && is_array($result['panel'])) {
                $state['jobs'][$index]['install_result'] = $result['panel'];
                $state['jobs'][$index]['install_text'] = (string)($result['panel_text'] ?? xsw_format_panel_info($result['panel']));
            }
            xsw_delete_job_secret((string)($job['id'] ?? ''));
            $ran[] = ['job' => $job['id'] ?? '', 'type' => $job['type'] ?? '', 'status' => 'done'];
            xsw_save_state($state);
        } catch (Throwable $e) {
            $state = xsw_load_state();
            $payload = is_array($job['payload'] ?? null) ? $job['payload'] : [];
            $sessionId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($payload['session_id'] ?? ''));
            if (in_array((string)($job['type'] ?? ''), ['verify_firewall_ssh', 'read_firewall', 'apply_firewall'], true) && $sessionId !== '') {
                xsw_ensure_firewall_state($state);
                if (isset($state['firewall']['sessions'][$sessionId]) && is_array($state['firewall']['sessions'][$sessionId])) {
                    $state['firewall']['sessions'][$sessionId]['last_status'] = '失败：' . $e->getMessage();
                    $state['firewall']['sessions'][$sessionId]['last_used_at'] = time();
                }
                if (isset($state['firewall']['applies'][$sessionId]) && is_array($state['firewall']['applies'][$sessionId])) {
                    $state['firewall']['applies'][$sessionId]['status'] = 'failed';
                    $state['firewall']['applies'][$sessionId]['error'] = $e->getMessage();
                    $state['firewall']['applies'][$sessionId]['at'] = time();
                }
            }
            foreach (($state['jobs'] ?? []) as $failedIndex => $candidate) {
                if (($candidate['id'] ?? '') === ($job['id'] ?? '')) {
                    $state['jobs'][$failedIndex]['status'] = 'failed';
                    $state['jobs'][$failedIndex]['finished_at'] = time();
                    $state['jobs'][$failedIndex]['error'] = $e->getMessage();
                    $state['jobs'][$failedIndex]['progress'] = '失败：' . $e->getMessage();
                    break;
                }
            }
            xsw_delete_job_secret((string)($job['id'] ?? ''));
            xsw_save_state($state);
            xsw_log('error', '任务失败：' . $e->getMessage(), ['jobId' => $job['id'] ?? '', 'type' => $job['type'] ?? '']);
            throw $e;
        }
    }
    if ($ran) {
        return ['ran' => true, 'jobs' => $ran];
    }
    $pending = array_values(array_filter(($state['jobs'] ?? []), fn($job) => ($job['status'] ?? '') === 'pending'));
    usort($pending, fn($a, $b) => (int)($a['run_at'] ?? 0) <=> (int)($b['run_at'] ?? 0));
    return ['ran' => false, 'reason' => 'waiting', 'next' => $pending[0]['run_at'] ?? 0];
}

function xsw_entry_links(array $state): array
{
    try {
        $plan = xsw_build_plan($state);
    } catch (Throwable) {
        return [];
    }
    $links = [];
    foreach ($plan['entries'] as $entry) {
        $server = $state['servers'][$entry['server']] ?? null;
        if (!$server || empty($entry['public_key'])) {
            continue;
        }
        $params = [
            'encryption' => 'none',
            'security' => 'reality',
            'flow' => 'xtls-rprx-vision',
            'sni' => $entry['sni'],
            'fp' => $entry['fingerprint'],
            'pbk' => $entry['public_key'],
            'sid' => $entry['short_id'],
            'type' => 'tcp',
            'headerType' => 'none',
            'spx' => $entry['spider_x'],
        ];
        $query = http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        $name = rawurlencode((string)$entry['line_name']);
        $links[$entry['line_id']] = [
            'name' => $entry['line_name'],
            'server' => $entry['server'],
            'url' => 'vless://' . $entry['uuid'] . '@' . xsw_public_host($server) . ':' . (int)$entry['port'] . '?' . $query . '#' . $name,
        ];
    }
    return $links;
}

function xsw_standalone_client_infos(array $state): array
{
    $infos = [];
    foreach (($state['standalone']['entries'] ?? []) as $entry) {
        $server = $state['servers'][$entry['server'] ?? ''] ?? null;
        if (!$server) {
            continue;
        }
        $host = xsw_public_host($server);
        $protocol = (string)($entry['protocol'] ?? 'vless');
        $info = [
            'id' => (string)($entry['id'] ?? ''),
            'name' => (string)($entry['name'] ?? $entry['id'] ?? ''),
            'server' => (string)($entry['server'] ?? ''),
            'server_label' => xsw_server_label($server),
            'protocol' => $protocol,
            'host' => $host,
            'port' => (int)($entry['port'] ?? 0),
            'url' => '',
        ];
        if ($protocol === 'socks5') {
            $user = (string)($entry['username'] ?? '');
            $pass = (string)($entry['password'] ?? '');
            $info['username'] = $user;
            $info['password'] = $pass;
            $info['url'] = 'socks5://' . rawurlencode($user) . ':' . rawurlencode($pass) . '@' . $host . ':' . (int)$entry['port'];
        } elseif (!empty($entry['public_key'])) {
            $params = [
                'encryption' => 'none',
                'security' => 'reality',
                'flow' => 'xtls-rprx-vision',
                'sni' => (string)($entry['sni'] ?? 'www.cloudflare.com'),
                'fp' => (string)($entry['fingerprint'] ?? 'chrome'),
                'pbk' => (string)$entry['public_key'],
                'sid' => (string)($entry['short_id'] ?? ''),
                'type' => 'tcp',
                'headerType' => 'none',
                'spx' => (string)($entry['spider_x'] ?? '/'),
            ];
            $query = http_build_query($params, '', '&', PHP_QUERY_RFC3986);
            $name = rawurlencode((string)$info['name']);
            $info['url'] = 'vless://' . (string)($entry['uuid'] ?? '') . '@' . $host . ':' . (int)$entry['port'] . '?' . $query . '#' . $name;
        }
        $infos[$info['id']] = $info;
    }
    return $infos;
}

function xsw_format_time(int $ts): string
{
    return $ts > 0 ? date('Y-m-d H:i:s', $ts) : '-';
}

function xsw_mask_token(string $token): string
{
    if (strlen($token) <= 12) {
        return str_repeat('*', strlen($token));
    }
    return substr($token, 0, 4) . str_repeat('*', max(4, strlen($token) - 8)) . substr($token, -4);
}
