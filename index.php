<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
xsw_bootstrap();
xsw_require_login();

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$state = xsw_load_state();
xsw_ensure_pending_firewall_verify_jobs($state);

function xsw_flash(string $type, string $message): void
{
    $_SESSION['xsw_flash'][] = ['type' => $type, 'message' => $message];
}

function xsw_flash_results(string $message, array $results): void
{
    $errors = xsw_results_error_count($results);
    if ($errors > 0) {
        xsw_flash('err', $message . '，其中 ' . $errors . ' 个步骤异常，详情看审计日志');
        return;
    }
    xsw_flash('ok', $message);
}

function xsw_job_type_label(string $type): string
{
    return match ($type) {
        'create_line' => '链路新建',
        'update_line' => '拓扑变更',
        'delete_line' => '链路下线',
        'create_standalone' => '单节点开通',
        'delete_standalone' => '单节点下线',
        'install_3xui' => '面板安装',
        'verify_firewall_ssh' => 'SSH 校验',
        'apply_firewall' => '防火墙策略',
        default => $type,
    };
}

function xsw_job_status_label(string $status): string
{
    return match ($status) {
        'pending' => '待处理',
        'running' => '处理中',
        'done' => '完成',
        'failed' => '异常',
        'cancelled' => '已取消',
        default => $status,
    };
}

function xsw_job_status_class(string $status): string
{
    return match ($status) {
        'running', 'done' => 'status-ok',
        'failed' => 'status-err',
        default => '',
    };
}

function xsw_job_payload_summary(array $job): string
{
    $payload = is_array($job['payload'] ?? null) ? $job['payload'] : [];
    return match ((string)($job['type'] ?? '')) {
        'create_line' => trim((string)($payload['name'] ?? '新链路')) . ' · ' . (string)($payload['path'] ?? ''),
        'update_line' => (string)($payload['line_id'] ?? '') . ' · ' . (string)($payload['path'] ?? '') . (!empty($payload['keep_entry']) ? ' · 保持入口' : ''),
        'delete_line' => '下线 ' . (string)($payload['line_id'] ?? ''),
        'create_standalone' => trim((string)($payload['name'] ?? '单节点')) . ' · ' . (string)($payload['server'] ?? '') . ' · ' . ((string)($payload['protocol'] ?? 'vless') === 'socks5' ? 'SOCKS5' : 'VLESS Reality') . ' · ' . (string)($payload['port'] ?? ''),
        'delete_standalone' => '下线 ' . (string)($payload['entry_id'] ?? ''),
        'install_3xui' => trim((string)($payload['name'] ?? '新面板')) . ' · ' . (string)($payload['host'] ?? '') . ':' . (string)($payload['ssh_port'] ?? '22') . ' · ' . (string)($payload['ssh_user'] ?? 'root'),
        'verify_firewall_ssh' => '校验 ' . (string)($payload['host'] ?? '') . ':' . (string)($payload['ssh_port'] ?? '22') . ' · ' . (string)($payload['ssh_user'] ?? 'root'),
        'apply_firewall' => xsw_firewall_payload_summary($payload),
        default => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    };
}

function xsw_firewall_rules_from_post(array $post): array
{
    $ids = (array)($post['firewall_rule_id'] ?? []);
    $protocols = (array)($post['firewall_rule_protocol'] ?? []);
    $portsRows = (array)($post['firewall_rule_port'] ?? []);
    $policies = (array)($post['firewall_rule_policy'] ?? []);
    $sources = (array)($post['firewall_rule_source'] ?? []);
    $remarks = (array)($post['firewall_rule_remark'] ?? []);
    $enabledRows = (array)($post['firewall_rule_enabled'] ?? []);
    $rules = [];
    $max = max(count($ids), count($protocols), count($portsRows), count($policies), count($sources), count($remarks));
    for ($i = 0; $i < $max; $i++) {
        $ports = trim((string)($portsRows[$i] ?? ''));
        $source = trim((string)($sources[$i] ?? ''));
        $remark = trim((string)($remarks[$i] ?? ''));
        if ($ports === '' && $source === '' && $remark === '') {
            continue;
        }
        $rules[] = [
            'id' => (string)($ids[$i] ?? ''),
            'protocol' => (string)($protocols[$i] ?? 'tcp'),
            'ports' => xsw_parse_firewall_ports($ports),
            'policy' => (string)($policies[$i] ?? 'allow'),
            'sources' => xsw_parse_firewall_sources($source),
            'remark' => $remark,
            'enabled' => in_array((string)$i, array_map('strval', $enabledRows), true),
            'updated_at' => time(),
        ];
    }
    return xsw_normalize_firewall_rules($rules);
}

function xsw_firewall_status_meta(string $status, bool $enabled): array
{
    if (str_starts_with($status, '失败')) {
        return ['应用失败', 'status-err'];
    }
    return match ($status) {
        '等待应用' => ['等待应用', ''],
        '等待清除' => ['等待清除', ''],
        '策略已应用' => ['已生效', 'status-ok'],
        '已清除 JD 策略' => ['已清除', ''],
        default => [$enabled ? '正常' : '停用', $enabled ? 'status-ok' : ''],
    };
}

function xsw_nav_icon(string $name): string
{
    $attrs = 'class="nav-icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
    $paths = match ($name) {
        'grid' => '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>',
        'database' => '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
        'download' => '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/>',
        'shield' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'route' => '<circle cx="6" cy="19" r="3"/><circle cx="18" cy="5" r="3"/><path d="M9 19h3a4 4 0 0 0 0-8h-1a4 4 0 0 1 0-8h4"/>',
        'plug' => '<path d="M9 7V2"/><path d="M15 7V2"/><path d="M7 7h10v4a5 5 0 0 1-10 0V7z"/><path d="M12 16v6"/>',
        'clock' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'rocket' => '<path d="M4.5 16.5c-1 1-1.5 3-1.5 4.5 1.5 0 3.5-.5 4.5-1.5"/><path d="M9 15 4 20"/><path d="M14 4c3 0 5 2 5 5 0 5-6 10-10 10l-4-4C5 10 9 4 14 4z"/><path d="M15 9h.01"/>',
        'settings' => '<path d="M12 15.5A3.5 3.5 0 1 0 12 8a3.5 3.5 0 0 0 0 7.5z"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2 3.5-.2-.1a1.7 1.7 0 0 0-2 .2l-.3.2-3.8-2.2-.1-.4a1.7 1.7 0 0 0-1.4-1.1H9.7L7.8 13.5l.2-.3a1.7 1.7 0 0 0 0-2.1l-.2-.3 1.9-3.5h.4a1.7 1.7 0 0 0 1.4-1.1l.1-.4 3.8-2.2.3.2a1.7 1.7 0 0 0 2 .2l.2-.1 2 3.5-.1.1a1.7 1.7 0 0 0-.3 1.9l.1.4v4.4l-.2.8z"/>',
        'file' => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h6"/>',
        default => '<circle cx="12" cy="12" r="9"/>',
    };
    return '<svg ' . $attrs . '>' . $paths . '</svg>';
}

function xsw_validated_line_payload(array $state, string $name, string $pathText): array
{
    $name = trim($name);
    if ($name === '') {
        throw new RuntimeException('请填写链路名称');
    }
    $path = xsw_parse_path_input($pathText, $state['servers']);
    return [
        'name' => $name,
        'path' => implode('>', $path),
    ];
}

function xsw_redirect(string $page = '', string $fragment = ''): void
{
    $target = strtok((string)$_SERVER['REQUEST_URI'], '?');
    if ($page !== '') {
        $target .= '?page=' . rawurlencode($page);
    }
    if ($fragment !== '') {
        $target .= '#' . rawurlencode($fragment);
    }
    header('Location: ' . $target);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');
    $redirectPage = '';
    $redirectFragment = '';
    if (in_array($action, ['import_3xui_blocks', 'add_server', 'update_server', 'delete_server', 'test_one_server', 'test_servers'], true)) {
        $redirectPage = 'servers';
    }
    if (in_array($action, ['change_password'], true)) {
        $redirectPage = 'settings';
    }
    $actionPageMap = [
        'create_line' => 'lines',
        'schedule_create_line' => 'lines',
        'update_line' => 'lines',
        'schedule_update_line' => 'lines',
        'delete_line' => 'lines',
        'schedule_delete_line' => 'lines',
        'create_standalone' => 'singles',
        'delete_standalone' => 'singles',
        'install_3xui' => 'installer',
        'mark_install_copied' => 'installer',
        'clear_install_results' => 'installer',
        'firewall_connect' => 'firewall',
        'firewall_connect_assets' => 'firewall',
        'firewall_select' => 'firewall',
        'firewall_exit_active' => 'firewall',
        'firewall_forget' => 'firewall',
        'apply_firewall' => 'firewall',
        'cancel_job' => 'jobs',
        'clear_finished_jobs' => 'jobs',
    ];
    if (isset($actionPageMap[$action])) {
        $redirectPage = $actionPageMap[$action];
    }
    if (in_array($action, ['mark_all_logs_read', 'mark_log_read', 'mark_log_unread', 'delete_log', 'delete_read_logs', 'clear_logs'], true)) {
        $redirectPage = 'logs';
    }
    try {
        if ($action === 'logout') {
            unset($_SESSION['xsw_ok']);
            xsw_redirect();
        }
        if ($action === 'import_3xui_blocks') {
            $servers = xsw_parse_3xui_import((string)($_POST['xui_import_text'] ?? ''), $state['servers'] ?? []);
            $purgeResults = [];
            if (!empty($_POST['purge_before_import'])) {
                $purgeResults = xsw_purge_all_managed($state);
            }
            foreach ($servers as $code => $server) {
                $state['servers'][$code] = $server;
            }
            if (!empty($state['lines'])) {
                xsw_validate_topology($state);
            }
            xsw_save_state($state);
            xsw_flash_results('已导入/更新 ' . count($servers) . ' 台资源' . ($purgeResults ? '，并已先清空旧链路' : ''), $purgeResults);
        } elseif ($action === 'add_server') {
            $server = xsw_normalize_server($_POST);
            if (isset($state['servers'][$server['code']])) {
                throw new RuntimeException('资源编号已存在：' . $server['code']);
            }
            $state['servers'][$server['code']] = $server;
            xsw_save_state($state);
            xsw_flash('ok', '资源已新增：' . $server['code']);
        } elseif ($action === 'update_server') {
            $code = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['server_code'] ?? '')));
            if ($code === '' || !isset($state['servers'][$code])) {
                throw new RuntimeException('找不到资源：' . $code);
            }
            $input = $_POST;
            $input['code'] = $code;
            if (trim((string)($input['access_url'] ?? '')) === '') {
                $input['access_url'] = $state['servers'][$code]['access_url'] ?? '';
            }
            if (trim((string)($input['api_token'] ?? '')) === '') {
                $input['api_token'] = $state['servers'][$code]['api_token'] ?? '';
            }
            $state['servers'][$code] = xsw_normalize_server($input);
            if (!empty($state['lines'])) {
                xsw_validate_topology($state);
            }
            xsw_save_state($state);
            xsw_flash('ok', '资源已保存：' . $code);
        } elseif ($action === 'delete_server') {
            $code = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['server_code'] ?? '')));
            if ($code === '' || !isset($state['servers'][$code])) {
                throw new RuntimeException('找不到资源：' . $code);
            }
            $usage = xsw_server_usage($state, $code);
            if ($usage) {
                throw new RuntimeException('资源 ' . $code . ' 正在使用中：' . implode('、', $usage) . '。先变更/下线链路后再移除资源。');
            }
            unset($state['servers'][$code]);
            xsw_save_state($state);
            xsw_flash('ok', '资源已从控制台移除：' . $code);
        } elseif ($action === 'test_one_server') {
            $code = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['server_code'] ?? '')));
            if ($code === '' || !isset($state['servers'][$code])) {
                throw new RuntimeException('找不到资源：' . $code);
            }
            $checkedAt = time();
            try {
                $result = xsw_test_server($state['servers'][$code]);
            } catch (Throwable $e) {
                $result = ['ok' => false, 'error' => $e->getMessage()];
            }
            $result['checked_at'] = $checkedAt;
            $state['last_results']['test']['at'] = $checkedAt;
            $state['last_results']['test']['results'][$code] = $result;
            xsw_save_state($state);
            xsw_flash('ok', '资源检测完成：' . $code);
        } elseif ($action === 'test_servers') {
            $results = [];
            $checkedAt = time();
            foreach ($state['servers'] as $code => $server) {
                try {
                    $result = xsw_test_server($server);
                } catch (Throwable $e) {
                    $result = ['ok' => false, 'error' => $e->getMessage()];
                }
                $result['checked_at'] = $checkedAt;
                $results[$code] = $result;
            }
            $state['last_results']['test'] = ['at' => $checkedAt, 'results' => $results];
            xsw_save_state($state);
            xsw_flash('ok', '连通性检测完成');
        } elseif ($action === 'create_line') {
            $linePayload = xsw_validated_line_payload($state, (string)($_POST['new_line_name'] ?? ''), (string)($_POST['new_line_path'] ?? ''));
            $job = xsw_enqueue_job($state, 'create_line', [
                'name' => $linePayload['name'],
                'path' => $linePayload['path'],
            ]);
            xsw_kick_worker();
            $redirectPage = 'lines';
            xsw_flash('ok', '已提交链路新建任务：' . $job['id']);
        } elseif ($action === 'schedule_create_line') {
            $linePayload = xsw_validated_line_payload($state, (string)($_POST['new_line_name'] ?? ''), (string)($_POST['new_line_path'] ?? ''));
            $job = xsw_schedule_job($state, 'create_line', xsw_parse_schedule_time((string)($_POST['new_line_run_at'] ?? '')), [
                'name' => $linePayload['name'],
                'path' => $linePayload['path'],
            ]);
            $redirectPage = 'lines';
            xsw_flash('ok', '已创建计划新建任务：' . $job['id']);
        } elseif ($action === 'update_line') {
            $lineId = (string)($_POST['line_id'] ?? '');
            if (!xsw_line_exists($state, $lineId)) {
                throw new RuntimeException('找不到链路：' . $lineId);
            }
            $linePayload = xsw_validated_line_payload($state, (string)($_POST['line_name'] ?? ''), (string)($_POST['line_path'] ?? ''));
            $job = xsw_enqueue_job($state, 'update_line', [
                'line_id' => $lineId,
                'name' => $linePayload['name'],
                'path' => $linePayload['path'],
                'keep_entry' => !empty($_POST['keep_entry']),
            ]);
            xsw_kick_worker();
            $redirectPage = 'lines';
            xsw_flash('ok', '已提交拓扑变更任务：' . $job['id']);
        } elseif ($action === 'schedule_update_line') {
            $lineId = (string)($_POST['line_id'] ?? '');
            if (!xsw_line_exists($state, $lineId)) {
                throw new RuntimeException('找不到链路：' . $lineId);
            }
            $linePayload = xsw_validated_line_payload($state, (string)($_POST['line_name'] ?? ''), (string)($_POST['line_path'] ?? ''));
            $job = xsw_schedule_job($state, 'update_line', xsw_parse_schedule_time((string)($_POST['line_run_at'] ?? '')), [
                'line_id' => $lineId,
                'name' => $linePayload['name'],
                'path' => $linePayload['path'],
                'keep_entry' => !empty($_POST['keep_entry']),
            ]);
            $redirectPage = 'lines';
            xsw_flash('ok', '已创建计划变更任务：' . $job['id']);
        } elseif ($action === 'delete_line') {
            $lineId = (string)($_POST['line_id'] ?? '');
            if (!xsw_line_exists($state, $lineId)) {
                throw new RuntimeException('找不到链路：' . $lineId);
            }
            $existingDeleteJob = xsw_line_delete_job($state, $lineId);
            if ($existingDeleteJob) {
                throw new RuntimeException('这条链路已经有下线任务：' . (string)($existingDeleteJob['id'] ?? ''));
            }
            $job = xsw_enqueue_job($state, 'delete_line', [
                'line_id' => $lineId,
            ]);
            xsw_kick_worker();
            $redirectPage = 'lines';
            xsw_flash('ok', '已提交链路下线任务：' . $job['id']);
        } elseif ($action === 'schedule_delete_line') {
            $lineId = (string)($_POST['line_id'] ?? '');
            if (!xsw_line_exists($state, $lineId)) {
                throw new RuntimeException('找不到链路：' . $lineId);
            }
            $existingDeleteJob = xsw_line_delete_job($state, $lineId);
            if ($existingDeleteJob) {
                throw new RuntimeException('这条链路已经有下线任务：' . (string)($existingDeleteJob['id'] ?? ''));
            }
            $job = xsw_schedule_job($state, 'delete_line', xsw_parse_schedule_time((string)($_POST['line_run_at'] ?? '')), [
                'line_id' => $lineId,
            ]);
            $redirectPage = 'lines';
            xsw_flash('ok', '已创建计划下线任务：' . $job['id']);
        } elseif ($action === 'create_standalone') {
            $standaloneName = trim((string)($_POST['standalone_name'] ?? ''));
            $standaloneServer = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['standalone_server'] ?? '')));
            $standalonePort = (int)($_POST['standalone_port'] ?? 0);
            if ($standaloneName === '') {
                throw new RuntimeException('请填写入口名称');
            }
            if ($standaloneServer === '' || empty($state['servers'][$standaloneServer])) {
                throw new RuntimeException('请选择资源');
            }
            if ($standalonePort < 1 || $standalonePort > 65535) {
                throw new RuntimeException('入口端口不正确');
            }
            $job = xsw_enqueue_job($state, 'create_standalone', [
                'name' => $standaloneName,
                'server' => $standaloneServer,
                'protocol' => !empty($_POST['standalone_socks5']) ? 'socks5' : 'vless',
                'port' => $standalonePort,
            ]);
            xsw_kick_worker();
            $redirectPage = 'singles';
            xsw_flash('ok', '已提交单节点开通任务：' . $job['id']);
        } elseif ($action === 'delete_standalone') {
            $job = xsw_enqueue_job($state, 'delete_standalone', [
                'entry_id' => (string)($_POST['entry_id'] ?? ''),
            ]);
            xsw_kick_worker();
            $redirectPage = 'singles';
            xsw_flash('ok', '已提交单节点下线任务：' . $job['id']);
        } elseif ($action === 'install_3xui') {
            $secret = [
                'ssh_password' => (string)($_POST['install_ssh_password'] ?? ''),
                'ssh_private_key' => (string)($_POST['install_ssh_private_key'] ?? ''),
            ];
            if (trim($secret['ssh_password']) === '' && trim($secret['ssh_private_key']) === '') {
                throw new RuntimeException('请填写 SSH 密码或私钥');
            }
            $job = xsw_enqueue_job($state, 'install_3xui', [
                'code' => strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['install_code'] ?? ''))),
                'name' => trim((string)($_POST['install_name'] ?? '')),
                'host' => xsw_clean_ssh_host((string)($_POST['install_host'] ?? '')),
                'ssh_port' => max(1, min(65535, (int)($_POST['install_ssh_port'] ?? 22))),
                'ssh_user' => preg_replace('/[^A-Za-z0-9_.-]/', '', (string)($_POST['install_ssh_user'] ?? 'root')),
                'panel_port' => (int)($_POST['install_panel_port'] ?? 0),
                'ssl_mode' => in_array((string)($_POST['install_ssl_mode'] ?? 'ip'), ['ip', 'none'], true) ? (string)$_POST['install_ssl_mode'] : 'ip',
            ]);
            xsw_save_job_secret($job['id'], $secret);
            xsw_kick_worker();
            $redirectPage = 'installer';
            xsw_flash('ok', '已提交 3x-ui 安装任务：' . $job['id']);
        } elseif ($action === 'mark_install_copied') {
            xsw_mark_install_result_copied($state, (string)($_POST['job_id'] ?? ''));
            $redirectPage = in_array((string)($_POST['return_page'] ?? ''), ['installer', 'jobs'], true) ? (string)$_POST['return_page'] : 'jobs';
            xsw_flash('ok', '面板信息已复制并隐藏');
        } elseif ($action === 'clear_install_results') {
            $cleared = 0;
            foreach ($state['jobs'] as &$job) {
                if ((string)($job['type'] ?? '') !== 'install_3xui') {
                    continue;
                }
                if (!empty($job['install_result']) || !empty($job['install_text']) || !empty($job['install_copied_at'])) {
                    unset($job['install_result'], $job['install_text'], $job['install_copied_at']);
                    $cleared++;
                }
            }
            unset($job);
            xsw_save_state($state);
            $redirectPage = 'installer';
            xsw_flash('ok', '已清理安装结果：' . $cleared . ' 条');
        } elseif ($action === 'firewall_connect') {
            $session = xsw_upsert_firewall_session($state, (string)($_POST['firewall_host'] ?? ''), (int)($_POST['firewall_ssh_port'] ?? 22), (string)($_POST['firewall_ssh_user'] ?? 'root'), [
                'ssh_password' => (string)($_POST['firewall_ssh_password'] ?? ''),
                'ssh_private_key' => (string)($_POST['firewall_ssh_private_key'] ?? ''),
            ], (string)($_POST['firewall_label'] ?? ''));
            $state['firewall']['sessions'][(string)$session['id']]['last_used_at'] = time();
            xsw_save_state($state);
            xsw_kick_worker();
            $redirectPage = 'firewall';
            xsw_flash('ok', ((string)($session['last_status'] ?? '') === '待后台校验' ? '已保存 SSH 信息，等待后台校验：' : '已接入防火墙管理：') . (string)($session['label'] ?? $session['host']));
        } elseif ($action === 'firewall_connect_assets') {
            $code = strtoupper(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_POST['firewall_server_code'] ?? '')));
            if ($code === '' || !isset($state['servers'][$code])) {
                throw new RuntimeException('请选择一台要接入防火墙管理的资源');
            }
            $secret = [
                'ssh_password' => (string)($_POST['asset_firewall_ssh_password'] ?? ''),
                'ssh_private_key' => (string)($_POST['asset_firewall_ssh_private_key'] ?? ''),
            ];
            if (trim($secret['ssh_password']) === '' && trim($secret['ssh_private_key']) === '') {
                throw new RuntimeException('请填写 SSH 密码或 SSH 私钥');
            }
            $sshPort = max(1, min(65535, (int)($_POST['asset_firewall_ssh_port'] ?? 22)));
            $sshUser = preg_replace('/[^A-Za-z0-9_.-]/', '', (string)($_POST['asset_firewall_ssh_user'] ?? 'root'));
            if ($sshUser === '') {
                $sshUser = 'root';
            }
            $server = $state['servers'][$code];
            $host = xsw_server_host($server);
            if ($host === '') {
                throw new RuntimeException('资源 ' . $code . ' 没有可用连接主机');
            }
            $session = xsw_upsert_firewall_session($state, $host, $sshPort, $sshUser, $secret, xsw_server_label($server));
            $state['firewall']['sessions'][(string)$session['id']]['last_used_at'] = time();
            xsw_save_state($state);
            xsw_kick_worker();
            $redirectPage = 'firewall';
            xsw_flash('ok', ((string)($session['last_status'] ?? '') === '待后台校验' ? '已保存 SSH 信息，等待后台校验：' : '已从资源中心接入：') . xsw_server_label($server));
        } elseif ($action === 'firewall_forget') {
            $count = xsw_forget_firewall_sessions($state, (array)($_POST['firewall_target_ids'] ?? []));
            $redirectPage = 'firewall';
            xsw_flash('ok', $count > 0 ? ('已退出 ' . $count . ' 台服务器的防火墙管理') : '没有选择要退出的服务器');
        } elseif ($action === 'firewall_select') {
            $selected = xsw_firewall_selected_sessions($state, [(string)($_POST['firewall_session_id'] ?? '')]);
            $session = $selected[0];
            $state['firewall']['active_session_id'] = (string)$session['id'];
            $state['firewall']['sessions'][(string)$session['id']]['last_used_at'] = time();
            xsw_save_state($state);
            $redirectPage = 'firewall';
            xsw_flash('ok', '已进入防火墙管理：' . (string)($session['label'] ?? $session['host']));
        } elseif ($action === 'firewall_exit_active') {
            $state['firewall']['active_session_id'] = '';
            xsw_save_state($state);
            $redirectPage = 'firewall';
            xsw_flash('ok', '已退出当前防火墙管理');
        } elseif ($action === 'apply_firewall') {
            $mode = (string)($_POST['firewall_mode'] ?? 'apply');
            $mode = in_array($mode, ['apply', 'clear'], true) ? $mode : 'apply';
            $sessions = xsw_firewall_selected_sessions($state, [(string)($state['firewall']['active_session_id'] ?? '')]);
            $policy = [
                'mode' => $mode,
                'enabled' => !empty($_POST['firewall_enabled']),
                'deny_ping' => !empty($_POST['firewall_deny_ping']),
                'rules' => xsw_firewall_rules_from_post($_POST),
                'persist' => true,
            ];
            $queued = 0;
            $updated = 0;
            foreach ($sessions as $session) {
                $sessionId = (string)($session['id'] ?? '');
                $policyState = xsw_normalize_firewall_policy($policy);
                if ($mode === 'clear') {
                    $policyState = [
                        'enabled' => false,
                        'deny_ping' => false,
                        'rules' => [],
                        'persist' => !empty($policy['persist']),
                    ];
                }
                $state['firewall']['sessions'][$sessionId]['policy'] = $policyState;
                $state['firewall']['sessions'][(string)$session['id']]['last_used_at'] = time();
                $state['firewall']['sessions'][(string)$session['id']]['last_status'] = $mode === 'clear' ? '等待清除' : '等待应用';
                $state['firewall']['applies'][$sessionId] = [
                    'at' => time(),
                    'host' => (string)($session['host'] ?? ''),
                    'mode' => $mode,
                    'pending' => true,
                    'payload' => $policyState,
                    'results' => [],
                ];
                $jobResult = xsw_enqueue_unique_firewall_job($state, xsw_firewall_payload_from_session($session, $policy));
                xsw_save_job_secret((string)$jobResult['job']['id'], xsw_load_firewall_session_secret($sessionId));
                if (!empty($jobResult['updated'])) {
                    $updated++;
                } else {
                    $queued++;
                }
                xsw_save_state($state);
            }
            xsw_kick_worker();
            $redirectPage = 'firewall';
            xsw_flash('ok', '已保存当前规则并提交后台任务' . ($updated ? '，更新等待任务 ' . $updated . ' 个' : '') . ($queued ? '，新增任务 ' . $queued . ' 个' : ''));
        } elseif ($action === 'cancel_job') {
            xsw_cancel_job($state, (string)($_POST['job_id'] ?? ''));
            $redirectPage = 'jobs';
            xsw_flash('ok', '任务已取消');
        } elseif ($action === 'clear_finished_jobs') {
            $keptJobs = [];
            $deleted = 0;
            foreach (($state['jobs'] ?? []) as $job) {
                $status = (string)($job['status'] ?? '');
                if (in_array($status, ['pending', 'running'], true)) {
                    $keptJobs[] = $job;
                    continue;
                }
                xsw_delete_job_secret((string)($job['id'] ?? ''));
                $deleted++;
            }
            $state['jobs'] = $keptJobs;
            xsw_save_state($state);
            $redirectPage = 'jobs';
            xsw_flash('ok', '已清理已结束任务：' . $deleted . ' 条');
        } elseif ($action === 'mark_all_logs_read') {
            $changed = xsw_mark_all_logs_read();
            $redirectPage = 'logs';
            xsw_flash('ok', '已读审计记录：' . $changed . ' 条');
        } elseif ($action === 'mark_log_read') {
            xsw_set_log_read((string)($_POST['log_id'] ?? ''), true);
            $redirectPage = 'logs';
            xsw_flash('ok', '审计记录已标为已读');
        } elseif ($action === 'mark_log_unread') {
            xsw_set_log_read((string)($_POST['log_id'] ?? ''), false);
            $redirectPage = 'logs';
            xsw_flash('ok', '审计记录已标为未读');
        } elseif ($action === 'delete_log') {
            xsw_delete_log((string)($_POST['log_id'] ?? ''));
            $redirectPage = 'logs';
            xsw_flash('ok', '审计记录已删除');
        } elseif ($action === 'delete_read_logs') {
            $deleted = xsw_delete_read_logs();
            $redirectPage = 'logs';
            xsw_flash('ok', '已删除已读审计记录：' . $deleted . ' 条');
        } elseif ($action === 'clear_logs') {
            $deleted = xsw_clear_logs();
            $redirectPage = 'logs';
            xsw_flash('ok', '已清空审计记录：' . $deleted . ' 条');
        } elseif ($action === 'change_password') {
            $password = (string)($_POST['new_password'] ?? '');
            $confirm = (string)($_POST['new_password_confirm'] ?? '');
            if (strlen($password) < 10) {
                throw new RuntimeException('新密码至少 10 位');
            }
            if ($password !== $confirm) {
                throw new RuntimeException('两次密码不一致');
            }
            $config = xsw_load_config();
            $config['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
            xsw_save_config($config);
            xsw_flash('ok', '管理密码已更新');
        }
    } catch (Throwable $e) {
        xsw_log('error', $e->getMessage(), ['action' => $action]);
        xsw_flash('err', $e->getMessage());
    }
    xsw_redirect($redirectPage, $redirectFragment);
}

$flashes = $_SESSION['xsw_flash'] ?? [];
unset($_SESSION['xsw_flash']);
xsw_ensure_firewall_state($state);
$entryLinks = xsw_entry_links($state);
$standaloneEntries = $state['standalone']['entries'] ?? [];
$standaloneInfos = xsw_standalone_client_infos($state);
$nextStandalonePort = xsw_next_standalone_port($state);
$linePaths = [];
foreach (($state['lines'] ?? []) as $line) {
    $linePaths[(string)($line['id'] ?? '')] = implode(' -> ', $line['path'] ?? []);
}
$pendingJobs = array_values(array_filter(($state['jobs'] ?? []), fn($job) => ($job['status'] ?? '') === 'pending'));
usort($pendingJobs, fn($a, $b) => (int)($a['run_at'] ?? 0) <=> (int)($b['run_at'] ?? 0));
$runningJobs = array_values(array_filter(($state['jobs'] ?? []), fn($job) => ($job['status'] ?? '') === 'running'));
$readyJobs = array_values(array_filter($pendingJobs, fn($job) => (int)($job['run_at'] ?? 0) <= time()));
$nextJobAt = (int)($pendingJobs[0]['run_at'] ?? 0);
$defaultRunAt = date('Y-m-d\TH:i', time() + 3600);
$nextServerCode = xsw_next_server_code($state['servers'] ?? []);
$installJobs = array_values(array_filter(($state['jobs'] ?? []), fn($job) => ($job['type'] ?? '') === 'install_3xui' && !empty($job['install_result'])));
$installJobs = array_reverse($installJobs);
$firewallSessions = is_array($state['firewall']['sessions'] ?? null) ? $state['firewall']['sessions'] : [];
uasort($firewallSessions, fn($a, $b) => (int)($b['last_used_at'] ?? 0) <=> (int)($a['last_used_at'] ?? 0));
$firewallSelectableSessions = array_filter($firewallSessions, fn($session, $id) => is_array($session) && xsw_firewall_session_has_secret((string)$id), ARRAY_FILTER_USE_BOTH);
$firewallSessionsByHost = [];
foreach ($firewallSelectableSessions as $fwId => $fwSession) {
    $fwHost = strtolower(trim((string)($fwSession['host'] ?? '')));
    if ($fwHost !== '' && !isset($firewallSessionsByHost[$fwHost])) {
        $firewallSessionsByHost[$fwHost] = (string)$fwId;
    }
}
$firewallResourceRows = [];
$firewallResourceHosts = [];
foreach (($state['servers'] ?? []) as $serverCode => $server) {
    if (!is_array($server)) {
        continue;
    }
    $host = xsw_server_host($server);
    if ($host === '') {
        continue;
    }
    $hostKey = strtolower($host);
    $sessionId = (string)($firewallSessionsByHost[$hostKey] ?? '');
    $firewallResourceHosts[$hostKey] = true;
    $firewallResourceRows[] = [
        'code' => (string)$serverCode,
        'label' => xsw_server_label($server),
        'host' => $host,
        'session_id' => $sessionId,
        'session' => $sessionId !== '' && isset($firewallSelectableSessions[$sessionId]) ? $firewallSelectableSessions[$sessionId] : null,
    ];
}
$firewallStandaloneSessions = array_filter($firewallSelectableSessions, function ($session) use ($firewallResourceHosts) {
    $host = strtolower(trim((string)($session['host'] ?? '')));
    return $host === '' || !isset($firewallResourceHosts[$host]);
});
$firewallReads = is_array($state['firewall']['reads'] ?? null) ? $state['firewall']['reads'] : [];
$firewallApplies = is_array($state['firewall']['applies'] ?? null) ? $state['firewall']['applies'] : [];
$firewallActiveId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($state['firewall']['active_session_id'] ?? ''));
$firewallActive = ($firewallActiveId !== '' && isset($firewallSessions[$firewallActiveId]) && xsw_firewall_session_has_secret($firewallActiveId)) ? $firewallSessions[$firewallActiveId] : null;
$firewallPolicy = $firewallActive ? xsw_firewall_policy_for_session($state, $firewallActiveId) : xsw_firewall_default_policy();
$firewallRules = xsw_firewall_rules_from_policy($firewallPolicy);
$firewallActiveStatus = $firewallActive ? (string)($firewallActive['last_status'] ?? '') : '';
$browserIp = trim((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? ''));
if (str_contains($browserIp, ',')) {
    $browserIp = trim((string)explode(',', $browserIp)[0]);
}
$browserCidr = filter_var($browserIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $browserIp . '/32' : '';
$firewallActiveHost = strtolower(trim((string)($firewallActive['host'] ?? '')));
$firewallActiveServer = null;
foreach (($state['servers'] ?? []) as $candidateServer) {
    if (is_array($candidateServer) && strtolower(xsw_server_host($candidateServer)) === $firewallActiveHost) {
        $firewallActiveServer = $candidateServer;
        break;
    }
}
$firewallPanelPort = 0;
if ($firewallActiveServer) {
    $accessParts = parse_url((string)($firewallActiveServer['access_url'] ?? ''));
    $firewallPanelPort = (int)($accessParts['port'] ?? 0);
}
$firewallStandalonePorts = [];
foreach (($state['standalone']['entries'] ?? []) as $entry) {
    $serverCode = (string)($entry['server'] ?? '');
    $entryServer = is_array($state['servers'][$serverCode] ?? null) ? $state['servers'][$serverCode] : null;
    if ($entryServer && strtolower(xsw_server_host($entryServer)) === $firewallActiveHost) {
        $port = (int)($entry['port'] ?? 0);
        if ($port > 0) {
            $firewallStandalonePorts[] = (string)$port;
        }
    }
}
$firewallStandalonePorts = array_values(array_unique($firewallStandalonePorts));
$firewallLast = is_array($state['last_results']['firewall'] ?? null) ? $state['last_results']['firewall'] : [];
$firewallRead = is_array($state['last_results']['firewall_read'] ?? null) ? $state['last_results']['firewall_read'] : [];
$testResults = $state['last_results']['test']['results'] ?? [];
$testLastAt = (int)($state['last_results']['test']['at'] ?? 0);
$testCheckedCount = count($testResults);
$testOkCount = count(array_filter($testResults, fn($row) => !empty($row['ok'])));
$testFailCount = $testCheckedCount - $testOkCount;
$testUntestedCount = max(0, count($state['servers'] ?? []) - $testCheckedCount);
$testFailedRows = [];
foreach ($testResults as $code => $row) {
    if (!is_array($row) || !empty($row['ok'])) {
        continue;
    }
    $testFailedRows[] = [
        'code' => (string)$code,
        'error' => (string)($row['error'] ?? '接入异常'),
    ];
}
$recentLogs = xsw_recent_logs();
$logStats = xsw_log_stats();
$recentErrorCount = count(array_filter($recentLogs, fn($log) => ($log['level'] ?? '') === 'error'));
$pages = [
    'dashboard' => '运营总览',
    'servers' => '资源中心',
    'singles' => '单节点入口',
    'lines' => '链路编排',
    'jobs' => '任务中心',
    'installer' => '面板安装',
    'firewall' => '防火墙策略',
    'logs' => '审计日志',
    'settings' => '后台设置',
];
$pageIcons = [
    'dashboard' => 'grid',
    'servers' => 'database',
    'singles' => 'plug',
    'lines' => 'route',
    'jobs' => 'clock',
    'installer' => 'download',
    'firewall' => 'shield',
    'logs' => 'file',
    'settings' => 'settings',
];
$page = (string)($_GET['page'] ?? 'dashboard');
if (!isset($pages[$page])) {
    $page = 'dashboard';
}
$autoRefreshJobs = $page === 'jobs' && (count($runningJobs) > 0 || count($readyJobs) > 0);
$plan = null;
$planError = '';
try {
    if (!empty($state['servers'])) {
        $tmp = $state;
        $plan = xsw_build_plan($tmp);
    }
} catch (Throwable $e) {
    $planError = $e->getMessage();
}
?><!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php if ($autoRefreshJobs): ?><meta http-equiv="refresh" content="8"><?php endif; ?>
  <title>JD</title>
  <style>
    :root {
      --bg:#f4f6fa; --ink:#172033; --muted:#6d7788; --line:#dfe6ef; --panel:#fff;
      --primary:#2563eb; --primary-dark:#1849a9; --primary-soft:#eef5ff;
      --green:#18a058; --green-dark:#0f7a3d; --green-soft:#effaf3;
      --red:#d92d20; --red-soft:#fff2f0;
      --amber:#f79009; --amber-soft:#fff7ed; --cyan:#0e7490; --cyan-soft:#ecfeff;
      --soft:#f3f6fa; --table-head:#f8fafc; --shadow:0 1px 2px rgba(24,36,56,.05),0 8px 24px rgba(24,36,56,.04);
    }
    * { box-sizing:border-box; }
    html { min-height:100%; }
    body { margin:0; min-height:100vh; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif; background:var(--bg); color:var(--ink); letter-spacing:0; }
    header { position:fixed; left:0; top:0; z-index:12; width:272px; height:78px; display:flex; align-items:center; gap:10px; padding:22px 24px 10px; background:#f7f7f5; border:0; box-shadow:none; }
    header > div:first-child { display:flex; align-items:center; min-width:0; padding-left:14px; }
    header .pill { display:none; }
    h1 { display:block; font-size:22px; margin:0; letter-spacing:.02em; color:#111827; font-weight:800; line-height:1; }
    h1::before { content:none; }
    h2 { font-size:16px; margin:0 0 14px; letter-spacing:0; }
    main { width:100%; margin:0; padding:0 0 48px 272px; position:relative; z-index:1; }
    .app-layout { display:block; min-width:0; }
    .sidebar { position:fixed; top:78px; left:0; bottom:0; width:272px; overflow:auto; overscroll-behavior:contain; z-index:11; display:flex; flex-direction:column; gap:4px; background:#f7f7f5; border:0; border-radius:0; padding:16px 24px 22px; box-shadow:none; }
    .nav-link { display:flex; align-items:center; gap:12px; min-height:42px; padding:0 14px; border-radius:18px; color:#111827; text-decoration:none; font-weight:650; font-size:15px; transition:background .14s ease,color .14s ease; }
    .nav-link:hover { background:#ededeb; color:#111827; }
    .nav-link.active { background:#e7e7e4; color:#111827; box-shadow:none; }
    .nav-icon { width:19px; height:19px; flex:0 0 19px; color:#111827; }
    .nav-link.active .nav-icon { color:#111827; }
    .sidebar-logout { margin-top:auto; padding-top:18px; }
    .sidebar-logout button { width:100%; justify-content:flex-start; min-height:42px; border:0; border-radius:18px; background:transparent; color:#111827; font-size:15px; font-weight:650; padding:0 14px; }
    .sidebar-logout button:hover { background:#ededeb; border-color:transparent; }
    .content { min-width:0; width:min(1320px, calc(100vw - 320px)); margin:0 auto; padding:36px 24px 40px; }
    .page-head { display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:18px; min-height:38px; }
    .page-head h2 { font-size:22px; margin:0; color:#0f1f3d; }
    .page-panel { display:none; }
    body[data-page="dashboard"] .grid { display:none; }
    body[data-page="servers"] .page-servers,
    body[data-page="installer"] .page-installer,
    body[data-page="firewall"] .page-firewall,
    body[data-page="lines"] .page-lines,
    body[data-page="singles"] .page-singles,
    body[data-page="jobs"] .page-jobs,
    body[data-page="settings"] .page-settings,
    body[data-page="logs"] .page-logs { display:block; }
    body:not([data-page="dashboard"]) .grid { grid-template-columns:1fr; }
    body:not([data-page="dashboard"]) .grid > div { display:contents; }
    .grid { display:grid; grid-template-columns:minmax(360px, 1fr) minmax(420px, 1.25fr); gap:16px; align-items:start; }
    .page-grid { display:grid; grid-template-columns:minmax(0, 1fr) minmax(320px, .72fr); gap:16px; align-items:start; }
    .section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; margin-bottom:16px; box-shadow:var(--shadow); }
    .section-head { display:flex; justify-content:space-between; gap:12px; align-items:center; margin-bottom:12px; padding-bottom:10px; border-bottom:1px solid #edf1f6; }
    .section-head h2 { margin:0; }
    .toolbar { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:12px; }
    .danger-zone { border:1px solid #f3b8b0; background:var(--red-soft); border-radius:8px; padding:12px; margin-top:14px; }
    .label { display:block; color:var(--muted); font-size:12px; margin-bottom:7px; }
    .value { display:block; font-size:18px; font-weight:800; overflow-wrap:anywhere; }
    textarea, input, select { width:100%; border:1px solid var(--line); border-radius:6px; background:#fff; color:var(--ink); font:14px/1.45 ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace; padding:9px 11px; transition:border-color .14s ease,box-shadow .14s ease,background .14s ease; }
    textarea:focus, input:focus, select:focus { outline:none; border-color:#9cc2ff; box-shadow:0 0 0 3px rgba(37,99,235,.10); }
    input, select { height:38px; font-family:inherit; }
    textarea { min-height:128px; resize:vertical; }
    .row { display:grid; grid-template-columns:repeat(3, 1fr); gap:12px; }
    .row.two { grid-template-columns:repeat(2, 1fr); }
    .actions { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
    .standalone-submit-row { display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:12px; align-items:center; margin-top:12px; }
    .standalone-submit-row .green { justify-self:start; width:auto; }
    .standalone-submit-row .bottom-link { justify-self:end; width:104px; padding-left:0; padding-right:0; }
    button, .button { display:inline-flex; align-items:center; justify-content:center; min-height:36px; border:1px solid var(--line); border-radius:6px; background:#fff; color:var(--ink); padding:0 12px; font-weight:700; cursor:pointer; text-decoration:none; transition:background .14s ease,border-color .14s ease,color .14s ease,box-shadow .14s ease; }
    button:hover, .button:hover { border-color:#b8c7da; background:#fbfdff; }
    button.primary { background:var(--primary); border-color:var(--primary); color:#fff; }
    button.primary:hover { background:var(--primary-dark); border-color:var(--primary-dark); }
    button.green { background:var(--green); border-color:var(--green); color:#fff; }
    button.green:hover { background:var(--green-dark); border-color:var(--green-dark); }
    button.danger { background:var(--red-soft); border-color:#f3b8b0; color:var(--red); }
    button:disabled { opacity:.55; cursor:not-allowed; }
    .hint { color:var(--muted); font-size:13px; margin:8px 0 0; line-height:1.5; }
    .toast-stack { position:fixed; top:82px; right:24px; z-index:60; display:grid; gap:10px; width:min(360px, calc(100vw - 32px)); pointer-events:none; }
    .toast { border:1px solid var(--line); border-radius:8px; padding:12px 14px; background:#fff; box-shadow:0 16px 40px rgba(17,24,39,.16); font-size:13px; font-weight:700; line-height:1.45; pointer-events:auto; animation:toast-in .18s ease-out; }
    .toast.ok { border-color:#8edccc; color:#0f5f59; background:var(--green-soft); }
    .toast.err { border-color:#f3b8b0; color:var(--red); background:var(--red-soft); }
    .toast.is-leaving { opacity:0; transform:translateY(-6px); transition:opacity .2s ease, transform .2s ease; }
    @keyframes toast-in { from { opacity:0; transform:translateY(-8px); } to { opacity:1; transform:translateY(0); } }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { border-bottom:1px solid var(--line); padding:8px 8px; text-align:left; vertical-align:top; }
    th { color:var(--muted); font-weight:700; background:var(--table-head); }
    tbody tr:hover td { background:#fbfdff; }
    code { background:var(--soft); padding:2px 5px; border-radius:5px; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
    .mono { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
    .status-ok { color:var(--green); font-weight:800; }
    .status-err { color:var(--red); font-weight:800; }
    .pill { display:inline-flex; align-items:center; min-height:24px; border:1px solid var(--line); border-radius:999px; padding:0 9px; background:#fff; color:var(--muted); font-size:12px; font-weight:700; }
    .pill.status-ok { border-color:#8edccc; background:var(--green-soft); color:#0f5f59; }
    .pill.status-err { border-color:#f3b8b0; background:var(--red-soft); color:var(--red); }
    .split { display:flex; justify-content:space-between; gap:12px; align-items:center; }
    .logs { display:grid; gap:8px; }
    .log { border:1px solid var(--line); border-radius:6px; padding:10px; background:#fff; font-size:13px; }
    .log.unread { border-color:#9ebbd3; background:var(--primary-soft); }
    .log .time { color:var(--muted); font-size:12px; margin-bottom:4px; }
    .log-head { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; }
    .log-actions { display:flex; flex-wrap:wrap; gap:8px; justify-content:flex-end; }
    .log-actions form { display:inline-flex; }
    .copyline { display:flex; gap:8px; align-items:stretch; min-width:0; width:100%; }
    .copyline input, .copyline textarea { flex:1 1 auto; min-width:0; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
    .copyline button { flex:0 0 auto; min-width:104px; white-space:nowrap; }
    .form-grid { display:grid; grid-template-columns:90px 1fr 1.6fr 1.2fr 1fr auto; gap:10px; align-items:end; }
    .server-list { display:grid; gap:10px; margin-top:14px; }
    .server-card { border:1px solid var(--line); border-radius:8px; background:#fff; padding:12px; transition:border-color .14s ease,box-shadow .14s ease; }
    .server-card:hover { border-color:#cbd6e4; box-shadow:0 8px 24px rgba(24,36,56,.05); }
    .server-card-head { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; margin-bottom:10px; }
    .server-title { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
    .health-board { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:10px; margin:0 0 14px; }
    .health-metric { border:1px solid var(--line); border-radius:8px; background:linear-gradient(180deg,#fff,#f8fafc); padding:11px 12px; min-width:0; }
    .health-metric span { display:block; color:var(--muted); font-size:12px; margin-bottom:6px; }
    .health-metric strong { display:block; font-size:18px; overflow-wrap:anywhere; }
    .health-failures { display:grid; gap:8px; border:1px solid #f3b8b0; background:var(--red-soft); border-radius:8px; padding:10px 12px; margin:-4px 0 14px; color:var(--red); font-size:13px; }
    .health-detail { display:inline-flex; flex-wrap:wrap; gap:6px; align-items:center; margin-top:8px; border:1px solid var(--line); border-radius:6px; padding:6px 8px; background:var(--table-head); font-size:12px; }
    .health-detail.status-ok { border-color:#99d2c9; background:var(--green-soft); }
    .health-detail.status-err { border-color:#f3b8b0; background:var(--red-soft); }
    .danger-impact { border:1px solid #f3b8b0; border-radius:8px; background:#fff; padding:10px 12px; margin:8px 0 10px; color:var(--red); font-weight:800; }
    .server-fields { display:grid; grid-template-columns:80px 1fr 1.5fr 1.1fr 1fr; gap:10px; align-items:end; }
    .server-fields input, .form-grid input { min-width:0; }
    .server-actions { display:flex; flex-wrap:wrap; gap:8px; justify-content:flex-end; }
    .muted-box { background:#fbfcfe; border:1px solid var(--line); border-radius:8px; padding:12px; }
    details.advanced { border:1px dashed var(--line); border-radius:8px; margin-top:14px; background:var(--table-head); }
    details.advanced > summary { cursor:pointer; display:flex; justify-content:space-between; align-items:center; gap:12px; padding:12px; font-weight:800; }
    details.advanced > summary::marker { content:""; }
    .advanced-body { border-top:1px solid var(--line); padding:12px; }
    details.section { padding:0; }
    details.section > summary { cursor:pointer; list-style:none; display:flex; justify-content:space-between; align-items:center; gap:12px; padding:18px; }
    details.section > summary::-webkit-details-marker { display:none; }
    details.section > summary h2 { margin:0; }
    details.section[open] > summary { border-bottom:1px solid var(--line); }
    .details-body { padding:18px; }
    .server-strip { display:flex; flex-wrap:wrap; gap:8px; margin:10px 0 12px; min-width:0; }
    .server-chip { min-height:34px; min-width:0; padding:0 10px; border-radius:6px; border:1px solid var(--line); background:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .server-chip:hover { border-color:#b9cfef; color:var(--primary-dark); background:#f7fbff; }
    .line-card { border:1px solid var(--line); border-radius:8px; padding:14px; background:#fff; margin-bottom:12px; transition:border-color .14s ease,box-shadow .14s ease; overflow:hidden; }
    .line-card:hover { border-color:#cbd6e4; box-shadow:0 8px 24px rgba(24,36,56,.05); }
    .line-path { display:flex; flex-wrap:wrap; gap:6px; align-items:center; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
    .page-lines .server-strip { display:grid; grid-template-columns:repeat(auto-fill, minmax(158px, 1fr)); gap:8px; }
    .page-lines .server-chip { width:100%; justify-content:flex-start; }
    .page-lines .row { grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); }
    .page-lines .actions { gap:8px; }
    .page-lines .actions button { min-height:36px; white-space:nowrap; }
    .page-lines .line-path { margin-top:6px; color:#111827; line-height:1.6; overflow-wrap:anywhere; }
    .qr-entry { display:grid; grid-template-columns:260px minmax(0, 1fr); gap:16px; align-items:start; margin-top:14px; }
    .qr-box { width:100%; max-width:260px; aspect-ratio:1; border:1px solid var(--line); border-radius:8px; background:#fff; padding:14px; display:flex; align-items:center; justify-content:center; }
    .qr-box img { width:100%; height:100%; object-fit:contain; image-rendering:pixelated; }
    .panel-result { width:100%; min-height:118px; max-height:240px; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre; }
    .panel-result + button { align-self:flex-start; }
    .fw-console { display:grid; gap:12px; }
    .fw-topbar { display:flex; flex-wrap:wrap; gap:12px; align-items:center; border:1px solid var(--line); background:#fbfcfe; border-radius:8px; padding:12px 14px; }
    .fw-topbar .divider { width:1px; height:24px; background:var(--line); }
    .fw-managed { margin-left:auto; color:var(--muted); font-size:13px; font-weight:700; }
    .switch-line { display:inline-flex; align-items:center; gap:8px; margin:0; color:var(--ink); font-weight:800; white-space:nowrap; }
    .switch-line input { position:absolute; opacity:0; pointer-events:none; width:1px; height:1px; }
    .switch-line i { width:42px; height:22px; border-radius:999px; background:#cbd5e1; position:relative; transition:background .16s ease; }
    .switch-line i::after { content:""; position:absolute; width:18px; height:18px; left:2px; top:2px; border-radius:50%; background:#fff; box-shadow:0 1px 3px rgba(15,23,42,.25); transition:transform .16s ease; }
    .switch-line input:checked + i { background:var(--green); }
    .switch-line input:checked + i::after { transform:translateX(20px); }
    .fw-tabs { display:flex; flex-wrap:wrap; gap:0; border-bottom:1px solid var(--line); }
    .fw-tabs span { padding:11px 14px; color:var(--muted); border-bottom:2px solid transparent; font-weight:800; font-size:13px; }
    .fw-tabs .active { color:var(--primary-dark); border-bottom-color:var(--primary); background:#fbfdff; }
    .fw-actions { display:grid; grid-template-columns:auto minmax(360px, 1fr) auto auto minmax(220px, 320px); gap:10px; align-items:center; }
    .fw-quick-rules { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
    .fw-quick-rules .quick-title { color:var(--muted); font-size:12px; font-weight:800; margin-right:2px; }
    .fw-quick-rule { min-height:32px; padding:0 10px; border-color:#cfe8d7; background:#fff; color:var(--green); }
    .fw-quick-rule:hover { border-color:#8fd2a8; background:var(--green-soft); color:var(--green-dark); }
    .fw-search { min-width:0; }
    .fw-table-wrap { overflow-x:auto; border:1px solid var(--line); border-radius:6px; background:#fff; }
    .fw-table-wrap table { border:0; }
    .fw-security-table { min-width:1180px; width:100%; table-layout:fixed; }
    .fw-security-table th, .fw-security-table td { vertical-align:middle; }
    .fw-security-table th:first-child, .fw-security-table td:first-child { width:40px; text-align:center; }
    .fw-security-table th:nth-child(2), .fw-security-table td:nth-child(2) { width:76px; }
    .fw-security-table th:nth-child(3), .fw-security-table td:nth-child(3) { width:190px; }
    .fw-security-table th:nth-child(4), .fw-security-table td:nth-child(4) { width:82px; }
    .fw-security-table th:nth-child(5), .fw-security-table td:nth-child(5) { width:88px; }
    .fw-security-table th:nth-child(6), .fw-security-table td:nth-child(6) { width:64px; }
    .fw-security-table th:nth-child(7), .fw-security-table td:nth-child(7) { width:250px; }
    .fw-security-table th:nth-child(8), .fw-security-table td:nth-child(8) { width:210px; }
    .fw-security-table th:nth-child(9), .fw-security-table td:nth-child(9) { width:86px; }
    .fw-security-table th:nth-child(10), .fw-security-table td:nth-child(10) { width:92px; }
    .fw-security-table th { height:40px; color:#7b8493; background:#fafbfc; font-weight:700; }
    .fw-security-table td { height:48px; color:#6b7280; background:#fff; }
    .fw-security-table input, .fw-security-table select { height:32px; min-width:0; padding:4px 6px; border-color:transparent; background:transparent; color:#6b7280; }
    .fw-security-table input:focus, .fw-security-table select:focus, .fw-security-table textarea:focus { border-color:#bed7f4; background:#fff; outline:none; }
    .fw-security-table textarea { min-height:32px; height:32px; min-width:0; padding:5px 6px; border-color:transparent; background:transparent; color:#6b7280; resize:none; overflow:hidden; }
    .fw-security-table select[name="firewall_rule_policy[]"] { color:var(--green); font-weight:700; }
    .fw-security-table td:nth-child(6) { color:#6b7280; }
    .fw-rule-remove { min-height:28px; padding:0; border:0; background:transparent; color:var(--green); }
    .fw-rule-edit { min-height:28px; padding:0; border:0; background:transparent; color:var(--green); margin-right:12px; }
    .fw-rule-remove:hover, .fw-rule-edit:hover { text-decoration:underline; }
    .fw-security-table .pill { min-height:20px; padding:0; border:0; background:transparent; color:#6b7280; font-size:13px; }
    .fw-security-table .pill.status-ok { color:var(--green); background:transparent; border:0; }
    .fw-security-table .pill.status-err { color:var(--red); background:transparent; border:0; }
    .fw-resource-table { table-layout:fixed; }
    .fw-resource-table th:first-child, .fw-resource-table td:first-child { width:46px; text-align:center; }
    .fw-resource-table th:nth-child(2), .fw-resource-table td:nth-child(2) { width:26%; }
    .fw-resource-table th:nth-child(3), .fw-resource-table td:nth-child(3) { width:20%; }
    .fw-resource-table th:nth-child(4), .fw-resource-table td:nth-child(4) { width:18%; }
    .fw-resource-table th:nth-child(5), .fw-resource-table td:nth-child(5) { width:18%; }
    .fw-resource-table th:nth-child(6), .fw-resource-table td:nth-child(6) { width:190px; }
    .fw-resource-table td:last-child { white-space:nowrap; }
    .fw-resource-table td { vertical-align:middle; }
    .fw-manual-section { overflow:hidden; }
    .fw-manual-form { display:grid; gap:12px; }
    .fw-manual-grid { display:grid; grid-template-columns:minmax(180px, 1.05fr) minmax(180px, 1.05fr) 128px 150px; gap:12px; align-items:end; }
    .fw-manual-auth { display:grid; grid-template-columns:minmax(220px, 320px) minmax(420px, 1fr); gap:12px; align-items:start; }
    .fw-manual-auth textarea { min-height:104px; max-height:180px; }
    .fw-manual-footer { display:flex; justify-content:flex-start; align-items:center; }
    .fw-manual-footer button { min-width:92px; }
    @media (max-width: 1280px) { .content { width:calc(100vw - 272px); padding-right:18px; padding-left:18px; } .fw-actions { grid-template-columns:auto minmax(320px, 1fr) auto auto; } .fw-search { grid-column:1 / -1; max-width:none; } }
    @media (max-width: 1180px) { .form-grid, .server-fields, .health-board, .fw-manual-grid, .fw-manual-auth { grid-template-columns:1fr 1fr; } .server-actions { justify-content:flex-start; } }
    @media (max-width: 980px) { header { position:static; width:auto; height:auto; padding:14px 16px; background:#fff; border-bottom:1px solid var(--line); justify-content:space-between; } header .pill { display:inline-flex; } main { padding:16px; } .app-layout, .grid, .page-grid, .row, .row.two, .form-grid, .server-fields, .qr-entry, .fw-actions, .fw-manual-grid, .fw-manual-auth, .standalone-submit-row { grid-template-columns:1fr; } .standalone-submit-row .bottom-link { justify-self:start; } .fw-search { grid-column:auto; } .sidebar { position:static; width:auto; max-height:none; overflow:visible; background:transparent; padding:0; margin-bottom:16px; } .sidebar-logout { margin-top:8px; padding-top:0; } .sidebar-logout button { width:auto; border:1px solid var(--line); border-radius:6px; background:#fff; justify-content:center; min-height:36px; font-size:14px; } .content { width:100%; padding:0; grid-column:auto; } .page-lines .server-strip { grid-template-columns:repeat(auto-fill, minmax(140px, 1fr)); } }
  </style>
</head>
<body data-page="<?= xsw_h($page) ?>">
<header>
  <div>
    <h1>JD</h1>
    <span class="pill">v<?= xsw_h(XSW_VERSION) ?></span>
  </div>
</header>

<main>
  <?php if ($flashes): ?>
    <div class="toast-stack" aria-live="polite" aria-atomic="true">
      <?php foreach ($flashes as $flash): ?>
        <div class="toast <?= xsw_h($flash['type']) ?>" role="status"><?= xsw_h($flash['message']) ?></div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <div class="app-layout">
    <aside class="sidebar">
      <?php foreach ($pages as $pageId => $label): ?>
        <a class="nav-link <?= $page === $pageId ? 'active' : '' ?>" href="?page=<?= xsw_h($pageId) ?>">
          <?= xsw_nav_icon((string)($pageIcons[$pageId] ?? '')) ?>
          <span><?= xsw_h($label) ?></span>
        </a>
      <?php endforeach; ?>
      <form class="sidebar-logout" method="post">
        <button type="submit" name="action" value="logout">退出</button>
      </form>
    </aside>

    <div class="content">
      <div class="page-head">
        <div>
          <h2><?= xsw_h($pages[$page]) ?></h2>
        </div>
      </div>

  <?php if ($page === 'dashboard'): ?>
  <section class="section">
    <h2>运营概览</h2>
    <table>
      <tbody>
        <tr>
          <th>资源节点</th>
          <td><?= count($state['servers']) ?> 台</td>
          <th>托管链路</th>
          <td><?= count($state['lines']) ?> 条</td>
        </tr>
        <tr>
          <th>任务流水</th>
          <td>待处理 <?= count($pendingJobs) ?> / 处理中 <?= count($runningJobs) ?></td>
          <th>接入健康</th>
          <td>成功 <?= (int)$testOkCount ?> / 失败 <?= (int)$testFailCount ?> / 未检测 <?= (int)$testUntestedCount ?></td>
        </tr>
        <tr>
          <th>当前拓扑</th>
          <td colspan="3">
            <?php if (!$state['lines']): ?>
              -
            <?php else: ?>
              <?php foreach ($state['lines'] as $line): ?>
                <div><?= xsw_h((string)($line['name'] ?? $line['id'])) ?>：<span class="mono"><?= xsw_h(implode(' -> ', $line['path'] ?? [])) ?></span></div>
              <?php endforeach; ?>
            <?php endif; ?>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
  <?php endif; ?>

  <div class="grid">
    <div>
      <section class="section page-panel page-servers">
        <div class="section-head">
          <div>
            <h2>资源资产</h2>
          </div>
          <form method="post"><button type="submit" name="action" value="test_servers" data-busy="检测中" data-preserve-scroll="1">全量健康检查</button></form>
        </div>

        <div class="health-board">
          <div class="health-metric">
            <span>最近检测</span>
            <strong><?= $testLastAt ? xsw_h(xsw_format_time($testLastAt)) : '未执行' ?></strong>
          </div>
          <div class="health-metric">
            <span>成功</span>
            <strong class="status-ok"><?= (int)$testOkCount ?></strong>
          </div>
          <div class="health-metric">
            <span>失败</span>
            <strong class="<?= $testFailCount > 0 ? 'status-err' : '' ?>"><?= (int)$testFailCount ?></strong>
          </div>
          <div class="health-metric">
            <span>未检测</span>
            <strong><?= (int)$testUntestedCount ?></strong>
          </div>
        </div>
        <?php if ($testFailedRows): ?>
          <div class="health-failures">
            <?php foreach (array_slice($testFailedRows, 0, 6) as $failed): ?>
              <div><strong><?= xsw_h($failed['code']) ?></strong> · <?= xsw_h($failed['error']) ?></div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>

        <form method="post" class="muted-box" onsubmit="return confirm('新增资源只保存到控制台，不会改动真实节点。继续？')">
          <div class="form-grid">
            <label><span class="label">资源编号</span><input name="code" value="<?= xsw_h($nextServerCode) ?>" maxlength="12"></label>
            <label><span class="label">资源名称</span><input name="name" placeholder="例如 德国新1"></label>
            <label><span class="label">管理入口 URL</span><input name="access_url" placeholder="https://1.2.3.4:123/path"></label>
            <label><span class="label">接入令牌</span><input name="api_token" type="password" autocomplete="new-password" placeholder="粘贴 3x-ui API Token"></label>
            <label><span class="label">连接主机</span><input name="proxy_host" placeholder="默认取 URL 的 IP/域名"></label>
            <button class="primary" type="submit" name="action" value="add_server">新增资源</button>
          </div>
        </form>

        <div class="server-list">
          <?php if (!$state['servers']): ?>
            <p class="hint">还没有资源</p>
          <?php endif; ?>
          <?php foreach ($state['servers'] as $code => $server): ?>
            <?php
              $row = $testResults[$code] ?? null;
              $statusText = $row === null ? '未检测' : (!empty($row['ok']) ? 'OK' : '失败');
              $statusClass = $row === null ? '' : (!empty($row['ok']) ? 'status-ok' : 'status-err');
              $detail = '';
              if (is_array($row)) {
                  $detail = (string)($row['error'] ?? '');
                  if (!empty($row['ok'])) {
                      $xray = $row['summary']['xray'] ?? [];
                      $detail = (string)(($row['ms'] ?? 0) . ' ms');
                      if (is_array($xray) && !empty($xray['state'])) {
                          $detail .= ' · Xray ' . (string)$xray['state'];
                      }
                      if (is_array($xray) && !empty($xray['errorMsg'])) {
                          $detail .= ' · ' . (string)$xray['errorMsg'];
                      }
                  }
              }
              $usage = xsw_server_usage($state, (string)$code);
            ?>
            <form method="post" id="resource-<?= xsw_h((string)$code) ?>" class="server-card" onsubmit="return !event.submitter || !event.submitter.dataset.confirm || confirm(event.submitter.dataset.confirm)">
              <input type="hidden" name="server_code" value="<?= xsw_h((string)$code) ?>">
              <div class="server-card-head">
                <div>
                  <div class="server-title">
                    <strong><?= xsw_h(xsw_server_label($server)) ?></strong>
                    <span class="pill <?= xsw_h($statusClass) ?>"><?= xsw_h($statusText) ?></span>
                    <?php if ($usage): ?><span class="pill">链路占用</span><?php endif; ?>
                  </div>
                  <?php if (is_array($row)): ?>
                    <?php $rowCheckedAt = (int)($row['checked_at'] ?? $testLastAt); ?>
                    <div class="health-detail <?= xsw_h($statusClass) ?>">
                      <span><?= $rowCheckedAt ? xsw_h(xsw_format_time($rowCheckedAt)) : '最近检测' ?></span>
                      <?php if ($detail): ?><span class="mono"><?= xsw_h($detail) ?></span><?php endif; ?>
                    </div>
                  <?php endif; ?>
                  <?php if ($usage): ?><div class="hint">资源占用：<?= xsw_h(implode('、', $usage)) ?></div><?php endif; ?>
                </div>
                <div class="server-actions">
                  <button class="primary" type="submit" name="action" value="update_server">保存资源</button>
                  <button type="submit" name="action" value="test_one_server" data-busy="检测中" data-preserve-scroll="1">单点检测</button>
                  <button class="danger" type="submit" name="action" value="delete_server" data-confirm="只会从控制台移除资源，不会远程删除节点。继续？" <?= $usage ? 'disabled title="资源正被链路或计划任务使用"' : '' ?>>移除</button>
                </div>
              </div>
              <div class="server-fields">
                <label><span class="label">资源编号</span><input value="<?= xsw_h((string)$code) ?>" disabled></label>
                <label><span class="label">资源名称</span><input name="name" value="<?= xsw_h((string)($server['name'] ?? '')) ?>"></label>
                <label><span class="label">管理入口 URL</span><input name="access_url" type="password" autocomplete="new-password" placeholder="已保存，留空不变"></label>
                <label><span class="label">接入令牌</span><input name="api_token" type="password" autocomplete="new-password" placeholder="已保存，留空不变"></label>
                <label><span class="label">连接主机</span><input name="proxy_host" value="<?= xsw_h((string)($server['proxy_host'] ?? '')) ?>"></label>
              </div>
            </form>
          <?php endforeach; ?>
        </div>

        <details class="advanced" open>
          <summary><span>资产导入</span></summary>
          <div class="advanced-body">
            <form method="post" onsubmit="return confirm((event.submitter && event.submitter.dataset.confirm) || '导入会新增或更新资源，继续？')">
              <textarea name="xui_import_text" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-sensitive-empty="1" style="min-height:140px" placeholder="德国新1&#10;Username: ...&#10;Access URL: https://1.2.3.4:123/path&#10;API Token: ..."></textarea>
              <label style="display:flex; gap:8px; align-items:center; color:var(--muted); font-size:13px; margin-top:8px">
                <input type="checkbox" name="purge_before_import" value="1" style="width:16px; height:16px">
                导入前清空现有 JD 托管节点
              </label>
              <div class="actions" style="margin:10px 0 16px">
                <button type="submit" name="action" value="import_3xui_blocks" data-confirm="会新增或更新资源；如果勾选清空，会先实际删除现有 JD 托管节点。继续？">导入新增/更新</button>
              </div>
            </form>
          </div>
        </details>
      </section>

      <section class="section page-panel page-installer">
        <div class="section-head">
          <div>
            <h2>自动安装 3x-ui</h2>
          </div>
        </div>
        <form method="post" onsubmit="return confirm('会通过 SSH 登录目标服务器并执行 3x-ui 官方安装脚本。继续？')">
          <div class="row">
            <label><span class="label">资源编号</span><input name="install_code" value="<?= xsw_h($nextServerCode) ?>" maxlength="12"></label>
            <label><span class="label">资源名称</span><input name="install_name" placeholder="例如 德国新3"></label>
            <label><span class="label">目标 IP</span><input name="install_host" required placeholder="1.2.3.4"></label>
          </div>
          <div class="row" style="margin-top:12px">
            <label><span class="label">SSH 端口</span><input name="install_ssh_port" type="number" min="1" max="65535" value="22"></label>
            <label><span class="label">SSH 用户</span><input name="install_ssh_user" value="root"></label>
            <label><span class="label">面板端口</span><input name="install_panel_port" type="number" min="1" max="65535" placeholder="留空随机"></label>
          </div>
          <div class="row two" style="margin-top:12px">
            <label><span class="label">SSH 密码</span><input name="install_ssh_password" type="password" autocomplete="new-password" data-sensitive-empty="1"></label>
            <label>
              <span class="label">HTTPS 模式</span>
              <select name="install_ssl_mode">
                <option value="ip" selected>IP 证书</option>
                <option value="none">HTTP</option>
              </select>
            </label>
          </div>
          <label style="margin-top:12px"><span class="label">SSH 私钥</span><textarea name="install_ssh_private_key" data-sensitive-empty="1" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" style="min-height:110px"></textarea></label>
          <div class="actions" style="margin-top:12px">
            <button class="green" type="submit" name="action" value="install_3xui" data-busy="提交中">提交安装任务</button>
          </div>
        </form>
      </section>

      <section class="section page-panel page-installer">
        <div class="section-head">
          <div>
            <h2>安装结果</h2>
          </div>
          <?php if ($installJobs): ?>
            <form method="post" onsubmit="return confirm('清理所有安装结果展示？不会删除资源。')">
              <button class="danger" type="submit" name="action" value="clear_install_results">清理结果</button>
            </form>
          <?php endif; ?>
        </div>
        <?php if (!$installJobs): ?>
          <p class="hint">还没有安装结果</p>
        <?php else: ?>
          <?php foreach (array_slice($installJobs, 0, 8) as $job): ?>
            <?php
              $panel = is_array($job['install_result'] ?? null) ? $job['install_result'] : [];
              $panelText = (string)($job['install_text'] ?? '');
              $installCopiedAt = (int)($job['install_copied_at'] ?? 0);
            ?>
            <div class="line-card">
              <div class="split">
                <div>
                  <strong><?= xsw_h((string)($panel['name'] ?? '3x-ui')) ?></strong>
                  <span class="pill"><?= xsw_h((string)($panel['code'] ?? '')) ?></span>
                  <div class="hint"><?= xsw_h((string)($panel['host'] ?? '')) ?> · <?= xsw_h(xsw_format_time((int)($panel['installed_at'] ?? $job['finished_at'] ?? 0))) ?></div>
                </div>
              </div>
              <?php if ($panelText !== ''): ?>
                <div class="copyline" style="margin-top:10px">
                  <textarea class="panel-result" readonly onclick="this.select()"><?= xsw_h($panelText) ?></textarea>
                  <button type="button" class="copy-install-once" data-job-id="<?= xsw_h((string)($job['id'] ?? '')) ?>" data-return-page="installer">复制并隐藏</button>
                </div>
              <?php else: ?>
                <p class="hint">面板信息已复制并隐藏<?= $installCopiedAt ? ' · ' . xsw_h(xsw_format_time($installCopiedAt)) : '' ?></p>
              <?php endif; ?>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </section>

      <?php if (!$firewallActive): ?>
        <section class="section page-panel page-firewall">
          <div class="section-head">
            <div>
              <h2>资源中心服务器</h2>
            </div>
          </div>
          <?php if (!$firewallResourceRows): ?>
            <p class="hint">资源中心还没有可识别 IP 的服务器。</p>
          <?php else: ?>
            <table class="compact-table fw-resource-table">
              <thead><tr><th></th><th>服务器</th><th>IP</th><th>SSH</th><th>最后应用</th><th>操作</th></tr></thead>
              <tbody>
                <?php foreach ($firewallResourceRows as $fwResource): ?>
                  <?php
                    $fwSession = is_array($fwResource['session'] ?? null) ? $fwResource['session'] : null;
                    $fwSessionId = (string)($fwResource['session_id'] ?? '');
                    $fwApplyAt = $fwSession ? (int)($fwSession['last_apply_at'] ?? 0) : 0;
                  ?>
                  <tr>
                    <td><input type="radio" name="firewall_server_code" value="<?= xsw_h((string)$fwResource['code']) ?>" form="fw-assets-connect-form" style="width:16px; height:16px"></td>
                    <td><strong><?= xsw_h((string)$fwResource['label']) ?></strong><br><span class="pill"><?= xsw_h((string)$fwResource['code']) ?></span></td>
                    <td class="mono"><?= xsw_h((string)$fwResource['host']) ?></td>
                    <td>
                      <?php if ($fwSession): ?>
                        <?php $fwSessionStatus = (string)($fwSession['last_status'] ?? '已接入'); ?>
                        <span class="pill <?= $fwSessionStatus === '已接入' ? 'status-ok' : '' ?>"><?= xsw_h((string)($fwSession['ssh_user'] ?? 'root')) ?>:<?= (int)($fwSession['ssh_port'] ?? 22) ?> · <?= xsw_h($fwSessionStatus) ?></span>
                      <?php else: ?>
                        <span class="pill">未接入</span>
                      <?php endif; ?>
                    </td>
                    <td><?= $fwApplyAt ? xsw_h(xsw_format_time($fwApplyAt)) : '-' ?></td>
                    <td>
                      <?php if ($fwSession): ?>
                        <form method="post" style="display:inline">
                          <input type="hidden" name="firewall_session_id" value="<?= xsw_h($fwSessionId) ?>">
                          <button class="green" type="submit" name="action" value="firewall_select">进入管理</button>
                        </form>
                        <form method="post" style="display:inline" onsubmit="return confirm('会删除这台服务器保存在面板里的 SSH 凭据。继续？')">
                          <input type="hidden" name="firewall_target_ids[]" value="<?= xsw_h($fwSessionId) ?>">
                          <button class="danger" type="submit" name="action" value="firewall_forget">删除 SSH</button>
                        </form>
                      <?php else: ?>
                        <button type="button" class="fw-resource-pick" data-code="<?= xsw_h((string)$fwResource['code']) ?>">选择接入</button>
                      <?php endif; ?>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
            <form id="fw-assets-connect-form" method="post" class="muted-box" style="margin-top:12px" onsubmit="return confirm('会给选中的一台资源中心服务器保存 SSH 凭据。继续？')">
              <div class="row">
                <label><span class="label">SSH 端口</span><input name="asset_firewall_ssh_port" type="number" min="1" max="65535" value="22"></label>
                <label><span class="label">SSH 用户</span><input name="asset_firewall_ssh_user" value="root"></label>
                <label><span class="label">SSH 密码</span><input id="asset_firewall_ssh_password" name="asset_firewall_ssh_password" type="password" autocomplete="new-password" data-sensitive-empty="1"></label>
              </div>
              <label style="margin-top:12px"><span class="label">SSH 私钥</span><textarea name="asset_firewall_ssh_private_key" data-sensitive-empty="1" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" style="min-height:90px"></textarea></label>
              <div class="actions" style="margin-top:12px">
                <button class="green" type="submit" name="action" value="firewall_connect_assets" data-preserve-scroll="1">保存所选 SSH 信息</button>
              </div>
            </form>
          <?php endif; ?>
        </section>

        <?php if ($firewallStandaloneSessions): ?>
          <section class="section page-panel page-firewall">
            <div class="section-head">
              <div>
                <h2>其他已接入 IP</h2>
              </div>
            </div>
            <table class="compact-table fw-resource-table">
              <thead><tr><th></th><th>服务器</th><th>IP</th><th>SSH</th><th>最后应用</th><th>操作</th></tr></thead>
              <tbody>
                <?php foreach ($firewallStandaloneSessions as $fwId => $fwSession): ?>
                  <?php
                    $fwApplyAt = (int)($fwSession['last_apply_at'] ?? 0);
                  ?>
                  <tr>
                    <td></td>
                    <td><strong><?= xsw_h((string)($fwSession['label'] ?? $fwSession['host'] ?? $fwId)) ?></strong><br><span class="pill"><?= xsw_h((string)($fwSession['last_status'] ?? '已接入')) ?></span></td>
                    <td class="mono"><?= xsw_h((string)($fwSession['host'] ?? '')) ?></td>
                    <?php $fwSessionStatus = (string)($fwSession['last_status'] ?? '已接入'); ?>
                    <td><span class="pill <?= $fwSessionStatus === '已接入' ? 'status-ok' : '' ?>"><?= xsw_h((string)($fwSession['ssh_user'] ?? 'root')) ?>:<?= (int)($fwSession['ssh_port'] ?? 22) ?> · <?= xsw_h($fwSessionStatus) ?></span></td>
                    <td><?= $fwApplyAt ? xsw_h(xsw_format_time($fwApplyAt)) : '-' ?></td>
                    <td>
                      <form method="post" style="display:inline">
                        <input type="hidden" name="firewall_session_id" value="<?= xsw_h((string)$fwId) ?>">
                        <button class="green" type="submit" name="action" value="firewall_select">进入管理</button>
                      </form>
                      <form method="post" style="display:inline" onsubmit="return confirm('会删除这台服务器保存在面板里的 SSH 凭据。继续？')">
                        <input type="hidden" name="firewall_target_ids[]" value="<?= xsw_h((string)$fwId) ?>">
                        <button class="danger" type="submit" name="action" value="firewall_forget">删除</button>
                      </form>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </section>
        <?php endif; ?>

        <section class="section page-panel page-firewall fw-manual-section">
          <div class="section-head">
            <div>
              <h2>接入防火墙服务器</h2>
            </div>
          </div>
          <form method="post" class="fw-manual-form" onsubmit="return confirm('会保存这台服务器的 SSH 凭据，用于后续防火墙管理。继续？')">
            <div class="fw-manual-grid">
              <label><span class="label">显示名称</span><input name="firewall_label" placeholder="例如 德国新1"></label>
              <label><span class="label">目标 IP</span><input name="firewall_host" required placeholder="1.2.3.4"></label>
              <label><span class="label">SSH 端口</span><input name="firewall_ssh_port" type="number" min="1" max="65535" value="22"></label>
              <label><span class="label">SSH 用户</span><input name="firewall_ssh_user" value="root"></label>
            </div>
            <div class="fw-manual-auth">
              <label><span class="label">SSH 密码</span><input name="firewall_ssh_password" type="password" autocomplete="new-password" data-sensitive-empty="1"></label>
              <label><span class="label">SSH 私钥</span><textarea name="firewall_ssh_private_key" data-sensitive-empty="1" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off"></textarea></label>
            </div>
            <div class="fw-manual-footer">
              <button class="green" type="submit" name="action" value="firewall_connect">接入</button>
            </div>
          </form>
        </section>
      <?php else: ?>
        <?php $ruleRows = $firewallRules ?: [[
          'id' => '',
          'protocol' => 'tcp',
          'ports' => [],
          'policy' => 'allow',
          'sources' => ['0.0.0.0/0'],
          'remark' => '',
          'enabled' => true,
          'updated_at' => 0,
        ]]; ?>
        <section class="section page-panel page-firewall">
          <form method="post" class="fw-console" onsubmit="return event.submitter && event.submitter.dataset.noConfirm ? true : confirm((event.submitter && event.submitter.dataset.confirm) || '确定执行防火墙任务？')">
            <input type="hidden" name="firewall_mode" value="apply">
            <div class="fw-topbar">
              <label class="switch-line"><span>防火墙开关</span><input type="checkbox" name="firewall_enabled" value="1" <?= array_key_exists('enabled', $firewallPolicy) ? (!empty($firewallPolicy['enabled']) ? 'checked' : '') : 'checked' ?>><i></i></label>
              <span class="divider"></span>
              <label class="switch-line"><span>禁 ping</span><input type="checkbox" name="firewall_deny_ping" value="1" <?= !empty($firewallPolicy['deny_ping']) ? 'checked' : '' ?>><i></i></label>
              <?php [$activeStatusLabel, $activeStatusClass] = xsw_firewall_status_meta($firewallActiveStatus, !empty($firewallPolicy['enabled'])); ?>
              <span class="fw-managed">当前：<?= xsw_h((string)($firewallActive['label'] ?? $firewallActive['host'] ?? '')) ?> · <?= xsw_h((string)($firewallActive['host'] ?? '')) ?> · <span class="pill <?= xsw_h($activeStatusClass) ?>"><?= xsw_h($activeStatusLabel) ?></span></span>
              <button type="submit" name="action" value="firewall_exit_active" data-no-confirm="1">退出管理</button>
            </div>
            <div class="fw-tabs">
              <span class="active">端口规则：<?= count($firewallRules) ?></span>
            </div>
            <div class="fw-actions">
              <button class="green fw-rule-add" type="button">添加端口规则</button>
              <div class="fw-quick-rules">
                <span class="quick-title">快捷加入</span>
                <?php if ((int)($firewallActive['ssh_port'] ?? 0) > 0): ?>
                  <button type="button" class="fw-quick-rule" data-protocol="tcp" data-port="<?= (int)($firewallActive['ssh_port'] ?? 22) ?>" data-policy="allow" data-source="<?= xsw_h($browserCidr ?: '0.0.0.0/0') ?>" data-remark="SSH 远程服务">SSH</button>
                <?php endif; ?>
                <?php if ($firewallPanelPort > 0): ?>
                  <button type="button" class="fw-quick-rule" data-protocol="tcp" data-port="<?= (int)$firewallPanelPort ?>" data-policy="allow" data-source="<?= xsw_h($browserCidr ?: '0.0.0.0/0') ?>" data-remark="3x-ui 面板端口">面板</button>
                <?php endif; ?>
                <?php if ($firewallStandalonePorts): ?>
                  <button type="button" class="fw-quick-rule" data-protocol="tcp" data-port="<?= xsw_h(implode(',', $firewallStandalonePorts)) ?>" data-policy="allow" data-source="0.0.0.0/0" data-remark="单节点入口端口">单节点</button>
                <?php endif; ?>
                <button type="button" class="fw-quick-rule" data-protocol="tcp" data-port="22,3389,3306,5432,6379,27017" data-policy="deny" data-source="0.0.0.0/0" data-remark="高危端口阻止">高危阻止</button>
                <button type="button" class="fw-quick-rule" data-protocol="udp" data-port="1-65535" data-policy="deny" data-source="0.0.0.0/0" data-remark="UDP 全阻止">UDP 阻止</button>
                <?php if ($browserCidr): ?>
                  <button type="button" class="fw-quick-rule" data-protocol="tcp" data-port="" data-policy="allow" data-source="<?= xsw_h($browserCidr) ?>" data-remark="我的 IP 白名单">我的 IP</button>
                <?php endif; ?>
              </div>
              <label class="button">导入规则<input class="fw-rule-import" type="file" accept="application/json,.json" hidden></label>
              <button type="button" class="fw-rule-export">导出规则</button>
              <input class="fw-search" type="search" placeholder="请输入端口/来源">
            </div>
            <div class="fw-table-wrap">
              <table class="compact-table fw-rule-table fw-security-table">
                <thead><tr><th></th><th>协议</th><th>端口</th><th>状态</th><th>策略</th><th>方向</th><th>来源</th><th>备注</th><th>时间</th><th>操作</th></tr></thead>
                <tbody>
                  <?php foreach ($ruleRows as $idx => $rule): ?>
                    <?php
                      $ruleId = (string)($rule['id'] ?? '');
                      $protocol = (string)($rule['protocol'] ?? 'tcp');
                      $policy = (string)($rule['policy'] ?? 'allow');
                      $portsValue = xsw_firewall_port_label((array)($rule['ports'] ?? []));
                      $sourceValue = implode("\n", (array)($rule['sources'] ?? ['0.0.0.0/0']));
                      $enabled = array_key_exists('enabled', $rule) ? !empty($rule['enabled']) : true;
                      [$ruleStatusLabel, $ruleStatusClass] = xsw_firewall_status_meta($firewallActiveStatus, $enabled);
                    ?>
                    <tr>
                      <td><input type="checkbox" name="firewall_rule_enabled[]" value="<?= (int)$idx ?>" <?= $enabled ? 'checked' : '' ?> style="width:16px; height:16px"><input type="hidden" name="firewall_rule_id[]" value="<?= xsw_h($ruleId) ?>"></td>
                      <td><select name="firewall_rule_protocol[]"><option value="tcp" <?= $protocol === 'tcp' ? 'selected' : '' ?>>tcp</option><option value="udp" <?= $protocol === 'udp' ? 'selected' : '' ?>>udp</option></select></td>
                      <td><input name="firewall_rule_port[]" value="<?= xsw_h($portsValue) ?>" placeholder="22 或 33000-33110"></td>
                      <td><span class="pill <?= xsw_h($ruleStatusClass) ?>"><?= xsw_h($ruleStatusLabel) ?></span></td>
                      <td><select name="firewall_rule_policy[]"><option value="allow" <?= $policy === 'allow' ? 'selected' : '' ?>>放行</option><option value="deny" <?= $policy === 'deny' ? 'selected' : '' ?>>阻止</option></select></td>
                      <td>入站</td>
                      <td><textarea name="firewall_rule_source[]" placeholder="所有IP 或 1.2.3.4"><?= xsw_h($sourceValue) ?></textarea></td>
                      <td><input name="firewall_rule_remark[]" value="<?= xsw_h((string)($rule['remark'] ?? '')) ?>" placeholder="备注"></td>
                      <td><?= !empty($rule['updated_at']) ? xsw_h(xsw_format_time((int)$rule['updated_at'])) : '--' ?></td>
                      <td><button type="button" class="fw-rule-edit">修改</button><button type="button" class="fw-rule-remove danger">删除</button></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
            <div class="actions" style="margin-top:12px">
              <button class="green" type="submit" name="action" value="apply_firewall" data-preserve-scroll="1" onclick="this.form.firewall_mode.value='apply'" data-confirm="会应用当前安全组规则到这台服务器。继续？">应用规则</button>
              <button class="danger" type="submit" name="action" value="apply_firewall" data-preserve-scroll="1" onclick="this.form.firewall_mode.value='clear'" data-confirm="会清除这台服务器的 JD 防火墙规则。继续？">清空规则</button>
            </div>
          </form>
        </section>
      <?php endif; ?>
      <section class="section page-panel page-lines">
        <div class="section-head">
          <div>
            <h2>链路新建</h2>
          </div>
        </div>
        <form method="post" onsubmit="return confirm((event.submitter && event.submitter.dataset.confirm) || '确定执行？')">
          <span class="label">资源编排</span>
          <div class="server-strip">
            <?php foreach ($state['servers'] as $server): ?>
              <button type="button" class="server-chip path-chip" data-target="new_line_path" data-code="<?= xsw_h($server['code']) ?>"><?= xsw_h(xsw_server_label($server)) ?></button>
            <?php endforeach; ?>
          </div>
          <div class="row">
            <label><span class="label">链路名称</span><input name="new_line_name" required placeholder="例如 德国-美国-AK"></label>
            <label><span class="label">拓扑路径</span><input id="new_line_path" name="new_line_path" required placeholder="A>B>C>D" autocomplete="off"></label>
            <label><span class="label">计划时间</span><input name="new_line_run_at" type="datetime-local" value="<?= xsw_h($defaultRunAt) ?>"></label>
          </div>
          <div class="actions" style="margin-top:10px">
              <button class="green" type="submit" name="action" value="create_line" data-confirm="会提交任务创建这条链路，继续？">提交链路发布</button>
              <button type="submit" name="action" value="schedule_create_line" data-confirm="会保存计划，到时间后自动创建这条链路，继续？">计划新建</button>
              <button type="button" class="path-clear" data-target="new_line_path">清空拓扑</button>
          </div>
        </form>
      </section>

      <section class="section page-panel page-lines">
        <div class="section-head">
          <div>
            <h2>链路资产</h2>
          </div>
        </div>
        <?php if ($state['lines']): ?>
          <div style="margin-top:14px">
            <?php foreach ($state['lines'] as $line): ?>
              <?php
                $linePathValue = implode('>', $line['path']);
                $lineInputId = 'line_path_' . preg_replace('/[^A-Za-z0-9_-]/', '_', (string)$line['id']);
                $lineDeleteJob = xsw_line_delete_job($state, (string)$line['id']);
              ?>
              <div class="line-card">
                <div class="split">
                  <div>
                    <strong><?= xsw_h($line['name']) ?></strong>
                    <span class="pill"><?= xsw_h($line['id']) ?></span>
                    <?php if ($lineDeleteJob): ?><span class="pill">下线中 <?= xsw_h((string)($lineDeleteJob['id'] ?? '')) ?></span><?php endif; ?>
                    <div class="line-path"><?= xsw_h(implode(' -> ', $line['path'])) ?></div>
                  </div>
                </div>
                <form method="post" style="margin-top:12px" onsubmit="return confirm((event.submitter && event.submitter.dataset.confirm) || '确定执行？')">
                  <input type="hidden" name="line_id" value="<?= xsw_h($line['id']) ?>">
                  <span class="label">拓扑编排</span>
                  <div class="server-strip">
                    <?php foreach ($state['servers'] as $server): ?>
                      <button type="button" class="server-chip path-chip" data-target="<?= xsw_h($lineInputId) ?>" data-code="<?= xsw_h($server['code']) ?>"><?= xsw_h(xsw_server_label($server)) ?></button>
                    <?php endforeach; ?>
                  </div>
                  <div class="row">
                    <label><span class="label">链路名称</span><input name="line_name" value="<?= xsw_h($line['name']) ?>"></label>
                    <label><span class="label">拓扑路径</span><input id="<?= xsw_h($lineInputId) ?>" name="line_path" value="<?= xsw_h($linePathValue) ?>"></label>
                    <label><span class="label">计划时间</span><input name="line_run_at" type="datetime-local" value="<?= xsw_h($defaultRunAt) ?>"></label>
                  </div>
                  <label style="display:flex; gap:8px; align-items:center; color:var(--muted); font-size:13px; margin-top:8px">
                    <input type="checkbox" name="keep_entry" value="1" checked style="width:16px; height:16px">
                    入口资源不变时，保持 VLESS Reality 入口链接
                  </label>
                  <div class="actions" style="margin-top:10px">
                    <button type="button" class="path-clear" data-target="<?= xsw_h($lineInputId) ?>">清空拓扑</button>
                    <button type="button" class="path-restore" data-target="<?= xsw_h($lineInputId) ?>" data-value="<?= xsw_h($linePathValue) ?>">恢复当前拓扑</button>
                    <button class="green" type="submit" name="action" value="update_line" data-confirm="会提交任务，按新拓扑变更并发布。继续？">提交拓扑变更</button>
                    <button type="submit" name="action" value="schedule_update_line" data-confirm="会保存计划，到时间后变更并发布，继续？">计划变更</button>
                    <button type="submit" name="action" value="schedule_delete_line" data-confirm="会保存计划，到时间后下线这条链路，继续？" <?= $lineDeleteJob ? 'disabled title="这条链路已有下线任务"' : '' ?>>计划下线</button>
                  </div>
                </form>
                <form method="post" style="margin-top:10px" onsubmit="return confirm('会提交任务下线这条链路创建过的节点和路由，继续？')">
                  <input type="hidden" name="line_id" value="<?= xsw_h($line['id']) ?>">
                  <button class="danger" type="submit" name="action" value="delete_line" <?= $lineDeleteJob ? 'disabled title="这条链路已有下线任务"' : '' ?>>提交链路下线</button>
                </form>
                </div>
            <?php endforeach; ?>
          </div>
        <?php else: ?>
          <p class="hint">当前没有链路</p>
        <?php endif; ?>
      </section>

      <section class="section page-panel page-lines">
        <div class="section-head">
          <div>
            <h2>客户端入口</h2>
          </div>
        </div>
        <?php if (!$entryLinks): ?>
          <p class="hint">还没有可用入口</p>
        <?php else: ?>
          <?php foreach ($entryLinks as $lineId => $link): ?>
            <div class="hint"><?= xsw_h($link['name'] . ' · ' . ($linePaths[(string)$lineId] ?? '')) ?></div>
            <div class="copyline" style="margin-top:8px">
              <input readonly value="<?= xsw_h($link['url']) ?>" onclick="this.select()" title="<?= xsw_h($link['name']) ?>">
              <button type="button" onclick="navigator.clipboard && navigator.clipboard.writeText(this.previousElementSibling.value)">复制</button>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </section>

      <section class="section page-panel page-lines">
        <h2>链路组成</h2>
        <?php if ($planError): ?>
          <p class="hint"><?= xsw_h($planError) ?></p>
        <?php elseif (!$plan): ?>
          <p class="hint">还没有可展示的链路组成</p>
        <?php else: ?>
          <table>
            <thead><tr><th>类型</th><th>资源</th><th>端口</th><th>Tag</th></tr></thead>
            <tbody>
              <?php foreach ($plan['entries'] as $entry): ?>
                <tr>
                  <td><?= xsw_h('入口 ' . $entry['line_name']) ?></td>
                  <td><?= xsw_h($entry['server']) ?></td>
                  <td><code><?= (int)$entry['port'] ?></code></td>
                  <td><code><?= xsw_h($entry['inbound_tag']) ?></code></td>
                </tr>
              <?php endforeach; ?>
              <?php foreach ($plan['edges'] as $edge): ?>
                <tr>
                  <td><?= xsw_h($edge['line_name']) ?></td>
                  <td><?= xsw_h($edge['from'] . ' -> ' . $edge['to']) ?></td>
                  <td><code><?= (int)$edge['port'] ?></code></td>
                  <td><code><?= xsw_h($edge['outbound_tag']) ?></code></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
      </section>

      <section class="section page-panel page-singles">
        <div class="section-head">
          <div>
            <h2>单节点开通</h2>
          </div>
        </div>
        <form method="post" onsubmit="return confirm((event.submitter && event.submitter.dataset.confirm) || '确定执行？')">
          <div class="row">
            <label>
              <span class="label">资源</span>
              <select name="standalone_server" required>
                <?php foreach ($state['servers'] as $server): ?>
                  <option value="<?= xsw_h((string)$server['code']) ?>"><?= xsw_h(xsw_server_label($server)) ?></option>
                <?php endforeach; ?>
              </select>
            </label>
            <label><span class="label">入口名称</span><input name="standalone_name" required placeholder="例如 德国单节点"></label>
            <label><span class="label">入口端口</span><input name="standalone_port" required type="number" min="1" max="65535" value="<?= (int)$nextStandalonePort ?>"></label>
          </div>
          <label style="display:flex; gap:8px; align-items:center; color:var(--muted); font-size:13px; margin-top:10px">
            <input type="checkbox" name="standalone_socks5" value="1" style="width:16px; height:16px">
            SOCKS5 入口
          </label>
          <div class="standalone-submit-row">
            <button class="green" type="submit" name="action" value="create_standalone" data-confirm="会在所选资源上创建一个单节点入口，出口就是该资源本机。继续？" <?= empty($state['servers']) ? 'disabled title="请先添加资源"' : '' ?>>提交开通任务</button>
            <span></span>
            <a class="button bottom-link" href="#page-bottom">去底部</a>
          </div>
        </form>
      </section>

      <section class="section page-panel page-singles">
        <div class="section-head">
          <div>
            <h2>单节点资产</h2>
          </div>
        </div>
        <?php if (!$standaloneEntries): ?>
          <p class="hint">当前没有单节点入口</p>
        <?php else: ?>
          <?php foreach ($standaloneEntries as $entry): ?>
            <?php $info = $standaloneInfos[(string)($entry['id'] ?? '')] ?? null; ?>
            <div class="line-card">
              <div class="split">
                <div>
                  <strong><?= xsw_h((string)($entry['name'] ?? $entry['id'])) ?></strong>
                  <span class="pill"><?= xsw_h(strtoupper((string)($entry['protocol'] ?? 'vless')) === 'SOCKS5' ? 'SOCKS5' : 'VLESS Reality') ?></span>
                  <span class="pill"><?= xsw_h((string)($entry['id'] ?? '')) ?></span>
                  <div class="hint"><?= xsw_h((string)($info['server_label'] ?? $entry['server'] ?? '')) ?> · <code><?= (int)($entry['port'] ?? 0) ?></code></div>
                </div>
                <form method="post" onsubmit="return confirm('会提交任务删除这个单节点入口，继续？')">
                  <input type="hidden" name="entry_id" value="<?= xsw_h((string)($entry['id'] ?? '')) ?>">
                  <button class="danger" type="submit" name="action" value="delete_standalone">提交下线</button>
                </form>
              </div>
              <?php if ($info && ($info['protocol'] ?? '') === 'socks5'): ?>
                <div class="row" style="margin-top:10px">
                  <label><span class="label">Host</span><input readonly value="<?= xsw_h((string)$info['host']) ?>" onclick="this.select()"></label>
                  <label><span class="label">Port</span><input readonly value="<?= (int)$info['port'] ?>" onclick="this.select()"></label>
                  <label><span class="label">Username</span><input readonly value="<?= xsw_h((string)($info['username'] ?? '')) ?>" onclick="this.select()"></label>
                </div>
                <div class="copyline" style="margin-top:8px">
                  <input readonly value="<?= xsw_h((string)($info['password'] ?? '')) ?>" onclick="this.select()" title="SOCKS5 Password">
                  <button type="button" onclick="navigator.clipboard && navigator.clipboard.writeText(this.previousElementSibling.value)">复制密码</button>
                </div>
                <div class="copyline" style="margin-top:8px">
                  <input readonly value="<?= xsw_h((string)$info['url']) ?>" onclick="this.select()" title="SOCKS5 URL">
                  <button type="button" onclick="navigator.clipboard && navigator.clipboard.writeText(this.previousElementSibling.value)">复制入口</button>
                </div>
              <?php elseif ($info && !empty($info['url'])): ?>
                <div class="qr-entry">
                  <div class="qr-box">
                    <img src="qr.php?standalone=<?= xsw_h(rawurlencode((string)($entry['id'] ?? ''))) ?>" alt="VLESS Reality QR">
                  </div>
                  <div class="copyline">
                    <input readonly value="<?= xsw_h((string)$info['url']) ?>" onclick="this.select()" title="<?= xsw_h((string)($entry['name'] ?? $entry['id'])) ?>">
                    <button type="button" onclick="navigator.clipboard && navigator.clipboard.writeText(this.previousElementSibling.value)">复制入口</button>
                  </div>
                </div>
              <?php else: ?>
                <p class="hint">任务完成后显示入口信息</p>
              <?php endif; ?>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </section>
    </div>

    <div>
      <section class="section page-panel page-jobs">
        <?php $jobs = array_reverse($state['jobs'] ?? []); ?>
        <?php $finishedJobCount = count(array_filter($jobs, fn($job) => !in_array((string)($job['status'] ?? ''), ['pending', 'running'], true))); ?>
        <div class="section-head">
          <div>
            <h2>任务流水</h2>
          </div>
          <?php if ($finishedJobCount > 0): ?>
            <form method="post" onsubmit="return confirm('清理所有已结束任务流水？等待中和执行中的任务会保留。')">
              <button class="danger" type="submit" name="action" value="clear_finished_jobs">清理已结束</button>
            </form>
          <?php endif; ?>
        </div>
        <?php if (!$jobs): ?>
          <p class="hint">还没有任务</p>
        <?php else: ?>
          <table>
            <thead><tr><th>任务</th><th>状态</th><th>进度</th><th>时间</th><th>内容</th><th>操作</th></tr></thead>
            <tbody>
            <?php foreach ($jobs as $job): ?>
              <?php
                $jobStatus = (string)($job['status'] ?? '');
                $canCancelJob = $jobStatus === 'pending' && empty($job['cancelled_at']);
              ?>
              <tr>
                <td>
                  <code><?= xsw_h((string)($job['id'] ?? '')) ?></code>
                  <div class="hint"><?= xsw_h(xsw_job_type_label((string)($job['type'] ?? ''))) ?></div>
                </td>
                <td><span class="pill <?= xsw_h(xsw_job_status_class($jobStatus)) ?>"><?= xsw_h(xsw_job_status_label($jobStatus)) ?></span></td>
                <td>
                  <?= xsw_h((string)($job['progress'] ?? '等待调度执行')) ?>
                  <?php if (isset($job['result_count'])): ?>
                    <div class="hint">步骤 <?= (int)$job['result_count'] ?>，错误 <?= (int)($job['result_errors'] ?? 0) ?></div>
                  <?php endif; ?>
                  <?php if (!empty($job['error'])): ?><div class="hint status-err"><?= xsw_h((string)$job['error']) ?></div><?php endif; ?>
                </td>
                <td>
                  <div class="hint">计划 <?= xsw_h(xsw_format_time((int)($job['run_at'] ?? 0))) ?></div>
                  <?php if (!empty($job['started_at'])): ?><div class="hint">开始 <?= xsw_h(xsw_format_time((int)$job['started_at'])) ?></div><?php endif; ?>
                  <?php if (!empty($job['finished_at'])): ?><div class="hint">结束 <?= xsw_h(xsw_format_time((int)$job['finished_at'])) ?></div><?php endif; ?>
                </td>
                <td class="mono">
                  <?= xsw_h(xsw_job_payload_summary($job)) ?>
                  <?php if (!empty($job['install_text'])): ?>
                    <details class="advanced" style="margin-top:8px">
                      <summary><span>面板信息</span></summary>
                      <div class="advanced-body">
                        <div class="copyline">
                          <textarea class="panel-result" readonly onclick="this.select()"><?= xsw_h((string)$job['install_text']) ?></textarea>
                          <button type="button" class="copy-install-once" data-job-id="<?= xsw_h((string)($job['id'] ?? '')) ?>" data-return-page="jobs">复制并隐藏</button>
                        </div>
                      </div>
                    </details>
                  <?php elseif (!empty($job['install_copied_at'])): ?>
                    <div class="hint">面板信息已复制并隐藏</div>
                  <?php endif; ?>
                </td>
                <td>
                  <?php if ($canCancelJob): ?>
                    <form method="post" onsubmit="return confirm('取消这个任务？')">
                      <input type="hidden" name="job_id" value="<?= xsw_h((string)$job['id']) ?>">
                      <button type="submit" name="action" value="cancel_job" data-busy="取消中">取消</button>
                    </form>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
      </section>

      <section class="section page-panel page-settings">
        <h2>访问安全</h2>
        <form method="post">
          <div class="row">
            <label><span class="label">新管理凭据</span><input name="new_password" type="password" minlength="10" autocomplete="new-password"></label>
            <label><span class="label">确认管理凭据</span><input name="new_password_confirm" type="password" minlength="10" autocomplete="new-password"></label>
            <div style="display:flex; align-items:end"><button type="submit" name="action" value="change_password">更新凭据</button></div>
          </div>
        </form>
      </section>

      <section class="section page-panel page-logs">
        <div class="section-head">
          <div>
            <h2>审计记录</h2>
            <div class="toolbar">
              <span class="pill">未读 <?= (int)$logStats['unread'] ?></span>
              <span class="pill">全部 <?= (int)$logStats['total'] ?></span>
            </div>
          </div>
          <div class="actions">
            <form method="post"><button type="submit" name="action" value="mark_all_logs_read">全部标记已读</button></form>
            <form method="post" onsubmit="return confirm('清理所有已读审计记录？')"><button type="submit" name="action" value="delete_read_logs">清理已读</button></form>
            <form method="post" onsubmit="return confirm('清空全部审计记录？')"><button class="danger" type="submit" name="action" value="clear_logs">清空审计</button></form>
          </div>
        </div>
        <?php if (!$recentLogs): ?>
          <p class="hint">还没有审计记录</p>
        <?php else: ?>
          <div class="logs">
            <?php foreach ($recentLogs as $log): ?>
              <?php $logRead = !empty($log['read_at']); ?>
              <div class="log <?= $logRead ? '' : 'unread' ?>">
                <div class="log-head">
                  <div>
                    <div class="time"><?= xsw_h($log['ts'] ?? '') ?> · <?= xsw_h($log['level'] ?? '') ?></div>
                    <div><?= xsw_h($log['message'] ?? '') ?></div>
                  </div>
                  <div class="log-actions">
                    <span class="pill"><?= $logRead ? '已读' : '未读' ?></span>
                    <form method="post">
                      <input type="hidden" name="log_id" value="<?= xsw_h((string)($log['id'] ?? '')) ?>">
                      <?php if ($logRead): ?>
                        <button type="submit" name="action" value="mark_log_unread">标为未读</button>
                      <?php else: ?>
                        <button type="submit" name="action" value="mark_log_read">标为已读</button>
                      <?php endif; ?>
                    </form>
                    <form method="post" onsubmit="return confirm('清理这条审计记录？')">
                      <input type="hidden" name="log_id" value="<?= xsw_h((string)($log['id'] ?? '')) ?>">
                      <button class="danger" type="submit" name="action" value="delete_log">清理</button>
                    </form>
                  </div>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </section>
      <div id="page-bottom" aria-hidden="true"></div>
    </div>
  </div>
    </div>
  </div>
</main>
<script>
  const clearSensitiveFields = () => {
    document.querySelectorAll('[data-sensitive-empty]').forEach((field) => {
      field.value = '';
      field.defaultValue = '';
    });
  };
  clearSensitiveFields();
  window.addEventListener('pageshow', clearSensitiveFields);
  const copyText = async (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const temp = document.createElement('textarea');
    temp.value = text;
    temp.setAttribute('readonly', '');
    temp.style.position = 'fixed';
    temp.style.left = '-9999px';
    temp.style.top = '0';
    document.body.appendChild(temp);
    temp.focus();
    temp.select();
    const ok = document.execCommand('copy');
    temp.remove();
    if (!ok) {
      throw new Error('copy failed');
    }
  };
  const scrollKey = 'xsw-scroll:' + document.body.dataset.page;
  const savedScrollRaw = sessionStorage.getItem(scrollKey);
  if (savedScrollRaw !== null) {
    sessionStorage.removeItem(scrollKey);
    let savedScroll = { y: 0, targetId: '', targetTop: 0 };
    try {
      savedScroll = JSON.parse(savedScrollRaw);
    } catch (error) {
      savedScroll.y = Number(savedScrollRaw) || 0;
    }
    const restoreScroll = () => {
      window.scrollTo({ top: Math.max(0, Number(savedScroll.y) || 0), left: 0, behavior: 'auto' });
      if (!savedScroll.targetId) return;
      const target = document.getElementById(savedScroll.targetId);
      if (!target) return;
      const delta = target.getBoundingClientRect().top - (Number(savedScroll.targetTop) || 0);
      if (Math.abs(delta) > 1) {
        window.scrollBy({ top: delta, left: 0, behavior: 'auto' });
      }
    };
    requestAnimationFrame(() => {
      restoreScroll();
      requestAnimationFrame(restoreScroll);
      window.setTimeout(restoreScroll, 120);
    });
  }
  document.querySelectorAll('.toast').forEach((toast, index) => {
    const close = () => {
      toast.classList.add('is-leaving');
      window.setTimeout(() => toast.remove(), 220);
    };
    toast.addEventListener('click', close);
    window.setTimeout(close, 4200 + index * 450);
  });
  document.querySelectorAll('.copy-install-once').forEach((button) => {
    button.addEventListener('click', async () => {
      const box = button.closest('.copyline');
      const field = box ? box.querySelector('textarea') : null;
      const value = field ? field.value : '';
      if (!value) return;
      button.disabled = true;
      const original = button.textContent;
      button.textContent = '复制中';
      try {
        await copyText(value);
        const body = new URLSearchParams();
        body.set('action', 'mark_install_copied');
        body.set('job_id', button.dataset.jobId || '');
        body.set('return_page', button.dataset.returnPage || document.body.dataset.page || 'jobs');
        const response = await fetch(window.location.pathname, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body
        });
        if (!response.ok) throw new Error('mark failed');
        window.location.reload();
      } catch (error) {
        button.disabled = false;
        button.textContent = original;
        alert('复制失败，面板信息还没有隐藏。请手动选中文本复制后再点一次。');
      }
    });
  });
  document.querySelectorAll('form').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const submitter = event.submitter;
      if (submitter && submitter.dataset.preserveScroll) {
        const target = submitter.closest('.server-card, .section');
        sessionStorage.setItem(scrollKey, JSON.stringify({
          y: window.scrollY,
          targetId: target ? target.id : '',
          targetTop: target ? target.getBoundingClientRect().top : 0
        }));
      }
      if (!submitter || !submitter.dataset.busy) return;
      window.setTimeout(() => {
        if (event.defaultPrevented) return;
        submitter.disabled = true;
        submitter.textContent = submitter.dataset.busy;
      }, 0);
    });
  });
  document.querySelectorAll('.path-chip').forEach((button) => {
    button.addEventListener('click', () => {
      const pathInput = document.getElementById(button.dataset.target || '');
      if (!pathInput) return;
      const code = button.dataset.code || '';
      const parts = pathInput.value.split('>').map((item) => item.trim()).filter(Boolean);
      if (parts.includes(code)) return;
      parts.push(code);
      pathInput.value = parts.join('>');
    });
  });
  document.querySelectorAll('.path-clear').forEach((button) => {
    button.addEventListener('click', () => {
      const pathInput = document.getElementById(button.dataset.target || '');
      if (!pathInput) return;
      pathInput.value = '';
      pathInput.focus();
    });
  });
  document.querySelectorAll('.path-restore').forEach((button) => {
    button.addEventListener('click', () => {
      const pathInput = document.getElementById(button.dataset.target || '');
      if (!pathInput) return;
      pathInput.value = button.dataset.value || '';
      pathInput.focus();
    });
  });
  document.querySelectorAll('.fw-select-all').forEach((button) => {
    button.addEventListener('click', () => {
      const checked = button.dataset.checked === '1';
      document.querySelectorAll('input[name="firewall_target_ids[]"]').forEach((field) => {
        field.checked = checked;
      });
    });
  });
  document.querySelectorAll('.fw-resource-pick').forEach((button) => {
    button.addEventListener('click', () => {
      const code = button.dataset.code || '';
      const radio = Array.from(document.querySelectorAll('input[name="firewall_server_code"]')).find((field) => field.value === code);
      if (radio) radio.checked = true;
      const password = document.getElementById('asset_firewall_ssh_password');
      if (password) password.focus({preventScroll: true});
    });
  });
  document.querySelectorAll('.fw-rule-table').forEach((table) => {
    const rows = () => Array.from(table.querySelectorAll('tbody tr'));
    const reindexRows = () => {
      rows().forEach((row, index) => {
        const enabled = row.querySelector('input[name="firewall_rule_enabled[]"]');
        if (enabled) enabled.value = String(index);
      });
    };
    const setRow = (row, data = {}) => {
      const hidden = row.querySelector('input[name="firewall_rule_id[]"]');
      const enabled = row.querySelector('input[name="firewall_rule_enabled[]"]');
      const protocol = row.querySelector('select[name="firewall_rule_protocol[]"]');
      const port = row.querySelector('input[name="firewall_rule_port[]"]');
      const policy = row.querySelector('select[name="firewall_rule_policy[]"]');
      const source = row.querySelector('textarea[name="firewall_rule_source[]"]');
      const remark = row.querySelector('input[name="firewall_rule_remark[]"]');
      if (hidden) hidden.value = data.id || '';
      if (enabled) enabled.checked = data.enabled !== false;
      if (protocol) protocol.value = data.protocol === 'udp' ? 'udp' : 'tcp';
      if (port) port.value = Array.isArray(data.ports) ? data.ports.join(',') : (data.ports || data.port || '');
      if (policy) policy.value = data.policy === 'deny' ? 'deny' : 'allow';
      if (source) source.value = Array.isArray(data.sources) ? data.sources.join('\n') : (data.source || '');
      if (remark) remark.value = data.remark || '';
      const status = row.querySelector('td:nth-child(4) .pill');
      if (status) {
        status.textContent = enabled && enabled.checked ? '正常' : '停用';
        status.classList.toggle('status-ok', !!(enabled && enabled.checked));
      }
    };
    const addRow = (data = {}) => {
      const body = table.querySelector('tbody');
      const first = body ? body.querySelector('tr') : null;
      if (!body || !first) return null;
      const row = first.cloneNode(true);
      setRow(row, data);
      body.appendChild(row);
      bindRemove(row);
      reindexRows();
      return row;
    };
    const bindRemove = (row) => {
      const editButton = row.querySelector('.fw-rule-edit');
      if (editButton) {
        editButton.addEventListener('click', () => {
          const port = row.querySelector('input[name="firewall_rule_port[]"]');
          if (port) port.focus({preventScroll: true});
        });
      }
      const button = row.querySelector('.fw-rule-remove');
      if (!button) return;
      button.addEventListener('click', () => {
        const body = table.querySelector('tbody');
        if (!body) return;
        if (body.querySelectorAll('tr').length <= 1) {
          setRow(row, {source: ''});
          reindexRows();
          return;
        }
        row.remove();
        reindexRows();
      });
      const enabled = row.querySelector('input[name="firewall_rule_enabled[]"]');
      if (enabled) {
        enabled.addEventListener('change', () => setRow(row, {
          id: row.querySelector('input[name="firewall_rule_id[]"]')?.value || '',
          enabled: enabled.checked,
          protocol: row.querySelector('select[name="firewall_rule_protocol[]"]')?.value || 'tcp',
          port: row.querySelector('input[name="firewall_rule_port[]"]')?.value || '',
          policy: row.querySelector('select[name="firewall_rule_policy[]"]')?.value || 'allow',
          source: row.querySelector('textarea[name="firewall_rule_source[]"]')?.value || '',
          remark: row.querySelector('input[name="firewall_rule_remark[]"]')?.value || ''
        }));
      }
    };
    table.querySelectorAll('tbody tr').forEach(bindRemove);
    const consoleBox = table.closest('.fw-console');
    const addButton = consoleBox ? consoleBox.querySelector('.fw-rule-add') : null;
    if (addButton) {
      addButton.addEventListener('click', () => {
        const row = addRow({source: ''});
        if (row) row.querySelector('input[name="firewall_rule_port[]"]')?.focus();
      });
    }
    const quickButtons = consoleBox ? consoleBox.querySelectorAll('.fw-quick-rule') : [];
    quickButtons.forEach((button) => {
      button.addEventListener('click', () => {
        const row = addRow({
          enabled: true,
          protocol: button.dataset.protocol || 'tcp',
          port: button.dataset.port || '',
          policy: button.dataset.policy || 'allow',
          source: button.dataset.source || '0.0.0.0/0',
          remark: button.dataset.remark || ''
        });
        if (!row) return;
        const target = row.querySelector('input[name="firewall_rule_port[]"]');
        if (target) target.focus({preventScroll: true});
      });
    });
    const form = table.closest('form');
    if (form) {
      form.addEventListener('submit', reindexRows);
    }
    const search = consoleBox ? consoleBox.querySelector('.fw-search') : null;
    if (search) {
      search.addEventListener('input', () => {
        const keyword = search.value.trim().toLowerCase();
        rows().forEach((row) => {
          row.style.display = keyword === '' || row.textContent.toLowerCase().includes(keyword) ? '' : 'none';
        });
      });
    }
    const exportButton = consoleBox ? consoleBox.querySelector('.fw-rule-export') : null;
    if (exportButton) {
      exportButton.addEventListener('click', () => {
        reindexRows();
        const data = rows().map((row) => ({
          enabled: !!row.querySelector('input[name="firewall_rule_enabled[]"]')?.checked,
          protocol: row.querySelector('select[name="firewall_rule_protocol[]"]')?.value || 'tcp',
          ports: (row.querySelector('input[name="firewall_rule_port[]"]')?.value || '').split(',').map((item) => item.trim()).filter(Boolean),
          policy: row.querySelector('select[name="firewall_rule_policy[]"]')?.value || 'allow',
          sources: (row.querySelector('textarea[name="firewall_rule_source[]"]')?.value || '').split(/\s+/).map((item) => item.trim()).filter(Boolean),
          remark: row.querySelector('input[name="firewall_rule_remark[]"]')?.value || ''
        }));
        const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'xsw-firewall-rules.json';
        link.click();
        URL.revokeObjectURL(link.href);
      });
    }
    const importInput = consoleBox ? consoleBox.querySelector('.fw-rule-import') : null;
    if (importInput) {
      importInput.addEventListener('change', async () => {
        const file = importInput.files && importInput.files[0];
        if (!file) return;
        try {
          const data = JSON.parse(await file.text());
          if (!Array.isArray(data)) throw new Error('bad format');
          const body = table.querySelector('tbody');
          const first = body ? body.querySelector('tr') : null;
          if (!body || !first) return;
          body.innerHTML = '';
          data.forEach((item) => {
            const row = first.cloneNode(true);
            setRow(row, item && typeof item === 'object' ? item : {});
            body.appendChild(row);
            bindRemove(row);
          });
          if (!data.length) {
            const row = first.cloneNode(true);
            setRow(row, {source: ''});
            body.appendChild(row);
            bindRemove(row);
          }
          reindexRows();
        } catch (error) {
          alert('规则文件格式不正确');
        } finally {
          importInput.value = '';
        }
      });
    }
    reindexRows();
  });
</script>
</body>
</html>
