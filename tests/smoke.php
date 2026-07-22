<?php
declare(strict_types=1);

require dirname(__DIR__) . '/lib.php';

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$entry = [
    'line_id' => 'line1',
    'line_name' => 'Test route',
    'uuid' => '11111111-1111-4111-8111-111111111111',
    'private_key' => 'private-key',
    'public_key' => 'public-key',
    'short_id' => 'a1b2c3d4',
    'sni' => 'www.cloudflare.com',
    'dest' => 'www.cloudflare.com:443',
    'fingerprint' => 'chrome',
    'spider_x' => '/',
    'port' => 443,
    'remark' => 'Test route · entry',
];
$inbound = xsw_vless_reality_inbound($entry);

assert_true(($inbound['streamSettings']['network'] ?? '') === 'tcp', 'RAW must serialize as tcp');
assert_true(($inbound['settings']['clients'][0]['flow'] ?? '') === 'xtls-rprx-vision', 'server client flow is missing');
assert_true(($inbound['streamSettings']['realitySettings']['target'] ?? '') === 'www.cloudflare.com:443', 'Reality target is missing');
assert_true(!array_key_exists('dest', $inbound['streamSettings']['realitySettings']), 'legacy Reality dest key must not be emitted');
assert_true(($inbound['sniffing']['destOverride'] ?? []) === ['http', 'tls', 'quic'], 'sniffing protocols do not match the UI profile');
assert_true(($inbound['sniffing']['metadataOnly'] ?? true) === false, 'metadata-only must be disabled');
assert_true(($inbound['sniffing']['routeOnly'] ?? false) === true, 'route-only must be enabled');

$presets = xsw_reality_target_presets(xsw_default_state()['settings']);
assert_true(($presets[0]['id'] ?? '') === 'google-android', 'stable Reality preset must be first');
assert_true(($presets[0]['sni'] ?? '') === 'ai.android', 'Google Android SNI is missing');
assert_true(($presets[0]['dest'] ?? '') === 'dl.google.com:443', 'Google Android target is missing');
assert_true(xsw_validate_reality_hostname('AI.Android') === 'ai.android', 'SNI normalization failed');
assert_true(xsw_normalize_reality_destination('DL.Google.com') === 'dl.google.com:443', 'Reality target normalization failed');
assert_true(xsw_normalize_reality_spider_x('test') === '/test', 'SpiderX normalization failed');
assert_true(xsw_normalize_reality_client_version('') === '', 'empty minimum client version must remain the default');
assert_true(xsw_normalize_reality_client_version('0.0.0') === '0.0.0', 'minimum client version normalization failed');
$compatibilityTarget = xsw_compatibility_reality_target(
    array_replace(xsw_default_state()['settings'], ['reality_auto_target' => false]),
    new RuntimeException('HTTP 404')
);
assert_true(($compatibilityTarget['source'] ?? '') === 'compatibility', 'old-node Reality fallback source is missing');
assert_true(($compatibilityTarget['dest'] ?? '') === 'dl.google.com:443', 'old-node Reality fallback target is wrong');
assert_true(xsw_reality_scan_sni([
    'target' => 'dl.google.com:443',
    'serverNames' => ['*.google.com', 'ai.android', 'dl.google.com'],
]) === 'ai.android', 'node-local scan must skip wildcard SANs and keep a usable SNI');

$standalonePayload = xsw_standalone_vless_payload([
    'id' => 'single3',
    'name' => 'Standalone',
    'uuid' => $entry['uuid'],
    'private_key' => $entry['private_key'],
    'public_key' => $entry['public_key'],
    'short_id' => $entry['short_id'],
    'sni' => 'ai.android',
    'dest' => 'dl.google.com:443',
    'fingerprint' => 'chrome',
    'spider_x' => '/',
    'min_client_ver' => '0.0.0',
    'port' => 36000,
    'remark' => 'Standalone · single3',
]);
assert_true(($standalonePayload['settings']['clients'][0]['email'] ?? '') === 'xsw-entry-single3-36000', 'standalone client identity changed');
assert_true(($standalonePayload['streamSettings']['realitySettings']['target'] ?? '') === 'dl.google.com:443', 'standalone target maintenance payload is wrong');
assert_true(($standalonePayload['streamSettings']['realitySettings']['minClientVer'] ?? '') === '0.0.0', 'standalone minimum client version is missing');

$orphanFixtureInbounds = [[
    'settings' => json_encode(['clients' => [
        ['email' => 'xsw-entry-single3-36000'],
        ['email' => 'shared-client'],
    ]]),
]];
$orphanFixtureClients = [
    ['email' => 'xsw-entry-single3-36000'],
    ['email' => 'xsw-relay-a-b-33100'],
    ['email' => 'shared-client'],
    ['email' => 'unrelated-manual-client'],
];
$orphans = xsw_orphaned_client_emails(
    $orphanFixtureInbounds,
    $orphanFixtureClients,
    ['xsw-relay-a-b-33100', 'shared-client']
);
assert_true($orphans === ['xsw-relay-a-b-33100'], 'only detached candidate clients may be deleted');

$state = xsw_default_state();
$state['servers']['A'] = [
    'code' => 'A',
    'name' => 'Node A',
    'access_url' => 'https://127.0.0.1:2053/panel',
    'api_token' => 'test-token',
];
$state['lines'][] = ['id' => 'line1', 'name' => 'Test route', 'path' => ['A', 'B']];
$state['servers']['B'] = [
    'code' => 'B',
    'name' => 'Node B',
    'access_url' => 'https://127.0.0.2:2053/panel',
    'api_token' => 'test-token',
];
$state['managed']['entries']['line1'] = [
    'uuid' => $entry['uuid'],
    'port' => 443,
    'short_id' => $entry['short_id'],
    'sni' => $entry['sni'],
    'dest' => $entry['dest'],
    'fingerprint' => 'chrome',
    'spider_x' => '/',
    'public_key' => $entry['public_key'],
    'private_key' => $entry['private_key'],
];
$links = xsw_entry_links($state);
$url = (string)($links['line1']['url'] ?? '');
assert_true(str_contains($url, 'flow=xtls-rprx-vision'), 'generated client URL has no Vision flow');
assert_true(!str_contains(rawurldecode($url), '#JD'), 'generated client name still has the JD prefix');

echo "smoke tests passed\n";
