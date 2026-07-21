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
