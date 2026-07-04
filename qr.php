<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
xsw_bootstrap();
xsw_require_login();

$entryId = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_GET['standalone'] ?? ''));
if ($entryId === '') {
    http_response_code(404);
    exit;
}

$autoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoload)) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'QR library is not installed.';
    exit;
}
require $autoload;

$state = xsw_load_state();
$infos = xsw_standalone_client_infos($state);
$info = $infos[$entryId] ?? null;
if (!$info || ($info['protocol'] ?? '') !== 'vless' || empty($info['url'])) {
    http_response_code(404);
    exit;
}

$renderer = new \BaconQrCode\Renderer\ImageRenderer(
    new \BaconQrCode\Renderer\RendererStyle\RendererStyle(420, 18),
    new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
);
$writer = new \BaconQrCode\Writer($renderer);

header('Content-Type: image/svg+xml; charset=utf-8');
header('Cache-Control: private, no-store, max-age=0');
echo $writer->writeString((string)$info['url']);
