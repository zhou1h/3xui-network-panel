<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';
xsw_bootstrap();

$lockFile = XSW_DATA_DIR . '/cron.lock';
$lock = fopen($lockFile, 'c');
if (!$lock) {
    fwrite(STDERR, "cannot open lock\n");
    exit(1);
}
if (!flock($lock, LOCK_EX | LOCK_NB)) {
    echo json_encode(['ran' => false, 'reason' => 'locked'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(0);
}

try {
    $result = xsw_cron_tick();
    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $e) {
    xsw_log('error', $e->getMessage(), ['source' => 'cron']);
    fwrite(STDERR, $e->getMessage() . PHP_EOL);
    exit(1);
} finally {
    flock($lock, LOCK_UN);
    fclose($lock);
}

