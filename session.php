<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
auth();

if (!checkSessionRateLimit()) {
    http_response_code(429);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'rate_limit_exceeded']) . "\n";
    exit;
}

if (!checkDiskBudget()) {
    http_response_code(503);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'disk_full']) . "\n";
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

$in = json_decode(file_get_contents('php://input'), true);
if (!is_array($in)) {
    http_response_code(400);
    exit;
}

$sha1      = $in['sha1']            ?? '';
$plaintext = (int)($in['plaintextLength'] ?? 0);
$frameSize = (int)($in['frameSize']       ?? 0);

if (!preg_match('/^[0-9a-f]{40}$/', $sha1)
    || $plaintext <= 0 || $plaintext > MAX_PLAIN
    || $frameSize < 4096 || $frameSize > 8 * 1024 * 1024
) {
    http_response_code(400);
    exit;
}

$id  = bin2hex(random_bytes(16));
$dir = ROOT . '/' . $id;
mkdir($dir, 0700, true);

file_put_contents($dir . '/meta.json', json_encode([
    'sha1'            => $sha1,
    'plaintextLength' => $plaintext,
    'frameSize'       => $frameSize,
    'frames'          => intdiv($plaintext + $frameSize - 1, $frameSize),
    'created'         => time(),
]));

jsonOut(['id' => $id]);
