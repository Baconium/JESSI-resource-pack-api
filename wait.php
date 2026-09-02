<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
auth();

$dir = sessionDir($_GET['id'] ?? '');
if ($dir === null) {
    http_response_code(404);
    exit;
}

touch($dir . '/poll');

if (file_exists($dir . '/wanted')) {
    @unlink($dir . '/wanted');
    jsonOut(['deliver' => true]);
}

jsonOut(['deliver' => false]);
