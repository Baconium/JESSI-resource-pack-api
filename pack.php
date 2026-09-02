<?php
declare(strict_types=1);
require __DIR__ . '/common.php';

define('WAIT_FOR_START', 300);
define('STALL_TIMEOUT',  30);
define('POLL_FRESH',     60);

$id  = $_GET['id']  ?? '';
$key = $_GET['key'] ?? '';

if (!preg_match('/^[0-9a-f]{32}$/', $id) || !preg_match('/^[0-9a-f]{64}$/', $key)) {
    http_response_code(404);
    exit;
}

$dir      = ROOT . '/' . $id;
$metaFile = $dir . '/meta.json';
if (!is_file($metaFile)) {
    http_response_code(404);
    exit;
}

$meta      = json_decode(file_get_contents($metaFile), true);
$frameSize = $meta['frameSize'];
$plainLen  = $meta['plaintextLength'];
$rawKey    = hex2bin($key);

$blob = $dir . '/blob.bin';
$part = $dir . '/blob.part';

if (!is_file($blob) && !is_file($part)) {
    $poll = $dir . '/poll';
    if (!is_file($poll) || time() - filemtime($poll) > POLL_FRESH) {
        http_response_code(503);
        exit;
    }
    touch($dir . '/wanted');
}

$source   = null;
$deadline = time() + WAIT_FOR_START;
while (time() < $deadline) {
    if (is_file($blob)) { $source = $blob; break; }
    if (is_file($part)) { $source = $part; break; }
    usleep(100_000);
}
if ($source === null) {
    http_response_code(504);
    exit;
}

$fh = fopen($source, 'rb');

$firstLen = min($frameSize, $plainLen);
$need     = 16 + 12 + $firstLen + 16;
if (!awaitBytes($fh, $source, $need, STALL_TIMEOUT)) {
    http_response_code(504);
    exit;
}

fseek($fh, 16);
$nonce = fread($fh, 12);
$ct    = fread($fh, $firstLen);
$tag   = fread($fh, 16);
$first = openssl_decrypt(
    $ct, 'aes-256-gcm', $rawKey,
    OPENSSL_RAW_DATA, $nonce, $tag,
    pack('J', 0)
);

if ($first === false) {
    http_response_code(403);
    fclose($fh);
    exit;
}

while (ob_get_level() > 0) { ob_end_clean(); }
ini_set('zlib.output_compression', 'Off');
if (function_exists('apache_setenv')) {
    apache_setenv('no-gzip', '1');
}
set_time_limit(0);

header('Content-Type: application/zip');
header('Content-Length: ' . $plainLen);
header('Content-Disposition: inline; filename="pack.zip"');
header('Accept-Ranges: none');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] === 'HEAD') { exit; }

echo $first;
flush();

$done  = $firstLen;
$index = 1;

while ($done < $plainLen) {
    $n    = min($frameSize, $plainLen - $done);
    $need = ftell($fh) + 12 + $n + 16;

    if (!awaitBytes($fh, $source, $need, STALL_TIMEOUT)) { break; }

    $nonce = fread($fh, 12);
    $ct    = fread($fh, $n);
    $tag   = fread($fh, 16);

    $plain = openssl_decrypt(
        $ct, 'aes-256-gcm', $rawKey,
        OPENSSL_RAW_DATA, $nonce, $tag,
        pack('J', $index)
    );
    if ($plain === false) { break; }

    echo $plain;
    flush();

    $done  += $n;
    $index += 1;
}

fclose($fh);
