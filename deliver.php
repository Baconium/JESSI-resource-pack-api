<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
auth();

$dir = sessionDir($_GET['id'] ?? '');
if ($dir === null) {
    http_response_code(404);
    exit;
}

$meta     = json_decode(file_get_contents($dir . '/meta.json'), true);
$expected = 16 + $meta['plaintextLength'] + $meta['frames'] * 28;

if (!is_file($dir . '/blob.bin') && !is_file($dir . '/blob.part')) {
    if (time() - $meta['created'] > ABANDON_AFTER) {
        // session expired — clean up
        $dh = @opendir($dir);
        if ($dh) {
            while (($e = readdir($dh)) !== false) {
                if ($e !== '.' && $e !== '..') { @unlink($dir . '/' . $e); }
            }
            closedir($dh);
        }
        @rmdir($dir);
        jsonOut(['status' => 'expired']);
        exit;
    }
}

$part = $dir . '/blob.part';
$blob = $dir . '/blob.bin';

if (is_file($blob)) {
    jsonOut(['status' => 'cached']);
    exit;
}
if (is_file($part) && time() - filemtime($part) < 30) {
    jsonOut(['status' => 'in_flight']);
    exit;
}

set_time_limit(0);

$in  = fopen('php://input', 'rb');
$out = fopen($part, 'wb');
$written = 0;

$magic = fread($in, 4);
if ($magic !== "JRP1") {
    fclose($in);
    fclose($out);
    @unlink($part);
    http_response_code(400);
    jsonOut(['error' => 'bad_magic']);
    exit;
}
fwrite($out, $magic);
$written = 4;

while (!feof($in)) {
    $chunk = fread($in, 1 << 20);
    if ($chunk === false || $chunk === '') { break; }
    $written += strlen($chunk);
    if ($written > $expected) { break; }
    fwrite($out, $chunk);
    fflush($out);
}
fclose($in);
fclose($out);

if ($written < MIN_BLOB_BYTES || $written !== $expected) {
    @unlink($part);
    http_response_code(400);
    exit;
}

rename($part, $blob);
@unlink($dir . '/wanted');

jsonOut(['status' => 'stored']);
