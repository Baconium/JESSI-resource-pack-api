<?php
declare(strict_types=1);

$keyHex   = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
$expected = 'JESSI relay test vector. 0123456789abcdef';

$blobHex  = '4a525031000000100000000000000029000102030405060708090a0b0d4785488cc5b0' .
            '7ee120eeabc58c0b19a56690c4f1449e3fdf0d4d6f65cb36e70c0d0e0f1011121314' .
            '151617b8880cbb0b198e7d171a79e7a2bf13d1400a393848e10d17977905a80cd251' .
            '8318191a1b1c1d1e1f2021222324277971b92a012a6707089d9b121ce0e88bab548d' .
            'e0a668c8';

define('FRAME_SIZE', 16);
define('PLAIN_LEN',  41);
define('FRAMES',      3);

$blob      = hex2bin($blobHex);
$rawKey    = hex2bin($keyHex);
$plaintext = '';

$magic      = substr($blob, 0, 4);
$headerFz   = unpack('N', substr($blob, 4, 4))[1];
$headerPlen = unpack('J', substr($blob, 8, 8))[1];

if ($magic !== 'JRP1') {
    die("bad magic: got " . bin2hex($magic) . ", expected 4a525931\n");
}
if ($headerFz !== FRAME_SIZE) {
    die("bad frameSize: got $headerFz, expected " . FRAME_SIZE . "\n");
}
if ($headerPlen !== PLAIN_LEN) {
    die("bad plaintextLength: got $headerPlen, expected " . PLAIN_LEN . "\n");
}

echo "header decodes (magic=JRP1, frameSize=$headerFz, plainLen=$headerPlen)\n";

$offset = 16;

for ($i = 0; $i < FRAMES; $i++) {
    $n = min(FRAME_SIZE, PLAIN_LEN - strlen($plaintext));

    $nonce = substr($blob, $offset, 12);             $offset += 12;
    $ct    = substr($blob, $offset, $n);             $offset += $n;
    $tag   = substr($blob, $offset, 16);             $offset += 16;
    $aad   = pack('J', $i);

    $decrypted = openssl_decrypt(
        $ct, 'aes-256-gcm', $rawKey,
        OPENSSL_RAW_DATA, $nonce, $tag, $aad
    );

    if ($decrypted === false) {
        die("frame $i failed to decrypt (wrong key, tampered data, or OpenSSL error)\n");
    }

    $plaintext .= $decrypted;
    echo "frame $i decrypted (" . strlen($decrypted) . " bytes)\n";
}

if ($plaintext !== $expected) {
    die("plaintext mismatch\n  got:      " . bin2hex($plaintext) . "\n  expected: " . bin2hex($expected) . "\n");
}

echo "\n test vector decrypted correctly\n";
echo "plaintext: \"$plaintext\"\n";
