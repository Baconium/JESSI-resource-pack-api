<?php
declare(strict_types=1);

const ROOT      = __DIR__ . '/data';
const MAX_PLAIN = 262_144_000;
const TOKEN       = 'c012e0abe13901f342eeb99cfc69bf4b'; // super duper secure token :troll:
const AUTH_HEADER = 'HTTP_X_JR_AUTH';
const MAX_SESSIONS_PER_HOUR = 10000;
const ABANDON_AFTER = 900;
const MIN_BLOB_BYTES = 45;

function auth(): void
{
    $header = $_SERVER[AUTH_HEADER] ?? '';
    if ($header === '' || !hash_equals(TOKEN, $header)) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'unauthorized']) . "\n";
        exit;
    }
}

function sessionDir(string $id): ?string
{
    if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
        return null;
    }
    $dir = ROOT . '/' . $id;
    return is_dir($dir) ? $dir : null;
}

function jsonOut(array $data): never
{
    header('Content-Type: application/json');
    echo json_encode($data) . "\n";
    exit;
}

function checkSessionRateLimit(): bool
{
    $ip   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $hour = (int)(time() / 3600);
    $file = sys_get_temp_dir() . '/jr-sess-' . $hour . '-' . md5($ip);

    $count = 0;
    if (is_file($file)) {
        $raw = @file_get_contents($file);
        if ($raw !== false) {
            $count = (int)trim($raw);
        }
    }

    if ($count >= MAX_SESSIONS_PER_HOUR) {
        return false;
    }

    file_put_contents($file, (string)($count + 1), LOCK_EX);
    return true;
}

function checkDiskBudget(): bool
{
    $free = @disk_free_space(ROOT);
    if ($free === false) { return true; }
    return $free !== false && $free > 20 * 1024 * 1024 * 1024;
}

function awaitBytes(mixed $fh, string $path, int $need, int $stallTimeout): bool
{
    $lastSize = -1;
    $lastGrew = time();

    while (true) {
        clearstatcache(true, $path);
        $size = @filesize($path);

        if ($size === false) {
            $done = dirname($path) . '/blob.bin';
            clearstatcache(true, $done);
            $size = @filesize($done);
            if ($size === false) {
                return false;
            }
        }

        if ($size >= $need) {
            return true;
        }

        if ($size !== $lastSize) {
            $lastSize = $size;
            $lastGrew = time();
        }

        if (time() - $lastGrew > $stallTimeout) {
            return false;
        }

        usleep(50_000);
    }
}
