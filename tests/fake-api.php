<?php
// A fake SunLicense API for tests/run.php (php -S). /api/v2/license/validate answers 2xx only for a
// valid key; /api/v1/validate answers 200 for every key and says valid:false in the body.
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$body = json_decode(file_get_contents('php://input'), true) ?: [];
header('Content-Type: application/json');
file_put_contents(sys_get_temp_dir() . '/sunlicense-php-last-request.json', json_encode([
    'path' => $path, 'body' => $body, 'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
]));
if ($path === '/api/v1/validate') {
    echo '{"valid":false,"code":"NOT_FOUND"}';
    return;
}
if ($path !== '/api/v2/license/validate') {
    http_response_code(404);
    return;
}
if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer good-token') {
    http_response_code(401);
    echo '{"status":401}';
    return;
}
// Protection (tests/protection.php): one key answers valid with an unlock, one is suspended.
if (($body['license'] ?? null) === 'AX8P-QW3E-RT5Y-ZZ12') {
    $vectors = json_decode(file_get_contents(__DIR__ . '/fixtures/protection-test-vectors.json'), true);
    $suspended = file_exists(sys_get_temp_dir() . '/sunlicense-php-suspended');
    http_response_code($suspended ? 403 : 200);
    echo json_encode($suspended ? ['valid' => false, 'status' => 403, 'code' => 'SUSPENDED'] : $vectors['wire']['compatResponseV2']);
    return;
}
$valid = ($body['license'] ?? null) === 'GOOD-KEY';
http_response_code($valid ? 200 : 400);
echo json_encode(['valid' => $valid, 'code' => $valid ? 'VALID' : 'NOT_FOUND']);
