<?php
// Tests for the client against tests/fake-api.php on PHP's built-in server. No dependencies.
// Run from the repository root: php tests/run.php

declare(strict_types=1);

spl_autoload_register(function (string $class): void {
    $file = __DIR__ . '/../src/' . substr($class, strlen('SunLicense\\')) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

use SunLicense\SunLicenseClient;

$port = 18765;
$server = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/fake-api.php'],
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes
);
register_shutdown_function(fn () => proc_terminate($server));
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
    usleep(100_000);
}

$failed = 0;
$test = function (string $name, callable $fn) use (&$failed): void {
    try {
        $fn();
        echo "ok   $name\n";
    } catch (Throwable $e) {
        $failed++;
        echo "FAIL $name: {$e->getMessage()}\n";
    }
};
$check = function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};
$lastRequest = fn (): array => json_decode(file_get_contents(sys_get_temp_dir() . '/sunlicense-php-last-request.json'), true);

$test('a valid key is accepted', function () use ($port, $check, $lastRequest) {
    $result = (new SunLicenseClient("http://127.0.0.1:$port/", token: 'good-token'))->validate('GOOD-KEY', ['host' => 'pc-1']);
    $check($result->isValid() && $result->getStatusCode() === 200, "expected valid 200, got {$result}");
    $request = $lastRequest();
    $check($request['path'] === '/api/v2/license/validate', "wrong endpoint {$request['path']}");
    $check($request['body'] === ['license' => 'GOOD-KEY', 'host' => 'pc-1'], 'payload must be {"license": key, ...context}');
    $check(str_starts_with($request['userAgent'], 'sunlicense-php/'), 'User-Agent must be sunlicense-php');
});
$test('an unknown key is rejected', function () use ($port, $check) {
    $result = (new SunLicenseClient("http://127.0.0.1:$port", token: 'good-token'))->validate('BAD-KEY');
    $check(!$result->isValid(), "an unknown key was accepted: {$result}");
    $check($result->getStatusCode() === 400 && $result->toArray()['code'] === 'NOT_FOUND', "expected 400 NOT_FOUND, got {$result}");
});
$test('a wrong API key is rejected', function () use ($port, $check) {
    $result = (new SunLicenseClient("http://127.0.0.1:$port", token: 'wrong-token'))->validate('GOOD-KEY');
    $check(!$result->isValid() && $result->getStatusCode() === 401, "expected 401, got {$result}");
});

echo $failed === 0 ? "all tests passed\n" : "$failed failed\n";
exit($failed === 0 ? 0 : 1);
