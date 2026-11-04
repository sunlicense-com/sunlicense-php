<?php
// Tests for core unlock, integrity, the notice and protected files: SunLicense's protection test vectors
// (tests/fixtures/protection-test-vectors.json, a copy of cloud/docs/specs/protection-test-vectors.json) and the
// cache rules. Run from the repository root: php tests/protection.php

declare(strict_types=1);

spl_autoload_register(function (string $class): void {
    $file = __DIR__ . '/../src/' . substr($class, strlen('SunLicense\\')) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

use SunLicense\LockedException;
use SunLicense\RefusedException;
use SunLicense\SunLicenseClient;
use SunLicense\SunLicenseException;
use SunLicense\SunLicenseProtection as P;

$V = json_decode(file_get_contents(__DIR__ . '/fixtures/protection-test-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
const KEY = 'AX8P-QW3E-RT5Y-ZZ12';
const T0 = 1762000000.0;
$unlock = $V['wire']['compatResponseV2']['unlock'];
$compat = json_encode($V['wire']['compatResponseV2']);

$failed = 0;
$count = 0;
$test = function (string $name, callable $fn) use (&$failed, &$count): void {
    $count++;
    try {
        $fn();
        echo "ok   $name\n";
    } catch (Throwable $e) {
        $failed++;
        echo "FAIL $name: {$e->getMessage()} ({$e->getFile()}:{$e->getLine()})\n";
    }
};
$check = function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};
$throws = function (string $class, callable $fn) use ($check): Throwable {
    try {
        $fn();
    } catch (Throwable $e) {
        $check($e instanceof $class, 'expected ' . $class . ', got ' . get_class($e) . ': ' . $e->getMessage());
        return $e;
    }
    throw new RuntimeException("expected $class");
};
$tmp = function (): string {
    $d = sys_get_temp_dir() . '/sunlicense-protection-' . bin2hex(random_bytes(6));
    mkdir($d);
    return $d;
};
$clock = new stdClass();
$clock->t = T0;
$make = function (array $o = []) use ($tmp, $clock): P {
    return new P($o + ['licenseKey' => KEY, 'fingerprint' => 'machine-1', 'baseUrl' => 'https://api.example.test',
        'cacheDirectory' => $tmp(), '_now' => fn () => $clock->t, '_machine' => fn () => 'host-a']);
};

$test('HKDF matches RFC 5869 test case 1 and the product keys', function () use ($V, $check) {
    $t = $V['rfc5869TestCase1'];
    $check(bin2hex(hash_hkdf('sha256', hex2bin($t['ikmHex']), $t['length'], hex2bin($t['infoHex']), hex2bin($t['saltHex']))) === $t['okmHex'], 'okm');
    foreach ($V['productKeys'] as $k) {
        $key = hash_hkdf('sha256', hex2bin($k['orgSecretHex']), 32, $k['infoAscii'], $k['saltAscii']);
        $check(base64_encode($key) === $k['productKeyBase64'], $k['name']);
    }
});

foreach ($V['sealed'] as $v) {
    $test('sealed vector opens, and seals to the same bytes: ' . $v['name'], function () use ($v, $check) {
        $key = base64_decode($v['productKeyBase64']);
        [$data, $digests] = P::open($v['sealed'], $key);
        $check($data === base64_decode($v['dataBase64']), 'data');
        $check($digests == $v['digests'] && array_keys($digests) === array_keys($v['digests']), 'digests');
        $nonce = hex2bin($v['nonceHex']);
        $check('SLS1.' . P::encodeBase64Url($nonce . P::gcmEncrypt($key, $nonce, $v['plaintextUtf8'], 'SLS1')) === $v['sealed'], 'seal');
    });
}

foreach ($V['mustFail'] as $v) {
    $test('must fail: ' . $v['name'], fn () => $throws(LockedException::class, fn () => P::open($v['sealed'], base64_decode($v['productKeyBase64']))));
}

$test('digests, normalised input, padded base64url', function () use ($V, $check) {
    foreach ($V['digests'] as $d) {
        if (isset($d['inputUtf8'])) {
            $check(P::digest($d['inputUtf8']) === $d['sha256Hex'], 'utf8');
        }
        if (isset($d['inputBase64'])) {
            $check(P::digest(base64_decode($d['inputBase64'])) === $d['sha256Hex'], 'b64');
        }
        if (isset($d['input'])) {
            $check(P::normaliseDigest($d['input']) === $d['normalised'], 'normalised');
        }
    }
    $s = $V['sealed'][0]['sealed'];
    P::open($s . str_repeat('=', (4 - (strlen($s) - 5) % 4) % 4), base64_decode($V['sealed'][0]['productKeyBase64']));
    $check(P::decodeBase64('a$b') === null, 'not base64');
});

$test('locked until a valid answer with unlock; then unseal works and remembers digests', function () use ($make, $V, $compat, $check, $throws) {
    $p = $make();
    $check(!$p->unlocked(), 'locked');
    $throws(LockedException::class, fn () => $p->unseal($V['sealed'][0]['sealed']));
    $p->accept($compat);
    $check($p->unlocked(), 'unlocked');
    $check($p->unseal($V['sealed'][0]['sealed']) === base64_decode($V['sealed'][0]['dataBase64']), 'core');
    $check($p->digests() === $V['sealed'][0]['digests'], 'digests');
});

$test('v1 answers work; valid without unlock and unreadable answers keep what it had', function () use ($make, $V, $check) {
    $p = $make();
    $p->accept($V['wire']['validateResponseV1']);
    $check($p->unlocked(), 'v1');
    foreach (['{"valid":true,"code":"VALID"}', '<html>502</html>', ['status' => 401], null, ''] as $body) {
        $p->accept($body);
    }
    $check($p->unlocked(), 'kept');
});

$test('a refused check forgets the unlock, in memory and on disk', function () use ($make, $compat, $check) {
    $p = $make();
    $p->accept($compat);
    $check(is_file($p->cacheFile()), 'cached');
    $p->accept('{"valid":false,"status":403,"code":"SUSPENDED"}');
    $check(!$p->unlocked() && !is_file($p->cacheFile()), 'forgotten');
});

$test('the cache unlocks for 7 days on this machine with this key, and nowhere else', function () use ($make, $tmp, $clock, $compat, $unlock, $check) {
    $dir = $tmp();
    $clock->t = T0;
    $at = fn (array $o = []) => $make($o + ['cacheDirectory' => $dir]);
    $at()->accept($compat);
    $files = array_values(array_diff(scandir($dir), ['.', '..']));
    $check(count($files) === 1 && $files[0] === '.sunlicense-unlock-' . substr(hash('sha256', "sunlicense-unlock-file\0" . KEY), 0, 16), 'file name');
    $text = file_get_contents("$dir/{$files[0]}");
    $check(str_starts_with($text, 'SLC1.') && !str_contains($text, $unlock), 'format');
    $check($at()->unlocked(), 'same machine');
    $check(!$at(['_machine' => fn () => 'host-b'])->unlocked(), 'another machine');
    $check(!$at(['fingerprint' => 'machine-2'])->unlocked(), 'another machine id');
    $check(!$at(['licenseKey' => 'OTHR-XXXX'])->unlocked(), 'another key');
    $clock->t = T0 + 7 * 86400 - 60;
    $check($at()->unlocked(), '6 days 23:59');
    $clock->t = T0 + 7 * 86400;
    $check(!$at()->unlocked(), '7 days');
    $clock->t = T0 - 3600;
    $check(!$at()->unlocked(), 'clock turned back');
    // the same format as the other SDKs
    $raw = P::decodeBase64(substr($text, 5));
    $key = hash('sha256', "sunlicense-unlock-cache\0" . KEY . "\0machine-1\0host-a", true);
    $check(P::gcmDecrypt($key, substr($raw, 0, 12), substr($raw, 12)) === sprintf('%d', T0 * 1000) . "\n" . $unlock, 'plaintext');
    $clock->t = T0;
});

$test('memory only, and a new license key drops the unlock', function () use ($make, $compat, $check) {
    $p = $make(['cacheDirectory' => null]);
    $p->accept($compat);
    $check($p->unlocked() && $p->cacheFile() === null, 'memory');
    $p->license('NEWK-XXXX-XXXX-XXXX', 'machine-1');
    $check(!$p->unlocked(), 'new key');
});

$test('integrity: OK, MODIFIED with the changed files, as validate fields; directories too', function () use ($make, $tmp, $V, $compat, $check) {
    $p = $make();
    $p->accept($compat);
    $check($p->integrity(fn () => 'x') === null, 'nothing unsealed yet');
    $p->unseal($V['sealed'][2]['sealed']);
    $files = ['Main.class' => 'main', 'assets/rules.dat' => 'rules', 'lib/util.jar' => 'util'];
    $reader = function (string $f) use (&$files) {
        return $files[$f] ?? null;
    };
    $check($p->integrity($reader) === 'OK' && $p->validateFields() === ['integrity' => 'OK'], 'ok');
    $files['lib/util.jar'] = 'patched';
    unset($files['Main.class']);
    $check($p->integrity($reader) === 'MODIFIED' && $p->integrityResult() === 'MODIFIED', 'modified');
    $check($p->validateFields() === ['integrity' => 'MODIFIED', 'integrityDetail' => '2 changed: Main.class (missing), lib/util.jar'], json_encode($p->validateFields()));
    $root = $tmp();
    mkdir("$root/lib");
    file_put_contents("$root/Main.class", 'main');
    file_put_contents("$root/lib/util.jar", 'util');
    $digests = ['Main.class' => P::digest('main'), 'lib/util.jar' => 'SHA256:' . strtoupper(P::digest('util')), '../escape' => 'x'];
    $check($p->integrity($root, $digests) === 'MODIFIED' && $p->validateFields()['integrityDetail'] === '1 changed: ../escape (missing)', 'escape');
    unset($digests['../escape']);
    $check($p->integrity($root, $digests) === 'OK', 'directory ok');
});

$test('integrity detail stays within 200 characters', function () use ($check) {
    $d = P::detail(array_map(fn ($i) => sprintf('lib/some-long-library-name-%02d.jar', $i), range(0, 39)));
    $check(strlen($d) <= 200 && str_starts_with($d, '40 changed: ') && preg_match('/, \+\d+ more$/', $d) === 1, $d);
});

$test('notice: product, owner, masked key, terms; never the full key', function () use ($make, $check) {
    $p = $make(['product' => 'My Plugin', 'owner' => 'Example Studio', 'terms' => 'https://example.com/terms']);
    $check($p->notice() === 'My Plugin is licensed software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: https://example.com/terms', $p->notice());
    $check($make()->notice() === 'This product is licensed software. License AX8P-XXXX-XXXX-XXXX.', 'default');
    $check(P::mask(null) === '(none)' && P::mask('ABCDEFGHIJ') === 'ABCDXXXXXX', 'mask');
});

$test('protected files: API key, license and machine headers; refusals say why', function () use ($make, $check, $throws) {
    $seen = null;
    $answer = [200, 'RULES'];
    $get = function (string $url, array $headers) use (&$seen, &$answer) {
        $seen = [$url, $headers];
        return $answer;
    };
    $p = $make(['productCode' => 'my plugin', 'apiKey' => 'sk_test', '_get' => $get]);
    $check($p->protectedFile('rules.dat') === 'RULES', 'body');
    $check($seen[0] === 'https://api.example.test/api/v2/protected-files/my%20plugin/rules.dat', $seen[0]);
    $check($seen[1]['Authorization'] === 'Bearer sk_test' && $seen[1]['license'] === KEY && $seen[1]['fingerprint'] === 'machine-1', 'headers');
    $answer = [403, '{"code":"SUSPENDED"}'];
    $e = $throws(RefusedException::class, fn () => $p->protectedFile('rules.dat'));
    $check($e->getStatus() === 403 && str_contains($e->getMessage(), 'SUSPENDED'), $e->getMessage());
    $answer = [503, ''];
    $throws(SunLicenseException::class, fn () => $p->protectedFile('rules.dat'));
    $throws(LogicException::class, fn () => $make(['_get' => $get])->protectedFile('x'));
});

$test('offline .lic: signed unlock works; bad signature, other key, expired or past refresh do not', function () use ($make, $clock, $unlock, $check) {
    if (!function_exists('sodium_crypto_sign_keypair')) {
        echo "     (skipped: no ext-sodium)\n";
        return;
    }
    $pair = sodium_crypto_sign_keypair();
    $pub = base64_encode(hex2bin('302a300506032b6570032100') . sodium_crypto_sign_publickey($pair));
    $lic = function (array $payload, ?string $secret = null) use ($pair) {
        $bytes = json_encode($payload, JSON_UNESCAPED_SLASHES);
        return P::encodeBase64Url($bytes) . '.' . P::encodeBase64Url(sodium_crypto_sign_detached($bytes, $secret ?? sodium_crypto_sign_secretkey($pair)));
    };
    $base = ['format' => 'sunlicense-offline/1', 'licenseKey' => KEY, 'issuedAt' => '2025-11-01T00:00:00Z', 'refreshAfter' => '2025-11-20T00:00:00Z',
        'policy' => ['expiresAt' => '2026-01-01T00:00:00.123456789Z'], 'unlock' => $unlock];
    $clock->t = (float) strtotime('2025-11-10T00:00:00Z');
    $at = fn () => $make(['cacheDirectory' => null]);
    $p = $at();
    $check($p->acceptOffline($lic($base), $pub) && $p->unlocked(), 'valid file');
    $check(!$at()->acceptOffline($lic($base, sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair())), $pub), 'signature');
    $check(!$at()->acceptOffline($lic(['licenseKey' => 'OTHR-XXXX'] + $base), $pub), 'another key');
    $check(!$at()->acceptOffline($lic(['policy' => ['expiresAt' => '2025-11-05T00:00:00Z']] + $base), $pub), 'expired');
    $check(!$at()->acceptOffline($lic(['refreshAfter' => '2025-11-09T00:00:00Z'] + $base), $pub), 'refresh');
    $noUnlock = $base;
    unset($noUnlock['unlock']);
    $check(!$at()->acceptOffline($lic($noUnlock), $pub), 'no unlock');
    $check(!$at()->acceptOffline('garbage', $pub), 'garbage');
    $clock->t = T0;
});

// client->validate against tests/fake-api.php on PHP's built-in server
$port = 18766;
$server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/fake-api.php'],
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
register_shutdown_function(fn () => proc_terminate($server));
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
    usleep(100_000);
}
$suspended = sys_get_temp_dir() . '/sunlicense-php-suspended';
@unlink($suspended);
$lastRequest = fn (): array => json_decode(file_get_contents(sys_get_temp_dir() . '/sunlicense-php-last-request.json'), true);

$test('client->validate sends integrity and keeps or forgets the unlock', function () use ($port, $tmp, $V, $check, $lastRequest, $suspended) {
    $client = new SunLicenseClient("http://127.0.0.1:$port", 'good-token');
    $p = $client->protection(['cacheDirectory' => $tmp(), '_machine' => fn () => 'host-a']);
    $check($client->validate(KEY, ['fingerprint' => 'machine-1'])->isValid(), 'valid');
    $check($p->unlocked() && $p->getLicenseKey() === KEY && $p->getFingerprint() === 'machine-1', 'unlocked');
    $check(!isset($lastRequest()['body']['integrity']), 'no integrity before a check');
    $p->unseal($V['sealed'][0]['sealed']);
    $check($p->integrity(fn () => 'not the jar') === 'MODIFIED', 'modified');
    touch($suspended);
    try {
        $check(!$client->validate(KEY, ['fingerprint' => 'machine-1'])->isValid(), 'refused');
    } finally {
        @unlink($suspended);
    }
    $body = $lastRequest()['body'];
    $check(($body['integrity'] ?? null) === 'MODIFIED' && ($body['integrityDetail'] ?? null) === '1 changed: plugin.jar', json_encode($body));
    $check(!$p->unlocked(), 'forgotten');
});

echo "$count tests, $failed failed\n";
exit($failed === 0 ? 0 : 1);
