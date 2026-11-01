<?php
// Tests for built-in product analytics. No dependencies. Run from the repository root: php tests/analytics.php

declare(strict_types=1);

spl_autoload_register(function (string $class): void {
    $file = __DIR__ . '/../src/' . substr($class, strlen('SunLicense\\')) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

use SunLicense\SunLicenseAnalytics;
use SunLicense\SunLicenseClient;

$failed = 0;
$test = function (string $name, callable $fn) use (&$failed): void {
    try {
        $fn();
        echo "ok   $name\n";
    } catch (Throwable $e) {
        $failed++;
        echo "FAIL $name: {$e->getMessage()} (line {$e->getLine()})\n";
    }
};
$check = function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};
$tmp = function (): string {
    $dir = sys_get_temp_dir() . '/sunlicense-analytics-' . bin2hex(random_bytes(6));
    mkdir($dir);
    return $dir;
};
/** A transport that records requests (body decoded as arrays) and answers $status / Retry-After. */
$recorder = function (int $status = 204, ?string $retryAfter = null): object {
    return new class ($status, $retryAfter) {
        public array $seen = [];

        public function __construct(public int $status, public ?string $retryAfter)
        {
        }

        public function __invoke(string $url, array $headers, string $body): array
        {
            $named = [];
            foreach ($headers as $h) {
                [$k, $v] = explode(': ', $h, 2);
                $named[$k] = $v;
            }
            $this->seen[] = ['url' => $url, 'headers' => $named, 'body' => json_decode($body, true), 'raw' => $body];
            return [$this->status, $this->retryAfter];
        }
    };
};
$noEnv = fn (string $name) => false;
$make = function (array $options) use ($tmp, $noEnv): SunLicenseAnalytics {
    return new SunLicenseAnalytics($options + ['_env' => $noEnv, 'dataDirectory' => $tmp()]);
};

// SunLicense's conformance fixtures (spec 185 section 4.8,
// analytics-service/src/test/resources/conformance/reports.json): copy the file again when it changes.
$fixtures = json_decode((string) file_get_contents(__DIR__ . '/fixtures/conformance-reports.json'), true);

foreach ($fixtures['cases'] as $case) {
    $test("conformance: sends the request side of \"{$case['name']}\"", function () use ($case, $tmp, $recorder, $noEnv, $check) {
        $r = $case['report'];
        $system = $r['metrics'] ?? [];
        $productVersion = $system['productVersion'] ?? null;
        unset($system['productVersion']);
        $dir = $tmp();
        if (isset($r['installId'])) {
            file_put_contents("$dir/.sunlicense-install-id", $r['installId']);
        }
        $transport = $recorder();
        $analytics = new SunLicenseAnalytics([
            'baseUrl' => 'https://api.example.test/',
            'apiKey' => $case['licensed'] ? 'slk_test' : null,
            'licenseKey' => $r['licenseKey'] ?? null,
            'fingerprint' => $r['fingerprint'] ?? null,
            'productAnalyticsId' => $r['productAnalyticsId'] ?? null,
            'dataDirectory' => $dir,
            'productVersion' => $productVersion,
            '_collect' => fn () => $system,
            '_env' => $noEnv,
            '_transport' => $transport,
        ]);
        $check($analytics->sendNow() === 204, 'expected 204');
        $sent = $transport->seen[0];
        $check($sent['url'] === 'https://api.example.test/api/v2/analytics/report', "wrong url {$sent['url']}");
        $expected = ['schema' => 1] + $r;
        $expected['sdk'] = ['name' => 'php', 'version' => SunLicenseClient::VERSION];
        ksort($expected);
        $body = $sent['body'];
        ksort($body);
        $check($body == $expected, 'body ' . json_encode($body) . ' != ' . json_encode($expected));
        $check(($sent['headers']['Authorization'] ?? null) === ($case['licensed'] ? 'Bearer slk_test' : null), 'Authorization header');
        $check(preg_match('#^sunlicense-php/\d+\.\d+\.\d+ analytics$#', $sent['headers']['User-Agent']) === 1, 'User-Agent');
    });
}

$test('collects raw built-in metrics, nothing personal; JSON objects stay objects', function () use ($make, $recorder, $check) {
    $t = $recorder();
    $make(['productAnalyticsId' => 'pa_x', 'productVersion' => 'v1.2.3', '_transport' => $t])->sendNow();
    $m = $t->seen[0]['body']['metrics'];
    $check($m['productVersion'] === 'v1.2.3' && $m['runtime'] === 'php' && $m['runtimeVersion'] === PHP_VERSION, 'runtime');
    $check($m['platform'] === 'standalone' && isset($m['os'], $m['arch']), 'platform');
    foreach ([gethostname(), get_current_user(), getcwd(), getenv('HOME')] as $personal) {
        $check(!$personal || !str_contains($t->seen[0]['raw'], (string) $personal), "report contains $personal");
    }
    $t2 = $recorder();
    $make(['productAnalyticsId' => 'pa_x', '_collect' => fn () => [], '_transport' => $t2])->sendNow();
    $check(str_contains($t2->seen[0]['raw'], '"metrics":{}'), 'empty metrics is an object');
});

$test('client analytics() uses the client base URL and API key; forProduct takes a product analytics id', function () use ($tmp, $recorder, $check) {
    $t = $recorder();
    $client = new SunLicenseClient('https://api.example.test/', token: 'slk_x');
    $a = $client->analytics(['licenseKey' => 'K', 'fingerprint' => 'f', 'dataDirectory' => $tmp(), 'autoReport' => false,
                             '_env' => fn () => false, '_transport' => $t]);
    $check($a->sendNow() === 204, 'sent');
    $check($t->seen[0]['url'] === 'https://api.example.test/api/v2/analytics/report', 'url');
    $check($t->seen[0]['headers']['Authorization'] === 'Bearer slk_x', 'API key');
    $check(!isset($t->seen[0]['body']['installId']), 'no install id with only a license');
    $free = SunLicenseAnalytics::forProduct('pa_abc', ['autoReport' => false, 'enabled' => false]);
    $check($free->isEnabled() === false, 'switch');
});

$test('opt-out: product switch, environment; nothing is sent', function () use ($make, $recorder, $check) {
    $cases = [
        ['enabled' => false],
        ['enabled' => fn () => false],
        ['enabled' => function () { throw new RuntimeException('config gone'); }],
        ['_env' => fn ($n) => $n === 'SUNLICENSE_ANALYTICS' ? 'off' : false],
        ['_env' => fn ($n) => $n === 'SUNLICENSE_ANALYTICS' ? ' FALSE ' : false],
        ['_env' => fn ($n) => $n === 'SUNLICENSE_ANALYTICS' ? '0' : false],
    ];
    foreach ($cases as $i => $extra) {
        $t = $recorder();
        $a = $make($extra + ['productAnalyticsId' => 'pa_x', '_transport' => $t]);
        $check($a->isEnabled() === false, "case $i off");
        $check($a->sendNow() === 0 && $a->tick() === 0 && $t->seen === [], "case $i sent nothing");
    }
    $on = false;
    $t = $recorder();
    $a = $make(['productAnalyticsId' => 'pa_x', 'enabled' => function () use (&$on) { return $on; }, '_transport' => $t]);
    $check($a->sendNow() === 0, 'off');
    $on = true;
    $check($a->sendNow() === 204, 'switched on at runtime');
});

$test('identity: nothing sent without one; licensed needs API key, license key and machine id', function () use ($make, $recorder, $check) {
    $t = $recorder();
    $check($make(['_transport' => $t])->sendNow() === 0, 'none');
    $check($make(['apiKey' => 'slk', 'fingerprint' => 'f', '_transport' => $t])->sendNow() === 0, 'no key');
    $key = null;
    $a = $make(['apiKey' => 'slk', 'fingerprint' => 'f', 'licenseKey' => function () use (&$key) { return $key; }, '_transport' => $t]);
    $check($a->sendNow() === 0, 'no key yet');
    $key = ' AX8P-4Q2M ';
    $check($a->sendNow() === 204 && $t->seen[0]['body']['licenseKey'] === 'AX8P-4Q2M', 'key read before the report');
});

$test('never throws: transport errors, broken suppliers, unwritable directory', function () use ($make, $check) {
    $a = $make(['productAnalyticsId' => 'pa_x', 'productVersion' => function () { throw new RuntimeException('x'); },
                '_transport' => function () { throw new RuntimeException('network down'); }]);
    $check($a->sendNow() === -1, 'no answer');
    $b = new SunLicenseAnalytics(['productAnalyticsId' => 'pa_x', 'dataDirectory' => '/proc/nonexistent/sunlicense',
                                  '_env' => fn () => false, '_transport' => fn () => [204, null]]);
    $check($b->sendNow() === 204, 'works without a writable directory');
});

$test('schedule: first report 1-30 minutes after the first start, then every 30 minutes; Retry-After', function () use ($tmp, $recorder, $check) {
    $dir = $tmp();
    $t = $recorder(429, '120');
    $options = ['productAnalyticsId' => 'pa_x', 'dataDirectory' => $dir, '_env' => fn () => false, '_transport' => $t,
                '_random' => fn (int $min, int $max) => $min];
    $a = new SunLicenseAnalytics($options);
    $check($a->tick() === 0 && $t->seen === [], 'first tick only schedules');
    $state = json_decode(file_get_contents("$dir/.sunlicense-analytics.json"), true);
    $check($state['nextAt'] - time() >= 59 && $state['nextAt'] - time() <= 60, 'first report in 1 minute');
    $state['nextAt'] = time() - 1;
    file_put_contents("$dir/.sunlicense-analytics.json", json_encode($state));
    $check((new SunLicenseAnalytics($options))->tick() === 429, 'due: sent');
    $check((new SunLicenseAnalytics($options))->tick() === 0, 'another process does not send again');
    $state = json_decode(file_get_contents("$dir/.sunlicense-analytics.json"), true);
    $check(abs($state['nextAt'] - time() - 120) <= 1, 'Retry-After honoured');
    $check(SunLicenseAnalytics::nextDelay(204, '86400') === 1800 && SunLicenseAnalytics::nextDelay(-1, null) === 1800, '30 min');
    $check(SunLicenseAnalytics::nextDelay(429, '5') === 60 && SunLicenseAnalytics::nextDelay(403, '999999') === 86400, 'bounds');
    $check(SunLicenseAnalytics::nextDelay(503, 'Wed, 21 Oct 2026 07:28:00 GMT') === 1800, 'HTTP date');
});

$test('install id: created once, kept, a v4 UUID', function () use ($tmp, $make, $recorder, $check) {
    $dir = $tmp();
    $t = $recorder();
    $make(['productAnalyticsId' => 'pa_x', 'dataDirectory' => $dir, '_transport' => $t])->sendNow();
    $make(['productAnalyticsId' => 'pa_x', 'dataDirectory' => $dir, '_transport' => $t])->sendNow();
    $id = file_get_contents("$dir/.sunlicense-install-id");
    $check(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $id) === 1, "uuid $id");
    $check($t->seen[0]['body']['installId'] === $id && $t->seen[1]['body']['installId'] === $id, 'kept');
});

$test('features: counted across processes, kept until a report is stored', function () use ($tmp, $recorder, $check) {
    $dir = $tmp();
    $t = $recorder(503, '60');
    $options = ['productAnalyticsId' => 'pa_x', 'dataDirectory' => $dir, '_env' => fn () => false, '_transport' => $t];
    // two "requests" count uses, each saving them at the end
    (new SunLicenseAnalytics($options))->feature('auto-sell')->feature('Auto-Sell', 2)->feature('bad name!')->feature('x', 0)->tick();
    (new SunLicenseAnalytics($options))->feature('web-editor')->tick();
    $a = new SunLicenseAnalytics($options);
    $check($a->sendNow() === 503, '503');
    $check($t->seen[0]['body']['features'] == ['auto-sell' => 3, 'web-editor' => 1], json_encode($t->seen[0]['body']['features']));
    $t->status = 204;
    $b = new SunLicenseAnalytics($options);
    $b->feature('auto-sell');
    $check($b->sendNow() === 204, '204');
    $check($t->seen[1]['body']['features'] == ['auto-sell' => 4, 'web-editor' => 1], 'kept after a 503');
    (new SunLicenseAnalytics($options))->sendNow();
    $check(!isset($t->seen[2]['body']['features']), 'gone after a 204');
    $off = new SunLicenseAnalytics(['enabled' => false] + $options);
    $off->feature('auto-sell')->tick();
    (new SunLicenseAnalytics($options))->sendNow();
    $check(!isset($t->seen[3]['body']['features']), 'nothing counted while off');
});

$test('features: at most 50 per report, the rest wait', function () use ($make, $tmp, $recorder, $check) {
    $t = $recorder();
    $a = $make(['productAnalyticsId' => 'pa_x', '_transport' => $t]);
    for ($i = 0; $i < 60; $i++) {
        $a->feature("f$i");
    }
    $a->sendNow();
    $a->sendNow();
    $check(count($t->seen[0]['body']['features']) === 50 && count($t->seen[1]['body']['features']) === 10, 'split');
});

$test('custom charts: every type, the wire shape of spec 185 section 4.6', function () use ($make, $recorder, $check) {
    $t = $recorder();
    $a = $make(['productAnalyticsId' => 'pa_x', '_transport' => $t])
        ->simplePie('storage', fn () => 'mysql')
        ->advancedPie('modules', fn () => ['shop' => 2, 'auctions' => 1, 'zero' => 0])
        ->drilldownPie('java', fn () => ['Java 21' => ['21.0.4' => 1], 'empty' => []])
        ->singleLine('players', fn () => 42)
        ->multiLine('worlds', fn () => ['overworld' => 30, 'nether' => -2])
        ->simpleBar('commands', fn () => ['sell' => 12])
        ->advancedBar('tiers', fn () => ['gold' => [1, 2, 3], 'bad' => [1, 'x']])
        ->simplePie('nothing', fn () => null)
        ->simplePie('empty', fn () => '  ')
        ->singleLine('huge', fn () => 2000000000)
        ->simplePie('throws', function () { throw new RuntimeException('x'); })
        ->simplePie('Bad Id', fn () => 'x')
        ->simplePie('removed', fn () => 'x')
        ->removeChart('removed')
        ->advancedPie('numeric', fn () => ['0' => 2, '1' => 1]);
    $check($a->sendNow() === 204, '204');
    $expected = [
        ['id' => 'storage', 'type' => 'simple_pie', 'data' => ['value' => 'mysql']],
        ['id' => 'modules', 'type' => 'advanced_pie', 'data' => ['values' => ['shop' => 2, 'auctions' => 1]]],
        ['id' => 'java', 'type' => 'drilldown_pie', 'data' => ['values' => ['Java 21' => ['21.0.4' => 1]]]],
        ['id' => 'players', 'type' => 'single_line', 'data' => ['value' => 42]],
        ['id' => 'worlds', 'type' => 'multi_line', 'data' => ['values' => ['overworld' => 30, 'nether' => -2]]],
        ['id' => 'commands', 'type' => 'simple_bar', 'data' => ['values' => ['sell' => 12]]],
        ['id' => 'tiers', 'type' => 'advanced_bar', 'data' => ['values' => ['gold' => [1, 2, 3]]]],
        ['id' => 'numeric', 'type' => 'advanced_pie', 'data' => ['values' => ['0' => 2, '1' => 1]]],
    ];
    $check($t->seen[0]['body']['charts'] == $expected, json_encode($t->seen[0]['body']['charts']));
    $check(str_contains($t->seen[0]['raw'], '"values":{"0":2,"1":1}'), 'numeric keys stay a JSON object');
});

$test('custom charts: same id replaces, at most 30; a report over 16 KB keeps the built-ins', function () use ($make, $recorder, $check) {
    $t = $recorder();
    $a = $make(['productAnalyticsId' => 'pa_x', '_transport' => $t]);
    $a->simplePie('storage', fn () => 'mysql')->simplePie('STORAGE', fn () => 'sqlite');
    for ($i = 0; $i < 40; $i++) {
        $a->singleLine("c$i", fn () => $i);
    }
    $a->sendNow();
    $check(count($t->seen[0]['body']['charts']) === 30, '30');
    $check($t->seen[0]['body']['charts'][0] == ['id' => 'storage', 'type' => 'simple_pie', 'data' => ['value' => 'sqlite']], 'replaced');
    $big = $make(['productAnalyticsId' => 'pa_x', '_transport' => $t]);
    for ($i = 0; $i < 30; $i++) {
        $big->advancedPie("big$i", function () {
            $v = [];
            for ($j = 0; $j < 50; $j++) {
                $v[str_repeat('v', 40) . $j] = $j + 1;
            }
            return $v;
        });
    }
    $big->feature('kept');
    $check($big->sendNow() === 204, '204');
    $check(!isset($t->seen[1]['body']['charts']) && !isset($t->seen[1]['body']['features']) && isset($t->seen[1]['body']['metrics']), 'stripped');
    $big->sendNow();
    $check(!isset($t->seen[2]['body']['charts']) && ($t->seen[2]['body']['metrics'] ?? null) !== null, 'still stripped');
});

$test('a real HTTP request (cURL or streams) and the shutdown hook', function () use ($tmp, $check) {
    $port = 18766;
    $log = sys_get_temp_dir() . '/sunlicense-php-analytics-' . bin2hex(random_bytes(4)) . '.json';
    $router = sys_get_temp_dir() . '/sunlicense-php-analytics-router.php';
    file_put_contents($router, '<?php file_put_contents(getenv("SL_LOG"), json_encode(["path" => $_SERVER["REQUEST_URI"],'
        . ' "ua" => $_SERVER["HTTP_USER_AGENT"] ?? "", "body" => json_decode(file_get_contents("php://input"), true)]) . "\n", FILE_APPEND);'
        . ' http_response_code(429); header("Retry-After: 300");');
    $server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", $router], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes, null, ['SL_LOG' => $log]);
    try {
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100_000);
        }
        $dir = $tmp();
        $a = new SunLicenseAnalytics(['baseUrl' => "http://127.0.0.1:$port", 'productAnalyticsId' => 'pa_real', 'dataDirectory' => $dir,
                                      '_env' => fn () => false]);
        $check($a->sendNow() === 429, 'status from a real server');
        $state = json_decode(file_get_contents("$dir/.sunlicense-analytics.json"), true);
        $check(abs($state['nextAt'] - time() - 300) <= 1, 'Retry-After header read');
        $line = json_decode(trim(file_get_contents($log)), true);
        $check($line['path'] === '/api/v2/analytics/report' && $line['body']['productAnalyticsId'] === 'pa_real', 'request');
        $check(str_starts_with($line['ua'], 'sunlicense-php/'), 'User-Agent');
        // a script that starts the reporter sends once a report is due, after it ends
        file_put_contents("$dir/.sunlicense-analytics.json", json_encode(['nextAt' => time() - 1]));
        $script = sprintf('require %s; require %s; SunLicense\SunLicenseAnalytics::forProduct("pa_real", ["baseUrl" => "http://127.0.0.1:%d", "dataDirectory" => %s]); echo "done";',
            var_export(__DIR__ . '/../src/SunLicenseClient.php', true), var_export(__DIR__ . '/../src/SunLicenseAnalytics.php', true), $port, var_export($dir, true));
        $out = shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($script));
        $check($out === 'done', "script output $out");
        $check(count(file($log)) === 2, 'the shutdown hook sent one report');
    } finally {
        proc_terminate($server);
        @unlink($log);
    }
});

echo $failed === 0 ? "all tests passed\n" : "$failed failed\n";
exit($failed === 0 ? 0 : 1);
