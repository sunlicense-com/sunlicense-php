<?php

declare(strict_types=1);

namespace SunLicense;

/**
 * Built-in product analytics: about every 30 minutes this install tells SunLicense its product version,
 * OS, architecture, CPU cores, locale, PHP version and platform (WordPress, Laravel, Symfony or
 * standalone). Sellers see the totals on the product's Analytics tab.
 *
 * PHP runs per request, so there is no background thread: the reporter keeps its schedule in a small
 * state file and, when a report is due, sends it after the script has finished (a shutdown function;
 * at most once every 30 minutes, whatever the traffic). Long-running workers and cron jobs can call
 * tick() instead.
 *
 * ```php
 * // A licensed product: the same API key, license key and machine id it validates with.
 * $analytics = $client->analytics(['licenseKey' => $key, 'fingerprint' => $machineId,
 *                                  'productVersion' => '2.3.1', 'dataDirectory' => __DIR__ . '/storage']);
 * // A free product: its public product analytics id (Product → Analytics), no license needed.
 * $analytics = SunLicenseAnalytics::forProduct('pa_7Hk2mQ9xZr4LbN8vT1wYcD', ['dataDirectory' => __DIR__ . '/storage']);
 * $analytics->feature('auto-sell');
 * $analytics->simplePie('storage', fn () => $config['storage']);
 * ```
 *
 * It never blocks, delays or fails a license check and never throws: errors are swallowed. Nothing is
 * sent while the product's `enabled` switch is off, the environment variable SUNLICENSE_ANALYTICS is
 * off/false/0, or the constant SUNLICENSE_ANALYTICS is false; each is checked before every report. No
 * personal data is sent: no user names, host names, IP addresses, file paths or player names.
 */
final class SunLicenseAnalytics
{
    /** Sent as sdk.name / sdk.version; follows SunLicenseClient::VERSION. */
    public const SDK_NAME = 'php';
    public const DEFAULT_BASE_URL = 'https://api.sunlicense.com';
    /** Environment variable (and constant) that switches analytics off on a machine. */
    public const ENV_SWITCH = 'SUNLICENSE_ANALYTICS';

    public const INTERVAL = 1800;
    private const PATH = '/api/v2/analytics/report';
    private const MIN_WAIT = 60;
    private const MAX_WAIT = 86400;
    private const MAX_BODY = 16384;
    private const INSTALL_ID_FILE = '.sunlicense-install-id';
    private const STATE_FILE = '.sunlicense-analytics.json';
    private const CORE_KEYS = ['schema', 'licenseKey', 'fingerprint', 'productAnalyticsId', 'installId', 'sdk', 'metrics'];
    private const OFF = ['off', 'false', '0', 'no', 'disabled'];
    private const MAX_FEATURES = 50;
    private const MAX_CHARTS = 30;
    private const MAX_VALUES = 50;
    private const MAX_BAR = 20;
    private const MAX_NUMBER = 1000000000;

    private string $endpoint;
    private ?string $apiKey;
    /** @var string|callable|null */
    private $licenseKey;
    private ?string $fingerprint;
    private ?string $productAnalyticsId;
    /** @var string|callable|null */
    private $productVersion;
    /** @var array{0: string, 1: ?string}|null */
    private ?array $platform;
    /** @var bool|callable */
    private $enabled;
    private string $directory;
    private int $timeout;
    /** @var callable */
    private $env;
    /** @var callable|null */
    private $transport;
    /** @var callable|null */
    private $collect;
    /** @var callable */
    private $random;
    private bool $closed = false;
    /** @var array<string, int> uses counted in this process, not yet in the state file */
    private array $features = [];
    /** @var array<string, array{0: string, 1: callable}> */
    private array $charts = [];
    private ?array $metrics = null;
    private ?string $installId = null;

    /**
     * Options: baseUrl, apiKey, licenseKey (string or callable), fingerprint, productAnalyticsId,
     * productVersion (string or callable), platform ([name, version]), enabled (bool or callable),
     * dataDirectory (where the install id and schedule are kept; default the system temp directory),
     * timeout (seconds, default 3).
     *
     * @param array<string, mixed> $options
     */
    public function __construct(array $options = [])
    {
        $this->endpoint = rtrim(trim((string) ($options['baseUrl'] ?? self::DEFAULT_BASE_URL)) ?: self::DEFAULT_BASE_URL, '/') . self::PATH;
        $this->apiKey = self::clean($options['apiKey'] ?? null, 512);
        $this->licenseKey = $options['licenseKey'] ?? null;
        $this->fingerprint = self::clean($options['fingerprint'] ?? null, 255);
        $this->productAnalyticsId = self::clean($options['productAnalyticsId'] ?? null, 64);
        $this->productVersion = $options['productVersion'] ?? null;
        $this->platform = isset($options['platform'][0]) ? [(string) $options['platform'][0], $options['platform'][1] ?? null] : null;
        $this->enabled = $options['enabled'] ?? true;
        $this->directory = rtrim((string) ($options['dataDirectory'] ?? (sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sunlicense')), '/\\');
        $this->timeout = max(1, (int) ($options['timeout'] ?? 3));
        // Test seams (not part of the public API).
        $this->env = $options['_env'] ?? static fn (string $name) => getenv($name);
        $this->transport = $options['_transport'] ?? null;
        $this->collect = $options['_collect'] ?? null;
        $this->random = $options['_random'] ?? static fn (int $min, int $max): int => random_int($min, $max);
    }

    /**
     * Starts reporting: the first report goes 1–30 minutes after the first start on this install, then
     * one every 30 minutes, sent after a script that runs when one is due. Never throws.
     *
     * @param array<string, mixed> $options see the constructor
     */
    public static function start(array $options = []): self
    {
        try {
            $analytics = new self($options);
            if ($options['autoReport'] ?? true) {
                register_shutdown_function(static function () use ($analytics): void {
                    $analytics->tick();
                });
            }
            return $analytics;
        } catch (\Throwable $e) {
            return new self(['enabled' => false]);
        }
    }

    /**
     * A free product: reports with its public product analytics id (Product → Analytics). Never throws.
     *
     * @param array<string, mixed> $options see the constructor
     */
    public static function forProduct(string $productAnalyticsId, array $options = []): self
    {
        return self::start(['productAnalyticsId' => $productAnalyticsId] + $options);
    }

    /** True unless the product's switch, SUNLICENSE_ANALYTICS (environment or constant) turns it off. */
    public function isEnabled(): bool
    {
        return !$this->optedOut();
    }

    /** Stops reporting from this process. */
    public function close(): void
    {
        $this->closed = true;
    }

    /**
     * Counts uses of one of your product's features ("auto-sell"): `$uses` is added and sent with the
     * next report, and kept until a report is stored. Never throws; nothing is counted while analytics is
     * off. Names are lower-cased and must match [a-z0-9][a-z0-9._-]{0,47}.
     */
    public function feature(string $name, int $uses = 1): self
    {
        try {
            $id = self::chartId($name);
            if ($id !== null && $uses >= 1 && !$this->optedOut()) {
                $this->features[$id] = min(self::MAX_NUMBER, ($this->features[$id] ?? 0) + $uses);
            }
        } catch (\Throwable $e) {
            // never throws
        }
        return $this;
    }

    /** A pie of one value per install: simplePie('storage', fn () => $config['storage']). */
    public function simplePie(string $id, callable $callback): self
    {
        return $this->chart($id, 'simple_pie', $callback);
    }

    /** A pie of weighted values per install: advancedPie('modules', fn () => ['shop' => 1]). */
    public function advancedPie(string $id, callable $callback): self
    {
        return $this->chart($id, 'advanced_pie', $callback);
    }

    /** A two-level pie: drilldownPie('database', fn () => ['mysql' => ['8.0' => 1]]). */
    public function drilldownPie(string $id, callable $callback): self
    {
        return $this->chart($id, 'drilldown_pie', $callback);
    }

    /** A number summed over installs: singleLine('users', fn () => $userCount). */
    public function singleLine(string $id, callable $callback): self
    {
        return $this->chart($id, 'single_line', $callback);
    }

    /** Several numbers per install, one line each. */
    public function multiLine(string $id, callable $callback): self
    {
        return $this->chart($id, 'multi_line', $callback);
    }

    /** Numbers per category: simpleBar('orders', fn () => ['paid' => 12]). */
    public function simpleBar(string $id, callable $callback): self
    {
        return $this->chart($id, 'simple_bar', $callback);
    }

    /** Several numbers per category: advancedBar('tiers', fn () => ['gold' => [1, 2, 3]]). */
    public function advancedBar(string $id, callable $callback): self
    {
        return $this->chart($id, 'advanced_bar', $callback);
    }

    /** Stops sending a custom chart. */
    public function removeChart(string $id): self
    {
        $key = self::chartId($id);
        if ($key !== null) {
            unset($this->charts[$key]);
        }
        return $this;
    }

    /**
     * Saves this process's feature counts and sends a report if one is due. Returns the HTTP status (204 =
     * stored), 0 when nothing was due or analytics is off, -1 when SunLicense didn't answer. Runs by itself
     * after each script started with start(); call it from a worker loop or cron job too. Never throws.
     */
    public function tick(): int
    {
        try {
            if ($this->closed || !$this->identified()) {
                return 0;
            }
            if ($this->optedOut()) {
                $this->features = [];
                return 0;
            }
            $due = false;
            $this->withState(function (array $state) use (&$due): array {
                $state = $this->mergeFeatures($state);
                $now = time();
                if (!isset($state['nextAt'])) {
                    $state['nextAt'] = $now + ($this->random)(60, 1800);
                } elseif ($state['nextAt'] <= $now) {
                    $due = true;
                    $state['nextAt'] = $now + self::INTERVAL; // claimed: no other process sends this one
                }
                return $state;
            });
            return $due ? $this->sendNow() : 0;
        } catch (\Throwable $e) {
            return -1;
        }
    }

    /**
     * Sends one report now and returns the HTTP status (204 = stored, 0 = nothing sent because analytics is
     * off or the product isn't identified, -1 = no answer). For tests and scripts. Never throws.
     */
    public function sendNow(): int
    {
        try {
            if ($this->closed || $this->optedOut()) {
                return 0;
            }
            $state = $this->withState(fn (array $s): array => $this->mergeFeatures($s));
            [$report, $sending] = $this->report($state['features'] ?? []);
            if ($report === null) {
                return 0;
            }
            $body = self::json($report);
            if (strlen($body) > self::MAX_BODY) {
                $report = array_intersect_key($report, array_flip(self::CORE_KEYS));
                $sending = [];
                $body = self::json($report);
            }
            $headers = [
                'Content-Type: application/json',
                'User-Agent: sunlicense-php/' . SunLicenseClient::VERSION . ' analytics',
            ];
            if (isset($report['licenseKey'])) {
                $headers[] = 'Authorization: Bearer ' . $this->apiKey;
            }
            try {
                [$status, $retryAfter] = $this->transport !== null
                    ? ($this->transport)($this->endpoint, $headers, $body)
                    : $this->post($headers, $body);
            } catch (\Throwable $e) {
                [$status, $retryAfter] = [-1, null];
            }
            $status = $status > 0 ? (int) $status : -1;
            $this->withState(function (array $s) use ($status, $retryAfter, $sending): array {
                if ($status === 204) {
                    foreach ($sending as $name => $uses) {
                        $left = ($s['features'][$name] ?? 0) - $uses;
                        if ($left > 0) {
                            $s['features'][$name] = $left;
                        } else {
                            unset($s['features'][$name]);
                        }
                    }
                }
                $s['nextAt'] = time() + self::nextDelay($status, $retryAfter);
                return $s;
            });
            return $status;
        } catch (\Throwable $e) {
            return -1;
        }
    }

    /** 30 minutes after a 204 or no answer; else the server's Retry-After, between 1 minute and 24 hours. */
    public static function nextDelay(int $status, ?string $retryAfter): int
    {
        if ($status === 204 || $retryAfter === null || !preg_match('/^\s*(\d+)\s*$/', $retryAfter, $m)) {
            return self::INTERVAL;
        }
        return min(self::MAX_WAIT, max(self::MIN_WAIT, (int) $m[1]));
    }

    /** Feature names and chart ids: lower-cased, [a-z0-9][a-z0-9._-]{0,47}, else null. */
    public static function chartId(string $value): ?string
    {
        $id = strtolower(trim($value));
        return preg_match('/^[a-z0-9][a-z0-9._-]{0,47}$/D', $id) === 1 ? $id : null;
    }

    /** Trimmed, control characters removed, cut at $max (bytes, never inside a UTF-8 character); null when empty. */
    public static function clean(mixed $value, int $max): ?string
    {
        if ($value === null || is_array($value) || is_object($value) && !method_exists($value, '__toString')) {
            return null;
        }
        $s = trim((string) preg_replace('/[\x00-\x1f\x7f]/', '', (string) $value));
        if ($s === '') {
            return null;
        }
        if (strlen($s) > $max) {
            $s = trim(function_exists('mb_strcut') ? mb_strcut($s, 0, $max, 'UTF-8') : substr($s, 0, $max));
        }
        return $s === '' ? null : $s;
    }

    /** A chart callback's value as the report's `data`, or null when there's nothing (valid) to send. */
    public static function chartData(string $type, mixed $value): ?array
    {
        if ($value === null) {
            return null;
        }
        switch ($type) {
            case 'simple_pie':
                $v = is_string($value) || is_int($value) ? self::clean($value, 64) : null;
                return $v === null ? null : ['value' => $v];
            case 'single_line':
                return self::number($value) === null ? null : ['value' => $value];
            case 'advanced_pie':
            case 'multi_line':
            case 'simple_bar':
                $values = self::numbers($value, $type === 'advanced_pie' ? 1 : -self::MAX_NUMBER);
                return $values === null ? null : ['values' => $values];
            case 'drilldown_pie':
                $out = [];
                foreach (is_array($value) ? $value : [] as $outer => $inner) {
                    $key = self::clean($outer, 64);
                    $slice = self::numbers($inner, 1);
                    if ($key !== null && $slice !== null && count($out) < self::MAX_VALUES) {
                        $out[$key] = $slice;
                    }
                }
                return $out === [] ? null : ['values' => (object) $out];
            case 'advanced_bar':
                $out = [];
                foreach (is_array($value) ? $value : [] as $k => $list) {
                    $key = self::clean($k, 64);
                    $nums = is_array($list) ? array_slice(array_values($list), 0, self::MAX_BAR) : [];
                    $fine = $nums !== [] && count(array_filter($nums, fn ($n) => self::number($n) === null)) === 0;
                    if ($key !== null && $fine && count($out) < self::MAX_VALUES) {
                        $out[$key] = $nums;
                    }
                }
                return $out === [] ? null : ['values' => (object) $out];
        }
        return null;
    }

    // ---- internals ----

    private function chart(string $id, string $type, callable $callback): self
    {
        $key = self::chartId($id);
        if ($key !== null) {
            unset($this->charts[$key]); // the same id replaces the earlier one, at the end
            $this->charts[$key] = [$type, $callback];
        }
        return $this;
    }

    private function identified(): bool
    {
        return $this->productAnalyticsId !== null || ($this->apiKey !== null && $this->fingerprint !== null);
    }

    private function optedOut(): bool
    {
        try {
            $env = ($this->env)(self::ENV_SWITCH);
            if (is_string($env) && self::isOff($env)) {
                return true;
            }
            if (defined('SUNLICENSE_ANALYTICS')) {
                $constant = constant('SUNLICENSE_ANALYTICS');
                if ($constant === false || is_string($constant) && self::isOff($constant)) {
                    return true;
                }
            }
            return !(is_callable($this->enabled) && !is_string($this->enabled) ? ($this->enabled)() : $this->enabled);
        } catch (\Throwable $e) {
            return true; // a config that can't be read counts as off
        }
    }

    private static function isOff(string $value): bool
    {
        return in_array(strtolower(trim($value)), self::OFF, true);
    }

    /**
     * @param array<string, int> $pending
     * @return array{0: ?array<string, mixed>, 1: array<string, int>}
     */
    private function report(array $pending): array
    {
        $key = self::clean(self::value($this->licenseKey), 128);
        $licensed = $key !== null && $this->apiKey !== null && $this->fingerprint !== null;
        if (!$licensed && $this->productAnalyticsId === null) {
            return [null, []];
        }
        $r = ['schema' => 1];
        if ($licensed) {
            $r['licenseKey'] = $key;
            $r['fingerprint'] = $this->fingerprint;
        }
        if ($this->productAnalyticsId !== null) {
            $r['productAnalyticsId'] = $this->productAnalyticsId;
            $r['installId'] = $this->installId(); // also with a license: an unknown key then still counts
        }
        $r['sdk'] = ['name' => self::SDK_NAME, 'version' => SunLicenseClient::VERSION];
        $metrics = [];
        $version = self::clean(self::value($this->productVersion), 64);
        if ($version !== null) {
            $metrics['productVersion'] = $version;
        }
        try {
            $this->metrics ??= $this->collect !== null ? ($this->collect)() : self::collect($this->platform ?? self::detectPlatform());
            $metrics += $this->metrics;
        } catch (\Throwable $e) {
            // the identity still goes
        }
        $r['metrics'] = (object) $metrics;
        $sending = array_slice($pending, 0, self::MAX_FEATURES, true);
        if ($sending !== []) {
            $r['features'] = (object) $sending;
        }
        $charts = [];
        foreach ($this->charts as $id => [$type, $callback]) {
            if (count($charts) >= self::MAX_CHARTS) {
                break;
            }
            try {
                $data = self::chartData($type, $callback());
            } catch (\Throwable $e) {
                $data = null; // a callback that throws leaves its chart out
            }
            if ($data !== null) {
                $charts[] = ['id' => (string) $id, 'type' => $type, 'data' => $data];
            }
        }
        if ($charts !== []) {
            $r['charts'] = $charts;
        }
        return [$r, $sending];
    }

    /** @return array<string, mixed> raw values; the server maps them to families and majors */
    public static function collect(?array $platform): array
    {
        $m = [];
        $family = PHP_OS_FAMILY;
        $release = @php_uname('r');
        if ($family === 'Darwin') {
            $m['os'] = 'Mac OS X';
            $plist = @is_readable('/System/Library/CoreServices/SystemVersion.plist')
                ? (string) @file_get_contents('/System/Library/CoreServices/SystemVersion.plist') : '';
            $m['osVersion'] = preg_match('#<key>ProductVersion</key>\s*<string>([^<]+)</string>#', $plist, $v) ? $v[1] : self::macVersion($release);
        } elseif ($family === 'Windows') {
            // php_uname('v'): "build 22631 (Windows 11 Pro)"
            $m['os'] = preg_match('/\((Windows (?:Server )?\d{1,4})\b/i', (string) @php_uname('v'), $w) ? $w[1] : 'Windows';
            $m['osVersion'] = $release;
        } else {
            $m['os'] = $family;
            $m['osVersion'] = $release;
        }
        $m['arch'] = @php_uname('m');
        $cores = self::cores();
        if ($cores !== null) {
            $m['cores'] = $cores;
        }
        $locale = class_exists(\Locale::class) ? \Locale::getDefault() : (getenv('LC_ALL') ?: getenv('LANG'));
        if (is_string($locale) && !preg_match('/^(C|POSIX)(\.|$)/', $locale) && $locale !== 'en_US_POSIX') {
            $m['locale'] = $locale;
        }
        $m['runtime'] = 'php';
        $m['runtimeVersion'] = PHP_VERSION;
        if ($platform !== null) {
            $m['platform'] = strtolower((string) $platform[0]);
            $m['platformVersion'] = $platform[1] ?? null;
        }
        $out = [];
        foreach ($m as $k => $v) {
            $v = is_int($v) ? $v : self::clean($v, $k === 'platform' ? 32 : 64);
            if ($v !== null) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    /** From the kernel version: Darwin 23.5.0 is macOS 14.5, Darwin 19.6.0 macOS 10.15; newer kernels aren't guessed. */
    public static function macVersion(?string $darwin): ?string
    {
        if ($darwin === null || !preg_match('/^(\d+)\.(\d+)/', $darwin, $m)) {
            return null;
        }
        [$major, $minor] = [(int) $m[1], (int) $m[2]];
        if ($major >= 25) {
            return null;
        }
        return $major >= 20 ? ($major - 9) . '.' . $minor : ($major >= 5 ? '10.' . ($major - 4) : null);
    }

    private static function cores(): ?int
    {
        $n = getenv('NUMBER_OF_PROCESSORS');
        if (is_string($n) && ctype_digit($n)) {
            return max(1, min(1024, (int) $n));
        }
        if (PHP_OS_FAMILY === 'Linux' && @is_readable('/proc/cpuinfo')) {
            $count = preg_match_all('/^processor\s*:/m', (string) @file_get_contents('/proc/cpuinfo'));
            return $count > 0 ? min(1024, $count) : null;
        }
        return null;
    }

    /** @return array{0: string, 1: ?string} what the product runs in: WordPress, Laravel, Symfony, else standalone */
    public static function detectPlatform(): array
    {
        try {
            if (defined('ABSPATH') && isset($GLOBALS['wp_version'])) {
                return ['wordpress', (string) $GLOBALS['wp_version']];
            }
            if (class_exists('Illuminate\Foundation\Application', false)) {
                return ['laravel', defined('Illuminate\Foundation\Application::VERSION') ? constant('Illuminate\Foundation\Application::VERSION') : null];
            }
            if (class_exists('Symfony\Component\HttpKernel\Kernel', false)) {
                return ['symfony', defined('Symfony\Component\HttpKernel\Kernel::VERSION') ? constant('Symfony\Component\HttpKernel\Kernel::VERSION') : null];
            }
        } catch (\Throwable $e) {
            // fall through
        }
        return ['standalone', null];
    }

    /** Merges this process's feature counts into the state (and forgets them here). */
    private function mergeFeatures(array $state): array
    {
        foreach ($this->features as $name => $uses) {
            $state['features'][$name] = min(self::MAX_NUMBER, ($state['features'][$name] ?? 0) + $uses);
        }
        $this->features = [];
        return $state;
    }

    /**
     * Reads, changes and writes the state file under an exclusive lock. Without a writable directory the
     * state lives only in this process.
     */
    private function withState(callable $change): array
    {
        $path = $this->directory . DIRECTORY_SEPARATOR . self::STATE_FILE;
        $handle = null;
        try {
            if (!is_dir($this->directory)) {
                @mkdir($this->directory, 0775, true);
            }
            $handle = @fopen($path, 'c+');
            if ($handle !== false && flock($handle, LOCK_EX)) {
                $state = json_decode((string) stream_get_contents($handle), true);
                $state = $change(is_array($state) ? $state : []);
                ftruncate($handle, 0);
                rewind($handle);
                fwrite($handle, (string) json_encode($state));
                fflush($handle);
                return $state;
            }
        } catch (\Throwable $e) {
            // fall through to memory
        } finally {
            if (is_resource($handle)) {
                flock($handle, LOCK_UN);
                fclose($handle);
            }
        }
        static $memory = [];
        $memory[$path] = $change($memory[$path] ?? []);
        return $memory[$path];
    }

    private function installId(): string
    {
        if ($this->installId !== null) {
            return $this->installId;
        }
        $path = $this->directory . DIRECTORY_SEPARATOR . self::INSTALL_ID_FILE;
        $stored = @is_file($path) ? trim((string) @file_get_contents($path)) : '';
        if (preg_match('/^[A-Za-z0-9_-]{8,64}$/D', $stored) === 1) {
            return $this->installId = $stored;
        }
        $b = random_bytes(16);
        $b[6] = chr(ord($b[6]) & 0x0f | 0x40);
        $b[8] = chr(ord($b[8]) & 0x3f | 0x80);
        $this->installId = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
        if (!is_dir($this->directory)) {
            @mkdir($this->directory, 0775, true);
        }
        @file_put_contents($path, $this->installId); // read-only disk: this run still has an id
        return $this->installId;
    }

    /** @return array{0: int, 1: ?string} status (-1 = no answer) and Retry-After */
    private function post(array $headers, string $body): array
    {
        $retryAfter = null;
        if (function_exists('curl_init')) {
            $handle = curl_init($this->endpoint);
            if ($handle === false) {
                return [-1, null];
            }
            curl_setopt_array($handle, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => $this->timeout,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_HEADERFUNCTION => static function ($h, string $line) use (&$retryAfter): int {
                    if (stripos($line, 'retry-after:') === 0) {
                        $retryAfter = trim(substr($line, 12));
                    }
                    return strlen($line);
                },
            ]);
            $ok = curl_exec($handle);
            $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
            return [$ok === false || $status === 0 ? -1 : $status, $retryAfter];
        }
        $context = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers),
            'content' => $body,
            'timeout' => $this->timeout,
            'ignore_errors' => true,
        ]]);
        $result = @file_get_contents($this->endpoint, false, $context);
        if ($result === false) {
            return [-1, null];
        }
        $status = -1;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            } elseif (stripos($line, 'retry-after:') === 0) {
                $retryAfter = trim(substr($line, 12));
            }
        }
        return [$status, $retryAfter];
    }

    private static function value(mixed $v): mixed
    {
        try {
            return is_callable($v) && !is_string($v) ? $v() : $v;
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function number(mixed $v): ?int
    {
        return is_int($v) && abs($v) <= self::MAX_NUMBER ? $v : null;
    }

    private static function numbers(mixed $value, int $min): ?object
    {
        $out = [];
        foreach (is_array($value) ? $value : [] as $k => $v) {
            $key = self::clean($k, 64);
            if ($key !== null && self::number($v) !== null && $v >= $min && count($out) < self::MAX_VALUES) {
                $out[$key] = $v;
            }
        }
        return $out === [] ? null : (object) $out;
    }

    private static function json(array $report): string
    {
        return (string) json_encode($report, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
