# SunLicense — PHP Client

Official PHP client for [SunLicense](https://sunlicense.com), a licence management and
anti-piracy system for indie software developers.

> **Early preview.** The client API is being finalised alongside SunLicense 2.0.

## Install

```bash
composer require sunlicense/sunlicense
```

## Usage

```php
use SunLicense\SunLicenseClient;

$client = new SunLicenseClient(
    'https://your-instance.example.com',
    token: getenv('SUNLICENSE_TOKEN') ?: null, // optional
);

$result = $client->validate('LICENCE-KEY-HERE', ['productId' => 7]);

if ($result->isValid()) {
    echo "Licence valid\n";
} else {
    echo "Rejected: {$result->getStatusCode()} {$result->getBody()}\n";
}
```

Decode the response as an array:

```php
$data = $result->toArray();   // null when the body is not JSON
echo $data['message'] ?? '';
```

## Transport

Uses **cURL** when the extension is available, and falls back to PHP's **stream wrappers**
when it isn't — so it works on shared hosting where cURL is sometimes disabled.

No third-party dependencies.

## API

### `new SunLicenseClient(string $baseUrl, ?string $token = null, int $timeout = 10)`

| Parameter | Description |
|---|---|
| `$baseUrl` | **Required.** Base URL of your SunLicense instance |
| `$token` | API token, if your endpoint requires one |
| `$timeout` | Request timeout in seconds |

### `validate(string $licenseKey, array $context = []): ValidationResult`

Throws `InvalidArgumentException` for an empty key, `SunLicense\SunLicenseException` when
the request cannot be completed.

### `ValidationResult`

`isValid(): bool` · `getStatusCode(): int` · `getBody(): string` · `toArray(): ?array`

## Built-in analytics

Reports anonymous usage statistics for your product's **Analytics** tab (installs, versions, OS, PHP,
platform), plus your own feature usage and charts. Like bStats, for PHP apps and plugins.

```php
use SunLicense\SunLicenseAnalytics;

// A licensed product: the API key, license key and machine id it validates with.
$analytics = $client->analytics(['licenseKey' => $key, 'fingerprint' => $machineId,
                                 'productVersion' => '2.3.1', 'dataDirectory' => __DIR__ . '/storage']);
// A free product, no license: its public product analytics id (Product → Analytics).
$analytics = SunLicenseAnalytics::forProduct('pa_7Hk2mQ9xZr4LbN8vT1wYcD', ['dataDirectory' => __DIR__ . '/storage']);

$analytics->feature('auto-sell');                              // feature usage
$analytics->simplePie('storage', fn () => $config['driver']);  // custom charts
```

PHP runs per request, so there's no background thread: the reporter keeps its schedule (and feature counts)
in a small state file in `dataDirectory`, locked, and sends a due report after the script has finished (a
shutdown function, with a 3-second timeout), at most once every 30 minutes whatever the traffic. Workers and
cron jobs can pass `'autoReport' => false` and call `$analytics->tick()`. Charts: `simplePie`, `advancedPie`,
`drilldownPie`, `singleLine`, `multiLine`, `simpleBar`, `advancedBar`, `removeChart`.

**What is sent** (raw values; SunLicense groups them, e.g. `5.15.0-1051-oracle` into Linux 5.15): your
product version, the OS and its version, CPU architecture, CPU cores, locale, PHP version, the platform (`wordpress`, `laravel` or `symfony` with its version, else `standalone`),
the SDK's name and version, and the identity: licensed = license key + machine id (with the API key), free =
the product analytics id + a random install id kept in `.sunlicense-install-id` in `dataDirectory` (default the system temp directory; pass your app's storage folder). The country comes from SunLicense's edge, not
from the SDK. Nothing personal is sent: no user, host, server or player names, IP addresses or file paths.

**Switching it off.** Nothing is sent, not even an empty report, while any of these says so (checked before
every report): your product's own switch (`'enabled' => false`, or a callable read before each report); the environment variable `SUNLICENSE_ANALYTICS=off` (also
`false` or `0`); the constant `SUNLICENSE_ANALYTICS` defined as `false`.

The first report goes 1 to 30 minutes after start (random), then one every 30 minutes (checked on each script run). When
SunLicense answers with `Retry-After` (analytics switched off for the product, rate limits) it waits that long,
at most 24 hours. Reporting never runs on the license check's path, never delays or fails a check, and swallows
its own errors.

Docs: https://docs.sunlicense.com/guide/sdks#built-in-analytics

## Protection: core unlock, tamper reports, ownership notice

`sunlicense seal <file> --product <code> [--digest <files>]` (the [CLI](https://docs.sunlicense.com/cli/)) encrypts
part of your product, its *core*, on SunLicense's servers under a key only they hold, and prints the sealed text
(`SLS1.…`) you ship. A valid license check answers with that key (`unlock`); a refused one (suspended, expired,
revoked) doesn't, and this SDK forgets the one it had. So a copy whose license check was cut out can't run its core.
The unlock from the last valid check is cached for 7 days (in `cacheDirectory`, default `~/.sunlicense` or the temp directory), encrypted under a key bound to the license key,
the machine id and this machine, so outages don't stop your customers.

```php
$client = new SunLicenseClient('https://api.sunlicense.com', getenv('SUNLICENSE_API_KEY'));
$protection = $client->protection(['licenseKey' => $key, 'fingerprint' => $machineId, 'product' => 'My Plugin',
    'owner' => 'Example Studio', 'terms' => 'https://example.com/terms', 'cacheDirectory' => $dataDir]);
error_log($protection->notice());                       // product, owner, masked key
$client->validate($key, ['fingerprint' => $machineId]); // sends integrity, keeps or forgets the unlock
$core = $protection->unseal(SEALED_CORE);               // throws LockedException without a valid unlock
$protection->integrity(__DIR__);                        // 'OK' / 'MODIFIED', sent with the next check
```

- `unseal(sealed)`: the core, or throws `LockedException` without a valid unlock (or for data sealed for another product).
- `integrity(...)`: compares the files whose digests were sealed with the core (`--digest`) with what is running;
  `OK` or `MODIFIED` (with the changed files) is sent with the next check, where Sentinel sees it.
- `notice()`: `My Bot is licensed software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: …`; never the full
  key or the buyer's name.
- `$protection->protectedFile($name)`: a file uploaded to the product (Standard plan), sent only while the license is valid.
- `accept(body)` and `validateFields()`: for your own HTTP code; the client does both when you create the protection from it.
- `acceptOffline($file, $publicKey)`: the unlock from a valid [offline license file](https://docs.sunlicense.com/guide/offline-licenses) (ext-sodium).
- Needs ext-openssl for AES-GCM (or ext-sodium on a CPU with AES).

Honest limit: someone with a valid license can still extract the unlock and patch their copy; that copy then fails
its integrity check and is reported. Protection raises the cost and makes leaks visible. Wire format and test
vectors: `tests/fixtures/protection-test-vectors.json` (a copy of SunLicense's); docs:
https://docs.sunlicense.com/guide/protection

## Requirements

**PHP 8.0 or newer.** `ext-curl` is suggested but not required.

## Other clients

Also available for **Java**, **.NET**, **JavaScript**, **Python** and **Lua**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-php/issues

## Changelog

- **0.2.0**: core unlock, tamper reports, the ownership notice and protected files: `$client->protection()`, `SunLicenseProtection`.
- **0.1.0**: built-in product analytics (opt-out), feature usage and custom charts: `$client->analytics()`, `SunLicenseAnalytics::forProduct()`.
- **0.0.2**: validates against `/api/v2/license/validate` (`{"license": key, ...context}`), like
  every other SunLicense client. **0.0.1 called `/api/v1/validate`, which answers HTTP 200 for every
  key, so `isValid()` was true for unknown, revoked and expired keys.** Upgrade with
  `composer update sunlicense/sunlicense`.
- **0.0.1**: first release.

## Tests

```bash
php tests/run.php
php tests/analytics.php
php tests/protection.php
```

## Licence

MIT © Hapangama
