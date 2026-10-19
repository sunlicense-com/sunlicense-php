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

## Requirements

**PHP 8.0 or newer.** `ext-curl` is suggested but not required.

## Other clients

Also available for **Java**, **.NET**, **JavaScript**, **Python** and **Lua**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-php/issues

## Changelog

- **0.0.2**: validates against `/api/v2/license/validate` (`{"license": key, ...context}`), like
  every other SunLicense client. **0.0.1 called `/api/v1/validate`, which answers HTTP 200 for every
  key, so `isValid()` was true for unknown, revoked and expired keys.** Upgrade with
  `composer update sunlicense/sunlicense`.
- **0.0.1**: first release.

## Tests

```bash
php tests/run.php
```

## Licence

MIT © Hapangama
