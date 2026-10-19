<?php

declare(strict_types=1);

namespace SunLicense;

/**
 * Official SunLicense client for PHP.
 *
 * Early preview. The client API is being finalised alongside SunLicense 2.0.
 *
 * Uses cURL when available and falls back to the stream wrappers, so it works on
 * shared hosting where cURL is sometimes disabled. No third-party dependencies.
 *
 * @link https://docs.sunlicense.hapangama.com
 */
final class SunLicenseClient
{
    /** The version of this client. */
    public const VERSION = '0.0.2';

    private string $baseUrl;
    private ?string $token;
    private int $timeout;

    /**
     * @param string      $baseUrl Base URL of your SunLicense instance.
     * @param string|null $token   API token, if your endpoint requires one.
     * @param int         $timeout Request timeout in seconds.
     *
     * @throws \InvalidArgumentException When $baseUrl is empty.
     */
    public function __construct(string $baseUrl, ?string $token = null, int $timeout = 10)
    {
        if ($baseUrl === '') {
            throw new \InvalidArgumentException('SunLicense: baseUrl must not be empty');
        }

        $this->baseUrl = rtrim($baseUrl, '/');
        $this->token = $token;
        $this->timeout = $timeout;
    }

    /**
     * Validates a licence key.
     *
     * @param string                $licenseKey The licence key to check.
     * @param array<string, scalar> $context    Extra fields, e.g. productId or hwid.
     *
     * @throws \InvalidArgumentException When $licenseKey is empty.
     * @throws SunLicenseException       When the request cannot be completed.
     */
    public function validate(string $licenseKey, array $context = []): ValidationResult
    {
        if ($licenseKey === '') {
            throw new \InvalidArgumentException('SunLicense: licenseKey must not be empty');
        }

        $payload = json_encode(
            ['license' => $licenseKey] + $context,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
        );

        // The endpoint every SunLicense SDK uses: 2xx means valid, 4xx means rejected (0.0.1 called
        // /api/v1/validate, which answers 200 for every key, so every key passed).
        $url = $this->baseUrl . '/api/v2/license/validate';

        [$status, $body] = \function_exists('curl_init')
            ? $this->sendWithCurl($url, $payload)
            : $this->sendWithStreams($url, $payload);

        return new ValidationResult($status >= 200 && $status < 300, $status, $body);
    }

    /**
     * @return array{0: int, 1: string}
     *
     * @throws SunLicenseException
     */
    private function sendWithCurl(string $url, string $payload): array
    {
        $handle = curl_init($url);

        if ($handle === false) {
            throw new SunLicenseException('SunLicense: could not initialise cURL');
        }

        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => $this->headers(),
        ]);

        $body = curl_exec($handle);
        $error = curl_error($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        if ($body === false) {
            throw new SunLicenseException('SunLicense request failed: ' . $error);
        }

        return [$status, (string) $body];
    }

    /**
     * @return array{0: int, 1: string}
     *
     * @throws SunLicenseException
     */
    private function sendWithStreams(string $url, string $payload): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $this->headers()),
                'content' => $payload,
                'timeout' => $this->timeout,
                'ignore_errors' => true,
            ],
        ]);

        $body = @file_get_contents($url, false, $context);

        if ($body === false) {
            throw new SunLicenseException('SunLicense request failed: could not reach ' . $url);
        }

        $status = 0;

        foreach ($http_response_header ?? [] as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $matches) === 1) {
                $status = (int) $matches[1];
            }
        }

        return [$status, $body];
    }

    /** @return list<string> */
    private function headers(): array
    {
        $headers = [
            'Content-Type: application/json',
            'User-Agent: sunlicense-php/' . self::VERSION,
        ];

        if ($this->token !== null && $this->token !== '') {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }

        return $headers;
    }
}
