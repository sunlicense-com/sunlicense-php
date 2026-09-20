<?php

declare(strict_types=1);

namespace SunLicense;

/** The outcome of a licence validation call. */
final class ValidationResult
{
    public function __construct(
        private bool $valid,
        private int $statusCode,
        private string $body,
    ) {
    }

    /** Whether the server accepted the licence. */
    public function isValid(): bool
    {
        return $this->valid;
    }

    /** The HTTP status code of the response. */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /** The raw response body. */
    public function getBody(): string
    {
        return $this->body;
    }

    /**
     * The response body decoded as an associative array, or null when it is not JSON.
     *
     * @return array<string, mixed>|null
     */
    public function toArray(): ?array
    {
        try {
            $decoded = json_decode($this->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return \is_array($decoded) ? $decoded : null;
    }

    public function __toString(): string
    {
        return sprintf('ValidationResult { valid: %s, status: %d }', $this->valid ? 'true' : 'false', $this->statusCode);
    }
}
