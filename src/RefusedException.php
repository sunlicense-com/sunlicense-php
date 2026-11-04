<?php

declare(strict_types=1);

namespace SunLicense;

/** A protected file SunLicense refused (license not valid, file missing, plan without protected files). */
final class RefusedException extends \RuntimeException
{
    /** @param int $status 401/403 refused, 404 no such file, 402 plan without protected files */
    public function __construct(private int $status, string $message)
    {
        parent::__construct($message);
    }

    /** The HTTP status: 401/403 refused, 404 no such file, 402 plan without protected files. */
    public function getStatus(): int
    {
        return $this->status;
    }
}
