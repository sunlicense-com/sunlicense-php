<?php

declare(strict_types=1);

namespace SunLicense;

/** No unlock: the license wasn't confirmed valid (online, cached or offline), or the data was sealed for another product. */
final class LockedException extends \RuntimeException
{
}
