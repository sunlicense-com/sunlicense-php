<?php

declare(strict_types=1);

namespace SunLicense;

/**
 * Protection for a licensed product: core unlock, tamper reports, the ownership notice and protected files. The same
 * behaviour as the Java SDK's SunLicenseProtection.
 *
 *     $client = new SunLicenseClient('https://api.sunlicense.com', getenv('SUNLICENSE_API_KEY'));
 *     $protection = $client->protection([
 *         'licenseKey' => $key, 'fingerprint' => $machineId,
 *         'product' => 'My Plugin', 'owner' => 'Example Studio', 'terms' => 'https://example.com/terms',
 *         'productCode' => 'my-plugin',              // for protected files
 *         'cacheDirectory' => WP_CONTENT_DIR . '/sunlicense',   // where the 7-day unlock cache lives
 *     ]);
 *     error_log($protection->notice());              // one line: product, owner, masked key
 *     $client->validate($key, ['fingerprint' => $machineId]);  // sends integrity, keeps or forgets the unlock
 *     $core = $protection->unseal(SEALED_CORE);      // throws LockedException without a valid unlock
 *     $protection->integrity(__DIR__);               // 'OK' / 'MODIFIED', sent with the next check
 *     $rules = $protection->protectedFile('rules.dat');  // Standard plan
 *
 * Core unlock: `sunlicense seal` encrypts part of the product (its "core") under a key only SunLicense holds. A valid
 * license check answers with that key (`unlock`); a rejected one (suspended, expired, revoked...) doesn't, and the
 * unlock this install had is forgotten. So a copy whose license check was cut out can't run its core. To keep working
 * through outages the unlock from the last valid check is cached on disk for 7 days, encrypted with a key derived from
 * the license key, the machine id and this machine; an offline license file (.lic) carries it too.
 *
 * Needs ext-openssl (or ext-sodium on a CPU with AES) for AES-GCM, and ext-sodium for offline license files.
 *
 * Honest limit: someone with a valid license can still extract the unlock and patch their copy; that copy then fails
 * its integrity check and is reported. Protection raises the cost and makes leaks visible.
 */
final class SunLicenseProtection
{
    public const DEFAULT_BASE_URL = 'https://api.sunlicense.com';
    /** Seconds the unlock from the last valid check keeps working without an answer from SunLicense. */
    public const CACHE_TTL = 7 * 24 * 3600;
    private const SKEW = 600;
    private const SEALED_PREFIX = 'SLS1.';
    private const SEALED_AAD = 'SLS1';
    private const CACHE_PREFIX = 'SLC1.';
    private const CACHE_FILE = '.sunlicense-unlock-';
    private const MAX_DETAIL = 200;

    private string $baseUrl;
    private ?string $apiKey;
    private ?string $licenseKey;
    private ?string $fingerprint;
    private ?string $productCode;
    private ?string $productName;
    private ?string $owner;
    private ?string $terms;
    private ?string $cacheDirectory;
    private int $timeout;
    /** @var callable(): float */
    private $now;
    /** @var callable(): string */
    private $machine;
    /** @var (callable(string, array<string, string>): array{0: int, 1: string})|null */
    private $get;
    private ?string $unlock = null;
    /** @var array<string, string> */
    private array $digests = [];
    private ?string $integrity = null;
    private ?string $integrityDetail = null;

    /**
     * @param array<string, mixed> $options baseUrl, apiKey, licenseKey, fingerprint, productCode (protected files),
     *                                      product and owner (the notice), terms (link), cacheDirectory (null = memory
     *                                      only; default ~/.sunlicense, else the temp directory), timeout
     */
    public function __construct(array $options = [])
    {
        $this->baseUrl = rtrim((string) ($options['baseUrl'] ?? self::DEFAULT_BASE_URL), '/');
        $this->apiKey = self::trim($options['apiKey'] ?? null);
        $this->licenseKey = self::trim($options['licenseKey'] ?? null);
        $this->fingerprint = self::trim($options['fingerprint'] ?? null);
        $this->productCode = self::trim($options['productCode'] ?? null);
        $this->productName = self::trim($options['product'] ?? null);
        $this->owner = self::trim($options['owner'] ?? null);
        $this->terms = self::trim($options['terms'] ?? null);
        $this->cacheDirectory = \array_key_exists('cacheDirectory', $options)
            ? self::trim($options['cacheDirectory'])
            : self::defaultCacheDirectory();
        $this->timeout = (int) ($options['timeout'] ?? 15);
        $this->now = $options['_now'] ?? static fn (): float => microtime(true);
        $this->machine = $options['_machine'] ?? [self::class, 'machineId'];
        $this->get = $options['_get'] ?? null;
    }

    // ---- license and answers ----

    /** The license key and machine id this install checks with; a different key drops the unlock held in memory. */
    public function license(?string $licenseKey, ?string $fingerprint = null): void
    {
        $key = self::trim($licenseKey);
        if ($key === null || $key !== $this->licenseKey) {
            $this->unlock = null;
        }
        $this->licenseKey = $key;
        $this->fingerprint = self::trim($fingerprint);
    }

    public function getLicenseKey(): ?string
    {
        return $this->licenseKey;
    }

    public function getFingerprint(): ?string
    {
        return $this->fingerprint;
    }

    /**
     * Reads a license check's answer (the JSON body, as text or decoded, of /api/v2/license/validate or
     * /api/v1/validate). A valid answer with `unlock` keeps and caches it; a definite "no" (valid: false) forgets it.
     * Anything unreadable is ignored (treat that like no answer). Never throws.
     *
     * @param string|array<string, mixed>|null $body
     */
    public function accept($body): void
    {
        if (\is_string($body)) {
            $body = json_decode($body, true);
        }
        if (!\is_array($body) || !\array_key_exists('valid', $body)) {
            return;
        }
        if ($body['valid'] === true) {
            $this->acceptAnswer(true, \is_string($body['unlock'] ?? null) ? $body['unlock'] : null);
        } elseif ($body['valid'] === false) {
            $this->acceptAnswer(false);
        }
    }

    /** Same as accept() for an answer already read: valid with its unlock (or null), or rejected. */
    public function acceptAnswer(bool $valid, ?string $unlockBase64 = null): void
    {
        if (!$valid) {
            $this->rejected();
            return;
        }
        if (self::trim($unlockBase64) === null) {
            return; // valid, but the product has nothing sealed: keep what we have
        }
        $key = base64_decode(trim((string) $unlockBase64), true);
        if ($key === false || !self::validKey($key)) {
            return;
        }
        $this->unlock = $key;
        $this->writeCache($key);
    }

    /** SunLicense said no: the unlock (in memory and on disk) is gone until the next valid check. */
    public function rejected(): void
    {
        $this->unlock = null;
        $file = $this->cacheFile();
        if ($file !== null && is_file($file)) {
            @unlink($file);
        }
    }

    /**
     * Takes the unlock from an offline license file (.lic): checks its Ed25519 signature with the organization's
     * public key (base64 X.509), that it is for this license key and not expired or past its refresh window. Returns
     * false (and changes nothing) when the file isn't usable, carries no unlock, or ext-sodium is missing.
     */
    public function acceptOffline(string $file, string $publicKeyBase64): bool
    {
        $payload = self::verifiedOffline($file, $publicKeyBase64);
        if ($payload === null) {
            return false;
        }
        $lk = $payload['licenseKey'] ?? null;
        if ($this->licenseKey !== null && \is_string($lk) && strcasecmp($this->licenseKey, trim($lk)) !== 0) {
            return false;
        }
        $now = ($this->now)();
        $issued = self::instant($payload['issuedAt'] ?? null);
        if ($issued !== null && $issued > $now + self::SKEW) {
            return false;
        }
        $expires = self::instant(\is_array($payload['policy'] ?? null) ? ($payload['policy']['expiresAt'] ?? null) : null);
        if ($expires !== null && $now >= $expires) {
            return false;
        }
        $refresh = self::instant($payload['refreshAfter'] ?? null);
        if ($refresh !== null && $now >= $refresh) {
            return false;
        }
        if (!\is_string($payload['unlock'] ?? null)) {
            return false;
        }
        $k = base64_decode(trim($payload['unlock']), true);
        if ($k === false || !self::validKey($k)) {
            return false;
        }
        $this->unlock = $k; // the file is its own cache: nothing written to disk
        return true;
    }

    /** True when an unlock is available: from this run's valid check, the offline file, or the cache (≤ 7 days). */
    public function unlocked(): bool
    {
        return $this->key() !== null;
    }

    // ---- core unlock ----

    /**
     * Decrypts data sealed with `sunlicense seal` (an `SLS1.` string). Throws LockedException without an unlock, or
     * when the data was sealed for another product. Remembers the digests sealed with it for integrity().
     */
    public function unseal(string $sealed): string
    {
        $key = $this->key();
        if ($key === null) {
            throw new LockedException('No valid license check yet: the protected part of this product stays locked.');
        }
        [$data, $digests] = self::open($sealed, $key);
        $this->digests = $digests;
        return $data;
    }

    /** @return array<string, string> The digests sealed with the last data unseal() opened (path => lowercase hex SHA-256). */
    public function digests(): array
    {
        return $this->digests;
    }

    /**
     * Opens an `SLS1.` blob: 'SLS1.' + base64url(nonce 12 || AES-256-GCM ciphertext || tag 16), AAD 'SLS1', plaintext
     * JSON {"v":1,"digests":{path: sha256hex},"data":"<base64>"}.
     *
     * @return array{0: string, 1: array<string, string>} the data and its digests
     *
     * @throws LockedException on a wrong key, changed data, or text that isn't sealed data
     */
    public static function open(string $sealed, string $key): array
    {
        $s = trim($sealed);
        if (!str_starts_with($s, self::SEALED_PREFIX)) {
            throw new LockedException('Not sealed data: expected text starting with ' . self::SEALED_PREFIX);
        }
        $raw = self::decodeBase64(substr($s, \strlen(self::SEALED_PREFIX)));
        if ($raw === null) {
            throw new LockedException('Not sealed data: not base64url');
        }
        if (\strlen($raw) < 12 + 16) {
            throw new LockedException('Not sealed data: too short');
        }
        $plain = self::gcmDecrypt($key, substr($raw, 0, 12), substr($raw, 12), self::SEALED_AAD);
        if ($plain === null) {
            throw new LockedException("This data wasn't sealed for this product's unlock (sealed for another product, or re-sealed since).");
        }
        $m = json_decode($plain, true);
        if (!\is_array($m) || !\is_string($m['data'] ?? null)) {
            throw new LockedException('Not sealed data: sealed content has no data');
        }
        $data = self::decodeBase64($m['data']);
        if ($data === null) {
            throw new LockedException("Not sealed data: sealed content isn't readable");
        }
        $digests = [];
        if (\is_array($m['digests'] ?? null)) {
            foreach ($m['digests'] as $path => $d) {
                if (\is_string($d)) {
                    $digests[(string) $path] = strtolower($d);
                }
            }
            ksort($digests, SORT_STRING);
        }
        return [$data, $digests];
    }

    /**
     * Compares the sealed digests with the product's files: $source is a directory (paths resolve inside it; default
     * the working directory) or a callable(string $path): ?string. $digests defaults to the ones sealed with the last
     * unseal(). Returns 'OK' or 'MODIFIED', or null when nothing was sealed with digests; the result goes with the next
     * license check.
     *
     * @param string|callable|null       $source
     * @param array<string, string>|null $digests
     */
    public function integrity($source = null, ?array $digests = null): ?string
    {
        $digests ??= $this->digests;
        if ($digests === []) {
            return null;
        }
        $reader = \is_callable($source) ? $source : self::directoryReader(\is_string($source) ? $source : (string) getcwd());
        $paths = array_map('strval', array_keys($digests));
        sort($paths, SORT_STRING);
        $changed = [];
        foreach ($paths as $path) {
            try {
                $bytes = $reader($path);
            } catch (\Throwable) {
                $bytes = null;
            }
            if (!\is_string($bytes)) {
                $changed[] = $path . ' (missing)';
            } elseif (hash('sha256', $bytes) !== self::normaliseDigest($digests[$path])) {
                $changed[] = $path;
            }
        }
        if ($changed === []) {
            $this->integrity = 'OK';
            $this->integrityDetail = null;
        } else {
            $this->integrity = 'MODIFIED';
            $this->integrityDetail = self::detail($changed);
        }
        return $this->integrity;
    }

    /** The latest integrity() result, or null before any. */
    public function integrityResult(): ?string
    {
        return $this->integrity;
    }

    /**
     * Fields to add to the next license check's JSON body: integrity and, when modified, integrityDetail. Works as
     * SunLicenseClient::validate()'s $context too.
     *
     * @return array<string, string>
     */
    public function validateFields(): array
    {
        $fields = [];
        if ($this->integrity !== null) {
            $fields['integrity'] = $this->integrity;
            if ($this->integrityDetail !== null) {
                $fields['integrityDetail'] = $this->integrityDetail;
            }
        }
        return $fields;
    }

    // ---- ownership notice ----

    /**
     * One line for the start-up log: product, owner, masked license key and terms link, e.g. "My Plugin is licensed
     * software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: https://…". Never the full key or the buyer's name.
     */
    public function notice(): string
    {
        $b = ($this->productName ?? 'This product') . ' is licensed software';
        if ($this->owner !== null) {
            $b .= ' by ' . $this->owner;
        }
        $b .= '. License ' . self::mask($this->licenseKey) . '.';
        if ($this->terms !== null) {
            $b .= ' Terms: ' . $this->terms;
        }
        return $b;
    }

    /** "AX8P-XXXX-XXXX-XXXX": the first group, the rest as X. */
    public static function mask(?string $key): string
    {
        $k = self::trim($key);
        if ($k === null) {
            return '(none)';
        }
        $groups = explode('-', $k);
        if (\count($groups) === 1) {
            return substr($k, 0, 4) . str_repeat('X', max(0, \strlen($k) - 4));
        }
        $out = [$groups[0]];
        foreach (\array_slice($groups, 1) as $g) {
            $out[] = str_repeat('X', \strlen($g));
        }
        return implode('-', $out);
    }

    // ---- protected files ----

    /**
     * Downloads a protected file uploaded to the product (Standard plan). SunLicense sends it only while the license
     * is valid. Throws RefusedException when it says no, SunLicenseException when it can't be reached.
     */
    public function protectedFile(string $name): string
    {
        if ($this->productCode === null) {
            throw new \LogicException('SunLicense: set productCode to download protected files');
        }
        if ($this->licenseKey === null) {
            throw new RefusedException(401, 'No license key');
        }
        $url = $this->baseUrl . '/api/v2/protected-files/' . rawurlencode($this->productCode) . '/' . rawurlencode($name);
        $headers = ['X-License-Key' => $this->licenseKey, 'User-Agent' => 'sunlicense-php/' . SunLicenseClient::VERSION];
        if ($this->apiKey !== null) {
            $headers['Authorization'] = 'Bearer ' . $this->apiKey;
        }
        if ($this->fingerprint !== null) {
            $headers['X-Fingerprint'] = $this->fingerprint;
        }
        [$status, $body] = $this->get !== null ? ($this->get)($url, $headers) : $this->httpGet($url, $headers);
        if ($status === 200) {
            return $body;
        }
        if ($status >= 500 || $status === 429 || $status <= 0) {
            throw new SunLicenseException("SunLicense returned HTTP $status for protected file $name");
        }
        $j = json_decode($body, true);
        $code = \is_array($j) ? ($j['code'] ?? $j['detail'] ?? null) : null;
        throw new RefusedException($status, "SunLicense refused protected file $name (HTTP $status" . (\is_string($code) ? ", $code" : '') . ')');
    }

    /**
     * @param array<string, string> $headers
     *
     * @return array{0: int, 1: string}
     */
    private function httpGet(string $url, array $headers): array
    {
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = "$k: $v";
        }
        if (\function_exists('curl_init')) {
            $h = curl_init($url);
            if ($h === false) {
                throw new SunLicenseException('SunLicense: could not initialise cURL');
            }
            curl_setopt_array($h, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $this->timeout, CURLOPT_HTTPHEADER => $lines]);
            $body = curl_exec($h);
            $status = (int) curl_getinfo($h, CURLINFO_RESPONSE_CODE);
            if ($body === false) {
                throw new SunLicenseException('Cannot reach SunLicense at ' . $this->baseUrl . ': ' . curl_error($h));
            }
            return [$status, (string) $body];
        }
        $context = stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", $lines),
            'timeout' => $this->timeout, 'ignore_errors' => true]]);
        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            throw new SunLicenseException('Cannot reach SunLicense at ' . $this->baseUrl);
        }
        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }
        return [$status, $body];
    }

    // ---- helpers ----

    /** Lowercase hex SHA-256. */
    public static function digest(string $bytes): string
    {
        return hash('sha256', $bytes);
    }

    /** A digest as compared: lowercase, without a "sha256:" prefix. */
    public static function normaliseDigest(string $d): string
    {
        $t = strtolower(trim($d));
        return str_starts_with($t, 'sha256:') ? substr($t, 7) : $t;
    }

    /**
     * "N changed: a, b, +3 more", at most 200 characters (sent as integrityDetail).
     *
     * @param list<string> $changed
     */
    public static function detail(array $changed): string
    {
        $n = \count($changed);
        $b = "$n changed: ";
        $shown = 0;
        foreach ($changed as $c) {
            $next = ($shown === 0 ? '' : ', ') . $c;
            $reserve = $shown + 1 < $n ? 16 : 0;
            if (\strlen($b) + \strlen($next) + $reserve > self::MAX_DETAIL) {
                break;
            }
            $b .= $next;
            $shown++;
        }
        if ($shown < $n) {
            $b .= ($shown === 0 ? '' : ', ') . '+' . ($n - $shown) . ' more';
        }
        return substr($b, 0, self::MAX_DETAIL);
    }

    /** Base64 in any flavour the server may send: url-safe or standard, with or without padding; null when it isn't. */
    public static function decodeBase64(string $s): ?string
    {
        $t = rtrim(strtr(trim($s), '-_', '+/'), '=');
        if (preg_match('#^[A-Za-z0-9+/]*$#', $t) !== 1 || \strlen($t) % 4 === 1) {
            return null;
        }
        $r = base64_decode($t . str_repeat('=', (4 - \strlen($t) % 4) % 4), true);
        return $r === false ? null : $r;
    }

    public static function encodeBase64Url(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }

    /** AES-GCM ciphertext || tag; ext-openssl, or ext-sodium where the CPU has AES. */
    public static function gcmEncrypt(string $key, string $nonce, string $plain, string $aad = ''): string
    {
        if (\function_exists('openssl_encrypt')) {
            $tag = '';
            $ct = openssl_encrypt($plain, 'aes-' . (\strlen($key) * 8) . '-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
            if ($ct === false) {
                throw new \RuntimeException('AES-GCM failed');
            }
            return $ct . $tag;
        }
        if (\function_exists('sodium_crypto_aead_aes256gcm_is_available') && sodium_crypto_aead_aes256gcm_is_available() && \strlen($key) === 32) {
            return sodium_crypto_aead_aes256gcm_encrypt($plain, $aad, $nonce, $key);
        }
        throw new \RuntimeException('SunLicense protection needs ext-openssl (or ext-sodium on a CPU with AES)');
    }

    /** AES-GCM decryption of ciphertext || tag; null when the tag doesn't match (wrong key or changed data). */
    public static function gcmDecrypt(string $key, string $nonce, string $data, string $aad = ''): ?string
    {
        if (!self::validKey($key) || \strlen($data) < 16) {
            return null;
        }
        if (\function_exists('openssl_decrypt')) {
            $plain = openssl_decrypt(substr($data, 0, -16), 'aes-' . (\strlen($key) * 8) . '-gcm', $key, OPENSSL_RAW_DATA, $nonce, substr($data, -16), $aad);
            return $plain === false ? null : $plain;
        }
        if (\function_exists('sodium_crypto_aead_aes256gcm_is_available') && sodium_crypto_aead_aes256gcm_is_available() && \strlen($key) === 32) {
            $plain = sodium_crypto_aead_aes256gcm_decrypt($data, $aad, $nonce, $key);
            return $plain === false ? null : $plain;
        }
        return null;
    }

    /** SHA-256 of the OS, architecture, host name and machine id: what makes a copied cache file useless elsewhere. */
    public static function machineId(): string
    {
        $raw = PHP_OS_FAMILY . '|' . php_uname('m') . '|' . (gethostname() ?: '?');
        foreach (['/etc/machine-id', '/var/lib/dbus/machine-id'] as $f) {
            if (@is_readable($f)) {
                $id = trim((string) @file_get_contents($f));
                if ($id !== '') {
                    $raw .= '|' . $id;
                    break;
                }
            }
        }
        return hash('sha256', $raw);
    }

    private static function defaultCacheDirectory(): ?string
    {
        $home = getenv('HOME') ?: (getenv('USERPROFILE') ?: null);
        if ($home !== null && @is_writable($home)) {
            return rtrim($home, '/\\') . DIRECTORY_SEPARATOR . '.sunlicense';
        }
        return rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'sunlicense';
    }

    private static function trim(mixed $s): ?string
    {
        if ($s === null) {
            return null;
        }
        $t = trim((string) $s);
        return $t === '' ? null : $t;
    }

    private static function validKey(string $k): bool
    {
        return \in_array(\strlen($k), [16, 24, 32], true);
    }

    private static function directoryReader(string $dir): callable
    {
        $root = realpath($dir) ?: $dir;
        return static function (string $name) use ($root): ?string {
            $p = realpath($root . DIRECTORY_SEPARATOR . $name);
            if ($p === false || !str_starts_with($p, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) || !is_file($p)) {
                return null;
            }
            $b = @file_get_contents($p);
            return $b === false ? null : $b;
        };
    }

    private static function instant(mixed $s): ?float
    {
        if (!\is_string($s)) {
            return null;
        }
        $t = preg_replace('/(\.\d{6})\d+/', '$1', trim($s));
        $d = \DateTimeImmutable::createFromFormat(\DateTimeInterface::RFC3339_EXTENDED, (string) $t)
            ?: \DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.uP', (string) $t)
            ?: \DateTimeImmutable::createFromFormat(\DateTimeInterface::RFC3339, (string) $t);
        if ($d === false) {
            try {
                $d = new \DateTimeImmutable((string) $t);
            } catch (\Exception) {
                return null;
            }
        }
        return (float) $d->format('U.u');
    }

    /** @return array<string, mixed>|null */
    private static function verifiedOffline(string $file, string $publicKeyBase64): ?array
    {
        if (!\function_exists('sodium_crypto_sign_verify_detached') || self::trim($publicKeyBase64) === null) {
            return null;
        }
        $parts = explode('.', trim($file));
        if (\count($parts) !== 2) {
            return null;
        }
        $payload = self::decodeBase64($parts[0]);
        $sig = self::decodeBase64($parts[1]);
        $spki = base64_decode(trim($publicKeyBase64), true);
        // An Ed25519 X.509 public key is a fixed 12-byte header and the 32-byte key.
        if ($payload === null || $sig === null || $spki === false || \strlen($spki) !== 44 || \strlen($sig) !== 64
            || bin2hex(substr($spki, 0, 12)) !== '302a300506032b6570032100') {
            return null;
        }
        try {
            if (!sodium_crypto_sign_verify_detached($sig, $payload, substr($spki, 12))) {
                return null;
            }
        } catch (\Throwable) {
            return null;
        }
        $parsed = json_decode($payload, true);
        return \is_array($parsed) ? $parsed : null;
    }

    // ---- the unlock cache: one file per license key, AES-GCM under a key bound to the key, the machine id and this machine ----

    private function key(): ?string
    {
        if ($this->unlock !== null) {
            return $this->unlock;
        }
        $k = $this->readCache();
        if ($k !== null) {
            $this->unlock = $k;
        }
        return $k;
    }

    /** @internal */
    public function cacheFile(): ?string
    {
        if ($this->cacheDirectory === null || $this->licenseKey === null) {
            return null;
        }
        $id = substr(hash('sha256', "sunlicense-unlock-file\0" . $this->licenseKey), 0, 16);
        return rtrim($this->cacheDirectory, '/\\') . DIRECTORY_SEPARATOR . self::CACHE_FILE . $id;
    }

    private function cacheKey(): string
    {
        return hash('sha256', "sunlicense-unlock-cache\0" . $this->licenseKey . "\0" . ($this->fingerprint ?? '') . "\0" . ($this->machine)(), true);
    }

    private function writeCache(string $key): void
    {
        $file = $this->cacheFile();
        if ($file === null) {
            return;
        }
        try {
            $plain = \sprintf('%d', (int) floor(($this->now)() * 1000)) . "\n" . base64_encode($key);
            $nonce = random_bytes(12);
            $blob = $nonce . self::gcmEncrypt($this->cacheKey(), $nonce, $plain);
            $dir = \dirname($file);
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
            }
            $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (@file_put_contents($tmp, self::CACHE_PREFIX . self::encodeBase64Url($blob)) !== false) {
                @chmod($tmp, 0600);
                @rename($tmp, $file);
            }
        } catch (\Throwable) {
            // memory only
        }
    }

    private function readCache(): ?string
    {
        $file = $this->cacheFile();
        if ($file === null || !is_file($file)) {
            return null;
        }
        $text = trim((string) @file_get_contents($file));
        if (!str_starts_with($text, self::CACHE_PREFIX)) {
            return null;
        }
        $raw = self::decodeBase64(substr($text, \strlen(self::CACHE_PREFIX)));
        if ($raw === null || \strlen($raw) < 28) {
            return null;
        }
        $plain = self::gcmDecrypt($this->cacheKey(), substr($raw, 0, 12), substr($raw, 12));
        if ($plain === null || !str_contains($plain, "\n")) {
            return null; // another machine, another license key, or a damaged file
        }
        [$millis, $b64] = explode("\n", $plain, 2);
        if (!ctype_digit($millis)) {
            return null;
        }
        $saved = ((int) $millis) / 1000;
        $now = ($this->now)();
        if ($saved > $now + self::SKEW || $now >= $saved + self::CACHE_TTL) {
            return null; // older than 7 days, or the clock was turned back
        }
        $k = base64_decode($b64, true);
        return $k !== false && self::validKey($k) ? $k : null;
    }
}
