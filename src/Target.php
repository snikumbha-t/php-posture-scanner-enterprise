<?php
declare(strict_types=1);

namespace PvC;

/**
 * Validates and resolves a user-supplied target.
 * Rejects private / loopback / link-local / reserved addresses so the
 * scanner can't be used as an SSRF proxy into internal networks.
 */
final class Target
{
    public string $raw;
    public string $scheme;
    public string $host;
    public int $port;
    public string $ip;
    public string $base;      // scheme://host:port
    public bool $allowPrivate;

    /** @throws \RuntimeException */
    public static function parse(string $input, bool $allowPrivate = false): self
    {
        $input = trim($input);
        if ($input === '') {
            throw new \RuntimeException('No URL provided.');
        }
        if (!preg_match('#^https?://#i', $input)) {
            $input = 'https://' . $input;
        }
        $parts = parse_url($input);
        if ($parts === false || empty($parts['host'])) {
            throw new \RuntimeException('That does not look like a valid URL.');
        }

        $t = new self();
        $t->raw = $input;
        $t->allowPrivate = $allowPrivate;
        $t->scheme = strtolower($parts['scheme'] ?? 'https');
        $t->host = strtolower($parts['host']);
        $t->port = (int)($parts['port'] ?? ($t->scheme === 'https' ? 443 : 80));

        if (!in_array($t->scheme, ['http', 'https'], true)) {
            throw new \RuntimeException('Only http and https URLs are supported.');
        }
        if (strlen($t->host) > 253 || !preg_match('/^[a-z0-9.\-\[\]:]+$/i', $t->host)) {
            throw new \RuntimeException('Invalid host name.');
        }

        $t->ip = self::resolve($t->host);
        if (!$allowPrivate && !self::isPublic($t->ip)) {
            throw new \RuntimeException(
                "Refusing to scan a private, loopback, or reserved address ($t->ip). " .
                'This tool only scans publicly reachable hosts.'
            );
        }

        $t->base = $t->scheme . '://' . $t->host . (
            (($t->scheme === 'https' && $t->port === 443) || ($t->scheme === 'http' && $t->port === 80))
                ? '' : ':' . $t->port
        );
        return $t;
    }

    private static function resolve(string $host): string
    {
        $host = trim($host, '[]');
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }
        $rec = @dns_get_record($host, DNS_A | DNS_AAAA);
        if ($rec) {
            foreach ($rec as $r) {
                if (!empty($r['ip'])) return $r['ip'];
                if (!empty($r['ipv6'])) return $r['ipv6'];
            }
        }
        $ip = gethostbyname($host);
        if ($ip !== $host && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        throw new \RuntimeException("Could not resolve host: $host");
    }

    public static function isPublic(string $ip): bool
    {
        return (bool)filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    public function url(string $path = '/'): string
    {
        if ($path === '' || $path[0] !== '/') $path = '/' . $path;
        return $this->base . $path;
    }
}
