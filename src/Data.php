<?php
declare(strict_types=1);

namespace PvC;

/**
 * PHP release / end-of-life reference data.
 * Source: php.net/supported-versions.php (captured 2026-10-24).
 * Dates are the END of security support for each branch.
 */
final class Data
{
    /** Latest patch release per branch (for "you are N releases behind" advice). */
    public const LATEST = [
        '8.5' => '8.5.11',
        '8.4' => '8.4.26',
        '8.3' => '8.3.35',
        '8.2' => '8.2.34',
        '8.1' => '8.1.34',
    ];

    /** Branch => [active_support_end, security_support_end] (ISO dates). */
    public const SUPPORT = [
        '8.5' => ['2027-12-31', '2029-12-31'],
        '8.4' => ['2026-12-31', '2028-12-31'],
        '8.3' => ['2025-12-31', '2027-12-31'],
        '8.2' => ['2024-12-31', '2026-12-31'],
        '8.1' => ['2024-12-31', '2025-12-31'],
        '8.0' => ['2022-11-26', '2023-11-26'],
        '7.4' => ['2021-11-28', '2022-11-28'],
        '7.3' => ['2020-12-06', '2021-12-06'],
        '7.2' => ['2019-11-30', '2020-11-30'],
        '7.1' => ['2018-12-01', '2019-12-01'],
        '7.0' => ['2018-01-10', '2019-01-10'],
        '5.6' => ['2017-01-19', '2018-12-31'],
    ];

    /** Latest supported branch, for upgrade recommendations. */
    public const CURRENT_BRANCH = '8.4';

    /**
     * Classify a PHP version string against the EOL table.
     * @return array{branch:string,status:string,secEnd:?string,latest:?string,behind:bool}
     */
    public static function classify(string $version, string $today): array
    {
        $v = ltrim($version, 'v');
        if (!preg_match('/^(\d+)\.(\d+)(?:\.(\d+))?/', $v, $m)) {
            return ['branch' => $v, 'status' => 'unknown', 'secEnd' => null, 'latest' => null, 'behind' => false];
        }
        $branch = $m[1] . '.' . $m[2];
        $support = self::SUPPORT[$branch] ?? null;
        $latest = self::LATEST[$branch] ?? null;
        $behind = $latest !== null && version_compare($v, $latest, '<');

        if ($support === null) {
            // Older than our table => definitely EOL, or unknown future branch.
            $status = version_compare($branch, '5.6', '<=') ? 'eol' : 'unknown';
            return ['branch' => $branch, 'status' => $status, 'secEnd' => null, 'latest' => $latest, 'behind' => $behind];
        }

        [$activeEnd, $secEnd] = $support;
        if ($today > $secEnd) {
            $status = 'eol';
        } elseif ($today > $activeEnd) {
            $status = 'security-only';
        } else {
            $status = 'supported';
        }
        return ['branch' => $branch, 'status' => $status, 'secEnd' => $secEnd, 'latest' => $latest, 'behind' => $behind];
    }

    /** High-value paths that should NOT be publicly readable on a PHP site. */
    public const EXPOSED_PATHS = [
        '/.env'                 => ['Environment file', 'critical', 'application/octet-stream'],
        '/.git/config'          => ['Git repository config', 'critical', ''],
        '/.git/HEAD'            => ['Git repository metadata', 'critical', ''],
        '/composer.json'        => ['Composer manifest (dependency list)', 'low', 'json'],
        '/composer.lock'        => ['Composer lock (exact dependency versions)', 'medium', 'json'],
        '/phpinfo.php'          => ['phpinfo() dump', 'high', ''],
        '/info.php'             => ['phpinfo() dump', 'high', ''],
        '/test.php'             => ['Test/debug script', 'medium', ''],
        '/.htaccess'            => ['Apache config file', 'medium', ''],
        '/server-status'        => ['Apache mod_status page', 'high', ''],
        '/wp-config.php.bak'    => ['WordPress config backup', 'critical', ''],
        '/config.php.bak'       => ['Config backup', 'critical', ''],
        '/.DS_Store'            => ['macOS directory index artifact', 'low', ''],
        '/backup.zip'           => ['Site backup archive', 'critical', ''],
        '/database.sql'         => ['Database dump', 'critical', ''],
        '/.user.ini'            => ['Per-directory PHP config', 'low', ''],
    ];

    /** Security response headers we expect on a modern site. */
    public const SECURITY_HEADERS = [
        'strict-transport-security' => ['HSTS', 'high', 'Forces browsers to use HTTPS, preventing downgrade and cookie-theft attacks.'],
        'content-security-policy'   => ['Content-Security-Policy', 'high', 'Primary defence against cross-site scripting (XSS) and data injection.'],
        'x-content-type-options'    => ['X-Content-Type-Options', 'medium', 'Stops browsers MIME-sniffing a response away from its declared type.'],
        'x-frame-options'           => ['X-Frame-Options', 'medium', 'Prevents the page being framed (clickjacking). Can also be covered by CSP frame-ancestors.'],
        'referrer-policy'           => ['Referrer-Policy', 'low', 'Controls how much referrer information leaks to other sites.'],
        'permissions-policy'        => ['Permissions-Policy', 'low', 'Restricts access to powerful browser features (camera, geolocation, etc.).'],
    ];
}
