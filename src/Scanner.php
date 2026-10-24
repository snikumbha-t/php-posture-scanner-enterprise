<?php
declare(strict_types=1);

namespace PvC;

require_once __DIR__ . '/Http.php';
require_once __DIR__ . '/Target.php';
require_once __DIR__ . '/Data.php';
require_once __DIR__ . '/Finding.php';

/**
 * Passive PHP security-posture scanner.
 *
 * Every check reads only what the target already serves publicly over
 * ordinary HTTP GET/HEAD requests. It sends no exploit payloads, performs
 * no authentication bypass, brute-forcing, or fuzzing, and makes a small,
 * bounded number of requests.
 */
final class Scanner
{
    private Http $http;
    private string $today;
    /** @var Finding[] */
    private array $findings = [];
    private array $meta = [];

    public function __construct(?Http $http = null, ?string $today = null)
    {
        $this->http = $http ?? new Http();
        $this->today = $today ?? date('Y-m-d');
    }

    public function scan(Target $t): array
    {
        $this->findings = [];
        $this->meta = [
            'target' => $t->base,
            'ip' => $t->ip,
            'scanned_at' => date('c'),
            'is_php' => false,
            'php_version' => null,
            'server' => null,
            'cms' => null,
        ];

        // 1. Fetch the homepage over the requested scheme.
        $home = $this->http->get($t->url('/'));
        if (!$home->ok()) {
            $this->add('conn', 'info', 'Could not fetch the site',
                "The request to {$t->base} failed: " . ($home->error ?? 'no response') . '.',
                'Check that the URL is correct and the site is reachable, then try again.',
                '', 'Connectivity');
            return $this->result($t);
        }
        $this->meta['final_url'] = $home->finalUrl;
        $this->meta['status'] = $home->status;

        // 2. HTTPS / transport checks (also fetches the http:// variant).
        $this->checkTransport($t, $home);

        // 3. Detect PHP + server software.
        $this->detectPhp($t, $home);

        // 4. Security headers.
        $this->checkSecurityHeaders($home);

        // 5. Cookie flags.
        $this->checkCookies($home);

        // 6. Information disclosure in the homepage body / banners.
        $this->checkDisclosure($home);

        // 7. CMS detection (WordPress etc.).
        $this->detectCms($t, $home);

        // 8. Exposed sensitive files (bounded, parallel).
        $this->checkExposedFiles($t);

        return $this->result($t);
    }

    // ---- checks -----------------------------------------------------------

    private function checkTransport(Target $t, Response $home): void
    {
        if ($t->scheme === 'https') {
            // Does plain HTTP redirect to HTTPS?
            $httpUrl = 'http://' . substr($t->base, strlen('https://'));
            $plain = $this->http->get($httpUrl, [], false);
            $loc = $plain->header('location');
            $redirects = $plain->status >= 300 && $plain->status < 400
                && $loc !== null && stripos($loc, 'https://') === 0;
            if ($plain->ok() && $plain->status > 0 && !$redirects && $plain->status < 400) {
                $this->add('http-no-redirect', 'medium', 'HTTP is served without redirecting to HTTPS',
                    "Requesting the site over plain http:// returned status {$plain->status} instead of redirecting to https://. Traffic can be intercepted or downgraded.",
                    'Configure the web server to 301-redirect all http:// requests to https://, then enable HSTS.',
                    "GET $httpUrl → HTTP {$plain->status}", 'Transport');
            } else {
                $this->add('https-ok', 'good', 'HTTPS is in use',
                    'The site is served over HTTPS' . ($redirects ? ' and plain HTTP redirects to it.' : '.'),
                    '', '', 'Transport');
            }
        } else {
            $this->add('no-https', 'high', 'Site is being served over plain HTTP',
                'The scanned URL uses http://. All traffic, including any login credentials and session cookies, travels unencrypted.',
                'Obtain a TLS certificate (e.g. free via Let\'s Encrypt) and serve the site over HTTPS, redirecting HTTP to HTTPS.',
                $t->base, 'Transport');
        }
    }

    private function detectPhp(Target $t, Response $home): void
    {
        $signals = [];
        $version = null;

        $server = $home->header('server');
        $this->meta['server'] = $server;
        $xpb = $home->header('x-powered-by');

        if ($xpb && stripos($xpb, 'php') !== false) {
            $signals[] = "X-Powered-By: $xpb";
            if (preg_match('/php\/([0-9][0-9.]*)/i', $xpb, $m)) $version = $m[1];
        }
        if ($server && stripos($server, 'php') !== false) {
            $signals[] = "Server: $server";
            if (!$version && preg_match('/php\/([0-9][0-9.]*)/i', $server, $m)) $version = $m[1];
        }
        foreach ($home->headerAll('set-cookie') as $c) {
            if (preg_match('/^(PHPSESSID|PHPSESSION)=/i', $c)) {
                $signals[] = 'Session cookie: ' . explode('=', $c, 2)[0];
            }
        }
        if (($he = $home->header('x-generator')) && stripos($he, 'php') !== false) {
            $signals[] = "X-Generator: $he";
        }
        // Body / link heuristics.
        if (preg_match('/href=["\'][^"\']*\.php(\?|["\'#])/i', $home->body)
            || preg_match('/action=["\'][^"\']*\.php/i', $home->body)) {
            $signals[] = 'Links/forms point to .php endpoints';
        }
        if (stripos($home->finalUrl, '.php') !== false) {
            $signals[] = 'URL ends in .php';
        }
        // Frameworks that imply PHP.
        foreach (['laravel_session' => 'Laravel', 'symfony' => 'Symfony', 'ci_session' => 'CodeIgniter'] as $needle => $fw) {
            foreach ($home->headerAll('set-cookie') as $c) {
                if (stripos($c, $needle) !== false) $signals[] = "$fw cookie detected";
            }
        }

        $isPhp = $signals !== [];
        $this->meta['is_php'] = $isPhp;
        $this->meta['php_version'] = $version;

        if (!$isPhp) {
            $this->add('not-php', 'info', 'No PHP signature detected',
                'None of the passive signals examined (X-Powered-By, Server banner, PHPSESSID cookie, .php links, framework cookies) indicate PHP. The site may not use PHP, or it may be hiding its stack — which is good practice.',
                'If this site is PHP-based, the absence of fingerprints is a positive sign. The remaining checks still apply to any web server.',
                '', 'Fingerprint');
            return;
        }

        $this->add('is-php', 'good', 'PHP detected',
            'The site presents signals consistent with a PHP backend.',
            '', implode("\n", $signals), 'Fingerprint');

        if ($version) {
            $this->checkPhpVersion($version);
        } else {
            $this->add('php-version-hidden', 'good', 'PHP version is not exposed',
                'A PHP stack was detected but no exact version is advertised in response headers. This is the recommended configuration.',
                '', '', 'Fingerprint');
        }
    }

    private function checkPhpVersion(string $version): void
    {
        $c = Data::classify($version, $this->today);
        $this->meta['php_version'] = $version;
        $this->meta['php_branch'] = $c['branch'];

        // Exposing the exact version is itself a (minor) disclosure issue.
        $this->add('php-version-exposed', 'low', 'Exact PHP version is exposed',
            "The response advertises PHP $version. Publishing the precise version lets an attacker map known CVEs to your install without any effort.",
            'Set expose_php = Off in php.ini and remove any PHP version from the Server header (e.g. ServerTokens Prod on Apache).',
            "Detected version: $version", 'Information disclosure');

        switch ($c['status']) {
            case 'eol':
                $this->add('php-eol', 'critical', "PHP $version is end-of-life",
                    "PHP branch {$c['branch']} no longer receives security fixes" .
                    ($c['secEnd'] ? " (security support ended {$c['secEnd']})" : '') .
                    '. Any vulnerability discovered since then is unpatched on this version.',
                    "Upgrade to a supported branch (PHP " . Data::CURRENT_BRANCH . " is current). Test on a staging copy first, as major upgrades can introduce breaking changes.",
                    "Branch {$c['branch']} — EOL", 'PHP version');
                break;
            case 'security-only':
                $this->add('php-security-only', 'medium', "PHP $version receives security fixes only",
                    "PHP branch {$c['branch']} is in its security-only window" .
                    ($c['secEnd'] ? " (ends {$c['secEnd']})" : '') .
                    '. It gets no bug fixes or improvements and will reach end-of-life soon.',
                    'Plan an upgrade to PHP ' . Data::CURRENT_BRANCH . ' before security support ends.',
                    "Branch {$c['branch']} — security-only until {$c['secEnd']}", 'PHP version');
                break;
            case 'supported':
                if ($c['behind'] && $c['latest']) {
                    $this->add('php-patch-behind', 'medium', "PHP is behind the latest patch ({$c['latest']})",
                        "The branch {$c['branch']} is supported, but version $version is older than the latest patch release {$c['latest']}, which likely contains security fixes.",
                        "Apply the latest {$c['branch']} patch release ({$c['latest']}). Patch upgrades within a branch are backwards-compatible.",
                        "$version < {$c['latest']}", 'PHP version');
                } else {
                    $this->add('php-supported', 'good', "PHP $version is current and supported",
                        "Branch {$c['branch']} is actively supported and on the latest patch.",
                        '', '', 'PHP version');
                }
                break;
            default:
                $this->add('php-version-unknown', 'info', "PHP version $version could not be classified",
                    'The version string did not match the known release table. Verify it against php.net/supported-versions.php.',
                    'Confirm you are on an actively supported branch (currently PHP ' . Data::CURRENT_BRANCH . ').',
                    $version, 'PHP version');
        }
    }

    private function checkSecurityHeaders(Response $home): void
    {
        foreach (Data::SECURITY_HEADERS as $key => [$label, $sev, $why]) {
            $val = $home->header($key);
            if ($val === null) {
                // frame-options can be satisfied by CSP frame-ancestors
                if ($key === 'x-frame-options'
                    && ($csp = $home->header('content-security-policy'))
                    && stripos($csp, 'frame-ancestors') !== false) {
                    continue;
                }
                $this->add("hdr-$key", $sev === 'high' ? 'medium' : 'low',
                    "Missing security header: $label",
                    $why,
                    $this->headerAdvice($key),
                    '', 'Security headers');
            } else {
                $this->add("hdr-$key-ok", 'good', "$label is set", '', '', $val, 'Security headers');
                if ($key === 'strict-transport-security' && !preg_match('/max-age=\s*(\d+)/i', $val, $m)) {
                    // present but malformed
                } elseif ($key === 'strict-transport-security' && isset($m) && (int)$m[1] < 15552000) {
                    $this->add('hsts-short', 'low', 'HSTS max-age is short',
                        "HSTS is set but max-age={$m[1]} is below the recommended 6 months (15552000s).",
                        'Increase max-age to at least 15552000 and consider adding includeSubDomains.',
                        $val, 'Security headers');
                }
            }
        }
    }

    private function headerAdvice(string $key): string
    {
        return match ($key) {
            'strict-transport-security' => 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains (only once HTTPS works everywhere).',
            'content-security-policy' => 'Define a Content-Security-Policy. Start in report-only mode, then tighten script-src and remove unsafe-inline.',
            'x-content-type-options' => 'Add: X-Content-Type-Options: nosniff.',
            'x-frame-options' => 'Add: X-Frame-Options: SAMEORIGIN, or a CSP frame-ancestors directive.',
            'referrer-policy' => 'Add: Referrer-Policy: strict-origin-when-cross-origin.',
            'permissions-policy' => 'Add a Permissions-Policy disabling features you do not use, e.g. geolocation=(), camera=(), microphone=().',
            default => '',
        };
    }

    private function checkCookies(Response $home): void
    {
        $cookies = $home->headerAll('set-cookie');
        if (!$cookies) return;
        foreach ($cookies as $c) {
            $name = explode('=', $c, 2)[0];
            $isSession = preg_match('/sess|phpsessid|token|auth/i', $name);
            $missing = [];
            if (!preg_match('/;\s*secure/i', $c)) $missing[] = 'Secure';
            if (!preg_match('/;\s*httponly/i', $c)) $missing[] = 'HttpOnly';
            if (!preg_match('/;\s*samesite/i', $c)) $missing[] = 'SameSite';
            if ($missing) {
                $sev = $isSession ? 'medium' : 'low';
                $this->add('cookie-' . md5($name), $sev,
                    "Cookie '$name' is missing flags: " . implode(', ', $missing),
                    ($isSession ? 'This looks like a session/auth cookie. ' : '') .
                    'Missing cookie attributes make session hijacking or CSRF easier.',
                    'Set the missing attributes. For PHP sessions use session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax (or Strict).',
                    $c, 'Cookies');
            }
        }
    }

    private function checkDisclosure(Response $home): void
    {
        $body = $home->body;
        // phpinfo() rendered inline
        if (stripos($body, 'phpinfo()') !== false
            || preg_match('/<title>phpinfo\(\)/i', $body)
            || (stripos($body, 'PHP Version') !== false && stripos($body, 'Zend Engine') !== false)) {
            $this->add('phpinfo-home', 'high', 'Page appears to render phpinfo() output',
                'The response contains phpinfo()-style content, which leaks the full PHP configuration, loaded modules, paths, and environment.',
                'Remove any phpinfo() calls from publicly reachable scripts.',
                'phpinfo markers found in body', 'Information disclosure');
        }
        // PHP error / stack traces
        if (preg_match('/(Fatal error|Parse error|Warning|Notice|Deprecated):.*on line \d+/i', $body)
            || preg_match('/Stack trace:/i', $body)
            || stripos($body, 'Uncaught') !== false && stripos($body, '.php') !== false) {
            $this->add('php-errors', 'high', 'PHP errors or stack traces are displayed',
                'The page exposes PHP error output. This reveals file paths, code structure, and sometimes database details — valuable reconnaissance for an attacker.',
                'Set display_errors = Off (and display_startup_errors = Off) in production. Log errors to a file instead with log_errors = On.',
                'Error/stack-trace text found in body', 'Information disclosure');
        }
        // Framework debug pages
        if (stripos($body, 'Whoops\\') !== false || stripos($body, 'laravel.log') !== false
            || preg_match('/Symfony.*Exception/i', $body)) {
            $this->add('debug-mode', 'critical', 'Framework debug mode appears to be enabled',
                'The response contains a framework debug/exception page (e.g. Laravel Whoops, Symfony profiler). These expose source code, config values, and environment variables.',
                'Disable debug mode in production: set APP_DEBUG=false (Laravel) / APP_ENV=prod with debug off (Symfony).',
                'Debug handler markers found in body', 'Information disclosure');
        }
        // Verbose server banner
        $server = $home->header('server');
        if ($server && preg_match('/\d+\.\d+/', $server)) {
            $this->add('server-banner', 'low', 'Web server version is advertised',
                "The Server header exposes a version: \"$server\". Like PHP version disclosure, this helps attackers match known CVEs.",
                'Reduce the banner: Apache ServerTokens Prod / ServerSignature Off, or nginx server_tokens off.',
                "Server: $server", 'Information disclosure');
        }
    }

    private function detectCms(Target $t, Response $home): void
    {
        $body = $home->body;
        if (stripos($body, 'wp-content') !== false || stripos($body, 'wp-includes') !== false
            || preg_match('#/wp-json#i', $body)) {
            $this->meta['cms'] = 'WordPress';
            $ver = null;
            if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([0-9.]+)/i', $body, $m)) {
                $ver = $m[1];
            }
            $this->add('cms-wordpress', 'info', 'WordPress detected' . ($ver ? " (version $ver)" : ''),
                'The site is built on WordPress.' . ($ver ? " The generator tag exposes version $ver." : ''),
                ($ver
                    ? 'Remove the generator meta tag to avoid version disclosure, keep core/plugins/themes updated, and run a dedicated WordPress scanner (e.g. WPScan) for plugin-level CVEs.'
                    : 'Keep WordPress core, plugins and themes updated, and run a dedicated WordPress scanner (e.g. WPScan) for plugin-level CVEs.'),
                $ver ? "generator: WordPress $ver" : 'wp-content / wp-json references', 'CMS');

            // wp-login reachable?
            $login = $this->http->get($t->url('/wp-login.php'), [], false);
            if ($login->ok() && $login->status === 200 && stripos($login->body, 'user_login') !== false) {
                $this->add('wp-login', 'low', 'wp-login.php is publicly reachable',
                    'The WordPress login page is accessible without restriction, exposing it to credential-stuffing and brute-force attempts.',
                    'Consider rate-limiting, a login firewall/2FA plugin, or IP-restricting wp-admin.',
                    'GET /wp-login.php → 200', 'CMS');
            }
        }
    }

    private function checkExposedFiles(Target $t): void
    {
        // Baseline: request two random paths that cannot exist. If the server
        // answers 200 (a catch-all / soft-200 handler, common with SPAs and
        // framework front controllers), we can't trust a bare 200 and must
        // confirm each file by its content and by differing from the baseline.
        $rand1 = '/pvc-' . bin2hex(random_bytes(6)) . '-notfound';
        $rand2 = '/pvc-' . bin2hex(random_bytes(6)) . '.notfound';
        $base = $this->http->multi([
            'b1' => ['url' => $t->url($rand1), 'follow' => false],
            'b2' => ['url' => $t->url($rand2), 'follow' => false],
        ], 2);
        $catchAll = false;
        $baseBodies = [];
        foreach ($base as $b) {
            if ($b->ok() && $b->status === 200) {
                $catchAll = true;
                $baseBodies[] = $this->normalize($b->body);
            }
        }

        $reqs = [];
        foreach (Data::EXPOSED_PATHS as $path => $info) {
            $reqs[$path] = ['url' => $t->url($path), 'follow' => false];
        }
        $resp = $this->http->multi($reqs, 6);
        $anyExposed = false;

        foreach (Data::EXPOSED_PATHS as $path => [$label, $sev, $typeHint]) {
            $r = $resp[$path] ?? null;
            if (!$r || !$r->ok() || $r->status !== 200) continue;

            $body = $r->body;
            if ($this->looksLikeSoft404($body)) continue;

            // Under a catch-all, a 200 is only meaningful if the body differs
            // from the baseline response AND positively matches the file type.
            if ($catchAll) {
                $norm = $this->normalize($body);
                foreach ($baseBodies as $bb) {
                    if ($norm === $bb || (strlen($bb) > 0 && similar_text($norm, $bb) / max(strlen($norm), strlen($bb)) > 0.9)) {
                        if (!$this->confirmsFileType($path, $body)) continue 2;
                    }
                }
                if (!$this->confirmsFileType($path, $body)) continue;
            }

            // Light content confirmation for a few high-signal files.
            if ($path === '/.env' && !preg_match('/^[A-Z0-9_]+=/m', $body) && stripos($r->contentType(), 'text') === false) {
                // 200 but not env-shaped and not text: likely a catch-all page.
                if (stripos($body, '<html') !== false) continue;
            }
            if (($path === '/.git/config') && stripos($body, '[core]') === false) continue;
            if (($path === '/phpinfo.php' || $path === '/info.php')
                && stripos($body, 'phpinfo') === false && stripos($body, 'PHP Version') === false) continue;

            $anyExposed = true;
            $this->add('exposed-' . md5($path), $sev,
                "Exposed file: $path ($label)",
                "The path $path returned HTTP 200 and appears to serve its contents publicly. " .
                $this->exposureWhy($path),
                "Block public access to $path (deny at the web-server level or move it outside the web root). " .
                $this->exposureFix($path),
                "GET $path → 200 (" . strlen($body) . " bytes, " . ($r->contentType() ?: 'no content-type') . ")",
                'Exposed files');
        }

        if (!$anyExposed) {
            $this->add('no-exposed-files', 'good', 'No common sensitive files were exposed',
                'None of the ' . count(Data::EXPOSED_PATHS) . ' well-known sensitive paths checked (.env, .git, backups, phpinfo, etc.) were publicly readable.',
                '', '', 'Exposed files');
        }
    }

    private function looksLikeSoft404(string $body): bool
    {
        return (bool)preg_match('/\b(404|not found|page not found|does not exist)\b/i', substr($body, 0, 2000))
            && stripos($body, '<html') !== false;
    }

    private function normalize(string $body): string
    {
        return preg_replace('/\s+/', ' ', strtolower(substr($body, 0, 4000))) ?? '';
    }

    /** Positive, content-based confirmation that a 200 really is the named file. */
    private function confirmsFileType(string $path, string $body): bool
    {
        $head = substr($body, 0, 4000);
        return match (true) {
            $path === '/.env' => (bool)preg_match('/^[A-Z][A-Z0-9_]*\s*=/m', $head),
            str_starts_with($path, '/.git') => str_contains($head, '[core]') || str_starts_with(ltrim($head), 'ref:') || preg_match('/^[0-9a-f]{40}/', ltrim($head)),
            str_contains($path, 'composer') => $this->isJson($head) && stripos($head, 'require') !== false,
            in_array($path, ['/phpinfo.php', '/info.php'], true) => stripos($head, 'phpinfo') !== false || (stripos($head, 'PHP Version') !== false && stripos($head, 'Zend') !== false),
            str_ends_with($path, '.sql') => (bool)preg_match('/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL)/i', $head),
            str_ends_with($path, '.zip') => str_starts_with($body, "PK\x03\x04"),
            $path === '/server-status' => stripos($head, 'Apache Server Status') !== false,
            $path === '/.htaccess' || $path === '/.user.ini' => (bool)preg_match('/(RewriteEngine|Options |Deny |Require |=\s*\w)/i', $head) && stripos($head, '<html') === false,
            $path === '/.DS_Store' => str_contains($body, "Bud1") || str_contains(substr($body, 0, 8), "\x00\x00\x00\x01Bud1"),
            str_contains($path, 'bak') || str_contains($path, 'backup') => stripos($head, '<?php') !== false || stripos($head, 'DB_') !== false,
            default => false,
        };
    }

    private function isJson(string $s): bool
    {
        json_decode(trim($s));
        return json_last_error() === JSON_ERROR_NONE && trim($s) !== '';
    }

    private function exposureWhy(string $path): string
    {
        return match (true) {
            $path === '/.env' => 'Environment files typically contain database passwords, API keys, and the application secret.',
            str_starts_with($path, '/.git') => 'An exposed .git directory lets an attacker reconstruct your entire source code, including removed secrets in history.',
            str_contains($path, 'composer') => 'This reveals your exact dependency versions, making known-CVE matching trivial.',
            in_array($path, ['/phpinfo.php', '/info.php'], true) => 'It leaks the full PHP configuration and server environment.',
            str_contains($path, 'bak') || str_contains($path, 'backup') || str_contains($path, '.sql') => 'Backups and dumps often contain complete source or data, including credentials.',
            default => 'Publicly serving this file leaks internal configuration details.',
        };
    }

    private function exposureFix(string $path): string
    {
        return match (true) {
            str_starts_with($path, '/.git') => 'Deny all requests to /.git in the web server config.',
            $path === '/.env' => 'Keep .env outside the document root; it should never be web-accessible.',
            default => 'Remove the file if it is not needed, or deny access to it.',
        };
    }

    // ---- helpers ----------------------------------------------------------

    private function add(string $id, string $sev, string $title, string $detail,
                         string $rec = '', string $evidence = '', string $cat = 'General'): void
    {
        $this->findings[] = new Finding($id, $sev, $title, $detail, $rec, $evidence, $cat);
    }

    private function result(Target $t): array
    {
        $counts = array_fill_keys(Finding::SEVERITIES, 0);
        $score = 100;
        foreach ($this->findings as $f) {
            $counts[$f->severity]++;
            $score -= $f->weight();
        }
        $score = max(0, min(100, $score));
        $grade = match (true) {
            $score >= 90 => 'A',
            $score >= 75 => 'B',
            $score >= 60 => 'C',
            $score >= 40 => 'D',
            default => 'F',
        };

        // Action plan: issues only, ordered by severity then category.
        $rank = array_flip(Finding::SEVERITIES);
        $issues = array_filter($this->findings, fn($f) => !in_array($f->severity, ['good', 'info'], true));
        usort($issues, fn($a, $b) => $rank[$a->severity] <=> $rank[$b->severity]);

        return [
            'meta' => $this->meta + ['requests' => $this->http->requestCount],
            'score' => $score,
            'grade' => $grade,
            'counts' => $counts,
            'findings' => array_map(fn($f) => $f->toArray(), $this->findings),
            'action_plan' => array_map(fn($f) => $f->toArray(), array_values($issues)),
        ];
    }
}
