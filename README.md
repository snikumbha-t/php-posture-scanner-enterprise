# PHP Posture Scanner

A small, self-contained PHP web application that checks a website's **PHP security posture**. Give it a URL and it will:

1. **Detect whether the site runs PHP** — from `X-Powered-By`, the `Server` banner, `PHPSESSID` / framework cookies, and `.php` links/forms.
2. **Check the PHP version against the official end-of-life schedule** (php.net) — EOL, security-only, or behind the latest patch.
3. **Inspect security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
4. **Check cookie flags** — Secure, HttpOnly, SameSite on session/auth cookies.
5. **Look for information disclosure** — rendered `phpinfo()`, displayed PHP errors/stack traces, framework debug pages, verbose server banners.
6. **Detect CMS** (WordPress) and version disclosure.
7. **Probe a short list of well-known sensitive paths** — `.env`, `.git/`, `composer.*`, backups, DB dumps, `phpinfo.php`, `server-status` — with content confirmation to avoid false positives on catch-all sites.

It then produces a **grade (A–F), a 0–100 score, and a prioritised list of actions with concrete fixes.**

## Scope & ethics

This is a **passive** assessment tool. It makes a small, bounded number of ordinary `GET`/`HEAD` requests and reads only what the server already serves publicly. It sends **no exploit payloads**, does no brute-forcing, fuzzing, or authentication bypass — it is in the same category as Mozilla Observatory, securityheaders.com, or WhatWeb.

> **Only scan sites you own or are explicitly authorised to test.** Scanning systems without permission may be unlawful in your jurisdiction.

Built-in safety guards:
- **SSRF protection** — refuses private, loopback, link-local, and reserved IPs (incl. `169.254.169.254`) by default.
- **DNS pinning** — the validated IP is pinned for the whole scan, so DNS rebinding can't redirect requests to an internal host mid-scan.
- **Rate limiting** — per-IP cap (default 20 scans/hour).
- **Bounded reads** — response bodies are capped (default 1.5 MB).

## Requirements

PHP 8.1+ with the `curl`, `json`, `mbstring` and `openssl` extensions (all standard).

## Run the web app

```bash
php -S 0.0.0.0:8000 -t public public/index.php
# open http://localhost:8000
```

Behind Apache/nginx, set the document root to `public/`.

### JSON API

```bash
curl -X POST -d "url=https://example.com" "http://localhost:8000/?format=json"
```

## Run from the command line

```bash
php bin/scan.php https://example.com
php bin/scan.php https://example.com --json
```

## Options

| Setting | How | Default |
|---|---|---|
| Allow scanning private/loopback IPs (local testing only) | env `PVC_ALLOW_PRIVATE=1` (web) or `--allow-private` (CLI) | off |
| Rate limit | `RATE_LIMIT` / `RATE_WINDOW` constants in `public/index.php` | 20 / 3600s |
| Request timeout & max body | `Http` constructor args | 12s / 1.5 MB |

## Layout

```
public/index.php   front controller: form, HTML report, JSON endpoint
bin/scan.php       CLI entry point
src/Http.php       cURL multi client (parallel, DNS-pinned, bounded)
src/Target.php     URL validation + SSRF guard
src/Data.php       PHP EOL table, sensitive-path & header definitions
src/Finding.php    finding model + severity weights
src/Scanner.php    the checks + scoring
test/              vulnerable & hardened fixtures + run.php harness
```

## Testing

`test/` contains a deliberately insecure PHP fixture and a hardened one. To reproduce:

```bash
php -S 127.0.0.1:8081 test/vuln/router.php &
php -S 127.0.0.1:8082 test/safe/router.php &
php test/run.php
```

The vulnerable fixture grades **F** (EOL PHP, exposed `.env`/`.git`, phpinfo, missing headers, insecure cookie); the hardened fixture grades **B** (clean, HTTPS being the only flag since the local fixture is served over HTTP).

## Limitations

Passive checks cannot find application-level vulnerabilities (SQL injection, XSS, broken access control, business-logic flaws). For those, follow up with an authenticated audit, a dynamic scanner like OWASP ZAP, and — for WordPress — WPScan. This tool is a fast first-pass posture check, not a penetration test.

## EOL data

PHP version data is captured from php.net on 2026-10-24 in `src/Data.php`. Update the `SUPPORT` and `LATEST` constants periodically to keep version advice accurate.
