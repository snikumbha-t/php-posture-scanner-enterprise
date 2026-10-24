<?php
declare(strict_types=1);

namespace PvC;

/**
 * Minimal cURL wrapper with parallel fetching and DNS pinning
 * (the resolved, validated IP is pinned so DNS rebinding can't redirect us).
 */
final class Http
{
    public const UA = 'PHP-Vuln-Checker/1.0 (+passive security assessment)';

    /** @var array<string,string> host:port => ip pins */
    private array $pins = [];
    private int $timeout;
    private int $maxBody;
    public int $requestCount = 0;

    public function __construct(int $timeout = 12, int $maxBody = 1_500_000)
    {
        $this->timeout = $timeout;
        $this->maxBody = $maxBody;
    }

    public function pin(string $host, int $port, string $ip): void
    {
        $this->pins["$host:$port"] = $ip;
    }

    /**
     * @param array<string,array{url:string,method?:string,headers?:array<int,string>,follow?:bool,nobody?:bool}> $requests
     * @return array<string,Response>
     */
    public function multi(array $requests, int $concurrency = 8): array
    {
        $results = [];
        $queue = $requests;
        $mh = curl_multi_init();
        $active = [];

        $add = function () use (&$queue, &$active, $mh) {
            if (!$queue) return false;
            $key = array_key_first($queue);
            $req = $queue[$key];
            unset($queue[$key]);
            $ch = $this->handle($req);
            $active[(int)$ch] = [$key, $ch, $req];
            curl_multi_add_handle($mh, $ch);
            return true;
        };

        for ($i = 0; $i < $concurrency && $add(); $i++);

        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 1.0);
            while ($info = curl_multi_info_read($mh)) {
                $ch = $info['handle'];
                [$key, , $req] = $active[(int)$ch];
                $results[$key] = $this->toResponse($ch, $req, $info['result']);
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($active[(int)$ch]);
                $add();
            }
        } while (($running || $active) && $status === CURLM_OK);

        curl_multi_close($mh);
        return $results;
    }

    public function get(string $url, array $headers = [], bool $follow = true, string $method = 'GET'): Response
    {
        return $this->multi(['x' => ['url' => $url, 'headers' => $headers, 'follow' => $follow, 'method' => $method]])['x'];
    }

    private function handle(array $req)
    {
        $this->requestCount++;
        $ch = curl_init($req['url']);
        $buf = new \stdClass();
        $buf->headers = [];
        $buf->body = '';
        $max = $this->maxBody;

        $resolve = [];
        foreach ($this->pins as $hp => $ip) {
            $resolve[] = "$hp:$ip";
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => $req['follow'] ?? false,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 6,
            CURLOPT_USERAGENT => self::UA,
            CURLOPT_HTTPHEADER => $req['headers'] ?? [],
            CURLOPT_CUSTOMREQUEST => $req['method'] ?? 'GET',
            CURLOPT_NOBODY => ($req['method'] ?? 'GET') === 'HEAD',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_ENCODING => '',
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_RESOLVE => $resolve,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use ($buf) {
                $buf->headers[] = $line;
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use ($buf, $max) {
                if (strlen($buf->body) < $max) {
                    $buf->body .= substr($chunk, 0, $max - strlen($buf->body));
                }
                return strlen($chunk);
            },
        ]);
        $this->state[(int)$ch] = $buf;
        return $ch;
    }

    private array $state = [];

    private function toResponse($ch, array $req, int $curlResult): Response
    {
        $st = $this->state[(int)$ch];
        unset($this->state[(int)$ch]);
        $r = new Response();
        $r->url = $req['url'];
        $r->finalUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $r->status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $r->time = (float)curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        $r->error = $curlResult !== CURLE_OK ? curl_strerror($curlResult) : null;
        $r->body = $st->body;

        // Only keep the headers of the *last* response in a redirect chain
        $blocks = [];
        $cur = [];
        foreach ($st->headers as $line) {
            $line = rtrim($line, "\r\n");
            if (preg_match('#^HTTP/\S+\s+\d+#', $line)) {
                if ($cur) $blocks[] = $cur;
                $cur = [$line];
            } elseif ($line !== '') {
                $cur[] = $line;
            }
        }
        if ($cur) $blocks[] = $cur;
        $last = $blocks ? end($blocks) : [];
        $r->redirectChain = array_map(fn($b) => $b[0] ?? '', $blocks);
        foreach (array_slice($last, 1) as $h) {
            if (!str_contains($h, ':')) continue;
            [$k, $v] = explode(':', $h, 2);
            $r->headers[strtolower(trim($k))][] = trim($v);
        }
        return $r;
    }
}

final class Response
{
    public string $url = '';
    public string $finalUrl = '';
    public int $status = 0;
    public float $time = 0;
    public ?string $error = null;
    public string $body = '';
    /** @var array<string,string[]> */
    public array $headers = [];
    public array $redirectChain = [];

    public function header(string $name): ?string
    {
        $v = $this->headers[strtolower($name)] ?? null;
        return $v ? implode(', ', $v) : null;
    }

    /** @return string[] */
    public function headerAll(string $name): array
    {
        return $this->headers[strtolower($name)] ?? [];
    }

    public function ok(): bool
    {
        return $this->error === null && $this->status > 0;
    }

    public function contentType(): string
    {
        return strtolower((string)$this->header('content-type'));
    }
}
