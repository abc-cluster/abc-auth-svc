<?php
declare(strict_types=1);

namespace Tests\Conformance\Helpers;

/**
 * Client — a thin Guzzle-like HTTP wrapper that mirrors the primitives in
 * `../../bin/lib.sh` (GET / POST / header / body / status). Khan teams can
 * substitute their own preferred HTTP client (Laravel's `Http`, Guzzle direct,
 * Saloon, etc.); the shape this class exposes is what the Pest tests call.
 *
 * The wrapper intentionally does NOT throw on non-2xx — every error path in the
 * test plan is verified by status + body assertions, never by exception type.
 */
final class Client
{
    private \GuzzleHttp\Client $http;

    public function __construct(string $baseUrl)
    {
        $this->http = new \GuzzleHttp\Client([
            'base_uri'         => $baseUrl,
            'http_errors'      => false,
            'allow_redirects'  => false,
            'connect_timeout'  => 5,
            'timeout'          => 10,
        ]);
    }

    /** @param array<string,string|null> $headers */
    public function get(string $path, array $headers = [], ?string $cookieJar = null): Response
    {
        return $this->request('GET', $path, [], $headers, $cookieJar);
    }

    /** @param array<string,string|null> $headers */
    public function post(string $path, mixed $body = null, array $headers = [], ?string $cookieJar = null): Response
    {
        $opts = [];
        if (is_array($body)) {
            // Default to form-encoded for arrays — overridden when Content-Type header is set.
            if (($headers['Content-Type'] ?? null) === 'application/json') {
                $opts['json'] = $body;
            } else {
                $opts['form_params'] = $body;
            }
        } elseif (is_string($body)) {
            $opts['body'] = $body;
        }
        return $this->request('POST', $path, $opts, $headers, $cookieJar);
    }

    /** @param array<string,string|null> $headers */
    private function request(string $method, string $path, array $opts, array $headers, ?string $cookieJar): Response
    {
        $opts['headers'] = array_filter($headers, fn($v) => $v !== null);
        if ($cookieJar !== null) {
            $opts['cookies'] = new \GuzzleHttp\Cookie\FileCookieJar($cookieJar, true);
        }
        $r = $this->http->request($method, $path, $opts);
        return new Response($r);
    }
}

final class Response
{
    private \Psr\Http\Message\ResponseInterface $r;

    public function __construct(\Psr\Http\Message\ResponseInterface $r) { $this->r = $r; }

    public function status(): int { return $this->r->getStatusCode(); }
    public function header(string $name): string { return $this->r->getHeaderLine($name); }
    public function body(): string { return (string) $this->r->getBody(); }
    public function json(): array
    {
        $j = json_decode($this->body(), true, 512, JSON_THROW_ON_ERROR);
        return is_array($j) ? $j : [];
    }
}
