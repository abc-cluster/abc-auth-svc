<?php
declare(strict_types=1);

/*
 * SeedlingV1Test — illustrative Pest test cases for the seedling/v1 contract.
 *
 * Each test name encodes the case ID from `../TEST-PLAN.md` so the bash and
 * Pest suites stay aligned. Khan should port the remaining cases mechanically.
 */

it('health-01: GET /healthz happy path', function () {
    $r = $this->client->get('/healthz');
    expect($r->status())->toBe(200);
    expect($r->body())->toBe("ok\n");
    expect($r->header('X-Abc-Auth-API-Version'))->toBe('v1');
    expect($r->header('X-Request-Id'))->not->toBe('');
});

it('health-03: GET /readyz shape', function () {
    $r = $this->client->get('/readyz');
    expect($r->status())->toBe(200);
    $j = $r->json();
    expect($j['status'])->toBe('ready');
    expect($j['version'])->toBeString();
});

it('health-05: echoes inbound X-Request-Id', function () {
    $r = $this->client->get('/healthz', ['X-Request-Id' => 'test-12345']);
    expect($r->header('X-Request-Id'))->toBe('test-12345');
});

it('validate-02: no cookie → 302 to /auth/login', function () {
    $r = $this->client->get('/validate');
    expect($r->status())->toBe(302);
    expect($r->header('Location'))->toContain('/auth/login?next=');
});

it('auth-04: POST /auth/login with wrong password → 200 + HTML error', function () {
    $r = $this->client->post('/auth/login', [
        'username' => 'solar_civet',
        'password' => 'WRONG_PASSWORD',
    ]);
    expect($r->status())->toBe(200);
    expect($r->body())->toContain('Invalid username or password.');
});

it('auth-10: /auth/me with no bearer → 401 missing token', function () {
    $r = $this->client->get('/auth/me');
    expect($r->status())->toBe(401);
    expect($r->json()['error'])->toBe('missing token');
});

it('mgmt-02: GET /manage/slots with no operator token → 401 unauthorized', function () {
    $r = $this->client->get('/manage/slots');
    expect($r->status())->toBe(401);
    expect($r->json()['error'])->toBe('unauthorized');
});

it('mgmt-01: list slot projection has no secret fields', function () {
    $r = $this->client->get('/manage/slots', [
        'X-Operator-Token' => $this->f->operatorToken(),
    ]);
    expect($r->status())->toBe(200);
    $arr = $r->json();
    expect($arr)->toBeArray();
    foreach ($arr as $slot) {
        expect($slot)->not->toHaveKey('minio_secret_key');
        expect($slot)->not->toHaveKey('nomad_token_secret');
    }
});

it('verify-01: GET /verify happy path returns ok\\n and identity headers', function () {
    $r = $this->client->get('/verify', [
        'Authorization' => 'Bearer ' . $this->f->nomadTokenSolarCivet(),
    ]);
    expect($r->status())->toBe(200);
    expect($r->body())->toBe("ok\n");
    expect($r->header('X-Auth-User'))->toBe('solar_civet');
    expect($r->header('X-Auth-Type'))->toBeIn(['client', 'management']);
});

it('verify-04: GET /verify with no auth → 401 plain text', function () {
    $r = $this->client->get('/verify');
    expect($r->status())->toBe(401);
    expect($r->body())->toBe("unauthorized: missing or invalid token\n");
});

it('misc-01: unrouted path → 404 not found', function () {
    $r = $this->client->get('/this/path/does/not/exist');
    expect($r->status())->toBe(404);
    expect($r->json()['error'])->toBe('not found');
});
