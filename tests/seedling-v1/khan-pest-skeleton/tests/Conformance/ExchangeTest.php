<?php
declare(strict_types=1);

/*
 * ExchangeTest — illustration of a single-endpoint scoped Pest file.
 *
 * Pest convention is one assertion per test name. The bash runner's per-case
 * `it "<id>" "<title>"` maps onto Pest's `it('<id>: <title>', …)` cleanly.
 */

it('exch-01: happy path returns canonical credentials bundle', function () {
    $r = $this->client->post('/exchange', body: null, headers: [
        'Authorization' => 'Bearer ' . $this->f->opaqueSolarCivet(),
    ]);
    expect($r->status())->toBe(200);
    $j = $r->json();
    expect($j['source'])->toBe('seedling/v1');
    expect($j['whoami'])->toBe('solar_civet');
    expect($j['nomad'])->toHaveKeys(['addr','token','namespace','datacenters','head_pool','worker_pool']);
    expect($j['minio'])->toHaveKeys(['endpoint','access_key','secret_key']);
});

it('exch-02: missing Authorization → 401 missing_bearer_token', function () {
    $r = $this->client->post('/exchange');
    expect($r->status())->toBe(401);
    expect($r->json()['error'])->toBe('missing_bearer_token');
});

it('exch-03: empty bearer → 401 empty_bearer_token', function () {
    $r = $this->client->post('/exchange', headers: ['Authorization' => 'Bearer ']);
    expect($r->status())->toBe(401);
    expect($r->json()['error'])->toBe('empty_bearer_token');
});

it('exch-04: invalid bearer → 401 invalid_or_inactive_token', function () {
    $r = $this->client->post('/exchange', headers: ['Authorization' => 'Bearer abco_not_real_at_all_xx']);
    expect($r->status())->toBe(401);
    expect($r->json()['error'])->toBe('invalid_or_inactive_token');
});

it('exch-05: unknown opaque → SAME tag (no enumeration)', function () {
    $r = $this->client->post('/exchange', headers: [
        'Authorization' => 'Bearer abco_definitely_does_not_exist_xx',
    ]);
    expect($r->status())->toBe(401);
    expect($r->json()['error'])->toBe('invalid_or_inactive_token');
});
