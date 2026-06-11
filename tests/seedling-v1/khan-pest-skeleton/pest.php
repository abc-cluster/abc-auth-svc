<?php
declare(strict_types=1);

/*
 * Pest bootstrap for the seedling/v1 conformance tests.
 *
 * Khan teams should integrate the body of this file into their own pest.php /
 * tests/Pest.php; the only Khan-specific thing here is `uses(...)` which is
 * typical Pest boilerplate.
 *
 * For docs on Pest see https://pestphp.com/.
 */

use Tests\Conformance\Helpers\Client;
use Tests\Conformance\Helpers\Fixtures;

uses()->beforeEach(function () {
    // Build a shared HTTP client + fixture context for every test in the
    // Conformance directory. Available as `$this->client` / `$this->f`.
    $this->client = new Client(Fixtures::baseUrl());
    $this->f      = new Fixtures();
})->in('Conformance');
