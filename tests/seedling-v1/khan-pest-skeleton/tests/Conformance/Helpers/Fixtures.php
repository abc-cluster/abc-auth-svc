<?php
declare(strict_types=1);

namespace Tests\Conformance\Helpers;

use RuntimeException;

/**
 * Fixtures — reads the fixture env variables described in TEST-PLAN.md §1.
 *
 * The same variable names the bash runner reads are read here, so a single
 * CI invocation can drive both the bash and Pest suites against the same Khan
 * instance with one set of fixture credentials.
 */
final class Fixtures
{
    public static function baseUrl(): string
    {
        return self::env('BASE_URL', required: true);
    }

    public function operatorToken(): string
    {
        return self::env('OPERATOR_TOKEN', required: true);
    }

    public function nomadTokenSolarCivet(): string
    {
        return self::env('NOMAD_TOKEN_SOLAR_CIVET', required: true);
    }

    public function nomadTokenGraniteIguana(): string
    {
        return self::env('NOMAD_TOKEN_GRANITE_IGUANA', required: true);
    }

    public function opaqueSolarCivet(): string
    {
        return self::env('OPAQUE_SOLAR_CIVET', required: true);
    }

    public function opaqueGraniteIguana(): string
    {
        return self::env('OPAQUE_GRANITE_IGUANA', required: true);
    }

    public function slotPasswordSolarCivet(): string
    {
        return self::env('SLOT_PASSWORD_SOLAR_CIVET', required: true);
    }

    public function slotPasswordGraniteIguana(): string
    {
        return self::env('SLOT_PASSWORD_GRANITE_IGUANA', required: true);
    }

    private static function env(string $name, bool $required = false): string
    {
        $v = getenv($name);
        if ($v === false || $v === '') {
            if ($required) {
                throw new RuntimeException("required env var $name is not set; see TEST-PLAN.md §1 for the fixture contract");
            }
            return '';
        }
        return $v;
    }
}
