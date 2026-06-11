# khan-pest-skeleton/

A small, illustrative Pest test skeleton showing how the Khan team can port the
language-neutral `seedling/v1` test cases (in `../TEST-PLAN.md`) into Khan's own
PHP/Pest CI.

This is **not** a runnable Khan test suite — Khan owns its own test infrastructure.
This is a *reference shape* so the cases can be ported one-to-one and the IDs
(`auth-01`, `exch-02`, etc.) stay aligned across the bash and Pest runners.

## Layout

```
khan-pest-skeleton/
  pest.php                     # Pest's bootstrap; Khan replaces with its own
  tests/
    Conformance/
      SeedlingV1Test.php       # the main test file — happy paths
      ExchangeTest.php         # one tag-scoped file as illustration
      Helpers/
        Client.php             # Guzzle wrapper that mirrors lib.sh primitives
        Fixtures.php           # fixture env reader (matches the bash runner)
```

## How to adopt

1. Drop `tests/Conformance/Helpers/Client.php` and `Fixtures.php` into your Khan
   test tree (rename namespace).
2. Copy the test cases from `SeedlingV1Test.php` + `ExchangeTest.php`. For each
   case from `../TEST-PLAN.md` not yet covered, follow the existing pattern.
3. Wire Khan's CI to read the same env (BASE_URL, OPERATOR_TOKEN, NOMAD_TOKEN_*,
   OPAQUE_*, SLOT_PASSWORD_*) the bash runner reads. The fixture contract is the
   single source of truth — keep CI seed parity with `../bin/seed.sh`.
4. Khan's own Pest suite can extend (more cases, deeper assertions); to claim
   conformance the cases here MUST all pass.

The Pest cases below cover roughly 1/3 of the test plan as illustration; the
porting pattern for the rest is mechanical.
