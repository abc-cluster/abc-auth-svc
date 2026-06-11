# seedling/v1 — test suite

Conformance test cases that any `seedling/v1` implementation (the Go reference,
Khan, future re-implementations) MUST pass to claim contract compatibility.

- **[TEST-PLAN.md](TEST-PLAN.md)** — language-neutral case-by-case plan with the
  fixture contract. Read this first.
- **[bin/run.sh](bin/run.sh)** — runnable bash + curl + jq harness.
- **[khan-pest-skeleton/](khan-pest-skeleton/)** — Pest (Laravel) skeleton showing
  the same shape inside Khan's CI.

## Run

```bash
export BASE_URL=http://127.0.0.1:4182
export OPERATOR_TOKEN=…
export NOMAD_TOKEN_SOLAR_CIVET=…
export NOMAD_TOKEN_GRANITE_IGUANA=…
export NOMAD_TOKEN_AZURE_PANTHER=…
export OPAQUE_SOLAR_CIVET=abco_…
export OPAQUE_GRANITE_IGUANA=abco_…
export SLOT_PASSWORD_SOLAR_CIVET=…
export SLOT_PASSWORD_GRANITE_IGUANA=…
bin/run.sh
```

Filter to a single case:
```bash
bin/run.sh auth-04 exch-01 mgmt-12
```

Filter to a tag:
```bash
bin/run.sh --tag exchange
```

Opt-in to destructive (mutating) management cases:
```bash
RUN_DESTRUCTIVE=1 bin/run.sh --tag manage
```

## Related

- `api/seedling-v1.openapi.yaml` — wire contract (the spec)
- `api/CONFORMANCE.md` — narrative behavioural checklist
- `api/state-schema.md` — the PocketBase state model the reference uses
