# seedling/v1 — Reference state schema (PocketBase)

> This document describes the **reference state model** as implemented behind `abc-auth-svc` —
> three PocketBase v0.23 collections: `groups`, `slots`, `deletion_audit`. It is the
> reference because that is what the production seedling-tier service uses; the **wire
> contract is `seedling-v1.openapi.yaml`, not this schema**. Khan and any other implementation
> are free to use a different backing store (PostgreSQL, MariaDB, an in-memory store for
> tests) — they MUST preserve the contract-visible projection (`PublicSlot` in the OpenAPI
> spec) and the state semantics described in §3, but the column types, names, and indexes
> are implementation-internal.

**Source:**
[`abc-deployments/abc-seedling-prod/scripts/setup-pocketbase-schema.py`](https://github.com/abc-cluster/abc-deployments)
— the canonical creation script. PocketBase v0.23 flat `fields` format. Run-once, idempotent.

**Contract relationship:** the OpenAPI `PublicSlot` schema is a strict subset of the `slots`
record with all secret fields stripped. The OpenAPI `ExchangeBundle` cross-references
`slots.nomad_token_secret`, `slots.minio_secret_key`, plus per-deployment cluster fields
(`CLUSTER_NOMAD_ENDPOINT`, `CLUSTER_MINIO_ENDPOINT`, `CLUSTER_DATACENTER`,
`CLUSTER_HEAD_POOL`, `CLUSTER_WORKER_POOL` — these are server config, not record fields).

---

## 1. Collections at a glance

| Collection | Purpose | Cardinality | Mutability |
|---|---|---|---|
| `groups` | Tenant/namespace records. One row per allowlisted group (`mbhg-hostgen`, `sdsct-ceri`, …). | ~10–100 | rare ops change |
| `slots` | Per-user workbench slot — identity, credentials, lifecycle state. | ~100–10,000 | hot path on lifecycle ops |
| `deletion_audit` | Append-only log of slot deletion / suspension lifecycle events. | unbounded | insert-only |

A PocketBase **superuser** record (`_superusers` built-in collection) named
`abc-auth@abc-cluster.cloud` is the only programmatic account the service uses to talk to PB.
`PB_ADMIN_PASSWORD` is mandatory env on the service.

---

## 2. `groups`

A "group" is a tenant boundary — corresponds 1:1 to a Nomad namespace (`su-<group>`), a MinIO
group/policy, and a bucket layout. Group records are public-readable in PB so the rendering
of `config.yaml` and the operator UI can look up display names; PB **list/view rules** are
empty strings (public) — write rules require `@request.auth.id != ''` (any authenticated
caller; in practice only the superuser).

### Fields

| Name | Type | Required | Constraints | Notes |
|---|---|---|---|---|
| `name` | text | yes | min 1 / max 100 | The wire name (`mbhg-hostgen`). Used in namespace derivation, policy names, claim_code prefixes. SHOULD be `[a-z0-9_-]+`. Unique by convention; PB doesn't enforce uniqueness here so the create flow must check. |
| `display_name` | text | no | min 0 / max 200 | Human-readable label for UIs ("MBHG Host Genomics"). |
| `max_users` | number | no | min 0 / max 10000, integer | Soft cap on slot count for this group. Today only displayed; not enforced at claim time. |
| `active` | bool | no | — | Group is open for new claims. Suspended groups (false) reject claims. |
| `cred_source_default` | text | no | min 0 / max 40 | Default `slots.cred_source` applied to newly claimed slots when the claim does not override. Values: `""`, `"local"`, or `"seedling/v1"`. |

### PocketBase rules

```
listRule:   ""                            # public
viewRule:   ""                            # public
createRule: "@request.auth.id != ''"      # superuser only in practice
updateRule: "@request.auth.id != ''"
deleteRule: null                          # not deletable via API
```

### Seed data (`SEED_GROUPS` in the script)

| name | display_name | max_users | active |
|---|---|---|---|
| `demo` | Demo | 10 | yes |
| `mbhg-bioinformatics` | MBHG Bioinformatics | 30 | yes |
| `mbhg-hostgen` | MBHG Host Genomics | 30 | yes |
| `mbhg-tbgenomics` | MBHG TB Genomics | 30 | yes |
| `mbhg-animaltb` | MBHG Animal TB | 30 | yes |
| `psy-neuropsychiatry` | Psychiatry Neuropsych | 30 | yes |
| `sdsct-ceri` | SDSCT CERI | 30 | yes |

---

## 3. `slots`

The per-user record. Hot path — every `/validate`, `/exchange`, `/manage/*`,
`/workbench/token`, `/secrets/*` operation reads (and often writes) this collection.

### Fields

| Name | Type | Required | Hidden | Constraints | Notes |
|---|---|---|---|---|---|
| `slot_name` | text | yes | no | min 1 / max 100 | The wire identifier (`solar_civet`, `coral_starfish`). Matches Nomad token `Name` (with or without `pool-` prefix), matches JH user `jupyter-<slot_name>`. SHOULD be `[a-z0-9_]+`. |
| `group` | relation → `groups` | yes | no | maxSelect 1, no cascade-delete | The group this slot belongs to. The `group` field on the wire (`PublicSlot.group`) is the **id** of the related row; the `group_name` field is the looked-up `groups.name` (sometimes denormalised). |
| `claim_code` | text | yes | **yes** | min 8 / max 64 | The single-use code the operator hands a user. Hidden via the PB rule but the service uses it; never on the wire after claim. |
| `nomad_token_accessor` | text | no | no | max 200 | The Nomad ACL token accessor (visible identifier — non-secret). Used by `/manage/slots/{slot}/{rotate,suspend}` to revoke the old token. |
| `nomad_token_secret` | text | no | **yes** | max 200 | The Nomad ACL token secret. Returned in `/exchange` body; never logged. |
| `minio_access_key` | text | no | no | max 100 | MinIO IAM access key. Looked up by `findSlot("minio_access_key='...'")` during `/auth/login`. Visible on `PublicSlot`. |
| `minio_secret_key` | text | no | **yes** | max 200 | MinIO IAM secret. Returned in `/exchange` body; never logged. |
| `state` | select | yes | no | one of `unclaimed`, `claimed`, `suspended`, `expired` | Lifecycle state. See §3.1 state machine. |
| `claimed_by_name` | text | no | no | max 200 | Captured at claim time from the request body. Informational. |
| `claimed_by_email` | email | no | no | — | Captured at claim time. Informational. |
| `claimed_at` | date | no | no | — | UTC timestamp of claim. Format on write: `YYYY-MM-DD HH:MM:SS.000Z` (PB-tolerant). |
| `config_yaml` | text | no | **yes** | max 8192 | Rendered `config.yaml` blob — derived cache of `nomad_*` + `minio_*` + cluster endpoints. Re-rendered on every credential mutation. Served as attachment by `GET /slots/me/config`. |
| `config_yaml_at` | date | no | no | — | UTC timestamp of the last render. Visible on `PublicSlot`. |
| `config_yaml_renderer` | text | no | no | max 100 | Identifier of the code path that last rendered (e.g. `go-authsvc-Phase3`, `python-2.0`). For drift detection. |
| `cred_source` | text | no | no | max 40 | Slot-level credential resolver mode. `""` / `"local"` = the rendered `config_yaml` carries the real Nomad/MinIO creds; `"seedling/v1"` = the YAML carries an opaque token + broker endpoint, and the CLI exchanges at `/exchange` on use. |
| `opaque_token_hash` | text | no | **yes** | max 128 | Hex SHA-256 of the bare opaque (`abco_…`) token. The bare token NEVER touches this record. Used by `/exchange` for constant-time lookup (`filter=opaque_token_hash='<hex>' && state='claimed'`). Present iff `cred_source = "seedling/v1"`. |

### PocketBase rules

```
listRule:   "@request.auth.id != ''"      # superuser only
viewRule:   "@request.auth.id != ''"
createRule: "@request.auth.id != ''"
updateRule: "@request.auth.id != ''"
deleteRule: null                          # never via API
```

### 3.1 State machine

```
                   POST /slots/claim
                       │
                       ▼
   ┌──► unclaimed ──claim_code valid──► claimed ◄─reactivate─ suspended
   │      ▲                              │  │                    │
   │      │                              │  └─ rotate ─────────► claimed
   │      │                              │                  (creds rotated,
   │      │                              │                   state unchanged)
   │  (admin              ┌── suspend ──┘
   │   creates                │
   │   row)                   ▼
   │                      suspended ──reactivate──► claimed
   │                          │
   │                          └─ rotate ─► suspended (allowed; creds rotated)
   │
   └──◄── (admin reset) ── any state
```

Transitions:

- `unclaimed → claimed`: `POST /slots/claim`. Sets `claimed_by_*`, `claimed_at`, `state`,
  optionally `cred_source` + `opaque_token_hash`; persists rendered `config_yaml`.
- `claimed → suspended`: `POST /manage/slots/{slot}/suspend`. Best-effort upstream
  side-effects (MinIO disable, Nomad token delete, host creds removal, JH stop-server).
- `suspended → claimed`: `POST /manage/slots/{slot}/reactivate`. Mints fresh MinIO secret +
  new Nomad token, persists, re-renders config_yaml.
- `claimed | suspended → same`: `POST /manage/slots/{slot}/rotate`. Rotates creds without
  changing `state`.
- Any → `expired`: NOT exposed on `seedling/v1`. Reserved for future TTL-based expiry; the
  service treats `expired` identically to `suspended` for forward-auth purposes.

### 3.2 Indexes (implementation-internal)

PocketBase v0.23 doesn't expose declarative indexes on `text` fields beyond auto-indexed
foreign keys. Implementations on other stores SHOULD add:

- Unique index on `slot_name`.
- Unique index on `minio_access_key` (looked up by `/auth/login`).
- Unique index on `opaque_token_hash` where non-empty (looked up by `/exchange`).
- Composite index on `(state, group)` for the operator list endpoint.
- Lookup index on `nomad_token_accessor` for revocation by accessor.

### 3.3 Field cardinality and shape

- `claim_code` cardinality is "one issued per slot row at row creation time"; the value is
  random and uniformly distributed in the alphabet the operator tooling chose
  (`[A-Za-z0-9]{16-32}`). Treat as opaque.
- `opaque_token_hash` is `sha256_hex(<bare opaque>)`. The bare opaque is `abco_<32-byte
  random>` rendered as `abco_<urlsafe-b64>` (length depends on representation; the test
  fixture uses 43 chars after the prefix). Implementations MUST NOT store anything other
  than the hash.

---

## 4. `deletion_audit`

Append-only log. The reference implementation writes rows for deletion / heavy lifecycle
ops; the service does NOT consume them today (operator-only audit surface). Included for
completeness because Khan SHOULD preserve the same audit shape if implementing in-platform
audit.

### Fields

| Name | Type | Required | Constraints | Notes |
|---|---|---|---|---|
| `slot_name` | text | yes | min 1 / max 100 | The slot the event is about. |
| `group_name` | text | no | max 100 | At time of event (groups can be renamed). |
| `deleted_by` | text | no | max 200 | Operator identity. |
| `reason` | text | no | max 1000 | Free-text. |

### Rules

```
listRule:   "@request.auth.id != ''"      # superuser only
viewRule:   "@request.auth.id != ''"
createRule: "@request.auth.id != ''"
updateRule: null                          # append-only
deleteRule: null
```

---

## 5. Lifecycle: from row to working slot

For a Khan implementer building the equivalent flows on PG/MariaDB:

```
operator pre-mints a row
   │
   │ INSERT slots (slot_name, group, claim_code, state='unclaimed',
   │               nomad_token_accessor, nomad_token_secret,
   │               minio_access_key, minio_secret_key)
   │   ↑ Nomad ACL token already exists (created by operator tooling),
   │   ↑ MinIO IAM user already exists.
   │
   ▼
hands the claim_code to the user
   │
   │ user runs `abc auth claim <code>` (or POSTs /slots/claim with the code)
   │
   ▼
slot transitions to claimed (atomic find→patch under a per-code lock)
   │
   │ UPDATE slots SET state='claimed',
   │                  claimed_by_*=..., claimed_at=now(),
   │                  cred_source=resolved(),
   │                  opaque_token_hash=hash(opaque if seedling/v1),
   │                  config_yaml=render(slot)
   │   WHERE id=? AND state='unclaimed'
   │   RETURNING ...           -- 0 rows means the race lost
   │
   ▼
config.yaml flows back to the user
   │
   │ either embedded creds (cred_source=local) or
   │ embedded opaque token (cred_source=seedling/v1)
   │
   ▼
user submits jobs / pulls workbench tokens / etc.
```

The contract-visible operations are §6 onward. The state machine guarantees needed:

1. Concurrent claims on the same `claim_code` MUST resolve to exactly one success.
2. Re-claim of an already-claimed code MUST fail with `404 code_invalid_or_used` (no
   distinction between "never existed" and "already used").
3. Suspend → Reactivate MUST mint new credentials; reusing the old secrets is not
   conformant (the old secrets were revoked at suspend time).
4. Rotate MUST revoke the old Nomad token by accessor best-effort but MUST always
   produce a successful 200 if the PB patch succeeded.
5. Deletion (operator action) MUST write a `deletion_audit` row before removing the slot row.
   (Today the service does not implement deletion; this is the contract for when it does.)

---

## 6. JSON dump (PocketBase v0.23 import format)

For Khan implementers using PocketBase as their store (or for re-bootstrapping the
reference deployment), the schema is in
[`seedling-v1-pb-schema.json`](./seedling-v1-pb-schema.json) — a direct dump of the three
collections with `REPLACE_ME` placeholders for the `groups` collection ID (filled in at
import time, the same as `setup-pocketbase-schema.py`).

Importable via the PocketBase admin UI: Settings → Import collections. Or programmatically
via `POST /api/collections` for each collection (auth as `_superusers` first).

---

## 7. Khan-specific implementation notes

If Khan chooses **not** to use PocketBase:

1. **Map the field types.** PB `text` → varchar / nvarchar; `select` → enum or
   varchar+check; `relation` → foreign key; `date` → timestamptz / datetime; `email` → varchar
   with a check; `bool` → boolean; `number` (integer) → bigint.
2. **Preserve the rules' effect.** PB `listRule`/`viewRule` map to whether your API serves
   the collection through an open / authenticated path. For Khan-on-Laravel, the equivalent
   is route middleware; the `slots` collection's "superuser-only" rule maps to "only
   Khan-internal queries; never expose this through a public endpoint".
3. **Keep field names on the wire.** The contract-visible `PublicSlot` field names
   (`id`, `slot_name`, `group`, `group_name`, `state`, `cred_source`, `minio_access_key`,
   `config_yaml_at`, `opaque_token_hash`) are wire-locked. Inside Khan you can use whatever
   column names you like, but the JSON projection MUST match.
4. **The `group` field on the wire is the group ID, not the name.** This matches the PB
   relation semantics. `group_name` is the looked-up name; both are present in the
   projection because clients use the name and operators use the id.
5. **`config_yaml` is a derived cache, not source of truth.** Khan should treat it as
   regeneratable; if the cache is missing or empty, render on demand and persist.

---

## 8. Operator + service accounts

The service authenticates to PB as a superuser. There are two service-scoped secrets in the
reference deployment:

- `PB_ADMIN_PASSWORD` — superuser password; mounted to the auth-svc Nomad job via a Nomad
  Variable (`nomad/jobs/secrets/pb_admin_password`). Issued by `install-pocketbase.sh` and
  written to `/etc/abc-auth-svc/pb-admin-password` (chmod 600, root-owned).
- `OPERATOR_TOKEN` — the shared secret behind `X-Operator-Token`. Issued by the same install
  script and written to `/etc/abc-auth-svc/operator_token`. The Khan equivalent is in
  `seedling-v1-api-contract.md` §4.4.

Both rotations are operator chores — there is no in-API verb for either.

---

## Source

- Setup script: `abc-deployments/abc-seedling-prod/scripts/setup-pocketbase-schema.py`
- Reference implementation reader: `abc-auth-svc/internal/authsvc/pocketbase.go`
- Reference implementation writer (patches): `abc-auth-svc/internal/authsvc/{claim,manage,manage_rotate}.go`
- Brainstorms underpinning the design:
  - `abc-universe/brainstorms/abc-seedling-onboarding/2026-06-01-opaque-tokens-credential-broker.md`
  - `abc-universe/brainstorms/abc-seedling-onboarding/2026-06-01-claim-time-config-dropthrough.md`
