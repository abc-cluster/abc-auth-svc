# seedling/v1 — Test plan

A **language-neutral** case-by-case test plan that any conformant implementation of
`seedling/v1` (this repo's Go service, Khan's Laravel implementation, future
implementations) must pass. Each case names:

- The OpenAPI **operationId** it covers (from `api/seedling-v1.openapi.yaml`).
- The **CONFORMANCE.md** items it exercises.
- The **fixture row** it depends on (defined in §1).
- A **request** + **expected response** at the level a TDD authoring the implementation
  needs.

The runnable form lives in `bin/run.sh` + the per-tag `*.sh` shell files alongside this
document. Khan teams can either run the bash suite directly against a Khan instance or
port the cases to Pest using the skeleton in `khan-pest-skeleton/`.

---

## 1. Fixture contract

The runner expects the implementation to be running against a state-store seeded with the
fixture defined here. The bash runner ships a `bin/seed.sh` script that uses the PocketBase
admin API to set this state up; Khan implementations can seed via direct DB inserts or via
the equivalent admin route.

### Groups

| Field | Value |
|---|---|
| `name` | `demo` |
| `display_name` | `Demo` |
| `max_users` | `10` |
| `active` | `true` |
| `cred_source_default` | `seedling/v1` |

Plus the seven seeded groups from §3 of the schema doc.

### Slots

| slot_name | group | state | cred_source | claim_code | minio_access_key | nomad_token_secret | opaque (bare) |
|---|---|---|---|---|---|---|---|
| `solar_civet` | `demo` | `claimed` | `seedling/v1` | (used) | `MK_SOLAR_CIVET_AK` | `nomad-secret-solar-civet-001` | `abco_solar_civet_FIXTURE_BARE_42` |
| `coral_starfish` | `demo` | `unclaimed` | `""` | `CLAIM-CORAL-STARFISH-VALID-001` | `""` | `""` | — |
| `azure_panther` | `demo` | `claimed` | `local` | (used) | `MK_AZURE_PANTHER_AK` | `nomad-secret-azure-panther-001` | — |
| `granite_iguana` | `demo` | `suspended` | `seedling/v1` | (used) | `MK_GRANITE_IGUANA_AK` | `nomad-secret-granite-iguana-001` | `abco_granite_iguana_FIXTURE_BARE_57` |

The opaque hashes (`sha256_hex` of the bare opaque) are written to
`slots.opaque_token_hash` at fixture seed time. The bare opaque is preserved in the
runner's env (`OPAQUE_SOLAR_CIVET`, `OPAQUE_GRANITE_IGUANA`) and used as `Authorization:
Bearer` for the relevant test cases. The Nomad token secrets (`NOMAD_TOKEN_SOLAR_CIVET`)
are similarly preserved.

### Server config the implementation must have

| Knob | Value for tests |
|---|---|
| `SESSION_SECRET` | any non-empty random string |
| `SESSION_TTL_SECONDS` | `604800` |
| `COOKIE_SECURE` | `false` (so curl over localhost works) |
| `OPERATOR_TOKEN` | `op_test_token_RANDOM` (exported to the runner as `$OPERATOR_TOKEN`) |
| `CLI_TOKEN_TTL` | `60` |
| Cluster fields | any concrete values; exercised via `/exchange` response shape |

---

## 2. Per-endpoint test cases

Each case is identified `<TAG>-<NN>`. Sequencing notes call out when one case must run
before another. Bash test files implement these cases under matching names.

### 2.1 Health — `health-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `health-01` | `getHealthz` | C-01, C-02 — version + request-id stamping; happy path | `GET /healthz` | `200`; body `"ok\n"`; headers include `X-Abc-Auth-API-Version: v1` + `X-Request-Id` |
| `health-02` | `getHealthz` | C-08 alias path | `GET /auth/health` | identical to health-01 |
| `health-03` | `getReadyz` | shape | `GET /readyz` | `200`; JSON has `status: "ready"`, `version: string` |
| `health-04` | `getVersion` | shape | `GET /version` | `200`; JSON has fields `version`, `build_time`, `git_commit` (values MAY be empty) |
| `health-05` | C-02 echo | echo of inbound request id | `GET /healthz` with `X-Request-Id: test-12345` | `200`; response `X-Request-Id: test-12345` |
| `health-06` | C-02 mint | sanitisation rejects bad id and mints | `GET /healthz` with `X-Request-Id: ../../etc/passwd` | `200`; response `X-Request-Id` is freshly minted (not the bad value) |

### 2.2 Forward-auth — `validate-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `validate-01` | `forwardAuth` | V-01 happy path | `GET /validate` with the `abc_session` cookie of `solar_civet` | `200`; empty body; headers `X-Auth-User: solar_civet`, `Remote-User: solar_civet`, `X-WEBAUTH-USER: solar_civet` |
| `validate-02` | `forwardAuth` | V-02 no cookie | `GET /validate` no cookie | `302`; `Location: /auth/login?next=%2F`; empty body |
| `validate-03` | `forwardAuth` | V-02 next propagation | `GET /validate` no cookie, `X-Forwarded-Uri: /apps/foo` | `302`; `Location: /auth/login?next=%2Fapps%2Ffoo` |
| `validate-04` | `forwardAuth` | V-03 suspended slot | `GET /validate` with `granite_iguana` cookie | `302`; `Set-Cookie: abc_session=` (clearing) |
| `validate-05` | `forwardAuthOptional` | V-04 anon | `GET /validate-optional` no cookie | `200`; NO `X-Auth-User` header |
| `validate-06` | `forwardAuthOptional` | V-04 authenticated | `GET /validate-optional` with `solar_civet` cookie | `200`; `X-Auth-User: solar_civet` |

### 2.3 Auth — `auth-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `auth-01` | `getLoginForm` | A-01 | `GET /auth/login` | `200`; `Content-Type: text/html…`; `Cache-Control: no-store`; body contains a `<form` element |
| `auth-02` | `getLoginForm` | A-04 next sanitisation surfaces in HTML | `GET /auth/login?next=//evil.example/x` | `200`; HTML does NOT carry the scheme-relative URL verbatim |
| `auth-03` | `submitLogin` | A-03 success | `POST /auth/login` form `username=solar_civet&password=<correct>` | `302`; `Set-Cookie: abc_session=…`; `Location: /` |
| `auth-04` | `submitLogin` | A-02 wrong password is HTML 200 | `POST /auth/login` form `username=solar_civet&password=WRONG` | `200`; HTML body contains `Invalid username or password.` |
| `auth-05` | `submitLogin` | A-02 empty fields | `POST /auth/login` form `username=&password=` | `200`; HTML body contains `Username and password are required.` |
| `auth-06` | `submitLogin` | A-02 suspended slot | `POST /auth/login` form `username=granite_iguana&password=<correct>` | `200`; HTML body contains `Account suspended.` |
| `auth-07` | `submitLogin` | A-04 next sanitisation rejects scheme-relative | `POST /auth/login` form `username=solar_civet&password=<ok>&next=//evil/x` | `302`; `Location` is `/` (not `//evil/x`) |
| `auth-08` | `logout` | A-05 | `GET /auth/logout` | `302`; `Location: /auth/login`; `Set-Cookie` clearing `abc_session` (`Max-Age=-1` or `Max-Age=0`) |
| `auth-09` | `getMe` | A-06 happy path + CORS header | `GET /auth/me` with `Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET` | `200`; JSON has `user`, `groups`, `primary_group`, `namespace`, `role_based`; response header `Access-Control-Allow-Origin: *` |
| `auth-10` | `getMe` | missing bearer | `GET /auth/me` no auth | `401`; `{"error":"missing token"}` |
| `auth-11` | `getMe` | bogus bearer | `GET /auth/me` `Authorization: Bearer obviously-not-real` | `401`; `{"error":"invalid token"}` |
| `auth-12` | `getMe` | X-Nomad-Token equivalent | `GET /auth/me` `X-Nomad-Token: $NOMAD_TOKEN_SOLAR_CIVET` | identical to auth-09 |

### 2.4 Workbench — `wb-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `wb-01` | `mintWorkbenchToken` | happy path | `POST /workbench/token` Bearer `solar_civet`'s Nomad token, body `{}` | `200`; JSON has `token`, `id`, `expires_at`, `scopes`, `note`, `slot: "solar_civet"`, `hub_url` |
| `wb-02` | `mintWorkbenchToken` | W-02 default `expires_in` | request omits `expires_in` | `200`; `expires_at` ≈ now + 604800 s |
| `wb-03` | `mintWorkbenchToken` | W-02 explicit valid | body `{"expires_in":3600}` | `200`; `expires_at` ≈ now + 3600 s |
| `wb-04` | `mintWorkbenchToken` | W-02 too large | body `{"expires_in":99999999}` | `400`; `{"error":"expires_in cannot exceed 30 days (2592000 seconds)"}` |
| `wb-05` | `mintWorkbenchToken` | W-02 non-int | body `{"expires_in":"forever"}` | `400`; error tag `expires_in must be an integer (seconds)` |
| `wb-06` | `mintWorkbenchToken` | W-02 non-positive | body `{"expires_in":0}` | `400`; error tag `expires_in must be positive` |
| `wb-07` | `mintWorkbenchToken` | W-04 suspended → 403 | Bearer `granite_iguana`'s Nomad token | `403`; `{"error":"slot is suspended"}` |
| `wb-08` | `mintWorkbenchToken` | bad JSON | body `{` (malformed) | `400`; `{"error":"invalid JSON body"}` |
| `wb-09` | `mintWorkbenchToken` | missing bearer | no auth | `401`; error tag begins `missing token` |
| `wb-10` | `mintWorkbenchToken` | alias works | `POST /auth/workbench/token` | identical to wb-01 |

### 2.5 Exchange — `exch-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `exch-01` | `exchangeOpaque` | X-01 wire shape | `POST /exchange` `Authorization: Bearer $OPAQUE_SOLAR_CIVET` | `200`; JSON keys exactly `whoami`, `source`, `nomad`, `minio`; nested `nomad` has `addr`, `token`, `namespace`, `datacenters`, `head_pool`, `worker_pool`; `minio` has `endpoint`, `access_key`, `secret_key`; `source == "seedling/v1"` |
| `exch-02` | `exchangeOpaque` | X-02 missing | no `Authorization` | `401`; `{"error":"missing_bearer_token"}` |
| `exch-03` | `exchangeOpaque` | X-02 empty | `Authorization: Bearer ` | `401`; `{"error":"empty_bearer_token"}` |
| `exch-04` | `exchangeOpaque` | X-02 invalid | `Authorization: Bearer abco_not_a_real_one` | `401`; `{"error":"invalid_or_inactive_token"}` |
| `exch-05` | `exchangeOpaque` | X-02 collision | non-existent slot hash | `401`; SAME tag `invalid_or_inactive_token` |
| `exch-06` | `exchangeOpaque` | X-03 wrong source | bare opaque whose slot has `cred_source=local` (uses a side-fixture; runner skips if unavailable) | `409`; `{"error":"slot_not_on_seedling_v1"}` |
| `exch-07` | `exchangeOpaque` | X-04 logging boundary | observe stdout/file logs do not contain bare opaque, Nomad token secret, or MinIO secret | manual check — runner emits a warning if grep finds any |

### 2.6 Slots — user — `slot-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `slot-01` | `getSlotsMeConfig` | U-01 happy path | `GET /slots/me/config` Bearer `solar_civet`'s Nomad token | `200`; `Content-Type: text/yaml`; `Content-Disposition: attachment; filename="abc-config-solar_civet.yaml"`; `Cache-Control: no-store`; body parses as YAML with a top-level mapping |
| `slot-02` | `getSlotsMeConfig` | U-02 persistence | call slot-01 twice; the second should be served from PB cache | both responses identical; the PB `slots.config_yaml_at` was set on or before the second request |
| `slot-03` | `getSlotsMeConfig` | 401 | no auth | `401`; error tag begins `missing_token` |
| `slot-04` | `getSlotsMeConfig` | 403 on unclaimed | use a Nomad token belonging to `coral_starfish` (unclaimed) | `403`; error tag `slot_unclaimed` (or another `slot_*`) |
| `slot-05` | `claimSlot` | U-03 anon claim | `POST /slots/claim` `{"claim_code":"CLAIM-CORAL-STARFISH-VALID-001"}` | `200`; `Content-Type: application/yaml`; body is YAML; `coral_starfish` state in PB is now `claimed` |
| `slot-06` | `claimSlot` | U-04 opaque embedded once | repeat slot-05 on a fresh fixture, inspect body; THEN list slots and confirm `opaque_token_hash` is set but bare opaque does NOT appear anywhere else | manual + automated grep |
| `slot-07` | `claimSlot` | U-05 already-used | re-run slot-05 with the same code after slot-05 succeeded | `404`; `{"error":"code_invalid_or_used"}` |
| `slot-08` | `claimSlot` | U-05 unknown code | `{"claim_code":"NOT-A-REAL-CODE"}` | `404`; SAME tag `code_invalid_or_used` |
| `slot-09` | `claimSlot` | bad json | body `{garbled` | `400`; `{"error":"invalid_json"}` |
| `slot-10` | `claimSlot` | invalid cred_source | `{"claim_code":"valid","cred_source":"remote"}` | `400`; `{"error":"invalid_cred_source","requested":"remote","allowed":["local","seedling/v1"]}` |
| `slot-11` | `claimSlot` | U-06 concurrency | spawn 5 concurrent claims on same code | exactly 1 returns `200` + YAML; 4 return `404 code_invalid_or_used` |

### 2.7 Slots — operator — `mgmt-NN`

All require `X-Operator-Token: $OPERATOR_TOKEN`. Cases omit the header to verify O-02
guards.

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `mgmt-01` | `listManagedSlots` | O-03 shape | `GET /manage/slots` | `200`; JSON array; each entry has `slot_name`, `group`, `state`, `cred_source`; NO `minio_secret_key`, NO `nomad_token_secret` anywhere |
| `mgmt-02` | `listManagedSlots` | O-01 missing token | no `X-Operator-Token` | `401`; `{"error":"unauthorized"}` |
| `mgmt-03` | `listManagedSlots` | O-01 wrong token | `X-Operator-Token: wrong` | `401`; same shape |
| `mgmt-04` | `getManagedSlot` | happy path | `GET /manage/slots/solar_civet` | `200`; one `PublicSlot` |
| `mgmt-05` | `getManagedSlot` | 404 | `GET /manage/slots/no_such_slot` | `404`; `{"error":"not_found"}` |
| `mgmt-06` | `setCredSource` | O-04 local→seedling/v1 returns opaque once | `POST /manage/slots/azure_panther/cred-source` body `{"cred_source":"seedling/v1"}` | `200`; body has `opaque_token` (bare); a second `GET /manage/slots/azure_panther` does NOT include the bare value |
| `mgmt-07` | `setCredSource` | no-op | repeat mgmt-06 on a slot already at `seedling/v1` | `200`; `changed: false`; body has NO `opaque_token` |
| `mgmt-08` | `setCredSource` | invalid value | body `{"cred_source":"sausage"}` | `400`; `{"error":"invalid_cred_source"}` |
| `mgmt-09` | `setCredSource` | slot_not_claimed | request against `coral_starfish` | `400`; `{"error":"slot_not_claimed"}` |
| `mgmt-10` | `diagnoseSlot` | shape | `GET /manage/slots/solar_civet/diag` | `200`; JSON has `slot`, `pb`, `jh`, `host`, `checks`, `verdict`, `remediation_hints`; body is pretty-printed (2-space indent) |
| `mgmt-11` | `diagnoseSlot` | missing slot returns 200, not 404 | `GET /manage/slots/no_such_slot/diag` | `200`; `verdict` starts with `blocked_at:` |
| `mgmt-12` | `suspendSlot` | happy path | `POST /manage/slots/solar_civet/suspend` | `200`; `{"ok":true}`; subsequent `GET /manage/slots/solar_civet` shows `state: suspended` |
| `mgmt-13` | `suspendSlot` | 400 wrong state | re-run mgmt-12 (already suspended) | `400`; `{"error":"slot_not_claimed"}` |
| `mgmt-14` | `reactivateSlot` | happy path | `POST /manage/slots/solar_civet/reactivate` | `200`; subsequent get shows `state: claimed`; **new** Nomad token + MinIO secret persisted (`/exchange` returns different values than the pre-mgmt-12 fixture) |
| `mgmt-15` | `rotateSlot` | happy path on claimed | `POST /manage/slots/solar_civet/rotate` | `200`; `state` unchanged at `claimed`; new MinIO secret + new Nomad token; old Nomad accessor revoked best-effort |
| `mgmt-16` | `rotateSlot` | rotate works on suspended | suspend, then `POST .../rotate` | `200`; state still `suspended`; new creds persisted |
| `mgmt-17` | `rotateSlot` | 400 wrong state | rotate against unclaimed `coral_starfish` | `400`; `{"error":"slot_not_active"}` |

### 2.8 CLI tokens — `cli-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `cli-01` | `mintCLIToken` | happy path | `POST /cli-token` body `{"nomad_token":"$NOMAD_TOKEN_SOLAR_CIVET"}` | `200`; `code` is 64 hex; `ttl` matches `CLI_TOKEN_TTL` |
| `cli-02` | `mintCLIToken` | missing body | empty | `400`; `{"error":"missing request body"}` |
| `cli-03` | `mintCLIToken` | missing field | `{}` | `400`; `{"error":"nomad_token required"}` |
| `cli-04` | `mintCLIToken` | invalid nomad token | body has bogus token | `401`; error tag `invalid or expired Nomad token` |
| `cli-05` | `redeemCLIToken` | T-04 single use | mint, then `GET /redeem?code=<code>` | `302`; `Set-Cookie: abc_session=…`; `Location` is a same-origin path |
| `cli-06` | `redeemCLIToken` | T-04 replay | re-`GET /redeem?code=<code>` | `302`; `Location: /auth/login?error=link_expired`; NO cookie set |
| `cli-07` | `redeemCLIToken` | T-03 missing code | `GET /redeem` no code | `302`; `Location: /auth/login?error=missing_code` |
| `cli-08` | `redeemCLIToken` | T-05 grafana | mint with `{"portal":"grafana",...}`, then redeem | `302`; `Location` is `/login` (grafana app's login path) |

### 2.9 MinIO SSO — `minio-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `minio-01` | `minioSSOLand` | M-01 happy | mint with `portal=minio` then `GET /minio-login?code=<code>` | `302`; `Set-Cookie: token=…` (cookie name `token`, NOT `abc_session`); `Location: /`; `Max-Age=43200` |
| `minio-02` | `minioSSOLand` | M-03 missing code | `GET /minio-login` no code | `302`; `Location: /?error=missing_code` |
| `minio-03` | `minioSSOLand` | M-03 expired | redeem then re-redeem | `302`; `Location: /?error=link_expired` |

### 2.10 Verify — `verify-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `verify-01` | `verifyGet` | Y-02 happy | `GET /verify` Bearer `solar_civet`'s Nomad token | `200`; `Content-Type: text/plain`; body `"ok\n"`; headers `X-Auth-User`, `X-Auth-Group`, `X-Auth-Namespace`, `X-Auth-Policies`, `X-Auth-Type` all set |
| `verify-02` | `verifyGet` | Y-01 alias parity | `GET /verify-namespace` | identical to verify-01 |
| `verify-03` | `verifyPost` | Y-01 method parity | `POST /verify` with same bearer | identical to verify-01 |
| `verify-04` | `verifyGet` | Y-02 failure | no auth | `401`; body `"unauthorized: missing or invalid token\n"` |
| `verify-05` | `verifyGet` | Y-03 management token shape | (skip unless a management token is provisioned) Bearer `<management>` | `200`; `X-Auth-Type: management`, `X-Auth-Group: admin`, `X-Auth-Policies: management`, `X-Auth-Namespace: *` |

### 2.11 Secrets — `sec-NN`

All use `Authorization: Bearer $OPAQUE_SOLAR_CIVET`.

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `sec-01` | `secretsPut` | happy path string | `POST /secrets/put` body `{"key":"my_key","value":"hello"}` | `200`; `{"ok":true}` |
| `sec-02` | `secretsGet` | round-trip | `POST /secrets/get` body `{"key":"my_key"}` | `200`; `{"value":"hello"}` |
| `sec-03` | `secretsPut` | K-01 type coercion null | body `{"key":"k_null","value":null}` | `200`; subsequent get returns `{"value":""}` |
| `sec-04` | `secretsPut` | K-01 type coercion object | body `{"key":"k_obj","value":{"a":1}}` | `200`; subsequent get returns `{"value":"{\"a\":1}"}` (the JSON-encoded string) |
| `sec-05` | `secretsGet` | K-03 not found | `POST /secrets/get` body `{"key":"never_written"}` | `404`; `{"error":"not_found"}` |
| `sec-06` | `secretsPut` | missing key | body `{"value":"x"}` | `400`; `{"error":"key_and_value_required"}` |
| `sec-07` | `secretsPut` | bad json | body `{garbled` | `400`; `{"error":"bad_json"}` |
| `sec-08` | `secretsPut` | bearer missing | no auth | `401`; `{"error":"missing_bearer_token"}` |
| `sec-09` | `secretsPut` | bearer bogus | `Bearer abco_nonsense` | `401`; `{"error":"invalid_or_inactive_token"}` |
| `sec-10` | `secretsPut` | K-04 group override | body `{"key":"shared","value":"v","group":"demo"}` | `200`; the variable is stored at namespace `su-demo` (operator-side verification) |

### 2.12 Log level — `log-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `log-01` | `getLogLevel` | happy path | `GET /manage/log-level` Op token | `200`; `{"level":"info|debug|trace","mutable":true}` |
| `log-02` | `setLogLevel` | round-trip | `POST /manage/log-level` body `{"level":"debug"}` | `200`; `{"ok":true,"level":"debug","previous":"<old>"}` |
| `log-03` | `setLogLevel` | revert | `POST /manage/log-level` body `{"level":"info"}` | `200`; revert |
| `log-04` | `setLogLevel` | L-02 bad value | body `{"level":"sausage"}` | `400`; `{"error":"invalid_level","allowed":["info","debug","trace"]}` |
| `log-05` | `setLogLevel` | missing body | body `{}` | `400`; `{"error":"level_required"}` |
| `log-06` | `setLogLevel` | bad JSON | body `{garbled` | `400`; `{"error":"invalid_json"}` |
| `log-07` | both | O-01 missing op token | drop header | `401`; `{"error":"unauthorized"}` |

### 2.13 Catch-all — `misc-NN`

| ID | OpId | What it verifies | Request | Expect |
|---|---|---|---|---|
| `misc-01` | none | C-08 unrouted | `GET /this/path/does/not/exist` | `404`; `{"error":"not found"}` |
| `misc-02` | none | trailing-slash equivalence (impl choice) | `GET /healthz/` | either `200` (impl accepts) or `404` (impl strict) — runner accepts both, just records which |
| `misc-03` | none | method-not-allowed | `POST /healthz` | `405` (preferred) or `404` — runner accepts either |

---

## 3. Cross-cutting checks (run once across the suite)

Driven by `bin/run.sh` over the full output of the test runs:

- **No secrets in logs.** Grep the implementation's stdout / log file for `OPAQUE_SOLAR_CIVET`,
  `NOMAD_TOKEN_SOLAR_CIVET`, `MK_*_SK` (MinIO secret keys). Any hit fails the suite. (C-06.)
- **No raw cookie values in logs.** Grep for fully-formed `abc_session=…` cookies. (C-06.)
- **No URL query strings in access logs.** Grep for `?code=…`, `?next=…`. (C-06.)
- **All responses have `X-Abc-Auth-API-Version: v1`.** Aggregated from each curl's headers.

---

## 4. Running the suite

```bash
# 1. Seed the state store (PB-backed reference; equivalent for other stores)
BASE_URL=http://127.0.0.1:4182 PB_URL=http://127.0.0.1:8091 \
  bin/seed.sh

# 2. Run the suite
BASE_URL=http://127.0.0.1:4182 \
OPERATOR_TOKEN=op_test_token_RANDOM \
NOMAD_TOKEN_SOLAR_CIVET=nomad-secret-solar-civet-001 \
NOMAD_TOKEN_GRANITE_IGUANA=nomad-secret-granite-iguana-001 \
NOMAD_TOKEN_AZURE_PANTHER=nomad-secret-azure-panther-001 \
OPAQUE_SOLAR_CIVET=abco_solar_civet_FIXTURE_BARE_42 \
OPAQUE_GRANITE_IGUANA=abco_granite_iguana_FIXTURE_BARE_57 \
SLOT_PASSWORD_SOLAR_CIVET=<minio secret of solar_civet> \
  bin/run.sh

# Output: per-case PASS / FAIL summary, non-zero exit on any FAIL.
```

Selective: `bin/run.sh auth-04 exch-01 mgmt-12` runs only those cases.

---

## 5. Khan adoption path

For the Khan team:

1. Stand up a Khan instance with a state-store that satisfies the fixture contract (§1).
   The simplest path is to import the PB schema from `api/seedling-v1-pb-schema.json`
   into a fresh PocketBase; the harder path is to replicate the fixture in PG/MariaDB.
2. Run `bin/run.sh` against the Khan base URL. The expected initial state is a high
   failure rate; the test plan IS the TDD spec.
3. As Khan grows endpoints, move green tests from "FAIL" to "PASS"; the implementation is
   ready for `seedling/v1` conformance when the suite is green.
4. Port the cases to Pest (use the skeleton in `khan-pest-skeleton/`) so they run inside
   Khan's CI. Both the bash and the Pest forms should pass.

---

## 6. Source

- OpenAPI: `api/seedling-v1.openapi.yaml`
- Conformance: `api/CONFORMANCE.md`
- State schema: `api/state-schema.md`, `api/seedling-v1-pb-schema.json`
- Reference impl: `internal/authsvc/`
- Khan requirements: `abc-universe/design/decided/seedling-v1-api-contract.md`
- ADR: `abc-universe/design/decided/adrs/0065-seedling-v1-as-khan-contract.md`
