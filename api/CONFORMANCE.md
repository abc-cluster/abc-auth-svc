# seedling/v1 — Conformance checklist

A Khan (or any third-party) implementation of the `seedling/v1` API contract is **conformant** when:

1. Every behavioural check in §1 passes.
2. The Schemathesis run in §2 passes against a Khan instance pointed at the same OpenAPI spec.
3. The contract-version handshake in §3 matches.

The reference implementation is `abc-auth-svc` (this repo). Where this document and the OpenAPI spec
disagree, the OpenAPI spec wins.

Status legend in §1: **MUST** = blocking, **SHOULD** = expected by callers in the wild, **MAY** = optional.

---

## 1. Behavioural contracts

### 1.1 Cross-cutting

| ID | Requirement | Status |
|---|---|---|
| C-01 | Every response (success or error) MUST set `X-Abc-Auth-API-Version: v1`. | MUST |
| C-02 | Every response MUST set `X-Request-Id`. If the inbound request supplied a sanitisable `X-Request-Id` (`^[A-Za-z0-9_-]{1,64}$`), it MUST be echoed; otherwise a fresh value MUST be minted. | MUST |
| C-03 | Error responses on JSON endpoints MUST use the `{ "error": "<snake_case_tag>" }` envelope and `Content-Type: application/json`. Endpoints documented with extended error bodies (e.g. `invalid_cred_source`) MUST include the documented extra fields. | MUST |
| C-04 | Path aliases (`/auth/foo` for `/foo`) listed in `x-aliases` for an operation MUST serve the same handler with the same auth, body and response semantics. | MUST |
| C-05 | Implementations MUST tolerate unknown JSON fields on inbound requests (forward-compatibility). | MUST |
| C-06 | Implementations MUST NOT log the request query string, the `Authorization` or `Cookie` request headers, the bare opaque token, the MinIO secret key, or the Nomad token secret. | MUST |
| C-07 | Recoverer for panics MUST return `500 { "error": "internal error" }`. | MUST |
| C-08 | Unrouted paths MUST return `404 { "error": "not found" }`. | MUST |
| C-09 | The TLS / cookie `Secure` flag MUST default to `true` and only be disabled by explicit operator configuration. | MUST |
| C-10 | Responses MAY add fields beyond those documented; clients ignore extras. (This is the implementer's escape hatch — but additions are NOT contract changes.) | MAY |

### 1.2 Session cookie (`abc_session`)

| ID | Requirement | Status |
|---|---|---|
| S-01 | Value MUST be `base64url(<username>:<expiry_unix>:<hex_hmac_sha256>)`. The base64 variant SHOULD be URL-safe and MAY be padded or unpadded. Both forms MUST verify. | MUST |
| S-02 | The HMAC MUST be SHA-256 over `<username>:<expiry_unix>` using the implementation's `SESSION_SECRET`. | MUST |
| S-03 | Cookie attributes set on issue: `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` (per config), `Max-Age=<SESSION_TTL_SECONDS>`. `Domain` MUST be set when configured. | MUST |
| S-04 | Logout MUST set `abc_session=` with `Max-Age=-1` to expire the cookie. | MUST |
| S-05 | Across reference and mirror implementations operating in the same migration cohort: a cookie issued by either implementation MUST validate on either, provided `SESSION_SECRET` is shared. | SHOULD |

### 1.3 `/validate` family

| ID | Requirement | Status |
|---|---|---|
| V-01 | `GET /validate` MUST return 200 with a body of zero bytes and headers `X-Auth-User`, `Remote-User`, `X-WEBAUTH-USER` (all equal) when a valid non-blocked session is present. | MUST |
| V-02 | `GET /validate` MUST return 302 with `Location: /auth/login?next=<urlencoded X-Forwarded-Uri or '/'>` on any deny path. Body MUST be zero bytes. | MUST |
| V-03 | When a session cookie verifies but the slot is suspended or expired, `GET /validate` MUST clear `abc_session` via a `Set-Cookie` header alongside the 302. | MUST |
| V-04 | `GET /validate-optional` MUST return 200 in all cases. Identity headers are present only when authenticated. | MUST |
| V-05 | `GET /validate-shadow` is implementation-internal. Khan MAY omit it. If present, behaviour is the reference's parity-harness behaviour. | MAY |

### 1.4 Auth / session

| ID | Requirement | Status |
|---|---|---|
| A-01 | `GET /auth/login` MUST return 200 + `text/html` + `Cache-Control: no-store` regardless of query state. | MUST |
| A-02 | `POST /auth/login` failure MUST re-render the form with 200 (not 401 / 400) and an inline error string. This is the documented browser-flow contract; JSON 4xx is **wrong** here. | MUST |
| A-03 | `POST /auth/login` success MUST be 302 + `Set-Cookie: abc_session=…` + `Location` set to the sanitised `next` (default `/`). | MUST |
| A-04 | `next` sanitisation: only same-origin absolute paths survive. `//host/foo`, `https://other/`, `javascript:` and similar MUST be rejected and replaced with `/`. | MUST |
| A-05 | `GET /auth/logout` MUST always 302 to `/auth/login` and clear the cookie. | MUST |
| A-06 | `GET /auth/me` MUST set `Access-Control-Allow-Origin: *` on success (CLI consumption). | MUST |
| A-07 | `/auth/me` `primary_group` and `namespace` MUST equal each other on seedling-tier; on garden-tier they MAY diverge but Khan MUST document the mapping. | SHOULD |

### 1.5 `/workbench/token`

| ID | Requirement | Status |
|---|---|---|
| W-01 | Pool-token mapping MUST be: Nomad token `Name == "pool-<x>"` → JH user `<x>`; `Name == "<x>"` (no prefix) → JH user `<x>`. | MUST |
| W-02 | `expires_in` MUST default to 604800 (7 d) and be capped at 2592000 (30 d). Values outside [1, 2592000] MUST be rejected with 400. | MUST |
| W-03 | Body limit MUST be 64 KiB. Requests over this MUST be rejected with 400 (`request_too_large` or `invalid JSON body`). | MUST |
| W-04 | Slot suspended / expired MUST be 403 with the documented error tags (`slot is suspended` / `slot is expired`) — NOT 401. | MUST |
| W-05 | JH 403/404 MUST surface as 502 with `hint` + `diag` fields; transport-level failure MUST surface as 503 `hub unreachable`. | MUST |

### 1.6 `/exchange`

| ID | Requirement | Status |
|---|---|---|
| X-01 | Field names in the returned bundle (`whoami`, `source`, `nomad.{addr, token, namespace, datacenters, head_pool, worker_pool}`, `minio.{endpoint, access_key, secret_key}`) MUST match exactly — `abc-cluster-cli`'s `SeedlingV1CredSource` is wire-locked against them. | MUST |
| X-02 | Unknown opaque, malformed-opaque, and slot-in-wrong-state errors MUST all return the same `invalid_or_inactive_token` 401 — no enumeration. | MUST |
| X-03 | A slot whose `cred_source != seedling/v1` MUST return 409 `slot_not_on_seedling_v1` (NOT 401, NOT 403). | MUST |
| X-04 | The endpoint MUST NOT log the bundle. Only the slot name MAY appear in audit logs. | MUST |

### 1.7 Slots — user-facing

| ID | Requirement | Status |
|---|---|---|
| U-01 | `GET /slots/me/config` MUST return `text/yaml` with `Content-Disposition: attachment; filename="abc-config-<slot>.yaml"` and `Cache-Control: no-store`. | MUST |
| U-02 | First retrieval of `config.yaml` SHOULD persist the rendered text to the store along with `config_yaml_at` and `config_yaml_renderer`. | SHOULD |
| U-03 | `POST /slots/claim` MUST be anonymous (no auth header); the `claim_code` is the proof. | MUST |
| U-04 | The bare opaque token MUST appear ONLY embedded in the returned config.yaml when `cred_source = seedling/v1`. It MUST NOT appear elsewhere in the response, in headers, in logs, or in any later call. | MUST |
| U-05 | Bad code and already-used code MUST both return `404 code_invalid_or_used` (no enumeration). | MUST |
| U-06 | Concurrent claims on the same code MUST be serialised; only one client receives the YAML, the rest receive `code_invalid_or_used`. | MUST |

### 1.8 Slots — operator

| ID | Requirement | Status |
|---|---|---|
| O-01 | Every `/manage/*` operation MUST require `X-Operator-Token` and constant-time compare. | MUST |
| O-02 | When the implementation has no configured operator token, every `/manage/*` request MUST be rejected with 401 `unauthorized`. | MUST |
| O-03 | The list endpoint MUST return a JSON array, secret-stripped (no `minio_secret_key`, no `nomad_token_secret`). | MUST |
| O-04 | `POST /manage/slots/{slot}/cred-source` on a `local → seedling/v1` transition MUST return the freshly-minted bare opaque token in the response body **exactly once**. Subsequent reads of the slot MUST NOT expose it. | MUST |
| O-05 | `suspend`, `reactivate`, `rotate` MUST update PocketBase state atomically with respect to themselves (no half-applied state visible after a 5xx). Upstream side-effects (MinIO disable, Nomad token revoke, JH stop-server) are best-effort. | MUST |
| O-06 | `rotate` MUST issue a new MinIO secret and a new Nomad token, persist both to PB, and SHOULD revoke the old Nomad token by accessor (best-effort). | MUST |
| O-07 | `GET /manage/slots/{slot}/diag` MUST return 200 even when the slot is missing (`verdict: "blocked_at: pb_row_present"`). It is a diagnostic; failure is in the body, not the status. The body MUST be pretty-printed JSON (2-space indent). | MUST |

### 1.9 CLI tokens

| ID | Requirement | Status |
|---|---|---|
| T-01 | `code` MUST be 64 hex chars, single-use, with TTL `CLI_TOKEN_TTL` (default 60 s). | MUST |
| T-02 | Codes MUST be stored such that lookup is constant-time relative to the population (avoid leaking existence via timing). | SHOULD |
| T-03 | `/redeem` on an invalid or expired code MUST 302 to `/auth/login?error=link_expired` (NOT JSON 401). The browser flow needs the redirect. | MUST |
| T-04 | `/redeem` MUST consume the code; replay MUST return `link_expired`. | MUST |
| T-05 | `/redeem` with `portal == "grafana"` or `Host` containing `grafana.` MUST redirect to `/login` on the destination origin. Cross-subdomain trust MUST be limited to `*.abc-cluster.cloud` (or the per-deployment configured suffix). | MUST |

### 1.10 MinIO SSO

| ID | Requirement | Status |
|---|---|---|
| M-01 | The cookie name set by `/minio-login` MUST be `token` (NOT `abc_session`). It is scoped to the MinIO console origin. | MUST |
| M-02 | `Max-Age` MUST be 43200 (12 h) by default. | MUST |
| M-03 | All failure paths MUST be 302 (never JSON 4xx). MinIO console operators expect to land on a login form. | MUST |

### 1.11 `/verify` family

| ID | Requirement | Status |
|---|---|---|
| Y-01 | All four routes (`GET|POST /verify`, `GET|POST /verify-namespace`) MUST be identical in behaviour. | MUST |
| Y-02 | Success body MUST be `"ok\n"` `text/plain`. Failure body MUST be `"unauthorized: missing or invalid token\n"`. Plain-text bodies are part of the contract (Traefik forward-auth treats them opaquely). | MUST |
| Y-03 | Response headers on success MUST include `X-Auth-User`, `X-Auth-Group`, `X-Auth-Namespace`, `X-Auth-Policies` (comma-separated), `X-Auth-Type` (`client` or `management`). Management tokens MUST map to `group=admin`, `namespace=*`, `policies=management`, `type=management`. | MUST |

### 1.12 Secrets broker

| ID | Requirement | Status |
|---|---|---|
| K-01 | `value` accepted by `secrets/put` MAY be any JSON. The server-side stringification MUST be: string → verbatim; `null` → `""`; other → JSON-encode. | MUST |
| K-02 | `secrets/get` MUST always return `{ "value": "<string>" }`. Type information is intentionally not preserved. | MUST |
| K-03 | `secrets/get` on a non-existent key MUST return 404 `not_found` (not 200 with empty value, not 500). | MUST |
| K-04 | The `group` override field on `secrets/put` MUST resolve to namespace `su-<group>` or `default` for empty string. `secrets/get` has no group override; it always uses the slot's primary group. | MUST |

### 1.13 Log level

| ID | Requirement | Status |
|---|---|---|
| L-01 | `level` value space on the wire MUST include `info`, `debug`, `trace`. Numeric aliases (`1`, `2`, `3`, `l1`, `l2`, `l3`) MAY be accepted. | MUST |
| L-02 | Setting an unknown level MUST return `400 { "error": "invalid_level", "allowed": ["info","debug","trace"] }`. | MUST |
| L-03 | When the implementation has no mutable level (test mode), `POST /manage/log-level` MUST return 409 `level_not_mutable`. | MUST |

### 1.14 Versioning policy

| ID | Requirement | Status |
|---|---|---|
| P-01 | A wire-breaking change (removed/renamed field, changed status code, changed redirect target) MUST be introduced under a new path prefix or a new top-level version (`seedling/v2`) — never inside `v1`. | MUST |
| P-02 | Adding a new endpoint or a new optional field is NOT a breaking change. | MUST |
| P-03 | When the implementation is past initial draft, `info.version` of the OpenAPI spec MUST track semver: minor bumps for additive changes, patch bumps for clarifications, major bumps for v2. | SHOULD |
| P-04 | A deprecation MUST be flagged via OpenAPI `deprecated: true` on the operation for at least one minor cycle before removal. | SHOULD |

---

## 2. Schemathesis recipe

[Schemathesis](https://schemathesis.readthedocs.io/) generates property-based tests directly from the
OpenAPI spec. It catches: status-code drift, response-shape drift, schema-violating request rejection,
and many auth-related contract bugs.

### 2.1 Install

```bash
pipx install schemathesis
# or: pip install --user schemathesis
```

### 2.2 Smoke run against a local Khan / abc-auth-svc

```bash
# Implementation must be reachable on http://127.0.0.1:4182
# (or substitute the actual base URL).

schemathesis run \
  --url http://127.0.0.1:4182 \
  --checks all \
  --hypothesis-deadline=2000 \
  --hypothesis-max-examples=50 \
  --exclude-tag forward-auth \
  --exclude-tag minio-sso \
  --exclude-tag cli-tokens \
  api/seedling-v1.openapi.yaml
```

Notes:

- `--checks all` enables `status_code_conformance`, `not_a_server_error`, `response_schema_conformance`,
  `content_type_conformance`, `response_headers_conformance`.
- The exclusions cover endpoints whose contract is "302 + cookie", which Schemathesis cannot generate
  meaningful inputs for; cover those with the targeted tests in §2.4 instead.

### 2.3 Authenticated run

For endpoints requiring `nomadBearer`, `opaqueBearer`, or `operatorToken`, supply tokens via
`--header`:

```bash
# Operator endpoints
schemathesis run \
  --url http://127.0.0.1:4182 \
  --header "X-Operator-Token: $OPERATOR_TOKEN" \
  --tag slots-operator --tag log-level \
  --checks all \
  api/seedling-v1.openapi.yaml

# Nomad-bearer endpoints
schemathesis run \
  --url http://127.0.0.1:4182 \
  --header "Authorization: Bearer $NOMAD_TOKEN" \
  --tag auth --tag workbench --tag verify \
  --checks all --exclude-tag auth \
  api/seedling-v1.openapi.yaml

# Opaque-bearer endpoints
schemathesis run \
  --url http://127.0.0.1:4182 \
  --header "Authorization: Bearer $ABC_OPAQUE" \
  --tag exchange --tag secrets \
  --checks all \
  api/seedling-v1.openapi.yaml
```

### 2.4 Manual targeted tests

These cover behaviour Schemathesis alone cannot assert. Run them as a smoke pass; a fuller set lives
in the `abc-auth-svc` test suite for reference.

```bash
BASE=http://127.0.0.1:4182

# C-01 / C-02: API-version + request-id stamping on every response
curl -sI "$BASE/healthz" | grep -E 'X-Abc-Auth-API-Version: v1|X-Request-Id:' | wc -l   # → 2

# V-02: deny path is a 302
curl -sI "$BASE/validate" | head -2                                                     # → HTTP/1.1 302 …

# A-03: login success sets cookie + 302
curl -si -d "username=$U&password=$P" "$BASE/auth/login"                                # 302 + Set-Cookie

# A-04: next sanitisation rejects scheme-relative
curl -si "$BASE/auth/login?next=//evil.example/foo" | grep -E 'Location: //evil'        # → no match

# T-04: redeem is single-use
CODE=$(curl -s -d "{\"nomad_token\":\"$NOMAD_TOKEN\"}" "$BASE/cli-token" | jq -r .code)
curl -sI "$BASE/redeem?code=$CODE" | head -2                                            # → 302 with cookie
curl -sI "$BASE/redeem?code=$CODE" | grep -E 'error=link_expired'                       # → match

# X-02: opaque error normalisation
curl -sH "Authorization: Bearer abco_bogus" "$BASE/exchange" | jq .error               # → invalid_or_inactive_token

# Y-02: verify success body is exact plaintext
curl -s -H "Authorization: Bearer $NOMAD_TOKEN" "$BASE/verify" | xxd | head             # → "ok\n"
```

### 2.5 CI snippet

A minimal GitHub Actions step:

```yaml
- name: Schemathesis conformance
  run: |
    pipx install schemathesis
    schemathesis run \
      --url "$KHAN_TEST_URL" \
      --header "X-Operator-Token: ${{ secrets.OPERATOR_TOKEN }}" \
      --checks all \
      --hypothesis-max-examples=25 \
      api/seedling-v1.openapi.yaml
```

---

## 3. Contract-version handshake

A client SHOULD probe `GET /version` and `GET /readyz` once on startup. The implementation MUST
report:

- `X-Abc-Auth-API-Version: v1` on every response (including `/version` itself).
- `/version` body shape per the OpenAPI spec (build-string fields MAY be empty).
- `/readyz` 200 + `{ "status": "ready", "version": "<build>" }` (the body's `checks` map is free-form;
  clients MUST NOT depend on its shape).

A client that receives `X-Abc-Auth-API-Version` of a different major (e.g. `v2`) SHOULD refuse to
proceed and surface a clear error.

---

## 4. Khan-specific notes (deltas to call out)

The following items are NOT in the spec because they are deployment-context choices, but Khan should
think them through:

1. **`SESSION_SECRET` provenance.** abc-auth-svc and Khan operate at different tiers. If a slot
   migrates tiers in a single session, sharing `SESSION_SECRET` is the cleanest cookie portability
   answer. If not shared, the user re-logs at the tier boundary — acceptable but documented.
2. **`/auth/me` group expansion.** abc-auth-svc's seedling tier returns `groups=[primary_group]`.
   Khan's garden tier with role-based identity MAY expand `groups` to include role-derived memberships;
   `role_based: true` already signals this.
3. **`/manage/slots/{slot}/diag` host probes.** The `host.*` block is meaningful on a single-host
   seedling installation. On Khan's multi-host deployment, host probes will not apply directly.
   Khan SHOULD return the `host` block with all-`exists:false` plus a `host.unsupported: true` flag,
   so a single CLI diag tool produces output for both tiers.
4. **`pretty-printed` JSON on `/diag`.** Yes, even with the indent. Operators read this in a terminal.
5. **`/slots/claim` claim-code source.** abc-auth-svc derives codes from PocketBase pending invites.
   Khan's source will be different (Keycloak invite, garden-tier console). The wire shape is unchanged.
6. **Per-deployment trusted redirect suffix.** `*.abc-cluster.cloud` is the abc-auth-svc default; Khan
   SHOULD make this configurable. The CONTRACT property is that off-suffix `next_url` values are sanitised.

---

## 5. What's intentionally out of scope

- Caddy / ingress configuration. The contract is service-internal.
- The PocketBase schema. Two implementations of the same contract can have entirely different stores.
- Audit-log line formats. Required content (no secrets, request-id present) is in §1, but the line
  layout is implementation-internal.
- The MinIO admin client used for credential rotation. Khan may use `mc`, `madmin-go`, or a direct
  S3-API call — the only contract-visible result is that `POST /manage/slots/{slot}/rotate` returns
  200 and the next `GET /exchange` returns the new credentials.

---

*Last updated: 2026-06-10 alongside `seedling-v1.openapi.yaml` v1.0.0-draft.*
