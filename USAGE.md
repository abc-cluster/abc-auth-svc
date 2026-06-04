# abc-auth-svc — usage

## Running

```bash
# default: listen on 127.0.0.1:4182, info logs to stderr (JSON)
abc-auth-svc

# choose address + verbosity
abc-auth-svc -listen 127.0.0.1:4182 -log-level debug

# env form (Nomad injects these)
ABC_AUTH_LISTEN=127.0.0.1:4182 ABC_AUTH_LOG_LEVEL=info abc-auth-svc

# local dev with stubbed upstreams (Phase 1+)
abc-auth-svc -mock-upstreams

# print build identity
abc-auth-svc -version
```

## Flags / environment

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-listen` | `ABC_AUTH_LISTEN` | `127.0.0.1:4182` | listen address (host:port) |
| `-log-level` | `ABC_AUTH_LOG_LEVEL` | `info` | `info` \| `debug` \| `trace` |
| `-mock-upstreams` | `ABC_AUTH_MOCK_UPSTREAMS` | `false` | stub PB/JH/MinIO/Nomad (local dev) |
| `-version` | — | — | print version and exit |

Precedence: flags > env > defaults. **Secrets are never passed as flags** — they
come from env only (injected by Nomad Variables) and are scrubbed from logs.

## Endpoints (Phase 0)

| Method | Path | Response |
|---|---|---|
| GET | `/healthz` | `200 ok` (liveness) |
| GET | `/readyz` | `200 {"status":"ready","version":…,"checks":{}}` |
| GET | `/version` | `200 {"version":…,"build_time":…,"git_commit":…}` |
| *any* | other | `404 {"error":"not found"}` |

Every response carries `X-Abc-Auth-API-Version: v1` and `X-Request-Id`.

## Log format

Structured JSON to stderr (Loki scrapes it). One `http.access` record per
request:

```json
{"time":"2026-06-04T08:54:43Z","level":"INFO","msg":"http.access",
 "rid":"7b567ce00c3c07b485552dc0","method":"GET","path":"/healthz",
 "status":200,"bytes":3,"ms":0,"user":"","xff":""}
```

**Safety guarantees** (enforced, with tests):
- `path` is logged **without the query string** — a `?token=…` never reaches the log.
- `Authorization` / `Cookie` headers are never logged.
- Every record passes through the redacting handler (Bearer tokens, tailscale
  keys, PEM blocks, `scheme://user:pass@…` are scrubbed wherever they appear).

Set `-log-level debug` to also see HTTP-layer detail once upstreams are wired
(Phase 1+).

## Deployment (migration)

Runs on `:4182` beside the Python `abc-auth-svc` on `:4181`. Caddy routes
specific paths to the Go service as each phase lands; everything else stays on
Python. Roll back any phase by reverting one Caddy per-path rule. The Nomad job
spec lives in `abc-deployments` (versioned source of truth — no more `scp` drift).
