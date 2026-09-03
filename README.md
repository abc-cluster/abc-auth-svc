# abc-auth-svc

`abc-auth-svc` is the authentication gate and credential broker for an
[ABC-cluster](https://github.com/abc-cluster) deployment.

It does two jobs:

- **Forward-auth.** It sits in front of the interactive workbench and validates
  the session on every request, passing the authenticated identity upstream to
  JupyterHub.
- **Credential broker.** It mints and exchanges the per-user credentials a
  researcher needs for the rest of the cluster — a Nomad token for submitting
  work, object-store keys for reading and writing data, and a JupyterHub token
  for the notebook.

The point of brokering them together is that one login admits a researcher to
the command-line client and to the notebook alike, rather than each surface
carrying its own credential.

It is a single static Go binary with no runtime dependencies beyond the
services it brokers for.

## Build

```bash
go build -trimpath -o abc-auth-svc .
```

Or with [`just`](https://github.com/casey/just):

```bash
just build           # development build
just build-release   # stripped, with version metadata stamped in
```

Requires Go 1.26 or newer.

## Run

```bash
# defaults: listen on 127.0.0.1:4182, JSON logs to stderr
./abc-auth-svc

# local development against stubbed upstreams — no cluster required
./abc-auth-svc -mock-upstreams -log-level debug

# print build identity and exit
./abc-auth-svc -version
```

`-mock-upstreams` is the fastest way to see the service work: it answers with
fixed credentials and needs neither Nomad, MinIO, PocketBase nor JupyterHub.

See [USAGE.md](USAGE.md) for the full flag and environment reference.

## Configuration

Non-secret settings come from flags or environment variables. **Secrets are read
from the environment only, never from flags**, so they cannot appear in a
process listing, and every secret is registered with the log redactor so it
cannot be printed.

| Setting | Environment | Notes |
|---|---|---|
| Listen address | `ABC_AUTH_LISTEN` | default `127.0.0.1:4182` |
| Log level | `ABC_AUTH_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |
| Nomad API | `NOMAD_ADDR` | cluster scheduler |
| Nomad admin token | `NOMAD_TOKEN` | **secret** |
| JupyterHub API | `JUPYTERHUB_API_URL` | notebook service |
| JupyterHub admin token | `JUPYTERHUB_API_TOKEN` | **secret** |
| PocketBase URL | `POCKETBASE_URL` | slot store |
| PocketBase admin password | `PB_ADMIN_PASSWORD` | **secret** |
| Session signing key | `SESSION_SECRET` | **secret** |

The compiled-in defaults for cluster endpoints describe one particular
deployment. Any real deployment should set them explicitly; the reference
deployment injects them from its scheduler job definition.

## API

The wire contract is published as OpenAPI 3.1 and is the source of truth for
anyone implementing or mirroring this service:

- [`api/seedling-v1.openapi.yaml`](api/seedling-v1.openapi.yaml) — the specification.
- [`api/CONFORMANCE.md`](api/CONFORMANCE.md) — the behavioural checklist and a
  Schemathesis recipe an alternative implementation must pass.
- Rendered reference: <https://abc-cluster.github.io/abc-auth-svc/>

Implemented endpoints: `/healthz`, `/readyz`, `/version`; `/validate`,
`/validate-optional` (forward-auth); `/auth/login`, `/auth/logout`, `/auth/me`;
`/auth/workbench/token`; `/auth/exchange`; `/slots/me/config`;
`/manage/slots/{slot}/cred-source`.

> The contract is versioned `seedling/v1`. That identifier is part of the wire
> format and is consumed by clients, so it is retained as-is.

## Tests

```bash
go test ./...
```

The suite runs without a cluster: upstreams are stubbed, and the session and
credential paths are covered directly.

## Security

- Secrets are environment-only and are scrubbed from all log output.
- Sessions are signed; the cookie carries no credential material.
- Brokered credentials are minted per user and are scoped to that user.

Please report security issues privately to the maintainers rather than opening
a public issue.

## Licence

Eclipse Public License 2.0 — see [LICENSE](LICENSE); copyright holders are
listed in [NOTICE](NOTICE).
