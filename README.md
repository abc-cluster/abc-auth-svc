# abc-auth-svc

The Go implementation of **abc-auth-svc** — the seedling-tier workbench
**forward-auth + credential-broker** service for ABC-cluster.

It is the single gate in front of every workbench request (validates the session,
copies `Remote-User` to JupyterHub), and the broker that mints / exchanges the
per-slot credentials. It replaces the original ~2000-LOC single-file Python
service via a phased, parity-gated migration (strangler-fig).

This is a **standalone, dependency-free Go module** (mirroring `abc-node-probe`):
a single static binary, pure stdlib (`net/http` + `slog`), no third-party
dependencies. It ships beside the Python service on a separate port during the
migration.

📖 See [USAGE.md](USAGE.md) for running, flags, and the log format.

> **Status: Phase 0 (skeleton).** Stdlib HTTP server, redacting JSON access
> logging, `/healthz` + `/readyz` + `/version`, graceful shutdown. No upstreams
> (PocketBase / JupyterHub / MinIO / Nomad) are wired yet — those land in
> Phases 1–4. The migration plan lives in the abc-universe knowledge repo at
> `brainstorms/abc-workbench/2026-06-04-auth-svc-go-rewrite-plan-v2.md`.

---

## Why a separate project

`abc-auth-svc` is its own repo (not a binary inside `abc-cluster-cli`) for the
same reasons `abc-node-probe` is: it has an independent release cadence, a
service deployment lifecycle distinct from the CLI, and no need to couple to the
CLI's internal packages. It owns thin HTTP clients to its upstreams rather than
importing the CLI's. Shared code is extracted to a common module only if real
duplication emerges.

## Design tenets

- **Stdlib only.** `net/http` + Go 1.22 `ServeMux` routing; `slog` for logs. No
  web framework, no logging library, no router dependency.
- **Redaction is first-class.** As an auth service, every log record passes
  through a redacting `slog.Handler` (field-name + value-pattern). The access log
  records the request **path only** (never the query string — tokens live there)
  and never reads `Authorization` / `Cookie` headers.
- **Strangler-fig migration.** Runs on `:4182` beside the Python service on
  `:4181`; endpoints move over one phase at a time, each independently
  rollback-able by reverting a single Caddy per-path rule.

## Quick build

```bash
just build           # ./abc-auth-svc (dev)
just test            # go test ./...
just build-release   # version-stamped static binary
just ci              # fmt-check + vet + test
```

## Layout

```
abc-auth-svc/
  main.go                       — entrypoint; Version/BuildTime/GitCommit ldflags
  internal/authsvc/
    config.go                   — flags + env config
    log.go                      — redacting JSON slog logger
    redact.go                   — self-contained RedactingHandler + context logger
    middleware.go               — RequestID / AccessLog / Recoverer / VersionHeader
    health.go                   — /healthz, /readyz, /version
    server.go                   — server + middleware chain + graceful shutdown
    *_test.go
  justfile                      — build / test / release tasks
  .github/workflows/            — CI + tagged release (linux + darwin)
```
