# abc-auth-svc — legacy Python implementation

> ⚠️ **Retired 2026-06-09.** This branch (`legacy/python`) is an archival snapshot of
> the original ~2500-LOC stdlib Python forward-auth + credential-broker service that
> ran on aither's port `:4181` from late 2025 until the Go rewrite reached parity
> and took over 100% of the auth-svc data path.
>
> **For the current implementation, switch to `master`** (Go, single static binary,
> Phases 0–4 complete, port `:4182`). The OpenAPI 3.1 contract (`seedling/v1`),
> conformance checklist, and Redoc docs are also on `master` under `api/` and `docs/`.

---

## Why this branch exists

The Python service was the original abc-auth-svc — single-file, stdlib `http.server`,
no third-party dependencies. The Go rewrite supersedes it via a strangler-fig
migration plan (`abc-universe/brainstorms/abc-workbench/2026-06-04-auth-svc-go-rewrite-plan-v2.md`).

We preserve the Python source here, on its own branch and tagged
`python-final-2026-06-09`, so that:

- Cutover rollbacks within the safety window can grab a known-good Python source
  without reaching into the `abc-deployments` repo's `retired-python/` folder.
- Future readers tracing the design genealogy can read the implementation that
  defined the wire contract before it became `seedling/v1`.
- The Go implementation's tests reference Python behaviour ("HMAC `abc_session`
  cross-compatible with the Python") — having the Python source one branch away
  helps validate parity claims if doubt arises.

This branch is **not** intended for further development. It receives no commits
beyond this snapshot.

---

## Layout

| File | Was |
|---|---|
| `abc-auth-svc.py` | the ~2500-line stdlib HTTP service (forward-auth, mint, exchange, claim, secrets, manage/*) |
| `abc-auth-svc.nomad.hcl` | the `:4181` Nomad job spec (`abc-auth-svc`, raw_exec) |
| `install-auth-svc.sh` | the venv installer + repo↔live drift gate |
| `shadow-compare.sh` | the Phase-2 `/validate-shadow` parity harness (only meaningful while Python ran as the shadow target on `:4181`) |

---

## Live state at retirement (2026-06-09)

- Nomad job `abc-auth-svc` (ns `abc-reserved`, node aither, `:4181`):
  **stopped, not purged** (`nomad job stop abc-auth-svc`, deployment `f35f5c78`).
  The job def + the host binary/venv at `/opt/abc-auth-svc/` remain on aither for
  the rollback window.
- The Go job `abc-auth-svc-go` (`:4182`) carries all traffic. Caddy
  (`caddy-workbench.caddyfile`, all three virtual hosts) routes `/validate`,
  `/validate-optional`, `/auth/*`, `/slots/*`, `/manage/slots/*`, and `/verify*`
  exclusively to `:4182`.
- See `abc-universe/STATE.md` and
  `abc-universe/brainstorms/abc-workbench/2026-06-09-workbench-connect-and-spawn-failures.md`
  for the cutover history.

---

## Rollback (if a Go regression surfaces within the window)

1. Re-point Caddy: in `abc-deployments/abc-seedling-prod/auth/caddy-workbench.caddyfile`,
   flip the `:4182` upstreams back to `:4181` (or restore the pre-cutover
   Caddyfile from git history), adapt + reload `abc-workbench-caddy`.
2. Restart the Python job:
   ```
   git checkout python-final-2026-06-09 -- abc-auth-svc.nomad.hcl abc-auth-svc.py install-auth-svc.sh
   # then on aither, with the standard NOMAD_NAMESPACE/MGMT token:
   NOMAD_NAMESPACE=abc-reserved nomad job run abc-auth-svc.nomad.hcl
   ```
   The host `.py` + venv may still be at `/opt/abc-auth-svc/` from the original
   deploy.

---

## Source

- Tag: `python-final-2026-06-09`
- Imported from: `abc-deployments/abc-seedling-prod/auth/retired-python/` at the
  retirement-commit state.
- Successor: `master` (Go rewrite).
- Contract: `master:api/seedling-v1.openapi.yaml` (defines the wire contract this
  Python implementation originally shipped, now formalised).
