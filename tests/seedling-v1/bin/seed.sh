#!/usr/bin/env bash
# seed.sh — Seed the fixture state defined in TEST-PLAN.md §1 into the
# reference (PocketBase) state store.
#
# Khan implementations using a different store can either reimplement this
# script against their store's admin API or seed by direct DB inserts; the
# *state* it produces (slots in the documented configurations) is what the
# test suite expects, not this particular seeding mechanism.
#
# Required env:
#   PB_URL                          — PocketBase admin URL (e.g. http://127.0.0.1:8091)
#   PB_ADMIN_EMAIL                  — superuser email (default: abc-auth@abc-cluster.cloud)
#   PB_ADMIN_PASSWORD               — superuser password
#
# Also writes the following fixture creds to /tmp/seedling-v1-fixture.env
# which the runner sources to pick up the secrets:
#   OPAQUE_SOLAR_CIVET, OPAQUE_GRANITE_IGUANA
#   NOMAD_TOKEN_SOLAR_CIVET, NOMAD_TOKEN_GRANITE_IGUANA, NOMAD_TOKEN_AZURE_PANTHER
#   SLOT_PASSWORD_SOLAR_CIVET, SLOT_PASSWORD_GRANITE_IGUANA
#
# (For the Khan case these are externally provisioned; the seed script just
# prints reminders.)
#
# This is intentionally a stub — the reference deployment seeds via
# scripts/setup-pocketbase-schema.py + the operator tooling; reuse that
# instead of duplicating here.

set -uo pipefail

cat >&2 <<EOF
[seed.sh] This script is a STUB.

To seed the reference PocketBase deployment:
  python3 abc-deployments/abc-seedling-prod/scripts/setup-pocketbase-schema.py
  # …then use abc-cluster-cli or PB admin UI to mint the four fixture slots
  # documented in TEST-PLAN.md §1.

To seed Khan: implement against your state store. The required final state is
documented exhaustively in TEST-PLAN.md §1.

Required runner env (set these in your CI / wrapper script):
  BASE_URL                       (e.g. http://127.0.0.1:4182)
  OPERATOR_TOKEN                  (Khan's operator token)
  NOMAD_TOKEN_SOLAR_CIVET, …       (the bare Nomad ACL token secrets for the fixture slots)
  OPAQUE_SOLAR_CIVET, OPAQUE_GRANITE_IGUANA   (the bare opaques)
  SLOT_PASSWORD_SOLAR_CIVET, SLOT_PASSWORD_GRANITE_IGUANA  (the MinIO secret keys)

When you've seeded — run:
  bin/run.sh
EOF
exit 0
