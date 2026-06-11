#!/usr/bin/env bash
# run.sh — seedling/v1 conformance test runner.
#
# Usage:
#   bin/run.sh                   # run every case
#   bin/run.sh auth-04 sec-01    # run only the named cases
#   bin/run.sh --tag exchange    # run all cases in tests/seedling-v1/exchange.sh
#
# Exit status:
#   0 — all (selected) cases passed
#   1 — at least one case failed
#   2 — bad env / pre-flight failure (BASE_URL unreachable, jq missing, etc.)
#
# See TEST-PLAN.md for the case list and the fixture contract.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$ROOT_DIR/bin/lib.sh"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: $tool is required on PATH" >&2
    exit 2
  fi
done

: "${BASE_URL:?Set BASE_URL — e.g. http://127.0.0.1:4182}"

# Pre-flight: implementation reachable + v1 stamp present.
echo "==> Pre-flight: $BASE_URL/healthz"
if ! curl -sf --max-time 5 -o /dev/null "$BASE_URL/healthz"; then
  echo "ERROR: $BASE_URL/healthz did not respond 200" >&2
  exit 2
fi
api_version="$(curl -sI --max-time 5 "$BASE_URL/healthz" | awk 'tolower($1)=="x-abc-auth-api-version:" { sub(/$/,""); print $2; exit }')"
if [ "$api_version" != "v1" ]; then
  echo "ERROR: server reports X-Abc-Auth-API-Version: $api_version; this suite is for v1" >&2
  exit 2
fi
echo "    OK (X-Abc-Auth-API-Version: v1)"

# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

SUITE_ONLY=""
TAG_FILTER=""

while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG_FILTER="$2"; shift 2 ;;
    --help|-h) sed -n '1,18p' "$0"; exit 0 ;;
    *) SUITE_ONLY="$SUITE_ONLY $1"; shift ;;
  esac
done
SUITE_ONLY="${SUITE_ONLY# }"
export SUITE_ONLY

SUITE_PASS=0; SUITE_FAIL=0; SUITE_SKIP=0
export SUITE_PASS SUITE_FAIL SUITE_SKIP

# ---------------------------------------------------------------------------
# Run each tag's file
# ---------------------------------------------------------------------------

TAGS=(health validate auth workbench exchange slots manage cli-tokens minio verify secrets log-level misc)

for tag in "${TAGS[@]}"; do
  if [ -n "$TAG_FILTER" ] && [ "$tag" != "$TAG_FILTER" ]; then
    continue
  fi
  file="$ROOT_DIR/$tag.sh"
  if [ ! -f "$file" ]; then
    echo "${CYELL:-}WARN${CRST:-} tag '$tag' has no file at $file — skipping" >&2
    continue
  fi
  echo
  echo "==> $tag"
  # Source so SUITE_* counters and CURRENT_CASE_* state are shared.
  # shellcheck source=/dev/null
  source "$LIB"
  # shellcheck source=/dev/null
  source "$file"
  _finalise_open_case
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
total=$((SUITE_PASS + SUITE_FAIL + SUITE_SKIP))
printf "==> Summary: %d total · %d pass · %d fail · %d skip\n" \
  "$total" "$SUITE_PASS" "$SUITE_FAIL" "$SUITE_SKIP"

if [ "$SUITE_FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
