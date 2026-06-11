# shellcheck shell=bash
# lib.sh — primitives shared by all seedling/v1 test files.
#
# Source this from each test file. Exposes:
#
#   it <id> "<title>"     — start a case; later assertions are scoped to it.
#   expect_status <n>       — assert last response status == n.
#   expect_header <name> <value-regex>
#   expect_header_absent <name>
#   expect_json <jq-filter> <expected>   — jq-filter result == expected
#   expect_body_contains <substring>
#   expect_body_matches <regex>
#   expect_body_exact <bytes>
#   pass / fail "<reason>"  — record case result (or auto-pass on the next case).
#
# Helpers:
#
#   GET / POST / etc. — wrappers around curl that record status, headers, body
#                       into RESP_STATUS / RESP_HEADERS / RESP_BODY globals.
#   header <name>     — extract a response header.
#   body              — print last response body.
#   reset_resp        — clear the response state.
#
# Required env (the runner exports these):
#   BASE_URL                       — implementation under test (e.g. http://127.0.0.1:4182)
#   OPERATOR_TOKEN                 — operator token for /manage/*
#   NOMAD_TOKEN_SOLAR_CIVET         (fixture)
#   NOMAD_TOKEN_GRANITE_IGUANA      (fixture)
#   NOMAD_TOKEN_AZURE_PANTHER       (fixture)
#   OPAQUE_SOLAR_CIVET              (fixture, bare opaque)
#   OPAQUE_GRANITE_IGUANA           (fixture)
#   SLOT_PASSWORD_SOLAR_CIVET       (fixture, MinIO secret for /auth/login)

set -uo pipefail

: "${BASE_URL:?BASE_URL is required}"

# colour
if [ -t 1 ]; then
  CGREEN=$'\033[32m'; CRED=$'\033[31m'; CYELL=$'\033[33m'; CDIM=$'\033[2m'; CRST=$'\033[0m'
else
  CGREEN=""; CRED=""; CYELL=""; CDIM=""; CRST=""
fi

# Result counters (initialised by run.sh; safe defaults here).
: "${SUITE_PASS:=0}"
: "${SUITE_FAIL:=0}"
: "${SUITE_SKIP:=0}"
: "${SUITE_LOG:=/dev/stderr}"
: "${SUITE_ONLY:=}"        # space-separated case IDs to include; empty = all

CURRENT_CASE_ID=""
CURRENT_CASE_TITLE=""
CURRENT_CASE_FAILED=0
CURRENT_CASE_REPORTED=0

# RESP_* are written by GET/POST/etc.
RESP_STATUS=""
RESP_HEADERS=""
RESP_BODY=""

reset_resp() {
  RESP_STATUS=""
  RESP_HEADERS=""
  RESP_BODY=""
}

_record_pass() {
  [ "$CURRENT_CASE_REPORTED" -eq 1 ] && return 0
  CURRENT_CASE_REPORTED=1
  SUITE_PASS=$((SUITE_PASS + 1))
  printf "%sPASS%s  %-14s  %s\n" "$CGREEN" "$CRST" "$CURRENT_CASE_ID" "$CURRENT_CASE_TITLE"
}

_record_fail() {
  local reason="$1"
  [ "$CURRENT_CASE_REPORTED" -eq 1 ] && return 0
  CURRENT_CASE_REPORTED=1
  CURRENT_CASE_FAILED=1
  SUITE_FAIL=$((SUITE_FAIL + 1))
  printf "%sFAIL%s  %-14s  %s\n" "$CRED" "$CRST" "$CURRENT_CASE_ID" "$CURRENT_CASE_TITLE"
  printf "      reason: %s\n" "$reason"
  printf "      last response status: %s\n" "${RESP_STATUS:-<none>}"
  if [ -n "$RESP_BODY" ]; then
    printf "      body (first 4 lines):\n"
    printf "%s\n" "$RESP_BODY" | head -4 | sed 's/^/        /'
  fi
}

# it <id> "<title>"
it() {
  # If a prior case opened but never asserted, count it as pass (case bodies
  # without assertions are not how we should write tests, but be lenient).
  if [ -n "$CURRENT_CASE_ID" ] && [ "$CURRENT_CASE_REPORTED" -eq 0 ]; then
    _record_pass
  fi
  CURRENT_CASE_ID="$1"
  CURRENT_CASE_TITLE="$2"
  CURRENT_CASE_FAILED=0
  CURRENT_CASE_REPORTED=0

  # Filter: skip if SUITE_ONLY is set and this case isn't in it.
  if [ -n "$SUITE_ONLY" ]; then
    local found=0
    for cid in $SUITE_ONLY; do
      if [ "$cid" = "$CURRENT_CASE_ID" ]; then found=1; break; fi
    done
    if [ "$found" -eq 0 ]; then
      SUITE_SKIP=$((SUITE_SKIP + 1))
      CURRENT_CASE_REPORTED=1
      CURRENT_CASE_FAILED=1   # treat as a "do not run further assertions"
      printf "%sskip%s  %-14s  %s\n" "$CDIM" "$CRST" "$CURRENT_CASE_ID" "$CURRENT_CASE_TITLE" >&2
      return 0
    fi
  fi
  reset_resp
}

pass()  { _record_pass; }
fail()  { _record_fail "${1:-unspecified}"; }

_assertion_guard() {
  # Skip assertions if the case has been pre-failed (skip filter).
  [ "$CURRENT_CASE_FAILED" -eq 1 ] && [ "$CURRENT_CASE_REPORTED" -eq 1 ] && return 1
  return 0
}

# ----------------------------------------------------------------------------
# HTTP helpers
# ----------------------------------------------------------------------------

# _curl <method> <path> [extra curl args...]
# Writes status/headers/body to RESP_*. Returns 0 always (the test asserts).
_curl() {
  local method="$1"; shift
  local path="$1"; shift
  local tmp_hdr tmp_body status
  tmp_hdr=$(mktemp); tmp_body=$(mktemp)
  status=$(curl -sS -o "$tmp_body" -D "$tmp_hdr" -w "%{http_code}" \
                -X "$method" \
                --max-time 10 \
                "$@" \
                "$BASE_URL$path")
  RESP_STATUS="$status"
  RESP_HEADERS="$(cat "$tmp_hdr")"
  RESP_BODY="$(cat "$tmp_body")"
  rm -f "$tmp_hdr" "$tmp_body"
}

GET()    { _assertion_guard || return 0; _curl GET    "$1" "${@:2}"; }
POST()   { _assertion_guard || return 0; _curl POST   "$1" "${@:2}"; }
PUT()    { _assertion_guard || return 0; _curl PUT    "$1" "${@:2}"; }
DELETE() { _assertion_guard || return 0; _curl DELETE "$1" "${@:2}"; }
PATCH()  { _assertion_guard || return 0; _curl PATCH  "$1" "${@:2}"; }

header() {
  local name="$1"
  # BSD awk (macOS) has no IGNORECASE — explicit tolower() on both sides.
  printf "%s\n" "$RESP_HEADERS" | awk -v n="$name" '
    BEGIN { nlow = tolower(n) ":" }
    tolower($1) == nlow { sub(/^[^:]+:[ \t]*/, ""); sub(/\r$/, ""); print; exit }
  '
}

body() { printf "%s" "$RESP_BODY"; }

# ----------------------------------------------------------------------------
# Assertions
# ----------------------------------------------------------------------------

expect_status() {
  _assertion_guard || return 0
  local want="$1"
  if [ "$RESP_STATUS" = "$want" ]; then
    _record_pass
  else
    _record_fail "expected status $want; got $RESP_STATUS"
  fi
}

expect_header() {
  _assertion_guard || return 0
  local name="$1"; local re="$2"
  local v
  v="$(header "$name")"
  if [ -z "$v" ]; then
    _record_fail "header $name missing"
    return 0
  fi
  if printf "%s" "$v" | grep -Eq -- "$re"; then
    _record_pass
  else
    _record_fail "header $name = '$v'; did not match /$re/"
  fi
}

expect_header_absent() {
  _assertion_guard || return 0
  local name="$1"
  local v
  v="$(header "$name")"
  if [ -z "$v" ]; then
    _record_pass
  else
    _record_fail "header $name present ('$v') but should be absent"
  fi
}

# expect_json <jq filter> <expected literal>
expect_json() {
  _assertion_guard || return 0
  local filter="$1"; local want="$2"
  local got
  got="$(printf "%s" "$RESP_BODY" | jq -r "$filter" 2>/dev/null)"
  if [ "$got" = "$want" ]; then
    _record_pass
  else
    _record_fail "jq '$filter' = '$got'; want '$want'"
  fi
}

expect_body_contains() {
  _assertion_guard || return 0
  local needle="$1"
  if printf "%s" "$RESP_BODY" | grep -F -q -- "$needle"; then
    _record_pass
  else
    _record_fail "body did not contain '$needle'"
  fi
}

expect_body_matches() {
  _assertion_guard || return 0
  local re="$1"
  if printf "%s" "$RESP_BODY" | grep -Eq -- "$re"; then
    _record_pass
  else
    _record_fail "body did not match /$re/"
  fi
}

expect_body_exact() {
  _assertion_guard || return 0
  local want="$1"
  if [ "$RESP_BODY" = "$want" ]; then
    _record_pass
  else
    _record_fail "body did not equal expected exact bytes"
  fi
}

# Finalisation: close the open case (called from run.sh at end of each file).
_finalise_open_case() {
  if [ -n "$CURRENT_CASE_ID" ] && [ "$CURRENT_CASE_REPORTED" -eq 0 ]; then
    _record_pass
  fi
}
