#!/usr/bin/env bash
# shadow-compare.sh — compare the Go (:4182) vs Python (:4181) /validate verdicts.
#
# The forward-auth decision is driven by the abc_session cookie + slot state.
# Caddy (standard build) can't mirror live traffic, so this harness forges
# cookies with the LIVE SESSION_SECRET and exercises the /validate decision
# matrix against both services, reporting any disagreement.
#
# Run on aither (needs sudo to read the session secret):
#   ./shadow-compare.sh
#
# Complementary signal: the Go service's own GET /validate-shadow logs
# "validate.shadow.disagree" for any real request that reaches it (it calls the
# Python /validate internally). Tail it with:
#   nomad alloc logs -stderr -f <alloc> | grep validate.shadow
set -euo pipefail

PY="${PY_URL:-http://127.0.0.1:4181}"
GO="${GO_URL:-http://127.0.0.1:4182}"
SECRET="$(sudo cat /etc/abc-auth-svc/session_secret | tr -d '\n')"

mk_cookie() { # user  ttl_offset_seconds
  local user="$1" exp=$(( $(date +%s) + ${2:-3600} ))
  local payload="${user}:${exp}"
  local sig
  sig="$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')"
  printf '%s:%s' "$payload" "$sig" | base64 | tr '+/' '-_' | tr -d '\n'
}

verdict() { # base_url  cookie_value(optional)
  local args=(-s -o /dev/null -D - -H "X-Forwarded-Uri: /lab")
  [ -n "${2:-}" ] && args+=(-H "Cookie: abc_session=$2")
  curl "${args[@]}" "$1/validate" \
    | awk 'BEGIN{IGNORECASE=1} /^HTTP/{s=$2} /^Remote-User:/{gsub(/\r/,"",$2); u=$2} END{printf "%s/%s", s, u}'
}

fail=0
compare() { # label  cookie
  local py go
  py="$(verdict "$PY" "${2:-}")"
  go="$(verdict "$GO" "${2:-}")"
  if [ "$py" = "$go" ]; then
    printf 'AGREE     %-16s %s\n' "$1" "$py"
  else
    printf 'DISAGREE  %-16s py=[%s] go=[%s]\n' "$1" "$py" "$go"
    fail=1
  fi
}

echo "shadow-compare: Python=$PY  Go=$GO"
compare "valid-user"     "$(mk_cookie alice 3600)"
compare "expired-cookie" "$(mk_cookie alice -60)"
compare "no-cookie"      ""
compare "tampered-sig"   "$(mk_cookie alice 3600)TAMPER"
# To exercise the suspended/expired-slot path, pass a real suspended slot's
# minio_access_key:  compare "suspended" "$(mk_cookie <minio_access_key> 3600)"

if [ "$fail" -eq 0 ]; then
  echo "RESULT: all cases AGREE"
else
  echo "RESULT: DISAGREEMENTS found — do NOT cut over"
  exit 1
fi
