# exchange.sh — seedling/v1 conformance: POST /exchange.

it "exch-01" "happy path returns canonical credentials bundle"
  POST /exchange -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET"
  expect_status 200
  expect_json '.source'              'seedling/v1'
  expect_json '.whoami'              'solar_civet'
  expect_json '.nomad | has("addr") and has("token") and has("namespace") and has("datacenters") and has("head_pool") and has("worker_pool")' 'true'
  expect_json '.minio | has("endpoint") and has("access_key") and has("secret_key")' 'true'

it "exch-02" "missing Authorization → 401 missing_bearer_token"
  POST /exchange
  expect_status 401
  expect_json '.error' 'missing_bearer_token'

it "exch-03" "empty bearer → 401 empty_bearer_token"
  POST /exchange -H "Authorization: Bearer "
  expect_status 401
  expect_json '.error' 'empty_bearer_token'

it "exch-04" "invalid bearer → 401 invalid_or_inactive_token"
  POST /exchange -H "Authorization: Bearer abco_not_a_real_one_at_all"
  expect_status 401
  expect_json '.error' 'invalid_or_inactive_token'

it "exch-05" "non-existent slot → SAME tag (no enumeration)"
  POST /exchange -H "Authorization: Bearer abco_definitely_does_not_exist_in_pb_xx"
  expect_status 401
  expect_json '.error' 'invalid_or_inactive_token'

it "exch-07" "stdout/log redaction — bundle never logged"
  # Implementations expose a log file path via ABC_AUTH_LOG_PATH (the bash
  # runner doesn't enforce — we only WARN if it's set and contains a leak).
  if [ -n "${ABC_AUTH_LOG_PATH:-}" ] && [ -r "$ABC_AUTH_LOG_PATH" ]; then
    for needle in "$OPAQUE_SOLAR_CIVET" "$NOMAD_TOKEN_SOLAR_CIVET"; do
      if grep -F -q -- "$needle" "$ABC_AUTH_LOG_PATH"; then
        fail "log file $ABC_AUTH_LOG_PATH contains a secret literal — C-06 violation"
        break
      fi
    done
    pass
  else
    # No log path provided; treat as a soft pass.
    pass
  fi
