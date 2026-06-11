# cli-tokens.sh — seedling/v1 conformance: POST /cli-token, GET /redeem.

it "cli-01" "happy path mint magic code"
  POST /cli-token -H "Content-Type: application/json" \
    -d "{\"nomad_token\":\"$NOMAD_TOKEN_SOLAR_CIVET\"}"
  expect_status 200
  expect_json '.code  | test("^[0-9a-f]{64}$")' 'true'
  expect_json '.ttl   | type'                  'number'
  CODE_HAPPY="$(printf "%s" "$RESP_BODY" | jq -r '.code')"

it "cli-02" "missing body → 400"
  POST /cli-token
  expect_status 400
  expect_body_contains "missing request body"

it "cli-03" "missing nomad_token field → 400"
  POST /cli-token -H "Content-Type: application/json" -d '{}'
  expect_status 400
  expect_body_contains "nomad_token required"

it "cli-04" "bogus nomad token → 401"
  POST /cli-token -H "Content-Type: application/json" \
    -d '{"nomad_token":"obviously-not-real"}'
  expect_status 401
  expect_body_contains "invalid or expired Nomad token"

it "cli-05" "redeem the cli-01 code → 302 + abc_session cookie"
  if [ -z "${CODE_HAPPY:-}" ]; then
    fail "cli-05 prerequisite (cli-01) did not yield a code"
  else
    GET "/redeem?code=$CODE_HAPPY"
    expect_status 302
    expect_header "Set-Cookie" 'abc_session='
    expect_header "Location"   '^/'
  fi

it "cli-06" "replay → 302 link_expired, no cookie"
  if [ -z "${CODE_HAPPY:-}" ]; then
    fail "cli-06 prerequisite (cli-01) did not yield a code"
  else
    GET "/redeem?code=$CODE_HAPPY"
    expect_status 302
    expect_header "Location" 'error=link_expired'
    expect_header_absent "Set-Cookie"
  fi

it "cli-07" "missing code → 302 + error=missing_code"
  GET /redeem
  expect_status 302
  expect_header "Location" 'error=missing_code'

it "cli-08" "grafana portal redirect"
  POST /cli-token -H "Content-Type: application/json" \
    -d "{\"nomad_token\":\"$NOMAD_TOKEN_SOLAR_CIVET\",\"portal\":\"grafana\"}"
  expect_status 200
  CODE_GRAF="$(printf "%s" "$RESP_BODY" | jq -r '.code')"
  GET "/redeem?code=$CODE_GRAF"
  expect_status 302
  # Grafana redirects to /login on the destination origin.
  expect_header "Location" '^/login'
