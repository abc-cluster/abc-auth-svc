# minio.sh — seedling/v1 conformance: GET /minio-login.

it "minio-01" "happy path sets token cookie + redirects to /"
  POST /cli-token -H "Content-Type: application/json" \
    -d "{\"nomad_token\":\"$NOMAD_TOKEN_SOLAR_CIVET\",\"portal\":\"minio\",\"minio_password\":\"${SLOT_PASSWORD_SOLAR_CIVET:-unset}\"}"
  if [ "$RESP_STATUS" != "200" ]; then
    fail "prerequisite mint failed (status=$RESP_STATUS)"
    return 0 2>/dev/null || true
  fi
  CODE="$(printf "%s" "$RESP_BODY" | jq -r '.code')"
  GET "/minio-login?code=$CODE"
  expect_status 302
  expect_header "Set-Cookie" '^token='
  expect_header "Set-Cookie" 'Max-Age=43200'
  expect_header "Location" '^/$'

it "minio-02" "missing code → 302 + error=missing_code on / (NOT login)"
  GET /minio-login
  expect_status 302
  expect_header "Location" '/\?error=missing_code'

it "minio-03" "invalid code → 302 + error=link_expired"
  GET "/minio-login?code=deadbeef-not-a-real-code-zzzzz"
  expect_status 302
  expect_header "Location" 'error=link_expired'
