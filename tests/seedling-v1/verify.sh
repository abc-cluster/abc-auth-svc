# verify.sh — seedling/v1 conformance: /verify, /verify-namespace.

it "verify-01" "GET /verify happy path → 200 ok\\n + identity headers"
  GET /verify -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET"
  expect_status 200
  expect_header "Content-Type" '^text/plain'
  expect_body_exact $'ok\n'
  expect_header "X-Auth-User"      '^solar_civet$'
  expect_header "X-Auth-Group"     '.+'
  expect_header "X-Auth-Namespace" '.+'
  expect_header "X-Auth-Policies"  '.+'
  expect_header "X-Auth-Type"      '^(client|management)$'

it "verify-02" "GET /verify-namespace alias is identical"
  GET /verify-namespace -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET"
  expect_status 200
  expect_body_exact $'ok\n'

it "verify-03" "POST /verify same shape"
  POST /verify -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET"
  expect_status 200
  expect_body_exact $'ok\n'

it "verify-04" "no auth → 401 plain text"
  GET /verify
  expect_status 401
  expect_header "Content-Type" '^text/plain'
  expect_body_exact $'unauthorized: missing or invalid token\n'

it "verify-05" "management token shape (skip if not provisioned)"
  if [ -n "${NOMAD_MANAGEMENT_TOKEN:-}" ]; then
    GET /verify -H "Authorization: Bearer $NOMAD_MANAGEMENT_TOKEN"
    expect_status 200
    expect_header "X-Auth-Type"      '^management$'
    expect_header "X-Auth-Group"     '^admin$'
    expect_header "X-Auth-Namespace" '^\*$'
    expect_header "X-Auth-Policies"  '^management$'
  else
    pass
  fi
