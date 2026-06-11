# health.sh — seedling/v1 conformance: health + meta endpoints.
# Sourced by bin/run.sh; lib.sh has already been sourced.

it "health-01" "GET /healthz happy path"
  GET /healthz
  expect_status 200
  expect_body_exact $'ok\n'
  expect_header "X-Abc-Auth-API-Version" '^v1$'
  expect_header "X-Request-Id" '.+'

it "health-02" "GET /auth/health alias"
  GET /auth/health
  expect_status 200
  expect_body_exact $'ok\n'

it "health-03" "GET /readyz shape"
  GET /readyz
  expect_status 200
  expect_json '.status' 'ready'
  expect_json '.version | type' 'string'

it "health-04" "GET /version shape"
  GET /version
  expect_status 200
  # All three fields are present (values may be empty in dev builds).
  expect_json 'has("version") and has("build_time") and has("git_commit")' 'true'

it "health-05" "C-02 echo X-Request-Id"
  GET /healthz -H "X-Request-Id: test-12345"
  expect_status 200
  expect_header "X-Request-Id" '^test-12345$'

it "health-06" "C-02 mint when inbound id is unsafe"
  GET /healthz -H "X-Request-Id: ../../etc/passwd"
  expect_status 200
  # Bad value must NOT be echoed; some impl mints a fresh one.
  rid="$(header X-Request-Id)"
  if [ "$rid" = "../../etc/passwd" ]; then
    fail "X-Request-Id echoed unsafe inbound value '$rid'"
  else
    pass
  fi
