# auth.sh — seedling/v1 conformance: /auth/login (GET + POST), /auth/logout, /auth/me.

it "auth-01" "GET /auth/login renders the form"
  GET /auth/login
  expect_status 200
  expect_header "Content-Type"  '^text/html'
  expect_header "Cache-Control" '^no-store$'
  expect_body_matches '<form'

it "auth-02" "GET /auth/login?next=scheme-relative is sanitised"
  GET /auth/login?next=//evil.example/x
  expect_status 200
  if printf "%s" "$RESP_BODY" | grep -F -q '//evil.example/x'; then
    fail "rendered form leaks scheme-relative next URI"
  else
    pass
  fi

it "auth-03" "POST /auth/login success → 302 + Set-Cookie"
  POST /auth/login --data-urlencode "username=solar_civet" --data-urlencode "password=${SLOT_PASSWORD_SOLAR_CIVET:-unset}"
  expect_status 302
  expect_header "Set-Cookie" 'abc_session=[^;]+'
  expect_header "Location" '^/$'

it "auth-04" "POST /auth/login wrong password → 200 + form error"
  POST /auth/login --data-urlencode "username=solar_civet" --data-urlencode "password=WRONG_PASSWORD"
  expect_status 200
  expect_body_contains "Invalid username or password."

it "auth-05" "POST /auth/login empty form → 200 + required-fields message"
  POST /auth/login --data-urlencode "username=" --data-urlencode "password="
  expect_status 200
  expect_body_contains "Username and password are required."

it "auth-06" "POST /auth/login suspended slot → 200 + Account suspended"
  POST /auth/login --data-urlencode "username=granite_iguana" --data-urlencode "password=${SLOT_PASSWORD_GRANITE_IGUANA:-unset}"
  expect_status 200
  expect_body_contains "Account suspended."

it "auth-07" "POST /auth/login rejects scheme-relative next"
  POST /auth/login --data-urlencode "username=solar_civet" --data-urlencode "password=${SLOT_PASSWORD_SOLAR_CIVET:-unset}" --data-urlencode "next=//evil/x"
  expect_status 302
  loc="$(header Location)"
  case "$loc" in
    //*) fail "302 Location '$loc' was not sanitised" ;;
    *)   pass ;;
  esac

it "auth-08" "GET /auth/logout clears cookie + redirects to login"
  GET /auth/logout
  expect_status 302
  expect_header "Location"   '/auth/login'
  expect_header "Set-Cookie" 'abc_session='

it "auth-09" "/auth/me happy path with Nomad bearer"
  GET /auth/me -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET"
  expect_status 200
  expect_header "Access-Control-Allow-Origin" '^\*$'
  expect_json '.user'           'solar_civet'
  expect_json '.primary_group'  'demo'
  expect_json '.namespace'      'demo'
  expect_json '.role_based | type' 'boolean'

it "auth-10" "/auth/me missing bearer → 401 missing token"
  GET /auth/me
  expect_status 401
  expect_json '.error' 'missing token'

it "auth-11" "/auth/me bogus bearer → 401 invalid token"
  GET /auth/me -H "Authorization: Bearer obviously-not-a-real-token"
  expect_status 401
  expect_json '.error' 'invalid token'

it "auth-12" "/auth/me X-Nomad-Token equivalent"
  GET /auth/me -H "X-Nomad-Token: $NOMAD_TOKEN_SOLAR_CIVET"
  expect_status 200
  expect_json '.user' 'solar_civet'
