# validate.sh — seedling/v1 conformance: /validate, /validate-optional.
#
# Fixture cookie helpers — we obtain real abc_session cookies by logging in as
# the fixture slot via /auth/login. If your fixture stores a pre-computed cookie
# you can `export COOKIE_SOLAR_CIVET=...` to skip the login.

_jar_solar="$(mktemp)"
_jar_granite="$(mktemp)"

# Acquire cookie: login form, save cookies.
_login_cookie() {
  local user="$1" pass="$2" jar="$3"
  curl -sS -c "$jar" -o /dev/null --max-time 10 \
    -X POST -d "username=$user&password=$pass" \
    "$BASE_URL/auth/login" || true
}

_login_cookie "solar_civet"     "${SLOT_PASSWORD_SOLAR_CIVET:-unset}"     "$_jar_solar"
_login_cookie "granite_iguana"  "${SLOT_PASSWORD_GRANITE_IGUANA:-unset}"  "$_jar_granite"

it "validate-01" "/validate happy path with valid cookie"
  GET /validate -b "$_jar_solar"
  expect_status 200
  expect_header "X-Auth-User"    '^solar_civet$'
  expect_header "Remote-User"    '^solar_civet$'
  expect_header "X-WEBAUTH-USER" '^solar_civet$'

it "validate-02" "/validate no cookie → 302 to /auth/login?next=%2F"
  GET /validate
  expect_status 302
  expect_header "Location" '/auth/login\?next=%2F'

it "validate-03" "/validate no cookie + X-Forwarded-Uri propagates"
  GET /validate -H "X-Forwarded-Uri: /apps/foo"
  expect_status 302
  expect_header "Location" '/auth/login\?next=%2Fapps%2Ffoo'

it "validate-04" "/validate suspended slot → 302 + clear cookie"
  GET /validate -b "$_jar_granite"
  expect_status 302
  # Expect a Set-Cookie clearing the session (Max-Age=-1 or 0, or expires in the past).
  sc="$(header Set-Cookie)"
  case "$sc" in
    *abc_session=*Max-Age=-1*|*abc_session=*Max-Age=0*|*abc_session=*expires=*1970*)
      pass ;;
    *abc_session=\;*) pass ;;
    *) fail "expected Set-Cookie clearing abc_session; got '$sc'" ;;
  esac

it "validate-05" "/validate-optional no cookie → 200, no identity headers"
  GET /validate-optional
  expect_status 200
  expect_header_absent "X-Auth-User"

it "validate-06" "/validate-optional with cookie → 200 + identity headers"
  GET /validate-optional -b "$_jar_solar"
  expect_status 200
  expect_header "X-Auth-User" '^solar_civet$'

rm -f "$_jar_solar" "$_jar_granite"
