# workbench.sh — seedling/v1 conformance: POST /workbench/token.

it "wb-01" "happy path returns the JH token bundle"
  POST /workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{}'
  expect_status 200
  expect_json '.slot' 'solar_civet'
  expect_json '. | has("token") and has("id") and has("expires_at") and has("scopes") and has("note") and has("hub_url")' 'true'

it "wb-03" "explicit valid expires_in"
  POST /workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{"expires_in":3600}'
  expect_status 200
  expect_json '.expires_at | type' 'string'

it "wb-04" "expires_in too large → 400"
  POST /workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{"expires_in":99999999}'
  expect_status 400
  expect_json '.error' 'expires_in cannot exceed 30 days (2592000 seconds)'

it "wb-05" "expires_in non-int → 400"
  POST /workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{"expires_in":"forever"}'
  expect_status 400
  expect_body_contains "expires_in must be an integer"

it "wb-06" "expires_in non-positive → 400"
  POST /workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{"expires_in":0}'
  expect_status 400
  expect_body_contains "expires_in must be positive"

it "wb-07" "suspended slot → 403 (not 401)"
  POST /workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_GRANITE_IGUANA" \
    -H "Content-Type: application/json" -d '{}'
  expect_status 403
  expect_json '.error' 'slot is suspended'

it "wb-08" "malformed JSON body → 400"
  POST /workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{garbled'
  expect_status 400
  expect_json '.error' 'invalid JSON body'

it "wb-09" "missing bearer → 401"
  POST /workbench/token -H "Content-Type: application/json" -d '{}'
  expect_status 401
  expect_body_contains "missing token"

it "wb-10" "alias /auth/workbench/token works"
  POST /auth/workbench/token \
    -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{}'
  expect_status 200
  expect_json '.slot' 'solar_civet'
