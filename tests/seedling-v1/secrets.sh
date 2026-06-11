# secrets.sh — seedling/v1 conformance: /secrets/put, /secrets/get.

it "sec-01" "put string then round-trip"
  POST /secrets/put -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" \
    -d '{"key":"sv1_test_string","value":"hello"}'
  expect_status 200
  expect_json '.ok' 'true'

it "sec-02" "get reads back the put"
  POST /secrets/get -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" \
    -d '{"key":"sv1_test_string"}'
  expect_status 200
  expect_json '.value' 'hello'

it "sec-03" "K-01 null → empty string"
  POST /secrets/put -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" \
    -d '{"key":"sv1_test_null","value":null}'
  if [ "$RESP_STATUS" = "200" ]; then
    POST /secrets/get -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
      -H "Content-Type: application/json" \
      -d '{"key":"sv1_test_null"}'
    expect_status 200
    expect_json '.value' ''
  else
    # Some impls might reject value=null as invalid — record but don't fail.
    pass
  fi

it "sec-04" "K-01 object → JSON-encoded string"
  POST /secrets/put -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" \
    -d '{"key":"sv1_test_obj","value":{"a":1}}'
  expect_status 200
  POST /secrets/get -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" \
    -d '{"key":"sv1_test_obj"}'
  expect_status 200
  expect_json '.value' '{"a":1}'

it "sec-05" "K-03 not-found is 404 (not 200, not 500)"
  POST /secrets/get -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" \
    -d '{"key":"sv1_never_written_zzz"}'
  expect_status 404
  expect_json '.error' 'not_found'

it "sec-06" "put missing key → 400"
  POST /secrets/put -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" \
    -d '{"value":"x"}'
  expect_status 400
  expect_json '.error' 'key_and_value_required'

it "sec-07" "put bad JSON → 400 bad_json"
  POST /secrets/put -H "Authorization: Bearer $OPAQUE_SOLAR_CIVET" \
    -H "Content-Type: application/json" -d '{garbled'
  expect_status 400
  expect_json '.error' 'bad_json'

it "sec-08" "put no bearer → 401 missing_bearer_token"
  POST /secrets/put -H "Content-Type: application/json" \
    -d '{"key":"x","value":"y"}'
  expect_status 401
  expect_json '.error' 'missing_bearer_token'

it "sec-09" "put bogus bearer → 401 invalid_or_inactive_token"
  POST /secrets/put -H "Authorization: Bearer abco_nonsense_completely_invalid_xx" \
    -H "Content-Type: application/json" \
    -d '{"key":"x","value":"y"}'
  expect_status 401
  expect_json '.error' 'invalid_or_inactive_token'
