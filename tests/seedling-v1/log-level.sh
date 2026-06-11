# log-level.sh — seedling/v1 conformance: /manage/log-level.

it "log-01" "GET current level"
  GET /manage/log-level -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  expect_json '.level | test("^(info|debug|trace)$")' 'true'
  expect_json '.mutable | type' 'boolean'
  ORIG_LEVEL="$(printf "%s" "$RESP_BODY" | jq -r .level)"

it "log-02" "POST set level=debug"
  POST /manage/log-level -H "X-Operator-Token: $OPERATOR_TOKEN" \
    -H "Content-Type: application/json" -d '{"level":"debug"}'
  expect_status 200
  expect_json '.ok'    'true'
  expect_json '.level' 'debug'

it "log-03" "POST revert to original"
  POST /manage/log-level -H "X-Operator-Token: $OPERATOR_TOKEN" \
    -H "Content-Type: application/json" -d "{\"level\":\"${ORIG_LEVEL:-info}\"}"
  expect_status 200
  expect_json '.level' "${ORIG_LEVEL:-info}"

it "log-04" "POST invalid level → 400 invalid_level + allowed"
  POST /manage/log-level -H "X-Operator-Token: $OPERATOR_TOKEN" \
    -H "Content-Type: application/json" -d '{"level":"sausage"}'
  expect_status 400
  expect_json '.error'              'invalid_level'
  expect_json '.allowed | join(",")' 'info,debug,trace'

it "log-05" "POST missing level → 400 level_required"
  POST /manage/log-level -H "X-Operator-Token: $OPERATOR_TOKEN" \
    -H "Content-Type: application/json" -d '{}'
  expect_status 400
  expect_json '.error' 'level_required'

it "log-06" "POST bad JSON → 400 invalid_json"
  POST /manage/log-level -H "X-Operator-Token: $OPERATOR_TOKEN" \
    -H "Content-Type: application/json" -d '{garbled'
  expect_status 400
  expect_json '.error' 'invalid_json'

it "log-07" "POST no operator token → 401 unauthorized"
  POST /manage/log-level -H "Content-Type: application/json" -d '{"level":"info"}'
  expect_status 401
  expect_json '.error' 'unauthorized'
