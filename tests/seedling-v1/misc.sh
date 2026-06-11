# misc.sh — seedling/v1 conformance: catch-all + method/path tolerance.

it "misc-01" "C-08 unrouted path → 404 not found"
  GET /this/path/does/not/exist
  expect_status 404
  expect_json '.error' 'not found'

it "misc-02" "trailing slash tolerance (impl choice)"
  GET /healthz/
  case "$RESP_STATUS" in
    200|404) pass ;;
    *) fail "expected 200 or 404 for /healthz/; got $RESP_STATUS" ;;
  esac

it "misc-03" "method-not-allowed → 405 or 404 (impl choice)"
  POST /healthz
  case "$RESP_STATUS" in
    405|404) pass ;;
    *) fail "expected 404 or 405 for POST /healthz; got $RESP_STATUS" ;;
  esac
