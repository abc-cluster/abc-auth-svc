# slots.sh — seedling/v1 conformance: /slots/me/config, /slots/claim.

it "slot-01" "GET /slots/me/config happy path returns YAML attachment"
  GET /slots/me/config -H "Authorization: Bearer $NOMAD_TOKEN_SOLAR_CIVET"
  expect_status 200
  expect_header "Content-Type"        '^text/yaml'
  expect_header "Content-Disposition" 'attachment; filename="abc-config-solar_civet\.yaml"'
  expect_header "Cache-Control"       '^no-store$'
  # Body parses as YAML with a top-level mapping (we use python -c with PyYAML if available;
  # otherwise just a heuristic check for a leading non-list key).
  if command -v python3 >/dev/null 2>&1; then
    if printf "%s" "$RESP_BODY" | python3 -c "import sys, yaml; d = yaml.safe_load(sys.stdin); sys.exit(0 if isinstance(d, dict) else 1)" 2>/dev/null; then
      pass
    else
      fail "body did not parse as a YAML mapping"
    fi
  else
    expect_body_matches '^[A-Za-z_]+:'
  fi

it "slot-03" "GET /slots/me/config without auth → 401"
  GET /slots/me/config
  expect_status 401

it "slot-04" "GET /slots/me/config for unclaimed slot → 403 slot_*"
  if [ -n "${NOMAD_TOKEN_CORAL_STARFISH:-}" ]; then
    GET /slots/me/config -H "Authorization: Bearer $NOMAD_TOKEN_CORAL_STARFISH"
    expect_status 403
    expect_body_matches '"error":"slot_'
  else
    # No token issued for the unclaimed slot — skip.
    pass
  fi

it "slot-08" "claim with unknown code → 404 code_invalid_or_used"
  POST /slots/claim -H "Content-Type: application/json" \
    -d '{"claim_code":"NOT-A-REAL-CODE-EVER"}'
  expect_status 404
  expect_json '.error' 'code_invalid_or_used'

it "slot-09" "claim with bad JSON → 400 invalid_json"
  POST /slots/claim -H "Content-Type: application/json" -d '{garbled'
  expect_status 400
  expect_json '.error' 'invalid_json'

it "slot-10" "claim with invalid cred_source → 400 invalid_cred_source + extras"
  POST /slots/claim -H "Content-Type: application/json" \
    -d '{"claim_code":"x","cred_source":"remote"}'
  expect_status 400
  expect_json '.error'     'invalid_cred_source'
  expect_json '.requested' 'remote'
  expect_json '.allowed | join(",")' 'local,seedling/v1'

# slot-05/06/07/11 (the happy-path claim and concurrency) mutate the fixture.
# They are written as a separate `bin/claim-flow.sh` that re-seeds before
# running. The runner does NOT invoke them by default; opt-in with --tag claim-flow.
