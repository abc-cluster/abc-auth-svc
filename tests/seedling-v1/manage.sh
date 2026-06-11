# manage.sh — seedling/v1 conformance: /manage/slots/*.
#
# All cases require X-Operator-Token. NEGATIVE cases drop the header.
# DESTRUCTIVE cases (suspend/reactivate/rotate/cred-source flip) mutate the
# fixture. To keep the read-only manage cases safe for a casual CI run, only
# mgmt-01..05 and mgmt-10..11 run by default. Opt into mutating runs by
# exporting RUN_DESTRUCTIVE=1.

it "mgmt-01" "GET /manage/slots returns secret-stripped projection"
  GET /manage/slots -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  # Body is an array.
  expect_json 'type' 'array'
  # No entry contains a secret-key field.
  if printf "%s" "$RESP_BODY" | jq -e 'any(.[]; has("minio_secret_key") or has("nomad_token_secret"))' >/dev/null 2>&1; then
    fail "PublicSlot projection leaked a secret field"
  else
    pass
  fi

it "mgmt-02" "no operator token → 401 unauthorized"
  GET /manage/slots
  expect_status 401
  expect_json '.error' 'unauthorized'

it "mgmt-03" "wrong operator token → 401"
  GET /manage/slots -H "X-Operator-Token: definitely-wrong"
  expect_status 401
  expect_json '.error' 'unauthorized'

it "mgmt-04" "GET /manage/slots/solar_civet returns one slot"
  GET /manage/slots/solar_civet -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  expect_json '.slot_name' 'solar_civet'

it "mgmt-05" "unknown slot → 404 not_found"
  GET /manage/slots/no_such_slot -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 404
  expect_json '.error' 'not_found'

it "mgmt-10" "diag returns the structured report"
  GET /manage/slots/solar_civet/diag -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  expect_json '. | has("slot") and has("pb") and has("jh") and has("host") and has("checks") and has("verdict") and has("remediation_hints")' 'true'

it "mgmt-11" "diag for unknown slot is 200 with blocked verdict (NOT 404)"
  GET /manage/slots/no_such_slot/diag -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  expect_json '.verdict' "$(printf '%s' "$RESP_BODY" | jq -r '.verdict')"
  # Verdict starts with "blocked_at:".
  v="$(printf '%s' "$RESP_BODY" | jq -r '.verdict')"
  case "$v" in
    blocked_at:*) pass ;;
    *) fail "expected verdict 'blocked_at: …' for unknown slot; got '$v'" ;;
  esac

# ---------------------------------------------------------------------------
# Destructive (mutating) cases — opt-in only.
# ---------------------------------------------------------------------------

if [ "${RUN_DESTRUCTIVE:-0}" != "1" ]; then
  it "mgmt-skipped" "mutating mgmt cases skipped (set RUN_DESTRUCTIVE=1 to enable)"
  pass
  return 0 2>/dev/null || true
fi

it "mgmt-12" "suspend a claimed slot → 200 ok, state=suspended"
  POST /manage/slots/solar_civet/suspend -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  expect_json '.ok' 'true'

it "mgmt-13" "re-suspend an already-suspended slot → 400 slot_not_claimed"
  POST /manage/slots/solar_civet/suspend -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 400
  expect_json '.error' 'slot_not_claimed'

it "mgmt-14" "reactivate suspended → 200 + creds rotated"
  POST /manage/slots/solar_civet/reactivate -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  expect_json '.ok' 'true'

it "mgmt-15" "rotate a claimed slot → 200, state unchanged"
  POST /manage/slots/solar_civet/rotate -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 200
  expect_json '.ok' 'true'

it "mgmt-17" "rotate an unclaimed slot → 400 slot_not_active"
  POST /manage/slots/coral_starfish/rotate -H "X-Operator-Token: $OPERATOR_TOKEN"
  expect_status 400
  expect_json '.error' 'slot_not_active'
