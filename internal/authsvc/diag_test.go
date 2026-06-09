package authsvc

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// fakeExisterHub is an okHub that also answers UserExists, so diag's
// jh_user_present check can be exercised in both directions.
type fakeExisterHub struct {
	*fakeHub
	exists bool
}

func (f fakeExisterHub) UserExists(_ context.Context, _ string) (*bool, error) {
	b := f.exists
	return &b, nil
}

func diagServer(t *testing.T, slot *Slot, hubUserExists bool) *Server {
	t.Helper()
	mgr := newRecManager(slot)
	hub := fakeExisterHub{fakeHub: okHub(), exists: hubUserExists}
	cfg := Upstreams{Nomad: okNomad("pool-x"), Hub: hub, Store: mgr}
	s, _ := newP4Server(t, opTok, cfg)
	return s
}

func TestDiag_RequiresOperator(t *testing.T) {
	s := diagServer(t, &Slot{SlotName: "x", State: "claimed"}, true)
	rr := httptestGET(t, s, "/manage/slots/x/diag", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
}

func TestDiag_NoPBRow(t *testing.T) {
	s := diagServer(t, nil, true)
	rr := httptestGET(t, s, "/manage/slots/ghost/diag", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var rep SlotDiagReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Verdict != "blocked_at: pb_row_present" {
		t.Errorf("verdict=%q", rep.Verdict)
	}
}

func TestDiag_ReportShape_AndJHUserCheck(t *testing.T) {
	// claimed slot, JH user missing → verdict must flag jh_user_present.
	s := diagServer(t, &Slot{ID: "id", SlotName: "x", GroupName: "g", State: "claimed",
		MinioAccessKey: "slot-x"}, false)
	rr := httptestGET(t, s, "/manage/slots/x/diag", opHdr(opTok))
	var rep SlotDiagReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Slot != "x" {
		t.Errorf("slot=%q", rep.Slot)
	}
	// pb_row_present + pb_state_claimed pass; jh_user_present fails.
	checks := map[string]bool{}
	for _, c := range rep.Checks {
		checks[c.Check] = c.OK
	}
	if !checks["pb_row_present"] || !checks["pb_state_claimed"] {
		t.Errorf("pb checks should pass: %+v", checks)
	}
	if checks["jh_user_present"] {
		t.Errorf("jh_user_present should fail when hub says user absent")
	}
	if rep.Verdict == "ready" {
		t.Errorf("verdict should be blocked, got ready")
	}
	// remediation hints should include the JH user hint.
	if len(rep.RemediationHints) == 0 {
		t.Errorf("expected remediation hints")
	}
}

func TestDiag_PBFieldsSurfaced(t *testing.T) {
	s := diagServer(t, &Slot{ID: "id", SlotName: "x", GroupName: "g", State: "unclaimed",
		MinioAccessKey: "slot-x", CredSource: "seedling/v1"}, true)
	rr := httptestGET(t, s, "/manage/slots/x/diag", opHdr(opTok))
	var rep SlotDiagReport
	_ = json.Unmarshal(rr.Body.Bytes(), &rep)
	if rep.PB["state"] != "unclaimed" || rep.PB["minio_access_key"] != "slot-x" {
		t.Errorf("pb block wrong: %v", rep.PB)
	}
}
