package authsvc

import (
	"net/http"
	"testing"
)

func TestRotate_RequiresOperator(t *testing.T) {
	mgr := newRecManager(&Slot{State: "claimed"})
	s := lifecycleServer(t, mgr, newRecNomadAdmin(), newRecMinioAdmin())
	rr := postJSON(t, s, "/manage/slots/x/rotate", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
}

func TestRotate_NotActive(t *testing.T) {
	mgr := newRecManager(&Slot{SlotName: "x", State: "unclaimed"})
	s := lifecycleServer(t, mgr, newRecNomadAdmin(), newRecMinioAdmin())
	rr := postJSON(t, s, "/manage/slots/x/rotate", "", opHdr(opTok))
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "slot_not_active" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestRotate_OK_RotatesMintsDeletesOld(t *testing.T) {
	mgr := newRecManager(&Slot{ID: "id1", SlotName: "calm_dassie", GroupName: "mbhg-hostgen",
		State: "claimed", MinioAccessKey: "slot-calm_dassie", NomadTokenAccessor: "acc-old"})
	na := newRecNomadAdmin()
	ma := newRecMinioAdmin()
	s := lifecycleServer(t, mgr, na, ma)
	rr := postJSON(t, s, "/manage/slots/calm_dassie/rotate", "", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(ma.rotated) != 1 {
		t.Errorf("expected MinIO rotate, got %v", ma.rotated)
	}
	if len(na.created) != 1 {
		t.Errorf("expected new Nomad token, got %v", na.created)
	}
	// The OLD accessor must be deleted AFTER the new creds are patched.
	if len(na.deleted) != 1 || na.deleted[0] != "acc-old" {
		t.Errorf("expected old accessor deleted, got %v", na.deleted)
	}
	p := mgr.patchWith("minio_secret_key")
	if p == nil || p["minio_secret_key"] != "newsecret-slot-calm_dassie" || p["nomad_token_accessor"] != "acc-calm_dassie" {
		t.Errorf("rotate patch wrong: %v", p)
	}
	// rotate must NOT change state (claimed stays claimed).
	if _, ok := p["state"]; ok {
		t.Errorf("rotate must not patch state: %v", p)
	}
	if len(mgr.invalidated) == 0 {
		t.Errorf("expected slot-state cache invalidation")
	}
}

func TestRotate_SuspendedSlotAllowed(t *testing.T) {
	// rotate is valid for both claimed and suspended.
	mgr := newRecManager(&Slot{ID: "id1", SlotName: "x", GroupName: "g",
		State: "suspended", MinioAccessKey: "slot-x"})
	s := lifecycleServer(t, mgr, newRecNomadAdmin(), newRecMinioAdmin())
	rr := postJSON(t, s, "/manage/slots/x/rotate", "", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
