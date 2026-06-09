package authsvc

import (
	"net/http"
	"testing"
)

const opTok = "op-secret"

func lifecycleServer(t *testing.T, mgr *recManager, na *recNomadAdmin, ma *recMinioAdmin) *Server {
	t.Helper()
	redirectTestDirs(t)
	s, _ := newP4Server(t, opTok, Upstreams{
		Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr,
		NomadAdmin: na, MinioAdmin: ma,
	})
	return s
}

// ── suspend ────────────────────────────────────────────────────────────────

func TestSuspend_RequiresOperator(t *testing.T) {
	mgr := newRecManager(&Slot{State: "claimed"})
	s := lifecycleServer(t, mgr, newRecNomadAdmin(), newRecMinioAdmin())
	rr := postJSON(t, s, "/manage/slots/x/suspend", "", nil) // no operator token
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
}

func TestSuspend_NotFound(t *testing.T) {
	mgr := newRecManager(nil)
	s := lifecycleServer(t, mgr, newRecNomadAdmin(), newRecMinioAdmin())
	rr := postJSON(t, s, "/manage/slots/x/suspend", "", opHdr(opTok))
	if rr.Code != http.StatusNotFound || decodeErr(t, rr) != "not_found" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestSuspend_NotClaimed(t *testing.T) {
	mgr := newRecManager(&Slot{SlotName: "x", State: "unclaimed"})
	s := lifecycleServer(t, mgr, newRecNomadAdmin(), newRecMinioAdmin())
	rr := postJSON(t, s, "/manage/slots/x/suspend", "", opHdr(opTok))
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "slot_not_claimed" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestSuspend_OK_DisablesMinIO_DeletesToken_PatchesState(t *testing.T) {
	mgr := newRecManager(&Slot{ID: "id1", SlotName: "calm_dassie",
		State: "claimed", MinioAccessKey: "slot-calm_dassie", NomadTokenAccessor: "acc-old", NomadTokenSecret: "tok"})
	na := newRecNomadAdmin()
	ma := newRecMinioAdmin()
	s := lifecycleServer(t, mgr, na, ma)
	rr := postJSON(t, s, "/manage/slots/calm_dassie/suspend", "", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if en, ok := ma.enabled["slot-calm_dassie"]; !ok || en {
		t.Errorf("MinIO user should be disabled, enabled map=%v", ma.enabled)
	}
	if len(na.deleted) != 1 || na.deleted[0] != "acc-old" {
		t.Errorf("expected old accessor deleted, got %v", na.deleted)
	}
	if mgr.lastPatch()["state"] != "suspended" {
		t.Errorf("state not patched to suspended: %v", mgr.lastPatch())
	}
	if len(mgr.invalidated) == 0 {
		t.Errorf("slot-state cache should be invalidated")
	}
}

// ── reactivate ───────────────────────────────────────────────────────────────

func TestReactivate_NotSuspended(t *testing.T) {
	mgr := newRecManager(&Slot{SlotName: "x", State: "claimed"})
	s := lifecycleServer(t, mgr, newRecNomadAdmin(), newRecMinioAdmin())
	rr := postJSON(t, s, "/manage/slots/x/reactivate", "", opHdr(opTok))
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "slot_not_suspended" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestReactivate_OK_EnablesRotatesMints_PatchesClaimed(t *testing.T) {
	mgr := newRecManager(&Slot{ID: "id1", SlotName: "calm_dassie", GroupName: "mbhg-hostgen",
		State: "suspended", MinioAccessKey: "slot-calm_dassie"})
	na := newRecNomadAdmin()
	ma := newRecMinioAdmin()
	s := lifecycleServer(t, mgr, na, ma)
	rr := postJSON(t, s, "/manage/slots/calm_dassie/reactivate", "", opHdr(opTok))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if en := ma.enabled["slot-calm_dassie"]; !en {
		t.Errorf("MinIO user should be enabled")
	}
	if len(ma.rotated) != 1 {
		t.Errorf("expected MinIO secret rotation, got %v", ma.rotated)
	}
	if len(na.created) != 1 || na.created[0] != "calm_dassie" {
		t.Errorf("expected new Nomad token minted, got %v", na.created)
	}
	p := mgr.lastPatch()
	if p["state"] != "claimed" || p["nomad_token_accessor"] != "acc-calm_dassie" || p["minio_secret_key"] != "newsecret-slot-calm_dassie" {
		t.Errorf("reactivate patch wrong: %v", p)
	}
}
