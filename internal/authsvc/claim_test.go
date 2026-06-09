package authsvc

import (
	"net/http"
	"strings"
	"testing"
)

func claimServer(t *testing.T, mgr *recManager) *Server {
	t.Helper()
	redirectTestDirs(t)
	s, _ := newP4Server(t, "", Upstreams{
		Nomad: okNomad("pool-x"), Hub: okHub(), Store: mgr,
		NomadAdmin: newRecNomadAdmin(), MinioAdmin: newRecMinioAdmin(),
	})
	return s
}

func TestClaim_MissingCode(t *testing.T) {
	s := claimServer(t, newRecManager(nil))
	rr := postJSON(t, s, "/slots/claim", `{"name":"n"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "claim_code_required" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestClaim_InvalidCredSource(t *testing.T) {
	s := claimServer(t, newRecManager(nil))
	rr := postJSON(t, s, "/slots/claim", `{"claim_code":"abc","cred_source":"bogus"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "invalid_cred_source" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestClaim_CodeInvalidOrUsed(t *testing.T) {
	mgr := newRecManager(nil) // FindSlot returns nil → no unclaimed slot for this code
	s := claimServer(t, mgr)
	rr := postJSON(t, s, "/slots/claim", `{"claim_code":"nope"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusNotFound || decodeErr(t, rr) != "code_invalid_or_used" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestClaim_LocalOK_ReturnsYAMLAttachment(t *testing.T) {
	slot := &Slot{ID: "id1", SlotName: "calm_dassie", GroupName: "mbhg-hostgen",
		State: "unclaimed", MinioAccessKey: "slot-calm_dassie", MinioSecretKey: "ms", NomadTokenSecret: "nt"}
	mgr := newRecManager(slot)
	s := claimServer(t, mgr)
	rr := postJSON(t, s, "/slots/claim", `{"claim_code":"good","name":"Calm","email":"c@x"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "abc-config-calm_dassie.yaml") {
		t.Errorf("content-disposition=%q", cd)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("content-type=%q", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "access_token: nt") || !strings.Contains(body, "whoami: calm_dassie") {
		t.Errorf("yaml body missing creds:\n%s", body)
	}
	// state must have flipped to claimed; local must NOT carry cred_source.
	// (The handler emits the claim patch then a separate config_yaml patch;
	// select the claim patch by a field unique to it.)
	p := mgr.patchWith("claimed_by_name")
	if p == nil || p["state"] != "claimed" || p["claimed_by_name"] != "Calm" {
		t.Errorf("claim patch wrong: %v", p)
	}
	if _, ok := p["cred_source"]; ok {
		t.Errorf("local claim must not set cred_source: %v", p)
	}
}

func TestClaim_SeedlingV1_MintsOpaque_NoRealCredsInYAML(t *testing.T) {
	slot := &Slot{ID: "id1", SlotName: "x", GroupName: "g",
		State: "unclaimed", MinioAccessKey: "slot-x", MinioSecretKey: "REAL-MS", NomadTokenSecret: "REAL-NT"}
	mgr := newRecManager(slot)
	s := claimServer(t, mgr)
	rr := postJSON(t, s, "/slots/claim", `{"claim_code":"good","cred_source":"seedling/v1"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	p := mgr.patchWith("cred_source")
	if p == nil || p["cred_source"] != "seedling/v1" {
		t.Errorf("expected cred_source seedling/v1, got %v", p)
	}
	if p == nil || p["opaque_token_hash"] == nil || p["opaque_token_hash"] == "" {
		t.Errorf("expected opaque_token_hash to be set: %v", p)
	}
	// The opaque-shape YAML must NOT leak the real Nomad/MinIO secrets.
	body := rr.Body.String()
	if strings.Contains(body, "REAL-MS") || strings.Contains(body, "REAL-NT") {
		t.Errorf("real creds leaked into seedling/v1 YAML:\n%s", body)
	}
	if !strings.Contains(body, "cred_source: seedling/v1") {
		t.Errorf("seedling/v1 YAML wrong:\n%s", body)
	}
}
