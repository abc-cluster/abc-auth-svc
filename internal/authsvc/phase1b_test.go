package authsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func httptestGET(t *testing.T, s *Server, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	return rr
}

// ── renderer ──────────────────────────────────────────────────────────────────

func TestRenderConfigYAML_Local(t *testing.T) {
	y, err := renderConfigYAML(testCluster, "slot-calm_dassie", "mbhg-hostgen", "NT-tok", "calm_dassie", "MS-key", "local", "")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"active_context: seedling",
		"access_token: NT-tok",
		"id: pool-slot-calm_dassie",
		"access_key: calm_dassie",
		"secret_key: MS-key",
		"namespace: su-mbhg-hostgen",
		"token: NT-tok",
		"whoami: slot-calm_dassie",
		"upload_endpoint: https://upload.test/files/",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("local YAML missing %q:\n%s", want, y)
		}
	}
	if strings.Contains(y, "cred_source") {
		t.Errorf("local YAML must not carry cred_source:\n%s", y)
	}
}

func TestRenderConfigYAML_SeedlingV1(t *testing.T) {
	y, err := renderConfigYAML(testCluster, "slot-x", "g", "NT-secret", "ak", "MS-secret", "seedling/v1", "abco_opaque")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(y, "cred_source: seedling/v1") || !strings.Contains(y, "access_token: abco_opaque") ||
		!strings.Contains(y, "auth_endpoint: https://auth.test") {
		t.Errorf("seedling/v1 YAML wrong:\n%s", y)
	}
	// The real creds must NOT be in the opaque-shape YAML.
	if strings.Contains(y, "NT-secret") || strings.Contains(y, "MS-secret") || strings.Contains(y, "secret_key") {
		t.Errorf("real creds leaked into opaque YAML:\n%s", y)
	}
}

func TestRenderConfigYAML_SeedlingV1RequiresOpaque(t *testing.T) {
	if _, err := renderConfigYAML(testCluster, "slot-x", "g", "NT", "ak", "MS", "seedling/v1", ""); err == nil {
		t.Fatal("expected error when opaque is empty")
	}
}

func TestMintOpaque(t *testing.T) {
	tok, err := mintOpaque()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !strings.HasPrefix(tok, OpaquePrefix) || len(tok) < 20 {
		t.Errorf("bad opaque: %q", tok)
	}
	tok2, _ := mintOpaque()
	if tok == tok2 {
		t.Error("opaque tokens must be unique")
	}
}

// ── fake SlotManager ──────────────────────────────────────────────────────────

type fakeManager struct {
	fakeStore
	slot        *Slot
	patches     []map[string]any
	invalidated []string
}

func newFakeManager(slot *Slot) *fakeManager {
	fm := &fakeManager{slot: slot}
	fm.find = func(context.Context, string) (*Slot, error) { return fm.slot, nil }
	return fm
}

func (f *fakeManager) GetSlot(context.Context, string) (*Slot, error) { return f.slot, nil }
func (f *fakeManager) PatchSlot(_ context.Context, _ string, fields map[string]any) error {
	f.patches = append(f.patches, fields)
	if v, ok := fields["cred_source"].(string); ok {
		f.slot.CredSource = v
	}
	return nil
}
func (f *fakeManager) InvalidateSlotState(u string) { f.invalidated = append(f.invalidated, u) }

func mgrServer(t *testing.T, store SlotStore, opToken string) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.OperatorToken = opToken
	up := Upstreams{Nomad: okNomad("pool-calm_dassie"), Hub: okHub(), Store: store, Cluster: testCluster, HubPublicURL: "https://hub.test"}
	return NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up), &buf
}

// ── /slots/me/config ──────────────────────────────────────────────────────────

func TestSlotsMeConfig_MissingToken(t *testing.T) {
	s, _ := mgrServer(t, newFakeManager(&Slot{}), "")
	rr := httptestGET(t, s, "/slots/me/config", nil)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(decodeErr(t, rr), "missing_token") {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestSlotsMeConfig_ReturnsBlob(t *testing.T) {
	slot := &Slot{ID: "1", SlotName: "slot-calm_dassie", State: "claimed", ConfigYAML: "version: 1.0\n# cached blob\n"}
	s, _ := mgrServer(t, newFakeManager(slot), "")
	rr := httptestGET(t, s, "/slots/me/config", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d (%s)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/yaml" {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "cached blob") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

func TestSlotsMeConfig_RenderOnDemand(t *testing.T) {
	// claimed seedling/v1... no, render-on-demand needs a local slot (seedling/v1
	// without opaque is a no-op returning the empty blob). Use a local slot.
	slot := &Slot{ID: "1", SlotName: "slot-calm_dassie", State: "claimed", CredSource: "local",
		NomadTokenSecret: "NT", MinioAccessKey: "calm_dassie", MinioSecretKey: "MS", GroupName: "g", ConfigYAML: ""}
	fm := newFakeManager(slot)
	s, _ := mgrServer(t, fm, "")
	rr := httptestGET(t, s, "/slots/me/config", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "access_token: NT") {
		t.Errorf("rendered body missing creds:\n%s", rr.Body.String())
	}
	if len(fm.patches) == 0 {
		t.Errorf("expected the rendered blob to be persisted")
	}
}

func TestSlotsMeConfig_NotClaimed(t *testing.T) {
	slot := &Slot{ID: "1", SlotName: "slot-calm_dassie", State: "suspended"}
	s, _ := mgrServer(t, newFakeManager(slot), "")
	rr := httptestGET(t, s, "/slots/me/config", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusForbidden || !strings.Contains(decodeErr(t, rr), "slot_suspended") {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

// ── /manage/slots/{slot}/cred-source ──────────────────────────────────────────

func TestCredSource_RequiresOperator(t *testing.T) {
	s, _ := mgrServer(t, newFakeManager(&Slot{}), "op-secret")
	rr := post(t, s, "/manage/slots/slot-x/cred-source", `{"cred_source":"seedling/v1"}`, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rr.Code)
	}
}

func TestCredSource_FlipToSeedlingV1(t *testing.T) {
	slot := &Slot{ID: "1", SlotName: "slot-calm_dassie", State: "claimed", CredSource: "local",
		NomadTokenSecret: "NT-secret", MinioAccessKey: "calm_dassie", MinioSecretKey: "MS-secret", GroupName: "g"}
	fm := newFakeManager(slot)
	s, buf := mgrServer(t, fm, "op-secret")
	rr := post(t, s, "/manage/slots/slot-calm_dassie/cred-source", `{"cred_source":"seedling/v1"}`,
		map[string]string{"X-Operator-Token": "op-secret"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d (%s)", rr.Code, rr.Body.String())
	}
	var resp credSourceResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Changed || resp.CredSource != "seedling/v1" || resp.PreviousCredSource != "local" {
		t.Errorf("resp = %+v", resp)
	}
	if !strings.HasPrefix(resp.OpaqueToken, OpaquePrefix) {
		t.Errorf("expected a bare opaque in the flip response, got %q", resp.OpaqueToken)
	}
	// The cred_source + opaque hash must have been patched (hash, never bare).
	foundHash := false
	for _, p := range fm.patches {
		if h, ok := p["opaque_token_hash"].(string); ok && h == sha256Hex(resp.OpaqueToken) {
			foundHash = true
		}
	}
	if !foundHash {
		t.Errorf("opaque_token_hash not patched correctly; patches=%v", fm.patches)
	}
	// The bare opaque must NOT appear in the logs.
	if strings.Contains(buf.String(), resp.OpaqueToken) {
		t.Errorf("bare opaque leaked into logs:\n%s", buf.String())
	}
	if len(fm.invalidated) == 0 {
		t.Errorf("expected slot-state cache invalidation")
	}
}

func TestCredSource_FlipToLocal(t *testing.T) {
	slot := &Slot{ID: "1", SlotName: "slot-calm_dassie", State: "claimed", CredSource: "seedling/v1",
		NomadTokenSecret: "NT", MinioAccessKey: "calm_dassie", MinioSecretKey: "MS", GroupName: "g", OpaqueTokenHash: "abc"}
	fm := newFakeManager(slot)
	s, _ := mgrServer(t, fm, "op-secret")
	rr := post(t, s, "/manage/slots/slot-calm_dassie/cred-source", `{"cred_source":"local"}`,
		map[string]string{"X-Operator-Token": "op-secret"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d (%s)", rr.Code, rr.Body.String())
	}
	var resp credSourceResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.Changed || resp.CredSource != "local" || resp.OpaqueToken != "" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestCredSource_NoChange(t *testing.T) {
	slot := &Slot{ID: "1", SlotName: "slot-x", State: "claimed", CredSource: "local"}
	s, _ := mgrServer(t, newFakeManager(slot), "op-secret")
	rr := post(t, s, "/manage/slots/slot-x/cred-source", `{"cred_source":"local"}`,
		map[string]string{"X-Operator-Token": "op-secret"})
	var resp credSourceResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusOK || resp.Changed {
		t.Fatalf("status=%d changed=%v, want 200 changed=false", rr.Code, resp.Changed)
	}
}

func TestCredSource_InvalidValue(t *testing.T) {
	s, _ := mgrServer(t, newFakeManager(&Slot{}), "op-secret")
	rr := post(t, s, "/manage/slots/slot-x/cred-source", `{"cred_source":"bogus"}`,
		map[string]string{"X-Operator-Token": "op-secret"})
	if rr.Code != http.StatusBadRequest || !strings.Contains(decodeErr(t, rr), "invalid_cred_source") {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}
