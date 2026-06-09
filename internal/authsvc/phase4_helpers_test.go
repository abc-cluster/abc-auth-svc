package authsvc

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Phase-4 test doubles ──────────────────────────────────────────────────────
//
// These complement the read-path fakes in exchange_test.go / phase1b_test.go
// with the operator-tier admin surfaces the Phase-4 handlers drive. Named
// rec* (recording) to avoid colliding with the production mock* doubles used
// by --mock-upstreams.

// recNomadAdmin records VarPut/VarGet/CreateToken/DeleteToken/GetRoleID calls.
type recNomadAdmin struct {
	vars      map[string]string // "ns|path" -> value
	created   []string          // slot names CreateToken was called for
	deleted   []string          // accessors DeleteToken was called for
	roleID    string            // value GetRoleID returns
	varGetErr error             // forced VarGet error (besides ErrVarNotFound)
	createErr error             // forced CreateToken error
}

func newRecNomadAdmin() *recNomadAdmin {
	return &recNomadAdmin{vars: map[string]string{}, roleID: "role-abc"}
}

func (f *recNomadAdmin) key(ns, path string) string { return ns + "|" + path }

func (f *recNomadAdmin) VarGet(_ context.Context, ns, path string) (string, error) {
	if f.varGetErr != nil {
		return "", f.varGetErr
	}
	v, ok := f.vars[f.key(ns, path)]
	if !ok {
		return "", ErrVarNotFound
	}
	return v, nil
}
func (f *recNomadAdmin) VarPut(_ context.Context, ns, path, value string) error {
	if f.vars == nil {
		f.vars = map[string]string{}
	}
	f.vars[f.key(ns, path)] = value
	return nil
}
func (f *recNomadAdmin) CreateToken(_ context.Context, slot, _ string) (string, string, error) {
	if f.createErr != nil {
		return "", "", f.createErr
	}
	f.created = append(f.created, slot)
	return "acc-" + slot, "tok-" + slot, nil
}
func (f *recNomadAdmin) DeleteToken(_ context.Context, accessor string) error {
	f.deleted = append(f.deleted, accessor)
	return nil
}
func (f *recNomadAdmin) GetRoleID(_ context.Context, _ string) (string, error) {
	return f.roleID, nil
}

// recMinioAdmin records RotateSecret / SetEnabled calls.
type recMinioAdmin struct {
	rotated   []string        // users RotateSecret was called for
	enabled   map[string]bool // last enable/disable state per user
	rotateErr error
}

func newRecMinioAdmin() *recMinioAdmin { return &recMinioAdmin{enabled: map[string]bool{}} }

func (f *recMinioAdmin) RotateSecret(_ context.Context, user string) (string, error) {
	if f.rotateErr != nil {
		return "", f.rotateErr
	}
	f.rotated = append(f.rotated, user)
	return "newsecret-" + user, nil
}
func (f *recMinioAdmin) SetEnabled(_ context.Context, user string, enabled bool) error {
	if f.enabled == nil {
		f.enabled = map[string]bool{}
	}
	f.enabled[user] = enabled
	return nil
}

// recManager is a SlotManager that records patches AND applies the common
// fields back onto the held slot, so a subsequent FindSlot reflects the
// mutation (lets rotate/suspend/reactivate tests assert state transitions).
type recManager struct {
	slot        *Slot
	patches     []map[string]any
	invalidated []string
	findErr     error
	findResult  func(filter string) *Slot // optional filter-aware override
}

func newRecManager(slot *Slot) *recManager { return &recManager{slot: slot} }

func (m *recManager) FindSlot(_ context.Context, filter string) (*Slot, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	if m.findResult != nil {
		return m.findResult(filter), nil
	}
	return m.slot, nil
}
func (m *recManager) GroupName(_ context.Context, slot *Slot) string {
	if slot != nil {
		return slot.GroupName
	}
	return ""
}
func (m *recManager) CachedSlotState(_ context.Context, _ string) string {
	if m.slot != nil && m.slot.State != "" {
		return m.slot.State
	}
	return "none"
}
func (m *recManager) GetSlot(_ context.Context, _ string) (*Slot, error) { return m.slot, nil }
func (m *recManager) PatchSlot(_ context.Context, _ string, fields map[string]any) error {
	m.patches = append(m.patches, fields)
	if m.slot != nil {
		applyPatchToSlot(m.slot, fields)
	}
	return nil
}
func (m *recManager) InvalidateSlotState(u string) { m.invalidated = append(m.invalidated, u) }
func (m *recManager) ListSlots(_ context.Context, _ string, _ int) ([]Slot, error) {
	if m.slot == nil {
		return nil, nil
	}
	return []Slot{*m.slot}, nil
}

// lastPatch returns the most recent PatchSlot fields, or nil.
func (m *recManager) lastPatch() map[string]any {
	if len(m.patches) == 0 {
		return nil
	}
	return m.patches[len(m.patches)-1]
}

// patchWith returns the first recorded patch that contains key, or nil. Use
// this instead of lastPatch when a handler emits several patches (e.g. the
// creds/state patch followed by the persistSlotConfig config_yaml write) and
// the test cares about a specific one.
func (m *recManager) patchWith(key string) map[string]any {
	for _, p := range m.patches {
		if _, ok := p[key]; ok {
			return p
		}
	}
	return nil
}

// applyPatchToSlot mirrors the subset of fields the handlers patch so a
// re-read sees the new values.
func applyPatchToSlot(s *Slot, fields map[string]any) {
	set := func(k string, dst *string) {
		if v, ok := fields[k].(string); ok {
			*dst = v
		}
	}
	set("state", &s.State)
	set("minio_secret_key", &s.MinioSecretKey)
	set("nomad_token_accessor", &s.NomadTokenAccessor)
	set("nomad_token_secret", &s.NomadTokenSecret)
	set("cred_source", &s.CredSource)
	set("opaque_token_hash", &s.OpaqueTokenHash)
	set("claimed_by_name", &s.ClaimedByName)
	set("claimed_by_email", &s.ClaimedByEmail)
	set("claimed_at", &s.ClaimedAt)
}

// newP4Server builds a Server wired with the given Upstreams + operator
// token, filling Cluster/HubPublicURL defaults. Returns the server + its log
// buffer so tests can assert on emitted records.
func newP4Server(t *testing.T, opToken string, up Upstreams) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.OperatorToken = opToken
	if up.Cluster.Name == "" {
		up.Cluster = testCluster
	}
	if up.HubPublicURL == "" {
		up.HubPublicURL = "https://hub.test"
	}
	return NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up), &buf
}

// redirectTestDirs points credsDir/abcConfigDir at t.TempDir() for the
// duration of a test so the file-writing handlers (claim, rotate, reactivate,
// suspend) don't touch the host /etc. Restores the originals on cleanup.
func redirectTestDirs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origCreds, origCfg := credsDir, abcConfigDir
	credsDir = dir + "/minio-creds"
	abcConfigDir = dir + "/abc-configs"
	t.Cleanup(func() { credsDir, abcConfigDir = origCreds, origCfg })
	return dir
}

// postJSON sends a POST with a JSON body + optional headers.
func postJSON(t *testing.T, s *Server, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	return rr
}

// opHdr returns the operator-token header map.
func opHdr(tok string) map[string]string { return map[string]string{"X-Operator-Token": tok} }

// httptestGETWithReq serves a pre-built request (e.g. one carrying a cookie)
// and returns the recorder.
func httptestGETWithReq(t *testing.T, s *Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	return rr
}
