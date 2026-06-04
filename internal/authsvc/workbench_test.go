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

// ── configurable test doubles ─────────────────────────────────────────────────

type fakeNomad struct {
	fn func(ctx context.Context, token string) (*NomadTokenSelf, error)
}

func (f fakeNomad) LookupTokenSelf(ctx context.Context, token string) (*NomadTokenSelf, error) {
	return f.fn(ctx, token)
}

type fakeHub struct {
	fn       func(ctx context.Context, user, note string, expiresIn int64) (*JHToken, error)
	lastUser string
	lastNote string
	lastTTL  int64
}

func (f *fakeHub) MintUserToken(ctx context.Context, user, note string, expiresIn int64) (*JHToken, error) {
	f.lastUser, f.lastNote, f.lastTTL = user, note, expiresIn
	return f.fn(ctx, user, note, expiresIn)
}

func wbServer(t *testing.T, nomad NomadValidator, hub HubMinter) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	up := Upstreams{Nomad: nomad, Hub: hub, HubPublicURL: "https://workbench.test"}
	return NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up), &buf
}

func okNomad(name string) fakeNomad {
	return fakeNomad{fn: func(context.Context, string) (*NomadTokenSelf, error) {
		return &NomadTokenSelf{Name: name, Type: "client"}, nil
	}}
}

func okHub() *fakeHub {
	return &fakeHub{fn: func(_ context.Context, user, note string, _ int64) (*JHToken, error) {
		return &JHToken{Token: "jh-" + user, ID: "id-1", ExpiresAt: "2026-06-11T00:00:00Z",
			Scopes: []string{"access:servers!user=" + user}, Note: note}, nil
	}}
}

func post(t *testing.T, s *Server, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
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

func decodeErr(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	return e.Error
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestWorkbenchToken_MissingToken(t *testing.T) {
	s, _ := wbServer(t, okNomad("pool-x"), okHub())
	rr := post(t, s, "/auth/workbench/token", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(decodeErr(t, rr), "missing token") {
		t.Errorf("error = %q", decodeErr(t, rr))
	}
}

func TestWorkbenchToken_InvalidToken(t *testing.T) {
	nomad := fakeNomad{fn: func(context.Context, string) (*NomadTokenSelf, error) {
		return nil, ErrInvalidToken
	}}
	s, _ := wbServer(t, nomad, okHub())
	rr := post(t, s, "/auth/workbench/token", "", map[string]string{"X-Nomad-Token": "bad"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(decodeErr(t, rr), "invalid or expired") {
		t.Errorf("error = %q", decodeErr(t, rr))
	}
}

func TestWorkbenchToken_EmptyName(t *testing.T) {
	s, _ := wbServer(t, okNomad("  "), okHub())
	rr := post(t, s, "/auth/workbench/token", "", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(decodeErr(t, rr), "could not determine username") {
		t.Errorf("error = %q", decodeErr(t, rr))
	}
}

func TestWorkbenchToken_PoolSlotDerivation(t *testing.T) {
	hub := okHub()
	s, _ := wbServer(t, okNomad("pool-calm_dassie"), hub)
	rr := post(t, s, "/auth/workbench/token", "", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	var resp mintResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Slot != "slot-calm_dassie" {
		t.Errorf("slot = %q, want slot-calm_dassie", resp.Slot)
	}
	if hub.lastUser != "slot-calm_dassie" {
		t.Errorf("JH user = %q, want slot-calm_dassie", hub.lastUser)
	}
	if resp.Token == "" || resp.HubURL != "https://workbench.test" {
		t.Errorf("missing token/hub_url: %+v", resp)
	}
	// default note derives from the bare (abc) user, not the slot.
	if hub.lastNote != "abc-cli-calm_dassie" {
		t.Errorf("default note = %q, want abc-cli-calm_dassie", hub.lastNote)
	}
	if hub.lastTTL != workbenchTokenDefaultTTL {
		t.Errorf("default TTL = %d, want %d", hub.lastTTL, workbenchTokenDefaultTTL)
	}
}

func TestWorkbenchToken_NamedTokenVerbatim(t *testing.T) {
	hub := okHub()
	s, _ := wbServer(t, okNomad("anel"), hub)
	rr := post(t, s, "/auth/workbench/token", "", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if hub.lastUser != "anel" {
		t.Errorf("JH user = %q, want anel (verbatim)", hub.lastUser)
	}
}

func TestWorkbenchToken_BearerAuthAndCustomBody(t *testing.T) {
	hub := okHub()
	s, _ := wbServer(t, okNomad("pool-x"), hub)
	rr := post(t, s, "/auth/workbench/token", `{"note":"my laptop","expires_in":3600}`,
		map[string]string{"Authorization": "Bearer sometoken", "Content-Type": "application/json"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	if hub.lastNote != "my laptop" {
		t.Errorf("note = %q, want 'my laptop'", hub.lastNote)
	}
	if hub.lastTTL != 3600 {
		t.Errorf("ttl = %d, want 3600", hub.lastTTL)
	}
}

func TestWorkbenchToken_ExpiresInValidation(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{`{"expires_in":-5}`, "must be positive"},
		{`{"expires_in":0}`, "must be positive"},
		{`{"expires_in":2592001}`, "cannot exceed 30 days"},
		{`{"expires_in":"abc"}`, "must be an integer"},
		{`{"expires_in":1.5}`, "must be an integer"},
		{`not json`, "invalid JSON body"},
	}
	for _, c := range cases {
		s, _ := wbServer(t, okNomad("pool-x"), okHub())
		rr := post(t, s, "/auth/workbench/token", c.body, map[string]string{"X-Nomad-Token": "t"})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", c.body, rr.Code)
		}
		if !strings.Contains(decodeErr(t, rr), c.want) {
			t.Errorf("body %q: error = %q, want contains %q", c.body, decodeErr(t, rr), c.want)
		}
	}
}

func TestWorkbenchToken_HubHTTPError502(t *testing.T) {
	hub := &fakeHub{fn: func(context.Context, string, string, int64) (*JHToken, error) {
		return nil, &HubError{Kind: hubHTTPError, Status: 500, Body: "boom"}
	}}
	s, _ := wbServer(t, okNomad("pool-x"), hub)
	rr := post(t, s, "/auth/workbench/token", "", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
}

func TestWorkbenchToken_HubUnreachable503(t *testing.T) {
	hub := &fakeHub{fn: func(context.Context, string, string, int64) (*JHToken, error) {
		return nil, &HubError{Kind: hubUnreachable, Err: context.DeadlineExceeded}
	}}
	s, _ := wbServer(t, okNomad("pool-x"), hub)
	rr := post(t, s, "/auth/workbench/token", "", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

// Both the stripped (/workbench/token) and prefixed (/auth/workbench/token) routes
// reach the handler.
func TestWorkbenchToken_BothRoutes(t *testing.T) {
	for _, p := range []string{"/workbench/token", "/auth/workbench/token"} {
		s, _ := wbServer(t, okNomad("pool-x"), okHub())
		rr := post(t, s, p, "", map[string]string{"X-Nomad-Token": "t"})
		if rr.Code != http.StatusOK {
			t.Errorf("path %s: status = %d, want 200", p, rr.Code)
		}
	}
}

// The JupyterHub admin token (injected via env) must never reach the logs.
func TestNewLogger_ExactSecretScrub(t *testing.T) {
	var buf bytes.Buffer
	const secret = "jh-admin-secret-abcdef123456"
	logger := NewLogger(&buf, L1, []string{secret})
	logger.Info("startup", "msg_with_secret", "token "+secret+" loaded")
	logger.Info("plain " + secret)
	if strings.Contains(buf.String(), secret) {
		t.Errorf("admin token leaked into logs:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "[REDACTED:secret]") {
		t.Errorf("expected scrub marker:\n%s", buf.String())
	}
}
