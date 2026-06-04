package authsvc

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecret = "test-session-secret-key"

func valServer(t *testing.T, state, shadowURL string) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.SessionSecret = testSecret
	cfg.ShadowValidateURL = shadowURL
	store := fakeStore{
		find:  func(context.Context, string) (*Slot, error) { return nil, nil },
		state: func(context.Context, string) string { return state },
	}
	up := Upstreams{Nomad: mockNomad{}, Hub: mockHub{}, Store: store, Cluster: testCluster}
	return NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up), &buf
}

func tokenFor(user string, ttl time.Duration) string {
	return sessionVerifier{secret: []byte(testSecret)}.make(user, ttl)
}

func getWithCookie(t *testing.T, s *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Cookie", sessionCookieName+"="+token)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	return rr
}

// ── session HMAC ──────────────────────────────────────────────────────────────

func TestSession_RoundTrip(t *testing.T) {
	v := sessionVerifier{secret: []byte(testSecret)}
	tok := v.make("alice", time.Hour)
	user, ok := v.verify(tok)
	if !ok || user != "alice" {
		t.Fatalf("verify = %q,%v", user, ok)
	}
}

func TestSession_Tampered(t *testing.T) {
	v := sessionVerifier{secret: []byte(testSecret)}
	tok := v.make("alice", time.Hour)
	if _, ok := v.verify(tok + "x"); ok {
		t.Fatal("tampered token verified")
	}
}

func TestSession_Expired(t *testing.T) {
	v := sessionVerifier{secret: []byte(testSecret)}
	if _, ok := v.verify(v.make("alice", -time.Minute)); ok {
		t.Fatal("expired token verified")
	}
}

func TestSession_WrongSecret(t *testing.T) {
	tok := sessionVerifier{secret: []byte("secret-A")}.make("alice", time.Hour)
	if _, ok := (sessionVerifier{secret: []byte("secret-B")}).verify(tok); ok {
		t.Fatal("token verified under the wrong secret")
	}
}

func TestSession_UsernameWithColon(t *testing.T) {
	v := sessionVerifier{secret: []byte(testSecret)}
	user, ok := v.verify(v.make("ns:role:bob", time.Hour))
	if !ok || user != "ns:role:bob" {
		t.Fatalf("colon username = %q,%v", user, ok)
	}
}

// ── /validate ─────────────────────────────────────────────────────────────────

func TestValidate_ValidSession(t *testing.T) {
	s, _ := valServer(t, "none", "")
	rr := getWithCookie(t, s, "/validate", tokenFor("alice", time.Hour))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	for _, h := range []string{"Remote-User", "X-Auth-User", "X-WEBAUTH-USER"} {
		if rr.Header().Get(h) != "alice" {
			t.Errorf("%s = %q, want alice", h, rr.Header().Get(h))
		}
	}
}

func TestValidate_NoCookie(t *testing.T) {
	s, _ := valServer(t, "none", "")
	r := httptest.NewRequest(http.MethodGet, "/validate", nil)
	r.Header.Set("X-Forwarded-Uri", "/lab/tree")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "/auth/login?next=") || !strings.Contains(loc, "%2Flab%2Ftree") {
		t.Errorf("Location = %q", loc)
	}
}

func TestValidate_InvalidCookie(t *testing.T) {
	s, _ := valServer(t, "none", "")
	rr := getWithCookie(t, s, "/validate", "not-a-valid-token")
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
}

func TestValidate_SuspendedClearsCookie(t *testing.T) {
	s, _ := valServer(t, "suspended", "")
	rr := getWithCookie(t, s, "/validate", tokenFor("alice", time.Hour))
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if rr.Header().Get("Location") != "/auth/login" {
		t.Errorf("Location = %q", rr.Header().Get("Location"))
	}
	sc := rr.Header().Get("Set-Cookie")
	if !strings.Contains(sc, sessionCookieName+"=") || !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("expected cleared cookie, Set-Cookie = %q", sc)
	}
}

// ── /validate-optional ────────────────────────────────────────────────────────

func TestValidateOptional_Valid(t *testing.T) {
	s, _ := valServer(t, "none", "")
	rr := getWithCookie(t, s, "/validate-optional", tokenFor("alice", time.Hour))
	if rr.Code != http.StatusOK || rr.Header().Get("Remote-User") != "alice" {
		t.Fatalf("status=%d user=%q", rr.Code, rr.Header().Get("Remote-User"))
	}
}

func TestValidateOptional_Anonymous(t *testing.T) {
	s, _ := valServer(t, "none", "")
	rr := getWithCookie(t, s, "/validate-optional", "")
	if rr.Code != http.StatusOK || rr.Header().Get("Remote-User") != "" {
		t.Fatalf("status=%d user=%q, want 200 + no user", rr.Code, rr.Header().Get("Remote-User"))
	}
}

func TestValidateOptional_SuspendedNoHeaders(t *testing.T) {
	s, _ := valServer(t, "suspended", "")
	rr := getWithCookie(t, s, "/validate-optional", tokenFor("alice", time.Hour))
	if rr.Code != http.StatusOK || rr.Header().Get("Remote-User") != "" {
		t.Fatalf("status=%d user=%q, want 200 + no user", rr.Code, rr.Header().Get("Remote-User"))
	}
}

// ── /validate-shadow ──────────────────────────────────────────────────────────

func TestValidateShadow_Agree(t *testing.T) {
	py := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Remote-User", "alice")
		w.WriteHeader(http.StatusOK)
	}))
	defer py.Close()

	s, buf := valServer(t, "none", py.URL)
	rr := getWithCookie(t, s, "/validate-shadow", tokenFor("alice", time.Hour))
	if rr.Code != http.StatusOK || rr.Header().Get("Remote-User") != "alice" {
		t.Fatalf("status=%d user=%q (Go verdict)", rr.Code, rr.Header().Get("Remote-User"))
	}
	if strings.Contains(buf.String(), "validate.shadow.disagree") {
		t.Errorf("unexpected disagreement:\n%s", buf.String())
	}
}

func TestValidateShadow_Disagree(t *testing.T) {
	// Python denies (302) while Go allows — must be logged.
	py := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/auth/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer py.Close()

	s, buf := valServer(t, "none", py.URL)
	rr := getWithCookie(t, s, "/validate-shadow", tokenFor("alice", time.Hour))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (Go verdict returned)", rr.Code)
	}
	if !strings.Contains(buf.String(), "validate.shadow.disagree") {
		t.Errorf("expected a disagreement log:\n%s", buf.String())
	}
}
