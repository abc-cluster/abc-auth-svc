package authsvc

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// These tests assert that the debug records we added specifically capture the
// two incidents this quarter — so a future regression is one `grep` away
// rather than another alloc-exec + journalctl hunt.

// debugServer builds a workbench-token server logging at L2 to a buffer.
func debugServer(t *testing.T, nomadName string) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.SessionSecret = "test-session-secret" // non-empty so make/verify round-trips
	up := Upstreams{Nomad: okNomad(nomadName), Hub: okHub(), HubPublicURL: "https://hub.test"}
	return NewServer(cfg, NewLogger(&buf, L2, nil), BuildInfo{Version: "test"}, up), &buf
}

// Bug A: the workbench mint must log the raw-token-name → jh_user derivation,
// showing the bare (un-prefixed) JH user that the 2026-06-09 403 turned on.
func TestDebugLog_WorkbenchTokenDerivation(t *testing.T) {
	s, buf := debugServer(t, "pool-solar_civet")
	rr := post(t, s, "/auth/workbench/token", `{"note":"x"}`,
		map[string]string{"X-Nomad-Token": "t", "Content-Type": "application/json"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"workbench.token.derive_user"`) {
		t.Fatalf("missing derive_user debug record:\n%s", out)
	}
	if !strings.Contains(out, `"raw_name":"pool-solar_civet"`) ||
		!strings.Contains(out, `"jh_user":"solar_civet"`) ||
		!strings.Contains(out, `"pooled":true`) {
		t.Errorf("derive_user record wrong (Bug A guard):\n%s", out)
	}
}

// Named (non-pool) tokens map verbatim — the other branch of the derivation.
func TestDebugLog_WorkbenchTokenDerivation_Named(t *testing.T) {
	s, buf := debugServer(t, "abhi")
	post(t, s, "/auth/workbench/token", `{}`,
		map[string]string{"X-Nomad-Token": "t", "Content-Type": "application/json"})
	out := buf.String()
	if !strings.Contains(out, `"raw_name":"abhi"`) ||
		!strings.Contains(out, `"jh_user":"abhi"`) ||
		!strings.Contains(out, `"pooled":false`) {
		t.Errorf("named derivation record wrong:\n%s", out)
	}
}

// /validate must log the decision branch — the record that answers
// "why Remote-User=<x>" or "why 302".
func TestDebugLog_ValidateDecision(t *testing.T) {
	s, buf := debugServer(t, "pool-x")
	// No cookie → "no_cookie" branch.
	httptestGET(t, s, "/validate", nil)
	if !strings.Contains(buf.String(), `"msg":"validate.decide"`) ||
		!strings.Contains(buf.String(), `"result":"no_cookie"`) {
		t.Errorf("validate.decide no_cookie not logged:\n%s", buf.String())
	}
}

func TestDebugLog_ValidateAllow(t *testing.T) {
	s, buf := debugServer(t, "pool-x")
	// Mint a session cookie via the server's own session signer, then validate.
	tok := s.session.make("solar_civet", s.cfg.SessionTTL)
	r, _ := http.NewRequest(http.MethodGet, "/validate", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok})
	rr := httptestGETWithReq(t, s, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("validate status=%d", rr.Code)
	}
	out := buf.String()
	if !strings.Contains(out, `"result":"allow"`) || !strings.Contains(out, `"user":"solar_civet"`) {
		t.Errorf("validate.decide allow not logged:\n%s", out)
	}
}
