package authsvc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer builds a server whose logs go to buf, for assertion.
func newTestServer(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := NewLogger(&buf, L1)
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return NewServer(cfg, logger, BuildInfo{Version: "test"}), &buf
}

func TestHealthz(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("X-Abc-Auth-API-Version"); got != "v1" {
		t.Errorf("API version header = %q, want v1", got)
	}
	if rr.Header().Get("X-Request-Id") == "" {
		t.Errorf("missing X-Request-Id header")
	}
	if !strings.Contains(rr.Body.String(), "ok") {
		t.Errorf("body = %q, want it to contain ok", rr.Body.String())
	}
}

func TestReadyz(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp readyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /readyz: %v (body %q)", err, rr.Body.String())
	}
	if resp.Status != "ready" {
		t.Errorf("status = %q, want ready", resp.Status)
	}
	if resp.Version != "test" {
		t.Errorf("version = %q, want test", resp.Version)
	}
}

func TestVersion(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var bi BuildInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &bi); err != nil {
		t.Fatalf("decode /version: %v", err)
	}
	if bi.Version != "test" {
		t.Errorf("version = %q, want test", bi.Version)
	}
}

func TestNotFound(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/no/such/path", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

// TestAccessLog_PathOnly_NoTokenLeak is the security guarantee for the access
// log: a token in the query string must NOT appear in any log line, and the path
// (without query) must be logged.
func TestAccessLog_PathOnly_NoTokenLeak(t *testing.T) {
	s, buf := newTestServer(t)
	const secret = "SUPERSECRETTOKEN1234567890"
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz?token="+secret, nil))

	logs := buf.String()
	if !strings.Contains(logs, `"msg":"http.access"`) {
		t.Fatalf("no http.access record emitted; logs:\n%s", logs)
	}
	if !strings.Contains(logs, `"path":"/healthz"`) {
		t.Errorf("expected path-only %q in logs:\n%s", "/healthz", logs)
	}
	if strings.Contains(logs, secret) {
		t.Errorf("SECRET LEAKED into access log:\n%s", logs)
	}
}

// TestAccessLog_NoAuthHeaderLeak: an Authorization bearer must not reach the logs.
func TestAccessLog_NoAuthHeaderLeak(t *testing.T) {
	s, buf := newTestServer(t)
	const bearer = "abcDEF1234567890ghiJKLmnop"
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Cookie", "abc_session="+bearer)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if strings.Contains(buf.String(), bearer) {
		t.Errorf("Authorization/Cookie value leaked into logs:\n%s", buf.String())
	}
}

func TestRequestID_EchoAndSanitize(t *testing.T) {
	s, _ := newTestServer(t)

	// Valid inbound id is echoed.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "abc-123_DEF")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if got := rr.Header().Get("X-Request-Id"); got != "abc-123_DEF" {
		t.Errorf("echoed rid = %q, want abc-123_DEF", got)
	}

	// Unsafe inbound id (spaces) is dropped → a fresh id is generated.
	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req2.Header.Set("X-Request-Id", "bad id with spaces")
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req2)
	got := rr2.Header().Get("X-Request-Id")
	if got == "" || strings.Contains(got, " ") {
		t.Errorf("unsafe rid not replaced: %q", got)
	}
}
