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

func TestStatusWriter_CapturesStatusAndBytes(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, status: http.StatusOK}
	sw.WriteHeader(http.StatusTeapot)
	n, _ := sw.Write([]byte("hello"))

	if sw.status != http.StatusTeapot {
		t.Errorf("status = %d, want 418", sw.status)
	}
	if sw.bytes != n || sw.bytes != 5 {
		t.Errorf("bytes = %d, want 5", sw.bytes)
	}
}

// TestRecoverer_RecoversPanicAnd500 verifies a handler panic becomes a 500, is
// logged, and the access record still emits with status 500 (Recoverer inside
// AccessLog).
func TestRecoverer_RecoversPanicAnd500(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, L1, nil)

	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	h := chain(panicky,
		withBaseLogger(logger),
		RequestID,
		AccessLog,
		Recoverer,
	)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
	logs := buf.String()
	if !strings.Contains(logs, `"msg":"http.panic"`) {
		t.Errorf("missing http.panic record:\n%s", logs)
	}
	if !strings.Contains(logs, `"msg":"http.access"`) || !strings.Contains(logs, `"status":500`) {
		t.Errorf("access record should report status 500:\n%s", logs)
	}
}

func TestRequestIDFromContext(t *testing.T) {
	var got string
	h := chain(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = RequestIDFromContext(r.Context())
		}),
		RequestID,
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Request-Id", "fixed-rid-1")
	h.ServeHTTP(rr, req)

	if got != "fixed-rid-1" {
		t.Errorf("RequestIDFromContext = %q, want fixed-rid-1", got)
	}
}

func TestSanitizeRequestID(t *testing.T) {
	cases := map[string]string{
		"abc-123_DEF":           "abc-123_DEF",
		"":                      "",
		"has space":             "",
		"semi;colon":            "",
		strings.Repeat("a", 65): "", // too long
	}
	for in, want := range cases {
		if got := sanitizeRequestID(in); got != want {
			t.Errorf("sanitizeRequestID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRedactingHandler_FieldAndPattern proves both redaction modes: a sensitive
// KEY is replaced, and a Bearer token in any string VALUE is caught by the
// value-pattern net.
func TestRedactingHandler_FieldAndPattern(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, L1, nil)
	logger.Info("test",
		"access_token", "should-be-hidden-by-key",
		"note", "Authorization: Bearer abcDEF1234567890ghiJKL9876",
	)
	logs := buf.String()
	if strings.Contains(logs, "should-be-hidden-by-key") {
		t.Errorf("sensitive key value leaked:\n%s", logs)
	}
	if strings.Contains(logs, "abcDEF1234567890ghiJKL9876") {
		t.Errorf("Bearer token not redacted by value pattern:\n%s", logs)
	}
}

func TestGracefulShutdown(t *testing.T) {
	var buf bytes.Buffer
	cfg, err := LoadConfig([]string{"-listen", "127.0.0.1:0"}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	s := NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, Upstreams{Nomad: mockNomad{}, Hub: mockHub{}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	time.Sleep(50 * time.Millisecond) // let the listener come up
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error on graceful shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within shutdown grace window")
	}
}
