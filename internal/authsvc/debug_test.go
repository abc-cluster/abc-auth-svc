package authsvc

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDebugRoundTripper_TracesUpstreamCalls verifies the L3 upstream tracer
// emits one record per call carrying method/host/path/status — the trace that
// makes "which upstream returned what" a log read instead of a tcpdump.
func TestDebugRoundTripper_TracesUpstreamCalls(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // 418 — distinctive
	}))
	defer upstream.Close()

	var buf bytes.Buffer
	logger := NewLogger(&buf, L3, nil) // trace level
	client := withDebugTransport(&http.Client{}, logger)

	// Bind the logger into the request context (as the handlers do) so the
	// tracer logs via the request-scoped logger.
	ctx := WithLogger(context.Background(), logger)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/v1/acl/token/self", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	out := buf.String()
	if !strings.Contains(out, `"msg":"upstream.call"`) {
		t.Fatalf("no upstream.call record:\n%s", out)
	}
	if !strings.Contains(out, `"status":418`) {
		t.Errorf("status not traced:\n%s", out)
	}
	if !strings.Contains(out, `"path":"/v1/acl/token/self"`) {
		t.Errorf("path not traced:\n%s", out)
	}
	if !strings.Contains(out, `"method":"GET"`) {
		t.Errorf("method not traced:\n%s", out)
	}
}

func TestDebugRoundTripper_SilentAtInfoLevel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	var buf bytes.Buffer
	logger := NewLogger(&buf, L1, nil) // info — L3 records suppressed
	client := withDebugTransport(&http.Client{}, logger)
	ctx := WithLogger(context.Background(), logger)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if strings.Contains(buf.String(), "upstream.call") {
		t.Errorf("upstream.call must be suppressed at info level:\n%s", buf.String())
	}
}
