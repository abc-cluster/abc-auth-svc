package authsvc

import (
	"log/slog"
	"net/http"
	"time"
)

// debugRoundTripper wraps an upstream http.Client transport and emits one L3
// (trace) record per call: method, scheme+host, path (NO query — namespaces /
// var-paths are fine to log but query strings are dropped for brevity and to
// keep any future token-in-query out of logs), status, and duration. On a
// transport error it logs the error instead of a status.
//
// Why this exists: every auth-svc bug this quarter (the slot- jh_user
// mismatch, the placeholder JH admin token, the unreachable-Hub probe) was
// ultimately "which upstream call returned what". With this tracer, flipping
// the level to trace (POST /manage/log-level {"level":"trace"}) shows the
// full upstream conversation for any request, correlated by rid — no
// alloc-exec + tcpdump archaeology.
//
// The record uses the request-scoped logger when present (so it carries the
// rid), falling back to the service base logger for non-request calls (the
// startup JH probe). Secrets never appear: auth-svc passes all upstream
// credentials in headers, which this tracer does not log, and the redacting
// handler scrubs values regardless.
type debugRoundTripper struct {
	base http.RoundTripper
	log  *slog.Logger // fallback when ctx carries no bound logger
}

func (d debugRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	lg := FromContext(req.Context())
	if lg == discardLogger {
		lg = d.log
	}
	start := time.Now()
	resp, err := d.base.RoundTrip(req)
	dur := time.Since(start)

	ctx := req.Context()
	if err != nil {
		lg.LogAttrs(ctx, L3, "upstream.call",
			slog.String("method", req.Method),
			slog.String("host", req.URL.Host),
			slog.String("path", req.URL.Path),
			slog.String("error", err.Error()),
			slog.Int64("ms", dur.Milliseconds()),
		)
		return resp, err
	}
	lg.LogAttrs(ctx, L3, "upstream.call",
		slog.String("method", req.Method),
		slog.String("host", req.URL.Host),
		slog.String("path", req.URL.Path),
		slog.Int("status", resp.StatusCode),
		slog.Int64("ms", dur.Milliseconds()),
	)
	return resp, err
}

// withDebugTransport wraps c.Transport (or http.DefaultTransport) with the L3
// upstream tracer and returns c. Mutates and returns the same client for
// fluent use in BuildUpstreams.
func withDebugTransport(c *http.Client, log *slog.Logger) *http.Client {
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = debugRoundTripper{base: base, log: log}
	return c
}
