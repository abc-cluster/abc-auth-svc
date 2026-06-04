package authsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

const requestIDHeader = "X-Request-Id"

// statusWriter wraps http.ResponseWriter to capture the status code and bytes
// written, for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Flush forwards to the underlying writer when it supports http.Flusher.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withBaseLogger seeds the service logger into every request context so that
// middleware and handlers retrieve it via FromContext. Used instead of
// http.Server.BaseContext so the chain behaves identically under httptest.
func withBaseLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithLogger(r.Context(), logger)))
		})
	}
}

// VersionHeader stamps X-Abc-Auth-API-Version on every response.
func VersionHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Abc-Auth-API-Version", APIVersion)
		next.ServeHTTP(w, r)
	})
}

// RequestID ensures every request has a correlation id (accepted from the inbound
// X-Request-Id header when safe, else freshly generated), echoes it on the
// response, and binds a child logger carrying rid into the request context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := sanitizeRequestID(r.Header.Get(requestIDHeader))
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set(requestIDHeader, rid)

		ctx := context.WithValue(r.Context(), ridKey{}, rid)
		ctx = WithLogger(ctx, FromContext(ctx).With(slog.String("rid", rid)))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AccessLog emits exactly one http.access record per request through the redacting
// logger. It logs the PATH ONLY (never the query string — magic-link/CLI tokens
// live there) and never reads Authorization/Cookie headers. The record is emitted
// in a defer so a panicked request (recovered downstream) is still logged with its
// final status.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		ctx := r.Context()
		defer func() {
			FromContext(ctx).LogAttrs(ctx, L1, "http.access",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path), // PATH ONLY — never RawQuery
				slog.Int("status", sw.status),
				slog.Int("bytes", sw.bytes),
				slog.Int64("ms", time.Since(start).Milliseconds()),
				slog.String("user", r.Header.Get("Remote-User")),
				slog.String("xff", r.Header.Get("X-Forwarded-For")),
			)
		}()
		next.ServeHTTP(sw, r)
	})
}

// Recoverer converts a handler panic into a 500 and a logged http.panic record,
// keeping the process alive. It runs inside AccessLog so the access record sees
// the 500 status.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				ctx := r.Context()
				FromContext(ctx).LogAttrs(ctx, L1, "http.panic",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Any("panic", rec),
				)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// chain applies middleware so the first listed runs outermost.
func chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

type ridKey struct{}

// RequestIDFromContext returns the correlation id bound by RequestID, if any.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ridKey{}).(string); ok {
		return v
	}
	return ""
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "rid-unknown"
	}
	return hex.EncodeToString(b[:])
}

// sanitizeRequestID accepts only short, [A-Za-z0-9-_] inbound request ids, to
// defend against log-injection via the header. Anything else is dropped so a
// fresh id is generated.
func sanitizeRequestID(s string) string {
	if len(s) == 0 || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return ""
		}
	}
	return s
}
