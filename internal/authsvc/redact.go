package authsvc

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
)

// Log levels. Unlike some other ABC tools, L3 (trace) is a distinct value below
// L2 (debug) so the three levels are individually selectable.
const (
	L1 = slog.LevelInfo  // 0  — errors + key events (access log)
	L2 = slog.LevelDebug // -4 — HTTP detail
	L3 = slog.Level(-8)  // trace — max verbosity
)

// ── Context-bound logger ──────────────────────────────────────────────────────

type loggerKey struct{}

// discardLogger is returned by FromContext when no logger is bound, so callers
// never need a nil check.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// WithLogger binds a logger into ctx (e.g. a per-request child carrying the
// request id).
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

// FromContext returns the logger bound by WithLogger, or a discard logger.
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return discardLogger
}

// ── Redacting slog handler ────────────────────────────────────────────────────
//
// This is a self-contained copy of the redaction pattern used across ABC Go
// tools: field-name redaction (any attribute whose key names a secret) plus
// value-pattern redaction (Bearer tokens, tailscale keys, PEM blocks, passwords
// embedded in connection strings) applied to every string value. As an auth
// service we err on the side of more sensitive key names.

var sensitiveKeys = map[string]bool{
	"password":           true,
	"pass":               true,
	"passwd":             true,
	"private_key":        true,
	"pem":                true,
	"secret":             true,
	"secret_key":         true,
	"access_token":       true,
	"upload_token":       true,
	"token":              true,
	"bearer_token":       true,
	"auth_key":           true,
	"tailscale_auth_key": true,
	"ts_authkey":         true,
	"credential":         true,
	"credentials":        true,
	"session_secret":     true,
	"nomad_token":        true,
	"claim_code":         true,
	"opaque_token":       true,
	"cookie":             true,
	"authorization":      true,
}

type valuePattern struct {
	re  *regexp.Regexp
	rep string
}

var valuePatterns = []valuePattern{
	{regexp.MustCompile(`(?s)-----BEGIN .{0,30}PRIVATE KEY-----.*?-----END .{0,30}PRIVATE KEY-----`), "[REDACTED: private-key]"},
	{regexp.MustCompile(`tskey-auth-[A-Za-z0-9_-]{10,}`), "[REDACTED: tailscale-key]"},
	{regexp.MustCompile(`[Bb]earer [A-Za-z0-9.\-_]{20,}`), "Bearer [REDACTED]"},
	{regexp.MustCompile(`://[^:@/\s]+:[^@/\s]{6,}@`), "://[REDACTED]@"},
}

func redactValue(s string) string {
	for _, p := range valuePatterns {
		s = p.re.ReplaceAllString(s, p.rep)
	}
	return s
}

// RedactingHandler wraps an slog.Handler and scrubs sensitive attributes before
// they reach the underlying handler.
type RedactingHandler struct{ inner slog.Handler }

// NewRedactingHandler wraps inner with field-name + value-pattern redaction.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = scrubAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(scrubbed)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func scrubAttr(a slog.Attr) slog.Attr {
	if sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, "[REDACTED]")
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		sub := a.Value.Group()
		out := make([]any, len(sub))
		for i, s := range sub {
			out[i] = scrubAttr(s)
		}
		return slog.Group(a.Key, out...)
	case slog.KindString:
		return slog.String(a.Key, redactValue(a.Value.String()))
	}
	return a
}

// ── Exact-value secret scrub ──────────────────────────────────────────────────
//
// scrubHandler replaces exact occurrences of the service's own injected secrets
// (e.g. the JupyterHub admin token) with a placeholder, wherever they appear in
// a string message or attribute value. This is the slog analogue of the support
// bundle's known-secret scrub: it guarantees the service's own credentials never
// reach the log even if some record echoes one — while UUID-shaped non-secrets
// (alloc/eval IDs) survive because they don't equal a known secret. Secrets
// shorter than 6 chars are ignored.

type scrubHandler struct {
	inner   slog.Handler
	secrets []string // deduped, longest-first, len>=6
}

// wrapScrub wraps inner with an exact-value secret scrub. If no usable secrets
// are supplied it returns inner unchanged (no overhead).
func wrapScrub(inner slog.Handler, secrets []string) slog.Handler {
	seen := make(map[string]bool, len(secrets))
	keep := make([]string, 0, len(secrets))
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if len(s) >= 6 && !seen[s] {
			seen[s] = true
			keep = append(keep, s)
		}
	}
	if len(keep) == 0 {
		return inner
	}
	sort.SliceStable(keep, func(i, j int) bool { return len(keep[i]) > len(keep[j]) })
	return &scrubHandler{inner: inner, secrets: keep}
}

func (h *scrubHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *scrubHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, h.scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(h.scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

func (h *scrubHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = h.scrubAttr(a)
	}
	return &scrubHandler{inner: h.inner.WithAttrs(out), secrets: h.secrets}
}

func (h *scrubHandler) WithGroup(name string) slog.Handler {
	return &scrubHandler{inner: h.inner.WithGroup(name), secrets: h.secrets}
}

func (h *scrubHandler) scrub(s string) string {
	for _, sec := range h.secrets {
		s = strings.ReplaceAll(s, sec, "[REDACTED:secret]")
	}
	return s
}

func (h *scrubHandler) scrubAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindGroup:
		sub := a.Value.Group()
		out := make([]any, len(sub))
		for i, s := range sub {
			out[i] = h.scrubAttr(s)
		}
		return slog.Group(a.Key, out...)
	case slog.KindString:
		return slog.String(a.Key, h.scrub(a.Value.String()))
	}
	return a
}
