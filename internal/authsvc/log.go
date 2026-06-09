package authsvc

import (
	"io"
	"log/slog"
)

// NewLogger builds the service logger: JSON to w (stderr in production, where
// Loki scrapes it), wrapped so every record is redacted before it is written.
//
// Two layers: a RedactingHandler (field-name + value-pattern: Bearer …,
// tskey-auth-…, PEM, scheme://user:pass@…), and an outer exact-value scrub of the
// service's own injected secrets (scrubSecrets, e.g. the JupyterHub admin token)
// so a known credential can never appear even if a record echoes it.
func NewLogger(w io.Writer, level slog.Level, scrubSecrets []string) *slog.Logger {
	l, _ := NewLeveledLogger(w, level, scrubSecrets)
	return l
}

// NewLeveledLogger is NewLogger plus a *slog.LevelVar so the caller can change
// the active level at runtime without rebuilding the logger or restarting the
// process. main.go stores the returned LevelVar on the Server and exposes it
// via POST /manage/log-level, so an operator can flip to debug/trace mid-flight
// to capture an issue, then flip back — without bouncing the service (which
// would tear down every active forward-auth session). Tests use the plain
// NewLogger and ignore the LevelVar.
func NewLeveledLogger(w io.Writer, level slog.Level, scrubSecrets []string) (*slog.Logger, *slog.LevelVar) {
	lv := new(slog.LevelVar)
	lv.Set(level)
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})
	var h slog.Handler = NewRedactingHandler(base)
	h = wrapScrub(h, scrubSecrets) // outer: exact-value scrub runs first
	return slog.New(h), lv
}
