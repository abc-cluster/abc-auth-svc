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
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	var h slog.Handler = NewRedactingHandler(base)
	h = wrapScrub(h, scrubSecrets) // outer: exact-value scrub runs first
	return slog.New(h)
}
