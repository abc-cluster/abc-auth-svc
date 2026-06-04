package authsvc

import (
	"io"
	"log/slog"
)

// NewLogger builds the service logger: JSON to w (stderr in production, where
// Loki scrapes it), wrapped in a RedactingHandler so field-name and value-pattern
// redaction (Bearer …, tskey-auth-…, PEM, scheme://user:pass@…) apply to every
// record.
//
// Phase 1b will wrap this further with an exact-value scrub of the service's own
// injected env secrets (SESSION_SECRET, NOMAD_TOKEN, …) once those secrets
// actually flow. In Phase 0 no secrets are in scope, so the value-pattern net is
// sufficient.
func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(NewRedactingHandler(base))
}
