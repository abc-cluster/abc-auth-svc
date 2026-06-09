package authsvc

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// handleLogLevel implements GET/POST /manage/log-level (operator-gated).
//
//	GET  → {"level": "info|debug|trace", "mutable": <bool>}
//	POST {"level": "info|debug|trace"} → sets the active level at runtime.
//
// Designed for the exact debugging loop this quarter's incidents needed:
// flip to "trace" to capture the full upstream conversation (debugRoundTripper
// L3 records) + the per-request decision logs (validate / workbench-token /
// magic-link L2), reproduce the issue, read the rid-correlated trace, then
// flip back to "info". No restart — so active forward-auth sessions survive.
//
// When the server was built without a LevelVar (tests, or a future static
// deployment), POST returns 409 and GET reports mutable=false.
func (s *Server) handleLogLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	if !s.requireOperator(w, r) {
		return
	}

	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"level":   currentLevelString(s.levelVar, s.cfg.LogLevel),
			"mutable": s.levelVar != nil,
		})
		return
	}

	// POST — set the level.
	rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	var body struct {
		Level string `json:"level"`
	}
	if len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, &body); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid_json")
			return
		}
	}
	want := strings.TrimSpace(body.Level)
	if want == "" {
		errJSON(w, http.StatusBadRequest, "level_required")
		return
	}
	lvl, err := parseLevel(want)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_level",
			"allowed": []string{"info", "debug", "trace"},
		})
		return
	}
	if s.levelVar == nil {
		errJSON(w, http.StatusConflict, "level_not_mutable")
		return
	}
	prev := currentLevelString(s.levelVar, s.cfg.LogLevel)
	s.levelVar.Set(lvl)
	// Log the change at L1 (always visible) so the audit trail of who cranked
	// verbosity (and back) survives whatever the new level is.
	log.LogAttrs(ctx, L1, "manage.log_level.set",
		slog.String("from", prev), slog.String("to", levelString(lvl)))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"level":    levelString(lvl),
		"previous": prev,
	})
}

// currentLevelString returns the live level when a LevelVar is wired, else the
// static config level.
func currentLevelString(lv *slog.LevelVar, static slog.Level) string {
	if lv != nil {
		return levelString(lv.Level())
	}
	return levelString(static)
}
