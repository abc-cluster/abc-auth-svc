package authsvc

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const (
	workbenchTokenDefaultTTL int64 = 7 * 24 * 3600  // 7 days
	workbenchTokenMaxTTL     int64 = 30 * 24 * 3600 // 30 days
)

// mintResponse is the JSON body returned to the CLI (`abc workbench connect`).
// Field names must match internal/workbench.MintHubTokenResponse in abc-cluster-cli.
type mintResponse struct {
	Token     string   `json:"token"`
	ID        string   `json:"id"`
	ExpiresAt string   `json:"expires_at"`
	Scopes    []string `json:"scopes"`
	Note      string   `json:"note"`
	Slot      string   `json:"slot"`
	HubURL    string   `json:"hub_url"`
}

// handleWorkbenchToken implements POST /auth/workbench/token (and /workbench/token):
// authenticate the caller's Nomad ACL token, derive the JupyterHub username, and
// mint a JH user token via the admin API. Parity port of the Python
// _workbench_token_post.
func (s *Server) handleWorkbenchToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	// 1. Authenticate: X-Nomad-Token or Authorization: Bearer.
	token := strings.TrimSpace(r.Header.Get("X-Nomad-Token"))
	if token == "" {
		if a := r.Header.Get("Authorization"); len(a) >= 7 && strings.EqualFold(a[:7], "bearer ") {
			token = strings.TrimSpace(a[7:])
		}
	}
	if token == "" {
		errJSON(w, http.StatusUnauthorized, "missing token (provide X-Nomad-Token or Authorization: Bearer)")
		return
	}

	info, err := s.up.Nomad.LookupTokenSelf(ctx, token)
	if err != nil || info == nil {
		log.LogAttrs(ctx, L2, "workbench.token.auth_failed", slog.String("reason", errReason(err)))
		errJSON(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	rawName := strings.TrimSpace(info.Name)
	if rawName == "" {
		errJSON(w, http.StatusUnauthorized, "could not determine username from token")
		return
	}

	// 2. Derive the JupyterHub username.
	//   pool token  Name="pool-<x>"  → jh_user "<x>" (bare; matches Caddy Remote-User)
	//   named token Name="<x>"       → jh_user verbatim
	//
	// Caddy's /validate response sets Remote-User: <bare>, and JH's HeaderAuthenticator
	// creates / matches the JH user under that bare name; the mint target MUST match.
	// Historically the pool branch constructed "slot-<bare>"; the only legacy user
	// matching that pattern is "slot-calm_dassie" predating 2026-05-28. See
	// abc-universe/brainstorms/abc-workbench/2026-06-09-workbench-connect-and-spawn-failures.md.
	var jhUser, abcUser string
	pooled := strings.HasPrefix(rawName, "pool-")
	if pooled {
		bare := strings.TrimPrefix(rawName, "pool-")
		jhUser, abcUser = bare, bare
	} else {
		jhUser, abcUser = rawName, rawName
	}
	// THE Bug-A decision point: log the raw token Name → derived jh_user
	// mapping at L2. When the 2026-06-09 mint 403 recurs (or a future naming
	// migration desyncs again), this single record shows whether the mint is
	// targeting the right JH user without an alloc-exec + journalctl hunt.
	log.LogAttrs(ctx, L2, "workbench.token.derive_user",
		slog.String("raw_name", rawName),
		slog.Bool("pooled", pooled),
		slog.String("jh_user", jhUser),
		slog.String("abc_user", abcUser))

	// Block suspended/expired slots from minting (defence in depth — JH itself
	// has no slot-state model). Keyed on minio_access_key == the bare abc user.
	// Skipped when no slot store is configured; "error"/"none" fail open.
	if s.up.Store != nil {
		if st := s.up.Store.CachedSlotState(ctx, abcUser); st == "suspended" || st == "expired" {
			errJSON(w, http.StatusForbidden, "slot is "+st)
			return
		}
	}

	// 3. Parse the optional body { note, expires_in }.
	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var body struct {
		Note      string          `json:"note"`
		ExpiresIn json.RawMessage `json:"expires_in"`
	}
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	note := strings.TrimSpace(body.Note)
	if note == "" {
		note = "abc-cli-" + abcUser
	}

	expiresIn := workbenchTokenDefaultTTL
	if len(body.ExpiresIn) > 0 && string(body.ExpiresIn) != "null" {
		var n int64
		if err := json.Unmarshal(body.ExpiresIn, &n); err != nil {
			errJSON(w, http.StatusBadRequest, "expires_in must be an integer (seconds)")
			return
		}
		if n <= 0 {
			errJSON(w, http.StatusBadRequest, "expires_in must be positive")
			return
		}
		if n > workbenchTokenMaxTTL {
			errJSON(w, http.StatusBadRequest, "expires_in cannot exceed 30 days (2592000 seconds)")
			return
		}
		expiresIn = n
	}

	// 4. Mint via the JupyterHub admin API.
	tok, err := s.up.Hub.MintUserToken(ctx, jhUser, note, expiresIn)
	if err != nil {
		var he *HubError
		if errors.As(err, &he) && he.Kind == hubHTTPError {
			// Classify 403 / 404 by probing whether the JH user exists.
			// One cheap GET disambiguates the three actual causes (wrong
			// name vs scope too narrow vs hub unreachable) — saves the
			// "alloc-exec + journalctl + ssh" hunts the 2026-06-09 mint
			// bug forced.
			diag := ""
			if he.Status == http.StatusForbidden || he.Status == http.StatusNotFound {
				if ex, ok := s.up.Hub.(HubUserExister); ok {
					exists, probeErr := ex.UserExists(ctx, jhUser)
					switch {
					case probeErr != nil:
						diag = "jh-user-probe-failed"
					case exists != nil && !*exists:
						diag = "jh-user-not-found"
					case exists != nil && *exists:
						diag = "jh-scope-or-token-issue"
					}
				}
			}
			attrs := []slog.Attr{
				slog.String("user", jhUser),
				slog.Int("hub_status", he.Status),
			}
			if diag != "" {
				attrs = append(attrs, slog.String("diag", diag))
			}
			log.LogAttrs(ctx, L1, "workbench.token.mint_failed", attrs...)
			body := map[string]any{
				"error": he.Error(),
				"hint":  "GET /manage/slots/" + abcUser + "/diag (operator-gated) for a structured readiness report.",
			}
			if diag != "" {
				body["diag"] = diag
			}
			writeJSON(w, http.StatusBadGateway, body)
			return
		}
		log.LogAttrs(ctx, L1, "workbench.token.hub_unreachable",
			slog.String("user", jhUser), slog.String("error", errReason(err)))
		errJSON(w, http.StatusServiceUnavailable, "hub unreachable")
		return
	}

	log.LogAttrs(ctx, L1, "workbench.token.mint_ok",
		slog.String("user", jhUser),
		slog.String("note", note),
		slog.Int64("expires_in", expiresIn),
	)

	scopes := tok.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	respNote := tok.Note
	if respNote == "" {
		respNote = note
	}
	writeJSON(w, http.StatusOK, mintResponse{
		Token:     tok.Token,
		ID:        tok.ID,
		ExpiresAt: tok.ExpiresAt,
		Scopes:    scopes,
		Note:      respNote,
		Slot:      jhUser,
		HubURL:    s.up.HubPublicURL,
	})
}

func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func errReason(err error) string {
	if err == nil {
		return "nil-identity"
	}
	return err.Error()
}
