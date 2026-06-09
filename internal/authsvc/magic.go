package authsvc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// magicCode is one entry in the in-memory cli-token store.
//
// One-time codes are issued by POST /auth/cli-token (called from `abc portal
// open` family of CLI commands), and redeemed by GET /auth/redeem (visited by
// the browser the CLI launches). Codes are single-use and short-lived
// (CLITokenTTL, default 60s) so a leaked URL can't be replayed.
type magicCode struct {
	Username string
	Expiry   time.Time
	NextURL  string
	Extra    map[string]string // portal-specific (e.g. minio_token, portal)
}

// magicCodeStore is a tiny in-memory map with a TTL sweep. Mirrors the
// Python service's `_cli_codes` dict + `_cli_codes_issue/_cli_codes_redeem`
// helpers. Single-process; if/when this service is replicated, replace with a
// shared store (Redis / PB).
type magicCodeStore struct {
	mu sync.Mutex
	m  map[string]magicCode
}

func newMagicCodeStore() *magicCodeStore { return &magicCodeStore{m: map[string]magicCode{}} }

// issue mints a 32-byte hex code, stores the entry, and returns the code.
// Expired entries are swept at issue time (cheap; bounded by call rate).
func (s *magicCodeStore) issue(username, nextURL string, ttl time.Duration, extra map[string]string) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	code := hex.EncodeToString(buf[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if v.Expiry.Before(now) {
			delete(s.m, k)
		}
	}
	s.m[code] = magicCode{
		Username: username, Expiry: now.Add(ttl),
		NextURL: nextURL, Extra: extra,
	}
	return code, nil
}

// redeem consumes the code (single-use). Returns nil for unknown / expired.
func (s *magicCodeStore) redeem(code string) *magicCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.m[code]
	if !ok {
		return nil
	}
	delete(s.m, code)
	if entry.Expiry.Before(time.Now()) {
		return nil
	}
	return &entry
}

// ── POST /auth/cli-token ─────────────────────────────────────────────────────
// Body: {"nomad_token": "...", "next": "...", "portal": "workbench|grafana|minio",
//         "minio_password": "..." (optional, for minio portal)}
// Resp: {"code": "...", "ttl": <seconds>}
//
// Mirrors Python _cli_token_post. Validates the Nomad ACL token via the same
// path /auth/exchange + /validate use, derives the bare username, optionally
// pre-fetches a MinIO console JWT (for the minio portal), and issues a code.

type cliTokenRequest struct {
	NomadToken    string `json:"nomad_token"`
	Next          string `json:"next"`
	Portal        string `json:"portal"`
	MinIOPassword string `json:"minio_password"`
}

type cliTokenResponse struct {
	Code string `json:"code"`
	TTL  int    `json:"ttl"`
}

func (s *Server) handleCLITokenPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if len(rawBody) == 0 {
		errJSON(w, http.StatusBadRequest, "missing request body")
		return
	}
	var req cliTokenRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	nt := strings.TrimSpace(req.NomadToken)
	if nt == "" {
		errJSON(w, http.StatusBadRequest, "nomad_token required")
		return
	}
	next := strings.TrimSpace(req.Next)
	if next == "" {
		next = "/"
	}
	portal := strings.ToLower(strings.TrimSpace(req.Portal))

	info, err := s.up.Nomad.LookupTokenSelf(ctx, nt)
	if err != nil || info == nil {
		log.LogAttrs(ctx, L2, "cli_token.auth_failed", slog.String("reason", errReason(err)))
		errJSON(w, http.StatusUnauthorized, "invalid or expired Nomad token")
		return
	}
	rawName := strings.TrimSpace(info.Name)
	if rawName == "" {
		errJSON(w, http.StatusUnauthorized, "could not determine username from token")
		return
	}
	username := strings.TrimPrefix(rawName, "pool-")

	// Suspend/expire gate. "none"/"error" fail open (no store, or transient).
	if s.up.Store != nil {
		if st := s.up.Store.CachedSlotState(ctx, username); st == "suspended" || st == "expired" {
			errJSON(w, http.StatusForbidden, "slot is "+st)
			return
		}
	}

	// Build extra. Always store the portal so /auth/redeem and /auth/minio-login
	// don't need to introspect the Host header.
	extra := map[string]string{}
	if portal != "" {
		extra["portal"] = portal
	}
	if portal == "minio" {
		// Pool tokens reuse the Nomad token as the MinIO secret unless an
		// explicit minio_password is supplied. Pre-fetching the MinIO STS
		// token here means the browser visit to /auth/minio-login can set the
		// cookie without an extra round-trip.
		pw := strings.TrimSpace(req.MinIOPassword)
		if pw == "" {
			pw = nt
		}
		if login, ok := s.up.Minio.(MinIOConsoleLogin); ok {
			if jwt, lerr := login.ConsoleLogin(ctx, username, pw); lerr == nil && jwt != "" {
				extra["minio_token"] = jwt
			} else if lerr != nil {
				log.LogAttrs(ctx, L1, "cli_token.minio_prelogin_failed",
					slog.String("user", username), slog.String("error", errReason(lerr)))
			}
		}
	}

	ttl := s.cfg.CLITokenTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	code, ierr := s.codes.issue(username, next, ttl, extra)
	if ierr != nil {
		errJSON(w, http.StatusInternalServerError, "code mint failed")
		return
	}

	log.LogAttrs(ctx, L1, "cli_token.issued",
		slog.String("user", username),
		slog.String("portal", portal),
		slog.String("next", next))

	writeJSON(w, http.StatusOK, cliTokenResponse{Code: code, TTL: int(ttl.Seconds())})
}

// ── GET /auth/redeem ─────────────────────────────────────────────────────────
// Query: ?code=<hex>
// Action: consume the code, set abc_session cookie, 302 to the (validated)
//
//	next URL. Same browser flow as Python _auth_redeem.

func (s *Server) handleAuthRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		http.Redirect(w, r, "/auth/login?error=missing_code", http.StatusFound)
		return
	}
	entry := s.codes.redeem(code)
	if entry == nil {
		log.LogAttrs(ctx, L1, "cli_token.redeem_failed", slog.String("reason", "invalid_or_expired"))
		http.Redirect(w, r, "/auth/login?error=link_expired", http.StatusFound)
		return
	}

	// Decide the post-redeem redirect target.
	portal := entry.Extra["portal"]
	host := r.Host
	var dest, destReason string
	switch {
	case portal == "grafana" || strings.Contains(host, "grafana."):
		// Grafana needs /login to force auth-proxy re-evaluation, otherwise
		// it serves the cached anonymous session.
		dest, destReason = "/login", "grafana"
	case entry.NextURL != "" && isTrustedRedirect(entry.NextURL):
		dest, destReason = entry.NextURL, "trusted_absolute"
	default:
		dest, destReason = safeNext(entry.NextURL), "safe_next"
	}
	// L2: which redirect branch + whether a minio_token rode along. The portal
	// SSO flows are the ones that mis-redirect when next/host disagree; this
	// makes the branch chosen explicit per rid.
	_, hasMinioToken := entry.Extra["minio_token"]
	log.LogAttrs(ctx, L2, "cli_token.redeem_decide",
		slog.String("user", entry.Username),
		slog.String("portal", portal),
		slog.String("dest_reason", destReason),
		slog.String("dest", dest),
		slog.Bool("has_minio_token", hasMinioToken))

	tok := s.session.make(entry.Username, s.cfg.SessionTTL)
	setSessionCookie(w, s.cfg, tok)
	log.LogAttrs(ctx, L1, "cli_token.redeemed",
		slog.String("user", entry.Username),
		slog.String("next", dest))
	http.Redirect(w, r, dest, http.StatusFound)
}

// isTrustedRedirect mirrors the Python _is_trusted_redirect: an absolute URL
// is trusted iff its host is the cluster auth-endpoint host or a sibling under
// the same trailing-suffix domain (matching seedling.abc-cluster.cloud style).
// A nil cfg.TrustedDomain disables absolute-URL acceptance (path-only).
func isTrustedRedirect(raw string) bool {
	if raw == "" {
		return false
	}
	// Cheap path-only check: matches the Python is_trusted_redirect early-exit.
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	// We accept absolute URLs whose host lives under .abc-cluster.cloud. This
	// matches the deployed seedling pattern (workbench / upload / grafana /
	// minio . seedling . abc-cluster . cloud). Tighten if other deployments
	// share the same Caddy with a different TLD.
	const suffix = ".abc-cluster.cloud"
	// strip scheme
	rest := raw
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(rest, p) {
			rest = rest[len(p):]
			break
		}
	}
	// host ends at first '/'
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return strings.HasSuffix(rest, suffix)
}
