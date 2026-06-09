package authsvc

import (
	"log/slog"
	"net/http"
	"strings"
)

// handleAuthMinIOLogin implements GET /auth/minio-login?code=<hex>.
//
// Browser flow:
//
//  1. `abc portal open minio` mints a code via /auth/cli-token (portal=minio),
//     which pre-fetches a MinIO console JWT into `extra.minio_token`.
//  2. The CLI opens https://minio.seedling.…/auth/minio-login?code=<code>.
//  3. Caddy routes /auth/minio-login* on minio.seedling.* → this handler.
//  4. We redeem the code and set the MinIO console token cookie (scoped to
//     minio.seedling.* via the visit Host), then 302 to the console root.
//
// Mirrors Python _auth_minio_login. If the code didn't carry a JWT (older
// flow), we attempt a fresh ConsoleLogin with an empty secret — which will
// fail, but the user is redirected to the MinIO login page and can sign in.
func (s *Server) handleAuthMinIOLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		http.Redirect(w, r, "/?error=missing_code", http.StatusFound)
		return
	}
	entry := s.codes.redeem(code)
	if entry == nil {
		log.LogAttrs(ctx, L1, "minio_login.redeem_failed", slog.String("reason", "invalid_or_expired"))
		http.Redirect(w, r, "/?error=link_expired", http.StatusFound)
		return
	}

	jwt := entry.Extra["minio_token"]
	if jwt == "" {
		if login, ok := s.up.Minio.(MinIOConsoleLogin); ok {
			if tok, lerr := login.ConsoleLogin(ctx, entry.Username, ""); lerr == nil {
				jwt = tok
			}
		}
	}
	if jwt == "" {
		log.LogAttrs(ctx, L1, "minio_login.no_token", slog.String("user", entry.Username))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Mirror Python: HttpOnly, SameSite=Lax, Max-Age=43200 (12h), Secure when
	// the deployment runs HTTPS. Path=/ — MinIO console reads the token cookie
	// from any path on its origin.
	c := &http.Cookie{
		Name:     "token",
		Value:    jwt,
		Path:     "/",
		MaxAge:   43200,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cfg.CookieSecure,
	}
	http.SetCookie(w, c)
	log.LogAttrs(ctx, L1, "minio_login.ok", slog.String("user", entry.Username))
	http.Redirect(w, r, "/", http.StatusFound)
}
