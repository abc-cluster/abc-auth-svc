package authsvc

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// nomadTokenFromRequest extracts a Nomad token from X-Nomad-Token or
// Authorization: Bearer.
func nomadTokenFromRequest(r *http.Request) string {
	if t := strings.TrimSpace(r.Header.Get("X-Nomad-Token")); t != "" {
		return t
	}
	if a := r.Header.Get("Authorization"); len(a) >= 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

// handleAuthMe implements GET /auth/me — return the caller's identity + groups.
// Parity port of the Python _auth_me (role-based MinIO-group expansion deferred
// to Phase 3b; role-based tokens currently return policy-derived groups).
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Access-Control-Allow-Origin", "*")

	token := nomadTokenFromRequest(r)
	if token == "" {
		errJSON(w, http.StatusUnauthorized, "missing token")
		return
	}
	info, err := s.up.Nomad.LookupTokenSelf(ctx, token)
	if err != nil || info == nil {
		errJSON(w, http.StatusUnauthorized, "invalid token")
		return
	}

	id := nomadIdentity(info)
	roleBased := strings.HasPrefix(id.Policies, "role:")
	groups := groupsFromPolicies(id.Policies)
	primary := id.Namespace
	if primary == "" && len(groups) > 0 {
		primary = groups[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          id.User,
		"groups":        groups,
		"primary_group": primary,
		"namespace":     primary,
		"role_based":    roleBased,
	})
}

// handleLogout implements GET /auth/logout — clear the session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	clearSessionCookie(w, s.cfg)
	w.Header().Set("Location", "/auth/login")
	w.WriteHeader(http.StatusFound)
}

// handleLoginGet serves the HTML login form.
func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	s.serveLogin(w, safeNext(r.URL.Query().Get("next")), "")
}

// handleLoginPost validates MinIO credentials, checks slot state, and on success
// sets the session cookie and redirects. Parity port of the Python _login_post.
func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := strings.TrimSpace(r.PostFormValue("password"))
	next := safeNext(r.PostFormValue("next"))

	if username == "" || password == "" {
		s.serveLogin(w, next, "Username and password are required.")
		return
	}

	valid, err := s.up.Minio.ValidateCredential(ctx, username, password)
	if err != nil || !valid {
		FromContext(ctx).LogAttrs(ctx, L1, "login.fail", slog.String("user", username))
		s.serveLogin(w, next, "Invalid username or password.")
		return
	}

	// Slot-state check (uncached, matching the Python login path). Fail open if
	// PocketBase is unreachable — don't block valid users on a store hiccup.
	if s.up.Store != nil {
		if slot, ferr := s.up.Store.FindSlot(ctx, "minio_access_key='"+username+"'"); ferr == nil && slot != nil {
			switch slot.State {
			case "suspended":
				FromContext(ctx).LogAttrs(ctx, L1, "login.blocked", slog.String("user", username), slog.String("state", "suspended"))
				s.serveLogin(w, next, "Account suspended. Contact your administrator.")
				return
			case "expired":
				FromContext(ctx).LogAttrs(ctx, L1, "login.blocked", slog.String("user", username), slog.String("state", "expired"))
				s.serveLogin(w, next, "Account is no longer active.")
				return
			}
		}
	}

	setSessionCookie(w, s.cfg, s.session.make(username, s.cfg.SessionTTL))
	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusFound)
	FromContext(ctx).LogAttrs(ctx, L1, "login.ok", slog.String("user", username))
}

func (s *Server) serveLogin(w http.ResponseWriter, next, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = loginTemplate.Execute(w, loginData{Next: next, Error: errMsg})
}

// safeNext sanitises a post-login redirect target: only same-origin absolute
// paths are allowed (protocol-relative // is rejected — a hardening over the
// Python, which only checks the leading /).
func safeNext(raw string) string {
	u, err := url.QueryUnescape(strings.TrimSpace(raw))
	if err != nil {
		u = strings.TrimSpace(raw)
	}
	if !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") {
		return "/"
	}
	return u
}

type loginData struct {
	Next  string
	Error string
}

// loginTemplate is a functional sign-in form (presentation only; html/template
// escapes Next/Error). The POST carries username/password/next.
var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>abc-cluster · sign in</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
         display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; }
  .card { background: #1e293b; padding: 2rem; border-radius: 10px; width: 320px; box-shadow: 0 10px 30px rgba(0,0,0,.4); }
  h1 { font-size: 1.1rem; margin: 0 0 1rem; }
  label { display: block; font-size: .8rem; margin: .75rem 0 .25rem; color: #94a3b8; }
  input { width: 100%; padding: .6rem; border: 1px solid #334155; border-radius: 6px;
          background: #0f172a; color: #e2e8f0; box-sizing: border-box; }
  button { width: 100%; margin-top: 1.25rem; padding: .6rem; border: 0; border-radius: 6px;
           background: #2563eb; color: #fff; font-weight: 600; cursor: pointer; }
  .error-block { background: #7f1d1d; color: #fecaca; padding: .5rem .75rem; border-radius: 6px;
                 font-size: .85rem; margin-bottom: .5rem; }
</style>
</head>
<body>
  <form class="card" method="POST" action="/auth/login">
    <h1>Sign in to abc-cluster</h1>
    {{if .Error}}<div class="error-block">{{.Error}}</div>{{end}}
    <label for="username">Username</label>
    <input id="username" name="username" autocomplete="username" autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password">
    <input type="hidden" name="next" value="{{.Next}}">
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
`))
