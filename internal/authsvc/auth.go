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

// loginTemplate renders the workbench sign-in page (html/template escapes
// Next and Error; the POST carries username/password/next).
var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html data-theme="dark" data-system="grid" lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>abc-cluster &middot; workbench &middot; sign in</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;1,400&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root[data-system="grid"][data-theme="dark"]{
  --bg:#070f0c;--bg-1:#0b1a15;--bg-2:#0f2219;
  --text:#c5e5dc;--text-dim:#7db8a8;--text-mute:#4a7d6f;
  --ink:#e8f9f4;--ink-dim:#c8a84c;--ink-faint:rgba(200,168,76,.15);
  --accent:#c8a84c;--rule:#163d32;--rule-soft:#0e2a22;
  --sel:rgba(200,168,76,.22);--danger:#e05a4e;--danger-bg:rgba(224,90,78,.08);
  --font-sans:'IBM Plex Sans',system-ui,sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
}
:root[data-system="grid"][data-theme="light"]{
  --bg:#f0faf7;--bg-1:#e5f5f0;--bg-2:#d8ede7;
  --text:#1a4a3a;--text-dim:#2d7060;--text-mute:#6aaa96;
  --ink:#0a2820;--ink-dim:#907028;--ink-faint:rgba(144,112,40,.15);
  --accent:#907028;--rule:#a8d8cc;--rule-soft:#c8e8e0;
  --sel:rgba(144,112,40,.22);--danger:#c0392b;--danger-bg:rgba(192,57,43,.08);
  --font-sans:'IBM Plex Sans',system-ui,sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
}
*,*::before,*::after{box-sizing:border-box;}
html{font-size:14px;}
body{
  margin:0;min-height:100vh;display:flex;flex-direction:column;
  background:var(--bg);color:var(--text);font-family:var(--font-sans);
  -webkit-font-smoothing:antialiased;
}
::selection{background:var(--sel);color:var(--ink);}

/* topbar */
.topbar{border-bottom:1px solid var(--rule);position:relative;z-index:5;}
.topbar-inner{max-width:1180px;margin:0 auto;padding:14px 32px;
  display:flex;align-items:center;gap:12px;}
.brand{display:flex;align-items:center;gap:10px;color:var(--ink);
  text-decoration:none;border:none;}
.brand-mark{width:22px;height:22px;}
.brand-name{font-family:var(--font-mono);font-size:13px;
  letter-spacing:-.01em;font-weight:600;}
.brand-name .dim{color:var(--text-dim);}
.brand-name .tier{color:var(--text-mute);}
.top-spacer{flex:1;}
.tier-tag{
  display:inline-flex;align-items:center;gap:8px;
  font-family:var(--font-mono);font-size:11px;
  letter-spacing:.16em;text-transform:uppercase;color:var(--text-mute);
}
.tier-dot{
  width:6px;height:6px;border-radius:50%;background:var(--ink);
  display:inline-block;animation:wb-pulse 2.4s ease-in-out infinite;
}
.theme-btn{
  appearance:none;cursor:pointer;width:38px;height:38px;
  display:inline-flex;align-items:center;justify-content:center;
  border:1px solid var(--rule);background:var(--bg-1);color:var(--ink);
  position:relative;transition:border-color .12s,background .12s;
}
.theme-btn:hover{border-color:var(--ink-dim);background:var(--bg-2);}
.theme-btn svg{
  width:18px;height:18px;position:absolute;inset:0;margin:auto;
  transition:opacity 200ms ease,transform 280ms ease;
}
:root[data-theme="dark"] .ti-sun{opacity:0;transform:scale(.6) rotate(-30deg);}
:root[data-theme="dark"] .ti-moon{opacity:1;transform:scale(1) rotate(0);}
:root[data-theme="light"] .ti-sun{opacity:1;transform:scale(1) rotate(0);}
:root[data-theme="light"] .ti-moon{opacity:0;transform:scale(.6) rotate(30deg);}

/* main */
main{
  flex:1;position:relative;z-index:5;
  display:flex;align-items:center;justify-content:center;
  padding:56px 24px;
}
.backdrop{
  position:absolute;inset:0;pointer-events:none;
  background-image:radial-gradient(var(--ink) 1px,transparent 1px);
  background-size:24px 24px;opacity:.045;
  -webkit-mask-image:radial-gradient(ellipse 70% 65% at 70% 38%,#000 30%,transparent 78%);
  mask-image:radial-gradient(ellipse 70% 65% at 70% 38%,#000 30%,transparent 78%);
}
.frame{position:relative;width:100%;max-width:980px;}
.brackets{
  position:absolute;inset:-12px;pointer-events:none;opacity:.6;
  background:
    linear-gradient(var(--rule),var(--rule)) top left/18px 1px no-repeat,
    linear-gradient(var(--rule),var(--rule)) top left/1px 18px no-repeat,
    linear-gradient(var(--rule),var(--rule)) top right/18px 1px no-repeat,
    linear-gradient(var(--rule),var(--rule)) top right/1px 18px no-repeat,
    linear-gradient(var(--rule),var(--rule)) bottom left/18px 1px no-repeat,
    linear-gradient(var(--rule),var(--rule)) bottom left/1px 18px no-repeat,
    linear-gradient(var(--rule),var(--rule)) bottom right/18px 1px no-repeat,
    linear-gradient(var(--rule),var(--rule)) bottom right/1px 18px no-repeat;
}
.panels{
  display:grid;grid-template-columns:minmax(0,1fr) 440px;
  border:1px solid var(--rule);
  background:color-mix(in srgb,var(--bg-1) 70%,transparent);
  backdrop-filter:blur(2px);
}
@media(max-width:700px){
  .panels{grid-template-columns:1fr;}
  .ctx-panel{border-right:none;border-bottom:1px solid var(--rule);}
}

/* context panel */
.ctx-panel{
  padding:40px 36px;border-right:1px solid var(--rule);
  display:flex;flex-direction:column;gap:28px;
}
.badge-row{
  display:inline-flex;align-items:center;gap:9px;
  font-family:var(--font-mono);font-size:11px;
  letter-spacing:.22em;text-transform:uppercase;color:var(--ink);
  margin-bottom:16px;
}
.badge{
  border:1px solid var(--rule);padding:3px 8px;
  color:var(--accent);letter-spacing:.18em;font-size:10px;
}
.ctx-h1{
  font-family:var(--font-mono);
  font-size:clamp(22px,3vw,30px);line-height:1.08;
  letter-spacing:-.02em;font-weight:600;color:var(--ink);
  margin:0 0 14px;
}
.ctx-desc{
  font-size:14.5px;line-height:1.65;color:var(--text-dim);
  max-width:42ch;margin:0;
}

/* facts */
.facts{
  margin:0;border-top:1px solid var(--rule-soft);
  border-left:1px solid var(--rule-soft);display:grid;
}
.fact-row{
  display:grid;grid-template-columns:116px minmax(0,1fr);
  border-right:1px solid var(--rule-soft);border-bottom:1px solid var(--rule-soft);
}
.fact-key{
  padding:13px 12px;
  font-family:var(--font-mono);font-size:10px;
  letter-spacing:.14em;text-transform:uppercase;
  color:var(--text-mute);border-right:1px solid var(--rule-soft);
}
.fact-key.warn{color:var(--accent);}
.fact-val{
  margin:0;padding:13px 14px;
  font-family:var(--font-mono);font-size:12px;color:var(--text);
}
.fact-val .dim{color:var(--ink-dim);}
.fact-val .warn{color:var(--accent);font-weight:600;}
.fact-val .mute{color:var(--text-dim);}

/* editor hint */
.editor-hint{margin-top:auto;}
.hint-label{
  font-family:var(--font-mono);font-size:10px;letter-spacing:.16em;
  text-transform:uppercase;color:var(--text-mute);margin-bottom:9px;
}
.cmd-row{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  border:1px solid var(--rule);background:var(--bg);
  padding:11px 12px 11px 14px;
}
.cmd-text{font-family:var(--font-mono);font-size:12.5px;color:var(--text);}
.cmd-text .prompt{color:var(--ink-dim);}
.copy-btn{
  appearance:none;background:transparent;border:1px solid var(--rule);
  color:var(--text-dim);cursor:pointer;
  font-family:var(--font-mono);font-size:10px;
  padding:4px 10px;letter-spacing:.14em;text-transform:uppercase;
  transition:color 120ms,border-color 120ms;
}
.copy-btn:hover{color:var(--ink);border-color:var(--ink-dim);}

/* auth card */
.auth-card{display:flex;flex-direction:column;background:var(--bg-1);}
.card-header{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 24px;border-bottom:1px solid var(--rule);background:var(--bg-2);
}
.card-svc{
  font-family:var(--font-mono);font-size:11px;
  letter-spacing:.16em;text-transform:uppercase;color:var(--text-dim);
}
.card-svc .path{
  color:var(--ink);text-transform:none;
  letter-spacing:0;margin-left:8px;
}
.tls-badge{
  display:inline-flex;align-items:center;gap:7px;
  font-family:var(--font-mono);font-size:10px;
  letter-spacing:.12em;text-transform:uppercase;color:var(--text-mute);
}
.tls-dot{
  width:6px;height:6px;border-radius:50%;background:var(--ink);
  box-shadow:0 0 0 3px color-mix(in srgb,var(--ink) 20%,transparent);
}

/* form */
.auth-form{padding:26px 24px 24px;display:flex;flex-direction:column;gap:18px;}

.error-banner{
  display:grid;grid-template-columns:auto minmax(0,1fr);gap:11px;
  align-items:start;border:1px solid var(--danger);
  background:var(--danger-bg);padding:12px 14px;
}
.error-text{font-size:13px;line-height:1.55;color:var(--text);}
.error-text b{color:var(--danger);font-weight:600;}

.field{display:flex;flex-direction:column;gap:5px;}
.field-top{
  display:flex;align-items:baseline;justify-content:space-between;gap:10px;
  font-size:12.5px;font-weight:500;color:var(--text-dim);
}
.field-top label{cursor:pointer;}
.req{color:var(--accent);margin-left:2px;}
.example-btn{
  appearance:none;background:transparent;border:none;
  color:var(--ink-dim);cursor:pointer;
  font-family:var(--font-mono);font-size:10px;
  letter-spacing:.1em;text-transform:uppercase;
  border-bottom:1px dotted var(--ink-faint);padding:0 0 1px;
}
.example-btn:hover{color:var(--accent);border-bottom-color:var(--accent);}
.field input{
  width:100%;background:var(--bg);border:1px solid var(--rule);
  color:var(--text);font-family:var(--font-mono);font-size:14px;
  line-height:1.5;letter-spacing:-.01em;
  padding:11px 14px;border-radius:0;appearance:none;-webkit-appearance:none;
}
.field input:hover{border-color:var(--ink-dim);}
.field input:focus{outline:none;border-color:var(--accent);background:var(--bg-2);}
.field.err input{border-color:var(--danger);}
.key-wrap{position:relative;display:flex;}
.key-wrap input{padding-right:64px;}
.show-btn{
  position:absolute;right:1px;top:1px;bottom:1px;width:58px;
  appearance:none;background:transparent;border:none;
  border-left:1px solid var(--rule);color:var(--text-mute);cursor:pointer;
  font-family:var(--font-mono);font-size:10px;
  letter-spacing:.12em;text-transform:uppercase;
  transition:color 120ms;
}
.show-btn:hover{color:var(--ink);}
.fhint{font-size:11.5px;color:var(--text-mute);line-height:1.4;}

.submit-btn{
  display:flex;align-items:center;justify-content:center;gap:8px;
  width:100%;margin-top:4px;padding:13px 20px;
  background:var(--accent);color:#1a1208;border:none;
  font-family:var(--font-mono);font-size:13px;font-weight:600;
  letter-spacing:-.01em;cursor:pointer;transition:filter 120ms;
}
.submit-btn:hover{filter:brightness(1.08);}
.submit-btn:disabled{opacity:.75;cursor:not-allowed;filter:none;}
.spin{
  width:14px;height:14px;
  border:2px solid color-mix(in srgb,#1a1208 35%,transparent);
  border-top-color:#1a1208;border-radius:50%;
  display:inline-block;animation:wb-spin .7s linear infinite;
}

.form-footer{
  margin:4px 0 0;font-size:12px;line-height:1.55;color:var(--text-mute);
  border-top:1px solid var(--rule-soft);padding-top:14px;
}

@keyframes wb-spin{to{transform:rotate(360deg);}}
@keyframes wb-pulse{0%,100%{opacity:1;}50%{opacity:.35;}}
</style>
</head>
<body>

<div class="backdrop" aria-hidden="true"></div>

<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="#" aria-label="abc-cluster workbench">
      <svg class="brand-mark" viewBox="0 0 100 100" aria-hidden="true">
        <line x1="20" y1="50" x2="80" y2="50" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
        <circle cx="20" cy="50" r="9" fill="var(--bg)" stroke="currentColor" stroke-width="3"/>
        <circle cx="50" cy="50" r="9" fill="var(--bg)" stroke="currentColor" stroke-width="3"/>
        <circle cx="80" cy="50" r="9" fill="var(--bg)" stroke="currentColor" stroke-width="3"/>
      </svg>
      <span class="brand-name">abc<span class="dim">-cluster</span><span class="tier"> &middot; workbench</span></span>
    </a>
    <div class="top-spacer"></div>
    <span class="tier-tag"><span class="tier-dot" aria-hidden="true"></span>seedling</span>
    <button class="theme-btn" type="button" id="theme-btn" aria-label="Toggle theme">
      <svg class="ti-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
        <circle cx="12" cy="12" r="4"/>
        <line x1="12" y1="2" x2="12" y2="4" stroke-linecap="round"/>
        <line x1="12" y1="20" x2="12" y2="22" stroke-linecap="round"/>
        <line x1="2" y1="12" x2="4" y2="12" stroke-linecap="round"/>
        <line x1="20" y1="12" x2="22" y2="12" stroke-linecap="round"/>
        <line x1="4.6" y1="4.6" x2="6" y2="6" stroke-linecap="round"/>
        <line x1="18" y1="18" x2="19.4" y2="19.4" stroke-linecap="round"/>
        <line x1="4.6" y1="19.4" x2="6" y2="18" stroke-linecap="round"/>
        <line x1="18" y1="6" x2="19.4" y2="4.6" stroke-linecap="round"/>
      </svg>
      <svg class="ti-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" aria-hidden="true">
        <path d="M19.6 17.8a8.4 8.4 0 1 1-9.4-12.6 7 7 0 0 0 9.4 12.6Z"/>
      </svg>
    </button>
  </div>
</header>

<main>
  <div class="frame">
    <div class="brackets" aria-hidden="true"></div>
    <div class="panels">

      <section class="ctx-panel">
        <div>
          <div class="badge-row"><span class="badge">cockpit</span>workbench.seedling</div>
          <h1 class="ctx-h1">Sign in to your<br>workbench.</h1>
          <p class="ctx-desc">The browser cockpit for the seedling tier. Authenticate with your pool slot credentials, start your JupyterLab server, and drive cluster jobs from notebooks and a terminal.</p>
        </div>

        <dl class="facts">
          <div class="fact-row">
            <dt class="fact-key">Session</dt>
            <dd class="fact-val">16 GB &middot; 8 CPU &middot; 512 tasks</dd>
          </div>
          <div class="fact-row">
            <dt class="fact-key">Storage</dt>
            <dd class="fact-val">/data/workbench/&lt;slot&gt;/home <span class="dim">&middot; persistent</span></dd>
          </div>
          <div class="fact-row">
            <dt class="fact-key warn">Lifetime</dt>
            <dd class="fact-val"><span class="mute">Data purged after </span><span class="warn">14 days</span><span class="mute"> &mdash; avoid sensitive data.</span></dd>
          </div>
        </dl>

        <div class="editor-hint">
          <div class="hint-label">Prefer your editor?</div>
          <div class="cmd-row">
            <span class="cmd-text"><span class="prompt">$ </span>abc workbench connect</span>
            <button type="button" class="copy-btn" id="copy-btn">Copy</button>
          </div>
        </div>
      </section>

      <section class="auth-card">
        <div class="card-header">
          <span class="card-svc">abc-auth-svc<span class="path">/auth/login</span></span>
          <span class="tls-badge"><span class="tls-dot" aria-hidden="true"></span>tls</span>
        </div>

        <form class="auth-form" method="POST" action="/auth/login" id="login-form">
          {{if .Error}}
          <div role="alert" class="error-banner">
            <svg viewBox="0 0 24 24" width="17" height="17" fill="none" aria-hidden="true" style="margin-top:1px;flex-shrink:0;">
              <circle cx="12" cy="12" r="9" stroke="var(--danger)" stroke-width="1.6"/>
              <line x1="12" y1="7.5" x2="12" y2="13" stroke="var(--danger)" stroke-width="1.7" stroke-linecap="round"/>
              <circle cx="12" cy="16.4" r="1.05" fill="var(--danger)"/>
            </svg>
            <div class="error-text"><b>{{.Error}}</b></div>
          </div>
          {{end}}

          <div class="field{{if .Error}} err{{end}}">
            <div class="field-top">
              <label for="wb-slot">Pool slot<span class="req">*</span></label>
              <button type="button" class="example-btn" id="example-btn">use example</button>
            </div>
            <input id="wb-slot" name="username" type="text"
              autocomplete="username" spellcheck="false"
              placeholder="slot-calm_dassie" autofocus>
            <span class="fhint">Pseudonymous slot claimed via the landing page.</span>
          </div>

          <div class="field{{if .Error}} err{{end}}">
            <div class="field-top">
              <label for="wb-key">MinIO access key<span class="req">*</span></label>
            </div>
            <div class="key-wrap">
              <input id="wb-key" name="password" type="password"
                autocomplete="current-password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;">
              <button type="button" class="show-btn" id="show-btn">Show</button>
            </div>
            <span class="fhint">Provisioned with your slot &mdash; not a password you chose.</span>
          </div>

          <input type="hidden" name="next" value="{{.Next}}">

          <button type="submit" class="submit-btn" id="submit-btn">
            <span id="submit-label">Start session</span>
            <span id="submit-arrow">&rarr;</span>
          </button>

          <p class="form-footer">
            Access is provisioned through your pool claim &mdash; no sign-up or password reset here. Trouble signing in? Contact your administrator.
          </p>
        </form>
      </section>

    </div>
  </div>
</main>

<script>
(function(){
  var html=document.documentElement;

  document.getElementById('theme-btn').addEventListener('click',function(){
    html.dataset.theme=html.dataset.theme==='dark'?'light':'dark';
  });

  document.getElementById('show-btn').addEventListener('click',function(){
    var inp=document.getElementById('wb-key');
    var hide=inp.type==='password';
    inp.type=hide?'text':'password';
    this.textContent=hide?'Hide':'Show';
  });

  document.getElementById('example-btn').addEventListener('click',function(){
    document.getElementById('wb-slot').value='slot-calm_dassie';
    document.getElementById('wb-slot').focus();
  });

  document.getElementById('copy-btn').addEventListener('click',function(){
    var btn=this;
    try{navigator.clipboard.writeText('abc workbench connect');}catch(e){}
    btn.textContent='Copied';
    btn.style.color='var(--accent)';
    btn.style.borderColor='var(--accent)';
    setTimeout(function(){
      btn.textContent='Copy';
      btn.style.color='';
      btn.style.borderColor='';
    },1600);
  });

  document.getElementById('login-form').addEventListener('submit',function(){
    var btn=document.getElementById('submit-btn');
    var lbl=document.getElementById('submit-label');
    var arr=document.getElementById('submit-arrow');
    btn.disabled=true;
    var spin=document.createElement('span');
    spin.className='spin';
    btn.insertBefore(spin,lbl);
    lbl.textContent='Authenticating…';
    if(arr)arr.style.display='none';
  });
})();
</script>
</body>
</html>
`))
