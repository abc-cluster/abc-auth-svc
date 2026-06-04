package authsvc

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// validateVerdict is the decision /validate reaches, factored out so /validate,
// /validate-optional, and the shadow comparison all share one code path.
type validateVerdict struct {
	allow       bool   // valid session + not suspended/expired
	user        string // Remote-User when allow
	denyState   string // "suspended"/"expired" when a valid cookie maps to a blocked slot
	clearCookie bool   // clear the cookie (suspended/expired)
}

// decideValidate computes the forward-auth verdict from the request's session
// cookie + slot state. No I/O beyond the (cached) slot-state lookup.
func (s *Server) decideValidate(ctx context.Context, r *http.Request) validateVerdict {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return validateVerdict{}
	}
	username, ok := s.session.verify(c.Value)
	if !ok {
		return validateVerdict{}
	}
	state := s.slotState(ctx, username)
	if state == "suspended" || state == "expired" {
		return validateVerdict{denyState: state, clearCookie: true}
	}
	return validateVerdict{allow: true, user: username}
}

func (s *Server) slotState(ctx context.Context, username string) string {
	if s.up.Store == nil {
		return "none"
	}
	return s.up.Store.CachedSlotState(ctx, username)
}

func setAuthUser(w http.ResponseWriter, username string) {
	w.Header().Set("X-Auth-User", username)
	w.Header().Set("Remote-User", username)
	w.Header().Set("X-WEBAUTH-USER", username)
}

// handleValidate implements GET /validate — the forward-auth hot path. 200 +
// identity headers on success; 302 to the login form otherwise (suspended slots
// get their cookie cleared). Parity port of the Python _validate.
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.decideValidate(ctx, r)
	if v.allow {
		setAuthUser(w, v.user)
		w.WriteHeader(http.StatusOK)
		return
	}
	if v.denyState != "" {
		clearSessionCookie(w, s.cfg)
		w.Header().Set("Location", "/auth/login")
		w.WriteHeader(http.StatusFound)
		FromContext(ctx).LogAttrs(ctx, L1, "validate.denied", slog.String("state", v.denyState))
		return
	}
	orig := r.Header.Get("X-Forwarded-Uri")
	if orig == "" {
		orig = "/"
	}
	w.Header().Set("Location", "/auth/login?next="+url.QueryEscape(orig))
	w.WriteHeader(http.StatusFound)
}

// handleValidateOptional implements GET /validate-optional — always 200, with
// identity headers only when a valid (non-blocked) session is present. Used by
// the Grafana proxy so anonymous viewers are not redirected.
func (s *Server) handleValidateOptional(w http.ResponseWriter, r *http.Request) {
	v := s.decideValidate(r.Context(), r)
	if v.allow {
		setAuthUser(w, v.user)
	}
	w.WriteHeader(http.StatusOK)
}

// handleValidateShadow implements GET /validate-shadow — Phase-2 parity harness.
// It returns the Go verdict but, when a shadow target (the Python /validate) is
// configured, also asks Python for its verdict and logs any disagreement. Its
// return value gates nothing in production (Caddy still points at Python), so it
// is safe to serve the Go answer here.
func (s *Server) handleValidateShadow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	goV := s.decideValidate(ctx, r)
	goStatus, goUser := verdictHTTP(goV)

	if s.shadowURL != "" {
		pyStatus, pyUser, err := s.callShadow(ctx, r)
		switch {
		case err != nil:
			FromContext(ctx).LogAttrs(ctx, L1, "validate.shadow.error", slog.String("error", err.Error()))
		case pyStatus != goStatus || pyUser != goUser:
			FromContext(ctx).LogAttrs(ctx, L1, "validate.shadow.disagree",
				slog.Int("go_status", goStatus), slog.String("go_user", goUser),
				slog.Int("py_status", pyStatus), slog.String("py_user", pyUser))
		default:
			FromContext(ctx).LogAttrs(ctx, L2, "validate.shadow.agree", slog.Int("status", goStatus))
		}
	}

	// Apply the Go verdict (gates nothing in production).
	if goV.allow {
		setAuthUser(w, goV.user)
	}
	w.WriteHeader(goStatus)
}

// verdictHTTP collapses a verdict to the (status, Remote-User) pair used for
// shadow comparison: 200 + user on allow, else 302 with no user.
func verdictHTTP(v validateVerdict) (int, string) {
	if v.allow {
		return http.StatusOK, v.user
	}
	return http.StatusFound, ""
}

// callShadow asks the configured Python /validate for its verdict, forwarding the
// session cookie and X-Forwarded-Uri. Redirects are not followed (the 302 is the
// signal). Returns (status, Remote-User, err).
func (s *Server) callShadow(ctx context.Context, r *http.Request) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.shadowURL, nil)
	if err != nil {
		return 0, "", err
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if u := r.Header.Get("X-Forwarded-Uri"); u != "" {
		req.Header.Set("X-Forwarded-Uri", u)
	}
	resp, err := s.shadowClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	return resp.StatusCode, strings.TrimSpace(resp.Header.Get("Remote-User")), nil
}
