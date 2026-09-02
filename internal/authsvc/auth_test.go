package authsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func authServer(t *testing.T, minio MinIOValidator, store SlotStore, nomad NomadValidator) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.SessionSecret = testSecret
	up := Upstreams{Nomad: nomad, Hub: okHub(), Store: store, Minio: minio, Cluster: testCluster}
	return NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up), &buf
}

func nomadReturning(info *NomadTokenSelf) fakeNomad {
	return fakeNomad{fn: func(context.Context, string) (*NomadTokenSelf, error) { return info, nil }}
}

func postForm(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	return rr
}

// ── safeNext + identity ───────────────────────────────────────────────────────

func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"/lab/tree":       "/lab/tree",
		"%2Flab":          "/lab",
		"":                "/",
		"http://evil.com": "/",
		"//evil.com":      "/",
		"relative":        "/",
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGroupsFromPolicies(t *testing.T) {
	if g := groupsFromPolicies("management"); len(g) != 1 || g[0] != "*" {
		t.Errorf("management = %v", g)
	}
	g := groupsFromPolicies("su-mbhg-hostgen-pool,su-multi-group-member")
	if len(g) != 2 || g[0] != "mbhg-hostgen" || g[1] != "multi-group" {
		t.Errorf("groups = %v, want [mbhg-hostgen multi-group]", g)
	}
	if g := groupsFromPolicies("role:r-foo"); len(g) != 0 {
		t.Errorf("role-based should expand to empty here, got %v", g)
	}
}

// nsGuess resolves both "member-<ns>" and "<ns>-member" to the same namespace,
// so the group name reported for them should agree too. Before this, the prefix
// form came back as "member-su-foo" while its namespace resolved to "su-foo".
func TestGroupsFromPoliciesPrefixAndSuffixFormsAgree(t *testing.T) {
	prefixForm := groupsFromPolicies("member-su-mbhg-hostgen")
	suffixForm := groupsFromPolicies("su-mbhg-hostgen-member")
	if len(prefixForm) != 1 || prefixForm[0] != "mbhg-hostgen" {
		t.Errorf("member-su-mbhg-hostgen = %v, want [mbhg-hostgen]", prefixForm)
	}
	if len(suffixForm) != 1 || suffixForm[0] != "mbhg-hostgen" {
		t.Errorf("su-mbhg-hostgen-member = %v, want [mbhg-hostgen]", suffixForm)
	}
	// Both shapes name the same group, so they must dedupe to one entry.
	if both := groupsFromPolicies("member-su-mbhg-hostgen,su-mbhg-hostgen-member"); len(both) != 1 {
		t.Errorf("the two shapes of one group = %v, want a single entry", both)
	}
}

// A group whose own name ends in "-group" is why "-group-admin" is not in the
// suffix list: "su-multi-group-admin" is the group "multi-group" with an -admin
// suffix, indistinguishable by shape from "<group>-group-admin". Pinning this
// keeps a future suffix addition from silently truncating it to "multi".
func TestGroupsFromPoliciesKeepsGroupSuffixedNames(t *testing.T) {
	for _, policy := range []string{"su-multi-group-member", "su-multi-group-admin", "su-multi-group-pool"} {
		if g := groupsFromPolicies(policy); len(g) != 1 || g[0] != "multi-group" {
			t.Errorf("%s = %v, want [multi-group]", policy, g)
		}
	}
}

func TestNomadIdentity(t *testing.T) {
	// management
	id := nomadIdentity(&NomadTokenSelf{Name: "root", Type: "management"})
	if id.Group != "admin" || id.Namespace != "*" || id.Policies != "management" {
		t.Errorf("management id = %+v", id)
	}
	// policy-based, namespace derived from group (strip -pool)
	id = nomadIdentity(&NomadTokenSelf{Name: "pool-x", Type: "client", Policies: []string{"su-mbhg-hostgen-pool"}})
	if id.Group != "su-mbhg-hostgen-pool" || id.Namespace != "su-mbhg-hostgen" || id.Policies != "su-mbhg-hostgen-pool" {
		t.Errorf("policy id = %+v", id)
	}
	// role-based
	id = nomadIdentity(&NomadTokenSelf{Name: "anel", Type: "client", Roles: []NomadRole{{Name: "r-cluster-admin"}}})
	if id.Group != "cluster-admin" || id.Policies != "role:r-cluster-admin" {
		t.Errorf("role id = %+v", id)
	}
}

// ── /auth/me ──────────────────────────────────────────────────────────────────

func TestAuthMe_MissingToken(t *testing.T) {
	s, _ := authServer(t, mockMinio{}, mockStore{}, okNomad("x"))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAuthMe_PolicyBased(t *testing.T) {
	nomad := nomadReturning(&NomadTokenSelf{Name: "pool-x", Type: "client", Policies: []string{"su-mbhg-hostgen-pool"}})
	s, _ := authServer(t, mockMinio{}, mockStore{}, nomad)
	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	r.Header.Set("X-Nomad-Token", "t")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("missing CORS header")
	}
	var out struct {
		User         string   `json:"user"`
		Groups       []string `json:"groups"`
		PrimaryGroup string   `json:"primary_group"`
		RoleBased    bool     `json:"role_based"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.User != "pool-x" || len(out.Groups) != 1 || out.Groups[0] != "mbhg-hostgen" || out.RoleBased {
		t.Errorf("me = %+v", out)
	}
}

func TestAuthMe_Management(t *testing.T) {
	nomad := nomadReturning(&NomadTokenSelf{Name: "root", Type: "management"})
	s, _ := authServer(t, mockMinio{}, mockStore{}, nomad)
	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	r.Header.Set("Authorization", "Bearer t")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, r)
	var out struct {
		Groups       []string `json:"groups"`
		PrimaryGroup string   `json:"primary_group"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Groups) != 1 || out.Groups[0] != "*" || out.PrimaryGroup != "*" {
		t.Errorf("management me = %+v", out)
	}
}

// ── /auth/login + /auth/logout ────────────────────────────────────────────────

func TestLoginGet(t *testing.T) {
	s, _ := authServer(t, mockMinio{}, mockStore{}, okNomad("x"))
	rr := httptestGET(t, s, "/auth/login?next=%2Flab", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Sign in") {
		t.Fatalf("status=%d body has form? %v", rr.Code, strings.Contains(rr.Body.String(), "Sign in"))
	}
	if !strings.Contains(rr.Body.String(), `value="/lab"`) {
		t.Errorf("next not reflected:\n%s", rr.Body.String())
	}
}

func TestLoginPost_MissingFields(t *testing.T) {
	s, _ := authServer(t, mockMinio{}, mockStore{}, okNomad("x"))
	rr := postForm(t, s, "/auth/login", url.Values{"username": {""}, "password": {""}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "required") {
		t.Fatalf("status=%d, want form with 'required'", rr.Code)
	}
}

func TestLoginPost_InvalidCreds(t *testing.T) {
	s, _ := authServer(t, mockMinio{}, mockStore{}, okNomad("x"))
	rr := postForm(t, s, "/auth/login", url.Values{"username": {"alice"}, "password": {"wrong"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Invalid username or password") {
		t.Fatalf("status=%d, want form with 'Invalid'", rr.Code)
	}
}

func TestLoginPost_Valid(t *testing.T) {
	store := fakeStore{find: func(context.Context, string) (*Slot, error) { return nil, nil }}
	s, _ := authServer(t, mockMinio{}, store, okNomad("x"))
	rr := postForm(t, s, "/auth/login", url.Values{"username": {"alice"}, "password": {"goodpw"}, "next": {"/lab"}})
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d (%s), want 302", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "/lab" {
		t.Errorf("Location = %q", rr.Header().Get("Location"))
	}
	// The Set-Cookie must carry a valid session for alice.
	var token string
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("no session cookie set")
	}
	if user, ok := (sessionVerifier{secret: []byte(testSecret)}).verify(token); !ok || user != "alice" {
		t.Errorf("session cookie invalid: user=%q ok=%v", user, ok)
	}
}

func TestLoginPost_Suspended(t *testing.T) {
	store := fakeStore{find: func(context.Context, string) (*Slot, error) {
		return &Slot{State: "suspended"}, nil
	}}
	s, _ := authServer(t, mockMinio{}, store, okNomad("x"))
	rr := postForm(t, s, "/auth/login", url.Values{"username": {"alice"}, "password": {"goodpw"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "suspended") {
		t.Fatalf("status=%d, want form with 'suspended'", rr.Code)
	}
}

func TestLogout(t *testing.T) {
	s, _ := authServer(t, mockMinio{}, mockStore{}, okNomad("x"))
	rr := httptestGET(t, s, "/auth/logout", nil)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/auth/login" {
		t.Fatalf("status=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	sc := rr.Header().Get("Set-Cookie")
	if !strings.Contains(sc, sessionCookieName+"=") || !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("logout did not clear cookie: %q", sc)
	}
}
