package authsvc

import (
	"context"
	"net/http"
	"testing"
)

func verifyServer(t *testing.T, nomad NomadValidator) *Server {
	t.Helper()
	s, _ := newP4Server(t, "", Upstreams{Nomad: nomad, Hub: okHub()})
	return s
}

func TestVerify_MissingToken(t *testing.T) {
	s := verifyServer(t, fakeNomad{fn: func(context.Context, string) (*NomadTokenSelf, error) {
		return nil, ErrInvalidToken
	}})
	rr := httptestGET(t, s, "/verify", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
}

func TestVerify_ClientToken_SetsIdentityHeaders(t *testing.T) {
	s := verifyServer(t, fakeNomad{fn: func(context.Context, string) (*NomadTokenSelf, error) {
		return &NomadTokenSelf{Name: "pool-solar_civet", Type: "client",
			Namespace: "su-mbhg-hostgen", Policies: []string{"su-mbhg-hostgen-pool"}}, nil
	}})
	rr := httptestGET(t, s, "/verify", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	h := rr.Header()
	if h.Get("X-Auth-User") != "pool-solar_civet" {
		t.Errorf("X-Auth-User=%q", h.Get("X-Auth-User"))
	}
	if h.Get("X-Auth-Group") != "su-mbhg-hostgen-pool" {
		t.Errorf("X-Auth-Group=%q", h.Get("X-Auth-Group"))
	}
	if h.Get("X-Auth-Namespace") != "su-mbhg-hostgen" {
		t.Errorf("X-Auth-Namespace=%q", h.Get("X-Auth-Namespace"))
	}
	if h.Get("X-Auth-Type") != "client" {
		t.Errorf("X-Auth-Type=%q", h.Get("X-Auth-Type"))
	}
}

func TestVerify_ManagementToken(t *testing.T) {
	s := verifyServer(t, fakeNomad{fn: func(context.Context, string) (*NomadTokenSelf, error) {
		return &NomadTokenSelf{Name: "root", Type: "management"}, nil
	}})
	rr := httptestGET(t, s, "/verify", map[string]string{"X-Nomad-Token": "t"})
	h := rr.Header()
	if h.Get("X-Auth-Group") != "admin" || h.Get("X-Auth-Namespace") != "*" || h.Get("X-Auth-Policies") != "management" {
		t.Errorf("management headers wrong: group=%q ns=%q pol=%q",
			h.Get("X-Auth-Group"), h.Get("X-Auth-Namespace"), h.Get("X-Auth-Policies"))
	}
}

// ── nomadIdentityHeaders unit cases (no HTTP) ────────────────────────────────

func TestNomadIdentityHeaders_RoleDerivation(t *testing.T) {
	h := nomadIdentityHeaders(&NomadTokenSelf{
		Name:  "ana",
		Type:  "client",
		Roles: []NomadRole{{ID: "r1", Name: "r-su-mtb-resistotyper-ml-member"}},
	})
	// role "r-..." → group strips the "r-" prefix; policy_str = "role:<name>".
	if h["X-Auth-Group"] != "su-mtb-resistotyper-ml-member" {
		t.Errorf("group=%q", h["X-Auth-Group"])
	}
	if h["X-Auth-Policies"] != "role:r-su-mtb-resistotyper-ml-member" {
		t.Errorf("policies=%q", h["X-Auth-Policies"])
	}
	// namespace guess strips the -member suffix.
	if h["X-Auth-Namespace"] != "su-mtb-resistotyper-ml" {
		t.Errorf("namespace=%q", h["X-Auth-Namespace"])
	}
}

func TestNomadIdentityHeaders_PoolSuffixNamespace(t *testing.T) {
	h := nomadIdentityHeaders(&NomadTokenSelf{
		Name: "pool-x", Type: "client", Policies: []string{"su-mbhg-hostgen-pool"},
	})
	if h["X-Auth-Namespace"] != "su-mbhg-hostgen" {
		t.Errorf("namespace guess wrong: %q", h["X-Auth-Namespace"])
	}
}
