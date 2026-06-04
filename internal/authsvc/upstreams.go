package authsvc

import (
	"context"
	"net/http"
	"time"
)

// Upstreams bundles the external dependencies the handlers call. It is injected
// into the server so tests can substitute mocks.
type Upstreams struct {
	Nomad        NomadValidator
	Hub          HubMinter
	HubPublicURL string
}

// BuildUpstreams constructs the real upstream clients from config — or
// deterministic mocks when --mock-upstreams is set (local dev / contributor
// testing without a live cluster).
func BuildUpstreams(cfg Config) Upstreams {
	if cfg.MockUpstreams {
		return Upstreams{
			Nomad:        mockNomad{},
			Hub:          mockHub{},
			HubPublicURL: cfg.HubPublicURL,
		}
	}
	return Upstreams{
		Nomad:        &NomadClient{Addr: cfg.NomadAddr, HTTP: &http.Client{Timeout: 5 * time.Second}},
		Hub:          &HubClient{APIURL: cfg.JupyterHubAPIURL, AdminToken: cfg.JupyterHubAdminToken, HTTP: &http.Client{Timeout: 10 * time.Second}},
		HubPublicURL: cfg.HubPublicURL,
	}
}

// ── Mock upstreams (deterministic; --mock-upstreams) ──────────────────────────

type mockNomad struct{}

// LookupTokenSelf treats the literal token "invalid" (or empty) as bad; anything
// else resolves to a fixed pool slot, so `abc workbench connect` can be exercised
// end-to-end against the Go service without a cluster.
func (mockNomad) LookupTokenSelf(_ context.Context, token string) (*NomadTokenSelf, error) {
	if token == "" || token == "invalid" {
		return nil, ErrInvalidToken
	}
	return &NomadTokenSelf{Name: "pool-calm_dassie", Type: "client", Namespace: "su-mbhg-hostgen"}, nil
}

type mockHub struct{}

func (mockHub) MintUserToken(_ context.Context, user, note string, expiresIn int64) (*JHToken, error) {
	return &JHToken{
		Token:     "mock-jh-token-for-" + user,
		ID:        "mock-1",
		ExpiresAt: "2026-06-11T00:00:00Z",
		Scopes:    []string{"access:servers!user=" + user},
		Note:      note,
	}, nil
}
