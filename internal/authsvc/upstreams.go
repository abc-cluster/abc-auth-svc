package authsvc

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// ClusterInfo is the cluster identity stamped into the /auth/exchange bundle and
// the rendered config.yaml.
type ClusterInfo struct {
	Name           string
	NomadEndpoint  string
	MinioEndpoint  string
	UploadEndpoint string
	AuthEndpoint   string
	Datacenter     string
	HeadPool       string
	WorkerPool     string
}

// Upstreams bundles the external dependencies the handlers call. It is injected
// into the server so tests can substitute mocks.
type Upstreams struct {
	Nomad        NomadValidator
	Hub          HubMinter
	Store        SlotStore
	Cluster      ClusterInfo
	HubPublicURL string
}

// BuildUpstreams constructs the real upstream clients from config — or
// deterministic mocks when --mock-upstreams is set (local dev / contributor
// testing without a live cluster).
func BuildUpstreams(cfg Config) Upstreams {
	cluster := ClusterInfo{
		Name:           cfg.ClusterName,
		NomadEndpoint:  cfg.ClusterNomadEndpoint,
		MinioEndpoint:  cfg.ClusterMinioEndpoint,
		UploadEndpoint: cfg.ClusterUploadEndpoint,
		AuthEndpoint:   cfg.ClusterAuthEndpoint,
		Datacenter:     cfg.ClusterDatacenter,
		HeadPool:       cfg.ClusterHeadPool,
		WorkerPool:     cfg.ClusterWorkerPool,
	}
	if cfg.MockUpstreams {
		return Upstreams{
			Nomad:        mockNomad{},
			Hub:          mockHub{},
			Store:        mockStore{},
			Cluster:      cluster,
			HubPublicURL: cfg.HubPublicURL,
		}
	}
	return Upstreams{
		Nomad:        &NomadClient{Addr: cfg.NomadAddr, HTTP: &http.Client{Timeout: 5 * time.Second}},
		Hub:          &HubClient{APIURL: cfg.JupyterHubAPIURL, AdminToken: cfg.JupyterHubAdminToken, HTTP: &http.Client{Timeout: 10 * time.Second}},
		Store:        NewPBClient(cfg.PocketBaseURL, cfg.PBAdminEmail, cfg.PBAdminPassword, &http.Client{Timeout: 10 * time.Second}),
		Cluster:      cluster,
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

type mockStore struct{}

func mockSlot() *Slot {
	return &Slot{
		ID: "mock", SlotName: "slot-calm_dassie", GroupName: "mbhg-hostgen",
		NomadTokenSecret: "mock-nomad-token-secret", MinioAccessKey: "calm_dassie",
		MinioSecretKey: "mock-minio-secret-key", State: "claimed", CredSource: "seedling/v1",
	}
}

// FindSlot resolves opaque/slot_name lookups to a fixed claimed seedling/v1 slot
// so the broker / config / flip paths can be exercised without a PocketBase; any
// other filter returns no slot.
func (mockStore) FindSlot(_ context.Context, filter string) (*Slot, error) {
	if strings.Contains(filter, "opaque_token_hash=") || strings.Contains(filter, "slot_name=") {
		return mockSlot(), nil
	}
	return nil, nil
}

func (mockStore) GroupName(_ context.Context, slot *Slot) string {
	if slot != nil {
		return slot.GroupName
	}
	return ""
}

func (mockStore) CachedSlotState(context.Context, string) string          { return "none" }
func (mockStore) GetSlot(context.Context, string) (*Slot, error)          { return mockSlot(), nil }
func (mockStore) PatchSlot(context.Context, string, map[string]any) error { return nil }
func (mockStore) InvalidateSlotState(string)                              {}
