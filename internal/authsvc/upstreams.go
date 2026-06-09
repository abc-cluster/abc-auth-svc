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
	NomadAdmin   NomadAdmin // operator-tier: Variables KV + ACL token mint/delete
	Hub          HubMinter
	Store        SlotStore
	Minio        MinIOValidator
	MinioAdmin   MinIOAdmin // operator-tier: rotate / enable / disable
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
			NomadAdmin:   mockNomadAdmin{},
			Hub:          mockHub{},
			Store:        mockStore{},
			Minio:        mockMinio{},
			MinioAdmin:   mockMinioAdmin{},
			Cluster:      cluster,
			HubPublicURL: cfg.HubPublicURL,
		}
	}
	nomadHTTP := &http.Client{Timeout: 5 * time.Second}
	nomadClient := &NomadClient{Addr: cfg.NomadAddr, HTTP: nomadHTTP}
	return Upstreams{
		Nomad:        nomadClient,
		NomadAdmin:   &AdminClient{NomadClient: nomadClient, AdminToken: cfg.NomadAdminToken},
		Hub:          &HubClient{APIURL: cfg.JupyterHubAPIURL, AdminToken: cfg.JupyterHubAdminToken, HTTP: &http.Client{Timeout: 10 * time.Second}},
		Store:        NewPBClient(cfg.PocketBaseURL, cfg.PBAdminEmail, cfg.PBAdminPassword, &http.Client{Timeout: 10 * time.Second}),
		Minio:        &ConsoleValidator{ConsoleURL: cfg.MinioConsoleURL, HTTP: &http.Client{Timeout: 8 * time.Second}},
		MinioAdmin:   &MCAdmin{Binary: cfg.MCLIBinary, AliasName: cfg.MCLIAlias},
		Cluster:      cluster,
		HubPublicURL: cfg.HubPublicURL,
	}
}

// ── Mock upstreams (deterministic; --mock-upstreams) ──────────────────────────

// mockNomadAdmin: deterministic responses for local dev / contributor tests.
// Each mint produces a synthetic accessor/secret pair; Variables persist in
// an in-process map; DeleteToken / SetEnabled are no-ops.
type mockNomadAdmin struct{}

func (mockNomadAdmin) VarGet(_ context.Context, _, _ string) (string, error) {
	return "", ErrVarNotFound
}
func (mockNomadAdmin) VarPut(_ context.Context, _, _, _ string) error { return nil }
func (mockNomadAdmin) CreateToken(_ context.Context, slot, _ string) (string, string, error) {
	return "mock-accessor-" + slot, "mock-secret-" + slot, nil
}
func (mockNomadAdmin) DeleteToken(_ context.Context, _ string) error          { return nil }
func (mockNomadAdmin) GetRoleID(_ context.Context, _ string) (string, error)  { return "mock-role", nil }


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
func (mockStore) ListSlots(context.Context, string, int) ([]Slot, error) {
	return []Slot{*mockSlot()}, nil
}
