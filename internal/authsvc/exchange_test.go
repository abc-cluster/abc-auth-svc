package authsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// fakeStore is a configurable SlotStore for handler tests.
type fakeStore struct {
	find  func(ctx context.Context, filter string) (*Slot, error)
	group func(ctx context.Context, slot *Slot) string
	state func(ctx context.Context, username string) string
}

func (f fakeStore) FindSlot(ctx context.Context, filter string) (*Slot, error) {
	return f.find(ctx, filter)
}
func (f fakeStore) GroupName(ctx context.Context, slot *Slot) string {
	if f.group != nil {
		return f.group(ctx, slot)
	}
	if slot != nil {
		return slot.GroupName
	}
	return ""
}
func (f fakeStore) CachedSlotState(ctx context.Context, username string) string {
	if f.state != nil {
		return f.state(ctx, username)
	}
	return "none"
}

var testCluster = ClusterInfo{
	Name:           "seedling",
	NomadEndpoint:  "https://nomad.test",
	MinioEndpoint:  "https://s3.test",
	UploadEndpoint: "https://upload.test/files/",
	AuthEndpoint:   "https://auth.test",
	Datacenter:     "dc1",
	HeadPool:       "platform",
	WorkerPool:     "compute",
}

func exServer(t *testing.T, store SlotStore) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg, err := LoadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	up := Upstreams{Nomad: mockNomad{}, Hub: mockHub{}, Store: store, Cluster: testCluster, HubPublicURL: "https://workbench.test"}
	return NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up), &buf
}

func TestExchange_MissingBearer(t *testing.T) {
	s, _ := exServer(t, fakeStore{find: func(context.Context, string) (*Slot, error) { return nil, nil }})
	rr := post(t, s, "/auth/exchange", "", nil)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(decodeErr(t, rr), "missing_bearer_token") {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestExchange_EmptyBearer(t *testing.T) {
	s, _ := exServer(t, fakeStore{find: func(context.Context, string) (*Slot, error) { return nil, nil }})
	rr := post(t, s, "/auth/exchange", "", map[string]string{"Authorization": "Bearer    "})
	if rr.Code != http.StatusUnauthorized || !strings.Contains(decodeErr(t, rr), "empty_bearer_token") {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestExchange_NotFound(t *testing.T) {
	s, _ := exServer(t, fakeStore{find: func(context.Context, string) (*Slot, error) { return nil, nil }})
	rr := post(t, s, "/auth/exchange", "", map[string]string{"Authorization": "Bearer abco_whatever"})
	if rr.Code != http.StatusUnauthorized || !strings.Contains(decodeErr(t, rr), "invalid_or_inactive_token") {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestExchange_LookupError(t *testing.T) {
	s, _ := exServer(t, fakeStore{find: func(context.Context, string) (*Slot, error) {
		return nil, context.DeadlineExceeded
	}})
	rr := post(t, s, "/auth/exchange", "", map[string]string{"Authorization": "Bearer abco_x"})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rr.Code)
	}
}

func TestExchange_WrongCredSource(t *testing.T) {
	s, _ := exServer(t, fakeStore{find: func(context.Context, string) (*Slot, error) {
		return &Slot{SlotName: "slot-x", State: "claimed", CredSource: "local"}, nil
	}})
	rr := post(t, s, "/auth/exchange", "", map[string]string{"Authorization": "Bearer abco_x"})
	if rr.Code != http.StatusConflict || !strings.Contains(decodeErr(t, rr), "slot_not_on_seedling_v1") {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestExchange_HappyBundle(t *testing.T) {
	var gotFilter string
	store := fakeStore{
		find: func(_ context.Context, filter string) (*Slot, error) {
			gotFilter = filter
			return &Slot{
				SlotName: "slot-calm_dassie", GroupName: "mbhg-hostgen", State: "claimed",
				CredSource: "seedling/v1", NomadTokenSecret: "NTSECRET-aaa", MinioAccessKey: "calm_dassie",
				MinioSecretKey: "MSSECRET-bbb",
			}, nil
		},
	}
	s, buf := exServer(t, store)
	rr := post(t, s, "/auth/exchange", "", map[string]string{"Authorization": "Bearer abco_realtoken"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d (%s), want 200", rr.Code, rr.Body.String())
	}

	// The filter must use the HASH and require state=claimed; never the bare opaque.
	if !strings.Contains(gotFilter, "opaque_token_hash='"+sha256Hex("abco_realtoken")+"'") ||
		!strings.Contains(gotFilter, "state='claimed'") {
		t.Errorf("filter = %q", gotFilter)
	}
	if strings.Contains(gotFilter, "abco_realtoken") {
		t.Errorf("bare opaque leaked into filter: %q", gotFilter)
	}

	var b credsBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if b.Whoami != "slot-calm_dassie" || b.Source != "seedling/v1" {
		t.Errorf("whoami/source = %q/%q", b.Whoami, b.Source)
	}
	if b.Nomad.Addr != "https://nomad.test" || b.Nomad.Token != "NTSECRET-aaa" || b.Nomad.Namespace != "su-mbhg-hostgen" {
		t.Errorf("nomad = %+v", b.Nomad)
	}
	if len(b.Nomad.Datacenters) != 1 || b.Nomad.Datacenters[0] != "dc1" || b.Nomad.HeadPool != "platform" || b.Nomad.WorkerPool != "compute" {
		t.Errorf("nomad pools/dc = %+v", b.Nomad)
	}
	if b.MinIO.Endpoint != "https://s3.test" || b.MinIO.AccessKey != "calm_dassie" || b.MinIO.SecretKey != "MSSECRET-bbb" {
		t.Errorf("minio = %+v", b.MinIO)
	}

	// Audit discipline: the per-slot secrets must NOT appear in the logs (the
	// bundle is the response payload, never logged).
	if strings.Contains(buf.String(), "NTSECRET-aaa") || strings.Contains(buf.String(), "MSSECRET-bbb") {
		t.Errorf("per-slot secret leaked into logs:\n%s", buf.String())
	}
}

// Slot-state guard on /auth/workbench/token (Phase 1b).
func TestWorkbenchToken_SuspendedSlotBlocked(t *testing.T) {
	store := fakeStore{
		find:  func(context.Context, string) (*Slot, error) { return nil, nil },
		state: func(_ context.Context, user string) string { return "suspended" },
	}
	var buf bytes.Buffer
	cfg, _ := LoadConfig(nil, func(string) string { return "" })
	up := Upstreams{Nomad: okNomad("pool-calm_dassie"), Hub: okHub(), Store: store, Cluster: testCluster, HubPublicURL: "https://hub.test"}
	s := NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up)

	rr := post(t, s, "/auth/workbench/token", "", map[string]string{"X-Nomad-Token": "t"})
	if rr.Code != http.StatusForbidden || !strings.Contains(decodeErr(t, rr), "slot is suspended") {
		t.Fatalf("status=%d err=%q, want 403 slot is suspended", rr.Code, decodeErr(t, rr))
	}
}
