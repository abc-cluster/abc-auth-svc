package authsvc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// kekGroup is one in-memory group record for the fake KEK store.
type kekGroup struct {
	name    string
	wrapped string
	version int
	alg     string
}

// fakeKEKStore implements SlotStore + KEKStore for the keys handler tests.
type fakeKEKStore struct {
	slot    *Slot                // the authenticated caller (nil = invalid token)
	groups  map[string]*kekGroup // groupID -> record
	readErr error                // forces GroupKEKRecord to fail
}

func (f *fakeKEKStore) FindSlot(context.Context, string) (*Slot, error) { return f.slot, nil }
func (f *fakeKEKStore) GroupName(_ context.Context, slot *Slot) string {
	if slot != nil {
		if g := f.groups[slot.Group]; g != nil {
			return g.name
		}
		return slot.GroupName
	}
	return ""
}
func (f *fakeKEKStore) CachedSlotState(context.Context, string) string { return "claimed" }

func (f *fakeKEKStore) GroupKEKRecord(_ context.Context, groupID string) (name, wrapped string, version int, alg string, hasKEK bool, err error) {
	if f.readErr != nil {
		return "", "", 0, "", false, f.readErr
	}
	g := f.groups[groupID]
	if g == nil {
		return "", "", 0, "", false, fmt.Errorf("group_not_found")
	}
	return g.name, g.wrapped, g.version, g.alg, g.wrapped != "", nil
}
func (f *fakeKEKStore) PutGroupKEK(_ context.Context, groupID, wrapped string, version int, alg string) error {
	g := f.groups[groupID]
	if g == nil {
		return fmt.Errorf("group_not_found")
	}
	g.wrapped, g.version, g.alg = wrapped, version, alg
	return nil
}

const testOpTok = "op-secret-token"

func testMKB64() string { return base64.StdEncoding.EncodeToString(make([]byte, mkLen)) }

func keysServer(t *testing.T, store SlotStore, mkB64 string) *Server {
	t.Helper()
	var buf bytes.Buffer
	getenv := func(k string) string {
		switch k {
		case "ABC_AUTH_ROOT_MK":
			return mkB64
		case "OPERATOR_TOKEN":
			return testOpTok
		}
		return ""
	}
	cfg, err := LoadConfig(nil, getenv)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	up := Upstreams{Nomad: mockNomad{}, Hub: mockHub{}, Store: store, Cluster: testCluster, HubPublicURL: "https://workbench.test"}
	return NewServer(cfg, NewLogger(&buf, L1, nil), BuildInfo{Version: "test"}, up)
}

// opHdrs adds the operator token to a member bearer (reuses bearer("abco_x") from secrets_test.go).
func opHdrs() map[string]string {
	h := bearer("abco_x")
	h["X-Operator-Token"] = testOpTok
	return h
}

// TestKeys_MintThenGet_RoundTrip is the core: operator mints a group KEK, then a
// member of that group releases it via /keys/get and gets a 32-byte key.
func TestKeys_MintThenGet_RoundTrip(t *testing.T) {
	store := &fakeKEKStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*kekGroup{"gidA": {name: "abc-grp-a"}},
	}
	s := keysServer(t, store, testMKB64())

	// mint
	rr := post(t, s, "/keys/mint", `{"group_id":"gidA"}`, opHdrs())
	if rr.Code != http.StatusOK {
		t.Fatalf("mint status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
	var mint struct {
		KekID   string `json:"kek_id"`
		Version int    `json:"version"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &mint)
	if mint.KekID != "group:abc-grp-a" || mint.Version != 1 {
		t.Fatalf("mint kek_id=%q version=%d", mint.KekID, mint.Version)
	}
	if store.groups["gidA"].wrapped == "" {
		t.Fatal("mint did not write wrapped KEK to PB")
	}

	// get (member of group A)
	rr = post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusOK {
		t.Fatalf("get status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
	var got struct {
		KekID   string `json:"kek_id"`
		Version int    `json:"version"`
		KEK     string `json:"kek"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.KekID != "group:abc-grp-a" || got.Version != 1 {
		t.Fatalf("get kek_id=%q version=%d", got.KekID, got.Version)
	}
	raw, err := base64.StdEncoding.DecodeString(got.KEK)
	if err != nil || len(raw) != kekLen {
		t.Fatalf("released KEK is not 32 bytes: len=%d err=%v", len(raw), err)
	}
}

// TestKeys_CrossGroupDenied: a member of group A asking for group B's KEK is 403.
func TestKeys_CrossGroupDenied(t *testing.T) {
	store := &fakeKEKStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*kekGroup{"gidA": {name: "abc-grp-a", wrapped: "x", version: 1}},
	}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/get", `{"kek_id":"group:abc-grp-b"}`, bearer("abco_x"))
	if rr.Code != http.StatusForbidden || !strings.Contains(decodeErr(t, rr), "not_a_member") {
		t.Fatalf("cross-group: status=%d err=%q (want 403 not_a_member)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_GetNotProvisioned: a member of a group with no KEK yet gets 404.
func TestKeys_GetNotProvisioned(t *testing.T) {
	store := &fakeKEKStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*kekGroup{"gidA": {name: "abc-grp-a"}}, // no wrapped KEK
	}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusNotFound || !strings.Contains(decodeErr(t, rr), "kek_not_provisioned") {
		t.Fatalf("status=%d err=%q (want 404 kek_not_provisioned)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_MintRequiresOperator: /keys/mint without the operator token is 401.
func TestKeys_MintRequiresOperator(t *testing.T) {
	store := &fakeKEKStore{groups: map[string]*kekGroup{"gidA": {name: "abc-grp-a"}}}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/mint", `{"group_id":"gidA"}`, bearer("abco_x")) // no X-Operator-Token
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d (want 401)", rr.Code)
	}
}

// TestKeys_UnconfiguredMK: with no root MK, /keys/get is 503.
func TestKeys_UnconfiguredMK(t *testing.T) {
	store := &fakeKEKStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*kekGroup{"gidA": {name: "abc-grp-a", wrapped: "x", version: 1}},
	}
	s := keysServer(t, store, "") // no MK
	rr := post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(decodeErr(t, rr), "managed_encryption_unconfigured") {
		t.Fatalf("status=%d err=%q (want 503)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_GetRequiresBearer: no Authorization header → 401.
func TestKeys_GetRequiresBearer(t *testing.T) {
	store := &fakeKEKStore{groups: map[string]*kekGroup{}}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/get", "", nil)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(decodeErr(t, rr), "missing_bearer_token") {
		t.Fatalf("status=%d err=%q (want 401)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_MintRotatesVersion: minting twice bumps the version and keeps it
// unwrappable at the new version.
func TestKeys_MintRotatesVersion(t *testing.T) {
	store := &fakeKEKStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*kekGroup{"gidA": {name: "abc-grp-a"}},
	}
	s := keysServer(t, store, testMKB64())
	_ = post(t, s, "/keys/mint", `{"group_id":"gidA"}`, opHdrs())
	rr := post(t, s, "/keys/mint", `{"group_id":"gidA"}`, opHdrs())
	var mint struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &mint)
	if mint.Version != 2 {
		t.Fatalf("second mint version=%d (want 2)", mint.Version)
	}
	// get must still work at the new version
	rr = post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusOK {
		t.Fatalf("get after rotate: status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}
