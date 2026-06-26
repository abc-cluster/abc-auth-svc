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

	"filippo.io/age"
)

// keyGroup is one in-memory group record for the fake key store.
type keyGroup struct {
	name      string
	recipient string // age1…
	wrapped   string // root-MK-wrapped AGE-SECRET-KEY-1…
	version   int
	alg       string
}

// fakeKeyStore implements SlotStore + KeyStore for the keys handler tests.
type fakeKeyStore struct {
	slot    *Slot                // the authenticated caller (nil = invalid token)
	groups  map[string]*keyGroup // groupID -> record
	readErr error                // forces GroupKeyRecord to fail
}

func (f *fakeKeyStore) FindSlot(context.Context, string) (*Slot, error) { return f.slot, nil }
func (f *fakeKeyStore) GroupName(_ context.Context, slot *Slot) string {
	if slot != nil {
		if g := f.groups[slot.Group]; g != nil {
			return g.name
		}
		return slot.GroupName
	}
	return ""
}
func (f *fakeKeyStore) CachedSlotState(context.Context, string) string { return "claimed" }

func (f *fakeKeyStore) GroupKeyRecord(_ context.Context, groupID string) (name, recipient, wrapped string, version int, alg string, hasKey bool, err error) {
	if f.readErr != nil {
		return "", "", "", 0, "", false, f.readErr
	}
	g := f.groups[groupID]
	if g == nil {
		return "", "", "", 0, "", false, fmt.Errorf("group_not_found")
	}
	return g.name, g.recipient, g.wrapped, g.version, g.alg, g.recipient != "" && g.wrapped != "", nil
}
func (f *fakeKeyStore) PutGroupKey(_ context.Context, groupID, recipient, wrapped string, version int, alg string) error {
	g := f.groups[groupID]
	if g == nil {
		return fmt.Errorf("group_not_found")
	}
	g.recipient, g.wrapped, g.version, g.alg = recipient, wrapped, version, alg
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

// TestKeys_MintThenGet_RoundTrip is the core: operator mints a group age keypair,
// then a member releases it via /keys/get and gets a valid age identity whose
// recipient matches what mint stored.
func TestKeys_MintThenGet_RoundTrip(t *testing.T) {
	store := &fakeKeyStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*keyGroup{"gidA": {name: "abc-grp-a"}},
	}
	s := keysServer(t, store, testMKB64())

	// mint
	rr := post(t, s, "/keys/mint", `{"group_id":"gidA"}`, opHdrs())
	if rr.Code != http.StatusOK {
		t.Fatalf("mint status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
	var mint struct {
		KekID     string `json:"kek_id"`
		Version   int    `json:"version"`
		Recipient string `json:"recipient"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &mint)
	if mint.KekID != "group:abc-grp-a" || mint.Version != 1 {
		t.Fatalf("mint kek_id=%q version=%d", mint.KekID, mint.Version)
	}
	if store.groups["gidA"].wrapped == "" || store.groups["gidA"].recipient == "" {
		t.Fatal("mint did not write recipient + wrapped secret to PB")
	}
	if !strings.HasPrefix(mint.Recipient, "age1") {
		t.Fatalf("mint recipient %q is not an age recipient", mint.Recipient)
	}

	// get (member of group A)
	rr = post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusOK {
		t.Fatalf("get status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
	var got struct {
		KekID     string `json:"kek_id"`
		Version   int    `json:"version"`
		Recipient string `json:"recipient"`
		Identity  string `json:"identity"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.KekID != "group:abc-grp-a" || got.Version != 1 {
		t.Fatalf("get kek_id=%q version=%d", got.KekID, got.Version)
	}
	if got.Recipient != store.groups["gidA"].recipient {
		t.Fatalf("released recipient %q != stored %q", got.Recipient, store.groups["gidA"].recipient)
	}
	// The released identity must parse and its recipient must match.
	ids, err := age.ParseIdentities(strings.NewReader(got.Identity))
	if err != nil || len(ids) != 1 {
		t.Fatalf("released identity does not parse: err=%v n=%d", err, len(ids))
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("released identity is not X25519: %T", ids[0])
	}
	if x.Recipient().String() != got.Recipient {
		t.Fatalf("identity recipient %q != released recipient %q", x.Recipient().String(), got.Recipient)
	}
}

// TestKeys_CrossGroupDenied: a member of group A asking for group B's key is 403.
func TestKeys_CrossGroupDenied(t *testing.T) {
	store := &fakeKeyStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*keyGroup{"gidA": {name: "abc-grp-a", recipient: "age1x", wrapped: "x", version: 1}},
	}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/get", `{"kek_id":"group:abc-grp-b"}`, bearer("abco_x"))
	if rr.Code != http.StatusForbidden || !strings.Contains(decodeErr(t, rr), "not_a_member") {
		t.Fatalf("cross-group: status=%d err=%q (want 403 not_a_member)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_GetNotProvisioned: a member of a group with no key yet gets 404.
func TestKeys_GetNotProvisioned(t *testing.T) {
	store := &fakeKeyStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*keyGroup{"gidA": {name: "abc-grp-a"}}, // no key
	}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusNotFound || !strings.Contains(decodeErr(t, rr), "key_not_provisioned") {
		t.Fatalf("status=%d err=%q (want 404 key_not_provisioned)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_MintRequiresOperator: /keys/mint without the operator token is 401.
func TestKeys_MintRequiresOperator(t *testing.T) {
	store := &fakeKeyStore{groups: map[string]*keyGroup{"gidA": {name: "abc-grp-a"}}}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/mint", `{"group_id":"gidA"}`, bearer("abco_x")) // no X-Operator-Token
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d (want 401)", rr.Code)
	}
}

// TestKeys_UnconfiguredMK: with no root MK, /keys/get is 503.
func TestKeys_UnconfiguredMK(t *testing.T) {
	store := &fakeKeyStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*keyGroup{"gidA": {name: "abc-grp-a", recipient: "age1x", wrapped: "x", version: 1}},
	}
	s := keysServer(t, store, "") // no MK
	rr := post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(decodeErr(t, rr), "managed_encryption_unconfigured") {
		t.Fatalf("status=%d err=%q (want 503)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_GetRequiresBearer: no Authorization header → 401.
func TestKeys_GetRequiresBearer(t *testing.T) {
	store := &fakeKeyStore{groups: map[string]*keyGroup{}}
	s := keysServer(t, store, testMKB64())
	rr := post(t, s, "/keys/get", "", nil)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(decodeErr(t, rr), "missing_bearer_token") {
		t.Fatalf("status=%d err=%q (want 401)", rr.Code, decodeErr(t, rr))
	}
}

// TestKeys_MintRotatesVersion: minting twice bumps the version and the new keypair
// is still releasable + valid.
func TestKeys_MintRotatesVersion(t *testing.T) {
	store := &fakeKeyStore{
		slot:   &Slot{ID: "s1", SlotName: "slot-a", Group: "gidA", State: "claimed"},
		groups: map[string]*keyGroup{"gidA": {name: "abc-grp-a"}},
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
	rr = post(t, s, "/keys/get", "", bearer("abco_x"))
	if rr.Code != http.StatusOK {
		t.Fatalf("get after rotate: status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}
