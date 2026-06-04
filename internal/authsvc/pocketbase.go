package authsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Slot is the subset of a PocketBase `slots` record the service reads. Secret
// fields (nomad_token_secret, minio_secret_key) are part of the /auth/exchange
// payload by design — they must be returned to the caller but never logged.
type Slot struct {
	ID               string `json:"id"`
	SlotName         string `json:"slot_name"`
	Group            string `json:"group"`      // relation id
	GroupName        string `json:"group_name"` // sometimes denormalised onto the record
	NomadTokenSecret string `json:"nomad_token_secret"`
	MinioAccessKey   string `json:"minio_access_key"`
	MinioSecretKey   string `json:"minio_secret_key"`
	State            string `json:"state"`
	CredSource       string `json:"cred_source"`
	OpaqueTokenHash  string `json:"opaque_token_hash"`
	ConfigYAML       string `json:"config_yaml"`
}

// SlotStore is the read-path slot/group access the common handlers depend on
// (interface so tests can substitute a fake).
type SlotStore interface {
	// FindSlot returns the first slot matching a PocketBase filter expression, or
	// (nil, nil) when none match.
	FindSlot(ctx context.Context, filter string) (*Slot, error)
	// GroupName resolves the slot's group display name.
	GroupName(ctx context.Context, slot *Slot) string
	// CachedSlotState returns the slot state for a username (keyed on
	// minio_access_key), with a short cache. "none" = no such slot; "error" =
	// store unreachable (callers fail open).
	CachedSlotState(ctx context.Context, username string) string
}

// SlotManager adds the write operations the operator endpoints need. The real
// PBClient implements it; the cred-source flip handler type-asserts for it.
type SlotManager interface {
	SlotStore
	GetSlot(ctx context.Context, id string) (*Slot, error)
	PatchSlot(ctx context.Context, id string, fields map[string]any) error
	InvalidateSlotState(username string)
}

// PBClient is the real SlotStore: an authenticated PocketBase REST client with a
// cached superuser token (lazy re-auth on 401) and a short slot-state cache.
type PBClient struct {
	URL           string
	AdminEmail    string
	AdminPassword string
	HTTP          *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time

	stateMu   sync.Mutex
	stateTTL  time.Duration
	stateData map[string]slotStateEntry
}

type slotStateEntry struct {
	state string
	ts    time.Time
}

// NewPBClient builds a PocketBase client. The slot-state cache TTL is 60s,
// matching the Python service (a suspended slot is denied within ~60s).
func NewPBClient(pbURL, adminEmail, adminPassword string, httpc *http.Client) *PBClient {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	return &PBClient{
		URL:           strings.TrimRight(pbURL, "/"),
		AdminEmail:    adminEmail,
		AdminPassword: adminPassword,
		HTTP:          httpc,
		stateTTL:      60 * time.Second,
		stateData:     make(map[string]slotStateEntry),
	}
}

// authToken returns a valid superuser JWT, re-authenticating when near expiry.
func (c *PBClient) authToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp.Add(-60*time.Second)) {
		return c.token, nil
	}
	body, _ := json.Marshal(map[string]string{"identity": c.AdminEmail, "password": c.AdminPassword})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.URL+"/api/collections/_superusers/auth-with-password", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return "", fmt.Errorf("pocketbase auth: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("pocketbase auth: empty token")
	}
	c.token = out.Token
	c.tokenExp = time.Now().Add(6 * 24 * time.Hour) // conservative TTL
	return c.token, nil
}

func (c *PBClient) clearToken() {
	c.mu.Lock()
	c.token, c.tokenExp = "", time.Time{}
	c.mu.Unlock()
}

// do issues an authenticated request, retrying once on 401 (token expiry).
func (c *PBClient) do(ctx context.Context, method, path string, body []byte, retry bool) ([]byte, error) {
	tok, err := c.authToken(ctx)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized && retry {
		c.clearToken()
		return c.do(ctx, method, path, body, false)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("pocketbase %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	return rb, nil
}

// FindSlot returns the first slot matching a PocketBase filter expression.
func (c *PBClient) FindSlot(ctx context.Context, filter string) (*Slot, error) {
	path := "/api/collections/slots/records?perPage=1&skipTotal=1&filter=" + url.QueryEscape(filter)
	rb, err := c.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return nil, err
	}
	var out struct {
		Items []Slot `json:"items"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, err
	}
	if len(out.Items) == 0 {
		return nil, nil
	}
	return &out.Items[0], nil
}

// GetSlot fetches a single slot record by id.
func (c *PBClient) GetSlot(ctx context.Context, id string) (*Slot, error) {
	rb, err := c.do(ctx, http.MethodGet, "/api/collections/slots/records/"+url.PathEscape(id), nil, true)
	if err != nil {
		return nil, err
	}
	var s Slot
	if err := json.Unmarshal(rb, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// PatchSlot updates fields on a slot record.
func (c *PBClient) PatchSlot(ctx context.Context, id string, fields map[string]any) error {
	body, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, "/api/collections/slots/records/"+url.PathEscape(id), body, true)
	return err
}

// InvalidateSlotState evicts a username from the slot-state cache (call after a
// state-changing operation).
func (c *PBClient) InvalidateSlotState(username string) {
	c.stateMu.Lock()
	delete(c.stateData, username)
	c.stateMu.Unlock()
}

// GroupName resolves a slot's group display name (denormalised field, else a
// groups-record lookup).
func (c *PBClient) GroupName(ctx context.Context, slot *Slot) string {
	if slot == nil {
		return ""
	}
	if n := strings.TrimSpace(slot.GroupName); n != "" {
		return n
	}
	if slot.Group == "" {
		return ""
	}
	rb, err := c.do(ctx, http.MethodGet, "/api/collections/groups/records/"+url.PathEscape(slot.Group), nil, true)
	if err != nil {
		return ""
	}
	var g struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rb, &g); err != nil {
		return ""
	}
	return g.Name
}

// CachedSlotState returns a slot's state keyed on minio_access_key, with a 60s
// cache. "none" when no slot matches; "error" when PocketBase is unreachable
// (callers fail open, matching the Python service).
func (c *PBClient) CachedSlotState(ctx context.Context, username string) string {
	now := time.Now()
	c.stateMu.Lock()
	if e, ok := c.stateData[username]; ok && now.Sub(e.ts) < c.stateTTL {
		c.stateMu.Unlock()
		return e.state
	}
	c.stateMu.Unlock()

	state := "none"
	slot, err := c.FindSlot(ctx, "minio_access_key='"+username+"'")
	if err != nil {
		state = "error"
	} else if slot != nil {
		state = slot.State
	}

	c.stateMu.Lock()
	c.stateData[username] = slotStateEntry{state: state, ts: now}
	c.stateMu.Unlock()
	return state
}
