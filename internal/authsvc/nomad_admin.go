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
)

// ErrVarNotFound is the Variable-store 404 — surfaced to /auth/secrets/get
// callers as HTTP 404 with body {"error":"not_found"}.
var ErrVarNotFound = errors.New("nomad variable not found")

// NomadAdmin is the management-tier surface NomadClient implements on top of
// LookupTokenSelf. The methods all need the operator-tier NOMAD_TOKEN (held
// by auth-svc) — distinct from the slot-tier token the caller presents on a
// /auth/secrets/* or /slots/claim request. Mirrors the Python service's
// _nomad_api helpers (lines 671–716 of abc-auth-svc.py).
type NomadAdmin interface {
	// VarGet returns the "value" item at path in namespace, or ErrVarNotFound.
	VarGet(ctx context.Context, namespace, path string) (string, error)
	// VarPut writes a Variable holding a single "value" item.
	VarPut(ctx context.Context, namespace, path, value string) error
	// CreateToken mints a new client-tier ACL token for slot_name + role_id
	// (empty role_id → no role). Returns (accessor, secret).
	CreateToken(ctx context.Context, slotName, roleID string) (string, string, error)
	// DeleteToken revokes an ACL token by accessor id. Best-effort — callers
	// log and ignore failures (matches Python _nomad_delete_token).
	DeleteToken(ctx context.Context, accessor string) error
	// GetRoleID looks up an ACL role by name, returning its id or "" if not
	// found. Used by /manage/slots/rotate to attach the per-group pool role
	// to a freshly-minted slot token.
	GetRoleID(ctx context.Context, roleName string) (string, error)
}

// AdminClient extends NomadClient with the operator-tier surface. The same
// HTTP client + base URL is used; AdminToken is the management-tier token
// held only by auth-svc (NOMAD_TOKEN env var). Kept here (separate file
// from nomad.go) so the read-only LookupTokenSelf surface stays minimal.
type AdminClient struct {
	*NomadClient
	AdminToken string
}

// nomadVarBody mirrors Nomad's Variable JSON: {Path, Namespace, Items: {key: val}}.
type nomadVarBody struct {
	Path      string            `json:"Path"`
	Namespace string            `json:"Namespace"`
	Items     map[string]string `json:"Items"`
}

func (c *AdminClient) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Addr, "/")+path, payload)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Nomad-Token", c.AdminToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return rb, resp.StatusCode, nil
}

func (c *AdminClient) VarGet(ctx context.Context, namespace, path string) (string, error) {
	q := "/v1/var/" + url.PathEscape(path) + "?namespace=" + url.QueryEscape(namespace)
	rb, status, err := c.do(ctx, http.MethodGet, q, nil)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", ErrVarNotFound
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("nomad var get: HTTP %d", status)
	}
	var out struct {
		Items map[string]string `json:"Items"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	v, ok := out.Items["value"]
	if !ok {
		return "", ErrVarNotFound
	}
	return v, nil
}

func (c *AdminClient) VarPut(ctx context.Context, namespace, path, value string) error {
	body := nomadVarBody{Path: path, Namespace: namespace, Items: map[string]string{"value": value}}
	q := "/v1/var/" + url.PathEscape(path) + "?namespace=" + url.QueryEscape(namespace)
	_, status, err := c.do(ctx, http.MethodPut, q, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("nomad var put: HTTP %d", status)
	}
	return nil
}

func (c *AdminClient) CreateToken(ctx context.Context, slotName, roleID string) (string, string, error) {
	body := map[string]any{
		"Name":     "pool-" + slotName,
		"Type":     "client",
		"Policies": []string{},
	}
	if roleID != "" {
		body["Roles"] = []map[string]string{{"ID": roleID}}
	} else {
		body["Roles"] = []map[string]string{}
	}
	rb, status, err := c.do(ctx, http.MethodPost, "/v1/acl/token", body)
	if err != nil {
		return "", "", err
	}
	if status < 200 || status >= 300 {
		return "", "", fmt.Errorf("nomad token create: HTTP %d", status)
	}
	var out struct {
		AccessorID string `json:"AccessorID"`
		SecretID   string `json:"SecretID"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", "", err
	}
	return out.AccessorID, out.SecretID, nil
}

func (c *AdminClient) DeleteToken(ctx context.Context, accessor string) error {
	if accessor == "" {
		return nil
	}
	_, status, err := c.do(ctx, http.MethodDelete, "/v1/acl/token/"+url.PathEscape(accessor), nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("nomad token delete: HTTP %d", status)
	}
	return nil
}

func (c *AdminClient) GetRoleID(ctx context.Context, roleName string) (string, error) {
	rb, status, err := c.do(ctx, http.MethodGet, "/v1/acl/roles", nil)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("nomad acl roles: HTTP %d", status)
	}
	var roles []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(rb, &roles); err != nil {
		return "", err
	}
	for _, r := range roles {
		if r.Name == roleName {
			return r.ID, nil
		}
	}
	return "", nil
}
