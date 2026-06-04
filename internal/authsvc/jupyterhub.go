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

// JHToken mirrors the object JupyterHub returns on POST /users/<u>/tokens.
type JHToken struct {
	Token     string   `json:"token"`
	ID        string   `json:"id"`
	ExpiresAt string   `json:"expires_at"`
	Scopes    []string `json:"scopes"`
	Note      string   `json:"note"`
}

// HubMinter mints a JupyterHub user token for a given JH username.
type HubMinter interface {
	MintUserToken(ctx context.Context, user, note string, expiresIn int64) (*JHToken, error)
}

// hubErrorKind distinguishes a JupyterHub HTTP-status error (→ 502) from an
// unreachable hub / transport error (→ 503), matching the Python service.
type hubErrorKind int

const (
	hubHTTPError hubErrorKind = iota
	hubUnreachable
)

// HubError carries a classified JupyterHub failure.
type HubError struct {
	Kind   hubErrorKind
	Status int
	Body   string
	Err    error
}

func (e *HubError) Error() string {
	if e.Kind == hubHTTPError {
		return fmt.Sprintf("hub mint failed: HTTP %d", e.Status)
	}
	return fmt.Sprintf("hub unreachable: %v", e.Err)
}

func (e *HubError) Unwrap() error { return e.Err }

// HubClient is the real HubMinter. It holds the JupyterHub admin token (the only
// place that does), so individual slots never need an admin-tier credential.
type HubClient struct {
	APIURL     string // e.g. http://127.0.0.1:15001/hub/api
	AdminToken string
	HTTP       *http.Client
}

// MintUserToken calls POST {APIURL}/users/<user>/tokens with the admin token.
func (c *HubClient) MintUserToken(ctx context.Context, user, note string, expiresIn int64) (*JHToken, error) {
	if strings.TrimSpace(c.AdminToken) == "" {
		return nil, &HubError{Kind: hubUnreachable, Err: errors.New("JUPYTERHUB_API_TOKEN not configured")}
	}
	payload := map[string]any{}
	if note != "" {
		payload["note"] = note
	}
	if expiresIn > 0 {
		payload["expires_in"] = expiresIn
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := strings.TrimRight(c.APIURL, "/") + "/users/" + url.PathEscape(user) + "/tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+c.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, &HubError{Kind: hubUnreachable, Err: err}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HubError{Kind: hubHTTPError, Status: resp.StatusCode, Body: string(rb)}
	}
	var out JHToken
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
