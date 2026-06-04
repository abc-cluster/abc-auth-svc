package authsvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// ErrInvalidToken is returned when a Nomad ACL token does not validate. The
// handler maps any LookupTokenSelf failure to 401, matching the Python service.
var ErrInvalidToken = errors.New("invalid or expired nomad token")

// NomadTokenSelf is the subset of GET /v1/acl/token/self we consume. Nomad
// returns PascalCase keys; default (case-insensitive) decoding matches them.
type NomadTokenSelf struct {
	Name      string
	Type      string
	Namespace string
	Policies  []string
	Roles     []NomadRole
}

// NomadRole is a role reference on a token (only Name is used today).
type NomadRole struct {
	ID   string
	Name string
}

// NomadValidator validates an inbound Nomad ACL token and returns its identity.
type NomadValidator interface {
	LookupTokenSelf(ctx context.Context, token string) (*NomadTokenSelf, error)
}

// NomadClient is the real NomadValidator: GET {Addr}/v1/acl/token/self with the
// caller's token in X-Nomad-Token.
type NomadClient struct {
	Addr string
	HTTP *http.Client
}

// LookupTokenSelf validates token against Nomad's ACL self endpoint. A non-200
// response (e.g. 403) yields ErrInvalidToken; a transport error is returned as-is
// (the handler treats both as 401, matching the Python service).
func (c *NomadClient) LookupTokenSelf(ctx context.Context, token string) (*NomadTokenSelf, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrInvalidToken
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Addr, "/")+"/v1/acl/token/self", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Nomad-Token", token)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrInvalidToken
	}
	var out NomadTokenSelf
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
