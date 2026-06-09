package authsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MinIOValidator checks whether an (accessKey, secretKey) pair is a real MinIO
// credential — used by the browser login.
type MinIOValidator interface {
	ValidateCredential(ctx context.Context, accessKey, secretKey string) (bool, error)
}

// MinIOConsoleLogin extends MinIOValidator with a JWT-returning console login
// — used by /auth/cli-token (portal=minio) to pre-fetch the STS token and by
// /auth/minio-login to set the MinIO console cookie. Mirrors the Python
// _minio_console_login helper.
type MinIOConsoleLogin interface {
	ConsoleLogin(ctx context.Context, accessKey, secretKey string) (string, error)
}

// ConsoleValidator validates credentials via the MinIO Console login API
// (POST /api/v1/login). A 200/204 means the credential authenticated; 401/403
// means it did not. This is a credential check equivalent to the Python's S3
// list_buckets probe (which treats an authorized-but-denied 403 as valid) —
// console login likewise succeeds for restricted members, so it needs no
// special-casing.
type ConsoleValidator struct {
	ConsoleURL string
	HTTP       *http.Client
}

func (c *ConsoleValidator) ValidateCredential(ctx context.Context, accessKey, secretKey string) (bool, error) {
	payload, _ := json.Marshal(map[string]string{"accessKey": accessKey, "secretKey": secretKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.ConsoleURL, "/")+"/api/v1/login", bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
		return true, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("minio console login: HTTP %d", resp.StatusCode)
	}
}

// ConsoleLogin posts to MinIO console /api/v1/login and extracts the JWT
// session token from the Set-Cookie header. Returns ("", nil) on a clean
// auth-rejected 401/403; an error only on transport/parse failure.
func (c *ConsoleValidator) ConsoleLogin(ctx context.Context, accessKey, secretKey string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"accessKey": accessKey, "secretKey": secretKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.ConsoleURL, "/")+"/api/v1/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		for _, c := range resp.Cookies() {
			if c.Name == "token" && c.Value != "" {
				return c.Value, nil
			}
		}
		return "", fmt.Errorf("minio console login: no token cookie in 2xx response")
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", nil
	default:
		return "", fmt.Errorf("minio console login: HTTP %d", resp.StatusCode)
	}
}

// mockMinio (for --mock-upstreams): any non-empty pair is valid except the
// sentinel secret "wrong", so the login flow can be exercised locally.
type mockMinio struct{}

func (mockMinio) ValidateCredential(_ context.Context, accessKey, secretKey string) (bool, error) {
	return accessKey != "" && secretKey != "" && secretKey != "wrong", nil
}

func (mockMinio) ConsoleLogin(_ context.Context, accessKey, secretKey string) (string, error) {
	if accessKey == "" || secretKey == "" || secretKey == "wrong" {
		return "", nil
	}
	return "mock-jwt-" + accessKey, nil
}
