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

// mockMinio (for --mock-upstreams): any non-empty pair is valid except the
// sentinel secret "wrong", so the login flow can be exercised locally.
type mockMinio struct{}

func (mockMinio) ValidateCredential(_ context.Context, accessKey, secretKey string) (bool, error) {
	return accessKey != "" && secretKey != "" && secretKey != "wrong", nil
}
