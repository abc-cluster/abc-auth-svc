package authsvc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

// MinIOAdmin is the credential-rotation / suspension surface used by
// /manage/slots/{rotate,suspend,reactivate}. The reference implementation
// shells out to the MinIO Client (`mcli admin user ...`) the same way the
// Python service does, with the same `sdroot` alias already configured at
// /root/.mcli/config.json on the deployment host. Going through the binary keeps us out
// of MinIO's Sig V4 admin API (saves several hundred lines of HMAC
// machinery for a single-host service).
type MinIOAdmin interface {
	// RotateSecret regenerates the secret key for user. Returns the new
	// secret. mcli admin user add is idempotent — it overwrites the secret
	// when the user already exists, matching Python _minio_rotate_secret.
	RotateSecret(ctx context.Context, user string) (string, error)
	// SetEnabled toggles a MinIO user between enabled/disabled. Used by
	// /manage/slots/{suspend,reactivate}.
	SetEnabled(ctx context.Context, user string, enabled bool) error
}

// MCAdmin is the real MinIOAdmin: a tiny exec wrapper around the mcli
// binary. AliasName defaults to "sdroot" (the alias the host's
// /root/.mcli/config.json carries). Binary defaults to "mcli" — overridable
// via MCLI_BIN env in deploy.
type MCAdmin struct {
	Binary    string // default "mcli"
	AliasName string // default "sdroot"
}

// genSecret produces a 32-byte url-safe secret. token_urlsafe(32) in Python
// returns ~43 chars; encoding 32 random bytes as raw url base64 → 43 chars.
func genSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (m *MCAdmin) bin() string {
	if m.Binary != "" {
		return m.Binary
	}
	return "mcli"
}

func (m *MCAdmin) alias() string {
	if m.AliasName != "" {
		return m.AliasName
	}
	return "sdroot"
}

func (m *MCAdmin) RotateSecret(ctx context.Context, user string) (string, error) {
	secret, err := genSecret()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, m.bin(), "admin", "user", "add", m.alias(), user, secret)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mcli admin user add %s: %v: %s", user, err, strings.TrimSpace(string(out)))
	}
	return secret, nil
}

func (m *MCAdmin) SetEnabled(ctx context.Context, user string, enabled bool) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	cmd := exec.CommandContext(ctx, m.bin(), "admin", "user", action, m.alias(), user)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mcli admin user %s %s: %v: %s", action, user, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// mockMinioAdmin (for --mock-upstreams): deterministic secret, no-op enable.
type mockMinioAdmin struct{}

func (mockMinioAdmin) RotateSecret(_ context.Context, user string) (string, error) {
	return "mock-secret-for-" + user, nil
}
func (mockMinioAdmin) SetEnabled(context.Context, string, bool) error { return nil }
