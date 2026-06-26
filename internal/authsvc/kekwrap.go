package authsvc

// kekwrap.go — the broker-internal envelope that wraps a per-group/per-slot KEK
// under the single root master key (MK). This is the seedling KEK-at-rest
// construction for the PocketBase store (ADR-0067 Amendment 2026-06-26): the
// wrapped KEK lives in PB (groups.kek_wrapped / slots.kek_wrapped) and the MK
// lives outside PB (env-injected from Nomad Variable abc/keys/root/mk), so a
// leaked PB file alone is not key disclosure.
//
// Construction (stdlib only — the service has no third-party deps):
//   wrapKey = HKDF-SHA256(MK, salt=random16, info="abc-kek-wrap-v1|<kek_id>|<version>")
//   blob    = salt || nonce || AES-256-GCM_seal(wrapKey, nonce, kek, aad)
//   aad     = "abc-kek-wrap-v1|<kek_id>|<version>"
// A fresh random salt per wrap derives a unique GCM key, so GCM nonce reuse is
// impossible even under a long-lived MK. kek_id+version are bound in both the
// HKDF info and the AEAD AAD, so a version downgrade or group swap fails closed.
//
// This wrap is entirely internal to the broker (mint wraps, /keys/get unwraps);
// it is independent of the CLI's abc-recipient (which wraps the per-file DEK
// under the KEK this layer protects).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
)

const (
	kekWrapLabel = "abc-kek-wrap-v1"        // HKDF info + AAD domain-separation prefix
	KEKWrapAlg   = "aes256-gcm-hkdf-sha256" // stored in <key>_alg; lets us evolve the construction
	mkLen        = 32                       // root MK is 32 bytes
	wrapSaltLen  = 16
)

// kekWrapAAD is the domain-separated additional-data / HKDF info for a wrap.
func kekWrapAAD(kekID string, version int) string {
	return kekWrapLabel + "|" + kekID + "|" + strconv.Itoa(version)
}

// wrapKEK encrypts a secret (a per-group age X25519 private key, since ADR-0067
// Amendment 2) under the root MK, binding kek_id+version. Output is
// base64(salt || nonce || ciphertext+tag) for storage in PB. Any non-empty
// plaintext length is accepted (the secret is the age `AGE-SECRET-KEY-1…` string).
func wrapKEK(mk []byte, kekID string, version int, kek []byte) (string, error) {
	if len(mk) != mkLen {
		return "", fmt.Errorf("root MK must be %d bytes, got %d", mkLen, len(mk))
	}
	if len(kek) == 0 {
		return "", fmt.Errorf("secret to wrap must not be empty")
	}
	salt := make([]byte, wrapSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	aad := kekWrapAAD(kekID, version)
	wrapKey, err := hkdf.Key(sha256.New, mk, salt, aad, 32)
	if err != nil {
		return "", fmt.Errorf("hkdf: %w", err)
	}
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, kek, []byte(aad))
	blob := make([]byte, 0, len(salt)+len(nonce)+len(ct))
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// unwrapKEK reverses wrapKEK. It fails closed (non-nil error, nil key) on a
// wrong MK, a tampered blob, or a kek_id/version that doesn't match what was
// sealed — the GCM tag covers the AAD.
func unwrapKEK(mk []byte, kekID string, version int, wrapped string) ([]byte, error) {
	if len(mk) != mkLen {
		return nil, fmt.Errorf("root MK must be %d bytes, got %d", mkLen, len(mk))
	}
	blob, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped KEK: %w", err)
	}
	if len(blob) < wrapSaltLen {
		return nil, fmt.Errorf("wrapped KEK too short")
	}
	aad := kekWrapAAD(kekID, version)
	salt := blob[:wrapSaltLen]
	rest := blob[wrapSaltLen:]
	wrapKey, err := hkdf.Key(sha256.New, mk, salt, aad, 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(rest) < ns+1 {
		return nil, fmt.Errorf("wrapped KEK too short")
	}
	nonce := rest[:ns]
	ct := rest[ns:]
	kek, err := gcm.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("unwrap failed (wrong MK or tampered secret): %w", err)
	}
	return kek, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return gcm, nil
}
