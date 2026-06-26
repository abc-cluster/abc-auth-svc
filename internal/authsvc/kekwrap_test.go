package authsvc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testMK(t *testing.T) []byte {
	t.Helper()
	mk := make([]byte, mkLen)
	if _, err := rand.Read(mk); err != nil {
		t.Fatalf("mk: %v", err)
	}
	return mk
}

// newKEK is a test helper for a 32-byte random secret (the production newKEK was
// removed when managed keys became age X25519; wrapKEK now wraps arbitrary bytes).
func newKEK() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func TestKEKWrapRoundTrip(t *testing.T) {
	mk := testMK(t)
	kek, err := newKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapKEK(mk, "group:abc-grp-x", 1, kek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	got, err := unwrapKEK(mk, "group:abc-grp-x", 1, wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, kek) {
		t.Fatal("round-trip KEK mismatch")
	}
}

func TestKEKWrapWrongMKFailsClosed(t *testing.T) {
	mk := testMK(t)
	other := testMK(t)
	kek, _ := newKEK()
	wrapped, _ := wrapKEK(mk, "group:g", 1, kek)
	if _, err := unwrapKEK(other, "group:g", 1, wrapped); err == nil {
		t.Fatal("unwrap with wrong MK must fail closed")
	}
}

func TestKEKWrapVersionTamperFailsClosed(t *testing.T) {
	mk := testMK(t)
	kek, _ := newKEK()
	wrapped, _ := wrapKEK(mk, "group:g", 2, kek)
	if _, err := unwrapKEK(mk, "group:g", 1, wrapped); err == nil {
		t.Fatal("version downgrade 2->1 must fail closed (AAD binds version)")
	}
}

func TestKEKWrapKekIDTamperFailsClosed(t *testing.T) {
	mk := testMK(t)
	kek, _ := newKEK()
	wrapped, _ := wrapKEK(mk, "group:A", 1, kek)
	if _, err := unwrapKEK(mk, "group:B", 1, wrapped); err == nil {
		t.Fatal("group swap A->B must fail closed (AAD binds kek_id)")
	}
}

func TestKEKWrapBodyTamperFailsClosed(t *testing.T) {
	mk := testMK(t)
	kek, _ := newKEK()
	wrapped, _ := wrapKEK(mk, "group:g", 1, kek)
	raw, _ := base64.StdEncoding.DecodeString(wrapped)
	raw[len(raw)-1] ^= 0xff // flip a ciphertext/tag byte
	if _, err := unwrapKEK(mk, "group:g", 1, base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered ciphertext must fail closed")
	}
}

func TestKEKWrapSaltUnique(t *testing.T) {
	mk := testMK(t)
	kek, _ := newKEK()
	a, _ := wrapKEK(mk, "group:g", 1, kek)
	b, _ := wrapKEK(mk, "group:g", 1, kek)
	if a == b {
		t.Fatal("two wraps of the same KEK must differ (random salt+nonce)")
	}
}

func TestKEKWrapRejectsBadInputs(t *testing.T) {
	if _, err := wrapKEK(make([]byte, 16), "group:g", 1, make([]byte, 32)); err == nil {
		t.Fatal("wrap must reject a non-32-byte MK")
	}
	if _, err := wrapKEK(make([]byte, mkLen), "group:g", 1, nil); err == nil {
		t.Fatal("wrap must reject an empty secret")
	}
	// Arbitrary non-32-byte secrets are now valid (the age AGE-SECRET-KEY string
	// is ~74 bytes). A 74-byte secret must round-trip.
	mk := make([]byte, mkLen)
	secret := []byte(strings.Repeat("k", 74))
	wrapped, err := wrapKEK(mk, "group:g", 1, secret)
	if err != nil {
		t.Fatalf("wrap 74-byte secret: %v", err)
	}
	got, err := unwrapKEK(mk, "group:g", 1, wrapped)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round-trip 74-byte secret: got=%q err=%v", got, err)
	}
}
