package authsvc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
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

func TestKEKWrapRejectsBadSizes(t *testing.T) {
	if _, err := wrapKEK(make([]byte, 16), "group:g", 1, make([]byte, kekLen)); err == nil {
		t.Fatal("wrap must reject a non-32-byte MK")
	}
	if _, err := wrapKEK(make([]byte, mkLen), "group:g", 1, make([]byte, 16)); err == nil {
		t.Fatal("wrap must reject a non-32-byte KEK")
	}
}
