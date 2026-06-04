package authsvc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const pbAuthPath = "/api/collections/_superusers/auth-with-password"

func TestPBClient_FindSlot_AndTokenReuse(t *testing.T) {
	authCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == pbAuthPath:
			authCalls++
			writeJSON(w, 200, map[string]string{"token": "pbjwt"})
		case strings.HasPrefix(r.URL.Path, "/api/collections/slots/records"):
			if r.Header.Get("Authorization") != "Bearer pbjwt" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeJSON(w, 200, map[string]any{"items": []map[string]any{{
				"id": "1", "slot_name": "slot-x", "state": "claimed",
				"cred_source": "seedling/v1", "minio_access_key": "x",
			}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewPBClient(srv.URL, "e", "p", srv.Client())
	slot, err := c.FindSlot(context.Background(), "minio_access_key='x'")
	if err != nil {
		t.Fatalf("FindSlot: %v", err)
	}
	if slot == nil || slot.SlotName != "slot-x" || slot.State != "claimed" {
		t.Fatalf("slot = %+v", slot)
	}
	// Second call must reuse the cached token (no re-auth).
	if _, err := c.FindSlot(context.Background(), "minio_access_key='x'"); err != nil {
		t.Fatalf("FindSlot 2: %v", err)
	}
	if authCalls != 1 {
		t.Errorf("auth calls = %d, want 1 (token should be cached)", authCalls)
	}
}

func TestPBClient_ReauthOn401(t *testing.T) {
	authCalls, dataCalls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == pbAuthPath:
			authCalls++
			writeJSON(w, 200, map[string]string{"token": fmt.Sprintf("jwt-%d", authCalls)})
		case strings.HasPrefix(r.URL.Path, "/api/collections/slots/records"):
			dataCalls++
			if dataCalls == 1 {
				w.WriteHeader(http.StatusUnauthorized) // simulate expiry on first data call
				return
			}
			writeJSON(w, 200, map[string]any{"items": []map[string]any{{"id": "1", "slot_name": "slot-y", "state": "claimed"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewPBClient(srv.URL, "e", "p", srv.Client())
	slot, err := c.FindSlot(context.Background(), "x")
	if err != nil {
		t.Fatalf("FindSlot: %v", err)
	}
	if slot == nil || slot.SlotName != "slot-y" {
		t.Fatalf("slot = %+v", slot)
	}
	if authCalls != 2 || dataCalls != 2 {
		t.Errorf("authCalls=%d dataCalls=%d, want 2/2 (401 → re-auth → retry)", authCalls, dataCalls)
	}
}

func TestPBClient_CachedSlotState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == pbAuthPath:
			writeJSON(w, 200, map[string]string{"token": "pbjwt"})
		case strings.HasPrefix(r.URL.Path, "/api/collections/slots/records"):
			if strings.Contains(r.URL.RawQuery, "bob") {
				writeJSON(w, 200, map[string]any{"items": []map[string]any{{"state": "suspended"}}})
			} else {
				writeJSON(w, 200, map[string]any{"items": []map[string]any{}})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewPBClient(srv.URL, "e", "p", srv.Client())
	if got := c.CachedSlotState(context.Background(), "bob"); got != "suspended" {
		t.Errorf("state(bob) = %q, want suspended", got)
	}
	if got := c.CachedSlotState(context.Background(), "nobody"); got != "none" {
		t.Errorf("state(nobody) = %q, want none", got)
	}
}

func TestPBClient_CachedSlotState_FailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pbAuthPath {
			writeJSON(w, 200, map[string]string{"token": "pbjwt"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // PB unhealthy
	}))
	defer srv.Close()

	c := NewPBClient(srv.URL, "e", "p", srv.Client())
	if got := c.CachedSlotState(context.Background(), "bob"); got != "error" {
		t.Errorf("state = %q, want error (fail open)", got)
	}
}
