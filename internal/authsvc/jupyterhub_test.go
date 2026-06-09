package authsvc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func hubClientStub(t *testing.T, h http.HandlerFunc) *HubClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &HubClient{APIURL: srv.URL, AdminToken: "jh-admin", HTTP: srv.Client()}
}

// MintUserToken must POST /users/<bare>/tokens with `Authorization: token <admin>`
// — the exact call the 2026-06-09 403 turned on (bare user, admin token).
func TestHubClient_MintUserToken_WireShape(t *testing.T) {
	c := hubClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token jh-admin" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/users/solar_civet/tokens" {
			t.Errorf("path = %q (must be bare user, no slot- prefix)", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["note"] != "my laptop" {
			t.Errorf("note = %v", body["note"])
		}
		_ = json.NewEncoder(w).Encode(JHToken{Token: "T", ID: "id1", Scopes: []string{"x"}})
	})
	tok, err := c.MintUserToken(context.Background(), "solar_civet", "my laptop", 3600)
	if err != nil {
		t.Fatalf("MintUserToken: %v", err)
	}
	if tok.Token != "T" || tok.ID != "id1" {
		t.Errorf("token = %+v", tok)
	}
}

func TestHubClient_MintUserToken_403(t *testing.T) {
	c := hubClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"no permission"}`))
	})
	_, err := c.MintUserToken(context.Background(), "x", "n", 0)
	var he *HubError
	if !asHubError(err, &he) || he.Status != http.StatusForbidden {
		t.Fatalf("want HubError 403, got %v", err)
	}
}

func TestHubClient_UserExists(t *testing.T) {
	c := hubClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/users/present") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	ex, err := c.UserExists(context.Background(), "present")
	if err != nil || ex == nil || !*ex {
		t.Errorf("present: ex=%v err=%v", ex, err)
	}
	ex, err = c.UserExists(context.Background(), "absent")
	if err != nil || ex == nil || *ex {
		t.Errorf("absent: ex=%v err=%v", ex, err)
	}
}

func TestHubClient_StopServer(t *testing.T) {
	c := hubClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || !strings.HasSuffix(r.URL.Path, "/users/x/server") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.StopServer(context.Background(), "x"); err != nil {
		t.Fatalf("StopServer: %v", err)
	}
}

func TestHubClient_StopServer_AlreadyStopped(t *testing.T) {
	c := hubClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // already stopped → treated as success
	})
	if err := c.StopServer(context.Background(), "x"); err != nil {
		t.Fatalf("StopServer(404) should be nil, got %v", err)
	}
}

// asHubError is errors.As specialised for *HubError (keeps the test import set
// minimal).
func asHubError(err error, target **HubError) bool {
	for err != nil {
		if he, ok := err.(*HubError); ok {
			*target = he
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
