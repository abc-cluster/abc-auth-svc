package authsvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// adminClientStub spins an httptest server impersonating the Nomad ACL +
// Variables API and returns an AdminClient pointed at it. The handler asserts
// the X-Nomad-Token header carries the operator token on every call.
func adminClientStub(t *testing.T, h http.HandlerFunc) *AdminClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	nc := &NomadClient{Addr: srv.URL, HTTP: srv.Client()}
	return &AdminClient{NomadClient: nc, AdminToken: "op-nomad-token"}
}

func requireAdminToken(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("X-Nomad-Token") != "op-nomad-token" {
		t.Errorf("missing/wrong X-Nomad-Token: %q", r.Header.Get("X-Nomad-Token"))
	}
}

func TestAdminClient_VarPutThenGet(t *testing.T) {
	store := map[string]string{}
	ac := adminClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		requireAdminToken(t, r)
		switch r.Method {
		case http.MethodPut:
			var body nomadVarBody
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &body); err != nil {
				t.Errorf("bad PUT body: %v", err)
			}
			store[body.Path] = body.Items["value"]
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			path := strings.TrimPrefix(r.URL.Path, "/v1/var/")
			v, ok := store[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Items": map[string]string{"value": v}})
		}
	})

	ctx := context.Background()
	if err := ac.VarPut(ctx, "su-g", "abc/users/x/k", "v1"); err != nil {
		t.Fatalf("VarPut: %v", err)
	}
	got, err := ac.VarGet(ctx, "su-g", "abc/users/x/k")
	if err != nil {
		t.Fatalf("VarGet: %v", err)
	}
	if got != "v1" {
		t.Errorf("VarGet = %q, want v1", got)
	}
}

func TestAdminClient_VarGetNotFound(t *testing.T) {
	ac := adminClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := ac.VarGet(context.Background(), "su-g", "missing")
	if !errors.Is(err, ErrVarNotFound) {
		t.Fatalf("want ErrVarNotFound, got %v", err)
	}
}

func TestAdminClient_CreateToken_WireShape(t *testing.T) {
	ac := adminClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		requireAdminToken(t, r)
		if r.URL.Path != "/v1/acl/token" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		// Must mint a client token named pool-<slot> with the role attached.
		if body["Name"] != "pool-calm_dassie" || body["Type"] != "client" {
			t.Errorf("create-token body wrong: %v", body)
		}
		roles, _ := body["Roles"].([]any)
		if len(roles) != 1 {
			t.Errorf("expected 1 role, got %v", body["Roles"])
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"AccessorID": "acc-1", "SecretID": "sec-1"})
	})
	acc, sec, err := ac.CreateToken(context.Background(), "calm_dassie", "role-id-1")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if acc != "acc-1" || sec != "sec-1" {
		t.Errorf("CreateToken = %q,%q", acc, sec)
	}
}

func TestAdminClient_CreateToken_NoRole(t *testing.T) {
	ac := adminClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		if roles, _ := body["Roles"].([]any); len(roles) != 0 {
			t.Errorf("expected no roles, got %v", body["Roles"])
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"AccessorID": "a", "SecretID": "s"})
	})
	if _, _, err := ac.CreateToken(context.Background(), "x", ""); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
}

func TestAdminClient_GetRoleID(t *testing.T) {
	ac := adminClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/acl/roles" {
			t.Errorf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"ID": "id-other", "Name": "r-other"},
			{"ID": "id-pool", "Name": "r-su-mbhg-hostgen-pool"},
		})
	})
	id, err := ac.GetRoleID(context.Background(), "r-su-mbhg-hostgen-pool")
	if err != nil {
		t.Fatalf("GetRoleID: %v", err)
	}
	if id != "id-pool" {
		t.Errorf("GetRoleID = %q, want id-pool", id)
	}
}

func TestAdminClient_GetRoleID_Missing(t *testing.T) {
	ac := adminClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{{"ID": "x", "Name": "r-other"}})
	})
	id, err := ac.GetRoleID(context.Background(), "r-absent")
	if err != nil || id != "" {
		t.Errorf("missing role should yield empty id, no err; got id=%q err=%v", id, err)
	}
}

func TestAdminClient_DeleteToken(t *testing.T) {
	called := false
	ac := adminClientStub(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete || !strings.HasSuffix(r.URL.Path, "/v1/acl/token/acc-9") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})
	if err := ac.DeleteToken(context.Background(), "acc-9"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	if !called {
		t.Error("DeleteToken did not call the API")
	}
	// empty accessor → no-op, no call.
	if err := ac.DeleteToken(context.Background(), ""); err != nil {
		t.Fatalf("DeleteToken(empty): %v", err)
	}
}
