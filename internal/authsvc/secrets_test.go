package authsvc

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// secretsServer wires a Store that resolves an opaque bearer to a claimed slot
// plus a recording NomadAdmin for the Variables KV.
func secretsServer(t *testing.T, slot *Slot, na NomadAdmin) (*Server, *recNomadAdmin) {
	t.Helper()
	rec, _ := na.(*recNomadAdmin)
	store := fakeStore{
		find: func(_ context.Context, filter string) (*Slot, error) {
			// only resolve when the filter is the opaque-hash + claimed shape
			if strings.Contains(filter, "opaque_token_hash=") && strings.Contains(filter, "state='claimed'") {
				return slot, nil
			}
			return nil, nil
		},
		group: func(_ context.Context, s *Slot) string {
			if s != nil {
				return s.GroupName
			}
			return ""
		},
	}
	s, _ := newP4Server(t, "", Upstreams{Nomad: okNomad("pool-x"), Hub: okHub(), Store: store, NomadAdmin: na})
	return s, rec
}

func bearer(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
}

func TestSecretsPut_MissingBearer(t *testing.T) {
	s, _ := secretsServer(t, &Slot{}, newRecNomadAdmin())
	rr := postJSON(t, s, "/auth/secrets/put", `{"key":"k","value":"v"}`, map[string]string{"Content-Type": "application/json"})
	if rr.Code != http.StatusUnauthorized || decodeErr(t, rr) != "missing_bearer_token" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestSecretsPut_InvalidBearer(t *testing.T) {
	// store returns nil for any filter → invalid_or_inactive_token
	store := fakeStore{find: func(context.Context, string) (*Slot, error) { return nil, nil }}
	s, _ := newP4Server(t, "", Upstreams{Nomad: okNomad("pool-x"), Hub: okHub(), Store: store, NomadAdmin: newRecNomadAdmin()})
	rr := postJSON(t, s, "/auth/secrets/put", `{"key":"k","value":"v"}`, bearer("bad-opaque"))
	if rr.Code != http.StatusUnauthorized || decodeErr(t, rr) != "invalid_or_inactive_token" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestSecretsPut_KeyAndValueRequired(t *testing.T) {
	slot := &Slot{SlotName: "calm_dassie", GroupName: "mbhg-hostgen", State: "claimed"}
	s, _ := secretsServer(t, slot, newRecNomadAdmin())
	rr := postJSON(t, s, "/auth/secrets/put", `{"key":""}`, bearer("opq"))
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "key_and_value_required" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestSecretsPut_OK_AndNamespacePath(t *testing.T) {
	slot := &Slot{SlotName: "calm_dassie", GroupName: "mbhg-hostgen", State: "claimed"}
	na := newRecNomadAdmin()
	s, _ := secretsServer(t, slot, na)
	rr := postJSON(t, s, "/auth/secrets/put", `{"key":"hf_token","value":"sekret"}`, bearer("opq"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	// ns = su-<group>, path = abc/users/<slot>/<key>
	want := na.key("su-mbhg-hostgen", "abc/users/calm_dassie/hf_token")
	if got := na.vars[want]; got != "sekret" {
		t.Errorf("var not stored at %q: got %q (all=%v)", want, got, na.vars)
	}
}

func TestSecretsPut_NonStringValueStringified(t *testing.T) {
	slot := &Slot{SlotName: "x", GroupName: "g", State: "claimed"}
	na := newRecNomadAdmin()
	s, _ := secretsServer(t, slot, na)
	rr := postJSON(t, s, "/auth/secrets/put", `{"key":"port","value":8080}`, bearer("opq"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if got := na.vars[na.key("su-g", "abc/users/x/port")]; got != "8080" {
		t.Errorf("numeric value not stringified: %q", got)
	}
}

func TestSecretsPut_NoGroupUsesDefaultNamespace(t *testing.T) {
	slot := &Slot{SlotName: "x", GroupName: "", State: "claimed"}
	na := newRecNomadAdmin()
	s, _ := secretsServer(t, slot, na)
	rr := postJSON(t, s, "/auth/secrets/put", `{"key":"k","value":"v"}`, bearer("opq"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if _, ok := na.vars[na.key("default", "abc/users/x/k")]; !ok {
		t.Errorf("expected default-namespace var, got %v", na.vars)
	}
}

func TestSecretsGet_OK(t *testing.T) {
	slot := &Slot{SlotName: "x", GroupName: "g", State: "claimed"}
	na := newRecNomadAdmin()
	na.vars[na.key("su-g", "abc/users/x/k")] = "the-value"
	s, _ := secretsServer(t, slot, na)
	rr := postJSON(t, s, "/auth/secrets/get", `{"key":"k"}`, bearer("opq"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"value":"the-value"`) {
		t.Errorf("body=%s", rr.Body.String())
	}
}

func TestSecretsGet_NotFound(t *testing.T) {
	slot := &Slot{SlotName: "x", GroupName: "g", State: "claimed"}
	s, _ := secretsServer(t, slot, newRecNomadAdmin())
	rr := postJSON(t, s, "/auth/secrets/get", `{"key":"absent"}`, bearer("opq"))
	if rr.Code != http.StatusNotFound || decodeErr(t, rr) != "not_found" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}

func TestSecretsGet_KeyRequired(t *testing.T) {
	slot := &Slot{SlotName: "x", GroupName: "g", State: "claimed"}
	s, _ := secretsServer(t, slot, newRecNomadAdmin())
	rr := postJSON(t, s, "/auth/secrets/get", `{}`, bearer("opq"))
	if rr.Code != http.StatusBadRequest || decodeErr(t, rr) != "key_required" {
		t.Fatalf("status=%d err=%q", rr.Code, decodeErr(t, rr))
	}
}
