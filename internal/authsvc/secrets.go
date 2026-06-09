package authsvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// secretsAuthSlot resolves a Bearer to its slot via the opaque-token hash on
// PocketBase. Same authentication path as /auth/exchange — the bare opaque
// is hashed (sha256Hex) and looked up against opaque_token_hash. Returns nil
// + writes the appropriate error status when the bearer is missing or
// inactive.
func (s *Server) secretsAuthSlot(w http.ResponseWriter, r *http.Request) *Slot {
	ctx := r.Context()
	log := FromContext(ctx)

	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		errJSON(w, http.StatusUnauthorized, "missing_bearer_token")
		return nil
	}
	opaque := strings.TrimSpace(auth[7:])
	if opaque == "" {
		errJSON(w, http.StatusUnauthorized, "empty_bearer_token")
		return nil
	}
	if s.up.Store == nil {
		errJSON(w, http.StatusInternalServerError, "store_not_configured")
		return nil
	}
	slot, err := s.up.Store.FindSlot(ctx, "opaque_token_hash='"+sha256Hex(opaque)+"' && state='claimed'")
	if err != nil {
		log.LogAttrs(ctx, L1, "secrets.auth.lookup_failed", slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return nil
	}
	if slot == nil {
		errJSON(w, http.StatusUnauthorized, "invalid_or_inactive_token")
		return nil
	}
	return slot
}

// secretsBody parses the JSON body of a /auth/secrets request. Returns nil
// on an unparseable body (the caller writes 400 with "bad_json"), or an
// empty map when no body was sent.
func secretsBody(r *http.Request) (map[string]any, bool) {
	rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if len(rawBody) == 0 {
		return map[string]any{}, true
	}
	var body map[string]any
	if err := json.Unmarshal(rawBody, &body); err != nil {
		return nil, false
	}
	if body == nil {
		body = map[string]any{}
	}
	return body, true
}

// secretsNamespaceAndPath mirrors the Python _secrets_ns_and_path. Variables
// live at abc/users/<slot>/<key> under the slot's group namespace
// (su-<group>) — or "default" when the slot has no group attached.
// The optional `group` override is accepted on PUT so a slot member of
// several groups can choose which group's namespace to write into.
func (s *Server) secretsNamespaceAndPath(ctx context.Context, slot *Slot, key, groupOverride string) (namespace, path string) {
	groupName := strings.TrimSpace(groupOverride)
	if groupName == "" && s.up.Store != nil {
		groupName = s.up.Store.GroupName(ctx, slot)
	}
	if groupName == "" {
		namespace = "default"
	} else {
		namespace = "su-" + groupName
	}
	path = "abc/users/" + slot.SlotName + "/" + key
	return namespace, path
}

// handleSecretsPut implements POST /auth/secrets/put.
// Body: {"key": "...", "value": ..., "group": "..." (optional)}.
// Stores under abc/users/<slot>/<key> in Nomad Variables.
func (s *Server) handleSecretsPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	slot := s.secretsAuthSlot(w, r)
	if slot == nil {
		return
	}
	body, ok := secretsBody(r)
	if !ok {
		errJSON(w, http.StatusBadRequest, "bad_json")
		return
	}
	key, _ := body["key"].(string)
	key = strings.TrimSpace(key)
	groupOverride, _ := body["group"].(string)
	val, hasVal := body["value"]
	if key == "" || !hasVal {
		errJSON(w, http.StatusBadRequest, "key_and_value_required")
		return
	}
	value := stringify(val)

	if s.up.NomadAdmin == nil {
		errJSON(w, http.StatusInternalServerError, "nomad_admin_not_configured")
		return
	}
	ns, path := s.secretsNamespaceAndPath(ctx, slot, key, groupOverride)
	if err := s.up.NomadAdmin.VarPut(ctx, ns, path, value); err != nil {
		log.LogAttrs(ctx, L1, "secrets.put.store_failed",
			slog.String("slot", slot.SlotName), slog.String("key", key),
			slog.String("ns", ns), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "store_failed")
		return
	}
	log.LogAttrs(ctx, L1, "secrets.put.ok",
		slog.String("slot", slot.SlotName), slog.String("key", key), slog.String("ns", ns))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSecretsGet implements POST /auth/secrets/get.
// Body: {"key": "..."}.
// Returns {"value": ...} (200) or {"error": "not_found"} (404).
func (s *Server) handleSecretsGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	slot := s.secretsAuthSlot(w, r)
	if slot == nil {
		return
	}
	body, ok := secretsBody(r)
	if !ok {
		errJSON(w, http.StatusBadRequest, "bad_json")
		return
	}
	key, _ := body["key"].(string)
	key = strings.TrimSpace(key)
	if key == "" {
		errJSON(w, http.StatusBadRequest, "key_required")
		return
	}
	if s.up.NomadAdmin == nil {
		errJSON(w, http.StatusInternalServerError, "nomad_admin_not_configured")
		return
	}
	ns, path := s.secretsNamespaceAndPath(ctx, slot, key, "")
	val, err := s.up.NomadAdmin.VarGet(ctx, ns, path)
	if err != nil {
		if errors.Is(err, ErrVarNotFound) {
			errJSON(w, http.StatusNotFound, "not_found")
			return
		}
		log.LogAttrs(ctx, L1, "secrets.get.read_failed",
			slog.String("slot", slot.SlotName), slog.String("key", key),
			slog.String("ns", ns), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "read_failed")
		return
	}
	log.LogAttrs(ctx, L1, "secrets.get.ok",
		slog.String("slot", slot.SlotName), slog.String("key", key), slog.String("ns", ns))
	writeJSON(w, http.StatusOK, map[string]string{"value": val})
}

// stringify coerces a JSON-decoded `value` to its string form, matching the
// Python `str(value)`. Non-string scalars are JSON-encoded so the caller
// gets a deterministic representation (numbers, bools, null, arrays, objects).
func stringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}
