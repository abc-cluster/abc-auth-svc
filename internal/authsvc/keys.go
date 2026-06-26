package authsvc

// keys.go — the seedling KEK broker (ADR-0067 Amendment 2026-06-26; spec
// specs/active/abc-managed-encryption-keys.md). Two endpoints:
//
//   POST /keys/get   (member-gated)   — release the caller's group KEK K_G so
//                                        the client unwraps per-file DEKs locally
//                                        (seedling key-delivery tiering: release,
//                                        not per-file unwrap; coarse audit row).
//   POST /keys/mint  (operator-gated) — mint/rotate a group's KEK, wrapped under
//                                        the root MK, into PB. Called at group
//                                        creation; group KEKs are never lazily minted.
//
// Membership is intrinsic: a slot belongs to exactly one group (slots.group,
// maxSelect=1), so releasing only the caller's own group KEK IS the cross-group
// boundary. The canonical kek_id is always derived from the group record's name,
// never trusted from the client, so mint and get agree byte-for-byte (the AAD
// binds kek_id+version).

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
)

// KEKStore is the PB read/write path for wrapped per-group KEKs. Implemented by
// PBClient; a fake substitutes in tests.
type KEKStore interface {
	GroupKEKRecord(ctx context.Context, groupID string) (name, wrapped string, version int, alg string, hasKEK bool, err error)
	PutGroupKEK(ctx context.Context, groupID, wrapped string, version int, alg string) error
}

// rootMK decodes the configured base64 root master key. ok=false when managed
// encryption is unconfigured or the value is malformed → /keys/* answer 503.
func (s *Server) rootMK() ([]byte, bool) {
	raw := strings.TrimSpace(s.cfg.RootMKB64)
	if raw == "" {
		return nil, false
	}
	mk, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(mk) != mkLen {
		return nil, false
	}
	return mk, true
}

// keysPrereqs resolves the shared preconditions for both endpoints: a configured
// MK and a KEK-capable store. Writes the error response and returns ok=false
// when either is missing.
func (s *Server) keysPrereqs(w http.ResponseWriter) (mk []byte, store KEKStore, ok bool) {
	mk, have := s.rootMK()
	if !have {
		errJSON(w, http.StatusServiceUnavailable, "managed_encryption_unconfigured")
		return nil, nil, false
	}
	store, isKEK := s.up.Store.(KEKStore)
	if !isKEK || store == nil {
		errJSON(w, http.StatusInternalServerError, "kek_store_unavailable")
		return nil, nil, false
	}
	return mk, store, true
}

// handleKeysGet implements POST /keys/get.
// Body (optional): {"kek_id": "group:<g>"} — if present it must name the
// caller's own group, else 403. Returns {"kek_id","version","kek"(base64)}.
func (s *Server) handleKeysGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	mk, store, ok := s.keysPrereqs(w)
	if !ok {
		return
	}
	slot := s.secretsAuthSlot(w, r)
	if slot == nil {
		return
	}
	if slot.Group == "" {
		errJSON(w, http.StatusConflict, "slot_has_no_group")
		return
	}
	body, parsed := secretsBody(r)
	if !parsed {
		errJSON(w, http.StatusBadRequest, "bad_json")
		return
	}

	name, wrapped, version, _, hasKEK, err := store.GroupKEKRecord(ctx, slot.Group)
	if err != nil {
		log.LogAttrs(ctx, L1, "keys.get.group_read_failed",
			slog.String("slot", slot.SlotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "kek_read_failed")
		return
	}
	if name == "" {
		errJSON(w, http.StatusConflict, "slot_has_no_group")
		return
	}
	kekID := "group:" + name

	// Optional client-supplied kek_id must match the caller's own group.
	if want, _ := body["kek_id"].(string); strings.TrimSpace(want) != "" && strings.TrimSpace(want) != kekID {
		log.LogAttrs(ctx, L1, "keys.get.denied",
			slog.String("slot", slot.SlotName), slog.String("requested", strings.TrimSpace(want)),
			slog.String("own", kekID))
		errJSON(w, http.StatusForbidden, "not_a_member")
		return
	}
	if !hasKEK {
		// Group KEKs are never lazily minted — must pre-exist from group creation.
		errJSON(w, http.StatusNotFound, "kek_not_provisioned")
		return
	}
	kek, err := unwrapKEK(mk, kekID, version, wrapped)
	if err != nil {
		log.LogAttrs(ctx, L1, "keys.get.unwrap_failed",
			slog.String("slot", slot.SlotName), slog.String("kek_id", kekID), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "kek_unwrap_failed")
		return
	}
	// Coarse "released" audit row (seedling tiering — release, not per-file).
	log.LogAttrs(ctx, L1, "keys.get.released",
		slog.String("slot", slot.SlotName), slog.String("kek_id", kekID), slog.Int("version", version))
	writeJSON(w, http.StatusOK, map[string]any{
		"kek_id":  kekID,
		"version": version,
		"kek":     base64.StdEncoding.EncodeToString(kek),
	})
}

// handleKeysMint implements POST /keys/mint (operator-gated).
// Body: {"group_id": "<pb group record id>"}. Mints the next KEK version
// (v1 if none), wraps it under the MK, writes PB. The kek_id is derived from the
// group record's name so it always matches what /keys/get will use.
func (s *Server) handleKeysMint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	if !s.requireOperator(w, r) {
		return
	}
	mk, store, ok := s.keysPrereqs(w)
	if !ok {
		return
	}
	body, parsed := secretsBody(r)
	if !parsed {
		errJSON(w, http.StatusBadRequest, "bad_json")
		return
	}
	groupID, _ := body["group_id"].(string)
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		errJSON(w, http.StatusBadRequest, "group_id_required")
		return
	}

	name, _, prevVersion, _, hasKEK, err := store.GroupKEKRecord(ctx, groupID)
	if err != nil {
		errJSON(w, http.StatusNotFound, "group_not_found")
		return
	}
	if name == "" {
		errJSON(w, http.StatusConflict, "group_has_no_name")
		return
	}
	kekID := "group:" + name
	version := 1
	if hasKEK {
		version = prevVersion + 1
	}
	kek, err := newKEK()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "kek_gen_failed")
		return
	}
	wrapped, err := wrapKEK(mk, kekID, version, kek)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "kek_wrap_failed")
		return
	}
	if err := store.PutGroupKEK(ctx, groupID, wrapped, version, KEKWrapAlg); err != nil {
		log.LogAttrs(ctx, L1, "keys.mint.write_failed",
			slog.String("kek_id", kekID), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "kek_write_failed")
		return
	}
	log.LogAttrs(ctx, L1, "keys.mint.ok", slog.String("kek_id", kekID), slog.Int("version", version))
	writeJSON(w, http.StatusOK, map[string]any{
		"kek_id":  kekID,
		"version": version,
		"minted":  true,
	})
}
