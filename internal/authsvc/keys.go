package authsvc

// keys.go — the seedling managed-key broker (ADR-0067 Amendment 2: the managed
// group key is a native age X25519 keypair, not a symmetric KEK). Two endpoints:
//
//   POST /keys/get   (member-gated)   — release the caller's group age IDENTITY
//                                        (AGE-SECRET-KEY-1…) + recipient (age1…) so
//                                        the client decrypts/encrypts with native age
//                                        (no plugin, no bespoke stanza). Coarse audit row.
//   POST /keys/mint  (operator-gated) — mint/rotate a group's age keypair: the public
//                                        recipient stored plaintext, the private key
//                                        wrapped under the root MK, into PB. Called at
//                                        group creation; group keys are never lazily minted.
//
// Membership is intrinsic: a slot belongs to exactly one group (slots.group,
// maxSelect=1), so releasing only the caller's own group identity IS the cross-group
// boundary. The kek_id ("group:<name>") is derived from the group record's name and
// binds the at-rest wrap (AAD), so mint and get agree byte-for-byte.

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"

	"filippo.io/age"
)

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

// KeyStore is the PB read/write path for the per-group age key material.
// Implemented by PBClient; a fake substitutes in tests.
type KeyStore interface {
	GroupKeyRecord(ctx context.Context, groupID string) (name, recipient, skWrapped string, version int, alg string, hasKey bool, err error)
	PutGroupKey(ctx context.Context, groupID, recipient, skWrapped string, version int, alg string) error
}

// keysPrereqs resolves the shared preconditions for both endpoints: a configured
// root MK and a key-capable store. Writes the error response and returns ok=false
// when either is missing.
func (s *Server) keysPrereqs(w http.ResponseWriter) (mk []byte, store KeyStore, ok bool) {
	mk, have := s.rootMK()
	if !have {
		errJSON(w, http.StatusServiceUnavailable, "managed_encryption_unconfigured")
		return nil, nil, false
	}
	store, isKey := s.up.Store.(KeyStore)
	if !isKey || store == nil {
		errJSON(w, http.StatusInternalServerError, "key_store_unavailable")
		return nil, nil, false
	}
	return mk, store, true
}

// handleKeysGet implements POST /keys/get.
// Body (optional): {"kek_id": "group:<g>"} — if present it must name the caller's
// own group, else 403. Returns {"kek_id","version","recipient","identity"}.
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

	name, recipient, skWrapped, version, _, hasKey, err := store.GroupKeyRecord(ctx, slot.Group)
	if err != nil {
		log.LogAttrs(ctx, L1, "keys.get.group_read_failed",
			slog.String("slot", slot.SlotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "key_read_failed")
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
	if !hasKey {
		// Group keys are never lazily minted — must pre-exist from group creation.
		errJSON(w, http.StatusNotFound, "key_not_provisioned")
		return
	}
	sk, err := unwrapKEK(mk, kekID, version, skWrapped)
	if err != nil {
		log.LogAttrs(ctx, L1, "keys.get.unwrap_failed",
			slog.String("slot", slot.SlotName), slog.String("kek_id", kekID), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "key_unwrap_failed")
		return
	}
	// Coarse "released" audit row (seedling tiering — release, not per-file). The
	// identity (secret) is NEVER logged.
	log.LogAttrs(ctx, L1, "keys.get.released",
		slog.String("slot", slot.SlotName), slog.String("kek_id", kekID), slog.Int("version", version))
	writeJSON(w, http.StatusOK, map[string]any{
		"kek_id":    kekID,
		"version":   version,
		"recipient": recipient,  // age1… public recipient
		"identity":  string(sk), // AGE-SECRET-KEY-1… group private key
	})
}

// handleKeysMint implements POST /keys/mint (operator-gated).
// Body: {"group_id": "<pb group record id>"}. Generates the next age keypair
// version (v1 if none), stores the public recipient plaintext + the private key
// wrapped under the MK. The kek_id is derived from the group record's name.
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

	name, _, _, prevVersion, _, hasKey, err := store.GroupKeyRecord(ctx, groupID)
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
	if hasKey {
		version = prevVersion + 1
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "key_gen_failed")
		return
	}
	recipient := id.Recipient().String() // age1…
	skWrapped, err := wrapKEK(mk, kekID, version, []byte(id.String()))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "key_wrap_failed")
		return
	}
	if err := store.PutGroupKey(ctx, groupID, recipient, skWrapped, version, KEKWrapAlg); err != nil {
		log.LogAttrs(ctx, L1, "keys.mint.write_failed",
			slog.String("kek_id", kekID), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "key_write_failed")
		return
	}
	log.LogAttrs(ctx, L1, "keys.mint.ok",
		slog.String("kek_id", kekID), slog.Int("version", version), slog.String("recipient", recipient))
	writeJSON(w, http.StatusOK, map[string]any{
		"kek_id":    kekID,
		"version":   version,
		"recipient": recipient,
		"minted":    true,
	})
}
