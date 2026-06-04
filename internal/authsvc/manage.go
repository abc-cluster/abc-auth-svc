package authsvc

import (
	"crypto/hmac"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// credSourceResponse is the body returned by the cred-source flip.
type credSourceResponse struct {
	OK                 bool   `json:"ok"`
	CredSource         string `json:"cred_source"`
	Changed            bool   `json:"changed"`
	PreviousCredSource string `json:"previous_cred_source,omitempty"`
	OpaqueToken        string `json:"opaque_token,omitempty"`
	Note               string `json:"note,omitempty"`
}

// requireOperator gates /manage/* on the X-Operator-Token header (constant-time
// compare). When no operator token is configured, all requests are rejected.
func (s *Server) requireOperator(w http.ResponseWriter, r *http.Request) bool {
	token := r.Header.Get("X-Operator-Token")
	if s.cfg.OperatorToken == "" || !hmac.Equal([]byte(token), []byte(s.cfg.OperatorToken)) {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

// handleCredSource implements POST /manage/slots/{slot}/cred-source — flip a slot
// between the `local` and `seedling/v1` credential-source pathways. Parity port
// of the Python _manage_cred_source.
//
// local → seedling/v1 mints a fresh opaque (returned ONCE in the response, the
// only moment the bare value leaves the server) and re-renders the blob in
// opaque shape. seedling/v1 → local clears the opaque hash and re-renders in
// real-creds shape. No MinIO/Nomad credential rotation happens here.
func (s *Server) handleCredSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	if !s.requireOperator(w, r) {
		return
	}
	slotName := r.PathValue("slot")
	if slotName == "" {
		errJSON(w, http.StatusBadRequest, "missing_slot")
		return
	}

	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var req struct {
		CredSource string `json:"cred_source"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			errJSON(w, http.StatusBadRequest, "bad_json_body")
			return
		}
	}
	want := strings.ToLower(strings.TrimSpace(req.CredSource))
	if want != "local" && want != "seedling/v1" {
		errJSON(w, http.StatusBadRequest, "invalid_cred_source")
		return
	}

	mgr, ok := s.up.Store.(SlotManager)
	if !ok {
		errJSON(w, http.StatusInternalServerError, "store_not_writable")
		return
	}

	slot, err := mgr.FindSlot(ctx, "slot_name='"+slotName+"'")
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if slot == nil {
		errJSON(w, http.StatusNotFound, "not_found")
		return
	}
	if slot.State != "claimed" {
		errJSON(w, http.StatusBadRequest, "slot_not_claimed")
		return
	}

	current := strings.ToLower(strings.TrimSpace(slot.CredSource))
	if current == "" {
		current = "local"
	}
	muser := slot.MinioAccessKey
	if muser == "" {
		muser = "slot-" + slotName
	}

	if want == current {
		writeJSON(w, http.StatusOK, credSourceResponse{OK: true, CredSource: current, Changed: false})
		return
	}

	resp := credSourceResponse{OK: true, CredSource: want, Changed: true, PreviousCredSource: current}

	if want == "seedling/v1" {
		opaque, err := mintOpaque()
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "mint_failed")
			return
		}
		if err := mgr.PatchSlot(ctx, slot.ID, map[string]any{
			"cred_source":       "seedling/v1",
			"opaque_token_hash": sha256Hex(opaque),
		}); err != nil {
			errJSON(w, http.StatusInternalServerError, "patch_failed")
			return
		}
		if _, err := persistSlotConfig(ctx, mgr, s.up.Cluster, slot.ID, opaque); err != nil {
			errJSON(w, http.StatusInternalServerError, "render_failed")
			return
		}
		resp.OpaqueToken = opaque
		resp.Note = "This is the ONLY response containing the bare opaque. Hand it to the user and discard from logs."
	} else { // local
		if err := mgr.PatchSlot(ctx, slot.ID, map[string]any{
			"cred_source":       "",
			"opaque_token_hash": "",
		}); err != nil {
			errJSON(w, http.StatusInternalServerError, "patch_failed")
			return
		}
		if _, err := persistSlotConfig(ctx, mgr, s.up.Cluster, slot.ID, ""); err != nil {
			errJSON(w, http.StatusInternalServerError, "render_failed")
			return
		}
	}

	mgr.InvalidateSlotState(muser)
	// NOTE (deferred): the Python also bounces the JupyterHub server here
	// (_jh_stop_server) so the spawn hook re-reads the flipped blob. Deferred —
	// the next spawn picks up the new blob; add a JH stop-server call later.

	// Audit: slot + transition only — NEVER the opaque token.
	log.LogAttrs(ctx, L1, "manage.cred_source.flip",
		slog.String("slot", slotName), slog.String("from", current), slog.String("to", want))
	writeJSON(w, http.StatusOK, resp)
}
