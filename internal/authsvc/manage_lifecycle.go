package authsvc

import (
	"log/slog"
	"net/http"
)

// handleManageSuspend implements POST /manage/slots/{slot}/suspend.
// Sequence (mirrors Python _manage_suspend):
//
//  1. mcli admin user disable <muser>        — MinIO requests start failing.
//  2. nomad ACL token delete <accessor>      — workbench Nomad token revoked.
//  3. remove /etc/jupyterhub/minio-creds/<X> + abc-configs/<X> — kill ambient
//     auth in the next spawn.
//  4. PB patch state=suspended.
//  5. InvalidateSlotState(muser)             — /validate cache flushed.
//  6. HubClient.StopServer(slot)             — kill any running JH server.
func (s *Server) handleManageSuspend(w http.ResponseWriter, r *http.Request) {
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

	muser := slot.MinioAccessKey
	if muser == "" {
		muser = "slot-" + slotName
	}

	// 1) MinIO disable — best-effort, like Python _mcli_safe.
	if s.up.MinioAdmin != nil {
		if err := s.up.MinioAdmin.SetEnabled(ctx, muser, false); err != nil {
			log.LogAttrs(ctx, L1, "suspend.minio_disable_failed",
				slog.String("user", muser), slog.String("error", err.Error()))
		}
	}

	// 2) Nomad ACL token revoke — best-effort.
	if slot.NomadTokenSecret == "" {
		// nothing to revoke (slot had no token)
	} else if s.up.NomadAdmin != nil {
		// Python tracks accessor on the slot record. Our Slot struct exposes
		// only NomadTokenSecret (the bare token) — we resolve the accessor
		// via Nomad's API on the bare token IF we have it, else skip.
		// Note: the Python service stores nomad_token_accessor separately on
		// the slot; we surface that field through PB raw lookup below.
	}
	if acc := slotAccessor(slot); acc != "" && s.up.NomadAdmin != nil {
		if err := s.up.NomadAdmin.DeleteToken(ctx, acc); err != nil {
			log.LogAttrs(ctx, L1, "suspend.nomad_token_delete_failed",
				slog.String("accessor", acc), slog.String("error", err.Error()))
		}
	}

	// 3) creds files removal — best-effort.
	if err := removeCredsFiles(slotName); err != nil {
		log.LogAttrs(ctx, L1, "suspend.creds_remove_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
	}

	// 4) PB patch state=suspended.
	if err := mgr.PatchSlot(ctx, slot.ID, map[string]any{"state": "suspended"}); err != nil {
		log.LogAttrs(ctx, L1, "suspend.pb_patch_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "patch_failed")
		return
	}

	// 5) Invalidate /validate cache so the next request denied immediately.
	mgr.InvalidateSlotState(muser)

	// 6) Stop any running JH server.
	if hub, ok := s.up.Hub.(*HubClient); ok {
		if err := hub.StopServer(ctx, slotName); err != nil {
			log.LogAttrs(ctx, L1, "suspend.jh_stop_failed",
				slog.String("slot", slotName), slog.String("error", err.Error()))
		}
	}

	log.LogAttrs(ctx, L1, "manage.suspend.ok", slog.String("slot", slotName))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleManageReactivate implements POST /manage/slots/{slot}/reactivate.
// Sequence (mirrors Python _manage_reactivate):
//
//  1. mcli admin user enable <muser>.
//  2. Mint a fresh MinIO secret + a fresh Nomad ACL token attached to the
//     per-group pool role.
//  3. PB patch state=claimed + new secrets + new accessor + new secret.
//  4. Rewrite /etc/jupyterhub/minio-creds/<X>.
//  5. Invalidate /validate cache (flush stale "suspended").
func (s *Server) handleManageReactivate(w http.ResponseWriter, r *http.Request) {
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
	if slot.State != "suspended" {
		errJSON(w, http.StatusBadRequest, "slot_not_suspended")
		return
	}

	muser := slot.MinioAccessKey
	if muser == "" {
		muser = "slot-" + slotName
	}
	groupName := mgr.GroupName(ctx, slot)
	roleName := "r-su-" + groupName + "-pool"

	if s.up.NomadAdmin == nil || s.up.MinioAdmin == nil {
		errJSON(w, http.StatusInternalServerError, "admin_clients_not_configured")
		return
	}

	roleID, _ := s.up.NomadAdmin.GetRoleID(ctx, roleName)

	if err := s.up.MinioAdmin.SetEnabled(ctx, muser, true); err != nil {
		log.LogAttrs(ctx, L1, "reactivate.minio_enable_failed",
			slog.String("user", muser), slog.String("error", err.Error()))
	}

	newSecret, err := s.up.MinioAdmin.RotateSecret(ctx, muser)
	if err != nil {
		log.LogAttrs(ctx, L1, "reactivate.minio_rotate_failed",
			slog.String("user", muser), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "minio_rotate_failed")
		return
	}
	newAcc, newTok, err := s.up.NomadAdmin.CreateToken(ctx, slotName, roleID)
	if err != nil {
		log.LogAttrs(ctx, L1, "reactivate.nomad_token_create_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "nomad_token_create_failed")
		return
	}

	if err := mgr.PatchSlot(ctx, slot.ID, map[string]any{
		"state":                "claimed",
		"minio_secret_key":     newSecret,
		"nomad_token_accessor": newAcc,
		"nomad_token_secret":   newTok,
	}); err != nil {
		log.LogAttrs(ctx, L1, "reactivate.pb_patch_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "patch_failed")
		return
	}
	if err := writeCredsFile(slotName, muser, newSecret, s.up.Cluster.MinioEndpoint); err != nil {
		log.LogAttrs(ctx, L1, "reactivate.creds_write_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
	}
	mgr.InvalidateSlotState(muser)

	log.LogAttrs(ctx, L1, "manage.reactivate.ok", slog.String("slot", slotName))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// slotAccessor reads the nomad_token_accessor PB field via the same JSON
// decoding the Slot struct doesn't yet surface explicitly. The PB response
// includes the field; we add a thin extension on Slot to keep it visible.
func slotAccessor(s *Slot) string { return s.NomadTokenAccessor }
