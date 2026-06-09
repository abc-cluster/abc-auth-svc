package authsvc

import (
	"log/slog"
	"net/http"
)

// handleManageRotate implements POST /manage/slots/{slot}/rotate.
// Sequence (mirrors Python _manage_rotate at L2453):
//
//  1. Look up slot + verify state ∈ {claimed, suspended}.
//  2. Mint a fresh MinIO secret (mcli admin user add — idempotent overwrite).
//  3. Mint a fresh Nomad ACL token attached to r-su-<group>-pool.
//  4. PB patch: new MinIO secret, new accessor, new Nomad secret.
//  5. Delete the OLD Nomad accessor (best-effort).
//  6. Rewrite /etc/jupyterhub/minio-creds/<slot> + abc-configs/<slot>.
//  7. persistSlotConfig (re-render config_yaml so /slots/me/config + spawn
//     hook serve the new creds).
//  8. Invalidate /validate cache.
//  9. StopServer (kill any running JH server so it picks up new env on next spawn).
//
// Cross-portal coherence rationale lives at brainstorms/abc-seedling-onboarding/
// 2026-06-01-claim-time-config-dropthrough.md.
func (s *Server) handleManageRotate(w http.ResponseWriter, r *http.Request) {
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
	if slot.State != "claimed" && slot.State != "suspended" {
		errJSON(w, http.StatusBadRequest, "slot_not_active")
		return
	}

	muser := slot.MinioAccessKey
	if muser == "" {
		muser = "slot-" + slotName
	}
	oldAccessor := slot.NomadTokenAccessor
	groupName := mgr.GroupName(ctx, slot)
	roleName := "r-su-" + groupName + "-pool"

	if s.up.NomadAdmin == nil || s.up.MinioAdmin == nil {
		errJSON(w, http.StatusInternalServerError, "admin_clients_not_configured")
		return
	}
	roleID, _ := s.up.NomadAdmin.GetRoleID(ctx, roleName)

	// (2) New MinIO secret.
	newSecret, err := s.up.MinioAdmin.RotateSecret(ctx, muser)
	if err != nil {
		log.LogAttrs(ctx, L1, "rotate.minio_rotate_failed",
			slog.String("user", muser), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "minio_rotate_failed")
		return
	}

	// (3) New Nomad ACL token.
	newAcc, newTok, err := s.up.NomadAdmin.CreateToken(ctx, slotName, roleID)
	if err != nil {
		log.LogAttrs(ctx, L1, "rotate.nomad_token_create_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "nomad_token_create_failed")
		return
	}

	// (4) PB patch — commits the new creds before we revoke the old ones, so
	// /slots/me/config + /auth/exchange immediately serve the rotated values.
	if err := mgr.PatchSlot(ctx, slot.ID, map[string]any{
		"minio_secret_key":     newSecret,
		"nomad_token_accessor": newAcc,
		"nomad_token_secret":   newTok,
	}); err != nil {
		log.LogAttrs(ctx, L1, "rotate.pb_patch_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "patch_failed")
		return
	}

	// (5) Best-effort delete of the OLD Nomad accessor.
	if oldAccessor != "" {
		if err := s.up.NomadAdmin.DeleteToken(ctx, oldAccessor); err != nil {
			log.LogAttrs(ctx, L1, "rotate.old_token_delete_failed",
				slog.String("accessor", oldAccessor), slog.String("error", err.Error()))
		}
	}

	// (6) Rewrite host creds files.
	if err := writeCredsFile(slotName, muser, newSecret, s.up.Cluster.MinioEndpoint); err != nil {
		log.LogAttrs(ctx, L1, "rotate.creds_write_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
	}

	// (7) Re-render slot.config_yaml so future config refreshes / spawn hook
	// reads emit the new creds. We pass "" for the opaque hint — rotation
	// preserves the existing cred_source (real-creds blob stays real, opaque
	// stays opaque) and the renderer reads the persisted opaque hash.
	if blob, err := persistSlotConfig(ctx, mgr, s.up.Cluster, slot.ID, ""); err != nil {
		log.LogAttrs(ctx, L1, "rotate.persist_config_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
	} else {
		// Also drop the rendered blob into /etc/jupyterhub/abc-configs/<slot>
		// — the spawn hook will use this on next login.
		if err := writeABCConfigFile(slotName, blob); err != nil {
			log.LogAttrs(ctx, L1, "rotate.abc_config_write_failed",
				slog.String("slot", slotName), slog.String("error", err.Error()))
		}
	}

	// (8) Flush /validate cache.
	mgr.InvalidateSlotState(muser)

	// (9) Kill any running JH server so it picks up the rotated env on next spawn.
	if hub, ok := s.up.Hub.(*HubClient); ok {
		if err := hub.StopServer(ctx, slotName); err != nil {
			log.LogAttrs(ctx, L1, "rotate.jh_stop_failed",
				slog.String("slot", slotName), slog.String("error", err.Error()))
		}
	}

	log.LogAttrs(ctx, L1, "manage.rotate.ok", slog.String("slot", slotName))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
