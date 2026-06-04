package authsvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// persistSlotConfig re-renders a slot's config_yaml from its current fields and
// writes it back to PocketBase. Returns the rendered YAML.
//
// Stable-blob invariant: for a seedling/v1 slot called without a bare opaque
// (e.g. a real-creds rotation), the user-visible YAML must not change — the
// server only stores the hash — so it returns the existing blob unchanged.
// Parity port of the Python _persist_slot_config.
func persistSlotConfig(ctx context.Context, mgr SlotManager, cluster ClusterInfo, slotID, opaqueToken string) (string, error) {
	slot, err := mgr.GetSlot(ctx, slotID)
	if err != nil {
		return "", err
	}
	cs := strings.ToLower(strings.TrimSpace(slot.CredSource))
	if cs == "seedling/v1" && opaqueToken == "" {
		return slot.ConfigYAML, nil
	}
	group := mgr.GroupName(ctx, slot)
	yaml, err := renderConfigYAML(cluster, slot.SlotName, group,
		slot.NomadTokenSecret, slot.MinioAccessKey, slot.MinioSecretKey, cs, opaqueToken)
	if err != nil {
		return "", err
	}
	if err := mgr.PatchSlot(ctx, slotID, map[string]any{
		"config_yaml":          yaml,
		"config_yaml_at":       nowPB(),
		"config_yaml_renderer": RendererVersion,
	}); err != nil {
		return "", err
	}
	return yaml, nil
}

// handleSlotsMeConfig implements GET /slots/me/config — return the calling
// slot's rendered config.yaml (powers `abc auth config refresh`). Auth: the
// caller's Nomad token. Parity port of the Python _slots_me_config.
func (s *Server) handleSlotsMeConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	token := strings.TrimSpace(r.Header.Get("X-Nomad-Token"))
	if token == "" {
		if a := r.Header.Get("Authorization"); len(a) >= 7 && strings.EqualFold(a[:7], "bearer ") {
			token = strings.TrimSpace(a[7:])
		}
	}
	if token == "" {
		errJSON(w, http.StatusUnauthorized, "missing_token")
		return
	}
	info, err := s.up.Nomad.LookupTokenSelf(ctx, token)
	if err != nil || info == nil {
		errJSON(w, http.StatusUnauthorized, "invalid_or_expired_token")
		return
	}
	slotName := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(info.Name), "pool-"))
	if slotName == "" {
		errJSON(w, http.StatusUnauthorized, "could_not_determine_slot")
		return
	}
	if s.up.Store == nil {
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}

	slot, err := s.up.Store.FindSlot(ctx, "slot_name='"+slotName+"'")
	if err != nil {
		log.LogAttrs(ctx, L1, "slots.config.lookup_failed", slog.String("slot", slotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if slot == nil {
		errJSON(w, http.StatusNotFound, "slot_not_found")
		return
	}
	if slot.State != "claimed" {
		state := slot.State
		if state == "" {
			state = "unknown"
		}
		errJSON(w, http.StatusForbidden, "slot_"+state)
		return
	}

	blob := slot.ConfigYAML
	if blob == "" {
		// Claimed but no rendered blob yet — render on demand (needs write access).
		mgr, ok := s.up.Store.(SlotManager)
		if !ok {
			errJSON(w, http.StatusInternalServerError, "config_render_failed")
			return
		}
		blob, err = persistSlotConfig(ctx, mgr, s.up.Cluster, slot.ID, "")
		if err != nil {
			log.LogAttrs(ctx, L1, "slots.config.render_failed", slog.String("slot", slotName), slog.String("error", err.Error()))
			errJSON(w, http.StatusInternalServerError, "config_render_failed")
			return
		}
	}

	body := []byte(blob)
	w.Header().Set("Content-Type", "text/yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="abc-config-%s.yaml"`, slotName))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	log.LogAttrs(ctx, L1, "slots.config.refresh", slog.String("slot", slotName))
}
