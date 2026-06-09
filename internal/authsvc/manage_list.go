package authsvc

import (
	"log/slog"
	"net/http"
)

// publicSlot is the secret-stripped projection of a Slot returned by the
// operator-facing GET endpoints. Mirrors the field allowlist the Python
// service's _manage_list_slots / _manage_get_slot publish.
type publicSlot struct {
	ID               string `json:"id"`
	SlotName         string `json:"slot_name"`
	Group            string `json:"group,omitempty"`
	GroupName        string `json:"group_name,omitempty"`
	State            string `json:"state"`
	CredSource       string `json:"cred_source,omitempty"`
	MinioAccessKey   string `json:"minio_access_key,omitempty"`
	ConfigYAMLAt     string `json:"config_yaml_at,omitempty"`
	OpaqueTokenHash  string `json:"opaque_token_hash,omitempty"`
}

func toPublicSlot(s Slot) publicSlot {
	return publicSlot{
		ID:              s.ID,
		SlotName:        s.SlotName,
		Group:           s.Group,
		GroupName:       s.GroupName,
		State:           s.State,
		CredSource:      s.CredSource,
		MinioAccessKey:  s.MinioAccessKey,
		OpaqueTokenHash: s.OpaqueTokenHash,
	}
}

// handleManageListSlots implements GET /manage/slots — operator-gated list.
// Mirrors Python _manage_list_slots. Returns up to 500 slot records with the
// safe field allowlist (no secrets).
func (s *Server) handleManageListSlots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.requireOperator(w, r) {
		return
	}
	mgr, ok := s.up.Store.(SlotManager)
	if !ok {
		errJSON(w, http.StatusInternalServerError, "store_not_writable")
		return
	}
	slots, err := mgr.ListSlots(ctx, "", 500)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]publicSlot, 0, len(slots))
	for _, sl := range slots {
		out = append(out, toPublicSlot(sl))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleManageGetSlot implements GET /manage/slots/{slot} — operator-gated,
// secret-filtered single-slot lookup. Mirrors Python _manage_get_slot.
func (s *Server) handleManageGetSlot(w http.ResponseWriter, r *http.Request) {
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
	if s.up.Store == nil {
		errJSON(w, http.StatusInternalServerError, "store_not_configured")
		return
	}
	slot, err := s.up.Store.FindSlot(ctx, "slot_name='"+slotName+"'")
	if err != nil {
		log.LogAttrs(ctx, L1, "manage.get_slot.lookup_failed",
			slog.String("slot", slotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if slot == nil {
		errJSON(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, toPublicSlot(*slot))
}
