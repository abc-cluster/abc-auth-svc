package authsvc

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// claimLock serialises /slots/claim across goroutines. The Python service uses
// a threading.Lock around the find→patch sequence so two concurrent claims
// can't both succeed on the same code. We do the same here with sync.Mutex
// (single-process; if/when this service is replicated, switch to a PB-side
// transaction).
var claimLock sync.Mutex

// claimRequest is the inbound body shape. cred_source is optional —
// "" / "local" / "seedling/v1" are accepted; everything else is rejected
// 400.
type claimRequest struct {
	ClaimCode  string `json:"claim_code"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	CredSource string `json:"cred_source"`
}

// handleSlotsClaim implements POST /slots/claim.
//
// 1) Validate body + cred_source.
// 2) Under claimLock:
//   - find unclaimed slot by claim_code,
//   - resolve effective cred_source (request → group default → "local"),
//   - optionally mint opaque (seedling/v1),
//   - PB patch state=claimed.
//
// 3) Render config.yaml via persistSlotConfig (single writer for slot.config_yaml).
// 4) Return the YAML as an attachment so the abc CLI writes it directly.
//
// Mirrors Python _claim_slot. Renderer + seedling/v1 opaque path reuse the
// existing render.go + slots.go helpers shared with the cred-source flip.
func (s *Server) handleSlotsClaim(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var req claimRequest
	if len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, &req); err != nil {
			errJSON(w, http.StatusBadRequest, "invalid_json")
			return
		}
	}
	claimCode := strings.TrimSpace(req.ClaimCode)
	if claimCode == "" {
		errJSON(w, http.StatusBadRequest, "claim_code_required")
		return
	}
	requestedCS := strings.ToLower(strings.TrimSpace(req.CredSource))
	if requestedCS != "" && requestedCS != "local" && requestedCS != "seedling/v1" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":     "invalid_cred_source",
			"requested": requestedCS,
			"allowed":   []string{"local", "seedling/v1"},
		})
		return
	}

	mgr, ok := s.up.Store.(SlotManager)
	if !ok {
		errJSON(w, http.StatusInternalServerError, "store_not_writable")
		return
	}

	claimLock.Lock()
	defer claimLock.Unlock()

	slot, err := mgr.FindSlot(ctx, "claim_code='"+claimCode+"' && state='unclaimed'")
	if err != nil {
		log.LogAttrs(ctx, L1, "claim.find_failed", slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if slot == nil {
		errJSON(w, http.StatusNotFound, "code_invalid_or_used")
		return
	}

	// Resolve effective cred_source: request → group default → "local".
	effectiveCS := requestedCS
	if effectiveCS == "" {
		effectiveCS = lookupGroupCredSourceDefault(ctx, s.up.Store, slot.Group)
	}
	if effectiveCS == "" {
		effectiveCS = "local"
	}

	patch := map[string]any{
		"state":            "claimed",
		"claimed_by_name":  strings.TrimSpace(req.Name),
		"claimed_by_email": strings.TrimSpace(req.Email),
		"claimed_at":       claimedAtNow(),
	}
	var opaqueForRender string
	if effectiveCS == "seedling/v1" {
		op, err := mintOpaque()
		if err != nil {
			log.LogAttrs(ctx, L1, "claim.opaque_mint_failed", slog.String("error", err.Error()))
			errJSON(w, http.StatusInternalServerError, "opaque_mint_failed")
			return
		}
		opaqueForRender = op
		patch["cred_source"] = "seedling/v1"
		patch["opaque_token_hash"] = sha256Hex(op)
	}
	// For "local" we deliberately leave cred_source absent — preserves parity
	// with pre-Phase-1 rows; the renderer treats "" and "local" identically.

	if err := mgr.PatchSlot(ctx, slot.ID, patch); err != nil {
		log.LogAttrs(ctx, L1, "claim.pb_patch_failed", slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Render config.yaml + persist (single writer for slot.config_yaml).
	blob, err := persistSlotConfig(ctx, mgr, s.up.Cluster, slot.ID, opaqueForRender)
	if err != nil {
		log.LogAttrs(ctx, L1, "claim.render_failed",
			slog.String("slot", slot.SlotName), slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "config_render_failed")
		return
	}

	log.LogAttrs(ctx, L1, "claim.ok",
		slog.String("slot", slot.SlotName),
		slog.String("cred_source", effectiveCS),
		slog.String("name", patch["claimed_by_name"].(string)))

	body := []byte(blob)
	filename := "abc-config-" + slot.SlotName + ".yaml"
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// lookupGroupCredSourceDefault fetches the group's cred_source_default via
// PB. Mirrors the Python `grp.get("cred_source_default")` lookup inside the
// claim handler. Returns "" if the group isn't there or the field is unset.
func lookupGroupCredSourceDefault(ctx context.Context, store SlotStore, groupID string) string {
	if groupID == "" {
		return ""
	}
	// Minimal access path: GroupName loads the record; for the cred_source_default
	// field we need a direct GET via the PBClient. Type-assert to access do().
	gp, ok := store.(*PBClient)
	if !ok {
		return ""
	}
	rb, err := gp.do(ctx, http.MethodGet, "/api/collections/groups/records/"+groupID, nil, true)
	if err != nil {
		return ""
	}
	var g struct {
		CredSourceDefault string `json:"cred_source_default"`
	}
	if err := json.Unmarshal(rb, &g); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(g.CredSourceDefault))
}

// claimedAtNow returns "%Y-%m-%d %H:%M:%S.000Z" — the PocketBase-compatible
// timestamp shape the Python writes. The fractional-seconds field is always
// .000 because PB tolerates that and the abc CLI doesn't read it.
func claimedAtNow() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05.000Z")
}
