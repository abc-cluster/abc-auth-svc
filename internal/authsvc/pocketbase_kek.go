package authsvc

// pocketbase_kek.go — PBClient read/write of the wrapped per-group KEK fields
// (groups.kek_wrapped / kek_version / kek_alg), added 2026-06-26 per the
// ADR-0067 Amendment (KEK store = PocketBase). The KEKs are stored wrapped
// under the root MK; this layer only moves the opaque wrapped blob in and out.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// GroupKEKRecord reads a group record's name + wrapped-KEK fields in one GET.
// hasKEK is false when the group has no KEK provisioned yet; a non-nil err means
// the group record itself could not be read.
func (c *PBClient) GroupKEKRecord(ctx context.Context, groupID string) (name, wrapped string, version int, alg string, hasKEK bool, err error) {
	rb, err := c.do(ctx, http.MethodGet, "/api/collections/groups/records/"+url.PathEscape(groupID), nil, true)
	if err != nil {
		return "", "", 0, "", false, err
	}
	var g struct {
		Name       string `json:"name"`
		KEKWrapped string `json:"kek_wrapped"`
		KEKVersion int    `json:"kek_version"`
		KEKAlg     string `json:"kek_alg"`
	}
	if err := json.Unmarshal(rb, &g); err != nil {
		return "", "", 0, "", false, err
	}
	return g.Name, g.KEKWrapped, g.KEKVersion, g.KEKAlg, g.KEKWrapped != "", nil
}

// PutGroupKEK writes the wrapped-KEK fields onto a group record (PATCH).
func (c *PBClient) PutGroupKEK(ctx context.Context, groupID, wrapped string, version int, alg string) error {
	body, err := json.Marshal(map[string]any{
		"kek_wrapped": wrapped,
		"kek_version": version,
		"kek_alg":     alg,
	})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, "/api/collections/groups/records/"+url.PathEscape(groupID), body, true)
	return err
}
