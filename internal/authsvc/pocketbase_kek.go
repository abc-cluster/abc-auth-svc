package authsvc

// pocketbase_kek.go — PBClient read/write of the per-group age key material
// (ADR-0067 Amendment 2: the managed group key is a native age X25519 keypair).
// The PUBLIC recipient (age1…) is stored in plaintext; the PRIVATE key
// (AGE-SECRET-KEY-1…) is stored wrapped under the root MK. Fields on `groups`:
//   age_recipient    (text)            — age1… public recipient
//   age_sk_wrapped   (text, HIDDEN)    — root-MK-wrapped AGE-SECRET-KEY-1…
//   age_key_version  (number)
//   age_key_alg      (text)            — wrap construction id
// This layer moves the opaque wrapped blob + the public recipient in and out.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// GroupKeyRecord reads a group record's name + age key fields in one GET.
// hasKey is false when the group has no age key provisioned yet; a non-nil err
// means the group record itself could not be read.
func (c *PBClient) GroupKeyRecord(ctx context.Context, groupID string) (name, recipient, skWrapped string, version int, alg string, hasKey bool, err error) {
	rb, err := c.do(ctx, http.MethodGet, "/api/collections/groups/records/"+url.PathEscape(groupID), nil, true)
	if err != nil {
		return "", "", "", 0, "", false, err
	}
	var g struct {
		Name          string `json:"name"`
		AgeRecipient  string `json:"age_recipient"`
		AgeSkWrapped  string `json:"age_sk_wrapped"`
		AgeKeyVersion int    `json:"age_key_version"`
		AgeKeyAlg     string `json:"age_key_alg"`
	}
	if err := json.Unmarshal(rb, &g); err != nil {
		return "", "", "", 0, "", false, err
	}
	hasKey = g.AgeRecipient != "" && g.AgeSkWrapped != ""
	return g.Name, g.AgeRecipient, g.AgeSkWrapped, g.AgeKeyVersion, g.AgeKeyAlg, hasKey, nil
}

// PutGroupKey writes the age key fields onto a group record (PATCH).
func (c *PBClient) PutGroupKey(ctx context.Context, groupID, recipient, skWrapped string, version int, alg string) error {
	body, err := json.Marshal(map[string]any{
		"age_recipient":   recipient,
		"age_sk_wrapped":  skWrapped,
		"age_key_version": version,
		"age_key_alg":     alg,
	})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, "/api/collections/groups/records/"+url.PathEscape(groupID), body, true)
	return err
}
