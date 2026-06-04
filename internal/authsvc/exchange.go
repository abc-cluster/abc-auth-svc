package authsvc

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

// OpaquePrefix namespaces opaque user tokens (abc-opaque) for grep/logs.
const OpaquePrefix = "abco_"

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// credsBundle is the real-credentials bundle returned by /auth/exchange. The
// keys must match the Python _build_creds_bundle exactly, since the CLI's
// SeedlingV1CredSource (abc-cluster-cli internal/credsource/seedling_v1.go)
// deserializes this verbatim.
type credsBundle struct {
	Whoami string      `json:"whoami"`
	Source string      `json:"source"`
	Nomad  bundleNomad `json:"nomad"`
	MinIO  bundleMinIO `json:"minio"`
}

type bundleNomad struct {
	Addr        string   `json:"addr"`
	Token       string   `json:"token"`
	Namespace   string   `json:"namespace"`
	Datacenters []string `json:"datacenters"`
	HeadPool    string   `json:"head_pool"`
	WorkerPool  string   `json:"worker_pool"`
}

type bundleMinIO struct {
	Endpoint  string `json:"endpoint"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

// handleAuthExchange implements POST /auth/exchange — the opaque-token
// credential broker (cred_source = seedling/v1). The caller presents the bare
// opaque (abco_…) as a Bearer; we hash it, resolve the claimed slot, and return
// the real Nomad + MinIO credentials. Parity port of the Python _auth_exchange.
func (s *Server) handleAuthExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := FromContext(ctx)

	if s.up.Store == nil {
		log.LogAttrs(ctx, L1, "exchange.no_store")
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}

	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		errJSON(w, http.StatusUnauthorized, "missing_bearer_token")
		return
	}
	opaque := strings.TrimSpace(auth[7:])
	if opaque == "" {
		errJSON(w, http.StatusUnauthorized, "empty_bearer_token")
		return
	}

	// Only the hash ever touches the store / logs — never the bare opaque.
	slot, err := s.up.Store.FindSlot(ctx, "opaque_token_hash='"+sha256Hex(opaque)+"' && state='claimed'")
	if err != nil {
		log.LogAttrs(ctx, L1, "exchange.lookup_failed", slog.String("error", err.Error()))
		errJSON(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if slot == nil {
		// Same response for "no such opaque" and "wrong state" — don't leak the
		// existence of a token we just suspended.
		errJSON(w, http.StatusUnauthorized, "invalid_or_inactive_token")
		return
	}
	if strings.TrimSpace(slot.CredSource) != "seedling/v1" {
		log.LogAttrs(ctx, L1, "exchange.wrong_cred_source",
			slog.String("slot", slot.SlotName), slog.String("cred_source", slot.CredSource))
		errJSON(w, http.StatusConflict, "slot_not_on_seedling_v1")
		return
	}

	group := s.up.Store.GroupName(ctx, slot)
	namespace := ""
	if group != "" {
		namespace = "su-" + group
	}

	bundle := credsBundle{
		Whoami: slot.SlotName,
		Source: "seedling/v1",
		Nomad: bundleNomad{
			Addr:        s.up.Cluster.NomadEndpoint,
			Token:       slot.NomadTokenSecret,
			Namespace:   namespace,
			Datacenters: []string{s.up.Cluster.Datacenter},
			HeadPool:    s.up.Cluster.HeadPool,
			WorkerPool:  s.up.Cluster.WorkerPool,
		},
		MinIO: bundleMinIO{
			Endpoint:  s.up.Cluster.MinioEndpoint,
			AccessKey: slot.MinioAccessKey,
			SecretKey: slot.MinioSecretKey,
		},
	}

	// Audit: slot name ONLY — never the bundle (it carries real credentials).
	log.LogAttrs(ctx, L1, "exchange.ok", slog.String("slot", slot.SlotName))
	writeJSON(w, http.StatusOK, bundle)
}
