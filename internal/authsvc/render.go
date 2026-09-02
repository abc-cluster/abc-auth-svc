package authsvc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// RendererVersion is stamped onto a slot's config_yaml_renderer field, matching
// the Python service so blobs are attributable across the migration.
const RendererVersion = "abc-auth-svc/v3.0"

// renderConfigYAML builds a complete ~/.abc/config.yaml for a slot. The output
// bytes must match the Python _build_config_yaml exactly — the CLI parses them
// verbatim.
//
//   - ""/"local"  → real Nomad token + MinIO secret baked in (CLI uses directly).
//   - "seedling/v1" → opaque shape: only the bare opaque + identity + endpoints;
//     the CLI exchanges the opaque for real creds at /auth/exchange. Requires a
//     non-empty opaqueToken.
func renderConfigYAML(c ClusterInfo, slotName, groupName, nomadToken, minioAccessKey, minioSecretKey, credSource, opaqueToken string) (string, error) {
	namespace := namespaceForGroup(groupName)
	cs := strings.ToLower(strings.TrimSpace(credSource))

	switch cs {
	case "", "local":
		return fmt.Sprintf(
			"version: 1.0\n"+
				"active_context: %[1]s\n"+
				"contexts:\n"+
				"    %[1]s:\n"+
				"        access_token: %[2]s\n"+
				"        admin:\n"+
				"            id: pool-%[3]s\n"+
				"            services:\n"+
				"                minio:\n"+
				"                    access_key: %[4]s\n"+
				"                    endpoint: %[5]s\n"+
				"                    secret_key: %[6]s\n"+
				"                nomad:\n"+
				"                    addr: %[7]s\n"+
				"                    datacenters:\n"+
				"                        - %[8]s\n"+
				"                    head_pool: %[9]s\n"+
				"                    namespace: %[10]s\n"+
				"                    token: %[2]s\n"+
				"                    worker_pool: %[11]s\n"+
				"                tools:\n"+
				"                    endpoint: %[5]s\n"+
				"        auth:\n"+
				"            whoami: %[3]s\n"+
				"        cluster_type: abc-cluster\n"+
				"        endpoint: %[7]s\n"+
				"        upload_endpoint: %[12]s\n",
			c.Name, nomadToken, slotName, minioAccessKey, c.MinioEndpoint, minioSecretKey,
			c.NomadEndpoint, c.Datacenter, c.HeadPool, namespace, c.WorkerPool, c.UploadEndpoint,
		), nil

	case "seedling/v1":
		if opaqueToken == "" {
			return "", fmt.Errorf("cred_source=seedling/v1 requires a non-empty opaque_token")
		}
		return fmt.Sprintf(
			"version: 1.0\n"+
				"active_context: %[1]s\n"+
				"contexts:\n"+
				"    %[1]s:\n"+
				"        cred_source: seedling/v1\n"+
				"        access_token: %[2]s\n"+
				"        auth:\n"+
				"            whoami: %[3]s\n"+
				"        auth_endpoint: %[4]s\n"+
				"        cluster_type: abc-cluster\n"+
				"        endpoint: %[5]s\n"+
				"        upload_endpoint: %[6]s\n",
			c.Name, opaqueToken, slotName, c.AuthEndpoint, c.NomadEndpoint, c.UploadEndpoint,
		), nil

	default:
		return "", fmt.Errorf("unsupported cred_source %q", credSource)
	}
}

// mintOpaque generates a fresh opaque user token (abco_ + 32 url-safe random
// bytes). Callers persist sha256Hex(token), never the bare value.
func mintOpaque() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return OpaquePrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// nowPB formats the current time in PocketBase v0.23's date format
// (milliseconds + 'Z'), matching the Python _now_iso_pb (millis hardcoded 000).
func nowPB() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05") + ".000Z"
}
