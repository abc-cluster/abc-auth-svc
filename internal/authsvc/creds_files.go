package authsvc

import (
	"fmt"
	"os"
	"path/filepath"
)

// MinIO creds file path: /etc/jupyterhub/minio-creds/<slot>. Read by TLJH's
// `_inject_minio_creds` spawn hook to populate the slot's JH server env
// with AWS_* vars. abc-config file: /etc/jupyterhub/abc-configs/<slot> —
// dropped into $HOME/.abc/config.yaml on first spawn so the abc CLI inside
// the workbench has ambient auth.
const (
	credsDir     = "/etc/jupyterhub/minio-creds"
	abcConfigDir = "/etc/jupyterhub/abc-configs"
)

// writeCredsFile writes /etc/jupyterhub/minio-creds/<slotName> with mode 600.
// Idempotent (overwrites). Mirrors the Python _write_creds_files helper.
//
// The MinIO endpoint baked into the file is the cluster's S3 endpoint
// (CLUSTER_MINIO_ENDPOINT), not the console URL — it's read by s5cmd /
// boto3 inside the workbench, not the browser. Best-effort permission
// hardening on the parent dir matches the Python (chmod 700).
func writeCredsFile(slotName, accessKey, secretKey, s3Endpoint string) error {
	if err := os.MkdirAll(credsDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(credsDir, 0o700)
	path := filepath.Join(credsDir, slotName)
	body := fmt.Sprintf("AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nS3_ENDPOINT_URL=%s\n",
		accessKey, secretKey, s3Endpoint)
	return os.WriteFile(path, []byte(body), 0o600)
}

// writeABCConfigFile writes the rendered config.yaml blob to
// /etc/jupyterhub/abc-configs/<slotName> with mode 600. Called by
// /slots/claim and /manage/slots/rotate after persistSlotConfig produces a
// fresh blob, so the next workbench spawn picks up the new creds.
func writeABCConfigFile(slotName, blob string) error {
	if err := os.MkdirAll(abcConfigDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(abcConfigDir, 0o700)
	path := filepath.Join(abcConfigDir, slotName)
	return os.WriteFile(path, []byte(blob), 0o600)
}

// removeCredsFiles removes both the minio-creds and abc-configs files for
// slotName. Used on suspend. Errors are best-effort — caller logs.
func removeCredsFiles(slotName string) error {
	var firstErr error
	for _, p := range []string{
		filepath.Join(credsDir, slotName),
		filepath.Join(abcConfigDir, slotName),
	} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
