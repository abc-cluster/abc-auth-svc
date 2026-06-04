package authsvc

import (
	"encoding/json"
	"net/http"
)

// BuildInfo carries the ldflags-injected build identity (mirrors abc-node-probe's
// Version / BuildTime / GitCommit).
type BuildInfo struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
}

// handleHealthz is the liveness probe: 200 as long as the process is up.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

type readyResponse struct {
	Status  string            `json:"status"`
	Version string            `json:"version"`
	Checks  map[string]string `json:"checks"`
}

// handleReadyz is the readiness probe. Phase 0 has no upstreams wired, so it is
// always ready; Phase 1+ adds PocketBase/JupyterHub/MinIO/Nomad reachability
// checks here.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	resp := readyResponse{
		Status:  "ready",
		Version: s.build.Version,
		Checks:  map[string]string{},
	}
	if s.cfg.MockUpstreams {
		resp.Checks["mode"] = "mock-upstreams"
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleVersion reports the build identity.
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.build)
}

func (s *Server) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
