package authsvc

import (
	"net/http"
	"strings"
)

// handleVerifyNomad implements GET/POST /verify (and /verify-namespace) —
// a Nomad-token introspection probe used by external integrators (Traefik
// forward-auth, observability sidecars). Mirrors Python _verify_nomad.
//
// Auth: X-Nomad-Token or Authorization: Bearer <token>.
// 200 OK  → token validates; sets X-Auth-User / X-Auth-Group / X-Auth-Namespace
//	 / X-Auth-Policies / X-Auth-Type headers and writes "ok\n" body.
// 401 → no token or token rejected by Nomad.
//
// The header names + decoding logic deliberately match the Python service;
// any integrator already wired up against /verify on :4181 sees identical
// behaviour on :4182.
func (s *Server) handleVerifyNomad(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.Header.Get("X-Nomad-Token"))
	if token == "" {
		if a := r.Header.Get("Authorization"); len(a) >= 7 && strings.EqualFold(a[:7], "bearer ") {
			token = strings.TrimSpace(a[7:])
		}
	}
	info, err := s.up.Nomad.LookupTokenSelf(r.Context(), token)
	if err != nil || info == nil {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized: missing or invalid token\n"))
		return
	}
	for k, v := range nomadIdentityHeaders(info) {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// nomadIdentityHeaders derives the X-Auth-* response headers from a Nomad ACL
// token-self introspection. Mirrors Python _nomad_identity_headers exactly so
// downstream readers (Caddy headers, Grafana auth-proxy) see the same string
// values whether Python or Go served the response.
func nomadIdentityHeaders(info *NomadTokenSelf) map[string]string {
	name := info.Name
	if name == "" {
		name = "anonymous"
	}
	ttype := info.Type
	if ttype == "" {
		ttype = "client"
	}
	policies := info.Policies
	roles := info.Roles

	var group, namespace, policyStr string
	switch ttype {
	case "management":
		group, namespace, policyStr = "admin", "*", "management"
	default:
		switch {
		case len(policies) > 0:
			group = policies[0]
			policyStr = strings.Join(policies, ",")
		case len(roles) > 0:
			roleName := roles[0].Name
			if roleName == "" {
				roleName = "unknown"
			}
			if strings.HasPrefix(roleName, "r-") {
				group = roleName[2:]
			} else {
				group = roleName
			}
			policyStr = "role:" + roleName
		default:
			group, policyStr = "unknown", ""
		}
		nsGuess := group
		switch {
		case strings.HasPrefix(group, "member-"):
			nsGuess = strings.TrimPrefix(group, "member-")
		case strings.HasSuffix(group, "-pool"):
			nsGuess = strings.TrimSuffix(group, "-pool")
		case strings.HasSuffix(group, "-admin"):
			nsGuess = strings.TrimSuffix(group, "-admin")
		case strings.HasSuffix(group, "-member"):
			nsGuess = strings.TrimSuffix(group, "-member")
		}
		namespace = info.Namespace
		if namespace == "" {
			namespace = nsGuess
		}
	}

	return map[string]string{
		"X-Auth-User":      name,
		"X-Auth-Group":     group,
		"X-Auth-Namespace": namespace,
		"X-Auth-Policies":  policyStr,
		"X-Auth-Type":      ttype,
	}
}
