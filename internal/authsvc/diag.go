package authsvc

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// SlotDiagReport is the JSON body of GET /manage/slots/{slot}/diag.
// Schema-mirrored from the Python service's _manage_diag_slot so operators
// don't need to relearn the format between Python (live) and Go (shadow).
//
// Designed so a single curl answers "why doesn't <slot> work?" end-to-end
// (auth, JH, host provisioning) — the alternative is the journalctl + ssh +
// alloc-exec sequence that surfaced both Bug A and Bug B on 2026-06-09.
type SlotDiagReport struct {
	Slot              string         `json:"slot"`
	PB                map[string]any `json:"pb"`
	JH                map[string]any `json:"jh"`
	Host              map[string]any `json:"host"`
	Checks            []DiagCheck    `json:"checks"`
	Verdict           string         `json:"verdict"`
	RemediationHints  []string       `json:"remediation_hints"`
}

// DiagCheck is one named readiness check.
type DiagCheck struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// handleSlotDiag implements GET /manage/slots/{slot}/diag — see SlotDiagReport.
// Operator-gated. Read-only; never mutates anything.
func (s *Server) handleSlotDiag(w http.ResponseWriter, r *http.Request) {
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

	report := SlotDiagReport{
		Slot:             slotName,
		PB:               map[string]any{},
		JH:               map[string]any{},
		Host:             map[string]any{},
		Checks:           []DiagCheck{},
		RemediationHints: []string{},
	}
	chk := func(name string, ok bool, detail string) {
		report.Checks = append(report.Checks, DiagCheck{Check: name, OK: ok, Detail: detail})
	}

	// 1) PocketBase row
	var slot *Slot
	if s.up.Store == nil {
		chk("pb_row_present", false, "store not configured")
		report.Verdict = "blocked_at: pb_row_present"
		writeJSON(w, http.StatusOK, report)
		return
	}
	slot, err := s.up.Store.FindSlot(ctx, "slot_name='"+slotName+"'")
	if err != nil {
		chk("pb_row_present", false, "lookup error: "+err.Error())
		report.Verdict = "blocked_at: pb_row_present"
		writeJSON(w, http.StatusOK, report)
		return
	}
	if slot == nil {
		chk("pb_row_present", false, "no record")
		report.Verdict = "blocked_at: pb_row_present"
		writeJSON(w, http.StatusOK, report)
		return
	}
	chk("pb_row_present", true, "")
	report.PB["state"] = slot.State
	report.PB["minio_access_key"] = slot.MinioAccessKey
	report.PB["group"] = slot.Group
	report.PB["cred_source"] = slot.CredSource
	chk("pb_state_claimed", slot.State == "claimed", "state='"+slot.State+"'")

	// 2) JH side — admin token shape + user existence
	jhTok := s.cfg.JupyterHubAdminToken
	report.JH["api_url"] = s.cfg.JupyterHubAPIURL
	report.JH["admin_token_len"] = len(jhTok)
	if jhTok == "" {
		report.JH["admin_token_prefix"] = "(unset)"
		chk("jh_admin_token_real", false, "JUPYTERHUB_API_TOKEN unset")
	} else {
		pfx := jhTok
		if len(pfx) > 8 {
			pfx = pfx[:8]
		}
		report.JH["admin_token_prefix"] = pfx
		switch {
		case strings.Contains(jhTok, "REPLACE_WITH"):
			chk("jh_admin_token_real", false, "placeholder value (install-auth-svc.sh did not substitute)")
		case len(jhTok) < 32:
			chk("jh_admin_token_real", false, "suspiciously short")
		default:
			chk("jh_admin_token_real", true, "")
		}
	}

	report.JH["user_name_checked"] = slotName
	var existsPtr *bool
	if ex, ok := s.up.Hub.(HubUserExister); ok {
		var probeErr error
		existsPtr, probeErr = ex.UserExists(ctx, slotName)
		if probeErr != nil {
			report.JH["user_exists"] = nil
			chk("jh_user_present", false, "probe failed: "+probeErr.Error())
		} else if existsPtr == nil {
			report.JH["user_exists"] = nil
			chk("jh_user_present", false, "probe inconclusive")
		} else {
			report.JH["user_exists"] = *existsPtr
			if *existsPtr {
				chk("jh_user_present", true, "")
			} else {
				chk("jh_user_present", false, "GET /users/"+slotName+" → 404")
			}
		}
	} else {
		report.JH["user_exists"] = nil
		chk("jh_user_present", false, "hub minter does not implement HubUserExister")
	}

	// 3) Host probes — unix user, workbench home, minio-creds, abc-config
	sysUser := "jupyter-" + slotName
	var uid int = -1
	if pw, lerr := user.Lookup(sysUser); lerr == nil {
		uidN, _ := strconv.Atoi(pw.Uid)
		uid = uidN
		report.Host["unix_user"] = map[string]any{
			"name": sysUser, "exists": true, "uid": uidN,
		}
		chk("unix_user_present", true, "")
	} else {
		var unkErr user.UnknownUserError
		if errors.As(lerr, &unkErr) {
			report.Host["unix_user"] = map[string]any{"name": sysUser, "exists": false}
			chk("unix_user_present", false, "no system user "+sysUser+" on this host")
		} else {
			report.Host["unix_user"] = map[string]any{"name": sysUser, "exists": false, "error": lerr.Error()}
			chk("unix_user_present", false, "lookup error: "+lerr.Error())
		}
	}

	home := "/data/workbench/" + slotName + "/home"
	homeInfo, herr := os.Stat(home)
	homeMap := map[string]any{"path": home, "exists": herr == nil && homeInfo.IsDir()}
	if herr == nil && homeInfo.IsDir() {
		// best-effort owner check via syscall is non-portable; use os.Stat sys field
		// (Linux: *syscall.Stat_t). To keep this file portable across dev macs,
		// fall back to reading via the unix package on the live alloc only.
		if ownerUID, ok := tryStatOwnerUID(homeInfo); ok {
			homeMap["owner_uid"] = ownerUID
			homeMap["owner_matches"] = (uid >= 0 && ownerUID == uid)
			chk("workbench_home_present", true, "")
			if uid >= 0 && ownerUID != uid {
				chk("workbench_home_owned_by_user", false,
					"owner uid "+strconv.Itoa(ownerUID)+" != "+strconv.Itoa(uid))
			} else if uid >= 0 {
				chk("workbench_home_owned_by_user", true, "")
			}
		} else {
			homeMap["owner_uid"] = nil
			chk("workbench_home_present", true, "")
		}
	} else {
		chk("workbench_home_present", false, "missing: "+home)
	}
	report.Host["workbench_home"] = homeMap

	for _, p := range []struct {
		label, path string
	}{
		{"minio_creds_file", "/etc/jupyterhub/minio-creds/" + slotName},
		{"abc_config_file", "/etc/jupyterhub/abc-configs/" + slotName},
	} {
		_, fperr := os.Stat(p.path)
		present := fperr == nil
		report.Host[p.label] = map[string]any{"path": p.path, "exists": present}
		if present {
			chk(p.label+"_present", true, "")
		} else {
			chk(p.label+"_present", false, "missing: "+p.path)
		}
	}

	// 4) Verdict + remediation
	failed := []string{}
	failedSet := map[string]struct{}{}
	for _, c := range report.Checks {
		if !c.OK {
			failed = append(failed, c.Check)
			failedSet[c.Check] = struct{}{}
		}
	}
	if len(failed) == 0 {
		report.Verdict = "ready"
	} else {
		report.Verdict = "blocked_at: " + strings.Join(failed, ", ")
	}

	hints := []string{}
	if _, miss := failedSet["workbench_home_present"]; miss {
		hints = append(hints, "mkdir -p "+home+" && chown -R "+sysUser+":"+sysUser+" "+home+" && chmod 750 "+home)
	} else if _, miss := failedSet["workbench_home_owned_by_user"]; miss {
		hints = append(hints, "chown -R "+sysUser+":"+sysUser+" "+home)
	}
	if _, miss := failedSet["jh_user_present"]; miss {
		hints = append(hints, "User auto-creates on first browser login at https://workbench…/ "+
			"(Caddy injects Remote-User="+slotName+"); OR pre-create: curl -X POST "+
			"-H 'Authorization: token <admin>' "+s.cfg.JupyterHubAPIURL+"/users/"+slotName)
	}
	_, missMinio := failedSet["minio_creds_file_present"]
	_, missAbc := failedSet["abc_config_file_present"]
	if missMinio || missAbc {
		hints = append(hints, "bash provision-pool-user.sh "+slotName+" <minio_secret_key>  "+
			"# OR POST /manage/slots/"+slotName+"/rotate to re-mint creds")
	}
	if _, miss := failedSet["jh_admin_token_real"]; miss {
		hints = append(hints, "Re-run install-auth-svc.sh to substitute the JUPYTERHUB_API_TOKEN placeholder, then alloc-restart auth-svc")
	}
	if _, miss := failedSet["pb_state_claimed"]; miss && slot.State == "unclaimed" {
		hints = append(hints, "Slot '"+slotName+"' is unclaimed in PocketBase — flow it through POST /slots/claim with a claim_code, or manually update the PB record to state='claimed'")
	}
	report.RemediationHints = hints

	log.LogAttrs(ctx, L1, "manage.slot_diag",
		slog.String("slot", slotName),
		slog.String("verdict", report.Verdict))

	// Use json.Encoder so SlotDiagReport's nested map[string]any preserves
	// the field order the schema documents.
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}

// tryStatOwnerUID extracts the owner uid from os.FileInfo when the underlying
// syscall provides it (Linux/Darwin). Kept here so the rest of the file is
// pure-portable; a build-tag-gated stat.go (linux) implements the real call.
func tryStatOwnerUID(fi os.FileInfo) (int, bool) {
	return statOwnerUID(fi)
}
