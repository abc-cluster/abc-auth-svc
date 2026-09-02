package authsvc

import (
	"sort"
	"strings"
)

// identity is the resolved caller identity derived from a Nomad ACL token,
// matching the Python _nomad_identity_headers.
type identity struct {
	User      string
	Group     string
	Namespace string
	Policies  string // comma-joined policy names, "management", or "role:<name>"
}

// nomadIdentity derives the caller's identity from a token-self lookup.
func nomadIdentity(info *NomadTokenSelf) identity {
	name := info.Name
	if name == "" {
		name = "anonymous"
	}
	ttype := info.Type
	if ttype == "" {
		ttype = "client"
	}
	if ttype == "management" {
		return identity{User: name, Group: "admin", Namespace: "*", Policies: "management"}
	}

	var group, policyStr string
	switch {
	case len(info.Policies) > 0:
		group = info.Policies[0]
		policyStr = strings.Join(info.Policies, ",")
	case len(info.Roles) > 0:
		roleName := info.Roles[0].Name
		group = strings.TrimPrefix(roleName, "r-")
		policyStr = "role:" + roleName
	default:
		group, policyStr = "unknown", ""
	}

	nsGuess := group
	switch {
	case strings.HasPrefix(group, "member-"):
		nsGuess = group[len("member-"):]
	case strings.HasSuffix(group, "-pool"):
		nsGuess = group[:len(group)-len("-pool")]
	case strings.HasSuffix(group, "-admin"):
		nsGuess = group[:len(group)-len("-admin")]
	case strings.HasSuffix(group, "-member"):
		nsGuess = group[:len(group)-len("-member")]
	}
	ns := info.Namespace
	if ns == "" {
		ns = nsGuess
	}
	return identity{User: name, Group: group, Namespace: ns, Policies: policyStr}
}

// groupsFromPolicies derives a sorted list of clean group names from a
// comma-separated policy string, stripping the su- and member- prefixes and the
// -pool/-admin/-member suffixes. Management → ["*"]. Role references are skipped
// (need MinIO-group expansion, deferred). Parity port of the Python
// _groups_from_policies, which strips the su- prefix only.
//
// Known limitation: a "<ns>-group-admin" policy keeps a trailing "-group", so
// "su-mbhg-bioinformatics-group-admin" reports "mbhg-bioinformatics-group".
// Stripping "-group-admin" as a suffix would fix that one and break another —
// "su-multi-group-admin" is the group "multi-group" with an -admin suffix, not
// the group "multi". The two are indistinguishable without knowing the real
// group list, so this needs resolution against the store, not more suffixes.
func groupsFromPolicies(policyStr string) []string {
	if policyStr == "management" {
		return []string{"*"}
	}
	groups := []string{}
	seen := map[string]bool{}
	for _, p := range strings.Split(policyStr, ",") {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "role:") {
			continue
		}
		// nsGuess above accepts both policy shapes — "member-<ns>" and
		// "<ns>-member" — but only the suffix form was stripped here, so a
		// "member-su-foo" policy resolved to namespace "su-foo" while
		// reporting its group as "member-su-foo". Strip the prefix form too
		// so the two agree. No deployment uses the prefix shape today; this
		// keeps a policy named that way from being reported oddly rather
		// than changing any current answer.
		g := strings.TrimPrefix(p, "member-")
		if strings.HasPrefix(g, nsPrefix) {
			inner := strings.TrimPrefix(g, nsPrefix)
			g = inner
			for _, suf := range []string{"-pool", "-admin", "-member"} {
				if strings.HasSuffix(inner, suf) {
					g = inner[:len(inner)-len(suf)]
					break
				}
			}
		}
		if g != "" && !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
	}
	sort.Strings(groups)
	return groups
}
