package authsvc

import "strings"

// nsPrefix is the prefix a research group's Nomad namespace and MinIO bucket
// carry: group "mbhg-hostgen" lives in namespace "su-mbhg-hostgen".
const nsPrefix = "su-"

// namespaceForGroup returns the Nomad namespace for a group name.
//
// Group names are stored bare in PocketBase ("mbhg-hostgen") and the prefix is
// added here. A name that already carries the prefix is returned unchanged
// rather than doubled: "su-su-mbhg-hostgen" is not a namespace any cluster has,
// and nothing downstream notices. The broker renders the config, the CLI parses
// it, and the mistake only surfaces later as a job that will not place.
//
// An empty group yields a bare "su-", matching the unconditional concatenation
// this replaces; callers that care apply their own fallback first (exchange.go
// leaves the namespace empty, secrets.go substitutes "default").
func namespaceForGroup(group string) string {
	if strings.HasPrefix(group, nsPrefix) {
		return group
	}
	return nsPrefix + group
}
