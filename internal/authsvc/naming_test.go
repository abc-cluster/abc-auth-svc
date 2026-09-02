package authsvc

import (
	"strings"
	"testing"
)

func TestNamespaceForGroup(t *testing.T) {
	cases := map[string]string{
		// Bare group names — the shape PocketBase is supposed to store.
		"mbhg-hostgen":  "su-mbhg-hostgen",
		"multi-group":   "su-multi-group",
		"oryx-genomics": "su-oryx-genomics",
		// Already prefixed: returned unchanged rather than doubled. Seeding a
		// cluster with "su-"-prefixed group records produced "su-su-<group>",
		// a namespace no cluster has, with no error anywhere.
		"su-mbhg-hostgen":  "su-mbhg-hostgen",
		"su-oryx-genomics": "su-oryx-genomics",
		// Empty is left to the caller's own fallback; the bare prefix matches
		// the unconditional concatenation this replaced.
		"": "su-",
	}
	for in, want := range cases {
		if got := namespaceForGroup(in); got != want {
			t.Errorf("namespaceForGroup(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNamespaceForGroupIsIdempotent(t *testing.T) {
	for _, g := range []string{"mbhg-hostgen", "su-mbhg-hostgen", "multi-group"} {
		once := namespaceForGroup(g)
		if twice := namespaceForGroup(once); twice != once {
			t.Errorf("namespaceForGroup not idempotent for %q: %q then %q", g, once, twice)
		}
	}
}

// The rendered config is what the CLI reads, so check the prefix reaches it
// intact rather than only testing the helper in isolation.
func TestRenderConfigYAMLNamespaceNotDoubled(t *testing.T) {
	ci := ClusterInfo{Name: "abc-cluster"}
	for _, group := range []string{"oryx-genomics", "su-oryx-genomics"} {
		out, err := renderConfigYAML(ci, "naledi", group, "tok", "ak", "sk", "local", "")
		if err != nil {
			t.Fatalf("renderConfigYAML(%q): %v", group, err)
		}
		if want := "namespace: su-oryx-genomics"; !strings.Contains(out, want) {
			t.Errorf("group %q: rendered config missing %q", group, want)
		}
		if strings.Contains(out, "su-su-") {
			t.Errorf("group %q: rendered config has a doubled prefix", group)
		}
	}
}
