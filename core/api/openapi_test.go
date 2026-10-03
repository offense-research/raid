// Contract drift guard: the OpenAPI document and the router must agree.
//
// This is what caught the spec lagging behind for /v1/journal, /v1/grants,
// and the receipt/grant sub-resources. It asserts, in both directions, that
// every documented path is served and every served route is documented.
package api_test

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"offense.dev/raid/core/api"
)

func openAPIPaths(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	var doc struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	if len(doc.Paths) == 0 {
		t.Fatalf("openapi.yaml has no paths")
	}
	out := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		out = append(out, p)
	}
	return out
}

// coveredBy reports whether a concrete OpenAPI path is served by a router
// pattern: an exact route matches exactly, a subtree route (trailing slash)
// matches any path under it.
func coveredBy(route, path string) bool {
	if strings.HasSuffix(route, "/") {
		return strings.HasPrefix(path, route)
	}
	return route == path
}

func TestOpenAPIMatchesRouter(t *testing.T) {
	routes := api.NewServer(api.Config{}).Routes()
	if len(routes) == 0 {
		t.Fatal("router exposes no routes")
	}
	paths := openAPIPaths(t)

	// every documented path must be served
	for _, p := range paths {
		ok := false
		for _, r := range routes {
			if coveredBy(r, p) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("openapi path %q is documented but not served by any route %v", p, routes)
		}
	}

	// every served route must be documented
	for _, r := range routes {
		ok := false
		for _, p := range paths {
			if coveredBy(r, p) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("route %q is served but not documented in openapi.yaml", r)
		}
	}
}
