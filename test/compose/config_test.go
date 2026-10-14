// Static guard for the local authorization knobs. It has no build tag so it runs in the normal
// gate, independent of the lab.
package compose_test

import (
	"os"
	"strings"
	"testing"
)

// TestCompose_AuthAccessConfig pins the Caddy/oauth2-proxy authorization config that the runtime
// AC3-AC5 tests depend on. oauth2-proxy ignores a client-supplied X-Auth-Request-Groups header, so
// the runtime 403 test would still pass if Caddy's stripping lines were deleted; this test fails
// in that case, and also if the groups claim name or allowed_groups drift.
func TestCompose_AuthAccessConfig(t *testing.T) {
	caddy := mustRead(t, "caddy/Caddyfile")

	auth := strings.Index(caddy, "forward_auth oauth2-proxy")
	if auth < 0 {
		t.Fatal("caddy/Caddyfile has no forward_auth block")
	}
	for _, header := range []string{"-X-Auth-Request-User", "-X-Auth-Request-Email", "-X-Auth-Request-Groups"} {
		strip := strings.Index(caddy, "request_header "+header)
		if strip < 0 {
			t.Fatalf("caddy/Caddyfile does not strip the client's %s header", header)
		}
		if strip > auth {
			t.Fatalf("caddy/Caddyfile strips %s after forward_auth; it must come first", header)
		}
	}
	if !strings.Contains(caddy, "uri /oauth2/auth?allowed_groups=devops") {
		t.Fatal("caddy/Caddyfile forward_auth does not pass allowed_groups=devops")
	}

	proxy := mustRead(t, "oauth2-proxy/oauth2-proxy.cfg")
	if !strings.Contains(proxy, `oidc_groups_claim = "groups"`) {
		t.Fatal("oauth2-proxy.cfg does not read the groups claim (oidc_groups_claim)")
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
