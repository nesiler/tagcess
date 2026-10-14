package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 2026-10-06 (generic portal): the Headscale screens show simple states as coloured text, not
// chips, and their forms carry typed controls with a browser-side check and a plain message.
func TestHeadscaleScreensUseTypedControlsAndPlainStates(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"/headscale/dns", []string{`id="dns-name"`, `id="dns-value"`, `pattern="[0-9]{1,3}`, `data-msg="IPv4`, `required`}},
		{"/headscale/settings", []string{`type="number"`, `min="1"`, `max="65535"`, `pattern="tag:`, `data-multi`, `name="ssh_dst"`}},
		{"/headscale/keys/personal", []string{`list="expires_in-opts"`, `data-msg="Süreyi`}},
	}
	h := PreviewHandler()
	for _, tc := range cases {
		body := previewBody(t, h, tc.path)
		for _, w := range tc.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s lacks %s", tc.path, w)
			}
		}
	}
	for _, path := range []string{"/headscale/keys/preauth", "/headscale/keys/api", "/headscale/users", "/headscale/dns"} {
		body := previewBody(t, h, path)
		main := body[strings.Index(body, "<main"):]
		if strings.Contains(main, `class="pill pill-ok`) || strings.Contains(main, `class="pill pill-err`) || strings.Contains(main, `class="pill pill-warn`) {
			t.Errorf("%s still shows a simple state as a chip", path)
		}
	}
}

func previewBody(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d", path, rec.Code)
	}
	return rec.Body.String()
}
