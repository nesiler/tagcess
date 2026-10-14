package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// Item 11 (2026-10-06): the connection form uses typed controls with browser-side checks and
// explains every refusal next to its field; the server validation and the secret handling stay.
func TestK8sConnectionTypedFieldsAndFieldErrors(t *testing.T) {
	h := newK8sConnHarness(t)
	body := h.get().Body.String()
	for _, want := range []string{
		`id="endpoint"`, `type="url"`, `pattern="https://\S+"`, `data-msg="https:// ile`,
		`type="datetime-local"`, `data-line-pattern=`, `data-multi`, `name="namespaces"`,
		`list="controller-opts"`, `data-file-into="kubeconfig"`, `data-file-into="ca_data"`,
		`id="token"`, `type="password"`, `autocomplete="new-password"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("connection page lacks %s", want)
		}
	}

	cases := []struct {
		field, value, msg string
	}{
		{"endpoint", "http://10.1.2.3:6443", "https"},
		{"internal", "10.1.2.10", "satırı 1"},
		{"declared_token_expiry", "yarın", "süre biçimi geçersiz"},
		{"namespaces", "Web_Apps", "geçersiz ad"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			rec := h.postProfile(setField(k8sConnProfileForm(), tc.field, tc.value))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", rec.Code)
			}
			page := rec.Body.String()
			errBox := regexp.MustCompile(`<p class="field-err" id="` + tc.field + `-err">([^<]*)</p>`).FindStringSubmatch(page)
			if errBox == nil || !strings.Contains(errBox[1], tc.msg) {
				t.Fatalf("no field error under %s containing %q:\n%s", tc.field, tc.msg, errBox)
			}
			control := regexp.MustCompile(`<(?:input|textarea)[^>]*\sid="` + tc.field + `"[^>]*>`).FindString(page)
			if !strings.Contains(control, `aria-invalid="true"`) || !strings.Contains(control, tc.field+"-err") {
				t.Errorf("%s is not marked invalid and described by its error: %s", tc.field, control)
			}
			if !strings.Contains(page, "işaretli alanları düzeltin") {
				t.Error("the summary does not point to the marked fields")
			}
			if _, err := h.profile(); err == nil {
				t.Error("a refused profile was stored")
			}
		})
	}
}
