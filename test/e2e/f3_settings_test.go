//go:build integration

// End-to-end scenario for F3-030 AC6: the settings screen's protected tag list and locked test
// parameters take effect on the next operation, with no restart, and the two refusals (an empty
// list, a parameter the live policy cannot pass) hold.
package e2e_test

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var hiddenInputRE = regexp.MustCompile(`<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"`)

// confirmForm returns the hidden fields of the page's form with that action, the way the browser
// would post them back.
func confirmForm(t *testing.T, page, action string) url.Values {
	t.Helper()
	for _, m := range formRE.FindAllStringSubmatch(page, -1) {
		if html.UnescapeString(m[1]) != action {
			continue
		}
		v := url.Values{}
		for _, in := range hiddenInputRE.FindAllStringSubmatch(m[2], -1) {
			v.Set(in[1], html.UnescapeString(in[2]))
		}
		return v
	}
	t.Fatalf("the page has no form to %s: %s", action, excerpt(page))
	return nil
}

var lockedFieldNames = []string{"devops_group", "server_tag", "ui_port", "k8s_tag", "webhook_port", "ssh_src", "ssh_dst", "ssh_port"}

// lockedForm is the locked parameter form as the settings page shows it, with some values replaced.
func lockedForm(t *testing.T, page string, override map[string]string) url.Values {
	t.Helper()
	v := url.Values{}
	for _, n := range lockedFieldNames {
		v.Set(n, inputValue(page, n))
		if v.Get(n) == "" {
			t.Fatalf("the settings page shows no value for %s: %s", n, excerpt(page))
		}
	}
	for k, val := range override {
		v.Set(k, val)
	}
	return v
}

func (s *f3Stack) settingsAudit(event, result string) int {
	return s.proc.queryInt(s.t, `SELECT count(*) FROM audit_events WHERE event = ? AND result = ?`, event, result)
}

func TestE2E_F3_SettingsTakeEffect(t *testing.T) {
	var k8s2, kiosk uint64
	s := newPolicyStack(t, f3Options{prepare: func(s *f3Stack) {
		k8s2 = s.hs.NewNode(s.t, "f3026-ops", "k8s-2", f3K8sTag)
		kiosk = s.hs.NewNode(s.t, "f3026-ops", "kiosk-1", f3SharedTag)
	}})
	del := url.Values{"confirm": {"evet"}}

	// removeProtected is the two-step removal of one tag from the protected list.
	removeProtected := func(t *testing.T, tag string) {
		t.Helper()
		code, body := s.ui.post("/headscale/settings/tags", url.Values{"action": {"remove"}, "tag": {tag}})
		if code != http.StatusOK {
			t.Fatalf("remove %s: status %d: %s", tag, code, excerpt(body))
		}
		mustContain(t, "confirmation", body, tag+" korumalı listeden çıkarılsın mı")
		code, body = s.ui.post("/headscale/settings/tags", confirmForm(t, body, "/headscale/settings/tags"))
		if code != http.StatusOK {
			t.Fatalf("confirmed remove of %s: status %d: %s", tag, code, excerpt(body))
		}
		mustContain(t, "result", body, "korumalı tag listesi güncellendi")
	}

	s.section(t, "protected tags", func(t *testing.T) {
		page := s.ui.getOK("/headscale/settings")
		mustContain(t, "settings", page, f3ServerTag, f3K8sTag, "varsayılan")
		mustNotContain(t, "settings", page, "<code>"+f3SharedTag+"</code>")

		// The shared device is not protected; the k8s device is.
		mustContain(t, "shared device page", s.ui.getOK(devicePath(kiosk, "")), "Cihazı sil")
		if code, body := s.deviceAction(k8s2, "/delete", del); code != http.StatusConflict {
			t.Fatalf("delete of a protected device: status %d, want 409: %s", code, excerpt(body))
		}

		// Adding a tag protects the next operation on its devices.
		code, body := s.ui.post("/headscale/settings/tags", url.Values{"action": {"add"}, "tag": {f3SharedTag}})
		if code != http.StatusOK {
			t.Fatalf("add %s: status %d: %s", f3SharedTag, code, excerpt(body))
		}
		mustContain(t, "result", body, "korumalı tag listesi güncellendi")
		if code, body := s.deviceAction(kiosk, "/delete", del); code != http.StatusConflict {
			t.Fatalf("delete of the newly protected device: status %d, want 409: %s", code, excerpt(body))
		}
		if _, ok := s.node(kiosk); !ok {
			t.Fatal("the newly protected device was deleted")
		}
		detail := s.ui.getOK(devicePath(kiosk, ""))
		mustContain(t, "shared device page", detail, "korumalı sunucu")
		mustNotContain(t, "shared device page", detail, "Cihazı sil")

		// Removing one takes the protection off its devices at once.
		removeProtected(t, f3K8sTag)
		code, body = s.deviceAction(k8s2, "/delete", del)
		wantApplied(t, "delete of the no longer protected device", code, body)
		if _, ok := s.node(k8s2); ok {
			t.Fatal("the device is still in Headscale")
		}

		// The list is never empty.
		removeProtected(t, f3SharedTag)
		code, body = s.ui.post("/headscale/settings/tags", url.Values{"action": {"remove"}, "tag": {f3ServerTag}})
		if code != http.StatusBadRequest {
			t.Fatalf("emptying the list: status %d, want 400: %s", code, excerpt(body))
		}
		mustContain(t, "refusal", body, "boş bırakılamaz")
		mustContain(t, "settings", s.ui.getOK("/headscale/settings"), "<code>"+f3ServerTag+"</code>")
		if n := s.settingsAudit("headscale.settings.protected_tags", "applied"); n != 3 {
			t.Errorf("%d applied protected-tag audit rows, want 3 (add, remove, remove)", n)
		}
		if n := s.settingsAudit("headscale.settings.protected_tags", "failed"); n < 1 {
			t.Errorf("the refused emptying left no failed audit row")
		}
	})

	s.section(t, "locked test parameters", func(t *testing.T) {
		page := s.ui.getOK("/headscale/settings")
		if got := inputValue(page, "webhook_port"); got != "9443" {
			t.Fatalf("webhook port = %q, want the hook.listen port 9443", got)
		}

		// A port the live policy does not allow would be a lock born broken: refused, nothing stored.
		code, body := s.ui.post("/headscale/settings/locked", lockedForm(t, page, map[string]string{"webhook_port": "9444"}))
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("a parameter the policy cannot pass: status %d, want 422: %s", code, excerpt(body))
		}
		mustContain(t, "refusal", body, "canlı policy yeni kilitli testleri geçemiyor")
		// A value that is no port is refused too.
		code, body = s.ui.post("/headscale/settings/locked", lockedForm(t, page, map[string]string{"ssh_port": "99999"}))
		if code != http.StatusBadRequest {
			t.Fatalf("an invalid parameter: status %d, want 400: %s", code, excerpt(body))
		}
		page = s.ui.getOK("/headscale/settings")
		if got := inputValue(page, "webhook_port"); got != "9443" {
			t.Fatalf("a refused change was stored: webhook port = %q", got)
		}
		if got := inputValue(page, "ssh_port"); got != "22" {
			t.Fatalf("a refused change was stored: ssh port = %q", got)
		}

		// Let the policy allow 9444 through the editor's rule form, then change the parameter.
		text, base := s.editorState()
		code, body = s.ui.post("/headscale/policy/rules/add", url.Values{
			"text": {text}, "base_hash": {base}, "add_src": {f3K8sTag}, "add_dst": {"tag:vpn-server:9444"}, "add_proto": {"tcp"},
		})
		if code != http.StatusOK {
			t.Fatalf("add rule: status %d: %s", code, excerpt(body))
		}
		code, body = s.saveEditor(policyText(t, body), base)
		wantPolicyApplied(t, "save of the 9444 rule", code, body)

		// Moving the locked port is a weakening: the confirmation page, then the change.
		code, body = s.ui.post("/headscale/settings/locked", lockedForm(t, page, map[string]string{"webhook_port": "9444"}))
		if code != http.StatusOK {
			t.Fatalf("locked change: status %d: %s", code, excerpt(body))
		}
		mustContain(t, "confirmation", body, "Kilitli test parametreleri zayıflatılsın mı", "WebhookPort")
		code, body = s.ui.post("/headscale/settings/locked", confirmForm(t, body, "/headscale/settings/locked"))
		if code != http.StatusOK {
			t.Fatalf("confirmed locked change: status %d: %s", code, excerpt(body))
		}
		mustContain(t, "result", body, "kilitli test parametreleri kaydedildi")
		if got := inputValue(s.ui.getOK("/headscale/settings"), "webhook_port"); got != "9444" {
			t.Fatalf("webhook port = %q after the change, want 9444", got)
		}

		// The next operation uses it: the editor's save rebuilds the locked tests from the new
		// parameters, and Headscale ran them against the nodes.
		text, base = s.editorState()
		mustContain(t, "the live policy", text, `"accept": ["tag:vpn-server:9443"]`)
		code, body = s.saveEditor(strings.Replace(text, gateRule, gateEdited, 1), base)
		wantPolicyApplied(t, "save after the settings change", code, body)
		after := s.livePolicy()
		mustContain(t, "the saved policy", after, `"src": "tag:k8s", "accept": ["tag:vpn-server:9444"]`)
		mustNotContain(t, "the saved policy", after, `"accept": ["tag:vpn-server:9443"]`)
		if n := strings.Count(after, lockedMarker); n != 3 {
			t.Errorf("the saved policy carries %d locked tests, want 3", n)
		}
		if n := s.settingsAudit("headscale.settings.locked_tests", "applied"); n != 1 {
			t.Errorf("%d applied locked-test audit rows, want 1", n)
		}
		if n := s.settingsAudit("headscale.settings.locked_tests", "failed"); n != 2 {
			t.Errorf("%d failed locked-test audit rows, want 2 (the two refusals)", n)
		}
	})
}
