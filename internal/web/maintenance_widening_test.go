package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/maintenance"
)

// F3b-020 AC4, second half: while a host config change is open every Headscale tab disables its
// widening forms/buttons with the reason; narrowing actions stay enabled. The band alone was not
// enough (review MEDIUM 1), so each widening surface reads the same request context as the band.

// wideningMaint is the open-maintenance source bound to a page; *fakeHSConfigMaint is the shared
// fake from the H-07 screen tests.
func wideningMaint() *fakeHSConfigMaint {
	return &fakeHSConfigMaint{st: maintenance.Status{State: maintenance.Active, RequestID: "maint-open"}}
}

// enclosingFieldset returns the tag of the innermost fieldset that contains the first occurrence of
// action, and whether that first occurrence sits inside a fieldset at all.
func enclosingFieldset(body, action string) (tag string, inside bool) {
	i := strings.Index(body, action)
	if i < 0 {
		return "", false
	}
	open := strings.LastIndex(body[:i], "<fieldset")
	close := strings.LastIndex(body[:i], "</fieldset>")
	if open < 0 || close > open {
		return "", false
	}
	end := strings.IndexByte(body[open:], '>')
	if end < 0 {
		return "", false
	}
	return body[open : open+end+1], true
}

// assertWideningDisabled proves action is rendered inside a disabled fieldset and the reason shows.
func assertWideningDisabled(t *testing.T, body, action string) {
	t.Helper()
	if !strings.Contains(body, wideningBlockedNote) {
		t.Errorf("widening reason %q missing:\n%s", wideningBlockedNote, body)
	}
	tag, inside := enclosingFieldset(body, action)
	if !inside {
		t.Fatalf("widening action %q is not inside a fieldset:\n%s", action, body)
	}
	if !strings.Contains(tag, "disabled") {
		t.Errorf("widening action %q sits in %s, want a disabled fieldset:\n%s", action, tag, body)
	}
}

// assertNarrowingEnabled proves action is rendered and not inside a disabled fieldset.
func assertNarrowingEnabled(t *testing.T, body, action string) {
	t.Helper()
	tag, inside := enclosingFieldset(body, action)
	if !inside {
		if !strings.Contains(body, action) {
			t.Errorf("narrowing action %q is missing:\n%s", action, body)
		}
		return
	}
	if strings.Contains(tag, "disabled") {
		t.Errorf("narrowing action %q is inside a disabled fieldset (%s):\n%s", action, tag, body)
	}
}

func TestMaintenanceWidening_DeviceDetail(t *testing.T) {
	h := newDeviceActionsHarness(t, personalNode)
	h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)

	body := h.detail(personalNode.ID)
	// Widening: changing or clearing the expiry is disabled.
	assertWideningDisabled(t, body, `action="/headscale/devices/11/expiry"`)
	assertWideningDisabled(t, body, `action="/headscale/devices/11/expiry/disable"`)
	// Narrowing: expire, rename and delete stay enabled.
	assertNarrowingEnabled(t, body, `action="/headscale/devices/11/expire"`)
	assertNarrowingEnabled(t, body, `action="/headscale/devices/11/rename"`)
	assertNarrowingEnabled(t, body, `href="/headscale/devices/11/delete"`)
}

func TestMaintenanceWidening_DeviceReopen(t *testing.T) {
	h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)
	h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)

	body := h.get("/headscale/devices/31/reopen").Body.String()
	assertWideningDisabled(t, body, `action="/headscale/devices/31/reopen/apply"`)
}

func TestMaintenanceWidening_DeviceTags(t *testing.T) {
	h := newTagsHarness(t)
	h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)

	body := h.get(2).Body.String()
	assertWideningDisabled(t, body, `action="/headscale/devices/2/tags"`)
}

func TestMaintenanceWidening_PreAuthCreate(t *testing.T) {
	h := newKeysHarness(t)
	h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)

	body := h.get("/headscale/keys/preauth").Body.String()
	assertWideningDisabled(t, body, `action="/headscale/keys/preauth/create"`)
}

func TestMaintenanceWidening_PolicySave(t *testing.T) {
	h := newPolicyHarness(t)
	h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
	text := strings.Replace(policyLive, `"dst": ["*:*"]`, `"dst": ["tag:web:443"]`, 1)
	h.ed.previewRes.Current = policyLive
	h.ed.previewRes.Text = text
	h.ed.previewRes.Report = passingReport(text)

	rec := h.post("/headscale/policy/preview", editForm(text))
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d:\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	assertWideningDisabled(t, body, `action="/headscale/policy/save"`)
	// The editor itself is disabled too.
	assertWideningDisabled(t, body, `action="/headscale/policy/preview"`)
}

// With no maintenance bound (or off) the widening controls render unchanged: no fieldset, no note.
func TestMaintenanceWidening_OffLeavesFormsEnabled(t *testing.T) {
	h := newKeysHarness(t)
	h.chain = WithMaintenanceBanner(&fakeHSConfigMaint{st: maintenance.Status{State: maintenance.Off}}, h.chain)

	body := h.get("/headscale/keys/preauth").Body.String()
	if strings.Contains(body, wideningBlockedNote) {
		t.Errorf("off maintenance still shows the widening reason:\n%s", body)
	}
	if _, inside := enclosingFieldset(body, `action="/headscale/keys/preauth/create"`); inside {
		t.Errorf("off maintenance wraps the create form in a fieldset:\n%s", body)
	}
}
