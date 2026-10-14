package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/headscale/admin"
)

// AC8 (F3b-027): every screen wrapped in MaintenanceWideningGuard must render its widening forms
// inside a disabled fieldset with the reason while a host config change is open. The table has one
// row per wrapped call site, so a new guard without a covered row is visible.
func TestMaintenanceWidening_AllWrappedScreens(t *testing.T) {
	cases := []struct {
		name    string
		body    func(t *testing.T) string
		actions []string
	}{
		{
			name: "device detail expiry",
			body: func(t *testing.T) string {
				h := newDeviceActionsHarness(t, personalNode)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.detail(personalNode.ID)
			},
			actions: []string{`action="/headscale/devices/11/expiry"`, `action="/headscale/devices/11/expiry/disable"`},
		},
		{
			name: "device reopen",
			body: func(t *testing.T) string {
				h := newReopenHarness(t, []admin.AdminNode{expiredPersonalNode}, ownerUsers)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get("/headscale/devices/31/reopen").Body.String()
			},
			actions: []string{`action="/headscale/devices/31/reopen/apply"`},
		},
		{
			name: "device tags edit",
			body: func(t *testing.T) string {
				h := newTagsHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get(2).Body.String() // node 2 is already tagged: the edit form
			},
			actions: []string{`action="/headscale/devices/2/tags"`},
		},
		{
			name: "device tags warn",
			body: func(t *testing.T) string {
				h := newTagsHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get(1).Body.String() // node 1 is personal: the irreversible-conversion warning
			},
			actions: []string{`action="/headscale/devices/1/tags"`},
		},
		{
			name: "device tags confirm",
			body: func(t *testing.T) string {
				h := newTagsHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				f := h.form(1, "tag:web")
				f.Set("confirm_name", "alice-laptop")
				f.Set("confirm", "on")
				rec := h.post(1, f) // step 1 renders the final confirmation step
				if rec.Code != http.StatusOK {
					t.Fatalf("tags step 1 = %d: %s", rec.Code, rec.Body)
				}
				return rec.Body.String()
			},
			actions: []string{`action="/headscale/devices/1/tags"`},
		},
		{
			name: "device routes",
			body: func(t *testing.T) string {
				h := newRoutesHarness(t, []admin.AdminNode{routeNode(10)}, "", nil)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get(t, "/headscale/devices/10/routes", "devops").Body.String()
			},
			actions: []string{`action="/headscale/devices/10/routes"`},
		},
		{
			name: "pre-auth create",
			body: func(t *testing.T) string {
				h := newKeysHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get("/headscale/keys/preauth").Body.String()
			},
			actions: []string{`action="/headscale/keys/preauth/create"`},
		},
		{
			name: "personal key create",
			body: func(t *testing.T) string {
				h := newPersonalHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get("/headscale/keys/personal").Body.String()
			},
			actions: []string{`action="/headscale/keys/personal"`},
		},
		{
			name: "manual dns add",
			body: func(t *testing.T) string {
				h := newDNSRecordsHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get(t, "/headscale/dns").Body.String()
			},
			actions: []string{`action="/headscale/dns/preview"`},
		},
		{
			name: "manual dns edit",
			body: func(t *testing.T) string {
				h := newDNSRecordsHarness(t)
				h.manual.recs = []dns.Record{dnsManualRecord}
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get(t, "/headscale/dns").Body.String()
			},
			actions: []string{`action="/headscale/dns/preview"`},
		},
		{
			name: "manual dns approve",
			body: func(t *testing.T) string {
				h := newDNSRecordsHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				h.reviewer.previewPlans = []change.SitePlan{{
					Op:   change.SiteManualDNS,
					Diff: change.SiteDiff{DNS: "+" + dnsManualRecord.Name + " " + dnsManualRecord.Value},
				}}
				rec := h.post(t, "/headscale/dns/preview", url.Values{
					"action": {"add"}, "name": {dnsManualRecord.Name}, "value": {dnsManualRecord.Value},
				})
				if rec.Code != http.StatusOK {
					t.Fatalf("dns preview = %d: %s", rec.Code, rec.Body)
				}
				return rec.Body.String()
			},
			actions: []string{`action="/headscale/dns/approve"`},
		},
		{
			name: "policy editor and save",
			body: func(t *testing.T) string {
				h := newPolicyHarness(t)
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				text := strings.Replace(policyLive, `"dst": ["*:*"]`, `"dst": ["tag:web:443"]`, 1)
				h.ed.previewRes.Current = policyLive
				h.ed.previewRes.Text = text
				h.ed.previewRes.Report = passingReport(text)
				rec := h.post("/headscale/policy/preview", editForm(text))
				if rec.Code != http.StatusOK {
					t.Fatalf("preview = %d: %s", rec.Code, rec.Body)
				}
				return rec.Body.String()
			},
			actions: []string{`action="/headscale/policy/preview"`, `action="/headscale/policy/save"`},
		},
		{
			name: "policy rules card",
			body: func(t *testing.T) string {
				h := newPolicyFormsHarness(t, policyLive, &fakeAdminNodes{}, &fakeProtectedTags{})
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get("/headscale/policy").Body.String()
			},
			actions: []string{`formaction="/headscale/policy/rules/add"`},
		},
		{
			name: "policy tags card",
			body: func(t *testing.T) string {
				h := newPolicyFormsHarness(t, policyRich(t), &fakeAdminNodes{}, &fakeProtectedTags{})
				h.chain = WithMaintenanceBanner(wideningMaint(), h.chain)
				return h.get("/headscale/policy").Body.String()
			},
			actions: []string{`formaction="/headscale/policy/tags/set"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body(t)
			for _, action := range tc.actions {
				assertWideningDisabled(t, body, action)
			}
		})
	}
}
