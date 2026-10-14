package web

import (
	"context"
	"io"
	"net/http"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/hostapply"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
)

// Preview samples for the Headscale settings screen and the H-07 config screen (F3b-020). The
// config sample covers the read-only and patch states; the settings sample covers the defaults,
// the stored values and the confirmation page of a weakening change.

func init() {
	previewPages = append(previewPages,
		previewPage{"/headscale/settings", "headscale", "Headscale ayarları", func(r *http.Request) templ.Component {
			v := hsSettingsView{
				Tags: []string{"tag:vpn-server", "tag:k8s"},
				Locked: hsLockedFields{
					DevopsGroup: "group:devops", ServerTag: "tag:vpn-server", UIPort: "443", K8sTag: "tag:k8s",
					WebhookPort: "9000", SSHSrc: "group:devops", SSHDst: "tag:vpn-server, tag:k8s", SSHPort: "22",
				},
				ConfigWrite: true, ConfigWriteStored: true,
			}
			if r.URL.Query().Get("default") == "1" {
				v.TagsDefault = true
				v.LockedDefault = true
				v.ConfigWrite, v.ConfigWriteStored = false, false
			}
			if r.URL.Query().Get("empty") == "1" {
				v.Tags = nil
			}
			if r.URL.Query().Get("err") == "1" {
				v.Error = "ayar okunamadı veya bozuk; değişiklik yapılmadı: settings table locked"
			}
			v.DryRun = r.URL.Query().Get("dry") == "1"
			return HSSettingsPage(v, previewCSRF)
		}},
		previewPage{"/headscale/config", "headscale", "Headscale config", func(r *http.Request) templ.Component {
			v := hsConfigView{
				WriteEnabled: true, WriteStored: true,
				Current:       []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper},
				BaseRev:       "740a57b59f387810",
				HostRequestID: "0b7f4c1e-52d3-4a8e-9c61-3f2d8a7e5b10",
				HostState:     hostpatch.StateSucceeded, HostPhase: hostpatch.PhaseCheck,
				MaintState: maintenance.Off,
			}
			if r.URL.Query().Get("preview") == "1" {
				v.Preview = &hostapply.Preview{
					Current: []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper},
					Wanted:  []string{hostpatch.GroupDevops, hostpatch.GroupStandart},
					Added:   []string{hostpatch.GroupStandart},
					Removed: []string{hostpatch.GroupDeveloper},
					BaseRev: "740a57b59f387810",
				}
				v.Notice = "fark hazır; apply etmek için açık onay gerekir"
			}
			if r.URL.Query().Get("ro") == "1" {
				v.WriteEnabled, v.WriteStored = false, false
			}
			if r.URL.Query().Get("err") == "1" {
				v.Error = "zitadel: list grants: unavailable"
				v.Unknowns = []hostapply.Unknown{{Kind: "policy", Detail: "son policy yazımı belirsiz"}}
			}
			if r.URL.Query().Get("maint") == "1" {
				v.MaintState = maintenance.Active
				v.MaintID = "0b7f4c1e-52d3"
				v.MaintElapsed = "4 dk 12 sn"
			}
			if r.URL.Query().Get("fail") == "1" {
				v.MaintState = maintenance.Active
				v.MaintID = "0b7f4c1e-52d3"
				v.LastResult = &hsConfigLastResult{
					Status: string(hostpatch.StateFailed), Phase: string(hostpatch.PhaseCheck),
					ErrorCode: "configtest_failed", FinishedAt: "2026-10-02T09:00:00Z",
				}
			}
			v.DryRun = r.URL.Query().Get("dry") == "1"
			page := HSConfigPage(v, previewCSRF)
			if v.MaintState == maintenance.Active || v.MaintState == maintenance.ReconcilePending {
				return withPreviewMaint(previewMaint{st: maintenance.Status{State: v.MaintState, RequestID: v.MaintID, Elapsed: 252 * 1e9}}, page)
			}
			return page
		}},
		previewPage{"/headscale/settings/confirm", "headscale", "Korumayı zayıflatan değişiklik", func(*http.Request) templ.Component {
			return HSSettingsConfirmPage(hsConfirmView{
				Action:  "/headscale/settings/config-write",
				Heading: "Config yazma switch'i açılsın mı?",
				Warning: "Bu değişiklik Headscale config yazmasını açar (korumayı zayıflatır):",
				Reasons: []string{
					"Açıkken devops, allowed_groups değişikliğini onaylayıp Headscale config'ini tagcess üzerinden yazabilir.",
					"Bu switch üretimde yalnız lab groups-claim kabul/ret matrisi geçtikten sonra açılmalıdır.",
				},
				Fields:       []hsField{{Name: "enabled", Value: "true"}},
				Base:         "abc12345",
				ConfirmLabel: "Yazma switch'ini aç",
			}, previewCSRF)
		}},
	)
}

// previewMaint is the fixed maintenance row the preview samples show in the band.
type previewMaint struct{ st maintenance.Status }

func (m previewMaint) Get(context.Context) (maintenance.Status, error) { return m.st, nil }

// withPreviewMaint binds a fixed maintenance row to the context so the Headscale band renders it.
func withPreviewMaint(src MaintenanceBannerSource, c templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		return c.Render(context.WithValue(ctx, maintenanceBannerKey{}, src), w)
	})
}
