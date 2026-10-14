package web

import (
	"net/http"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
)

// The manual MagicDNS records samples of the preview server (cmd/tagcess-ui): the records screen
// with the site-derived and manual sets (the empty and refused states included) and the change
// preview (off-tailnet and blocked included). Real routes are used so the sidebar marks the right
// work area.

func init() {
	previewPages = append(previewPages,
		previewPage{"/headscale/dns", "headscale", "MagicDNS kayıtları", func(r *http.Request) templ.Component {
			v := previewDNSRecords()
			v.DryRun = r.URL.Query().Get("dry") == "1"
			switch {
			case r.URL.Query().Get("empty") == "1":
				v.SiteRows, v.ManualRows = nil, nil
			case r.URL.Query().Get("error") == "1":
				v.FormError = "site validation: value: \"not-an-ip\" geçerli bir IPv4 veya IPv6 adresi değil"
			}
			return DNSRecordsPage(v, previewCSRF)
		}},
		previewPage{"/headscale/dns/preview", "headscale", "Elle DNS kaydı preview'u", func(r *http.Request) templ.Component {
			if r.URL.Query().Get("blocked") == "1" {
				return DNSPreviewPage(dnsPreviewView{
					Blocked: "DNS dosyası kayıtlardan farklı: canlı dosyada elle düzenleme var",
				}, previewCSRF)
			}
			v := previewDNSPreview()
			if r.URL.Query().Get("off") == "1" {
				v.OffTailnet = "192.168.1.20"
			}
			return DNSPreviewPage(v, previewCSRF)
		}},
	)
}

func previewDNSRecords() dnsRecordsView {
	return dnsRecordsView{
		SiteRows: []dnsRecordRow{
			{Name: "git.example.com", Type: dns.TypeA, Value: "100.64.0.4", SiteID: 1, SiteLabel: "git.example.com"},
			{Name: "auth.example.com", Type: dns.TypeA, Value: "100.64.0.4", SiteID: 2, SiteLabel: "auth.example.com"},
			{Name: "wiki.example.com", Type: dns.TypeA, Value: "100.64.0.4", SiteID: 4, SiteLabel: "wiki.example.com"},
		},
		ManualRows: []dnsRecordRow{
			{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"},
			{Name: "printer.example.com", Type: dns.TypeA, Value: "192.168.1.20", OffTailnet: true},
		},
	}
}

func previewDNSPreview() dnsPreviewView {
	return dnsPreviewView{
		Diff:    change.SiteDiff{DNS: " old-db.example.com. 300 IN A 100.64.0.9\n+printer.example.com. 300 IN A 192.168.1.20\n"},
		Version: "p1",
		Request: "preview-request",
	}
}
