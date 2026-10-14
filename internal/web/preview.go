package web

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/site"
)

// The preview server (cmd/tagcess-ui) renders pages on fixed sample data, without Zitadel, Headscale
// or a database, so the interface can be looked at and screenshotted in isolation. It is never
// mounted by the tagcess binary. Each page family adds its samples to previewPages.
//
// Query flags on every page: ?dry=1 shows the dry-run pill, ?pending=N the pending-change pill,
// ?err=1 the unreadable status pill.

// previewActor is the signed-in user every preview page shows.
var previewActor = Actor{User: "carol", Email: "carol.example@example.com", Groups: []string{"devops"}}

// previewPage is one sample screen: its path, the work area it belongs to, its title and the body.
type previewPage struct {
	path   string
	active string
	title  string
	body   func(r *http.Request) templ.Component
}

// previewPages are the sample screens. Keep them in sidebar order.
var previewPages = []previewPage{
	{"/_ui", "", "Bileşen galerisi", func(*http.Request) templ.Component { return UIGalleryPage() }},
	{"/sites", "siteler", "Siteler", func(r *http.Request) templ.Component {
		if r.URL.Query().Get("empty") == "1" {
			return SitesPage(nil, previewCSRF)
		}
		return SitesPage(previewSites(), previewCSRF)
	}},
	{"/sites/new", "siteler", "Yeni site", func(*http.Request) templ.Component {
		return SiteFormPage(previewSiteForm(site.Site{Kind: site.KindRole, TargetKind: site.TargetK8s, Cert: "auto", MagicDNS: true}, true, ""), previewCSRF)
	}},
	{"/sites/1/edit", "siteler", "Site", func(r *http.Request) templ.Component {
		s := site.Site{
			ID: 1, Hosts: []string{"git.example.com", "gitlab.example.com"}, Kind: site.KindRole,
			Roles: []string{"devops", "yazilim"}, TargetKind: site.TargetURL, TargetURL: "http://100.64.0.5:8080",
			Cert: "auto", MagicDNS: true, Note: "GitLab", Owner: "devops",
			APIRules:  []site.APIRule{{Type: site.APIRuleHeaderPresent, Value: "Authorization"}},
			Redirects: []site.Redirect{{Source: "/eski", Target: "/yeni", Code: 301}},
			Headers:   []site.Header{{Name: "X-Note", Value: "tagcess"}},
		}
		return SiteFormPage(previewSiteForm(s, false, r.URL.Query().Get("error")), previewCSRF)
	}},
	{"/sites/2/edit", "siteler", "Site", func(*http.Request) templ.Component {
		s := site.Site{ID: 2, Hosts: []string{"auth.example.com"}, Kind: site.KindSystem, SystemTemplate: site.TemplateZitadel,
			SystemConfig: `{"internal_sources":["10.1.0.0/16"],"login_paths":["/ui/v2/login/*"]}`, TargetKind: site.TargetK8s}
		return SiteFormPage(previewSiteForm(s, false, ""), previewCSRF)
	}},
	{"/sites/review", "siteler", "Değişiklik preview'u", func(r *http.Request) templ.Component {
		v := SiteReviewView{
			Op: change.SiteUpdate, Hosts: []string{"git.example.com"}, Order: "Zitadel → Caddy → DNS",
			Warnings: []string{"Rol listesinden yazilim çıkarıldı; bu roldeki kullanıcılar erişimini kaybeder."},
			Target:   TargetChange{Before: "https://100.64.0.5", After: "http://100.64.0.5:8080"},
			Diff: change.SiteDiff{
				Caddy:   "--- a\n+++ b\n@@ -1,4 +1,4 @@\n git.example.com {\n-\treverse_proxy https://100.64.0.5\n+\treverse_proxy http://100.64.0.5:8080\n \timport gate devops\n }\n",
				DNS:     "",
				Zitadel: "+ https://git.example.com/oauth2/callback\n",
			},
			Version: "v1", Request: "r1",
		}
		if r.URL.Query().Get("blocked") == "1" {
			v.Blocked = "site validation: host git.example.com is already used by site 4"
		}
		return SiteReviewPage(v, previewCSRF)
	}},
	{"/sites/result", "siteler", "Değişiklik sonucu", func(r *http.Request) templ.Component {
		v := SiteResultView{ChangeID: 42, Status: change.StatusApplied, Applied: true, Sites: []string{"git.example.com", "wiki.example.com"}}
		switch r.URL.Query().Get("state") {
		case "failed":
			v = SiteResultView{ChangeID: 43, Status: change.StatusFailed, Failed: true, Reason: "caddy: reload: exit status 1", Sites: v.Sites}
		case "dry":
			v = SiteResultView{ChangeID: 44, Status: change.StatusDryRun, DryRun: true, Sites: v.Sites}
		}
		return SiteResultPage(v)
	}},
	{"/sites/first-import", "siteler", "İlk import", func(r *http.Request) templ.Component {
		if r.URL.Query().Get("preview") != "1" {
			return SiteFirstImportPage(SiteFirstImportView{Pending: true}, previewCSRF, false)
		}
		return SiteFirstImportPage(SiteFirstImportView{
			Pending: true, SeedCount: 13, ParityOK: true, Version: "p1",
			ManualDNS: []dns.Record{{Name: "old-db.example.com", Type: "A", Value: "100.64.0.9"}, {Name: "printer.example.com", Type: "A", Value: "192.168.1.20"}},
		}, previewCSRF, true)
	}},
}

const previewCSRF = "preview-csrf-token"

func previewSites() []SiteView {
	at := time.Date(2026, 10, 5, 14, 2, 0, 0, time.UTC)
	return []SiteView{
		{ID: 1, Hosts: []string{"git.example.com", "gitlab.example.com"}, Kind: site.KindRole, Roles: []string{"devops", "yazilim"}, Target: site.TargetURL, TargetURL: "http://100.64.0.5:8080", Health: "sağlıklı", CheckedAt: at, UpdatedAt: at},
		{ID: 2, Hosts: []string{"auth.example.com"}, Kind: site.KindSystem, SystemTemplate: site.TemplateZitadel, Target: site.TargetK8s, Health: "sağlıklı", CheckedAt: at, UpdatedAt: at.Add(-72 * time.Hour)},
		{ID: 3, Hosts: []string{"muhasebe.example.com"}, Kind: site.KindRole, Roles: []string{"muhasebe", "yonetim"}, Target: site.TargetK8s, Health: healthUnknown, UpdatedAt: at.Add(-30 * time.Hour)},
		{ID: 4, Hosts: []string{"wiki.example.com"}, Kind: site.KindOpen, Target: site.TargetK8s, Health: "sorunlu", CheckedAt: at, UpdatedAt: at.Add(-240 * time.Hour)},
	}
}

func previewSiteForm(s site.Site, isNew bool, errMsg string) SiteFormView {
	return newSiteFormView(s, isNew, []string{"devops", "yazilim", "muhasebe", "yonetim"}, []string{"100.64.0.5", "10.0.0.12"}, errMsg)
}

// previewStatus is the top bar status the query flags ask for.
type previewStatus struct{ r *http.Request }

func (p previewStatus) ShellStatus(context.Context) (ShellStatus, error) {
	q := p.r.URL.Query()
	if q.Get("err") == "1" {
		return ShellStatus{}, errPreviewStatus
	}
	n, _ := strconv.Atoi(q.Get("pending"))
	return ShellStatus{DryRun: q.Get("dry") == "1", Pending: n}, nil
}

type previewError string

func (e previewError) Error() string { return string(e) }

const errPreviewStatus = previewError("preview: status unreadable")

// PreviewHandler serves the static assets and the sample screens. Paths without a sample render a
// placeholder inside the shell, so every sidebar link opens.
func PreviewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", Static()))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page := previewPage{path: r.URL.Path, title: "Preview yok", body: func(*http.Request) templ.Component { return previewMissing(r.URL.Path) }}
		if r.URL.Path == "/" {
			page = previewPages[0]
		}
		for _, p := range previewPages {
			if p.path == r.URL.Path {
				page = p
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h := WithShell(previewStatus{r}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = Layout(previewActor, previewCSRF, page.active, page.title, page.body(r)).Render(r.Context(), w)
		}))
		h.ServeHTTP(w, r)
	})
	return mux
}
