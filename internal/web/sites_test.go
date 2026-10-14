package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/site"
)

// fakeSiteLister returns a fixed site set.
type fakeSiteLister struct {
	sites []site.Site
	err   error
}

func (f fakeSiteLister) ListSites(context.Context) ([]site.Site, error) { return f.sites, f.err }

// fakeSiteHealth knows the status of only the sites it lists; every other site has no data.
type fakeSiteHealth struct{ statuses map[int64]string }

func (f fakeSiteHealth) Health(_ context.Context, s site.Site) (SiteHealth, bool) {
	st, ok := f.statuses[s.ID]
	return SiteHealth{Status: st}, ok
}

// newSitesHarness wires the site list behind the production identity chain.
func newSitesHarness(t *testing.T, lister SiteLister, health SiteHealthReader) http.Handler {
	t.Helper()
	h, err := NewSitesHandler(SitesHandlerConfig{Lister: lister, Health: health, CSRF: testCSRF(t)})
	if err != nil {
		t.Fatalf("NewSitesHandler: %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return RequireDevops(mux)
}

// getSites issues an authenticated GET and returns the page body.
func getSites(t *testing.T, h http.Handler, target string) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", target, rec.Code)
	}
	return rec.Body.String()
}

// rowContaining returns the table row (a substring between <tr...> and </tr>) that holds marker.
func rowContaining(t *testing.T, body, marker string) string {
	t.Helper()
	for _, row := range strings.Split(body, "<tr") {
		if strings.Contains(row, marker) {
			return row
		}
	}
	t.Fatalf("no table row contains %q", marker)
	return ""
}

// AC1: the list shows each site's name (first host), kind, role, target, health and last change.
func TestSitesPage_ListFields(t *testing.T) {
	sites := []site.Site{{
		ID:         3,
		Hosts:      []string{"projects.lab.example.com", "projects2.lab.example.com"},
		Kind:       site.KindRole,
		Roles:      []string{"devops", "ops"},
		TargetKind: site.TargetK8s,
		UpdatedAt:  time.Date(2026, 10, 1, 12, 34, 56, 0, time.UTC),
	}}
	body := getSites(t, newSitesHarness(t, fakeSiteLister{sites: sites}, nil), "/sites")

	for _, want := range []string{
		"projects.lab.example.com", "rol", "devops", "ops", "k8s",
		healthUnknown, "2026-10-01 12:34",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
}

// AC2: with no health data a site shows "bilinmiyor" and is never shown as healthy; a site whose
// health is known shows its status. The unknown row must not carry the healthy status.
func TestSitesPage_UnknownHealth(t *testing.T) {
	sites := []site.Site{
		{ID: 1, Hosts: []string{"known.lab.example.com"}, Kind: site.KindOpen, OpenReason: site.OpenReasonIntentional, TargetKind: site.TargetK8s},
		{ID: 2, Hosts: []string{"unknown.lab.example.com"}, Kind: site.KindOpen, OpenReason: site.OpenReasonIntentional, TargetKind: site.TargetK8s},
	}
	health := fakeSiteHealth{statuses: map[int64]string{1: "sağlıklı"}}
	body := getSites(t, newSitesHarness(t, fakeSiteLister{sites: sites}, health), "/sites")

	if !strings.Contains(rowContaining(t, body, "known.lab.example.com"), "sağlıklı") {
		t.Error("the known site does not show its health status")
	}
	unknownRow := rowContaining(t, body, "unknown.lab.example.com")
	if !strings.Contains(unknownRow, healthUnknown) {
		t.Errorf("the site without health data does not show %q: %q", healthUnknown, unknownRow)
	}
	if strings.Contains(unknownRow, "sağlıklı") {
		t.Errorf("a site without health data was shown as healthy: %q", unknownRow)
	}
}

// F5 C1: a system site's target is the template's own (the stored k8s kind is only a placeholder the
// renderer requires), so the list must not label it "k8s"; a role site on k8s keeps the label.
func TestSitesPage_SystemSiteTargetIsNotK8s(t *testing.T) {
	sites := []site.Site{
		{ID: 1, Hosts: []string{"auth.lab.example.com"}, Kind: site.KindSystem, SystemTemplate: site.TemplateZitadel, TargetKind: site.TargetK8s},
		{ID: 2, Hosts: []string{"books.lab.example.com"}, Kind: site.KindRole, Roles: []string{"developer"}, TargetKind: site.TargetK8s},
	}
	body := getSites(t, newSitesHarness(t, fakeSiteLister{sites: sites}, nil), "/sites")
	system := rowContaining(t, body, "auth.lab.example.com")
	if strings.Contains(system, ">k8s<") || !strings.Contains(system, "şablonunun kendi hedefi") {
		t.Errorf("system site target = %q, want the template's own target and no k8s label", system)
	}
	if !strings.Contains(rowContaining(t, body, "books.lab.example.com"), ">k8s<") {
		t.Error("a role site on k8s lost its k8s label")
	}
}
