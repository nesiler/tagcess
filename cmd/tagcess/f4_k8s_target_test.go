package main

import (
	"context"
	"slices"
	"testing"

	"github.com/nesiler/tagcess/internal/site"
)

// G-2 (K-2): a k8s site's backend is measured directly at the ingress Caddy proxies to (the (k8s)
// snippet upstream, Host/SNI = the site host), so a dead backend fails the target check instead of
// hiding behind the gate's login redirect. A URL site keeps its own target; a system-template site
// is not measured (no adapter), so it stays unknown and never shows healthy without data.
func TestF4SubjectsProbeK8sBackendDirectly(t *testing.T) {
	sites := []site.Site{
		{ID: 1, Hosts: []string{"wiki.example.test"}, Kind: site.KindRole, TargetKind: site.TargetK8s},
		{ID: 2, Hosts: []string{"git.example.test"}, Kind: site.KindRole, TargetKind: site.TargetURL, TargetURL: "http://100.64.0.9:8080"},
		{ID: 3, Hosts: []string{"auth.example.test"}, Kind: site.KindSystem, SystemTemplate: site.TemplateZitadel, TargetKind: site.TargetK8s},
	}
	got, err := f4Subjects(f4Fakes{sites: sites}, "100.64.0.1", "", nil)(context.Background())
	if err != nil || len(got) != 3 {
		t.Fatalf("subjects = %+v, %v", got, err)
	}
	byHost := map[string]int{}
	for i, s := range got {
		byHost[s.Host] = i
	}

	k8s := got[byHost["wiki.example.test"]].Target
	if k8s == nil {
		t.Fatal("a k8s site has no target check; a dead backend would raise no alert")
	}
	if k8s.Host != "100.64.0.5" || k8s.Port != 443 || !k8s.TLS || k8s.ServerName != "wiki.example.test" || !k8s.SkipVerify || k8s.Template != "" {
		t.Errorf("k8s target = %+v, want the (k8s) upstream 100.64.0.5:443 over TLS with Host/SNI wiki.example.test, unverified like Caddy", k8s.Request)
	}

	url := got[byHost["git.example.test"]].Target
	if url == nil || url.Host != "100.64.0.9" || url.Port != 8080 || url.SkipVerify {
		t.Errorf("url target = %+v, want the site's own URL, verified", url)
	}

	sys := got[byHost["auth.example.test"]].Target
	if sys == nil || sys.Template != site.TemplateZitadel {
		t.Errorf("system k8s target = %+v, want a template request that is never measured", sys)
	}
}

// G-2: the ingress address Caddy proxies k8s sites to is an approved probe target, without a
// custom allowlist entry.
func TestProbeTargetsIncludeK8sUpstream(t *testing.T) {
	fk := f4Fakes{sites: []site.Site{{Hosts: []string{"app.example.test"}}}}
	list, err := probeTargets{custom: fk, sites: fk, vpnAddr: "100.64.0.1"}.ListTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range list {
		found = found || h == "100.64.0.5"
	}
	if !found {
		t.Errorf("targets = %v, want the k8s upstream 100.64.0.5", list)
	}
}

// The configured (k8s) upstream (sites.k8s_upstream, an existing installation's Traefik internal entrypoint on
// :8443) is what Caddy proxies to, so the target check measures that address, not the default.
func TestF4SubjectsUseConfiguredK8sUpstream(t *testing.T) {
	sites := []site.Site{{ID: 1, Hosts: []string{"wiki.example.test"}, Kind: site.KindRole, TargetKind: site.TargetK8s}}
	got, err := f4Subjects(f4Fakes{sites: sites}, "100.64.0.1", "https://100.64.0.7:8443", nil)(context.Background())
	if err != nil || len(got) != 1 || got[0].Target == nil {
		t.Fatalf("subjects = %+v, %v", got, err)
	}
	if tr := got[0].Target; tr.Host != "100.64.0.7" || tr.Port != 8443 || !tr.TLS {
		t.Errorf("k8s target = %+v, want the configured upstream 100.64.0.7:8443", tr.Request)
	}
	list, err := probeTargets{custom: f4Fakes{}, sites: f4Fakes{sites: sites}, k8sUpstream: "https://100.64.0.7:8443"}.ListTargets(context.Background())
	if err != nil || !slices.Contains(list, "100.64.0.7") {
		t.Errorf("targets = %v, %v; want the configured upstream host", list, err)
	}
}
