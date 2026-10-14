package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
)

type staticRoles []string

func (r staticRoles) ListRoles(context.Context) ([]string, error) { return r, nil }

// F6 parity (M6): the (k8s) upstream the first-import parity is checked with (sites.k8s_upstream) is the one
// every apply renders; unset keeps the render default.
func TestSiteSettingsReader_K8sUpstream(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := site.NewValidator(site.ValidatorConfig{AllowedDomains: []string{"example.test"}, AllowedTargets: []string{"100.64.0.5"}}, staticRoles{"devops"})
	if err != nil {
		t.Fatal(err)
	}
	ss, err := site.New(st.DB(), st.Queries(), v)
	if err != nil {
		t.Fatal(err)
	}
	for _, up := range []string{"", "https://100.64.0.5:8443"} {
		cfg := &config.Config{Sites: config.Sites{ACMEEmail: "admin@example.test", K8sUpstream: up}}
		got, err := siteSettingsReader(st.Queries(), ss, cfg)(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got.Caddy.K8sUpstream != up {
			t.Errorf("k8s_upstream %q reached the render as %q", up, got.Caddy.K8sUpstream)
		}
	}
}
