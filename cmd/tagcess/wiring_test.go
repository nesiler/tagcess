package main

import (
	"context"
	"testing"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/web"
)

// fakeGate stands in for *site.Store as the first-import gate.
type fakeGate struct{}

func (fakeGate) FirstImportPending(context.Context) (bool, error) { return false, nil }
func (fakeGate) FirstImportDone(context.Context) (bool, error)    { return false, nil }

// The review handler takes the first-import gate and the seed together or not at all. tagcess
// without a configured seed file (the shipped example leaves it commented out) must therefore pass
// no gate; passing the store anyway made the binary refuse to start (found by the F2-016 e2e run).
func TestFirstImportGate(t *testing.T) {
	var gate web.SiteFirstImportGate = fakeGate{}

	if got := firstImportGate(nil, gate); got != nil {
		t.Errorf("no seed configured: gate = %v, want nil", got)
	}
	if got := firstImportGate(&web.SiteSeedSource{}, gate); got != gate {
		t.Errorf("seed configured: gate = %v, want the store's gate", got)
	}
}

// config.example.yaml and the config reference say an empty dns.resolver means the MagicDNS
// default; the verifier itself treats an empty address as "skip", so the wiring has to apply the
// default or the post-write resolver check is silently off in production.
func TestDNSVerifier(t *testing.T) {
	cases := []struct {
		name, resolver, want string
	}{
		{"empty means the default", "", dns.DefaultResolver},
		{"explicit address is kept", "127.0.0.1:5353", "127.0.0.1:5353"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsVerifier(tc.resolver).Resolver; got != tc.want {
				t.Errorf("Resolver = %q, want %q", got, tc.want)
			}
		})
	}
}
