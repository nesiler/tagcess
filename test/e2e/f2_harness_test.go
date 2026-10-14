//go:build integration

// AC2 for F2-001: the shared F2 fixture (test/compose/f2) cleans up its throwaway Caddy/DNS/site
// workspace and leaves the shared lab record exactly as it found it. Two consecutive runs must both
// end clean, so a later F2 test can rely on the fixture being re-runnable. Each run returns from its
// subtest without calling Cleanup, and the parent then checks the workspace is gone, so the test
// proves the automatic t.Cleanup in f2.New is what removes it. It assumes `make lab-up` has run; run
// it with `make e2e` or `go test -tags=integration -run TestF2Harness_Cleanup ./test/e2e/...`.
//
// The lab check is deliberately ordered after t.Run returns. By then the fixture's t.Cleanup has run
// and its gRPC client is closed, so the parent re-reads the shared app with a brand-new read-only
// fixture. Comparing that against the pre-run baseline proves neither the run nor its cleanup wrote
// to the shared app. A read taken inside the subtest (before cleanup) could not prove this.
//
// The shared lab record is read-only here: writing the seeded app's redirect URIs is F2-009/F2-010,
// not this fixture (Codex decision, F2-001).
package e2e_test

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/nesiler/tagcess/test/compose/f2"
	"github.com/nesiler/tagcess/test/compose/seed"
)

func TestF2Harness_Cleanup(t *testing.T) {
	// Pre-run baseline: the shared lab record before either run touches anything. Its own read-only
	// handle stays open for the whole test.
	baseline := f2.New(t).SharedAppURIs(seed.OAuth2ProxyAppName)
	if len(baseline) == 0 {
		t.Fatal("the seeded oauth2-proxy app has no redirect URIs; cannot verify the lab was left alone")
	}

	for run := 1; run <= 2; run++ {
		// The subtest deliberately never calls f.Cleanup(). Everything it produced must be gone by
		// the time t.Run returns, because f2.New registered the cleanup with t.Cleanup. The parent
		// checks that here, so deleting the t.Cleanup call in the fixture makes this test fail.
		var (
			workspace string
			artifacts []string
		)
		t.Run(fmt.Sprintf("run%d", run), func(t *testing.T) {
			f := f2.New(t)

			caddyfile, dnsFile, siteData := f.WriteArtifacts()
			workspace = f.Dir()
			artifacts = []string{caddyfile, dnsFile, siteData}
			for _, path := range artifacts {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("fixture did not create %s: %v", path, err)
				}
			}
		})

		// t.Run has returned, so the fixture's automatic t.Cleanup has already run: the workspace is
		// gone and the subtest's gRPC client is closed.
		for _, path := range append([]string{workspace}, artifacts...) {
			if path == "" {
				t.Fatalf("run%d: the subtest failed before the fixture created its workspace", run)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("run%d: %s still exists after the subtest returned (stat err = %v); the fixture's automatic cleanup did not run", run, path, err)
			}
		}

		// Read the shared lab again with a fresh read-only fixture, strictly after cleanup. If the run
		// or its cleanup had written the shared app, this list would differ from the pre-run baseline.
		after := f2.New(t).SharedAppURIs(seed.OAuth2ProxyAppName)
		if !sameURIs(baseline, after) {
			t.Fatalf("run%d: the shared lab record changed after the fixture's cleanup:\nbaseline %v\nafter    %v", run, baseline, after)
		}
	}
}

// sameURIs compares two URI lists as sets: the fixture never writes the list, so a server-side
// reordering must not be mistaken for a change.
func sameURIs(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
