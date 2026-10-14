//go:build integration

package hostlab_test

import (
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/hostlab"
)

// AC6 (F3b-027): a sqlite3 failure inside patchDB must not leave the lab without a control plane.
// PatchDBErr returns the sqlite3 error so the test can observe the failure and Headscale's state.
func TestHostLab_PatchDBFailureRestartsHeadscale(t *testing.T) {
	lab := hostlab.Start(t)
	if err := lab.PatchDBErr(t, "THIS IS NOT VALID SQL;"); err == nil {
		t.Fatal("PatchDBErr reported success for invalid SQL")
	}
	if got := strings.TrimSpace(lab.Exec(t, "systemctl", "is-active", "headscale.service")); got != "active" {
		t.Errorf("headscale after a failed patch = %q, want active", got)
	}
}
