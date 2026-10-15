package change

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Issue #3 (review round 1): the admin group is a Caddy render input. A change applies the system
// site with the new group under the writer lock; later ordinary applies must not see drift.

func resyncLocked(t *testing.T, h *siteHarness) (SiteResult, error) {
	t.Helper()
	var res SiteResult
	var err error
	_ = WithWriterLock(func() error {
		res, err = h.sp.ResyncLocked(context.Background(), siteActor)
		return nil
	})
	return res, err
}

// After a successful group change, an ordinary site apply passes the drift gate.
func TestSiteAdminGroup_SiteApplyAfterChange(t *testing.T) {
	h := newSiteHarness(t)
	h.settings.Caddy.AdminGroup = "ops"
	res, err := resyncLocked(t, h)
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("group resync: %v (%s)", err, res.Status)
	}
	if disk, _ := h.caddy.state(); !strings.Contains(disk, "allowed_groups=ops") {
		t.Fatalf("disk Caddyfile lacks the new group:\n%s", disk)
	}
	res, err = h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("ordinary apply after the change: %v (%s)", err, res.Status)
	}
}

// A failed Caddy apply leaves the old group on disk; with the setting restored, ordinary applies
// still pass (no drift) and the new group never reached the disk.
func TestSiteAdminGroup_ApplyFailureKeepsOldGroup(t *testing.T) {
	h := newSiteHarness(t)
	h.caddy.applyErr = errors.New("caddy rejected the config")
	h.settings.Caddy.AdminGroup = "ops"
	res, err := resyncLocked(t, h)
	if err == nil && res.Status == StatusApplied {
		t.Fatal("a failing Caddy apply reported applied")
	}
	if disk, _ := h.caddy.state(); strings.Contains(disk, "allowed_groups=ops") {
		t.Fatalf("the new group reached the disk despite the failure:\n%s", disk)
	}
	// The handler restores the stored setting; the old group renders the baseline again.
	h.caddy.applyErr = nil
	h.settings.Caddy.AdminGroup = ""
	res, err = h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("ordinary apply after the failed change: %v (%s)", err, res.Status)
	}
}
