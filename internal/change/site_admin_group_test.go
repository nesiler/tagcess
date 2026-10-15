package change

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Issue #3: the admin group is a Caddy render input. A change applies only the Caddyfile, from the
// group in force to the new one, and refuses any other drift.

func applyGroup(t *testing.T, h *siteHarness, from, to string) error {
	t.Helper()
	var err error
	_ = WithWriterLock(func() error {
		err = h.sp.ApplyAdminGroup(context.Background(), siteActor, from, to)
		return nil
	})
	return err
}

func onlyCaddyCalls(calls []string) bool {
	return !slices.ContainsFunc(calls, func(c string) bool {
		return strings.HasPrefix(c, "dns") || strings.HasPrefix(c, "uri") || strings.HasPrefix(c, "zitadel")
	})
}

// After a successful group change, an ordinary site apply passes the drift gate, and DNS and
// Zitadel were not touched by the change.
func TestSiteAdminGroup_AppliesOnlyCaddy(t *testing.T) {
	h := newSiteHarness(t)
	h.calls.reset()
	if err := applyGroup(t, h, "", "ops"); err != nil {
		t.Fatalf("group apply: %v", err)
	}
	if !onlyCaddyCalls(h.calls.get()) {
		t.Fatalf("the change touched more than Caddy: %v", h.calls.get())
	}
	if disk, _ := h.caddy.state(); !strings.Contains(disk, "allowed_groups=ops") {
		t.Fatalf("disk Caddyfile lacks the new group:\n%s", disk)
	}
	h.settings.Caddy.AdminGroup = "ops" // the handler stores the setting after the apply
	res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("ordinary apply after the change: %v (%s)", err, res.Status)
	}
}

// A failing Caddy apply leaves the old group on disk and reports the error.
func TestSiteAdminGroup_ApplyFailureKeepsOldGroup(t *testing.T) {
	h := newSiteHarness(t)
	h.caddy.applyErr = errors.New("caddy rejected the config")
	if err := applyGroup(t, h, "", "ops"); err == nil {
		t.Fatal("a failing Caddy apply reported success")
	}
	if disk, _ := h.caddy.state(); strings.Contains(disk, "allowed_groups=ops") {
		t.Fatalf("the new group reached the disk despite the failure:\n%s", disk)
	}
	h.caddy.applyErr = nil
	res, err := h.sp.Submit(context.Background(), addReq(roleSiteRecord("wiki")))
	if err != nil || res.Status != StatusApplied {
		t.Fatalf("ordinary apply after the failed change: %v (%s)", err, res.Status)
	}
}

// An emergency edit of the Caddyfile (a tightened role on an unrelated site) is never overwritten:
// the change is refused, the file keeps the edit and nothing else is applied.
func TestSiteAdminGroup_UnrelatedDriftRefused(t *testing.T) {
	h := newSiteHarness(t)
	disk, _ := h.caddy.state()
	edited := disk + "\n# emergency: wiki closed\n"
	h.caddy.mu.Lock()
	h.caddy.disk = edited
	h.caddy.mu.Unlock()
	h.calls.reset()
	err := applyGroup(t, h, "", "ops")
	if err == nil || !strings.Contains(err.Error(), "farklı") {
		t.Fatalf("drifted Caddyfile accepted: %v", err)
	}
	if now, _ := h.caddy.state(); now != edited {
		t.Fatalf("the emergency edit was overwritten:\n%s", now)
	}
	if got := h.calls.get(); slices.ContainsFunc(got, func(c string) bool { return strings.HasPrefix(c, "caddy") }) || !onlyCaddyCalls(got) {
		t.Fatalf("a refused change wrote something: %v", got)
	}
}
