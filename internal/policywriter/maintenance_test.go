package policywriter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/policyrev"
)

// assertRefused checks that Save refuses req with "bakım sürüyor" and that nothing was written.
func assertRefused(t *testing.T, e *env, req SaveRequest) {
	t.Helper()
	setsBefore := len(e.hs.Sets())
	revsBefore := len(e.revisions())
	startsBefore := e.count(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply_start'`)
	live := e.hs.Policy()

	_, err := e.w.Save(context.Background(), req)
	if !errors.Is(err, maintenance.ErrMaintenance) {
		t.Fatalf("Save err = %v, want ErrMaintenance", err)
	}
	if !strings.Contains(err.Error(), "bakım sürüyor") {
		t.Errorf("err text = %q, want it to say \"bakım sürüyor\"", err)
	}
	if got := len(e.hs.Sets()); got != setsBefore {
		t.Errorf("SetPolicy calls = %d, want %d (nothing written)", got, setsBefore)
	}
	if got := len(e.revisions()); got != revsBefore {
		t.Errorf("revisions = %d, want %d (a refused save records none)", got, revsBefore)
	}
	if got := e.count(`SELECT count(*) FROM audit_events WHERE event = 'policy.apply_start'`); got != startsBefore {
		t.Errorf("apply_start audit events = %d, want %d", got, startsBefore)
	}
	if e.hs.Policy() != live {
		t.Error("the live policy changed")
	}
}

// F3b-015 AC1: while the maintenance is active a UI save, a rollback and a recovery are refused with
// "bakım sürüyor" before anything is written to Headscale; the preview still works.
func TestPolicyWriter_MaintenanceRefusesSave(t *testing.T) {
	ctx := context.Background()

	t.Run("ui save and rollback, preview still works", func(t *testing.T) {
		e := newEnv(t)
		a, _ := e.twoSaves()
		live := e.hs.Policy()
		if _, err := e.maint.Start(ctx, "req-1", devops); err != nil {
			t.Fatalf("Start maintenance: %v", err)
		}
		edit := strings.Replace(live, "// version B", "// version D", 1)

		assertRefused(t, e, SaveRequest{Actor: devops, Text: edit, BaseHash: policyrev.HashRaw(live)})
		assertRefused(t, e, SaveRequest{Actor: devops, Text: a.Raw, BaseHash: policyrev.HashRaw(live),
			Source: policyrev.SourceRollback, RollbackOf: a.ID, Reason: "geri alma"})

		res, err := e.w.Preview(ctx, SaveRequest{Actor: devops, Text: edit, BaseHash: policyrev.HashRaw(live)})
		if err != nil {
			t.Fatalf("Preview during maintenance: %v", err)
		}
		if !strings.Contains(res.Text, "version D") || !res.Report.Valid() {
			t.Errorf("preview = valid %v, text has the edit %v; want a working preview", res.Report.Valid(), strings.Contains(res.Text, "version D"))
		}
	})

	t.Run("recovery", func(t *testing.T) {
		e := newEnv(t)
		e.uncertainState()
		if _, err := e.maint.Start(ctx, "req-1", devops); err != nil {
			t.Fatalf("Start maintenance: %v", err)
		}
		assertRefused(t, e, e.recoverReq())

		// The recovery preview stays available too.
		if _, err := e.w.Preview(ctx, e.recoverReq()); err != nil {
			t.Fatalf("recovery Preview during maintenance: %v", err)
		}
	})
}

// Once the maintenance is off again the same save goes through.
func TestPolicyWriter_MaintenanceOffSavesAgain(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if _, err := e.maint.Start(ctx, "req-1", devops); err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(e.live, "// everyone reaches the gate", "// edited", 1)
	if _, err := e.save(text); !errors.Is(err, maintenance.ErrMaintenance) {
		t.Fatalf("save err = %v, want ErrMaintenance", err)
	}
	if _, err := e.maint.ToReconcilePending(ctx, "req-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.save(text); !errors.Is(err, maintenance.ErrMaintenance) {
		t.Fatalf("save during reconcile_pending err = %v, want ErrMaintenance", err)
	}
	if err := e.maint.Off(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.save(text); err != nil {
		t.Fatalf("save after maintenance: %v", err)
	}
}
