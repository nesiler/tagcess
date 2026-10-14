package hostapply

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
)

// closeService is the service as production wires it for F3b-019: no OnSucceeded override, so a
// recorded success moves the maintenance to reconcile_pending itself, and every reconcile request
// is counted.
func (e *env) closeService(t *testing.T, reconciles *int) *Service {
	t.Helper()
	svc, err := NewService(Config{
		Host:        e.host,
		Maintenance: e.maint,
		Audit:       audit.New(e.st.Queries()),
		Settings:    e.st.Queries(),
		Unknowns:    e.unknowns,
		Log:         slog.New(slog.NewTextHandler(e.logs, nil)),
		Now:         e.clock.now,
		NewID: func() string {
			id := e.ids[0]
			e.ids = e.ids[1:]
			return id
		},
		Reconcile: func() { *reconciles++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// openMaintenance starts a request (idA) so the maintenance is active.
func (e *env) openMaintenance(t *testing.T, svc *Service) {
	t.Helper()
	if _, err := svc.Apply(context.Background(), e.req(t, "devops", "developer")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func (e *env) closeReq() CloseRequest {
	return CloseRequest{Actor: "devops@example.com", RequestID: idA, Confirm: true}
}

// F3b-019 AC1: the recorded success moves the maintenance to reconcile_pending and asks for a
// reconcile; widening admin writes stay refused, only the reconcile may write.
func TestConfigService_SuccessReconcilesFirst(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var reconciles int
	svc := e.closeService(t, &reconciles)
	e.openMaintenance(t, svc)

	if _, err := svc.Poll(ctx); err != nil {
		t.Fatalf("Poll without result: %v", err)
	}
	if st := e.maintState(t); st.State != maintenance.Active || reconciles != 0 {
		t.Fatalf("before the result: state=%s reconciles=%d, want active/0", st.State, reconciles)
	}

	e.terminal(t, idA, hostpatch.StateSucceeded)
	pr, err := svc.Poll(ctx)
	if err != nil || !pr.Recorded {
		t.Fatalf("Poll = %+v, %v; want the result recorded", pr, err)
	}
	st := e.maintState(t)
	if st.State != maintenance.ReconcilePending || st.RequestID != idA {
		t.Fatalf("maintenance = %s/%s, want reconcile_pending/%s", st.State, st.RequestID, idA)
	}
	if reconciles != 1 {
		t.Errorf("reconcile requests = %d, want 1", reconciles)
	}
	if err := e.maint.CheckWidening(ctx, maintenance.SourceAdmin); !errors.Is(err, maintenance.ErrMaintenance) {
		t.Errorf("admin widening in reconcile_pending = %v, want ErrMaintenance", err)
	}
	if err := e.maint.CheckWidening(ctx, maintenance.SourceSync); err != nil {
		t.Errorf("sync widening in reconcile_pending = %v, want nil", err)
	}

	// The transition happens once; a later poll neither re-triggers nor moves anything.
	if _, err := svc.Poll(ctx); err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if reconciles != 1 {
		t.Errorf("reconcile requests after a second Poll = %d, want still 1", reconciles)
	}
	// A new config patch waits for the close, like after a success today.
	if _, err := svc.Apply(ctx, ApplyRequest{Actor: "devops@example.com", Wanted: []string{"devops"}, BaseRev: e.baseRev(t, devopsOnly)}); err == nil {
		t.Error("Apply in reconcile_pending succeeded, want a refusal")
	}
}

// A failed or interrupted result never starts the close: the flag stays open.
func TestConfigService_FailureDoesNotReconcile(t *testing.T) {
	for _, state := range []hostpatch.State{hostpatch.StateFailed, hostpatch.StateInterrupted} {
		t.Run(string(state), func(t *testing.T) {
			e := newEnv(t)
			var reconciles int
			svc := e.closeService(t, &reconciles)
			e.openMaintenance(t, svc)
			e.terminal(t, idA, state)
			if _, err := svc.Poll(context.Background()); err != nil {
				t.Fatalf("Poll: %v", err)
			}
			if st := e.maintState(t); st.State != maintenance.Active || reconciles != 0 {
				t.Fatalf("state=%s reconciles=%d, want active/0", st.State, reconciles)
			}
		})
	}
}

// F3b-019 AC4: a confirmed close with the fresh request ID records the host status in the audit
// log, writes no request and no config, and hands over to the reconcile.
func TestCloseMaintenance_ConfirmedAudited(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var reconciles int
	svc := e.closeService(t, &reconciles)
	e.openMaintenance(t, svc)
	e.terminal(t, idA, hostpatch.StateFailed)
	filesBefore := e.requestFiles(t)

	res, err := svc.CloseMaintenance(ctx, e.closeReq())
	if err != nil {
		t.Fatalf("CloseMaintenance: %v", err)
	}
	if res.HostRequestID != idA || res.HostState != hostpatch.StateFailed || res.Warning != "" {
		t.Errorf("result = %+v, want the failed host status without a warning", res)
	}
	if st := e.maintState(t); st.State != maintenance.ReconcilePending || st.RequestID != idA {
		t.Errorf("maintenance = %s/%s, want reconcile_pending/%s", st.State, st.RequestID, idA)
	}
	if reconciles != 1 {
		t.Errorf("reconcile requests = %d, want 1", reconciles)
	}
	if !slices.Equal(e.requestFiles(t), filesBefore) {
		t.Errorf("requests dir changed: %v -> %v", filesBefore, e.requestFiles(t))
	}
	var actor, target, result, diff string
	if err := e.st.DB().QueryRowContext(ctx,
		`SELECT actor, target, result, diff FROM audit_events WHERE event = ?`, EventCloseRequested,
	).Scan(&actor, &target, &result, &diff); err != nil {
		t.Fatalf("close audit row: %v", err)
	}
	if actor != "devops@example.com" || target != "request:"+idA {
		t.Errorf("audit actor/target = %q/%q", actor, target)
	}
	for _, want := range []string{"host_request_id", idA, "host_state", "failed"} {
		if !strings.Contains(diff, want) {
			t.Errorf("audit diff %s lacks %q", diff, want)
		}
	}
}

// F3b-019 AC5: no confirmation, no actor, a stale or empty request ID, or a maintenance that is not
// open all refuse and change nothing.
func TestCloseMaintenance_RequiresConfirmAndFreshID(t *testing.T) {
	tests := []struct {
		name string
		mut  func(r *CloseRequest)
		want error
	}{
		{"no confirmation", func(r *CloseRequest) { r.Confirm = false }, ErrConfirmRequired},
		{"no actor", func(r *CloseRequest) { r.Actor = " " }, ErrActorRequired},
		{"stale request ID", func(r *CloseRequest) { r.RequestID = idB }, ErrStaleRequestID},
		{"empty request ID", func(r *CloseRequest) { r.RequestID = "" }, ErrStaleRequestID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			var reconciles int
			svc := e.closeService(t, &reconciles)
			e.openMaintenance(t, svc)
			req := e.closeReq()
			tc.mut(&req)

			if _, err := svc.CloseMaintenance(context.Background(), req); !errors.Is(err, tc.want) {
				t.Fatalf("CloseMaintenance = %v, want %v", err, tc.want)
			}
			if st := e.maintState(t); st.State != maintenance.Active || st.RequestID != idA {
				t.Errorf("maintenance = %s/%s, want untouched active/%s", st.State, st.RequestID, idA)
			}
			if reconciles != 0 || e.countAudit(t, EventCloseRequested) != 0 {
				t.Errorf("reconciles=%d close audits=%d, want 0/0", reconciles, e.countAudit(t, EventCloseRequested))
			}
		})
	}

	t.Run("maintenance off", func(t *testing.T) {
		e := newEnv(t)
		var reconciles int
		svc := e.closeService(t, &reconciles)
		if _, err := svc.CloseMaintenance(context.Background(), e.closeReq()); !errors.Is(err, ErrNotOpen) {
			t.Fatalf("CloseMaintenance while off = %v, want ErrNotOpen", err)
		}
		if reconciles != 0 {
			t.Errorf("reconcile requests = %d, want 0", reconciles)
		}
	})

	t.Run("already reconcile_pending", func(t *testing.T) {
		e := newEnv(t)
		var reconciles int
		svc := e.closeService(t, &reconciles)
		e.openMaintenance(t, svc)
		if _, err := svc.CloseMaintenance(context.Background(), e.closeReq()); err != nil {
			t.Fatalf("first close: %v", err)
		}
		if _, err := svc.CloseMaintenance(context.Background(), e.closeReq()); !errors.Is(err, ErrNotOpen) {
			t.Fatalf("second close = %v, want ErrNotOpen", err)
		}
		if reconciles != 1 || e.countAudit(t, EventCloseRequested) != 1 {
			t.Errorf("reconciles=%d close audits=%d, want 1/1", reconciles, e.countAudit(t, EventCloseRequested))
		}
	})
}

// F3b-019 AC6: while the helper reports applying, the close is allowed with explicit confirmation
// and the result carries the warning.
func TestCloseMaintenance_ApplyingWarns(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var reconciles int
	svc := e.closeService(t, &reconciles)
	e.openMaintenance(t, svc)
	e.writeStatus(t, devopsOnly, idA, hostpatch.StateApplying)

	res, err := svc.CloseMaintenance(ctx, e.closeReq())
	if err != nil {
		t.Fatalf("CloseMaintenance: %v", err)
	}
	if res.HostState != hostpatch.StateApplying || res.Warning == "" {
		t.Errorf("result = %+v, want the applying state with a warning", res)
	}
	if st := e.maintState(t); st.State != maintenance.ReconcilePending || reconciles != 1 {
		t.Errorf("state=%s reconciles=%d, want reconcile_pending/1", st.State, reconciles)
	}
	var diff string
	if err := e.st.DB().QueryRowContext(ctx, `SELECT diff FROM audit_events WHERE event = ?`, EventCloseRequested).Scan(&diff); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "applying") {
		t.Errorf("audit diff %s lacks the applying host state", diff)
	}
}

// An unreadable status.json is not a way to lock the operator in: the close still works, with a
// warning, and the audit says the status could not be read.
func TestCloseMaintenance_UnreadableStatusWarns(t *testing.T) {
	e := newEnv(t)
	var reconciles int
	svc := e.closeService(t, &reconciles)
	e.openMaintenance(t, svc)
	if err := os.Remove(e.resDir + "/status.json"); err != nil {
		t.Fatal(err)
	}

	res, err := svc.CloseMaintenance(context.Background(), e.closeReq())
	if err != nil {
		t.Fatalf("CloseMaintenance: %v", err)
	}
	if res.Warning == "" || res.HostState != "" {
		t.Errorf("result = %+v, want a warning and no host state", res)
	}
	if st := e.maintState(t); st.State != maintenance.ReconcilePending {
		t.Errorf("state = %s, want reconcile_pending", st.State)
	}
}

// The success audit is written after the active -> reconcile_pending transition (F3b-027 AC4): when
// it cannot be written the close already moved the flag and the error is reported.
func TestCloseMaintenance_AuditFailureAfterTransition(t *testing.T) {
	e := newEnv(t)
	var reconciles int
	svc := e.closeService(t, &reconciles)
	e.openMaintenance(t, svc)
	svc.Audit = failingAudit{}

	if _, err := svc.CloseMaintenance(context.Background(), e.closeReq()); !errors.Is(err, ErrAudit) {
		t.Fatalf("CloseMaintenance = %v, want ErrAudit", err)
	}
	if st := e.maintState(t); st.State != maintenance.ReconcilePending || reconciles != 0 {
		t.Errorf("state=%s reconciles=%d, want reconcile_pending/0", st.State, reconciles)
	}
}

// AC4 (F3b-027): a close whose transition does not happen writes no success audit; the flag stays
// active and can be retried.
func TestCloseMaintenance_NoAuditWhenTransitionFails(t *testing.T) {
	e := newEnv(t)
	var reconciles int
	svc := e.closeService(t, &reconciles)
	e.openMaintenance(t, svc)
	svc.Maintenance = failingTransition{Flag: svc.Maintenance}

	if _, err := svc.CloseMaintenance(context.Background(), e.closeReq()); err == nil {
		t.Fatal("CloseMaintenance succeeded, want a transition error")
	}
	if st := e.maintState(t); st.State != maintenance.Active {
		t.Errorf("state = %s, want the active flag kept for a retry", st.State)
	}
	if n := e.countAudit(t, EventCloseRequested); n != 0 {
		t.Errorf("close audits = %d, want 0 when the transition fails", n)
	}
	if reconciles != 0 {
		t.Errorf("reconciles = %d, want 0", reconciles)
	}
}

type failingAudit struct{}

func (failingAudit) Write(context.Context, audit.Entry) (audit.Event, error) {
	return audit.Event{}, errors.New("disk full")
}

// failingTransition delegates to the real flag but refuses the close's transition.
type failingTransition struct{ Flag }

func (failingTransition) ToReconcilePending(context.Context, string) (maintenance.Status, error) {
	return maintenance.Status{}, errors.New("transition failed")
}

// F3b-019 AC8: the close path has no way to write a request, a backup or the config: the source
// does not call the request writer or build a request, and a close leaves the requests directory
// as it was (see TestCloseMaintenance_ConfirmedAudited).
func TestCloseMaintenance_NoConfigWrite(t *testing.T) {
	src, err := os.ReadFile("close.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{".Publish(", "BuildRequest", "os.WriteFile", "os.Rename", "os.Create", "backup", "requests/"} {
		if strings.Contains(string(src), banned) {
			t.Errorf("close.go contains %q; the close path must not write requests, backups or config", banned)
		}
	}
}
