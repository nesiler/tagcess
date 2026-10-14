// Package maintenance holds the durable Headscale maintenance flag (H-07, ADR 0021 c/d): one DB row
// that stops widening Headscale writes while a host config change is open or unresolved, its few
// allowed transitions, and CheckWidening, the single gate every widening writer calls.
//
// The package only stores and checks state. Starting and ending maintenance (F3b-018/019) and
// wiring the gate into the writers (F3b-014..017) live elsewhere. Deadlines and restarts never
// close the flag; only an explicit transition does.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// State is the maintenance state: off -> active -> reconcile_pending -> off.
type State string

const (
	// Off: no maintenance, every write is allowed.
	Off State = "off"
	// Active: a host request is running, or it ended failed/interrupted. Widening is refused.
	Active State = "active"
	// ReconcilePending: the request succeeded (or the operator closed the maintenance) and only the
	// reconcile may write until it finishes.
	ReconcilePending State = "reconcile_pending"
)

// Writer sources for CheckWidening. Any other source is treated like an admin write.
const (
	SourceAdmin = "admin"
	SourceSync  = "sync"
)

var (
	// ErrMaintenance is returned by CheckWidening when widening is not allowed, including when the
	// state cannot be read (fail safe, AGENTS rule 7).
	ErrMaintenance = errors.New("bakım sürüyor")
	// ErrInvalidTransition is returned when a transition's precondition does not hold: wrong
	// state, stale request ID or a host result that is not terminal yet.
	ErrInvalidTransition = errors.New("maintenance: invalid transition")
)

// timeFormat is fixed-width, like the audit log's, so the stored text sorts chronologically.
const timeFormat = "2006-01-02T15:04:05.000Z"

// Queries is the storage the service needs. It is satisfied by *db.Queries.
type Queries interface {
	GetHeadscaleMaintenance(ctx context.Context) (db.GetHeadscaleMaintenanceRow, error)
	StartHeadscaleMaintenance(ctx context.Context, arg db.StartHeadscaleMaintenanceParams) (int64, error)
	RenewHeadscaleMaintenance(ctx context.Context, arg db.RenewHeadscaleMaintenanceParams) (int64, error)
	SetHeadscaleMaintenanceHostResult(ctx context.Context, arg db.SetHeadscaleMaintenanceHostResultParams) (int64, error)
	HoldHeadscaleMaintenanceReconcile(ctx context.Context, updatedAt string) error
	ReconcilePendingHeadscaleMaintenance(ctx context.Context, arg db.ReconcilePendingHeadscaleMaintenanceParams) (int64, error)
	CloseHeadscaleMaintenance(ctx context.Context, arg db.CloseHeadscaleMaintenanceParams) (int64, error)
}

// Status is the maintenance row as the UI and the writers see it.
type Status struct {
	State     State
	RequestID string
	Actor     string
	// StartedAt is when the maintenance began (kept across renewals); zero while off.
	StartedAt time.Time
	UpdatedAt time.Time
	// Elapsed is the time since StartedAt on the service clock for the UI band; zero while off.
	Elapsed time.Duration
	// LastHostResult is the helper's last result as secret-free JSON; empty while none is in.
	LastHostResult string
	// PendingReconcile marks an automatic reconcile held back while the maintenance was open.
	PendingReconcile bool
	// CloseNote says how the last maintenance ended (for example a dry run applied no diff).
	CloseNote string
}

// Service reads and moves the maintenance state.
type Service struct {
	q     Queries
	clock func() time.Time
}

// New returns a service on q.
func New(q Queries) *Service { return &Service{q: q, clock: time.Now} }

// Get reads the current status.
func (s *Service) Get(ctx context.Context) (Status, error) {
	row, err := s.q.GetHeadscaleMaintenance(ctx)
	if err != nil {
		return Status{}, fmt.Errorf("maintenance: read state: %w", err)
	}
	st := Status{
		State:            State(row.State),
		RequestID:        row.RequestID,
		Actor:            row.Actor,
		LastHostResult:   row.LastHostResult,
		PendingReconcile: row.PendingReconcile != 0,
		CloseNote:        row.CloseNote,
	}
	switch st.State {
	case Off, Active, ReconcilePending:
	default:
		return Status{}, fmt.Errorf("maintenance: unknown state %q", row.State)
	}
	if st.StartedAt, err = parseTime(row.StartedAt); err != nil {
		return Status{}, err
	}
	if st.UpdatedAt, err = parseTime(row.UpdatedAt); err != nil {
		return Status{}, err
	}
	if !st.StartedAt.IsZero() {
		st.Elapsed = max(0, s.clock().Sub(st.StartedAt))
	}
	return st, nil
}

// Start opens a maintenance for a new request (off -> active).
func (s *Service) Start(ctx context.Context, requestID, actor string) (Status, error) {
	if err := checkRequest(requestID, actor); err != nil {
		return Status{}, err
	}
	n, err := s.q.StartHeadscaleMaintenance(ctx, db.StartHeadscaleMaintenanceParams{
		RequestID: requestID, Actor: actor, StartedAt: s.stamp(),
	})
	return s.moved(ctx, "start", n, err)
}

// Renew gives an open maintenance a new request ID (active -> active), only once the last host
// result is terminal. A request that is still running is never replaced.
func (s *Service) Renew(ctx context.Context, requestID, actor string) (Status, error) {
	if err := checkRequest(requestID, actor); err != nil {
		return Status{}, err
	}
	n, err := s.q.RenewHeadscaleMaintenance(ctx, db.RenewHeadscaleMaintenanceParams{
		RequestID: requestID, Actor: actor, UpdatedAt: s.stamp(),
	})
	return s.moved(ctx, "renew", n, err)
}

// SetHostResult stores the helper's latest result (secret-free JSON with a "status" field) for the
// open maintenance's current request.
func (s *Service) SetHostResult(ctx context.Context, requestID, resultJSON string) error {
	n, err := s.q.SetHeadscaleMaintenanceHostResult(ctx, db.SetHeadscaleMaintenanceHostResultParams{
		LastHostResult: resultJSON, UpdatedAt: s.stamp(), RequestID: requestID,
	})
	_, err = s.moved(ctx, "set host result", n, err)
	return err
}

// MarkPendingReconcile records that an automatic reconcile was held back. It does nothing while
// the maintenance is off.
func (s *Service) MarkPendingReconcile(ctx context.Context) error {
	if err := s.q.HoldHeadscaleMaintenanceReconcile(ctx, s.stamp()); err != nil {
		return fmt.Errorf("maintenance: mark pending reconcile: %w", err)
	}
	return nil
}

// ToReconcilePending moves the maintenance for requestID to reconcile_pending (active ->
// reconcile_pending), after success or an explicit close. A request ID that is no longer current
// is refused, so a stale confirmation cannot close a newer maintenance.
func (s *Service) ToReconcilePending(ctx context.Context, requestID string) (Status, error) {
	n, err := s.q.ReconcilePendingHeadscaleMaintenance(ctx, db.ReconcilePendingHeadscaleMaintenanceParams{
		UpdatedAt: s.stamp(), RequestID: requestID,
	})
	return s.moved(ctx, "to reconcile_pending", n, err)
}

// Off ends the maintenance (reconcile_pending -> off) and keeps note for the UI.
func (s *Service) Off(ctx context.Context, note string) error {
	n, err := s.q.CloseHeadscaleMaintenance(ctx, db.CloseHeadscaleMaintenanceParams{
		UpdatedAt: s.stamp(), CloseNote: note,
	})
	_, err = s.moved(ctx, "off", n, err)
	return err
}

// CheckWidening is the one gate for writes that widen access. Writers call it under their write
// lock: Off allows everything, Active refuses everything, and ReconcilePending allows only the
// reconcile (SourceSync). A state that cannot be read refuses.
func (s *Service) CheckWidening(ctx context.Context, source string) error {
	st, err := s.Get(ctx)
	if err != nil {
		return fmt.Errorf("%w: durum okunamadı: %w", ErrMaintenance, err)
	}
	switch {
	case st.State == Off:
		return nil
	case st.State == ReconcilePending && source == SourceSync:
		return nil
	}
	return ErrMaintenance
}

// moved turns an UPDATE's outcome into the new status or an error.
func (s *Service) moved(ctx context.Context, op string, rows int64, err error) (Status, error) {
	if err != nil {
		return Status{}, fmt.Errorf("maintenance: %s: %w", op, err)
	}
	if rows == 0 {
		return Status{}, fmt.Errorf("%w: %s", ErrInvalidTransition, op)
	}
	return s.Get(ctx)
}

func (s *Service) stamp() string { return s.clock().UTC().Format(timeFormat) }

func checkRequest(requestID, actor string) error {
	if strings.TrimSpace(requestID) == "" {
		return errors.New("maintenance: request ID is required")
	}
	if strings.TrimSpace(actor) == "" {
		return errors.New("maintenance: actor is required")
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("maintenance: bad time %q: %w", s, err)
	}
	return t, nil
}
