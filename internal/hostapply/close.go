package hostapply

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
)

// EventCloseRequested is the audit event of a confirmed "close the maintenance". The maintenance
// itself ends later, when the reconcile has finished (sync.EventMaintenanceClosed).
const EventCloseRequested = "headscale.maintenance.close_requested"

// Refusals of the close. Each one means nothing changed.
var (
	ErrConfirmRequired = errors.New("bakımı kapatmak için açık onay gerekli")
	ErrStaleRequestID  = errors.New("bakımın istek ID'si değişti; sayfayı yenileyin")
	ErrNotOpen         = errors.New("bakım açık değil veya zaten kapanıyor")
)

// reconcileFirst is the default OnSucceeded: a recorded success hands the maintenance to the
// reconcile (active -> reconcile_pending) and asks for a run. Widening writes stay refused until
// that run has finished (ADR 0021 c). If the move fails, the flag stays active and the next Poll
// tries again.
func (s *Service) reconcileFirst(ctx context.Context, requestID string) {
	if _, err := s.Maintenance.ToReconcilePending(ctx, requestID); err != nil {
		if !errors.Is(err, maintenance.ErrInvalidTransition) { // otherwise the operator closed it first
			s.Log.Error("maintenance could not move to reconcile_pending", "request_id", requestID, "err", err)
		}
		return
	}
	s.Log.Info("headscale config succeeded; reconcile runs before writers reopen", "request_id", requestID)
	s.requestReconcile()
}

func (s *Service) requestReconcile() {
	if s.Reconcile != nil {
		s.Reconcile()
	}
}

// CloseRequest is the devops operator's "close the maintenance". RequestID is the one the screen
// showed; Confirm is the explicit approval.
type CloseRequest struct {
	Actor     string
	RequestID string
	Confirm   bool
}

// CloseResult is what the screen shows after a close: the helper's last known status and, when
// that status is not a safe resting one, a warning.
type CloseResult struct {
	HostRequestID string
	HostState     hostpatch.State
	HostPhase     hostpatch.Phase
	// Warning is set while the helper still reports a request in flight, or its status could not be
	// read; the close went ahead on the operator's confirmation.
	Warning string
}

// CloseMaintenance ends an open maintenance on the operator's word (R2:24): the host status is
// written to the audit log, the maintenance moves to reconcile_pending and a reconcile is requested.
// It touches no request and no config; the reconcile ends the maintenance. A stale request ID, a
// missing confirmation or actor, or a maintenance that is not active refuses.
func (s *Service) CloseMaintenance(ctx context.Context, req CloseRequest) (CloseResult, error) {
	var res CloseResult
	switch {
	case strings.TrimSpace(req.Actor) == "":
		return res, ErrActorRequired
	case !req.Confirm:
		return res, ErrConfirmRequired
	}
	err := s.Lock(func() error {
		st, err := s.Maintenance.Get(ctx)
		if err != nil {
			return fmt.Errorf("bakım durumu okunamıyor: %w", err)
		}
		if st.State != maintenance.Active {
			return ErrNotOpen
		}
		if req.RequestID == "" || req.RequestID != st.RequestID {
			return ErrStaleRequestID
		}
		var hostState string
		res, hostState = s.hostSnapshot()
		// The transition runs first: the success audit is written only after it, so a transition
		// that does not happen is never recorded as a close (F3b-027 AC4).
		if _, err := s.Maintenance.ToReconcilePending(ctx, st.RequestID); err != nil {
			if errors.Is(err, maintenance.ErrInvalidTransition) {
				return ErrNotOpen
			}
			return fmt.Errorf("bakım kapatılamadı: %w", err)
		}
		entry := audit.Entry{
			Actor: req.Actor, Event: EventCloseRequested, Target: "request:" + st.RequestID, Result: "reconcile_pending",
			Diff: audit.Diff{
				{Field: "host_request_id", After: res.HostRequestID},
				{Field: "host_state", After: hostState},
				{Field: "host_phase", After: string(res.HostPhase)},
			},
		}
		if _, err := s.Audit.Write(ctx, entry); err != nil {
			return fmt.Errorf("%w: %w", ErrAudit, err)
		}
		return nil
	})
	if err != nil {
		return CloseResult{}, err
	}
	s.Log.Info("headscale maintenance close requested", "actor", req.Actor, "host_state", string(res.HostState))
	s.requestReconcile()
	return res, nil
}

// hostSnapshot reads the helper's status for the audit and the warning; the second value is the
// state text for the audit. An unreadable status does not block the close: it is the way out when
// the helper is gone (AGENTS rule 6).
func (s *Service) hostSnapshot() (CloseResult, string) {
	hs, err := s.Host.Status()
	switch {
	case err != nil:
		return CloseResult{Warning: "host durumu okunamadı; bakım yine de kapatıldı"}, "unreadable"
	case hs.ConfigError != "":
		return CloseResult{HostRequestID: hs.RequestID, HostState: hs.State, HostPhase: hs.Phase,
			Warning: "host Headscale config'i okunamıyor veya beklenmeyen değerler içeriyor"}, "config_error"
	}
	res := CloseResult{HostRequestID: hs.RequestID, HostState: hs.State, HostPhase: hs.Phase}
	if hs.State != "" && !hs.State.Terminal() {
		res.Warning = "host işlemi hâlâ sürüyor (" + string(hs.State) + "); config yarım kalmış olabilir"
	}
	return res, string(hs.State)
}
