package hostapply

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
)

// SettingConfigWriteEnabled is the settings key that must be "true" before tagcess starts an H-07
// request. It is off by default (R2:29 c); the screen that flips it is F3b-021.
const SettingConfigWriteEnabled = "headscale.config_write_enabled"

// Audit events and the actor recorded for results the host reports.
const (
	EventStarted  = "headscale.config.started"
	EventFinished = "headscale.config.finished"
	systemActor   = "system:hostapply"

	// codeRequestWriteFailed and codeAuditFailed are local results: the request never reached the
	// helper, so there is no host result. They are stored like a failed one, which lets an ordinary
	// new patch take over the open flag (ADR 0021 c).
	codeRequestWriteFailed = "request_write_failed"
	codeAuditFailed        = "audit_failed"
)

// ResultWait is how long a result may take before the watcher warns; the flag stays open.
const ResultWait = 150 * time.Second

// Refusals. Each one means nothing was written: no flag, no request.
var (
	ErrWriteDisabled     = errors.New("Headscale config yazma switch'i kapalı") //nolint:staticcheck // a product name, and the message the UI shows
	ErrStatusUnavailable = errors.New("host durumu (status.json) okunamıyor")
	ErrHostConfig        = errors.New("host Headscale config'i okunamıyor veya beklenmeyen değerler içeriyor; yeni patch yok") //nolint:staticcheck // a product name, and the message the UI shows
	ErrStale             = errors.New("config yardımcının gördüğünden farklı; sayfayı yenileyin")
	ErrNoChange          = errors.New("istenen liste zaten apply edilmiş")
	ErrActorRequired     = errors.New("hostapply: actor is required")
	ErrHostBusy          = errors.New("host işlemi sürüyor veya sonucu henüz yok")
	ErrAwaitingClose     = errors.New("başarılı sonuç bakımın kapanmasını bekliyor")
	ErrUnknownOutcome    = errors.New("belirsiz sonuç var; bakım açılmadı")
	// ErrPublish: the flag and the started audit are in, but the request could not be written. The
	// flag stays open; the way out is a new patch (R2:24).
	ErrPublish = errors.New("istek yazılamadı; bakım açık kaldı")
	// ErrAudit: the audit record could not be written, so no request was published; the flag stays open.
	ErrAudit = errors.New("audit kaydı yazılamadı; istek yayımlanmadı, bakım açık kaldı")
)

// Host is the shared-directory channel; *Client satisfies it.
type Host interface {
	Publish(doc []byte) error
	Result(requestID string) (hostpatch.Result, error)
	Status() (hostpatch.Status, error)
}

// Flag is the durable maintenance row; *maintenance.Service satisfies it.
type Flag interface {
	Get(ctx context.Context) (maintenance.Status, error)
	Start(ctx context.Context, requestID, actor string) (maintenance.Status, error)
	Renew(ctx context.Context, requestID, actor string) (maintenance.Status, error)
	SetHostResult(ctx context.Context, requestID, resultJSON string) error
	ToReconcilePending(ctx context.Context, requestID string) (maintenance.Status, error)
}

// Auditor is the append-only log; *audit.Logger satisfies it.
type Auditor interface {
	Write(ctx context.Context, e audit.Entry) (audit.Event, error)
}

// Settings is the settings table; *db.Queries satisfies it.
type Settings interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// Unknown is one unresolved write outcome (an uncertain policy, an unverified admin write, a key
// revocation that could not be verified).
type Unknown struct {
	Kind   string
	Detail string
}

// UnknownSource lists the open unresolved outcomes. A source that cannot be read is an error.
type UnknownSource interface {
	Open(ctx context.Context) ([]Unknown, error)
}

// Config wires the service. Host, Maintenance, Audit, Settings and Unknowns are required.
type Config struct {
	Host        Host
	Maintenance Flag
	Audit       Auditor
	Settings    Settings
	Unknowns    UnknownSource
	// Lock runs fn under the process-wide writer lock; it defaults to change.WithWriterLock.
	Lock func(fn func() error) error
	// OnSucceeded runs, outside the lock, while the flag is open and the host result for the current
	// request is "succeeded". Nil means the production behaviour (reconcileFirst): the maintenance
	// moves to reconcile_pending and a reconcile is requested. The service never ends the flag
	// itself; the reconcile does, once it has finished (F3b-019).
	OnSucceeded func(ctx context.Context, requestID string)
	// Reconcile asks for a reconcile run (the trigger's manual request). Nil: nothing is requested,
	// and the periodic reconcile picks the work up.
	Reconcile func()
	Log       *slog.Logger
	Now       func() time.Time
	// NewID returns a lowercase UUID; it defaults to a random v4.
	NewID func() string
}

// Service starts H-07 requests in the safe order and tracks their results.
type Service struct {
	Config
}

// NewService validates cfg and fills the defaults.
func NewService(cfg Config) (*Service, error) {
	if cfg.Host == nil || cfg.Maintenance == nil || cfg.Audit == nil || cfg.Settings == nil || cfg.Unknowns == nil {
		return nil, errors.New("hostapply: Host, Maintenance, Audit, Settings and Unknowns are required")
	}
	if cfg.Lock == nil {
		cfg.Lock = change.WithWriterLock
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewID == nil {
		cfg.NewID = newRequestID
	}
	svc := &Service{Config: cfg}
	if svc.OnSucceeded == nil {
		svc.OnSucceeded = svc.reconcileFirst
	}
	return svc, nil
}

// Preview is the read-only diff between the helper's current list and the wanted one.
type Preview struct {
	Current []string
	Wanted  []string // canonical order
	Added   []string
	Removed []string
	// BaseRev is the revision of Current; the approval carries it back so a stale preview is refused.
	BaseRev string
}

// Preview reads the fresh status.json and diffs it against wanted. It validates wanted with the
// shared F3b-004 rules and writes nothing. A status with config_error has no list to diff
// against: it is refused with ErrHostConfig.
func (s *Service) Preview(_ context.Context, wanted []string) (Preview, error) {
	if err := hostpatch.ValidateGroups(wanted); err != nil {
		return Preview{}, err
	}
	st, err := s.Host.Status()
	if err != nil {
		return Preview{}, fmt.Errorf("%w: %w", ErrStatusUnavailable, err)
	}
	if st.ConfigError != "" {
		return Preview{}, ErrHostConfig
	}
	want := canonical(wanted)
	p := Preview{Current: st.AllowedGroups, Wanted: want, BaseRev: st.BaseRev}
	for _, g := range want {
		if !slices.Contains(st.AllowedGroups, g) {
			p.Added = append(p.Added, g)
		}
	}
	for _, g := range st.AllowedGroups {
		if !slices.Contains(want, g) {
			p.Removed = append(p.Removed, g)
		}
	}
	return p, nil
}

// ApplyRequest is an approved patch: the new full list and the base_rev the preview showed.
type ApplyRequest struct {
	Actor   string
	Wanted  []string
	BaseRev string
}

// ApplyResult carries the new request ID and the unresolved outcomes that exist. On a refusal for
// unknown outcomes, Unknowns names them; on a recovery patch they are listed but do not block.
type ApplyResult struct {
	RequestID string
	Unknowns  []Unknown
}

// Apply starts a request: preconditions under the writer lock, then the maintenance flag and the
// started audit, and only then the request itself (ADR 0021 d). Any refusal leaves the flag, the
// requests directory and the audit log untouched.
func (s *Service) Apply(ctx context.Context, req ApplyRequest) (ApplyResult, error) {
	var res ApplyResult
	err := s.Lock(func() error {
		var err error
		res, err = s.apply(ctx, req)
		return err
	})
	return res, err
}

func (s *Service) apply(ctx context.Context, req ApplyRequest) (ApplyResult, error) {
	var res ApplyResult
	if strings.TrimSpace(req.Actor) == "" {
		return res, ErrActorRequired
	}
	if err := hostpatch.ValidateGroups(req.Wanted); err != nil {
		return res, err
	}
	if err := s.writeEnabled(ctx); err != nil {
		return res, err
	}
	hs, err := s.Host.Status()
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrStatusUnavailable, err)
	}
	if hs.ConfigError != "" {
		return res, ErrHostConfig
	}
	if hs.BaseRev != req.BaseRev {
		return res, ErrStale
	}
	wanted := canonical(req.Wanted)
	if slices.Equal(wanted, hs.AllowedGroups) {
		return res, ErrNoChange
	}
	if hs.State != "" && !hs.State.Terminal() {
		return res, ErrHostBusy
	}

	st, err := s.Maintenance.Get(ctx)
	if err != nil {
		return res, fmt.Errorf("bakım durumu okunamıyor: %w", err)
	}
	renew := false
	switch st.State {
	case maintenance.Off:
		// The "unknown outcome" rule applies only when a maintenance opens (R2:29 a).
		open, err := s.Unknowns.Open(ctx)
		if err != nil {
			return res, fmt.Errorf("%w: %w", ErrUnknownOutcome, err)
		}
		if len(open) > 0 {
			res.Unknowns = open
			return res, ErrUnknownOutcome
		}
	case maintenance.Active:
		if _, err := s.recordResult(ctx, st); err != nil {
			return res, err
		}
		if st, err = s.Maintenance.Get(ctx); err != nil {
			return res, fmt.Errorf("bakım durumu okunamıyor: %w", err)
		}
		switch hostStatus(st.LastHostResult) {
		case string(hostpatch.StateFailed), string(hostpatch.StateInterrupted):
		case string(hostpatch.StateSucceeded):
			return res, ErrAwaitingClose
		default:
			return res, ErrHostBusy
		}
		// A recovery patch must not be blocked by outcomes that arose after the maintenance began;
		// they are shown instead. An unreadable source does not block it either.
		if open, err := s.Unknowns.Open(ctx); err != nil {
			s.Log.Warn("unresolved outcomes could not be listed for a recovery patch")
		} else {
			res.Unknowns = open
		}
		renew = true
	default:
		return res, ErrAwaitingClose
	}

	id := s.NewID()
	doc, err := hostpatch.BuildRequest(id, hs.BaseRev, wanted)
	if err != nil {
		return res, err
	}
	// The flag first, then the audit, and only then the request.
	if renew {
		_, err = s.Maintenance.Renew(ctx, id, req.Actor)
	} else {
		_, err = s.Maintenance.Start(ctx, id, req.Actor)
	}
	if err != nil {
		return res, fmt.Errorf("bakım bayrağı yazılamadı: %w", err)
	}
	res.RequestID = id
	started := audit.Entry{
		Actor: req.Actor, Event: EventStarted, Target: "request:" + id, Result: "started",
		Diff: audit.Diff{
			{Field: "oidc.allowed_groups", Before: strings.Join(hs.AllowedGroups, ","), After: strings.Join(wanted, ",")},
			{Field: "request_id", After: id},
		},
	}
	if _, err := s.Audit.Write(ctx, started); err != nil {
		s.failLocal(ctx, id, codeAuditFailed)
		return res, fmt.Errorf("%w: %w", ErrAudit, err)
	}
	if err := s.Host.Publish(doc); err != nil {
		s.Log.Error("headscale config request not published", "request_id", id)
		s.failLocal(ctx, id, codeRequestWriteFailed)
		return res, fmt.Errorf("%w: %w", ErrPublish, err)
	}
	s.Log.Info("headscale config request started", "request_id", id, "actor", req.Actor)
	return res, nil
}

// writeEnabled is the service's own fail-closed check of the write switch: anything but a stored
// "true" refuses.
func (s *Service) writeEnabled(ctx context.Context) error {
	v, err := s.Settings.GetSetting(ctx, SettingConfigWriteEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWriteDisabled
	}
	if err != nil {
		return fmt.Errorf("%w: ayar okunamadı", ErrWriteDisabled)
	}
	if on, perr := strconv.ParseBool(strings.TrimSpace(v)); perr != nil || !on {
		return ErrWriteDisabled
	}
	return nil
}

// failLocal records that request id never reached the helper. The flag stays open; the result is
// stored like a failed host result so a new patch can take over (R2:24).
func (s *Service) failLocal(ctx context.Context, id, code string) {
	// The caller's context may be what failed (cancelled request); the local failure must still land.
	ctx = context.WithoutCancel(ctx)
	doc, _ := json.Marshal(hostResult{Status: string(hostpatch.StateFailed), RequestID: id, ErrorCode: code})
	entry := audit.Entry{
		Actor: systemActor, Event: EventFinished, Target: "request:" + id, Result: string(hostpatch.StateFailed),
		Diff: audit.Diff{{Field: "error_code", After: code}},
	}
	if _, err := s.Audit.Write(ctx, entry); err != nil {
		s.Log.Error("headscale config local failure not audited", "request_id", id)
	}
	if err := s.Maintenance.SetHostResult(ctx, id, string(doc)); err != nil {
		s.Log.Error("headscale config local failure not recorded", "request_id", id)
	}
}

// hostResult is what the maintenance row keeps of a result: secret-free fields only. The "status"
// key is what the maintenance transitions read.
type hostResult struct {
	Status         string `json:"status"`
	RequestID      string `json:"request_id"`
	Phase          string `json:"phase,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	ConfigChanged  *bool  `json:"config_changed,omitempty"`
	HealthVerified bool   `json:"health_verified,omitempty"`
	FinishedAt     string `json:"finished_at,omitempty"`
}

// hostStatus is the "status" of a stored host result, or "" while none is in or it is unreadable.
func hostStatus(stored string) string {
	var v struct {
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(stored), &v) != nil {
		return ""
	}
	return v.Status
}

// recordResult stores the host's terminal result for the open request, once: it audits first, then
// writes the maintenance row, so a crash in between repeats the audit instead of losing it. It
// does nothing when the maintenance is not active, a result is already stored, or the helper has
// no result for this request ID. Callers hold the writer lock.
func (s *Service) recordResult(ctx context.Context, st maintenance.Status) (bool, error) {
	if st.State != maintenance.Active || st.RequestID == "" || hostStatus(st.LastHostResult) != "" {
		return false, nil
	}
	r, err := s.Host.Result(st.RequestID)
	if errors.Is(err, ErrNoResult) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sonuç okunamıyor: %w", err)
	}
	if r.RequestID != st.RequestID {
		return false, nil
	}
	doc := hostResult{
		Status: string(r.State), RequestID: r.RequestID, Phase: string(r.Phase), ErrorCode: string(r.ErrorCode),
		ConfigChanged: r.ConfigChanged, HealthVerified: r.HealthVerified, FinishedAt: r.FinishedAt.UTC().Format(time.RFC3339),
	}
	changed := "unknown"
	if r.ConfigChanged != nil {
		changed = strconv.FormatBool(*r.ConfigChanged)
	}
	entry := audit.Entry{
		Actor: systemActor, Event: EventFinished, Target: "request:" + r.RequestID, Result: string(r.State),
		Diff: audit.Diff{
			{Field: "phase", After: string(r.Phase)},
			{Field: "error_code", After: string(r.ErrorCode)},
			{Field: "config_changed", After: changed},
			{Field: "health_verified", After: strconv.FormatBool(r.HealthVerified)},
		},
	}
	if _, err := s.Audit.Write(ctx, entry); err != nil {
		return false, fmt.Errorf("sonuç audit kaydı yazılamadı: %w", err)
	}
	b, _ := json.Marshal(doc)
	if err := s.Maintenance.SetHostResult(ctx, st.RequestID, string(b)); err != nil {
		return false, err
	}
	s.Log.Info("headscale config result recorded", "request_id", r.RequestID, "state", string(r.State))
	return true, nil
}

// PollResult is what one Poll did.
type PollResult struct {
	RequestID string
	// Recorded: the terminal result for RequestID was stored by this call.
	Recorded bool
	// Overdue: no result yet and ResultWait has passed. The flag stays open.
	Overdue bool
}

// Poll reads the helper's result for the open request, if there is one, and records it. It works
// from the database row alone, so it resumes after a container restart. A deadline never closes
// the flag. While the flag is open and the stored result is "succeeded" it runs the OnSucceeded
// hook (outside the writer lock).
func (s *Service) Poll(ctx context.Context) (PollResult, error) {
	var pr PollResult
	var succeeded string
	err := s.Lock(func() error {
		st, err := s.Maintenance.Get(ctx)
		if err != nil {
			return fmt.Errorf("bakım durumu okunamıyor: %w", err)
		}
		if st.State != maintenance.Active || st.RequestID == "" {
			return nil
		}
		pr.RequestID = st.RequestID
		if pr.Recorded, err = s.recordResult(ctx, st); err != nil {
			return err
		}
		if pr.Recorded {
			if st, err = s.Maintenance.Get(ctx); err != nil {
				return fmt.Errorf("bakım durumu okunamıyor: %w", err)
			}
		}
		switch hostStatus(st.LastHostResult) {
		case "":
			pr.Overdue = s.Now().Sub(st.UpdatedAt) > ResultWait
		case string(hostpatch.StateSucceeded):
			succeeded = st.RequestID
		}
		return nil
	})
	if err == nil && succeeded != "" && s.OnSucceeded != nil {
		s.OnSucceeded(ctx, succeeded)
	}
	return pr, err
}

// canonical returns groups in the closed set's canonical order. groups must already be valid.
func canonical(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range []string{hostpatch.GroupDevops, hostpatch.GroupDeveloper, hostpatch.GroupStandart} {
		if slices.Contains(groups, g) {
			out = append(out, g)
		}
	}
	return out
}

// newRequestID returns a random lowercase v4 UUID.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
