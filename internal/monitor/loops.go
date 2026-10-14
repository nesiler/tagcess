package monitor

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
)

// This file owns the life cycle of the F4 monitoring jobs (F4-038, K-01, K-02, K-03, P-02, ADR 0032
// proposed): the k8s inventory read, the alert-source evaluation and the read-only drift check run
// here on the intervals of the settings, and the health/TLS/two-gate runner (F4-018) is started
// beside them. It is not a scheduler: it knows exactly these four ready jobs and calls nothing
// else, so it never applies access settings, reconciles, or reads Certificate metadata. Every job
// has its own goroutine and runs one round at a time, so a slow source never overlaps itself and
// never holds the other jobs back. Settings and the profile are read again before every round, so a
// change made in the UI applies to the next round without a restart. A failed or partial round keeps
// the last full success and its time and is shown as stale/unknown; resolving alerts is the services'
// own decision on a full read, never this loop's.

// Job names of the four monitoring jobs.
const (
	JobInventory = "inventory" // k8s inventory read (F4-007), at the inventory interval
	JobAlerts    = "alerts"    // alert-source evaluation (F4-025), at the target interval
	JobDrift     = "drift"     // read-only drift check (F4-039), at the inventory interval
	JobHealth    = "health"    // target/TLS/two-gate runner (F4-018), which keeps its own schedule
)

// ErrSetupPending is returned (wrapped) by a job callback or a health cycle that did not run because
// the installation is not finished yet (first import, probe policy, k8s profile). It is a waiting
// state, not a failure: the job shows "missing" and the dashboard lists the pending steps once.
var ErrSetupPending = errors.New("monitor: setup is not finished")

// State is what a job's last round left. It is a label for the UI, not an alarm severity.
type State string

const (
	// StateFresh: the last round read completely.
	StateFresh State = "fresh"
	// StateStale: the last round failed or was partial; the last full success is older.
	StateStale State = "stale"
	// StateUnknown: no round ever succeeded, or the health runner stopped on its own.
	StateUnknown State = "unknown"
	// StateMissing: the k8s profile is not set yet; nothing was called.
	StateMissing State = "missing"
	// StateError: the settings or the profile could not be read; nothing was called.
	StateError State = "error"
)

// JobStatus is one job's visible state. LastSuccess is the last full success and only a full
// success moves it. Err is why the last round failed or was not run; it is for the operator's
// diagnosis, and its text is whatever the service returned.
type JobStatus struct {
	Job         string
	State       State
	LastAttempt time.Time
	LastSuccess time.Time
	Err         error
}

// Clock is the time source: a fake in tests.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// HealthRunner is the F4-018 runner: Run blocks until ctx is done and keeps its own schedule.
type HealthRunner interface {
	Run(ctx context.Context) error
}

// LoopsConfig wires the loops to the ready services. Everything but Clock is required. The
// callbacks return nil only after a complete read; a partial result must be an error.
type LoopsConfig struct {
	// Settings is the typed monitoring settings getter, read before every round.
	Settings func(ctx context.Context) (Settings, error)
	// ProfileReady reports whether the k8s profile can be read: nil when it can, k8s.ErrNotSet when
	// none is saved yet. It is asked before every inventory round, and nothing is read without it.
	ProfileReady func(ctx context.Context) error
	// Inventory performs one full k8s read (k8s.Reader.Read).
	Inventory func(ctx context.Context) error
	// Alerts evaluates the alert sources once (alert.Sources.Evaluate).
	Alerts func(ctx context.Context) error
	// Drift performs one read-only drift check (alert.Drift.Check).
	Drift func(ctx context.Context) error
	// Health is started once and stopped with the loops.
	Health HealthRunner
	// Clock defaults to the system clock.
	Clock Clock
}

// Loops runs the monitoring jobs. Run it once per Loops.
type Loops struct {
	cfg  LoopsConfig
	mu   sync.Mutex
	jobs map[string]JobStatus
	// wake holds one buffered channel per periodic job; Trigger fills them (F5 I4).
	wake map[string]chan struct{}
}

var jobOrder = []string{JobInventory, JobAlerts, JobDrift, JobHealth}

// NewLoops returns Loops over cfg; a missing service is an error, never a silently skipped job.
func NewLoops(cfg LoopsConfig) (*Loops, error) {
	if cfg.Settings == nil || cfg.ProfileReady == nil || cfg.Inventory == nil || cfg.Alerts == nil ||
		cfg.Drift == nil || cfg.Health == nil {
		return nil, errors.New("monitor: loops need the settings, profile, inventory, alerts, drift and health services")
	}
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	l := &Loops{cfg: cfg, jobs: map[string]JobStatus{}, wake: map[string]chan struct{}{}}
	for _, name := range jobOrder {
		l.jobs[name] = JobStatus{Job: name, State: StateUnknown}
		l.wake[name] = make(chan struct{}, 1)
	}
	return l, nil
}

// Trigger asks the inventory, alert and drift jobs to run a round now instead of at their next
// interval, and wakes the health runner when it supports it. It never blocks; triggers that arrive
// while a round runs coalesce into one more round (F5 I4: a saved profile, credential or policy
// shows up without waiting for the interval).
func (l *Loops) Trigger() {
	for _, name := range jobOrder {
		select {
		case l.wake[name] <- struct{}{}:
		default:
		}
	}
	if t, ok := l.cfg.Health.(interface{ Trigger() }); ok {
		t.Trigger()
	}
}

// Status returns every job's state in a fixed order.
func (l *Loops) Status() []JobStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]JobStatus, 0, len(jobOrder))
	for _, name := range jobOrder {
		out = append(out, l.jobs[name])
	}
	return out
}

// loopJob is one periodic job: the callback, the interval it runs at, and an optional readiness
// check that must pass before the callback is called.
type loopJob struct {
	name     string
	every    func(Settings) time.Duration
	ready    func(ctx context.Context) error
	call     func(ctx context.Context) error
	fallback time.Duration // the wait before settings were ever read
}

// Run starts the health runner and the periodic jobs and blocks until ctx is done, then returns
// ctx.Err(). Cancelling starts no new round, cancels the calls in flight (each bounded by the
// service's own timeouts) and waits for every callback, the health runner included, to return.
func (l *Loops) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	defaults := DefaultSettings()
	jobs := []loopJob{
		{name: JobInventory, every: func(s Settings) time.Duration { return s.InventoryInterval }, ready: l.cfg.ProfileReady, call: l.cfg.Inventory, fallback: defaults.InventoryInterval},
		{name: JobAlerts, every: func(s Settings) time.Duration { return s.TargetInterval }, call: l.cfg.Alerts, fallback: defaults.TargetInterval},
		{name: JobDrift, every: func(s Settings) time.Duration { return s.InventoryInterval }, call: l.cfg.Drift, fallback: defaults.InventoryInterval},
	}
	var wg sync.WaitGroup
	wg.Add(1 + len(jobs))
	go func() {
		defer wg.Done()
		l.runHealth(ctx)
	}()
	for _, j := range jobs {
		go func() {
			defer wg.Done()
			l.loop(ctx, j)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

// loop runs one job until ctx is done. Each round is due at its start plus the interval read at that
// start; a round that ran longer than its interval is followed by one due round, never by several.
func (l *Loops) loop(ctx context.Context, j loopJob) {
	every := j.fallback // the last known interval: kept while the settings cannot be read
	for ctx.Err() == nil {
		start := l.cfg.Clock.Now()
		if s, err := l.cfg.Settings(ctx); err != nil {
			l.record(j.name, start, err, errState(err)) // fail safe: no settings, no call
		} else {
			every = j.every(s)
			l.round(ctx, j, start)
		}
		select {
		case <-ctx.Done():
			return
		case <-l.wake[j.name]:
		case <-l.cfg.Clock.After(start.Add(every).Sub(l.cfg.Clock.Now())):
		}
	}
}

// round runs one round of j unless it is not ready.
func (l *Loops) round(ctx context.Context, j loopJob, start time.Time) {
	if j.ready != nil {
		if err := j.ready(ctx); err != nil {
			if ctx.Err() == nil {
				l.record(j.name, start, err, errState(err))
			}
			return
		}
	}
	err := j.call(ctx)
	if err != nil && ctx.Err() != nil {
		return // the service was stopped: that says nothing about the source
	}
	l.record(j.name, start, err, setupState(err))
}

// setupState is the visible state of a round that ran but is waiting for the installation.
func setupState(err error) State {
	if errors.Is(err, ErrSetupPending) {
		return StateMissing
	}
	return ""
}

// errState is the visible state of a round that could not even start.
func errState(err error) State {
	if errors.Is(err, k8s.ErrNotSet) || errors.Is(err, ErrSetupPending) {
		return StateMissing
	}
	return StateError
}

// record stores the round's outcome. A nil err is a full success; otherwise the last success stays.
// A start-up failure (state set) wins over stale/unknown, as it needs the operator.
func (l *Loops) record(name string, at time.Time, err error, state State) {
	if err != nil && !errors.Is(err, ErrSetupPending) && !errors.Is(err, k8s.ErrNotSet) {
		// The page shows only the state; the log keeps the cause of a failed round.
		slog.Warn("monitor: round failed", "job", name, "err", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.jobs[name]
	st.LastAttempt, st.Err = at, err
	switch {
	case err == nil:
		st.State, st.LastSuccess = StateFresh, at
	case state != "":
		st.State = state
	case st.LastSuccess.IsZero():
		st.State = StateUnknown
	default:
		st.State = StateStale
	}
	l.jobs[name] = st
}

// ReportHealthCycle feeds one finished health-runner cycle into the health job's state: wire it to
// health.Config.Report (CycleReport.At and CycleReport.Err). A cycle that failed to read its settings
// or sites keeps the last full success and shows the job stale (or unknown before any success); a
// cycle that ran moves the success time. Until the first cycle is reported the job stays unknown, so
// a runner that is alive but never completes a cycle is never shown fresh.
func (l *Loops) ReportHealthCycle(at time.Time, err error) {
	var state State
	if errors.Is(err, ErrSetupPending) {
		state = StateMissing
	}
	l.record(JobHealth, at, err, state)
}

// runHealth starts the health runner once. It reads its own settings and keeps its own schedule; if
// it stops by itself that is shown, and it is not started again. It does not mark the job fresh: the
// runner's cycle reports do (ReportHealthCycle).
func (l *Loops) runHealth(ctx context.Context) {
	err := l.cfg.Health.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("monitor: the health runner stopped")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.jobs[JobHealth]
	st.State, st.Err = StateUnknown, err
	l.jobs[JobHealth] = st
}
