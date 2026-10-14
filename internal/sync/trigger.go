// Trigger is the single reconcile queue (architecture.md §5): webhook signals, periodic ticks and
// manual requests all end up here, and at most one reconcile runs at a time. A webhook burst is
// merged into one run (Y-01.6) and a signal that lands while a reconcile is running causes exactly
// one more run afterwards. The queue only decides when to run; it never reads or writes a managed
// system itself (that is Reconciler.Run).
package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Trigger labels recorded on a sync run (Y-05.2). They match the sync_runs CHECK constraint and
// validTriggers.
const (
	TriggerWebhook  = "webhook"
	TriggerPeriodic = "periodic"
	TriggerManual   = "manual"
)

// triggerPriority decides which label a merged burst gets (Y-05.2). A manual request outranks a
// webhook, which outranks a periodic tick; an empty pending label has priority zero.
var triggerPriority = map[string]int{
	TriggerManual:   3,
	TriggerWebhook:  2,
	TriggerPeriodic: 1,
}

// Timing defaults: the webhook debounce window (Y-01.6, Y-01.1) and the periodic full comparison
// (Y-02.1). The shutdown timeout is a local safety bound, not a requirement value.
const (
	DefaultDebounce        = 2 * time.Second
	DefaultSyncInterval    = 5 * time.Minute
	DefaultShutdownTimeout = 30 * time.Second
)

// SyncIntervalSetting is the settings-table key of the periodic reconcile interval (Y-02.1). The UI
// writes it as whole minutes (F1-017 AC7).
const SyncIntervalSetting = "sync_interval"

// Sync interval bounds the settings layer must enforce (F1-017 AC7): 1-60 minutes.
const (
	MinSyncIntervalMinutes = 1
	MaxSyncIntervalMinutes = 60
)

// IntervalFromSetting turns the stored sync interval (whole minutes) into a period. An empty,
// malformed or out-of-range value falls back to def, so a bad setting can never busy-loop the
// scheduler or stretch the period without bound (the same fail-safe bounds idea as Settings.Validate).
func IntervalFromSetting(value string, def time.Duration) time.Duration {
	minutes, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || minutes < MinSyncIntervalMinutes || minutes > MaxSyncIntervalMinutes {
		return def
	}
	return time.Duration(minutes) * time.Minute
}

// RunFunc performs one reconcile for a trigger. It is Reconciler.Run in production.
type RunFunc func(ctx context.Context, trigger string) error

// TriggerConfig wires the scheduler. Run is required.
type TriggerConfig struct {
	Run RunFunc
	// Debounce is the window that merges signals into one run (Y-01.6). Zero: DefaultDebounce.
	Debounce time.Duration
	// Interval returns the periodic reconcile period (Y-02.1). It is read again every period, so a
	// changed setting takes effect from the next period. Nil: DefaultSyncInterval.
	Interval func() time.Duration
	// ShutdownTimeout bounds how long Stop waits for a running reconcile. Zero: DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
	// Logger receives background reconcile errors. Nil: slog.Default.
	Logger *slog.Logger
}

// Trigger serializes every reconcile. It implements hook.Signaler.
type Trigger struct {
	run             RunFunc
	debounce        time.Duration
	interval        func() time.Duration
	shutdownTimeout time.Duration
	log             *slog.Logger

	// mu guards pending and the notify send: a request sets pending and wakes the loop atomically, so
	// a signal can never be lost between the two.
	mu      sync.Mutex
	pending string
	notify  chan struct{}

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	started  atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
}

// NewTrigger validates the wiring and returns the scheduler.
func NewTrigger(cfg TriggerConfig) (*Trigger, error) {
	if cfg.Run == nil {
		return nil, errors.New("sync: a run function is required")
	}
	t := &Trigger{
		run:             cfg.Run,
		debounce:        cfg.Debounce,
		interval:        cfg.Interval,
		shutdownTimeout: cfg.ShutdownTimeout,
		log:             cfg.Logger,
		notify:          make(chan struct{}, 1),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}
	if t.debounce <= 0 {
		t.debounce = DefaultDebounce
	}
	if t.interval == nil {
		t.interval = func() time.Duration { return DefaultSyncInterval }
	}
	if t.shutdownTimeout <= 0 {
		t.shutdownTimeout = DefaultShutdownTimeout
	}
	if t.log == nil {
		t.log = slog.Default()
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	return t, nil
}

// Signal requests a webhook-triggered reconcile (hook.Signaler). It never blocks.
func (t *Trigger) Signal() { t.Request(TriggerWebhook) }

// RequestManual requests a reconcile an operator asked for from the interface (F1-017). It never
// blocks; the run is recorded with the manual trigger label (Y-05.2).
func (t *Trigger) RequestManual() { t.Request(TriggerManual) }

// Request queues a reconcile with the given trigger. It never blocks and merges with pending
// requests. When signals of different kinds land in the same burst a higher-priority trigger wins
// (manual > webhook > periodic), so a webhook burst that swallows a periodic tick is still recorded
// as webhook (Y-05.2). An unknown trigger is ignored; manual triggers (F1-017) call it with
// TriggerManual.
func (t *Trigger) Request(trigger string) {
	if !validTriggers[trigger] {
		return
	}
	t.mu.Lock()
	if triggerPriority[trigger] >= triggerPriority[t.pending] {
		t.pending = trigger
	}
	select {
	case t.notify <- struct{}{}:
	default:
	}
	t.mu.Unlock()
}

// Start launches the scheduler goroutine. It is idempotent, so a second call does not create a
// second reconcile loop.
func (t *Trigger) Start() {
	if t.started.CompareAndSwap(false, true) {
		go t.loop()
	}
}

// Stop asks the scheduler to stop and waits for a running reconcile to finish, up to
// ShutdownTimeout. On timeout it cancels the reconcile context and waits once more for the
// reconcile to unwind, so a caller that closes its dependencies afterwards cannot cut off the
// change pipeline's post-write bookkeeping (audit, change and sync_run records). It returns an
// error when the graceful timeout was exceeded; the caller should then exit. It is safe to call
// more than once and before Start.
func (t *Trigger) Stop() error {
	if !t.started.Load() {
		return nil
	}
	t.stopOnce.Do(func() { close(t.stop) })
	select {
	case <-t.done:
		return nil
	case <-time.After(t.shutdownTimeout):
	}
	t.cancel()
	select {
	case <-t.done:
	case <-time.After(t.shutdownTimeout):
	}
	return fmt.Errorf("sync: shutdown timed out after %s waiting for the running reconcile", t.shutdownTimeout)
}

// loop is the only goroutine that calls run, so reconciles never overlap.
func (t *Trigger) loop() {
	defer close(t.done)
	periodic := time.NewTimer(t.period())
	defer periodic.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-t.notify:
			if !t.waitDebounce(periodic) {
				return
			}
			if trigger := t.take(); trigger != "" {
				t.runOnce(trigger)
			}
		case <-periodic.C:
			// A periodic tick is one more signal on the same queue: it goes through the shared
			// debounce instead of running outside it, so it cannot slip in as a second run next to
			// a webhook burst (review F1-013 finding 1).
			periodic.Reset(t.period())
			t.Request(TriggerPeriodic)
		}
	}
}

// waitDebounce holds the run for the debounce window so signals that arrive together become one run
// (Y-01.6). The window is fixed from the first signal, so latency stays bounded (Y-01.1). A
// periodic tick inside the window joins the same burst and is folded into the pending request. It
// returns false when the scheduler is stopping.
func (t *Trigger) waitDebounce(periodic *time.Timer) bool {
	timer := time.NewTimer(t.debounce)
	defer timer.Stop()
	for {
		select {
		case <-t.stop:
			return false
		case <-t.notify:
			// Part of the same burst: the window does not move.
		case <-periodic.C:
			// Same burst: re-arm the period and record the request, then keep the window fixed.
			periodic.Reset(t.period())
			t.Request(TriggerPeriodic)
		case <-timer.C:
			return true
		}
	}
}

// take consumes the pending trigger and any notify token that belongs to the same burst, so a
// signal already merged into this run cannot start a second one. A signal that arrives during the
// run sets pending again and causes exactly one more run.
func (t *Trigger) take() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	trigger := t.pending
	t.pending = ""
	select {
	case <-t.notify:
	default:
	}
	return trigger
}

func (t *Trigger) runOnce(trigger string) {
	if err := t.run(t.ctx, trigger); err != nil {
		t.log.Error("reconcile failed", "trigger", trigger, "err", err)
	}
}

// period is the current interval, never zero (a broken setting falls back to the default).
func (t *Trigger) period() time.Duration {
	d := t.interval()
	if d <= 0 {
		return DefaultSyncInterval
	}
	return d
}
