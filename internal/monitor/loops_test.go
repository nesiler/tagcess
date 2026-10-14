package monitor

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
)

var loopsT0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

// guard bounds every wait of a test on real time; the loops themselves only ever see the fake clock.
const guard = 5 * time.Second

// loopClock is a manual clock: After registers a timer, Advance fires the due ones. Every After is
// announced on registered, so a test waits for the loops to be idle instead of sleeping.
type loopClock struct {
	mu         sync.Mutex
	now        time.Time
	timers     []loopTimer
	delays     []time.Duration
	registered chan struct{}
}

type loopTimer struct {
	when time.Time
	ch   chan time.Time
}

func newLoopClock() *loopClock {
	return &loopClock{now: loopsT0, registered: make(chan struct{}, 1024)}
}

func (c *loopClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *loopClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.delays = append(c.delays, d)
	if d <= 0 {
		ch <- c.now
	} else {
		c.timers = append(c.timers, loopTimer{when: c.now.Add(d), ch: ch})
	}
	c.registered <- struct{}{}
	return ch
}

func (c *loopClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	keep := c.timers[:0]
	for _, tm := range c.timers {
		if !tm.when.After(c.now) {
			tm.ch <- c.now
		} else {
			keep = append(keep, tm)
		}
	}
	c.timers = keep
}

func (c *loopClock) delaysFrom(i int) []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.delays[i:])
}

func (c *loopClock) delayCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.delays)
}

// loopRig holds the fake services the loops call and the getters the UI would change.
type loopRig struct {
	t     *testing.T
	clock *loopClock
	loops *Loops

	mu          sync.Mutex
	settings    Settings
	settingsErr error
	profileErr  error
	calls       map[string]int
	inFlight    map[string]int
	maxInFlight map[string]int
	cancelled   map[string]int
	errs        map[string]error
	block       map[string]chan struct{}
	getterCalls map[string]int
	entered     chan struct{}

	cancel  context.CancelFunc
	stopped bool
	done    chan error
}

func newLoopRig(t *testing.T) *loopRig {
	t.Helper()
	r := &loopRig{
		t:           t,
		clock:       newLoopClock(),
		settings:    DefaultSettings(),
		calls:       map[string]int{},
		inFlight:    map[string]int{},
		maxInFlight: map[string]int{},
		cancelled:   map[string]int{},
		errs:        map[string]error{},
		block:       map[string]chan struct{}{},
		getterCalls: map[string]int{},
		entered:     make(chan struct{}, 1024),
	}
	loops, err := NewLoops(LoopsConfig{
		Settings:     r.getSettings,
		ProfileReady: r.getProfile,
		Inventory:    r.call(JobInventory),
		Alerts:       r.call(JobAlerts),
		Drift:        r.call(JobDrift),
		Health:       healthStub{r},
		Clock:        r.clock,
	})
	if err != nil {
		t.Fatalf("NewLoops: %v", err)
	}
	r.loops = loops
	return r
}

func (r *loopRig) getSettings(context.Context) (Settings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getterCalls["settings"]++
	return r.settings, r.settingsErr
}

func (r *loopRig) getProfile(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getterCalls["profile"]++
	return r.profileErr
}

// call is a service callback: it counts calls and concurrency, optionally blocks, and returns the
// error the test configured for the job.
func (r *loopRig) call(name string) func(context.Context) error {
	return func(ctx context.Context) error {
		r.mu.Lock()
		r.calls[name]++
		r.inFlight[name]++
		r.maxInFlight[name] = max(r.maxInFlight[name], r.inFlight[name])
		blk, err := r.block[name], r.errs[name]
		r.mu.Unlock()
		select {
		case r.entered <- struct{}{}:
		default:
		}
		defer func() {
			r.mu.Lock()
			r.inFlight[name]--
			r.mu.Unlock()
		}()
		if blk != nil {
			select {
			case <-blk:
			case <-ctx.Done():
				r.mu.Lock()
				r.cancelled[name]++
				r.mu.Unlock()
				return ctx.Err()
			}
		}
		return err
	}
}

// healthStub is the F4-018 runner: it runs until its context is done.
type healthStub struct{ r *loopRig }

func (h healthStub) Run(ctx context.Context) error {
	h.r.mu.Lock()
	h.r.calls[JobHealth]++
	h.r.mu.Unlock()
	select {
	case h.r.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	h.r.mu.Lock()
	h.r.cancelled[JobHealth]++
	h.r.mu.Unlock()
	return ctx.Err()
}

func (r *loopRig) start() {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan error, 1)
	go func() { r.done <- r.loops.Run(ctx) }()
	r.t.Cleanup(func() {
		cancel()
		if r.stopped {
			return
		}
		select {
		case <-r.done:
		case <-time.After(guard):
		}
	})
}

// stop cancels the service and returns what Run returned, failing if it does not return.
func (r *loopRig) stop() error {
	r.t.Helper()
	r.cancel()
	r.stopped = true
	select {
	case err := <-r.done:
		return err
	case <-time.After(guard):
		r.t.Fatal("Run did not return after cancellation")
		return nil
	}
}

// waitTimers waits until n more After calls were registered: n jobs went idle.
func (r *loopRig) waitTimers(n int) {
	r.t.Helper()
	for range n {
		select {
		case <-r.clock.registered:
		case <-time.After(guard):
			r.t.Fatal("timed out waiting for a job to go idle")
		}
	}
}

// awaitCalls waits until the callback of name was entered n times.
func (r *loopRig) awaitCalls(name string, n int) {
	r.t.Helper()
	for r.count(name) < n {
		select {
		case <-r.entered:
		case <-time.After(guard):
			r.t.Fatalf("timed out waiting for %s call %d (have %d)", name, n, r.count(name))
		}
	}
}

func (r *loopRig) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[name]
}

func (r *loopRig) assertCalls(want map[string]int) {
	r.t.Helper()
	for _, name := range []string{JobInventory, JobAlerts, JobDrift, JobHealth} {
		if got := r.count(name); got != want[name] {
			r.t.Errorf("%s calls = %d, want %d", name, got, want[name])
		}
	}
}

func (r *loopRig) set(f func(*loopRig)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}

func (r *loopRig) status(name string) JobStatus {
	r.t.Helper()
	for _, s := range r.loops.Status() {
		if s.Job == name {
			return s
		}
	}
	r.t.Fatalf("no status for job %q", name)
	return JobStatus{}
}

// run drives the clock forward and waits for the jobs that were due to go idle again.
func (r *loopRig) advance(d time.Duration, idle int) {
	r.t.Helper()
	r.clock.Advance(d)
	r.waitTimers(idle)
}

func TestMonitorLoopsScheduleReadyJobsWithoutOverlap(t *testing.T) {
	r := newLoopRig(t)
	r.start()

	// First start: one round of every job, and the health runner started once.
	r.waitTimers(3)
	r.awaitCalls(JobHealth, 1)
	r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 1, JobDrift: 1, JobHealth: 1})

	// 60 s: only the alert evaluation (target interval) is due.
	r.advance(time.Minute, 1)
	r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 2, JobDrift: 1, JobHealth: 1})

	// 5 min in total: every job is due; a due job runs once, missed rounds are not replayed.
	r.advance(4*time.Minute, 3)
	r.assertCalls(map[string]int{JobInventory: 2, JobAlerts: 3, JobDrift: 2, JobHealth: 1})

	// A blocked inventory read does not overlap itself while the other jobs keep running.
	blk := make(chan struct{})
	r.set(func(r *loopRig) { r.block[JobInventory] = blk })
	r.advance(5*time.Minute, 2)
	r.awaitCalls(JobInventory, 3)
	r.advance(5*time.Minute, 2)
	r.assertCalls(map[string]int{JobInventory: 3, JobAlerts: 5, JobDrift: 4, JobHealth: 1})

	r.set(func(r *loopRig) { delete(r.block, JobInventory) })
	close(blk)
	// The overrun round is due at once: one more round, not several.
	r.waitTimers(2)
	r.assertCalls(map[string]int{JobInventory: 4, JobAlerts: 5, JobDrift: 4, JobHealth: 1})
	for _, name := range []string{JobInventory, JobAlerts, JobDrift, JobHealth} {
		if got := r.maxInFlight[name]; got > 1 {
			t.Errorf("%s ran %d at once", name, got)
		}
	}
}

func TestMonitorLoopsReadSettingsAndProfileNextCycle(t *testing.T) {
	r := newLoopRig(t)
	r.start()
	r.waitTimers(3)
	r.awaitCalls(JobHealth, 1)
	if got := r.clock.delaysFrom(0); !slices.Equal(sorted(got), []time.Duration{time.Minute, 5 * time.Minute, 5 * time.Minute}) {
		t.Fatalf("first-round delays = %v, want target 1m and inventory 5m twice", got)
	}

	// The UI changes the intervals: no restart, the next round of each job uses them.
	r.set(func(r *loopRig) {
		r.settings.InventoryInterval = 2 * time.Minute
		r.settings.TargetInterval = 30 * time.Second
	})
	from := r.clock.delayCount()
	r.advance(5*time.Minute, 3)
	if got := r.clock.delaysFrom(from); !slices.Equal(sorted(got), []time.Duration{30 * time.Second, 2 * time.Minute, 2 * time.Minute}) {
		t.Fatalf("second-round delays = %v, want alerts 30s and inventory/drift 2m", got)
	}

	// The profile getter is asked again before every inventory round, and its answer decides.
	r.mu.Lock()
	profile := r.getterCalls["profile"]
	r.mu.Unlock()
	if profile != 2 {
		t.Fatalf("profile getter calls = %d, want one per inventory round (2)", profile)
	}
	r.set(func(r *loopRig) { r.profileErr = k8s.ErrNotSet })
	r.advance(2*time.Minute, 3)
	r.assertCalls(map[string]int{JobInventory: 2, JobAlerts: 3, JobDrift: 3, JobHealth: 1})
	r.set(func(r *loopRig) { r.profileErr = nil })
	r.advance(2*time.Minute, 3)
	r.assertCalls(map[string]int{JobInventory: 3, JobAlerts: 4, JobDrift: 4, JobHealth: 1})
}

func sorted(d []time.Duration) []time.Duration {
	out := slices.Clone(d)
	slices.Sort(out)
	return out
}

func TestMonitorLoopsSourceFailureKeepsLastGood(t *testing.T) {
	for _, job := range []string{JobInventory, JobAlerts, JobDrift} {
		t.Run(job, func(t *testing.T) {
			r := newLoopRig(t)
			r.start()
			r.waitTimers(3)
			r.awaitCalls(JobHealth, 1)
			first := r.status(job)
			if first.State != StateFresh || !first.LastSuccess.Equal(loopsT0) {
				t.Fatalf("after the first round: %+v, want fresh at %v", first, loopsT0)
			}

			boom := fmt.Errorf("%s source: %w", job, errors.New("read failed"))
			r.set(func(r *loopRig) { r.errs[job] = boom })
			r.advance(5*time.Minute, 3)

			got := r.status(job)
			at := loopsT0.Add(5 * time.Minute)
			if got.State != StateStale || !got.LastSuccess.Equal(loopsT0) || !got.LastAttempt.Equal(at) || !errors.Is(got.Err, boom) {
				t.Fatalf("failed job status = %+v, want stale, last success %v, attempt %v, err %v", got, loopsT0, at, boom)
			}
			for _, other := range []string{JobInventory, JobAlerts, JobDrift} {
				if other == job {
					continue
				}
				if s := r.status(other); s.State != StateFresh || !s.LastSuccess.Equal(at) {
					t.Errorf("%s = %+v, want it to go on: fresh at %v", other, s, at)
				}
			}

			// A later full success replaces the failure.
			r.set(func(r *loopRig) { delete(r.errs, job) })
			r.advance(5*time.Minute, 3)
			if s := r.status(job); s.State != StateFresh || !s.LastSuccess.Equal(loopsT0.Add(10*time.Minute)) || s.Err != nil {
				t.Fatalf("recovered status = %+v, want fresh at +10m", s)
			}
		})
	}

	t.Run("never succeeded is unknown", func(t *testing.T) {
		r := newLoopRig(t)
		r.errs[JobInventory] = errors.New("boom")
		r.start()
		r.waitTimers(3)
		r.awaitCalls(JobHealth, 1)
		got := r.status(JobInventory)
		if got.State != StateUnknown || !got.LastSuccess.IsZero() || got.Err == nil {
			t.Fatalf("status = %+v, want unknown without a last success", got)
		}
		r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 1, JobDrift: 1, JobHealth: 1})
	})
}

func TestMonitorLoopsMissingConfigurationWaitsForValidSettings(t *testing.T) {
	t.Run("profile not set", func(t *testing.T) {
		r := newLoopRig(t)
		r.profileErr = k8s.ErrNotSet
		r.start()
		r.waitTimers(3)
		r.awaitCalls(JobHealth, 1)
		r.assertCalls(map[string]int{JobInventory: 0, JobAlerts: 1, JobDrift: 1, JobHealth: 1})
		got := r.status(JobInventory)
		if got.State != StateMissing || !errors.Is(got.Err, k8s.ErrNotSet) {
			t.Fatalf("status = %+v, want missing profile", got)
		}

		// Saved from the UI later: the next round reads it, no restart.
		r.set(func(r *loopRig) { r.profileErr = nil })
		r.advance(5*time.Minute, 3)
		r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 2, JobDrift: 2, JobHealth: 1})
		if s := r.status(JobInventory); s.State != StateFresh || s.Err != nil {
			t.Fatalf("status = %+v, want fresh once the profile exists", s)
		}
	})

	t.Run("profile unreadable", func(t *testing.T) {
		r := newLoopRig(t)
		bad := errors.New("database is locked")
		r.profileErr = bad
		r.start()
		r.waitTimers(3)
		r.awaitCalls(JobHealth, 1)
		r.assertCalls(map[string]int{JobInventory: 0, JobAlerts: 1, JobDrift: 1, JobHealth: 1})
		if got := r.status(JobInventory); got.State != StateError || !errors.Is(got.Err, bad) {
			t.Fatalf("status = %+v, want error state", got)
		}
	})

	t.Run("settings unreadable", func(t *testing.T) {
		r := newLoopRig(t)
		bad := errors.New("settings unreadable")
		r.settingsErr = bad
		r.start()
		r.waitTimers(3)
		r.awaitCalls(JobHealth, 1)
		// No settings, no interval, no external call: every job waits visibly.
		r.assertCalls(map[string]int{JobInventory: 0, JobAlerts: 0, JobDrift: 0, JobHealth: 1})
		for _, job := range []string{JobInventory, JobAlerts, JobDrift} {
			if got := r.status(job); got.State != StateError || !errors.Is(got.Err, bad) {
				t.Fatalf("%s status = %+v, want error state", job, got)
			}
		}
		r.advance(5*time.Minute, 3)
		r.assertCalls(map[string]int{JobInventory: 0, JobAlerts: 0, JobDrift: 0, JobHealth: 1})

		r.set(func(r *loopRig) { r.settingsErr = nil })
		r.advance(5*time.Minute, 3)
		r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 1, JobDrift: 1, JobHealth: 1})
		for _, job := range []string{JobInventory, JobAlerts, JobDrift} {
			if got := r.status(job); got.State != StateFresh || got.Err != nil {
				t.Fatalf("%s status = %+v, want fresh after the settings came back", job, got)
			}
		}
	})

	t.Run("last good is kept while settings are unreadable", func(t *testing.T) {
		r := newLoopRig(t)
		r.start()
		r.waitTimers(3)
		r.awaitCalls(JobHealth, 1)
		r.set(func(r *loopRig) { r.settingsErr = errors.New("settings unreadable") })
		r.advance(5*time.Minute, 3)
		got := r.status(JobDrift)
		if got.State != StateError || !got.LastSuccess.Equal(loopsT0) {
			t.Fatalf("status = %+v, want error with the last success %v kept", got, loopsT0)
		}
	})
}

func TestMonitorLoopsStopCancelsAllJobs(t *testing.T) {
	r := newLoopRig(t)
	blk := make(chan struct{}) // never closed: only cancellation can end the callbacks
	r.block[JobInventory], r.block[JobAlerts], r.block[JobDrift] = blk, blk, blk
	r.start()
	r.awaitCalls(JobInventory, 1)
	r.awaitCalls(JobAlerts, 1)
	r.awaitCalls(JobDrift, 1)
	r.awaitCalls(JobHealth, 1)

	if err := r.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	r.mu.Lock()
	for _, name := range []string{JobInventory, JobAlerts, JobDrift, JobHealth} {
		if r.cancelled[name] != 1 {
			t.Errorf("%s saw cancellation %d times, want 1", name, r.cancelled[name])
		}
	}
	r.mu.Unlock()

	// Nothing starts after the stop, whatever the clock does.
	r.clock.Advance(time.Hour)
	r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 1, JobDrift: 1, JobHealth: 1})
	if got := r.status(JobInventory); got.State == StateStale || got.State == StateFresh {
		t.Errorf("a cancelled round must not be recorded as a result: %+v", got)
	}

	t.Run("idle loops stop too", func(t *testing.T) {
		r := newLoopRig(t)
		r.start()
		r.waitTimers(3)
		r.awaitCalls(JobHealth, 1)
		if err := r.stop(); !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
		r.clock.Advance(time.Hour)
		r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 1, JobDrift: 1, JobHealth: 1})
	})

	t.Run("cancelled before start", func(t *testing.T) {
		r := newLoopRig(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := r.loops.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
		r.assertCalls(map[string]int{})
	})
}

func TestMonitorLoopsNeverApplyAccessOrPollCertificateMetadata(t *testing.T) {
	// The loops know exactly the ready read-only/local callbacks and nothing that applies access or
	// reads Certificate metadata: a new capability must show up here as a changed field list.
	var fields []string
	for f := range reflect.TypeFor[LoopsConfig]().Fields() {
		fields = append(fields, f.Name)
	}
	want := []string{"Settings", "ProfileReady", "Inventory", "Alerts", "Drift", "Health", "Clock"}
	if !slices.Equal(sorted2(fields), sorted2(want)) {
		t.Fatalf("LoopsConfig fields = %v, want %v", fields, want)
	}

	// Running every job for several rounds calls only those callbacks, and the health runner once.
	r := newLoopRig(t)
	r.start()
	r.waitTimers(3)
	r.awaitCalls(JobHealth, 1)
	for range 3 {
		r.advance(5*time.Minute, 3)
	}
	r.mu.Lock()
	var names []string
	for name := range r.calls {
		names = append(names, name)
	}
	r.mu.Unlock()
	if !slices.Equal(sorted2(names), sorted2([]string{JobInventory, JobAlerts, JobDrift, JobHealth})) {
		t.Fatalf("called %v, want exactly the four ready jobs", names)
	}
	if got := r.count(JobHealth); got != 1 {
		t.Fatalf("health runner started %d times, want once", got)
	}

	// A service that is not wired is a construction error, never a silently skipped job.
	if _, err := NewLoops(LoopsConfig{}); err == nil {
		t.Fatal("NewLoops with nothing wired returned no error")
	}
}

func sorted2(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// C-M1: the health job is not pre-marked fresh. It stays unknown until the runner reports a cycle,
// a reported cycle error shows it stale (or unknown before any success), and a good cycle moves the
// success time.
func TestMonitorLoopsHealthStateFollowsReportedCycles(t *testing.T) {
	r := newLoopRig(t)
	r.start()
	r.waitTimers(3)
	r.awaitCalls(JobHealth, 1)
	if got := r.status(JobHealth); got.State != StateUnknown || !got.LastSuccess.IsZero() {
		t.Fatalf("health before any cycle = %+v, want unknown with no success", got)
	}

	boom := errors.New("subjects unreadable")
	at := loopsT0.Add(time.Minute)
	r.loops.ReportHealthCycle(at, boom)
	if got := r.status(JobHealth); got.State != StateUnknown || !errors.Is(got.Err, boom) {
		t.Fatalf("health after a failed first cycle = %+v, want unknown with the error", got)
	}

	r.loops.ReportHealthCycle(at.Add(time.Minute), nil)
	if got := r.status(JobHealth); got.State != StateFresh || !got.LastSuccess.Equal(at.Add(time.Minute)) || got.Err != nil {
		t.Fatalf("health after a good cycle = %+v, want fresh", got)
	}

	r.loops.ReportHealthCycle(at.Add(2*time.Minute), boom)
	got := r.status(JobHealth)
	if got.State != StateStale || !got.LastSuccess.Equal(at.Add(time.Minute)) || !errors.Is(got.Err, boom) {
		t.Fatalf("health after a failed cycle = %+v, want stale keeping the last success", got)
	}
}

// F5 I4: Trigger runs the inventory, alert and drift jobs (and wakes the health runner) at once,
// without advancing the clock; a trigger that arrives while a round runs asks for one more round.
func TestMonitorLoopsTriggerRunsJobsNow(t *testing.T) {
	r := newLoopRig(t)
	r.start()
	r.waitTimers(3)
	// The health runner starts in its own goroutine; the three loop timers do not wait for it.
	r.awaitCalls(JobHealth, 1)
	r.assertCalls(map[string]int{JobInventory: 1, JobAlerts: 1, JobDrift: 1, JobHealth: 1})

	r.loops.Trigger()
	r.waitTimers(3)
	r.assertCalls(map[string]int{JobInventory: 2, JobAlerts: 2, JobDrift: 2, JobHealth: 1})

	// Nothing else is pending: no stray extra round.
	r.advance(time.Second, 0)
	r.assertCalls(map[string]int{JobInventory: 2, JobAlerts: 2, JobDrift: 2, JobHealth: 1})
}

type triggerStub struct {
	healthStub
	woke int
}

func (s *triggerStub) Trigger() { s.woke++ }

// The health runner is woken through the optional Trigger method.
func TestMonitorLoopsTriggerWakesHealthRunner(t *testing.T) {
	r := newLoopRig(t)
	stub := &triggerStub{healthStub: healthStub{r}}
	r.loops.cfg.Health = stub
	r.loops.Trigger()
	if stub.woke != 1 {
		t.Fatalf("health Trigger calls = %d, want 1", stub.woke)
	}
}

// F5 D1/A2: a job that could not start because the installation is unfinished is "missing", not an
// error; a round that returns ErrSetupPending (wrapped) shows the same.
func TestMonitorLoopsSetupPendingIsMissing(t *testing.T) {
	r := newLoopRig(t)
	r.set(func(r *loopRig) { r.errs[JobDrift] = fmt.Errorf("first import: %w", ErrSetupPending) })
	r.start()
	r.waitTimers(3)
	if got := r.status(JobDrift); got.State != StateMissing || !errors.Is(got.Err, ErrSetupPending) {
		t.Fatalf("drift = %+v, want missing with the setup-pending error", got)
	}
	r.loops.ReportHealthCycle(loopsT0, fmt.Errorf("probe policy: %w", ErrSetupPending))
	if got := r.status(JobHealth); got.State != StateMissing {
		t.Fatalf("health = %+v, want missing", got)
	}
	// Positive control: a plain failure is still stale/unknown, never missing.
	r.loops.ReportHealthCycle(loopsT0.Add(time.Minute), errors.New("boom"))
	if got := r.status(JobHealth); got.State == StateMissing {
		t.Fatalf("a plain failure was shown as missing: %+v", got)
	}
}
