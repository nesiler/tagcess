package health

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

var runnerT0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

// fakeClock is a manual clock: After registers a timer, Advance fires the due ones. Every After
// is announced on registered so a test can wait for the loop to be idle instead of sleeping.
type fakeClock struct {
	mu         sync.Mutex
	now        time.Time
	timers     []fakeTimer
	delays     []time.Duration
	registered chan struct{}
}

type fakeTimer struct {
	when time.Time
	ch   chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: runnerT0, registered: make(chan struct{}, 256)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.delays = append(c.delays, d)
	if d <= 0 {
		ch <- c.now
	} else {
		c.timers = append(c.timers, fakeTimer{when: c.now.Add(d), ch: ch})
	}
	c.registered <- struct{}{}
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
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

func (c *fakeClock) lastDelay() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delays[len(c.delays)-1]
}

// settingsBox is the settings getter the UI would change under the runner.
type settingsBox struct {
	mu    sync.Mutex
	s     monitor.Settings
	err   error
	calls int
}

func newSettingsBox() *settingsBox {
	return &settingsBox{s: monitor.DefaultSettings()}
}

func (b *settingsBox) get(context.Context) (monitor.Settings, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	return b.s, b.err
}

func (b *settingsBox) set(f func(*monitor.Settings)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f(&b.s)
}

func (b *settingsBox) fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.err = err
}

// fakeProber records every probe and its context, and tracks how many run at once.
type fakeProber struct {
	mu       sync.Mutex
	targets  []TargetRequest
	gates    []Request
	tlss     []TLSRequest
	budgets  []time.Duration // remaining context time when a probe started
	inflight int
	maxSeen  int
	started  int

	hold   func(n int) // optional: called with the 1-based start number
	target func(ctx context.Context, r TargetRequest) (TargetResult, error)
	gate   func(ctx context.Context, r Request) (GateResult, error)
	tls    func(ctx context.Context, r TLSRequest) (TLSObservation, error)
}

func (p *fakeProber) begin(ctx context.Context) {
	p.mu.Lock()
	p.inflight++
	if p.inflight > p.maxSeen {
		p.maxSeen = p.inflight
	}
	p.started++
	n := p.started
	if dl, ok := ctx.Deadline(); ok {
		p.budgets = append(p.budgets, time.Until(dl))
	}
	hold := p.hold
	p.mu.Unlock()
	if hold != nil {
		hold(n)
	}
}

func (p *fakeProber) end() {
	p.mu.Lock()
	p.inflight--
	p.mu.Unlock()
}

func (p *fakeProber) ProbeTarget(ctx context.Context, r TargetRequest) (TargetResult, error) {
	p.begin(ctx)
	defer p.end()
	p.mu.Lock()
	p.targets = append(p.targets, r)
	f := p.target
	p.mu.Unlock()
	if f != nil {
		return f(ctx, r)
	}
	return TargetResult{Protocol: ProtocolHTTP, Endpoint: fmt.Sprintf("%s:%d", r.Host, r.Port), Kind: KindHealthy, StatusCode: 200}, nil
}

func (p *fakeProber) ProbeGate(ctx context.Context, r Request) (GateResult, error) {
	p.begin(ctx)
	defer p.end()
	p.mu.Lock()
	p.gates = append(p.gates, r)
	f := p.gate
	p.mu.Unlock()
	if f != nil {
		return f(ctx, r)
	}
	return GateResult{Endpoint: fmt.Sprintf("%s:%d", r.Host, r.Port), Kind: GateLoginRedirect, StatusCode: 302}, nil
}

func (p *fakeProber) ProbeTLS(ctx context.Context, r TLSRequest) (TLSObservation, error) {
	p.begin(ctx)
	defer p.end()
	p.mu.Lock()
	p.tlss = append(p.tlss, r)
	f := p.tls
	p.mu.Unlock()
	if f != nil {
		return f(ctx, r)
	}
	return goodTLS(r.ServerName), nil
}

func (p *fakeProber) counts() (target, gate, tls int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.targets), len(p.gates), len(p.tlss)
}

func (p *fakeProber) max() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxSeen
}

var leafNotAfter = runnerT0.Add(90 * 24 * time.Hour)

func goodTLS(host string) TLSObservation {
	return TLSObservation{Host: host, ObservedAt: runnerT0, Reachable: true, Verification: TLSVerified,
		Leaf: &TLSLeaf{Fingerprint: "ab12", NotAfter: leafNotAfter}}
}

// fakeGates stands in for the F4-020 measurer: the runner only calls it and reports its evidence.
type fakeGates struct {
	mu    sync.Mutex
	calls []k8s.GateCandidate
	f     func(c k8s.GateCandidate) (GateEvidence, error)
}

func (g *fakeGates) Measure(_ context.Context, c k8s.GateCandidate) (GateEvidence, error) {
	g.mu.Lock()
	g.calls = append(g.calls, c)
	f := g.f
	g.mu.Unlock()
	if f != nil {
		return f(c)
	}
	return GateEvidence{Result: PathAnswered, Freshness: FreshnessFresh, LastGoodAt: runnerT0, Persisted: true}, nil
}

func (g *fakeGates) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

func testSubject(i int) Subject {
	host := fmt.Sprintf("app%d.example.test", i)
	return Subject{
		Site: fmt.Sprintf("site%d", i),
		Host: host,
		Target: &TargetRequest{Request: Request{
			Host: fmt.Sprintf("10.20.0.%d", 10+i), Port: 8080, ServerName: host,
		}},
		Gate: &Request{Host: "10.20.0.2", Port: 443, TLS: true, ServerName: host},
		TLS:  &TLSRequest{Host: "10.20.0.2", Port: 443, ServerName: host},
	}
}

func testCandidate(i int) k8s.GateCandidate {
	return k8s.GateCandidate{Site: fmt.Sprintf("site%d", i), Host: fmt.Sprintf("app%d.example.test", i),
		Address: fmt.Sprintf("10.20.0.%d", 50+i), Port: 80}
}

type runnerEnv struct {
	t        *testing.T
	st       *store.Store
	clock    *fakeClock
	settings *settingsBox
	prober   *fakeProber
	gates    *fakeGates
	reports  chan CycleReport
	subjects []Subject
	cands    []k8s.GateCandidate
	runner   *Runner
	obs      Observations // what the Store writes through; the real queries unless a test swaps it
}

const testVantage = "tagcess-net"

func newRunnerEnv(t *testing.T, subjects int, cands int) *runnerEnv {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &runnerEnv{t: t, st: st, clock: newFakeClock(), settings: newSettingsBox(), prober: &fakeProber{},
		gates: &fakeGates{}, reports: make(chan CycleReport, 128), obs: st.Queries()}
	for i := 1; i <= subjects; i++ {
		e.subjects = append(e.subjects, testSubject(i))
	}
	for i := 1; i <= cands; i++ {
		e.cands = append(e.cands, testCandidate(i))
	}
	return e
}

func (e *runnerEnv) build() *Runner {
	e.runner = NewRunner(Config{
		Settings:   e.settings.get,
		Subjects:   func(context.Context) ([]Subject, error) { return e.subjects, nil },
		Candidates: func(context.Context) ([]k8s.GateCandidate, error) { return e.cands, nil },
		Prober:     e.prober,
		Gates:      e.gates,
		Store:      NewStore(e.obs),
		Clock:      e.clock,
		Vantage:    testVantage,
		Report:     func(r CycleReport) { e.reports <- r },
	})
	return e.runner
}

// start runs the runner until the test ends.
func (e *runnerEnv) start() (cancel context.CancelFunc, done <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	d := make(chan error, 1)
	r := e.build()
	finished := make(chan struct{})
	go func() {
		d <- r.Run(ctx)
		close(finished)
	}()
	e.t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			e.t.Error("runner did not stop after cancel")
		}
	})
	return cancel, d
}

// cycles waits for n cycle reports.
func (e *runnerEnv) cycles(n int) []CycleReport {
	e.t.Helper()
	var out []CycleReport
	for len(out) < n {
		select {
		case r := <-e.reports:
			out = append(out, r)
		case <-time.After(10 * time.Second):
			e.t.Fatalf("timed out waiting for cycle reports: got %d of %d", len(out), n)
		}
	}
	return out
}

// idle waits until the loop has gone back to waiting on the clock.
func (e *runnerEnv) idle() {
	e.t.Helper()
	select {
	case <-e.clock.registered:
	case <-time.After(10 * time.Second):
		e.t.Fatal("timed out waiting for the loop to wait on the clock")
	}
}

func kinds(rs []CycleReport) map[CycleKind]int {
	m := map[CycleKind]int{}
	for _, r := range rs {
		m[r.Kind]++
	}
	return m
}

func TestHealthRunnerSchedulesTargetGatesAndTLSIndependently(t *testing.T) {
	e := newRunnerEnv(t, 3, 2)
	e.settings.set(func(s *monitor.Settings) { s.Concurrency = 2 })
	// The first three probes rendezvous: with a limit of 2 only two can be in flight, so the third
	// waits out the timeout and the peak stays exactly 2.
	var arrived atomic.Int32
	ready := make(chan struct{})
	e.prober.hold = func(n int) {
		if n > 3 {
			return
		}
		if arrived.Add(1) == 3 {
			close(ready)
		}
		select {
		case <-ready:
		case <-time.After(200 * time.Millisecond):
		}
	}
	e.start()

	first := e.cycles(2)
	e.idle()
	if k := kinds(first); k[CycleTarget] != 1 || k[CycleTLS] != 1 {
		t.Fatalf("first cycles = %v, want one target and one tls", k)
	}
	tg, ga, tl := e.prober.counts()
	if tg != 3 || ga != 3 || tl != 3 || e.gates.count() != 2 {
		t.Fatalf("after start: target=%d gate=%d tls=%d two-gate=%d, want 3/3/3/2", tg, ga, tl, e.gates.count())
	}
	if got := e.prober.max(); got != 2 {
		t.Fatalf("peak concurrent probes = %d, want exactly the limit 2", got)
	}

	// The target interval alone: TLS (6 h) does not run again.
	e.clock.Advance(60 * time.Second)
	next := e.cycles(1)
	e.idle()
	if next[0].Kind != CycleTarget {
		t.Fatalf("after 60s ran %v, want the target cycle only", next[0].Kind)
	}
	tg, ga, tl = e.prober.counts()
	if tg != 6 || ga != 6 || tl != 3 || e.gates.count() != 4 {
		t.Fatalf("after 60s: target=%d gate=%d tls=%d two-gate=%d, want 6/6/3/4", tg, ga, tl, e.gates.count())
	}

	// A long gap runs each due cycle once; missed cycles are not replayed.
	e.clock.Advance(6 * time.Hour)
	both := e.cycles(2)
	e.idle()
	if k := kinds(both); k[CycleTarget] != 1 || k[CycleTLS] != 1 {
		t.Fatalf("after 6h cycles = %v, want one target and one tls", k)
	}
	tg, ga, tl = e.prober.counts()
	if tg != 9 || ga != 9 || tl != 6 || e.gates.count() != 6 {
		t.Fatalf("after 6h: target=%d gate=%d tls=%d two-gate=%d, want 9/9/6/6", tg, ga, tl, e.gates.count())
	}
	for _, c := range e.prober.budgets {
		if c <= 0 || c > 5*time.Second {
			t.Fatalf("a probe ran with %v left, want within the 5s timeout", c)
		}
	}
}

func TestHealthRunnerReadsUpdatedSettings(t *testing.T) {
	e := newRunnerEnv(t, 1, 0)
	e.start()
	e.cycles(2)
	e.idle()
	if got := e.prober.targets[0]; got.Path != "/" || !reflect.DeepEqual(got.Statuses, []int{200}) {
		t.Fatalf("first target request = path %q statuses %v, want the defaults", got.Path, got.Statuses)
	}

	// The UI changes the settings; no restart.
	e.settings.set(func(s *monitor.Settings) {
		s.TargetInterval = 30 * time.Second
		s.Path = "/ready"
		s.ExpectedStatuses = []int{200, 204}
		s.Timeout = 2 * time.Second
	})
	e.clock.Advance(60 * time.Second)
	e.cycles(1)
	e.idle()
	e.prober.mu.Lock()
	got, gate, budget := e.prober.targets[1], e.prober.gates[1], e.prober.budgets[len(e.prober.budgets)-1]
	e.prober.mu.Unlock()
	if got.Path != "/ready" || !reflect.DeepEqual(got.Statuses, []int{200, 204}) || gate.Path != "/ready" {
		t.Fatalf("second cycle: target %q %v gate %q, want the updated path and statuses", got.Path, got.Statuses, gate.Path)
	}
	if budget <= 0 || budget > 2*time.Second {
		t.Fatalf("second cycle probe had %v left, want within the updated 2s timeout", budget)
	}
	if d := e.clock.lastDelay(); d != 30*time.Second {
		t.Fatalf("next wait = %v, want the updated 30s interval", d)
	}

	// An unreadable setting skips the cycle and keeps the last known interval; nothing is probed.
	before, _, _ := e.prober.counts()
	e.settings.fail(errors.New("settings unreadable"))
	e.clock.Advance(30 * time.Second)
	rep := e.cycles(1)
	e.idle()
	if rep[0].Err == nil || len(rep[0].Attempts) != 0 {
		t.Fatalf("report = %+v, want an error and no outcomes", rep[0])
	}
	after, _, _ := e.prober.counts()
	if after != before {
		t.Fatalf("probes ran with unreadable settings: %d -> %d", before, after)
	}
	if d := e.clock.lastDelay(); d != 30*time.Second {
		t.Fatalf("wait after a settings error = %v, want the last known 30s", d)
	}
}

func rowOf(t *testing.T, st *store.Store, category, site, host, endpoint, sni, path string) db.Observation {
	t.Helper()
	row, err := st.Queries().GetObservationByKey(context.Background(), db.GetObservationByKeyParams{
		Category: category, Site: site, Host: host, Source: SourceNetProbe, Vantage: testVantage,
		Endpoint: endpoint, Sni: sni, Path: path,
	})
	if err != nil {
		t.Fatalf("observation %s %s: %v", category, endpoint, err)
	}
	return row
}

func outcomeOf(t *testing.T, rs []CycleReport, category string) Attempt {
	t.Helper()
	for _, r := range rs {
		for _, o := range r.Attempts {
			if o.Category == category {
				return o
			}
		}
	}
	t.Fatalf("no %s outcome in %+v", category, rs)
	return Attempt{}
}

func TestHealthRunnerFailedProbeKeepsLastGood(t *testing.T) {
	e := newRunnerEnv(t, 1, 1)
	e.settings.set(func(s *monitor.Settings) { s.TargetInterval, s.TLSInterval = time.Minute, time.Minute })
	sub := e.subjects[0]
	e.start()

	// Cycle 1: everything answers as expected.
	rs := e.cycles(2)
	e.idle()
	tgt := rowOf(t, e.st, "target", sub.Site, sub.Host, "10.20.0.11:8080", sub.Host, "/")
	gate := rowOf(t, e.st, "caddy_gate", sub.Site, sub.Host, "10.20.0.2:443", sub.Host, "/")
	tls := rowOf(t, e.st, "tls", sub.Site, sub.Host, "10.20.0.2:443", sub.Host, "")
	good := formatTime(runnerT0)
	if tgt.ObservedAt != good || tgt.HttpStatus != 200 || tgt.Success != 1 ||
		gate.ObservedAt != good || gate.GateClass != "login_redirect" || gate.HttpStatus != 302 ||
		tls.ObservedAt != good || tls.TlsNotAfter != formatTime(leafNotAfter) || tls.TlsFingerprint != "ab12" {
		t.Fatalf("cycle 1 rows are not the good evidence:\n%+v\n%+v\n%+v", tgt, gate, tls)
	}
	if o := outcomeOf(t, rs, "target"); o.Freshness != FreshnessFresh || !o.Persisted || o.Err != nil {
		t.Fatalf("cycle 1 target outcome = %+v, want fresh and persisted", o)
	}

	// Cycle 2: a negative target answer, an unreachable gate, a TLS timeout and a stale two-gate.
	e.prober.mu.Lock()
	e.prober.target = func(context.Context, TargetRequest) (TargetResult, error) {
		return TargetResult{Kind: KindUnexpectedStatus, StatusCode: 503}, nil
	}
	e.prober.gate = func(context.Context, Request) (GateResult, error) {
		return GateResult{Kind: GateUnreachable}, nil
	}
	e.prober.tls = func(_ context.Context, r TLSRequest) (TLSObservation, error) {
		return TLSObservation{Host: r.ServerName, Verification: TLSUnknown, Err: "timeout"}, nil
	}
	e.prober.mu.Unlock()
	e.gates.f = func(k8s.GateCandidate) (GateEvidence, error) {
		return GateEvidence{Result: PathTimeout, Freshness: FreshnessStale, LastGoodAt: runnerT0, Persisted: true}, nil
	}
	e.clock.Advance(time.Minute)
	rs = e.cycles(2)
	e.idle()
	later := formatTime(runnerT0.Add(time.Minute))
	tgt = rowOf(t, e.st, "target", sub.Site, sub.Host, "10.20.0.11:8080", sub.Host, "/")
	gate = rowOf(t, e.st, "caddy_gate", sub.Site, sub.Host, "10.20.0.2:443", sub.Host, "/")
	tls = rowOf(t, e.st, "tls", sub.Site, sub.Host, "10.20.0.2:443", sub.Host, "")
	if tgt.ObservedAt != good || tgt.HttpStatus != 200 || tgt.LastAttemptAt != later || tgt.Success != 0 ||
		tgt.LastResult != "unexpected_status" || tgt.LastHttpStatus != 503 {
		t.Fatalf("failed target kept/changed wrong: %+v", tgt)
	}
	if gate.ObservedAt != good || gate.GateClass != "login_redirect" || gate.LastResult != "unreachable" || gate.Success != 0 {
		t.Fatalf("failed gate kept/changed wrong: %+v", gate)
	}
	if tls.ObservedAt != good || tls.TlsNotAfter != formatTime(leafNotAfter) || tls.LastResult != "timeout" || tls.Success != 0 || tls.LastAttemptAt != later {
		t.Fatalf("failed tls kept/changed wrong: %+v", tls)
	}
	for _, cat := range []string{"target", "caddy_gate", "tls"} {
		o := outcomeOf(t, rs, cat)
		if o.Freshness != FreshnessStale || !o.LastGoodAt.Equal(runnerT0) || !o.Persisted || o.Result == "ok" {
			t.Fatalf("%s outcome = %+v, want stale with the old good time", cat, o)
		}
	}
	if o := outcomeOf(t, rs, "config_risk"); o.Freshness != FreshnessStale || !o.LastGoodAt.Equal(runnerT0) || o.Result != string(PathTimeout) {
		t.Fatalf("two-gate outcome = %+v, want the measurer's stale evidence passed through", o)
	}

	// Cycle 3: refusals and an unverifiable leaf. The verified expiry stays; the diagnostic leaf is
	// the attempt's own.
	diag := runnerT0.Add(-24 * time.Hour)
	e.prober.mu.Lock()
	e.prober.target = func(context.Context, TargetRequest) (TargetResult, error) { return TargetResult{}, ErrRejected }
	e.prober.gate = func(context.Context, Request) (GateResult, error) { return GateResult{}, netpolicy.ErrDenied }
	e.prober.tls = func(_ context.Context, r TLSRequest) (TLSObservation, error) {
		return TLSObservation{Host: r.ServerName, Reachable: true, Verification: TLSFailed, Reason: TLSReasonExpired,
			Diagnostic: true, Leaf: &TLSLeaf{Fingerprint: "dead", NotAfter: diag}}, nil
	}
	e.prober.mu.Unlock()
	e.clock.Advance(time.Minute)
	rs = e.cycles(2)
	e.idle()
	tgt = rowOf(t, e.st, "target", sub.Site, sub.Host, "10.20.0.11:8080", sub.Host, "/")
	gate = rowOf(t, e.st, "caddy_gate", sub.Site, sub.Host, "10.20.0.2:443", sub.Host, "/")
	tls = rowOf(t, e.st, "tls", sub.Site, sub.Host, "10.20.0.2:443", sub.Host, "")
	if tgt.LastResult != "guard_rejected" || tgt.ObservedAt != good || gate.LastResult != "guard_rejected" || gate.ObservedAt != good {
		t.Fatalf("refused probes: target %+v gate %+v", tgt, gate)
	}
	if tls.LastResult != "tls_unverified" || tls.LastTlsVerifyError != TLSReasonExpired || tls.LastTlsNotAfter != formatTime(diag) ||
		tls.TlsNotAfter != formatTime(leafNotAfter) || tls.TlsFingerprint != "ab12" || tls.ObservedAt != good {
		t.Fatalf("unverifiable leaf: %+v", tls)
	}
	if o := outcomeOf(t, rs, "tls"); o.Freshness != FreshnessStale || o.Result != "tls_unverified" {
		t.Fatalf("tls outcome = %+v, want stale tls_unverified", o)
	}
}

func TestHealthRunnerMaintenanceAndShutdown(t *testing.T) {
	t.Run("maintenance still measures", func(t *testing.T) {
		e := newRunnerEnv(t, 1, 0)
		e.subjects[0].Maintenance = true
		e.start()
		rs := e.cycles(2)
		e.idle()
		tg, ga, tl := e.prober.counts()
		if tg != 1 || ga != 1 || tl != 1 {
			t.Fatalf("maintenance site probes target=%d gate=%d tls=%d, want 1/1/1", tg, ga, tl)
		}
		o := outcomeOf(t, rs, "target")
		if !o.Maintenance || !o.Persisted || o.Freshness != FreshnessFresh {
			t.Fatalf("maintenance outcome = %+v, want measured and marked for alarm suppression", o)
		}
		sub := e.subjects[0]
		if row := rowOf(t, e.st, "target", sub.Site, sub.Host, "10.20.0.11:8080", sub.Host, "/"); row.Success != 1 {
			t.Fatalf("maintenance measurement not stored: %+v", row)
		}
	})

	t.Run("cancel finishes in-flight probes and starts no more", func(t *testing.T) {
		e := newRunnerEnv(t, 3, 0)
		e.settings.set(func(s *monitor.Settings) { s.Concurrency = 1 })
		started := make(chan struct{})
		release := make(chan struct{})
		var ctxErrAfterRelease atomic.Value
		e.prober.target = func(ctx context.Context, r TargetRequest) (TargetResult, error) {
			close(started) // only the first call ever gets here: nothing else may start
			<-release
			ctxErrAfterRelease.Store(fmt.Sprint(ctx.Err()))
			return TargetResult{Protocol: ProtocolHTTP, Endpoint: "10.20.0.11:8080", Kind: KindHealthy, StatusCode: 200}, nil
		}
		cancel, done := e.start()
		<-started
		cancel()
		select {
		case err := <-done:
			t.Fatalf("Run returned (%v) while a probe was still in flight", err)
		default:
		}
		close(release)
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after the in-flight probe finished")
		}
		if got := ctxErrAfterRelease.Load(); got != "<nil>" {
			t.Fatalf("in-flight probe context error = %v, want none: cancel must not abort it", got)
		}
		tg, ga, tl := e.prober.counts()
		if tg != 1 || ga != 0 || tl != 0 {
			t.Fatalf("probes after cancel target=%d gate=%d tls=%d, want only the one in flight", tg, ga, tl)
		}
		sub := e.subjects[0]
		if row := rowOf(t, e.st, "target", sub.Site, sub.Host, "10.20.0.11:8080", sub.Host, "/"); row.Success != 1 {
			t.Fatalf("in-flight result was not stored: %+v", row)
		}
	})

	t.Run("cancel while waiting stops without another cycle", func(t *testing.T) {
		e := newRunnerEnv(t, 1, 0)
		cancel, done := e.start()
		e.cycles(2)
		e.idle()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not stop while waiting on the clock")
		}
		if tg, _, _ := e.prober.counts(); tg != 1 {
			t.Fatalf("target probes = %d, want 1", tg)
		}
	})
}

// recordingObs counts the writes that reach it and fails every observation write.
type recordingObs struct {
	err   error
	calls atomic.Int32
}

func (r *recordingObs) UpsertObservationGood(context.Context, db.UpsertObservationGoodParams) (db.Observation, error) {
	r.calls.Add(1)
	return db.Observation{}, r.err
}

func (r *recordingObs) UpsertObservationFailed(context.Context, db.UpsertObservationFailedParams) (db.Observation, error) {
	r.calls.Add(1)
	return db.Observation{}, r.err
}

func (r *recordingObs) GetObservationByKey(context.Context, db.GetObservationByKeyParams) (db.Observation, error) {
	return db.Observation{}, sql.ErrNoRows
}

func (r *recordingObs) ListProbeObservationsByVantage(context.Context, string) ([]db.Observation, error) {
	return nil, nil
}

func (r *recordingObs) DeleteObservation(context.Context, int64) (int64, error) { return 0, nil }

func TestHealthStoreFailureIsVisible(t *testing.T) {
	e := newRunnerEnv(t, 1, 1)
	boom := errors.New("disk full")
	rec := &recordingObs{err: boom}
	e.obs = rec
	before, err := e.st.Queries().ListSettings(context.Background())
	if err != nil {
		t.Fatalf("ListSettings: %v", err)
	}
	// The measurer reports an attempt it could not record.
	e.gates.f = func(k8s.GateCandidate) (GateEvidence, error) {
		return GateEvidence{Result: PathAnswered}, boom
	}
	e.start()
	rs := e.cycles(2)
	e.idle()

	if rec.calls.Load() == 0 {
		t.Fatal("the store was never asked to write")
	}
	for _, cat := range []string{"target", "caddy_gate", "tls", "config_risk"} {
		o := outcomeOf(t, rs, cat)
		if o.Persisted || o.Freshness == FreshnessFresh || o.Err == nil {
			t.Fatalf("%s outcome = %+v, want not persisted, not fresh, with the error", cat, o)
		}
	}
	if o := outcomeOf(t, rs, "target"); !errors.Is(o.Err, boom) {
		t.Fatalf("target error = %v, want the store error", o.Err)
	}
	// Nothing about access changed: the settings table is as it was.
	after, err := e.st.Queries().ListSettings(context.Background())
	if err != nil {
		t.Fatalf("ListSettings: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("settings changed by a failed observation write:\n%v\n%v", before, after)
	}
}

func probeRows(t *testing.T, e *runnerEnv, site string) []db.Observation {
	t.Helper()
	rows, err := e.st.Queries().ListObservationsBySite(context.Background(), site)
	if err != nil {
		t.Fatalf("ListObservationsBySite: %v", err)
	}
	return rows
}

// C-H1/B-H-3: a key the runner no longer measures (a changed path, a target that is gone) is deleted
// after a completed cycle, so the old row cannot mask the new one; other vantages stay.
func TestHealthRunnerPrunesKeysItNoLongerMeasures(t *testing.T) {
	e := newRunnerEnv(t, 2, 0)
	// A row of another vantage and one of the two-gate source must survive the cleanup.
	other := Key{Category: "target", Site: "site1", Host: "app1.example.test", Source: SourceNetProbe,
		Vantage: "other-net", Endpoint: "10.20.0.11:8080", SNI: "app1.example.test", Path: "/"}
	if _, err := NewStore(e.st.Queries()).RecordGood(context.Background(), other, runnerT0, Good{HTTPStatus: 200}); err != nil {
		t.Fatalf("seed other vantage: %v", err)
	}
	e.start()
	e.cycles(2)
	e.idle()
	count := func(site, category, path string) int {
		n := 0
		for _, r := range probeRows(t, e, site) {
			if r.Category == category && r.Path == path && r.Vantage == testVantage {
				n++
			}
		}
		return n
	}
	if count("site1", "target", "/") != 1 {
		t.Fatalf("the first cycle left no target row for path /: %+v", probeRows(t, e, "site1"))
	}

	// The check path changes: the next cycle writes the new key and drops the old one.
	e.settings.set(func(s *monitor.Settings) { s.Path = "/healthz" })
	e.clock.Advance(60 * time.Second)
	e.cycles(1)
	e.idle()
	if count("site1", "target", "/healthz") != 1 || count("site1", "target", "/") != 0 {
		t.Fatalf("after the path change: new=%d old=%d, want 1 and 0", count("site1", "target", "/healthz"), count("site1", "target", "/"))
	}
	if count("site1", "caddy_gate", "/healthz") != 1 || count("site1", "caddy_gate", "/") != 0 {
		t.Fatalf("the gate row was not moved to the new path")
	}
	foreign := false
	for _, r := range probeRows(t, e, "site1") {
		foreign = foreign || r.Vantage == "other-net"
	}
	if !foreign {
		t.Fatal("a row of another vantage was deleted")
	}

	// A site that is no longer listed loses its rows (target cycle and, later, the tls cycle).
	e.subjects = e.subjects[:1]
	e.clock.Advance(6 * time.Hour)
	e.cycles(2)
	e.idle()
	for _, r := range probeRows(t, e, "site2") {
		if r.Vantage == testVantage {
			t.Fatalf("a removed site kept its row: %+v", r)
		}
	}
	if len(probeRows(t, e, "site1")) == 0 {
		t.Fatal("the listed site lost its rows")
	}
}

// A failed site-list read prunes nothing: the last state stays.
func TestHealthRunnerKeepsRowsWhenSubjectsCannotBeRead(t *testing.T) {
	e := newRunnerEnv(t, 1, 0)
	e.start()
	e.cycles(2)
	e.idle()
	before := len(probeRows(t, e, "site1"))
	r := NewRunner(Config{
		Settings: e.settings.get, Prober: e.prober, Store: NewStore(e.obs), Clock: e.clock, Vantage: testVantage,
		Subjects: func(context.Context) ([]Subject, error) { return nil, errors.New("sites unreadable") },
	})
	if _, err := r.cycle(context.Background(), CycleTarget, monitor.DefaultSettings()); err == nil {
		t.Fatal("cycle err = nil, want the site list error")
	}
	if got := len(probeRows(t, e, "site1")); got != before {
		t.Fatalf("rows = %d after an unreadable site list, want %d", got, before)
	}
}

// A role site's gate that answers an anonymous request with 2xx is not enforcing: it is a failure
// (gate_open), never a healthy gate. An open site keeps today's behaviour.
func TestHealthRunnerGateOpenOnRoleSiteIsFailure(t *testing.T) {
	cases := []struct {
		name        string
		kind        string
		template    string
		wantOK      bool
		wantResult  string
		wantSuccess int64
	}{
		{"role site answering 200", site.KindRole, "", false, "gate_open", 0},
		{"system site answering 200", site.KindSystem, "", false, "gate_open", 0},
		{"tagcess template answering 200 (positive control)", site.KindSystem, site.TemplateTagcess, false, "gate_open", 0},
		{"open site answering 200 (positive control)", site.KindOpen, "", true, "ok", 1},
		{"headscale template answering 200 (open by design)", site.KindSystem, site.TemplateHeadscale, true, "ok", 1},
		{"zitadel template answering 200 (open by design)", site.KindSystem, site.TemplateZitadel, true, "ok", 1},
		{"wireguard_ui template answering 200 (open by design)", site.KindSystem, site.TemplateWireGuardUI, true, "ok", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRunnerEnv(t, 1, 0)
			e.subjects[0].Kind = tc.kind
			e.subjects[0].Template = tc.template
			e.prober.gate = func(context.Context, Request) (GateResult, error) {
				return GateResult{Kind: GateAnswered, StatusCode: 200}, nil
			}
			sub := e.subjects[0]
			e.start()
			rs := e.cycles(2)
			e.idle()
			gate := rowOf(t, e.st, "caddy_gate", sub.Site, sub.Host, "10.20.0.2:443", sub.Host, "/")
			if gate.Success != tc.wantSuccess {
				t.Fatalf("gate row = %+v, want success=%d", gate, tc.wantSuccess)
			}
			if !tc.wantOK && gate.LastResult != tc.wantResult {
				t.Fatalf("gate last result = %q, want %q", gate.LastResult, tc.wantResult)
			}
			if o := outcomeOf(t, rs, "caddy_gate"); o.Result != tc.wantResult {
				t.Fatalf("gate outcome = %+v, want result %q", o, tc.wantResult)
			}
		})
	}
	if text, ok := FailureText("gate_open"); !ok || text == "" {
		t.Errorf("FailureText(gate_open) = %q, %v", text, ok)
	}
}

// A cancelled cycle says nothing about the sources: it is not reported (M3).
func TestHealthRunnerCancelledCycleIsNotReported(t *testing.T) {
	e := newRunnerEnv(t, 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	base := e.settings.get
	cfgSettings := func(c context.Context) (monitor.Settings, error) {
		cancel() // the cycle starts, then the context is cancelled under it
		return base(c)
	}
	r := NewRunner(Config{
		Settings: cfgSettings,
		Subjects: func(context.Context) ([]Subject, error) { return e.subjects, nil },
		Prober:   e.prober, Store: NewStore(e.obs), Clock: e.clock, Vantage: testVantage,
		Report: func(rep CycleReport) { e.reports <- rep },
	})
	if err := r.Run(ctx); err == nil {
		t.Fatal("Run returned nil after cancel")
	}
	select {
	case rep := <-e.reports:
		t.Fatalf("a cancelled cycle was reported: %+v", rep)
	default:
	}
}

// F5 I4: Trigger starts a cycle of every kind at once, without advancing the clock.
func TestHealthRunnerTriggerRunsDueCyclesNow(t *testing.T) {
	e := newRunnerEnv(t, 1, 0)
	e.start()
	e.cycles(2)
	e.idle()

	e.runner.Trigger()
	got := e.cycles(2)
	e.idle()
	if k := kinds(got); k[CycleTarget] != 1 || k[CycleTLS] != 1 {
		t.Fatalf("after Trigger cycles = %v, want one target and one tls", k)
	}
}
