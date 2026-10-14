package health

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/site"
)

// This file schedules the F4 measurements (F4-018, K-02, P-02, R3 B-06, ADR 0032 proposed): the
// target and Caddy gate probes (F4-015), the presented leaf (F4-016) and the F4-020 two-gate
// measurement. One loop reads the settings at the start of every cycle, so a change made in the UI
// applies to the next cycle without a restart. Probes of a cycle run under the settings'
// concurrency and timeout; the two-gate measurement runs in the target cycle and under the same
// bounds. The runner interprets nothing beyond "met the expectation or not": a failed probe writes
// only the attempt, so the last good evidence and its time stay, and a store failure is reported,
// never shown as recorded. Maintenance only labels an outcome for alarm suppression; the
// measurement continues. The runner never changes access settings.

// Clock is the time source: a fake in tests.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// Prober is the F4-014..016 probe set; *Transport satisfies it.
type Prober interface {
	ProbeTarget(ctx context.Context, req TargetRequest) (TargetResult, error)
	ProbeGate(ctx context.Context, req Request) (GateResult, error)
	ProbeTLS(ctx context.Context, req TLSRequest) (TLSObservation, error)
}

// Measurer is the F4-020 two-gate measurement; *GateMeasurer satisfies it. The runner only calls
// it: candidates, claims and evidence belong to F4-020.
type Measurer interface {
	Measure(ctx context.Context, c k8s.GateCandidate) (GateEvidence, error)
}

// Subject is one site host to measure. Any of the three requests may be nil. The runner fills the
// HTTP path and expected statuses from the settings of the cycle; the rest comes from the caller
// (wiring a site list into Subjects is F4-031/F4-038).
type Subject struct {
	Site        string
	Host        string // site host: the Host/SNI name
	Kind        string // site kind; only site.KindOpen may answer an anonymous gate probe with 2xx
	Template    string // system template of a system site; the open-by-design ones may answer too
	Maintenance bool   // the site is in maintenance: measure, but mark outcomes for alarm suppression
	Target      *TargetRequest
	Gate        *Request
	TLS         *TLSRequest
}

// Config wires a Runner. Settings, Subjects, Prober, Store and Clock are required; Candidates and
// Gates together enable the two-gate measurement. Report, when set, receives every cycle.
type Config struct {
	Settings   func(ctx context.Context) (monitor.Settings, error)
	Subjects   func(ctx context.Context) ([]Subject, error)
	Candidates func(ctx context.Context) ([]k8s.GateCandidate, error)
	Prober     Prober
	Gates      Measurer
	Store      *Store
	Clock      Clock
	Vantage    string // where tagcess runs; part of every observation key
	Report     func(CycleReport)
}

// CycleKind names a cycle.
type CycleKind string

const (
	CycleTarget CycleKind = "target" // target, Caddy gate and two-gate measurements
	CycleTLS    CycleKind = "tls"    // presented leaf of every host
)

// Attempt is what one measurement attempt left. Result is "ok" or a failure class label.
// Persisted is false when the attempt is not in the observation store (a store error, or a
// measurement that was not run); Freshness is then empty and never "fresh".
type Attempt struct {
	Category    string // target, caddy_gate, tls or config_risk
	Site, Host  string
	Result      string
	Freshness   Freshness
	LastGoodAt  time.Time
	Persisted   bool
	Maintenance bool
	Err         error
}

// CycleReport is one finished cycle. Err is a settings or source read failure (the cycle, or its
// two-gate part, did not run); per-measurement failures are in Attempts.
type CycleReport struct {
	Kind     CycleKind
	At       time.Time
	Attempts []Attempt
	Err      error
}

// Runner runs the measurement loop. Run it once per Runner.
type Runner struct {
	cfg  Config
	wake chan struct{}
}

// NewRunner returns a Runner over cfg.
func NewRunner(cfg Config) *Runner { return &Runner{cfg: cfg, wake: make(chan struct{}, 1)} }

// Trigger makes the running loop start a due cycle of every kind now, instead of at its next
// interval (F5 I4: a saved policy or profile is measured without waiting). It never blocks;
// triggers that arrive while a cycle runs coalesce into one more.
func (r *Runner) Trigger() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run measures until ctx is cancelled and returns ctx.Err(). Cancelling lets the probes already
// running finish and be recorded (each is bounded by the timeout setting), starts nothing new and
// then returns. Each cycle is due at its start time plus the interval read at that start; a long
// gap runs a due cycle once and does not replay the missed ones.
func (r *Runner) Run(ctx context.Context) error {
	defaults := monitor.DefaultSettings()
	every := map[CycleKind]time.Duration{CycleTarget: defaults.TargetInterval, CycleTLS: defaults.TLSInterval}
	next := map[CycleKind]time.Time{}
	order := []CycleKind{CycleTarget, CycleTLS}
	for {
		now := r.cfg.Clock.Now()
		for _, kind := range order {
			if err := ctx.Err(); err != nil {
				return err
			}
			if due, ok := next[kind]; ok && now.Before(due) {
				continue
			}
			rep := CycleReport{Kind: kind, At: now}
			s, err := r.cfg.Settings(ctx)
			if err != nil {
				rep.Err = err // fail safe: no probes, keep the last known interval
			} else {
				if kind == CycleTarget {
					every[kind] = s.TargetInterval
				} else {
					every[kind] = s.TLSInterval
				}
				rep.Attempts, rep.Err = r.cycle(ctx, kind, s)
			}
			next[kind] = now.Add(every[kind])
			if r.cfg.Report != nil && ctx.Err() == nil { // a cancelled cycle says nothing about the sources
				r.cfg.Report(rep)
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		after := r.cfg.Clock.Now()
		wait := next[order[0]].Sub(after)
		for _, kind := range order {
			if d := next[kind].Sub(after); d < wait {
				wait = d
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.wake:
			clear(next) // every kind is due now
		case <-r.cfg.Clock.After(wait):
		}
	}
}

type job func(ctx context.Context) Attempt

// cycle builds the jobs of one cycle and runs them under the settings' bounds.
func (r *Runner) cycle(ctx context.Context, kind CycleKind, s monitor.Settings) ([]Attempt, error) {
	subjects, err := r.cfg.Subjects(ctx)
	if err != nil {
		return nil, err // keep the last state: nothing is probed or written
	}
	var jobs []job
	var cerr error
	keep := map[Key]bool{} // every key this cycle measures: the rest of the vantage's rows are stale
	add := func(j job, k Key) {
		jobs = append(jobs, j)
		keep[k] = true
	}
	for _, sub := range subjects {
		if kind == CycleTLS {
			if sub.TLS != nil {
				add(r.tlsJob(sub))
			}
			continue
		}
		if sub.Target != nil {
			add(r.targetJob(sub, s))
		}
		if sub.Gate != nil {
			add(r.gateJob(sub, s))
		}
	}
	if kind == CycleTarget && r.cfg.Candidates != nil && r.cfg.Gates != nil {
		var cands []k8s.GateCandidate
		if cands, cerr = r.cfg.Candidates(ctx); cerr == nil {
			maint := map[string]bool{}
			for _, sub := range subjects {
				maint[sub.Site] = sub.Maintenance
			}
			for _, c := range cands {
				jobs = append(jobs, r.twoGateJob(c, maint[c.Site]))
			}
		}
	}
	attempts := r.runJobs(ctx, s, jobs)
	if ctx.Err() == nil { // the site list was read completely: forget keys that are no longer measured
		categories := []string{"target", "caddy_gate"}
		if kind == CycleTLS {
			categories = []string{"tls"}
		}
		if perr := r.cfg.Store.Prune(context.WithoutCancel(ctx), r.cfg.Vantage, categories, keep); perr != nil {
			cerr = errors.Join(cerr, perr)
		}
	}
	return attempts, cerr
}

// runJobs runs jobs with at most s.Concurrency at once. A started job is never cancelled by ctx:
// it runs to its own timeout and its result is recorded. After cancellation no job is started.
func (r *Runner) runJobs(ctx context.Context, s monitor.Settings, jobs []job) []Attempt {
	out := make([]Attempt, len(jobs))
	started := make([]bool, len(jobs))
	sem := make(chan struct{}, s.Concurrency)
	var wg sync.WaitGroup
	for i, j := range jobs {
		sem <- struct{}{}
		if ctx.Err() != nil {
			<-sem
			break
		}
		started[i] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			jctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.Timeout)
			defer cancel()
			out[i] = j(jctx)
		}()
	}
	wg.Wait()
	done := out[:0]
	for i, o := range out {
		if started[i] {
			done = append(done, o)
		}
	}
	return done
}

func (r *Runner) targetJob(sub Subject, s monitor.Settings) (job, Key) {
	req := *sub.Target
	if req.Protocol != ProtocolTCP {
		req.Path, req.Statuses = s.Path, s.ExpectedStatuses
	}
	key := r.key("target", sub, req.Request, req.Path)
	j := func(ctx context.Context) Attempt {
		o := Attempt{Category: key.Category, Site: sub.Site, Host: sub.Host, Maintenance: sub.Maintenance}
		res, err := r.cfg.Prober.ProbeTarget(ctx, req)
		switch {
		case err != nil:
			return r.failed(ctx, o, key, probeErrorLabel(err), Failure{})
		case res.Kind == KindHealthy || res.Kind == KindTCPConnected:
			return r.good(ctx, o, key, Good{HTTPStatus: res.StatusCode})
		case res.Kind == KindUnknown:
			o.Result = string(res.Kind) // nothing was measured: record nothing
			return o
		}
		return r.failed(ctx, o, key, string(res.Kind), Failure{HTTPStatus: res.StatusCode})
	}
	return j, key
}

func (r *Runner) gateJob(sub Subject, s monitor.Settings) (job, Key) {
	req := *sub.Gate
	req.Path = s.Path
	key := r.key("caddy_gate", sub, req, req.Path)
	j := func(ctx context.Context) Attempt {
		o := Attempt{Category: key.Category, Site: sub.Site, Host: sub.Host, Maintenance: sub.Maintenance}
		res, err := r.cfg.Prober.ProbeGate(ctx, req)
		switch {
		case err != nil:
			return r.failed(ctx, o, key, probeErrorLabel(err), Failure{})
		case res.Kind == GateAnswered && sub.Kind != site.KindOpen && !answersAnonymously(sub.Template) && res.StatusCode >= 200 && res.StatusCode < 300:
			// the gate let an anonymous request through to a protected site: not enforcing
			return r.failed(ctx, o, key, "gate_open", Failure{HTTPStatus: res.StatusCode})
		case res.Kind == GateLoginRedirect || res.Kind == GateUnauthorized || res.Kind == GateForbidden || res.Kind == GateAnswered:
			return r.good(ctx, o, key, Good{HTTPStatus: res.StatusCode, GateClass: string(res.Kind)})
		case res.Kind == GateUnknown:
			o.Result = string(res.Kind)
			return o
		}
		return r.failed(ctx, o, key, string(res.Kind), Failure{HTTPStatus: res.StatusCode})
	}
	return j, key
}

// answersAnonymously is true for the system templates that Caddy renders without role control:
// headscale (OIDC and ts2021 clients), zitadel (the login) and wireguard_ui (its own login). The
// tagcess template is role-controlled and is not listed, so an open answer there stays a failure.
func answersAnonymously(template string) bool {
	switch template {
	case site.TemplateHeadscale, site.TemplateZitadel, site.TemplateWireGuardUI:
		return true
	}
	return false
}

func (r *Runner) tlsJob(sub Subject) (job, Key) {
	req := *sub.TLS
	key := r.key("tls", sub, Request{Host: req.Host, Port: req.Port, ServerName: req.ServerName}, "")
	j := func(ctx context.Context) Attempt {
		o := Attempt{Category: key.Category, Site: sub.Site, Host: sub.Host, Maintenance: sub.Maintenance}
		obs, err := r.cfg.Prober.ProbeTLS(ctx, req)
		if err != nil {
			return r.failed(ctx, o, key, probeErrorLabel(err), Failure{})
		}
		if obs.Healthy() {
			return r.good(ctx, o, key, Good{TLSNotAfter: obs.Leaf.NotAfter, TLSFinger: obs.Leaf.Fingerprint})
		}
		f := Failure{TLSVerify: obs.Reason}
		if obs.Leaf != nil { // the unverifiable leaf is the attempt's own diagnostic, never the good expiry
			f.TLSNotAfter, f.TLSFinger = obs.Leaf.NotAfter, obs.Leaf.Fingerprint
		}
		label := "unreachable"
		switch {
		case obs.Reachable && obs.Verification == TLSFailed:
			label = "tls_unverified"
		case obs.Err == "timeout":
			label = "timeout"
		}
		return r.failed(ctx, o, key, label, f)
	}
	return j, key
}

func (r *Runner) twoGateJob(c k8s.GateCandidate, maintenance bool) job {
	return func(ctx context.Context) Attempt {
		o := Attempt{Category: "config_risk", Site: c.Site, Host: c.Host, Maintenance: maintenance}
		ev, err := r.cfg.Gates.Measure(ctx, c)
		o.Result, o.LastGoodAt = string(ev.Result), ev.LastGoodAt
		if err != nil { // the attempt is not (known to be) recorded
			o.Err = err
			return o
		}
		o.Freshness, o.Persisted = ev.Freshness, ev.Persisted
		return o
	}
}

// key builds the observation key from the request, not from the probe result: the key must be the
// same whether the probe answered, failed or was refused.
func (r *Runner) key(category string, sub Subject, req Request, path string) Key {
	sni := req.ServerName
	if sni == "" {
		sni = req.Host
	}
	return Key{
		Category: category, Site: sub.Site, Host: sub.Host, Source: SourceNetProbe, Vantage: r.cfg.Vantage,
		Endpoint: net.JoinHostPort(req.Host, strconv.Itoa(req.Port)), SNI: sni, Path: path,
	}
}

func (r *Runner) good(ctx context.Context, o Attempt, k Key, g Good) Attempt {
	o.Result = "ok"
	rec, err := r.cfg.Store.RecordGood(context.WithoutCancel(ctx), k, r.cfg.Clock.Now(), g)
	return withRecord(o, rec, err)
}

func (r *Runner) failed(ctx context.Context, o Attempt, k Key, label string, f Failure) Attempt {
	o.Result = label
	f.Result, f.Error = label, failureLabelText[label]
	rec, err := r.cfg.Store.RecordFailed(context.WithoutCancel(ctx), k, r.cfg.Clock.Now(), f)
	return withRecord(o, rec, err)
}

// withRecord adds what the store said. A store error leaves the attempt not persisted and with no
// freshness claim at all.
func withRecord(o Attempt, rec Recorded, err error) Attempt {
	if err != nil {
		o.Err = err
		return o
	}
	o.Freshness, o.LastGoodAt, o.Persisted = rec.Freshness, rec.LastGoodAt, !rec.Skipped
	return o
}

// probeErrorLabel is the failure class of a probe that returned an error: the request or endpoint
// policy refused it before any connection, or the probe could not run.
func probeErrorLabel(err error) string {
	if errors.Is(err, ErrRejected) || errors.Is(err, netpolicy.ErrDenied) {
		return "guard_rejected"
	}
	return "source_error"
}
