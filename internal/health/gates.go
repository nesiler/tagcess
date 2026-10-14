package health

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/store/db"
)

// This file measures the alternative paths of the two-gate evaluation (F4-020, K-03, R3 B-05, ADR 0031
// proposed) over the F4-014 guarded transport and records them in the F4-017 observation store.
//
// A measurement is evidence from one vantage (where tagcess runs) for one endpoint, Host/SNI, path
// and time. It says that the path answered, never that the application is the same or that access is
// bypassed, and never that the internet can or cannot reach it: the internet is always listed as not
// tested. The configuration risk (the candidate itself) and the measurement are separate observation
// rows of the config_risk category (source k8s_config and net_probe), so one never clears, replaces or
// refreshes the other. A failed measurement writes only the attempt group and keeps the last good one.
// No body, header or credential is read, sent or stored.

// Observation sources of the two kinds of config_risk row.
const (
	SourceConfig   = "k8s_config" // the declared candidate (risk), no vantage
	SourceNetProbe = "net_probe"  // a measurement from a vantage
)

// Risk findings stored on a risk row. Unknown means the candidate could not be judged.
const (
	RiskAlternatePath = "alternate_path_candidate"
	RiskUnknown       = "unknown"
)

// Paths this measurement does not cover, listed on every row and every evidence.
const (
	UntestedInternet = "internet"
	UntestedIPv4     = "ipv4"
	UntestedIPv6     = "ipv6"
)

const gateClassAnswered = "answered"

// PathResult is what the measured path did. Anything but PathAnswered is the last attempt only.
type PathResult string

const (
	PathAnswered      PathResult = "answered"              // a final (non-redirect) HTTP response arrived
	PathRedirect      PathResult = "redirect_not_followed" // 3xx: not followed, recorded as a failed measurement
	PathTimeout       PathResult = "timeout"
	PathUnreachable   PathResult = "unreachable"
	PathRejected      PathResult = "guard_rejected" // policy, allowlist or request check refused it; nothing was sent
	PathNotMeasurable PathResult = "not_measurable" // the candidate has no address; no attempt, nothing recorded
)

// Claim is all a measurement may say. There is deliberately no claim of the same application, of a
// bypass or of a closed path.
type Claim string

const (
	ClaimNone         Claim = "none"
	ClaimPathAnswered Claim = "path_answered_from_vantage"
)

// Freshness says how current the last good answer for this key is.
type Freshness string

const (
	FreshnessFresh Freshness = "fresh" // this attempt answered
	FreshnessStale Freshness = "stale" // this attempt failed; an older answer is kept
	FreshnessNone  Freshness = "none"  // no answer has ever been recorded
)

// GateEvidence is the whole record of one measurement: where, what, when and how current. No body,
// header, error text or credential.
type GateEvidence struct {
	Vantage    string
	Endpoint   string // dialled address:port
	Host       string // Host header
	SNI        string
	Path       string
	ObservedAt time.Time // when this attempt finished
	Result     PathResult
	StatusCode int
	Claim      Claim
	Freshness  Freshness
	LastGoodAt time.Time // zero when nothing good is recorded
	Persisted  bool      // the attempt is in the observation store
	Untested   []string  // paths this measurement says nothing about
}

// GateObservations is the part of the F4-017 store the measurer writes; *db.Queries satisfies it.
type GateObservations interface {
	UpsertObservationGood(ctx context.Context, arg db.UpsertObservationGoodParams) (db.Observation, error)
	UpsertObservationFailed(ctx context.Context, arg db.UpsertObservationFailedParams) (db.Observation, error)
}

// GateMeasurer measures alternative-path candidates from one vantage. A nil Now uses time.Now.
// F4-018 calls Measure in the target interval; this type schedules nothing.
type GateMeasurer struct {
	Transport *Transport
	Store     GateObservations
	Vantage   string // where tagcess runs, e.g. "tagcess-net"; never "internet"
	Now       func() time.Time
}

func (m *GateMeasurer) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// endpointOf is the dialled address:port of a candidate; empty when it has no address.
func endpointOf(c k8s.GateCandidate) string {
	if c.Address == "" {
		return ""
	}
	return net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
}

func pathOf(c k8s.GateCandidate) string {
	if c.Path == "" {
		return "/"
	}
	return c.Path
}

func backendOf(c k8s.GateCandidate) string {
	if c.Backend.Service == "" {
		return ""
	}
	port := c.Backend.PortName
	if port == "" {
		port = strconv.Itoa(c.Backend.PortNumber)
	}
	return c.Backend.Service + ":" + port
}

// untested lists what a measurement of c cannot speak for: the internet, and the other IP family
// when the dialled address is an IP literal. For a hostname the family is unknown, so both are listed.
func untested(c k8s.GateCandidate) []string {
	out := []string{UntestedInternet}
	if addr, err := netip.ParseAddr(c.Address); err == nil {
		if addr.Is4() {
			out = append(out, UntestedIPv6)
		} else {
			out = append(out, UntestedIPv4)
		}
	} else {
		out = append(out, UntestedIPv4, UntestedIPv6)
	}
	return out
}

// RecordRisk stores the candidate as a configuration-risk row. It carries no vantage or response: a
// later measurement never changes it and it never changes a measurement. An unknown candidate is
// recorded as unknown, with its reasons, never as a clean result. scope names the unscanned paths.
func (m *GateMeasurer) RecordRisk(ctx context.Context, c k8s.GateCandidate, scope k8s.Scope) error {
	finding := RiskAlternatePath
	if c.Status != k8s.GateStatusCandidate {
		finding = RiskUnknown
	}
	var parts []string
	for _, x := range c.Context {
		parts = append(parts, string(x))
	}
	for _, r := range c.Reasons {
		parts = append(parts, string(r))
	}
	at := formatTime(m.now())
	_, err := m.Store.UpsertObservationGood(ctx, db.UpsertObservationGoodParams{
		Category: "config_risk", Site: c.Site, Host: c.Host, Route: c.RouteKey(), Source: SourceConfig,
		Endpoint: endpointOf(c), Sni: c.Host, Path: pathOf(c), Backend: backendOf(c),
		ObservedAt: at, RiskFinding: finding, RiskContext: strings.Join(parts, ","),
		UnscannedScope: strings.Join(append(scope.UnscannedLabels(), UntestedInternet), ","),
		LastAttemptAt:  at,
	})
	return err
}

// Measure sends one credentialless GET to the candidate's address with its Host/SNI and path through
// the guarded transport and records the outcome. A refused request (policy, allowlist, malformed) is
// a recorded failed measurement and sends nothing; a redirect is not followed and is a failed
// measurement too. A candidate without an address is PathNotMeasurable and records nothing. A
// cancelled caller returns its error and records nothing. A store failure returns the error with an
// evidence that is not Persisted, so the attempt is never shown as recorded.
func (m *GateMeasurer) Measure(ctx context.Context, c k8s.GateCandidate) (GateEvidence, error) {
	ev := GateEvidence{
		Vantage: m.Vantage, Endpoint: endpointOf(c), Host: c.Host, SNI: c.Host, Path: pathOf(c),
		Claim: ClaimNone, Freshness: FreshnessNone, Untested: untested(c),
	}
	if c.Address == "" {
		ev.Result = PathNotMeasurable
		return ev, nil
	}
	if err := ctx.Err(); err != nil {
		return GateEvidence{}, err
	}

	res, err := m.Transport.Get(ctx, Request{Host: c.Address, Port: c.Port, Path: pathOf(c), TLS: c.TLS, ServerName: c.Host})
	ev.ObservedAt = m.now()
	switch {
	case err == nil && res.Outcome == OutcomeResponded:
		ev.Result, ev.StatusCode, ev.Claim = PathAnswered, res.StatusCode, ClaimPathAnswered
	case err == nil:
		ev.Result, ev.StatusCode = PathRedirect, res.StatusCode
	case ctx.Err() != nil:
		return GateEvidence{}, err
	case errors.Is(err, ErrRejected) || errors.Is(err, netpolicy.ErrDenied):
		ev.Result = PathRejected
	default:
		ev.Result = PathUnreachable
		if kind, ferr := failureKind(ctx, err); ferr == nil && kind == KindTimeout {
			ev.Result = PathTimeout
		}
	}

	at := formatTime(ev.ObservedAt)
	if ev.Result == PathAnswered {
		_, err = m.Store.UpsertObservationGood(ctx, db.UpsertObservationGoodParams{
			Category: "config_risk", Site: c.Site, Host: c.Host, Route: c.RouteKey(), Source: SourceNetProbe,
			Vantage: m.Vantage, Endpoint: ev.Endpoint, Sni: c.Host, Path: ev.Path, Backend: backendOf(c),
			ObservedAt: at, HttpStatus: int64(ev.StatusCode), GateClass: gateClassAnswered,
			UnscannedScope: strings.Join(ev.Untested, ","), LastAttemptAt: at,
		})
		if err != nil {
			return ev, err
		}
		ev.Freshness, ev.LastGoodAt, ev.Persisted = FreshnessFresh, ev.ObservedAt, true
		return ev, nil
	}

	row, err := m.Store.UpsertObservationFailed(ctx, db.UpsertObservationFailedParams{
		Category: "config_risk", Site: c.Site, Host: c.Host, Route: c.RouteKey(), Source: SourceNetProbe,
		Vantage: m.Vantage, Endpoint: ev.Endpoint, Sni: c.Host, Path: ev.Path,
		LastAttemptAt: at, LastResult: string(ev.Result), LastHttpStatus: int64(ev.StatusCode),
		LastError: failureText[ev.Result],
	})
	if err != nil {
		return ev, err
	}
	ev.Persisted = true
	if row.ObservedAt != "" {
		if good, perr := time.Parse(timeFormat, row.ObservedAt); perr == nil {
			ev.Freshness, ev.LastGoodAt = FreshnessStale, good
		}
	}
	return ev, nil
}

// failureText is the fixed, sanitized last_error of a failed measurement; raw errors, which can echo
// addresses or response text, are never stored.
var failureText = map[PathResult]string{
	PathRedirect:    "redirect was not followed",
	PathTimeout:     "no answer within the time limit",
	PathUnreachable: "connection or TLS handshake failed",
	PathRejected:    "request refused before any connection",
}

// timeFormat is the observation store's fixed-width UTC format; text order is time order.
const timeFormat = "2006-01-02T15:04:05.000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }
