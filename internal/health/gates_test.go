package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/store/db"
	tk8s "github.com/nesiler/tagcess/test/k8s"
)

const (
	gateVantage = "tagcess-net"
	// bodyMarker is planted in every fixture response body; no stored value may ever contain it.
	bodyMarker = "BODY-MARKER-4f2a"
)

// gateEnv is the probe environment plus a measurer over the real observation store and a fake clock.
type gateEnv struct {
	*env
	m   *GateMeasurer
	now time.Time
	mu  sync.Mutex
}

func (g *gateEnv) clock() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.now
}

func (g *gateEnv) advance(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.now = g.now.Add(d)
}

func newGateEnv(t *testing.T, handler http.HandlerFunc) *gateEnv {
	t.Helper()
	e := newEnv(t, handler)
	// The alternative-path address is an approved target like any other (F4-014).
	if err := e.targets.Set(context.Background(), []string{testHost, testIP, "10.99.0.1", "other.internal.example"}); err != nil {
		t.Fatalf("Set targets: %v", err)
	}
	g := &gateEnv{env: e, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	g.m = &GateMeasurer{Transport: e.tr, Store: e.st.Queries(), Vantage: gateVantage, Now: g.clock}
	return g
}

func gateCandidate() k8s.GateCandidate {
	return k8s.GateCandidate{
		Site: "app", Host: testHost, Path: "/files", PathType: k8s.PathPrefix,
		Kind: k8s.GateExternalIP, Status: k8s.GateStatusCandidate,
		Context:   []k8s.GateContext{k8s.ContextCaddyProxy},
		Namespace: "web", Ingress: "app", UID: "uid-app",
		Backend: k8s.Backend{Service: "app", PortNumber: 80},
		Address: testIP, Port: testPort,
		Reachability: k8s.ReachabilityNotMeasured, Basis: k8s.BasisDeclaredProfile,
	}
}

func (g *gateEnv) probeRow(t *testing.T, c k8s.GateCandidate, vantage string) (db.Observation, bool) {
	t.Helper()
	return g.row(t, db.GetObservationByKeyParams{
		Category: "config_risk", Site: c.Site, Host: c.Host, Route: c.RouteKey(), Source: SourceNetProbe,
		Vantage: vantage, Endpoint: endpointOf(c), Sni: c.Host, Path: c.Path,
	})
}

func (g *gateEnv) riskRow(t *testing.T, c k8s.GateCandidate) (db.Observation, bool) {
	t.Helper()
	return g.row(t, db.GetObservationByKeyParams{
		Category: "config_risk", Site: c.Site, Host: c.Host, Route: c.RouteKey(), Source: SourceConfig,
		Endpoint: endpointOf(c), Sni: c.Host, Path: c.Path,
	})
}

func (g *gateEnv) row(t *testing.T, p db.GetObservationByKeyParams) (db.Observation, bool) {
	t.Helper()
	row, err := g.st.Queries().GetObservationByKey(context.Background(), p)
	if errors.Is(err, sql.ErrNoRows) {
		return db.Observation{}, false
	}
	if err != nil {
		t.Fatalf("GetObservationByKey: %v", err)
	}
	return row, true
}

func bodyHandler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("default page " + bodyMarker))
	}
}

// AC3: a measured answer is bound to the vantage, endpoint, Host/SNI, path and time it was seen with,
// stored in the observation store under that key, and says the internet was not tested. A second
// vantage is its own observation.
func TestTwoGateEvidenceIsBoundToVantage(t *testing.T) {
	ctx := context.Background()
	g := newGateEnv(t, bodyHandler(http.StatusOK))
	c := gateCandidate()

	ev, err := g.m.Measure(ctx, c)
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	want := GateEvidence{
		Vantage: gateVantage, Endpoint: testIP + ":8080", Host: testHost, SNI: testHost, Path: "/files",
		ObservedAt: g.now, Result: PathAnswered, StatusCode: http.StatusOK, Claim: ClaimPathAnswered,
		Freshness: FreshnessFresh, LastGoodAt: g.now, Persisted: true,
		Untested: []string{UntestedInternet, UntestedIPv6},
	}
	if !reflect.DeepEqual(ev, want) {
		t.Fatalf("evidence = %+v\nwant       %+v", ev, want)
	}

	row, ok := g.probeRow(t, c, gateVantage)
	if !ok {
		t.Fatal("no observation stored under the vantage/endpoint/Host/SNI/path key")
	}
	stamp := "2026-10-05T09:00:00.000Z"
	if row.Source != SourceNetProbe || row.Vantage != gateVantage || row.Endpoint != testIP+":8080" || row.Sni != testHost ||
		row.Host != testHost || row.Path != "/files" || row.Backend != "app:80" {
		t.Errorf("row key = %+v", row)
	}
	if row.ObservedAt != stamp || row.LastAttemptAt != stamp || row.Success != 1 || row.LastResult != "ok" || row.HttpStatus != 200 {
		t.Errorf("row time/result = %+v, want observed and attempted at %s with success", row, stamp)
	}
	if !strings.Contains(row.UnscannedScope, UntestedInternet) {
		t.Errorf("unscanned scope = %q, want the internet listed as not tested", row.UnscannedScope)
	}

	// Another vantage measuring the same path does not overwrite the first.
	g.advance(time.Minute)
	other := &GateMeasurer{Transport: g.tr, Store: g.st.Queries(), Vantage: "branch-office", Now: g.clock}
	if _, err := other.Measure(ctx, c); err != nil {
		t.Fatalf("Measure other vantage: %v", err)
	}
	first, _ := g.probeRow(t, c, gateVantage)
	second, ok := g.probeRow(t, c, "branch-office")
	if !ok || first.ID == second.ID || first.ObservedAt != stamp || second.ObservedAt == stamp {
		t.Errorf("vantage rows: first %+v second %+v (%v), want two separate observations", first, second, ok)
	}

	t.Run("Host header and SNI reach the path", func(t *testing.T) {
		const site = "other.internal.example"
		g := newGateEnv(t, nil)
		fx := tk8s.NewTLS(t, site)
		g.dialer.backend = fx.Addr()
		g.tr.rootCAs = fx.CAPool()
		c := gateCandidate()
		c.Host, c.TLS = site, true
		ev, err := g.m.Measure(ctx, c)
		if err != nil || ev.Result != PathAnswered || ev.SNI != site || ev.Host != site {
			t.Fatalf("Measure = %+v, %v; want an answer bound to %s", ev, err, site)
		}
		obs := fx.Observations()
		if len(obs) != 1 || obs[0].Host != site || obs[0].SNI != site {
			t.Fatalf("path observed %+v, want Host and SNI %q", obs, site)
		}
	})
}

// AC3: the configuration risk and the network measurement are separate observations: a measurement
// (answered or failed) never clears, replaces or refreshes the risk, and recording the risk again
// never touches the measurement.
func TestTwoGateRiskAndMeasurementAreIndependent(t *testing.T) {
	ctx := context.Background()
	g := newGateEnv(t, bodyHandler(http.StatusOK))
	c := gateCandidate()
	scope := k8s.FirstProfileScope()

	if err := g.m.RecordRisk(ctx, c, scope); err != nil {
		t.Fatalf("RecordRisk: %v", err)
	}
	risk, ok := g.riskRow(t, c)
	if !ok {
		t.Fatal("no risk observation stored")
	}
	if risk.Category != "config_risk" || risk.RiskFinding != RiskAlternatePath || risk.Vantage != "" ||
		risk.RiskContext != string(k8s.ContextCaddyProxy) || risk.Backend != "app:80" || risk.Success != 1 {
		t.Errorf("risk row = %+v, want an alternate-path finding with the expected-proxy context and no vantage", risk)
	}
	for _, label := range append(scope.UnscannedLabels(), UntestedInternet) {
		if !strings.Contains(risk.UnscannedScope, label) {
			t.Errorf("risk unscanned scope = %q, missing %q", risk.UnscannedScope, label)
		}
	}

	// An answered measurement leaves the risk row exactly as it was.
	g.advance(time.Minute)
	if _, err := g.m.Measure(ctx, c); err != nil {
		t.Fatalf("Measure: %v", err)
	}
	if after, _ := g.riskRow(t, c); !reflect.DeepEqual(after, risk) {
		t.Fatalf("risk after answered measurement = %+v\nwant unchanged     %+v", after, risk)
	}
	meas, ok := g.probeRow(t, c, gateVantage)
	if !ok || meas.RiskFinding != "" || meas.RiskContext != "" || meas.ID == risk.ID {
		t.Fatalf("measurement row = %+v (%v), want its own row carrying no risk finding", meas, ok)
	}

	// A failed measurement leaves it unchanged too.
	g.advance(time.Minute)
	g.tr.timeout = 50 * time.Millisecond
	g.dialer.block = true
	if ev, err := g.m.Measure(ctx, c); err != nil || ev.Result != PathTimeout {
		t.Fatalf("Measure = %+v, %v; want a timeout result", ev, err)
	}
	if after, _ := g.riskRow(t, c); !reflect.DeepEqual(after, risk) {
		t.Fatalf("risk after failed measurement = %+v\nwant unchanged   %+v", after, risk)
	}

	// Recording the risk again does not touch the measurement.
	measBefore, _ := g.probeRow(t, c, gateVantage)
	g.advance(time.Minute)
	if err := g.m.RecordRisk(ctx, c, scope); err != nil {
		t.Fatalf("RecordRisk: %v", err)
	}
	if after, _ := g.probeRow(t, c, gateVantage); !reflect.DeepEqual(after, measBefore) {
		t.Fatalf("measurement after RecordRisk = %+v\nwant unchanged        %+v", after, measBefore)
	}

	t.Run("an unknown candidate is recorded as unknown, not as a clean result", func(t *testing.T) {
		u := gateCandidate()
		u.Status, u.Reasons = k8s.GateStatusUnknown, []k8s.Reason{k8s.ReasonRouteConflict}
		u.Context = nil
		if err := g.m.RecordRisk(ctx, u, scope); err != nil {
			t.Fatalf("RecordRisk: %v", err)
		}
		row, ok := g.riskRow(t, u)
		if !ok || row.RiskFinding != RiskUnknown || row.RiskContext != string(k8s.ReasonRouteConflict) {
			t.Fatalf("risk row = %+v (%v), want an unknown finding with its reason", row, ok)
		}
	})
}

// AC4: a 200, a default page, a 404 or an identical body from the alternative path is only "the path
// answered from this vantage": it is not proof of the same application or of an access bypass, and
// no body (or header) is kept anywhere.
func TestTwoGateHTTPResponseIsNotBypassProof(t *testing.T) {
	ctx := context.Background()
	for name, status := range map[string]int{"200 default page": 200, "404 default backend": 404, "401 gate": 401} {
		t.Run(name, func(t *testing.T) {
			g := newGateEnv(t, bodyHandler(status))
			c := gateCandidate()
			ev, err := g.m.Measure(ctx, c)
			if err != nil {
				t.Fatalf("Measure: %v", err)
			}
			if ev.Result != PathAnswered || ev.StatusCode != status || ev.Claim != ClaimPathAnswered {
				t.Fatalf("evidence = %+v, want only a path-answered claim for status %d", ev, status)
			}
			// The same body answered by another path (the Caddy side) adds no claim either.
			again, err := g.m.Measure(ctx, c)
			if err != nil || again.Claim != ClaimPathAnswered {
				t.Fatalf("second Measure = %+v, %v", again, err)
			}

			var stored []db.Observation
			for _, cand := range []k8s.GateCandidate{c} {
				if row, ok := g.probeRow(t, cand, gateVantage); ok {
					stored = append(stored, row)
				}
			}
			all, err := g.st.Queries().ListObservationsBySite(ctx, c.Site)
			if err != nil {
				t.Fatalf("ListObservationsBySite: %v", err)
			}
			stored = append(stored, all...)
			blob, _ := json.Marshal(stored)
			evBlob, _ := json.Marshal(ev)
			if strings.Contains(string(blob), bodyMarker) || strings.Contains(string(evBlob), bodyMarker) {
				t.Fatal("a response body was stored or returned")
			}
			for _, row := range stored {
				if row.RiskFinding != "" || strings.Contains(strings.ToLower(row.GateClass+row.RiskContext), "bypass") {
					t.Errorf("row %+v reads as a risk/bypass finding; a response is no such proof", row)
				}
			}
		})
	}

	t.Run("no body header or credential field exists", func(t *testing.T) {
		for _, typ := range []reflect.Type{reflect.TypeOf(GateEvidence{}), reflect.TypeOf(db.Observation{})} {
			for i := 0; i < typ.NumField(); i++ {
				name := strings.ToLower(typ.Field(i).Name)
				for _, bad := range []string{"body", "header", "cookie", "token", "secret", "credential", "password", "bypass"} {
					if strings.Contains(name, bad) {
						t.Errorf("%s has field %s", typ, typ.Field(i).Name)
					}
				}
			}
		}
	})
}

// AC5: a timeout, a refused connection or a missing IPv6 measurement speaks only for the path that was
// tried. It is a last-attempt result with the untested paths named, keeps an earlier good observation
// as stale, and is never a universal "closed" or "safe".
func TestTwoGateFailureIsScopedAndUnknown(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name     string
		prep     func(g *gateEnv, c *k8s.GateCandidate)
		result   PathResult
		label    string
		untested []string
	}{
		{
			name: "timeout",
			prep: func(g *gateEnv, c *k8s.GateCandidate) {
				g.tr.timeout = 50 * time.Millisecond
				g.dialer.block = true
			},
			result: PathTimeout, label: "timeout", untested: []string{UntestedInternet, UntestedIPv6},
		},
		{
			name: "connection refused",
			prep: func(g *gateEnv, c *k8s.GateCandidate) {
				g.dialer.backend = "127.0.0.1:1"
			},
			result: PathUnreachable, label: "unreachable", untested: []string{UntestedInternet, UntestedIPv6},
		},
		{
			name: "hostname address, neither family known", // B-L-10
			prep: func(g *gateEnv, c *k8s.GateCandidate) {
				c.Address = "lb.example.test"
			},
			result: PathRejected, label: "guard_rejected", untested: []string{UntestedInternet, UntestedIPv4, UntestedIPv6},
		},
		{
			name: "IPv6 candidate, IPv4 never measured",
			prep: func(g *gateEnv, c *k8s.GateCandidate) {
				if err := g.targets.Set(ctx, []string{testHost, "fd00::5"}); err != nil {
					t.Fatalf("Set targets: %v", err)
				}
				c.Address = "fd00::5" // outside the probe policy: refused, nothing measured
			},
			result: PathRejected, label: "guard_rejected", untested: []string{UntestedInternet, UntestedIPv4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateEnv(t, bodyHandler(200))
			c := gateCandidate()
			tc.prep(g, &c)
			ev, err := g.m.Measure(ctx, c)
			if err != nil {
				t.Fatalf("Measure: %v", err)
			}
			if ev.Result != tc.result || ev.Claim != ClaimNone || !slices.Equal(ev.Untested, tc.untested) {
				t.Fatalf("evidence = %+v, want result %q, no claim, untested %v", ev, tc.result, tc.untested)
			}
			if ev.Freshness != FreshnessNone || !ev.LastGoodAt.IsZero() || !ev.Persisted {
				t.Errorf("evidence = %+v, want no good observation, persisted attempt", ev)
			}
			row, ok := g.probeRow(t, c, gateVantage)
			if !ok || row.Success != 0 || row.LastResult != tc.label || row.ObservedAt != "" {
				t.Fatalf("row = %+v (%v), want a failed attempt %q with no good observation", row, ok, tc.label)
			}
			if risk, ok := g.riskRow(t, c); ok {
				t.Errorf("a failed measurement wrote a risk row: %+v", risk)
			}
		})
	}

	t.Run("an earlier answer stays as stale evidence", func(t *testing.T) {
		g := newGateEnv(t, bodyHandler(200))
		c := gateCandidate()
		first, err := g.m.Measure(ctx, c)
		if err != nil || first.Result != PathAnswered {
			t.Fatalf("Measure = %+v, %v", first, err)
		}
		good := g.clock()
		g.advance(time.Hour)
		g.tr.timeout = 50 * time.Millisecond
		g.dialer.block = true
		ev, err := g.m.Measure(ctx, c)
		if err != nil || ev.Result != PathTimeout {
			t.Fatalf("Measure = %+v, %v; want a timeout", ev, err)
		}
		if ev.Freshness != FreshnessStale || !ev.LastGoodAt.Equal(good) {
			t.Fatalf("evidence = %+v, want stale evidence from %s", ev, good)
		}
		row, _ := g.probeRow(t, c, gateVantage)
		if row.Success != 0 || row.ObservedAt != "2026-10-05T09:00:00.000Z" || row.HttpStatus != 200 || row.LastAttemptAt != "2026-10-05T10:00:00.000Z" {
			t.Fatalf("row = %+v, want the good group kept and only the attempt group newer", row)
		}
	})

	t.Run("a candidate without an address is not measurable and writes nothing", func(t *testing.T) {
		g := newGateEnv(t, bodyHandler(200))
		c := gateCandidate()
		c.Address = ""
		ev, err := g.m.Measure(ctx, c)
		if err != nil || ev.Result != PathNotMeasurable || ev.Claim != ClaimNone || ev.Persisted {
			t.Fatalf("Measure = %+v, %v; want not measurable and nothing recorded", ev, err)
		}
		g.noNetwork(t)
		rows, _ := g.st.Queries().ListObservationsBySite(ctx, c.Site)
		if len(rows) != 0 {
			t.Fatalf("rows = %+v, want none", rows)
		}
	})

	t.Run("a store failure is not shown as a recorded attempt", func(t *testing.T) {
		g := newGateEnv(t, bodyHandler(200))
		g.m.Store = failingStore{}
		ev, err := g.m.Measure(ctx, gateCandidate())
		if err == nil || ev.Persisted || ev.Freshness != FreshnessNone {
			t.Fatalf("Measure = %+v, %v; want an error and nothing persisted", ev, err)
		}
	})
}

type failingStore struct{}

func (failingStore) UpsertObservationGood(context.Context, db.UpsertObservationGoodParams) (db.Observation, error) {
	return db.Observation{}, errors.New("disk full")
}

func (failingStore) UpsertObservationFailed(context.Context, db.UpsertObservationFailedParams) (db.Observation, error) {
	return db.Observation{}, errors.New("disk full")
}

// AC6: a redirect is not followed and is recorded as a failed measurement; a path the probe policy or
// the target allowlist refuses sends nothing; no credential, cookie or custom header is ever sent; a
// cancelled caller is not a measurement.
func TestTwoGateMeasurementUsesGuardedTransport(t *testing.T) {
	ctx := context.Background()

	t.Run("redirect is not followed", func(t *testing.T) {
		var mu sync.Mutex
		var headers []http.Header
		g := newGateEnv(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			headers = append(headers, r.Header.Clone())
			mu.Unlock()
			http.Redirect(w, r, "/login", http.StatusFound)
		})
		c := gateCandidate()
		ev, err := g.m.Measure(ctx, c)
		if err != nil {
			t.Fatalf("Measure: %v", err)
		}
		if ev.Result != PathRedirect || ev.Claim != ClaimNone || ev.StatusCode != http.StatusFound {
			t.Fatalf("evidence = %+v, want a not-followed redirect that claims nothing", ev)
		}
		if n := g.hits.Load(); n != 1 {
			t.Fatalf("path got %d requests, want 1 (redirect not followed)", n)
		}
		mu.Lock()
		for _, h := range headers {
			for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key"} {
				if h.Get(name) != "" {
					t.Errorf("request carried %s", name)
				}
			}
		}
		mu.Unlock()
		row, ok := g.probeRow(t, c, gateVantage)
		if !ok || row.Success != 0 || row.LastResult != "redirect_not_followed" || row.LastHttpStatus != http.StatusFound || row.ObservedAt != "" {
			t.Fatalf("row = %+v (%v), want a failed measurement", row, ok)
		}
	})

	t.Run("policy and allowlist refusals send nothing", func(t *testing.T) {
		for name, mut := range map[string]func(c *k8s.GateCandidate){
			"address outside the probe policy": func(c *k8s.GateCandidate) { c.Address = "10.99.0.1" },
			"port outside the probe policy":    func(c *k8s.GateCandidate) { c.Port = 9999 },
			"host not an approved target":      func(c *k8s.GateCandidate) { c.Host = "unapproved.example" },
			"address not an approved target":   func(c *k8s.GateCandidate) { c.Address = "10.20.0.77" },
			"path with a query":                func(c *k8s.GateCandidate) { c.Path = "/files?x=1" },
		} {
			t.Run(name, func(t *testing.T) {
				g := newGateEnv(t, bodyHandler(200))
				c := gateCandidate()
				mut(&c)
				ev, err := g.m.Measure(ctx, c)
				if err != nil {
					t.Fatalf("Measure: %v", err)
				}
				if ev.Result != PathRejected || ev.Claim != ClaimNone || ev.Freshness != FreshnessNone {
					t.Fatalf("evidence = %+v, want a rejected measurement", ev)
				}
				g.noNetwork(t)
				row, ok := g.probeRow(t, c, gateVantage)
				if !ok || row.Success != 0 || row.LastResult != "guard_rejected" || row.ObservedAt != "" {
					t.Fatalf("row = %+v (%v), want a failed guard_rejected attempt", row, ok)
				}
			})
		}
	})

	t.Run("a cancelled caller records nothing", func(t *testing.T) {
		g := newGateEnv(t, bodyHandler(200))
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := g.m.Measure(cctx, gateCandidate()); !errors.Is(err, context.Canceled) {
			t.Fatalf("Measure err = %v, want context.Canceled", err)
		}
		rows, _ := g.st.Queries().ListObservationsBySite(ctx, "app")
		if len(rows) != 0 {
			t.Fatalf("rows = %+v, want none", rows)
		}
	})
}
