package hostapply

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

const (
	idA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	idB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	idC = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

var devopsOnly = []string{"devops"}

type fakeUnknowns struct {
	list []Unknown
	err  error
}

func (f *fakeUnknowns) Open(context.Context) ([]Unknown, error) { return f.list, f.err }

// skewClock is the service clock: real time plus an adjustable offset, because the maintenance
// package stamps rows with its own real clock.
type skewClock struct{ offset atomic.Int64 }

func (c *skewClock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *skewClock) advance(d time.Duration) {
	c.offset.Add(int64(d))
}

type env struct {
	svc       *Service
	maint     *maintenance.Service
	st        *store.Store
	host      *Client
	reqDir    string
	resDir    string
	unknowns  *fakeUnknowns
	clock     *skewClock
	logs      *bytes.Buffer
	succeeded []string
	ids       []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	host, req, res := newClient(t)
	e := &env{
		maint: maintenance.New(st.Queries()), st: st, host: host, reqDir: req, resDir: res,
		unknowns: &fakeUnknowns{}, clock: &skewClock{}, logs: &bytes.Buffer{},
		ids: []string{idA, idB, idC},
	}
	e.svc = e.service(t, host)
	e.writeStatus(t, devopsOnly, "", "")
	e.setEnabled(t, "true")
	return e
}

func (e *env) service(t *testing.T, h Host) *Service {
	t.Helper()
	svc, err := NewService(Config{
		Host:        h,
		Maintenance: e.maint,
		Audit:       audit.New(e.st.Queries()),
		Settings:    e.st.Queries(),
		Unknowns:    e.unknowns,
		Log:         slog.New(slog.NewTextHandler(e.logs, nil)),
		Now:         e.clock.now,
		NewID: func() string {
			id := e.ids[0]
			e.ids = e.ids[1:]
			return id
		},
		OnSucceeded: func(_ context.Context, id string) { e.succeeded = append(e.succeeded, id) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (e *env) setEnabled(t *testing.T, v string) {
	t.Helper()
	err := e.st.Queries().UpsertSetting(context.Background(), db.UpsertSettingParams{
		Key: SettingConfigWriteEnabled, Value: v, UpdatedAt: "2026-10-02T09:00:00.000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) writeStatus(t *testing.T, groups []string, id string, state hostpatch.State) {
	t.Helper()
	rev, err := hostpatch.BaseRev(groups)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hostpatch.EncodeStatus(hostpatch.Status{
		Version: hostpatch.Version, RequestID: id, State: state, AllowedGroups: groups, BaseRev: rev,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.resDir, "status.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeConfigError plays a helper that could not read the live config: no groups, no base_rev.
func (e *env) writeConfigError(t *testing.T) {
	t.Helper()
	b, err := hostpatch.EncodeStatus(hostpatch.Status{Version: hostpatch.Version, ConfigError: hostpatch.CodeConfigUnreadable})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.resDir, "status.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *env) baseRev(t *testing.T, groups []string) string {
	t.Helper()
	rev, err := hostpatch.BaseRev(groups)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

func (e *env) req(t *testing.T, wanted ...string) ApplyRequest {
	t.Helper()
	return ApplyRequest{Actor: "devops@example.com", Wanted: wanted, BaseRev: e.baseRev(t, devopsOnly)}
}

func (e *env) countAudit(t *testing.T, event string) int {
	t.Helper()
	var n int
	if err := e.st.DB().QueryRowContext(context.Background(), `SELECT count(*) FROM audit_events WHERE event = ?`, event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) requestFiles(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(e.reqDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ent := range ents {
		names = append(names, ent.Name())
	}
	return names
}

func (e *env) maintState(t *testing.T) maintenance.Status {
	t.Helper()
	st, err := e.maint.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// terminal plays the helper: a final result for id (and the matching status.json), with the marker
// it consumed on accepting the request gone.
func (e *env) terminal(t *testing.T, id string, state hostpatch.State) {
	t.Helper()
	if err := os.Remove(filepath.Join(e.reqDir, "request.ready")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	writeResult(t, e.resDir, id, state)
	e.writeStatus(t, devopsOnly, id, state)
}

func hostResultStatus(t *testing.T, raw string) string {
	t.Helper()
	var v struct {
		Status    string `json:"status"`
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("last_host_result %q: %v", raw, err)
	}
	if v.ErrorCode != "" {
		return v.Status + "/" + v.ErrorCode
	}
	return v.Status
}

func TestConfigService_PreviewReadOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.writeStatus(t, []string{"devops", "standart"}, "", "")

	p, err := e.svc.Preview(ctx, []string{"standart", "developer", "devops"})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if want := []string{"devops", "standart"}; !slices.Equal(p.Current, want) {
		t.Errorf("Current = %v, want %v", p.Current, want)
	}
	if want := []string{"devops", "developer", "standart"}; !slices.Equal(p.Wanted, want) {
		t.Errorf("Wanted = %v, want canonical %v", p.Wanted, want)
	}
	if want := e.baseRev(t, []string{"devops", "standart"}); p.BaseRev != want {
		t.Errorf("BaseRev = %q, want %q", p.BaseRev, want)
	}
	if !slices.Equal(p.Added, []string{"developer"}) || len(p.Removed) != 0 {
		t.Errorf("diff = +%v -%v, want +[developer] -[]", p.Added, p.Removed)
	}

	for _, bad := range [][]string{nil, {"standart"}, {"devops", "root"}, {"devops", "devops"}} {
		if _, err := e.svc.Preview(ctx, bad); !errors.Is(err, hostpatch.ErrInvalidRequest) {
			t.Errorf("Preview(%v) error = %v, want ErrInvalidRequest", bad, err)
		}
	}
	if err := os.Remove(filepath.Join(e.resDir, "status.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Preview(ctx, []string{"devops"}); !errors.Is(err, ErrStatusUnavailable) {
		t.Errorf("Preview without status.json error = %v, want ErrStatusUnavailable", err)
	}
	e.writeConfigError(t)
	if _, err := e.svc.Preview(ctx, []string{"devops"}); !errors.Is(err, ErrHostConfig) {
		t.Errorf("Preview with config_error = %v, want ErrHostConfig", err)
	}

	if st := e.maintState(t); st.State != maintenance.Off {
		t.Errorf("maintenance = %s, want off", st.State)
	}
	if n := len(e.requestFiles(t)); n != 0 {
		t.Errorf("requests dir has %d files, want 0", n)
	}
	if n := e.countAudit(t, "headscale.config.started"); n != 0 {
		t.Errorf("audit started = %d, want 0", n)
	}
}

// spyHost records what the database and audit log held at the moment of publishing.
type spyHost struct {
	Host
	e         *env
	t         *testing.T
	state     maintenance.State
	reqID     string
	started   int
	published string
}

func (s *spyHost) Publish(doc []byte) error {
	st := s.e.maintState(s.t)
	s.state, s.reqID = st.State, st.RequestID
	s.started = s.e.countAudit(s.t, "headscale.config.started")
	req, err := hostpatch.ParseRequest(doc)
	if err != nil {
		s.t.Fatal(err)
	}
	s.published = req.RequestID
	return s.Host.Publish(doc)
}

func TestConfigService_FlagBeforeMarker(t *testing.T) {
	e := newEnv(t)
	spy := &spyHost{Host: e.host, e: e, t: t}
	svc := e.service(t, spy)

	res, err := svc.Apply(context.Background(), e.req(t, "devops", "developer"))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.RequestID != idA {
		t.Errorf("RequestID = %q, want %q", res.RequestID, idA)
	}
	if spy.state != maintenance.Active || spy.reqID != idA || spy.published != idA {
		t.Errorf("at publish: state=%s flag id=%q published=%q, want active/%s/%s", spy.state, spy.reqID, spy.published, idA, idA)
	}
	if spy.started != 1 {
		t.Errorf("started audit rows at publish = %d, want 1", spy.started)
	}
	st := e.maintState(t)
	if st.Actor != "devops@example.com" || st.RequestID != idA {
		t.Errorf("maintenance actor/id = %q/%q", st.Actor, st.RequestID)
	}
	var diff, actor string
	if err := e.st.DB().QueryRowContext(context.Background(), `SELECT actor, diff FROM audit_events WHERE event = 'headscale.config.started'`).Scan(&actor, &diff); err != nil {
		t.Fatal(err)
	}
	if actor != "devops@example.com" || !strings.Contains(diff, idA) || !strings.Contains(diff, "devops,developer") {
		t.Errorf("started audit actor=%q diff=%s", actor, diff)
	}
	if want := []string{idA + ".json", "request.ready"}; !slices.Equal(e.requestFiles(t), want) {
		t.Errorf("requests dir = %v, want %v", e.requestFiles(t), want)
	}
}

func TestConfigService_Preconditions(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, e *env, req *ApplyRequest)
		want  error
	}{
		{"write switch missing", func(t *testing.T, e *env, _ *ApplyRequest) {
			if _, err := e.st.DB().ExecContext(context.Background(), `DELETE FROM settings WHERE key = ?`, SettingConfigWriteEnabled); err != nil {
				t.Fatal(err)
			}
		}, ErrWriteDisabled},
		{"write switch off", func(t *testing.T, e *env, _ *ApplyRequest) { e.setEnabled(t, "false") }, ErrWriteDisabled},
		{"write switch garbage", func(t *testing.T, e *env, _ *ApplyRequest) { e.setEnabled(t, "maybe") }, ErrWriteDisabled},
		{"status unreadable", func(t *testing.T, e *env, _ *ApplyRequest) {
			if err := os.Remove(filepath.Join(e.resDir, "status.json")); err != nil {
				t.Fatal(err)
			}
		}, ErrStatusUnavailable},
		{"host config unreadable", func(t *testing.T, e *env, _ *ApplyRequest) { e.writeConfigError(t) }, ErrHostConfig},
		{"stale base_rev", func(t *testing.T, e *env, r *ApplyRequest) { r.BaseRev = e.baseRev(t, []string{"devops", "standart"}) }, ErrStale},
		{"empty actor", func(t *testing.T, e *env, r *ApplyRequest) { r.Actor = " " }, ErrActorRequired},
		{"invalid list", func(t *testing.T, e *env, r *ApplyRequest) { r.Wanted = []string{"standart"} }, hostpatch.ErrInvalidRequest},
		{"no change", func(t *testing.T, e *env, r *ApplyRequest) { r.Wanted = []string{"devops"} }, ErrNoChange},
		{"host request in flight", func(t *testing.T, e *env, _ *ApplyRequest) {
			e.writeStatus(t, devopsOnly, idC, hostpatch.StateApplying)
		}, ErrHostBusy},
		{"unknown policy outcome", func(t *testing.T, e *env, _ *ApplyRequest) {
			e.unknowns.list = []Unknown{{Kind: "policy", Detail: "revision #3 (unknown)"}}
		}, ErrUnknownOutcome},
		{"unverified admin or key outcome", func(t *testing.T, e *env, _ *ApplyRequest) {
			e.unknowns.list = []Unknown{{Kind: "headscale_admin_unverified", Detail: "hsadmin:node.expire:node:4"}}
		}, ErrUnknownOutcome},
		{"unknown source unreadable", func(t *testing.T, e *env, _ *ApplyRequest) {
			e.unknowns.err = errors.New("db down")
		}, ErrUnknownOutcome},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			req := e.req(t, "devops", "developer")
			tc.setup(t, e, &req)

			res, err := e.svc.Apply(context.Background(), req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Apply error = %v, want %v", err, tc.want)
			}
			if errors.Is(tc.want, ErrUnknownOutcome) && e.unknowns.err == nil && len(res.Unknowns) != 1 {
				t.Errorf("Unknowns = %v, want the open outcome listed", res.Unknowns)
			}
			if st := e.maintState(t); st.State != maintenance.Off {
				t.Errorf("maintenance = %s, want off", st.State)
			}
			if n := len(e.requestFiles(t)); n != 0 {
				t.Errorf("requests dir has %d files, want none", n)
			}
			if n := e.countAudit(t, "headscale.config.started"); n != 0 {
				t.Errorf("started audit rows = %d, want 0", n)
			}
		})
	}
}

// failFirst opens a maintenance and ends its request as failed; the flag stays active.
func failFirst(t *testing.T, e *env) {
	t.Helper()
	if _, err := e.svc.Apply(context.Background(), e.req(t, "devops", "developer")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	e.terminal(t, idA, hostpatch.StateFailed)
}

func TestConfigService_RecoveryPatchNotBlockedByLaterUnknowns(t *testing.T) {
	ctx := context.Background()
	later := []Unknown{
		{Kind: "headscale_admin_unverified", Detail: "hsadmin:node.expire:node:4"},
		{Kind: "key_revoke_failed", Detail: "headscale"},
	}

	t.Run("not blocked and listed", func(t *testing.T) {
		e := newEnv(t)
		failFirst(t, e)
		e.unknowns.list = later
		res, err := e.svc.Apply(ctx, e.req(t, "devops", "standart"))
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if res.RequestID != idB || !slices.Equal(res.Unknowns, later) {
			t.Errorf("result = %+v, want id %s with %v listed", res, idB, later)
		}
		if st := e.maintState(t); st.State != maintenance.Active || st.RequestID != idB {
			t.Errorf("maintenance = %s/%s, want active/%s", st.State, st.RequestID, idB)
		}
	})

	t.Run("source error does not block", func(t *testing.T) {
		e := newEnv(t)
		failFirst(t, e)
		e.unknowns.err = errors.New("alerts unreadable")
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "standart")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	})

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, e *env, r *ApplyRequest)
		want  error
	}{
		{"switch off", func(t *testing.T, e *env, _ *ApplyRequest) { e.setEnabled(t, "false") }, ErrWriteDisabled},
		{"status unreadable", func(t *testing.T, e *env, _ *ApplyRequest) {
			_ = os.Remove(filepath.Join(e.resDir, "status.json"))
		}, ErrStatusUnavailable},
		{"stale base_rev", func(t *testing.T, e *env, r *ApplyRequest) { r.BaseRev = e.baseRev(t, []string{"devops", "standart"}) }, ErrStale},
	} {
		t.Run("still refused: "+tc.name, func(t *testing.T) {
			e := newEnv(t)
			failFirst(t, e)
			e.unknowns.list = later
			req := e.req(t, "devops", "standart")
			tc.setup(t, e, &req)
			if _, err := e.svc.Apply(ctx, req); !errors.Is(err, tc.want) {
				t.Fatalf("Apply error = %v, want %v", err, tc.want)
			}
			if st := e.maintState(t); st.RequestID != idA {
				t.Errorf("flag id = %q, want unchanged %s", st.RequestID, idA)
			}
		})
	}
}

func TestConfigService_NewPatchAfterFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("running request is not replaced", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "standart")); !errors.Is(err, ErrHostBusy) {
			t.Fatalf("second Apply error = %v, want ErrHostBusy", err)
		}
		if st := e.maintState(t); st.RequestID != idA {
			t.Errorf("flag id = %q, want %s", st.RequestID, idA)
		}
	})

	for _, state := range []hostpatch.State{hostpatch.StateFailed, hostpatch.StateInterrupted} {
		t.Run(string(state)+" renews the same flag", func(t *testing.T) {
			e := newEnv(t)
			if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
				t.Fatal(err)
			}
			started := e.maintState(t).StartedAt
			e.terminal(t, idA, state)

			res, err := e.svc.Apply(ctx, e.req(t, "devops", "standart"))
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			st := e.maintState(t)
			if res.RequestID != idB || st.State != maintenance.Active || st.RequestID != idB || !st.StartedAt.Equal(started) {
				t.Errorf("after renew: result %q, state %s/%s, started %v (was %v)", res.RequestID, st.State, st.RequestID, st.StartedAt, started)
			}
			if n := e.countAudit(t, "headscale.config.started"); n != 2 {
				t.Errorf("started audit rows = %d, want 2", n)
			}
			if n := e.countAudit(t, "headscale.config.finished"); n != 1 {
				t.Errorf("finished audit rows = %d, want the old request's one", n)
			}
		})
	}

	t.Run("succeeded result waits for the close step", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
			t.Fatal(err)
		}
		e.terminal(t, idA, hostpatch.StateSucceeded)
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "standart")); !errors.Is(err, ErrAwaitingClose) {
			t.Fatalf("Apply error = %v, want ErrAwaitingClose", err)
		}
	})

	t.Run("reconcile_pending refuses", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
			t.Fatal(err)
		}
		e.terminal(t, idA, hostpatch.StateSucceeded)
		if _, err := e.svc.Poll(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := e.maint.ToReconcilePending(ctx, idA); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "standart")); !errors.Is(err, ErrAwaitingClose) {
			t.Fatalf("Apply error = %v, want ErrAwaitingClose", err)
		}
	})
}

// foreignResultHost answers every Result call with a succeeded result carrying another request ID,
// as a misbehaving Host could.
type foreignResultHost struct {
	Host
	id string
}

func (h foreignResultHost) Result(string) (hostpatch.Result, error) {
	return hostpatch.Result{
		Version: hostpatch.Version, RequestID: h.id, State: hostpatch.StateSucceeded,
		Phase: hostpatch.PhaseCheck, FinishedAt: time.Now(), HealthVerified: true,
	}, nil
}

func TestConfigService_RecordsResultForID(t *testing.T) {
	ctx := context.Background()

	t.Run("another id is ignored, own id recorded once", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
			t.Fatal(err)
		}
		e.terminal(t, idC, hostpatch.StateFailed) // result of some other request
		if r, err := e.svc.Poll(ctx); err != nil || r.Recorded {
			t.Fatalf("Poll with a foreign result = %+v, %v; want nothing recorded", r, err)
		}
		if st := e.maintState(t); st.LastHostResult != "" {
			t.Errorf("last_host_result = %q, want empty", st.LastHostResult)
		}

		e.terminal(t, idA, hostpatch.StateFailed)
		if r, err := e.svc.Poll(ctx); err != nil || !r.Recorded {
			t.Fatalf("Poll = %+v, %v; want recorded", r, err)
		}
		if r, err := e.svc.Poll(ctx); err != nil || r.Recorded {
			t.Fatalf("second Poll = %+v, %v; want nothing new", r, err)
		}
		st := e.maintState(t)
		if st.State != maintenance.Active || hostResultStatus(t, st.LastHostResult) != "failed/health_failed" {
			t.Errorf("state %s, last_host_result %s", st.State, st.LastHostResult)
		}
		if n := e.countAudit(t, "headscale.config.finished"); n != 1 {
			t.Errorf("finished audit rows = %d, want exactly 1", n)
		}
		if len(e.succeeded) != 0 {
			t.Errorf("success hook ran for a failure: %v", e.succeeded)
		}
	})

	t.Run("a result for another id is never recorded", func(t *testing.T) {
		for name, other := range map[string]string{"other id": idC, "nil uuid": "00000000-0000-0000-0000-000000000000", "empty id": ""} {
			t.Run(name, func(t *testing.T) {
				e := newEnv(t)
				if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
					t.Fatal(err)
				}
				svc := e.service(t, foreignResultHost{Host: e.host, id: other})
				if r, err := svc.Poll(ctx); err != nil || r.Recorded {
					t.Fatalf("Poll = %+v, %v; want nothing recorded", r, err)
				}
				if st := e.maintState(t); st.LastHostResult != "" {
					t.Errorf("last_host_result = %q, want empty", st.LastHostResult)
				}
				if n := e.countAudit(t, "headscale.config.finished"); n != 0 {
					t.Errorf("finished audit rows = %d, want 0", n)
				}
				if len(e.succeeded) != 0 {
					t.Errorf("success hook ran: %v", e.succeeded)
				}
			})
		}
	})

	t.Run("interrupted keeps the flag", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
			t.Fatal(err)
		}
		e.terminal(t, idA, hostpatch.StateInterrupted)
		if _, err := e.svc.Poll(ctx); err != nil {
			t.Fatal(err)
		}
		st := e.maintState(t)
		if st.State != maintenance.Active || !strings.HasPrefix(hostResultStatus(t, st.LastHostResult), "interrupted") {
			t.Errorf("state %s, last_host_result %s", st.State, st.LastHostResult)
		}
	})

	t.Run("success hands over to the close hook and leaves the flag", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
			t.Fatal(err)
		}
		e.terminal(t, idA, hostpatch.StateSucceeded)
		if _, err := e.svc.Poll(ctx); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(e.succeeded, []string{idA}) {
			t.Errorf("hook calls = %v, want [%s]", e.succeeded, idA)
		}
		if st := e.maintState(t); st.State != maintenance.Active || hostResultStatus(t, st.LastHostResult) != "succeeded" {
			t.Errorf("state %s, last_host_result %s", st.State, st.LastHostResult)
		}
		if n := e.countAudit(t, "headscale.config.finished"); n != 1 {
			t.Errorf("finished audit rows = %d, want 1", n)
		}
	})

	t.Run("poll with no maintenance does nothing", func(t *testing.T) {
		e := newEnv(t)
		if r, err := e.svc.Poll(ctx); err != nil || r != (PollResult{}) {
			t.Errorf("Poll = %+v, %v; want zero", r, err)
		}
	})
}

func TestConfigService_ResumesAfterRestart(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
		t.Fatal(err)
	}

	// The container restarts: a new service over the same database and directories.
	restarted := e.service(t, e.host)
	e.clock.advance(ResultWait + time.Minute)
	r, err := restarted.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll after restart: %v", err)
	}
	if !r.Overdue || r.Recorded {
		t.Errorf("Poll = %+v, want overdue and nothing recorded", r)
	}
	if st := e.maintState(t); st.State != maintenance.Active || st.RequestID != idA {
		t.Errorf("after the deadline: %s/%s, want the flag open with %s", st.State, st.RequestID, idA)
	}

	e.terminal(t, idA, hostpatch.StateFailed)
	if r, err := restarted.Poll(ctx); err != nil || !r.Recorded {
		t.Fatalf("Poll = %+v, %v; want the late result recorded", r, err)
	}
	if st := e.maintState(t); st.State != maintenance.Active || hostResultStatus(t, st.LastHostResult) != "failed/health_failed" {
		t.Errorf("state %s, last_host_result %s", st.State, st.LastHostResult)
	}
}

// failingHost fails every Publish with an error that must never reach the audit log.
type failingHost struct{ Host }

func (failingHost) Publish([]byte) error {
	return errors.New("write /run/tagcess/requests: s3cr3t-canary")
}

func TestConfigService_PublishFailureKeepsFlag(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	svc := e.service(t, failingHost{e.host})

	_, err := svc.Apply(ctx, e.req(t, "devops", "developer"))
	if !errors.Is(err, ErrPublish) {
		t.Fatalf("Apply error = %v, want ErrPublish", err)
	}
	st := e.maintState(t)
	if st.State != maintenance.Active || st.RequestID != idA {
		t.Errorf("maintenance = %s/%s, want active/%s", st.State, st.RequestID, idA)
	}
	if got := hostResultStatus(t, st.LastHostResult); got != "failed/request_write_failed" {
		t.Errorf("last_host_result = %s, want failed/request_write_failed", got)
	}
	if n := e.countAudit(t, "headscale.config.finished"); n != 1 {
		t.Errorf("finished audit rows = %d, want 1", n)
	}

	// The way out is an ordinary new patch with a new ID, on the same flag.
	res, err := e.svc.Apply(ctx, e.req(t, "devops", "developer"))
	if err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if st := e.maintState(t); res.RequestID != idB || st.RequestID != idB || st.State != maintenance.Active {
		t.Errorf("after retry: result %q, flag %s/%s", res.RequestID, st.State, st.RequestID)
	}
}

func TestConfigService_AuditNoSecrets(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	// One failed publish (error text with a canary), then a recovery that ends in a result.
	if _, err := e.service(t, failingHost{e.host}).Apply(ctx, e.req(t, "devops", "developer")); err == nil {
		t.Fatal("want a publish error")
	}
	e.ids = []string{idB}
	if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
		t.Fatal(err)
	}
	e.terminal(t, idB, hostpatch.StateFailed)
	if _, err := e.svc.Poll(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := e.st.DB().QueryContext(context.Background(), `SELECT actor, event, target, diff, result FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var dump strings.Builder
	for rows.Next() {
		var a, ev, tg, d, r sql.NullString
		if err := rows.Scan(&a, &ev, &tg, &d, &r); err != nil {
			t.Fatal(err)
		}
		dump.WriteString(strings.Join([]string{a.String, ev.String, tg.String, d.String, r.String}, "|") + "\n")
	}
	st := e.maintState(t)
	all := dump.String() + st.LastHostResult + e.logs.String()
	for _, banned := range []string{"s3cr3t-canary", `"patch"`, "base_rev", "BEGIN", "secret", "/run/tagcess"} {
		if strings.Contains(all, banned) {
			t.Errorf("audit, last_host_result or log contains %q:\n%s", banned, all)
		}
	}
	if dump.Len() == 0 {
		t.Fatal("no audit rows were written")
	}
}

func TestConfigService_WatchPollsUntilCancelled(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := e.svc.Apply(ctx, e.req(t, "devops", "developer")); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { e.svc.Watch(ctx, 5*time.Millisecond); close(done) }()

	e.terminal(t, idA, hostpatch.StateFailed)
	deadline := time.Now().Add(5 * time.Second)
	for e.maintState(t).LastHostResult == "" {
		if time.Now().After(deadline) {
			t.Fatal("the watcher did not record the result")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not stop on cancel")
	}
}
