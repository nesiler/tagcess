package k8s

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
	k8sfix "github.com/nesiler/tagcess/test/k8s"
)

// readerEnv is a reader over a real temporary SQLite database, a protected temporary credential
// file and the F4-001 API stand-in. The profile names the stand-in's endpoint.
type readerEnv struct {
	t        *testing.T
	api      *apiEnv
	env      *env
	creds    *CredentialStore
	snaps    *SnapshotStore
	reader   *Reader
	clients  atomic.Int32 // clients built, i.e. reads that got past the credential/profile checks
	timeout  time.Duration
	profile  Profile
	cred     Credential
	newToken func() string
}

func newReaderEnv(t *testing.T) *readerEnv {
	t.Helper()
	api := newAPIEnv(t, envOpts{})
	e := newEnv(t)
	re := &readerEnv{t: t, api: api, env: e, timeout: 200 * time.Millisecond, newToken: func() string { return sentinel(t) }}
	re.cred = api.cred()
	re.creds, _ = newCredStore(t)
	if _, err := re.creds.Replace(re.cred); err != nil {
		t.Fatalf("credential Replace: %v", err)
	}
	re.profile = validProfile()
	re.profile.Endpoint = re.cred.Endpoint
	re.saveProfile(re.profile)
	re.snaps = NewSnapshotStore(e.st.DB(), e.st.Queries())
	re.reader = newReader(e.profiles, re.creds, re.snaps, func(c Credential) (inventoryClient, error) {
		re.clients.Add(1)
		return api.client(t, c, re.timeout), nil
	}, e.clock.Now)

	for _, ns := range []string{"web", "apps"} {
		api.fx.ServeList(k8sfix.Ingresses, ns, k8sfix.Page{Items: []any{item("i-" + ns + "-1"), item("i-" + ns + "-2")}})
		api.fx.ServeList(k8sfix.Services, ns, k8sfix.Page{Items: []any{item("s-" + ns)}})
	}
	api.fx.ServeList(k8sfix.IngressClasses, "", k8sfix.Page{Items: []any{item("traefik")}})
	return re
}

func (re *readerEnv) saveProfile(p Profile) {
	re.t.Helper()
	if err := re.env.profiles.Save(context.Background(), p); err != nil {
		re.t.Fatalf("profile Save: %v", err)
	}
}

func (re *readerEnv) mustNormalize(p Profile) Profile {
	re.t.Helper()
	canon, err := normalize(p)
	if err != nil {
		re.t.Fatalf("normalize: %v", err)
	}
	return canon
}

func (re *readerEnv) count(table string) int {
	re.t.Helper()
	var n int
	if err := re.env.st.DB().QueryRowContext(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		re.t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func (re *readerEnv) state() State {
	re.t.Helper()
	st, err := re.reader.State(context.Background())
	if err != nil {
		re.t.Fatalf("State: %v", err)
	}
	return st
}

func (re *readerEnv) mustRead() Snapshot {
	re.t.Helper()
	snap, err := re.reader.Read(context.Background())
	if err != nil {
		re.t.Fatalf("Read: %v", err)
	}
	return snap
}

func (re *readerEnv) failedRead() *FailedReadError {
	re.t.Helper()
	_, err := re.reader.Read(context.Background())
	var fe *FailedReadError
	if !errors.As(err, &fe) {
		re.t.Fatalf("Read error = %v, want a *FailedReadError", err)
	}
	return fe
}

func ingressNames(inv Inventory) []string { return nameList(inv.Ingresses, ingressName) }

// dumpText is every text column of the two snapshot tables, to look for secrets in what is stored.
func (re *readerEnv) dumpText() string {
	re.t.Helper()
	var all strings.Builder
	for _, q := range []string{
		"SELECT scope || profile_version || observed_at || payload FROM k8s_snapshots",
		"SELECT scope || profile_version || attempted_at || outcome || error_class || error FROM k8s_snapshot_attempts",
	} {
		rows, err := re.env.st.DB().QueryContext(context.Background(), q)
		if err != nil {
			re.t.Fatalf("dump: %v", err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				re.t.Fatalf("dump scan: %v", err)
			}
			all.WriteString(s)
		}
		_ = rows.Close()
	}
	return all.String()
}

// AC1: the snapshot is published once, after every page of every selected read succeeded, with one
// ID, one scope and one observed_at, together with its "ok" attempt.
func TestK8sReader_PublishesOnlyCompleteSnapshot(t *testing.T) {
	re := newReaderEnv(t)
	re.api.fx.ServeList(k8sfix.Ingresses, "web",
		k8sfix.Page{Items: []any{item("i-web-1"), item("i-web-2")}},
		k8sfix.Page{Items: []any{item("i-web-3")}},
	)

	// While the last read (IngressClasses) is still running, nothing may be visible yet.
	pair := pairOf(re.mustNormalize(re.profile))
	var visibleEarly atomic.Bool
	re.api.setIntercept(func(_ http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/ingressclasses") {
			if _, err := re.env.st.Queries().LatestK8sSnapshot(context.Background(), db.LatestK8sSnapshotParams{Scope: pair.Scope, ProfileVersion: pair.Version}); !errors.Is(err, sql.ErrNoRows) {
				visibleEarly.Store(true)
			}
		}
		return false
	})

	re.env.clock.Advance(90 * time.Second)
	want := re.env.clock.Now()
	snap := re.mustRead()
	if visibleEarly.Load() {
		t.Error("a snapshot was visible before the last resource was read")
	}

	if snap.ID == 0 || snap.Scope != "apps,web" || !snap.ObservedAt.Equal(want) {
		t.Errorf("snapshot = {ID:%d Scope:%q ObservedAt:%v}, want scope apps,web at %v", snap.ID, snap.Scope, snap.ObservedAt, want)
	}
	if got, w := ingressNames(snap.Inventory), []string{"i-apps-1", "i-apps-2", "i-web-1", "i-web-2", "i-web-3"}; !slices.Equal(got, w) {
		t.Errorf("ingresses = %v, want %v (all pages of all namespaces, deterministic order)", got, w)
	}
	if len(snap.Inventory.Services) != 2 || len(snap.Inventory.IngressClasses) != 1 {
		t.Errorf("services/classes = %d/%d, want 2/1", len(snap.Inventory.Services), len(snap.Inventory.IngressClasses))
	}

	st := re.state()
	if st.Current == nil || st.Current.ID != snap.ID || !st.Current.ObservedAt.Equal(want) || !slices.Equal(ingressNames(st.Current.Inventory), ingressNames(snap.Inventory)) {
		t.Fatalf("State.Current = %+v, want the published snapshot", st.Current)
	}
	if st.Stale || st.Previous != nil {
		t.Errorf("Stale=%v Previous=%v, want a fresh snapshot with no old scope", st.Stale, st.Previous)
	}
	if a := st.LastAttempt; a == nil || a.Outcome != OutcomeOK || a.SnapshotID != snap.ID || !a.AttemptedAt.Equal(want) {
		t.Errorf("LastAttempt = %+v, want ok linked to snapshot %d", a, snap.ID)
	}
	if n, m := re.count("k8s_snapshots"), re.count("k8s_snapshot_attempts"); n != 1 || m != 1 {
		t.Errorf("rows: snapshots=%d attempts=%d, want 1 and 1", n, m)
	}

	t.Run("a failed attempt write rolls the snapshot back", func(t *testing.T) {
		re := newReaderEnv(t)
		// An attempt insert that aborts must take the snapshot insert with it.
		if _, err := re.env.st.DB().ExecContext(context.Background(), "CREATE TRIGGER no_attempts BEFORE INSERT ON k8s_snapshot_attempts BEGIN SELECT RAISE(ABORT, 'no'); END"); err != nil {
			t.Fatalf("trigger: %v", err)
		}
		if _, err := re.reader.Read(context.Background()); err == nil {
			t.Fatal("Read succeeded although the attempt row could not be written")
		}
		if n := re.count("k8s_snapshots"); n != 0 {
			t.Errorf("snapshots = %d, want none: the snapshot and its ok attempt are one transaction", n)
		}
	})
}

// A-L1: a failed Publish is a failed attempt, so the earlier snapshot reads as stale.
func TestK8sReader_PublishFailureRecordsAttempt(t *testing.T) {
	re := newReaderEnv(t)
	good := re.mustRead()
	if _, err := re.env.st.DB().ExecContext(context.Background(), "CREATE TRIGGER no_snaps BEFORE INSERT ON k8s_snapshots BEGIN SELECT RAISE(ABORT, 'no'); END"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	re.env.clock.Advance(time.Minute)
	if _, err := re.reader.Read(context.Background()); err == nil {
		t.Fatal("Read succeeded although the snapshot could not be stored")
	}
	st := re.state()
	if st.Current == nil || st.Current.ID != good.ID || !st.Stale || st.LastAttempt == nil || st.LastAttempt.Outcome != OutcomeFailed {
		t.Errorf("State = %+v, want the old snapshot stale with a failed last attempt", st)
	}
}

// AC2: a read cut off by 401, 403, a timeout or a decode error keeps the previous snapshot, reports
// it as stale with the failed last attempt, and never turns missing data into absence.
func TestIngressSnapshotPartialReadKeepsPrevious(t *testing.T) {
	cases := []struct {
		name      string
		break_    func(re *readerEnv)
		wantClass string
	}{
		{"401 on a later page", func(re *readerEnv) {
			re.api.fx.ServeList(k8sfix.Ingresses, "web", k8sfix.Page{Items: []any{item("i-web-1")}}, k8sfix.Page{Items: []any{item("i-web-9")}})
			re.api.setIntercept(func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Query().Get("continue") != "" {
					http.Error(w, `{"kind":"Status","code":401}`, http.StatusUnauthorized)
					return true
				}
				return false
			})
		}, ClassCredentialExpired},
		{"403 on services", func(re *readerEnv) {
			re.api.fx.Fail(k8sfix.Services, "apps", k8sfix.Failure{Status: 403})
		}, ClassForbidden},
		{"403 on ingress classes", func(re *readerEnv) {
			re.api.fx.Fail(k8sfix.IngressClasses, "", k8sfix.Failure{Status: 403})
		}, ClassForbidden},
		{"timeout", func(re *readerEnv) {
			re.api.fx.Fail(k8sfix.Ingresses, "web", k8sfix.Failure{Hang: true})
		}, ClassTimeout},
		{"decode error", func(re *readerEnv) {
			re.api.fx.Fail(k8sfix.Services, "web", k8sfix.Failure{Status: 200, Body: `{"kind":"ServiceList","items":[{"metadata":`})
		}, ClassDecode},
		{"wrong list kind", func(re *readerEnv) {
			re.api.fx.Fail(k8sfix.Services, "web", k8sfix.Failure{Status: 200, Body: `{"kind":"IngressList","items":[]}`})
		}, ClassDecode},
		{"server error", func(re *readerEnv) {
			re.api.fx.Fail(k8sfix.Services, "web", k8sfix.Failure{Status: 500})
		}, ClassHTTP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := newReaderEnv(t)
			good := re.mustRead()

			// The inventory shrinks (every route gone) while the read breaks: a partial or failed read
			// must not look like that deletion.
			for _, ns := range []string{"web", "apps"} {
				re.api.fx.ServeList(k8sfix.Ingresses, ns, k8sfix.Page{Items: []any{}})
			}
			tc.break_(re)
			re.env.clock.Advance(time.Minute)
			failedAt := re.env.clock.Now()

			fe := re.failedRead()
			if fe.Class != tc.wantClass {
				t.Errorf("class = %q, want %q (message %q)", fe.Class, tc.wantClass, fe.Message)
			}

			st := re.state()
			if st.Current == nil || st.Current.ID != good.ID || !st.Current.ObservedAt.Equal(good.ObservedAt) {
				t.Fatalf("Current = %+v, want the previous snapshot %d at %v", st.Current, good.ID, good.ObservedAt)
			}
			if got := ingressNames(st.Current.Inventory); len(got) != 4 {
				t.Errorf("previous payload ingresses = %v, want the 4 it was published with", got)
			}
			if !st.Stale {
				t.Error("Stale = false after a failed read, want true")
			}
			a := st.LastAttempt
			if a == nil || a.Outcome != OutcomeFailed || a.Class != tc.wantClass || a.SnapshotID != 0 || !a.AttemptedAt.Equal(failedAt) || a.Message == "" {
				t.Errorf("LastAttempt = %+v, want failed/%s at %v with a message and no snapshot", a, tc.wantClass, failedAt)
			}
			if n := re.count("k8s_snapshots"); n != 1 {
				t.Errorf("snapshots = %d, want only the previous one", n)
			}
			if txt := re.dumpText() + fe.Error(); strings.Contains(txt, re.cred.Token) {
				t.Error("the token reached the store or the error")
			}
		})
	}

	t.Run("no previous snapshot is not an empty one", func(t *testing.T) {
		re := newReaderEnv(t)
		re.api.fx.Fail(k8sfix.Services, "web", k8sfix.Failure{Status: 403})
		_ = re.failedRead()
		st := re.state()
		if st.Current != nil || st.Stale || st.LastAttempt == nil || st.LastAttempt.Outcome != OutcomeFailed {
			t.Errorf("State = %+v, want no snapshot, not stale, a failed attempt", st)
		}
		if n := re.count("k8s_snapshots"); n != 0 {
			t.Errorf("snapshots = %d, want none", n)
		}
	})

	t.Run("a good read after the failure is fresh again", func(t *testing.T) {
		re := newReaderEnv(t)
		first := re.mustRead()
		re.api.fx.Fail(k8sfix.Services, "web", k8sfix.Failure{Status: 403})
		re.env.clock.Advance(time.Minute)
		_ = re.failedRead()
		re.api.fx.ServeList(k8sfix.Services, "web", k8sfix.Page{Items: []any{item("s-web")}})
		re.env.clock.Advance(time.Minute)
		second := re.mustRead()
		st := re.state()
		if second.ID == first.ID || st.Current == nil || st.Current.ID != second.ID || st.Stale {
			t.Errorf("Current = %+v Stale=%v, want the new snapshot %d, fresh", st.Current, st.Stale, second.ID)
		}
	})
}

// AC3: an expired token keeps the last good snapshot and its observation time; after the operator
// replaces the credential file the next read publishes a new snapshot.
func TestK8sReader_CredentialExpiryKeepsLastGoodSnapshot(t *testing.T) {
	re := newReaderEnv(t)
	good := re.mustRead()

	// The cluster stops accepting the stored token.
	renewed := re.newToken()
	re.api.setToken(renewed)
	re.env.clock.Advance(2 * time.Hour)

	fe := re.failedRead()
	if fe.Class != ClassCredentialExpired {
		t.Errorf("class = %q, want %q", fe.Class, ClassCredentialExpired)
	}
	st := re.state()
	if st.Current == nil || st.Current.ID != good.ID || !st.Current.ObservedAt.Equal(good.ObservedAt) || !st.Stale {
		t.Fatalf("State = %+v, want the last good snapshot %d at %v, stale", st, good.ID, good.ObservedAt)
	}
	if len(st.Current.Inventory.Ingresses) != 4 {
		t.Errorf("last good payload has %d ingresses, want 4: expiry is not an empty inventory", len(st.Current.Inventory.Ingresses))
	}
	if n := re.count("k8s_snapshots"); n != 1 {
		t.Errorf("snapshots = %d, want 1", n)
	}

	// The reader holds no token between reads: the manual renewal is picked up by the next one.
	renewedCred := re.cred
	renewedCred.Token = renewed
	if _, err := re.creds.Replace(renewedCred); err != nil {
		t.Fatalf("credential Replace: %v", err)
	}
	re.env.clock.Advance(time.Minute)
	next := re.mustRead()
	if next.ID == good.ID || !next.ObservedAt.After(good.ObservedAt) {
		t.Errorf("next snapshot = {ID:%d at %v}, want a new one after %v", next.ID, next.ObservedAt, good.ObservedAt)
	}
	if st := re.state(); st.Current == nil || st.Current.ID != next.ID || st.Stale || st.LastAttempt.Outcome != OutcomeOK {
		t.Errorf("State after renewal = %+v, want the new snapshot, fresh", st)
	}
	seen := re.api.Seen()
	if last := seen[len(seen)-1]; last.Authorization != "Bearer "+renewed {
		t.Error("the read after renewal did not use the new token")
	}

	if txt := re.dumpText() + fe.Error(); strings.Contains(txt, re.cred.Token) || strings.Contains(txt, renewed) || strings.Contains(txt, "BEGIN CERTIFICATE") {
		t.Error("a token or CA reached the snapshot tables or the error")
	}
}

// AC4: after a namespace or profile change the old scope's snapshot is not the current one; it is
// returned separately as old-scope data until the new scope has its first complete read.
func TestK8sReader_ProfileChangeDoesNotReuseCurrentScope(t *testing.T) {
	re := newReaderEnv(t)
	old := re.mustRead()
	if old.Scope != "apps,web" {
		t.Fatalf("scope = %q, want the sorted namespaces apps,web", old.Scope)
	}

	narrowed := re.profile
	narrowed.Namespaces = []string{"web"}
	re.saveProfile(narrowed)

	st := re.state()
	if st.Current != nil || st.Stale {
		t.Fatalf("Current = %+v Stale=%v after a scope change, want none", st.Current, st.Stale)
	}
	if st.Previous == nil || st.Previous.ID != old.ID || st.Previous.Scope != "apps,web" || !st.Previous.ObservedAt.Equal(old.ObservedAt) || len(st.Previous.Inventory.Ingresses) != 4 {
		t.Fatalf("Previous = %+v, want the old scope's snapshot %d, as is", st.Previous, old.ID)
	}
	if st.LastAttempt != nil {
		t.Errorf("LastAttempt = %+v, want none for the new scope", st.LastAttempt)
	}

	t.Run("a failed first read of the new scope keeps showing the old scope as old", func(t *testing.T) {
		re.api.fx.Fail(k8sfix.Services, "web", k8sfix.Failure{Status: 403})
		re.env.clock.Advance(time.Minute)
		_ = re.failedRead()
		st := re.state()
		if st.Current != nil || st.Previous == nil || st.Previous.ID != old.ID || st.LastAttempt == nil || st.LastAttempt.Outcome != OutcomeFailed {
			t.Errorf("State = %+v, want no current, the old scope kept, a failed attempt", st)
		}
		if n := re.count("k8s_snapshots"); n != 1 {
			t.Errorf("snapshots = %d, want only the old scope's", n)
		}
	})

	t.Run("the first complete read of the new scope replaces the old one", func(t *testing.T) {
		re.api.fx.ServeList(k8sfix.Services, "web", k8sfix.Page{Items: []any{item("s-web")}})
		re.env.clock.Advance(time.Minute)
		fresh := re.mustRead()
		if fresh.Scope != "web" || len(fresh.Inventory.Ingresses) != 2 {
			t.Errorf("new snapshot = {Scope:%q ingresses:%d}, want only the web namespace", fresh.Scope, len(fresh.Inventory.Ingresses))
		}
		st := re.state()
		if st.Current == nil || st.Current.ID != fresh.ID || st.Previous != nil || st.Stale {
			t.Errorf("State = %+v, want the new scope current with no old-scope data", st)
		}
	})
}

// A-M1: restoring an earlier scope must not show its old snapshot as the current inventory.
func TestK8sReader_ProfileRevertIsStale(t *testing.T) {
	re := newReaderEnv(t)
	orig := re.profile
	old := re.mustRead()

	t.Run("positive control: same pair, no other read in between, is fresh", func(t *testing.T) {
		if st := re.state(); st.Current == nil || st.Current.ID != old.ID || st.Stale {
			t.Fatalf("State = %+v, want the snapshot current and fresh", st)
		}
	})

	narrowed := orig
	narrowed.Namespaces = []string{"web"}
	re.saveProfile(narrowed)
	re.env.clock.Advance(time.Minute)
	re.mustRead()
	re.saveProfile(orig)

	t.Run("revert marks the older snapshot stale", func(t *testing.T) {
		st := re.state()
		if st.Current == nil || st.Current.ID != old.ID || !st.Stale {
			t.Errorf("State = %+v, want the old snapshot as Current with Stale=true", st)
		}
	})
	t.Run("a later good read is fresh again", func(t *testing.T) {
		re.env.clock.Advance(time.Minute)
		fresh := re.mustRead()
		if st := re.state(); st.Current == nil || st.Current.ID != fresh.ID || st.Stale {
			t.Errorf("State = %+v, want the new snapshot fresh", st)
		}
	})
}

// A change to what identifies the connection or the read (endpoint, TLS name, namespaces, classes,
// controller) is a different pair; listeners and the declared expiry do not touch the read, so they
// are not. The namespace order never matters.
func TestK8sReader_PairIdentity(t *testing.T) {
	base := validProfile()
	pair := func(p Profile) snapshotPair {
		t.Helper()
		canon, err := normalize(p)
		if err != nil {
			t.Fatalf("normalize: %v", err)
		}
		return pairOf(canon)
	}
	basePair := pair(base)

	different := map[string]func(p *Profile){
		"endpoint":        func(p *Profile) { p.Endpoint = "https://10.1.2.4:6443" },
		"tls server name": func(p *Profile) { p.TLSServerName = "api.example.test" },
		"namespaces":      func(p *Profile) { p.Namespaces = []string{"web"} },
		"more namespaces": func(p *Profile) { p.Namespaces = []string{"web", "apps", "ops"} },
		"ingress classes": func(p *Profile) { p.IngressClasses = []string{"traefik", "internal"} },
		"controller":      func(p *Profile) { p.Controller = "example.com/other" },
	}
	for name, change := range different {
		p := base
		change(&p)
		if got := pair(p); got == basePair {
			t.Errorf("%s: pair did not change (%+v)", name, got)
		}
	}
	same := map[string]func(p *Profile){
		"namespace order": func(p *Profile) { p.Namespaces = []string{"web", "apps"} },
		"listeners":       func(p *Profile) { p.Internal = []Listener{{Address: "10.1.2.99", Port: 8443}} },
		"declared expiry": func(p *Profile) { p.DeclaredTokenExpiry = t0.Add(time.Hour) },
	}
	for name, change := range same {
		p := base
		change(&p)
		if got := pair(p); got != basePair {
			t.Errorf("%s: pair changed (%+v vs %+v)", name, got, basePair)
		}
	}
	if basePair.Scope != "apps,web" {
		t.Errorf("scope = %q, want the sorted, comma-joined namespaces", basePair.Scope)
	}
}

// The credential must belong to the stored profile: another endpoint or TLS name is refused with a
// fixed error before anything is resolved, dialled or sent, and the profile is the authority.
func TestK8sReader_CredentialMustMatchProfile(t *testing.T) {
	cases := []struct {
		name    string
		profile func(p *Profile)
		cred    func(c *Credential)
	}{
		{"credential endpoint differs", nil, func(c *Credential) {
			c.Endpoint = "https://other.example.test:6443" + strings.TrimPrefix(c.Endpoint, "https://"+apiHost+":6443")
		}},
		{"credential port differs", nil, func(c *Credential) { c.Endpoint = "https://" + apiHost + ":7443" }},
		{"credential path differs", nil, func(c *Credential) { c.Endpoint += "/k8s/clusters/other" }},
		{"credential TLS name differs", nil, func(c *Credential) { c.TLSServerName = "other.example.test" }},
		{"profile TLS name differs", func(p *Profile) { p.TLSServerName = "other.example.test" }, nil},
		{"profile endpoint differs", func(p *Profile) { p.Endpoint = "https://other.example.test:6443" }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := newReaderEnv(t)
			if tc.profile != nil {
				p := re.profile
				tc.profile(&p)
				re.saveProfile(p)
			}
			if tc.cred != nil {
				c := re.cred
				tc.cred(&c)
				if _, err := re.creds.Replace(c); err != nil {
					t.Fatalf("credential Replace: %v", err)
				}
			}
			fe := re.failedRead()
			if fe.Class != ClassCredentialMismatch {
				t.Errorf("class = %q, want %q", fe.Class, ClassCredentialMismatch)
			}
			re.api.noNetwork(t)
			if n := re.api.resolver.Calls(); n != 0 {
				t.Errorf("resolver called %d times, want 0", n)
			}
			if n := re.clients.Load(); n != 0 {
				t.Errorf("%d clients built, want none before the check", n)
			}
			if strings.Contains(fe.Error(), "other.example.test") || strings.Contains(fe.Error(), re.cred.Token) {
				t.Errorf("error echoes a value: %q", fe.Error())
			}
			if st := re.state(); st.Current != nil || st.LastAttempt == nil || st.LastAttempt.Class != ClassCredentialMismatch {
				t.Errorf("State = %+v, want no snapshot and the mismatch as the last attempt", st)
			}
		})
	}

	t.Run("a matching credential reads", func(t *testing.T) {
		re := newReaderEnv(t)
		re.mustRead()
		if n := len(re.api.Seen()); n == 0 {
			t.Error("no request reached the API")
		}
	})
}

// Without a usable profile or credential nothing is read; the previous snapshot stays.
func TestK8sReader_FailsSafeWithoutProfileOrCredential(t *testing.T) {
	t.Run("no profile", func(t *testing.T) {
		re := newReaderEnv(t)
		if _, err := re.env.st.DB().ExecContext(context.Background(), "DELETE FROM settings WHERE key = ?", settingKey); err != nil {
			t.Fatalf("delete profile: %v", err)
		}
		if _, err := re.reader.Read(context.Background()); !errors.Is(err, ErrNotSet) {
			t.Fatalf("Read error = %v, want ErrNotSet", err)
		}
		if _, err := re.reader.State(context.Background()); !errors.Is(err, ErrNotSet) {
			t.Errorf("State error = %v, want ErrNotSet", err)
		}
		re.api.noNetwork(t)
		if n := re.count("k8s_snapshot_attempts"); n != 0 {
			t.Errorf("attempts = %d, want none: there is no scope to attribute the attempt to", n)
		}
	})

	t.Run("no credential", func(t *testing.T) {
		re := newReaderEnv(t)
		good := re.mustRead()
		seen := len(re.api.Seen())
		other, _ := newCredStore(t)
		re.reader = newReader(re.env.profiles, other, re.snaps, func(c Credential) (inventoryClient, error) {
			return re.api.client(t, c, re.timeout), nil
		}, re.env.clock.Now)
		re.env.clock.Advance(time.Minute)
		fe := re.failedRead()
		if fe.Class != ClassCredential || !errors.Is(fe, ErrCredentialNotSet) {
			t.Errorf("failure = %+v (%v), want class %q wrapping ErrCredentialNotSet", fe, fe.Unwrap(), ClassCredential)
		}
		if got := len(re.api.Seen()); got != seen {
			t.Errorf("requests grew from %d to %d, want none", seen, got)
		}
		if st := re.state(); st.Current == nil || st.Current.ID != good.ID || !st.Stale {
			t.Errorf("State = %+v, want the previous snapshot kept, stale", st)
		}
	})
}
