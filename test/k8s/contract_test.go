package k8s

// F4-034: the read-only contract of the real runtime path. The scenarios below drive the real product
// pieces, with nothing stubbed on the product side: the F4-004 client behind the F4-043 address policy,
// the F4-007 reader over SQLite, the F4-003 protected credential file and the F4-011/F4-030/F4-041
// handlers behind the devops/CSRF chain. Only the cluster is a target: the personal k3s (the
// `integration` tests of this package, opt-in through RequireLab) or, for the regression gate, a local
// TLS API (contractAPI) that behaves like the lab: bearer tokens, a namespace-scoped read role and
// SelfSubjectAccessReview. A passing run against the local API is not an acceptance run (F4-033 AC4).
//
// The product never writes to Kubernetes. The only writes of a scenario are the target's own: the lab
// tooling's `revoke`/`conflict` with the bootstrap identity (see lab.go).

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	ik8s "github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/web"
)

const (
	contractHost       = "fixture.k8s-lab.test"
	contractConflict   = "conflict.k8s-lab.test"
	contractController = "traefik.io/ingress-controller"
	contractClass      = "traefik"
)

// target is the cluster a scenario runs against. Token is valid at the start; Revoke makes every token
// issued so far invalid (HTTP 401, as an expired token) and NewToken returns a new valid one.
type target struct {
	Server, CAPEM, ServerName string // ServerName is a DNS name or empty (the endpoint host)
	Namespace                 string
	Class, Controller         string
	Token                     string
	Revoke                    func()
	NewToken                  func() string
	AddConflict               func()
	// Record stores a nonsecret evidence record (the lab record directory when set) and logs it.
	Record func(name string, v any)
}

// ---- local API target ------------------------------------------------------------------------------

type apiRequest struct {
	Method, Path string
	Access       *Access // set for a SelfSubjectAccessReview
}

type fakeIngress struct {
	name, uid  string
	host       string
	entrypoint bool
	paths      [][2]string // path, service
}

// contractAPI is a local TLS API shaped like the lab: it serves the three lists the product reads for
// the fixture namespace only, answers SelfSubjectAccessReview from allow, accepts only registered bearer
// tokens, and refuses (405) and records everything else, so a test can prove nothing was mutated.
type contractAPI struct {
	t     *testing.T
	ns    string
	url   string
	caPEM string

	mu        sync.Mutex
	valid     map[string]bool
	reqs      []apiRequest
	ingresses []fakeIngress
	services  []string
	allow     func(Access) bool
}

// contractIP returns a non-loopback IPv4 address of this machine: the F4-043 policy refuses loopback
// whatever it is configured with, so the real client cannot be pointed at 127.0.0.1.
func contractIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		skipUnlessGate(t, os.Getenv, "no network interfaces: %v", err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		ip = ip.Unmap()
		if !ok || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		return ip.String()
	}
	skipUnlessGate(t, os.Getenv, "no non-loopback IPv4 address: the API address policy refuses loopback, so the local API cannot be reached")
	return ""
}

// skipUnlessGate skips the local-API twins on a machine that cannot run them, except under CI or the
// gate (CI or TAGCESS_GATE set), where a silent skip would leave `make check` green with the contract
// untested (C-L11).
func skipUnlessGate(tb interface {
	Helper()
	Skipf(string, ...any)
	Fatalf(string, ...any)
}, getenv func(string) string, format string, args ...any) {
	tb.Helper()
	if getenv("CI") != "" || getenv("TAGCESS_GATE") != "" {
		tb.Fatalf(format+" (not allowed to skip under CI/TAGCESS_GATE)", args...)
	}
	tb.Skipf(format, args...)
}

// narrowAllow is the answer table of the lab's read-only ServiceAccount: get/list on Ingresses and
// Services of its namespace and on IngressClasses, nothing else.
func narrowAllow(ns string) func(Access) bool {
	return func(a Access) bool {
		read := (a.Verb == "get" || a.Verb == "list") && a.Subresource == ""
		switch {
		case a.Namespace == ns && a.Group == "networking.k8s.io" && a.Resource == "ingresses":
			return read
		case a.Namespace == ns && a.Group == "" && a.Resource == "services":
			return read
		case a.Namespace == "" && a.Group == "networking.k8s.io" && a.Resource == "ingressclasses":
			return read
		}
		return false
	}
}

func newContractAPI(t *testing.T, ns string) *contractAPI {
	t.Helper()
	const dns = "kubernetes.lab.test"
	ca, caKey, _ := newTestCA(t)
	leaf := newLeafCert(t, ca, caKey, dns)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", net.JoinHostPort(contractIP(t), "0"))
	if err != nil {
		t.Fatalf("contract API listen: %v", err)
	}
	a := &contractAPI{
		t: t, ns: ns, valid: map[string]bool{}, allow: narrowAllow(ns),
		caPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		services: []string{"fixture"},
		ingresses: []fakeIngress{{
			name: "fixture", uid: "uid-fixture", host: contractHost,
			paths: [][2]string{{"/", "fixture"}},
		}},
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(a.handle))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	a.url = srv.URL
	return a
}

// token mints a JWT-shaped token for the lab ServiceAccount (the product reads its sub claim for
// display) with a random tail, and registers it as valid.
func (a *contractAPI) token() string {
	a.t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		a.t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]string{"sub": "system:serviceaccount:" + a.ns + ":" + ik8s.DefaultServiceAccountName})
	enc := base64.RawURLEncoding
	tok := enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(claims) + "." + hex.EncodeToString(nonce)
	a.mu.Lock()
	a.valid[tok] = true
	a.mu.Unlock()
	return tok
}

func (a *contractAPI) revokeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.valid = map[string]bool{}
}

func (a *contractAPI) addConflict() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.services = append(a.services, "fixture-b")
	a.ingresses = append(a.ingresses, fakeIngress{
		name: "conflict", uid: "uid-conflict", host: contractConflict, entrypoint: true,
		paths: [][2]string{{"/", "fixture"}, {"/app", "fixture-b"}},
	})
}

func (a *contractAPI) requests() []apiRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.reqs)
}

// mutations are the requests that are neither a read nor a SelfSubjectAccessReview.
func (a *contractAPI) mutations() []apiRequest {
	var out []apiRequest
	for _, r := range a.requests() {
		if r.Method != http.MethodGet && r.Access == nil {
			out = append(out, r)
		}
	}
	return out
}

func (a *contractAPI) accesses() []Access {
	var out []Access
	for _, r := range a.requests() {
		if r.Access != nil {
			out = append(out, *r.Access)
		}
	}
	return out
}

func (a *contractAPI) handle(w http.ResponseWriter, r *http.Request) {
	req := apiRequest{Method: r.Method, Path: r.URL.Path}
	var body ssarBody
	if r.Method == http.MethodPost && r.URL.Path == ssarPath {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if json.Unmarshal(raw, &body) == nil {
			ra := body.Spec.ResourceAttributes
			req.Access = &Access{Namespace: ra.Namespace, Group: ra.Group, Resource: ra.Resource, Subresource: ra.Subresource, Verb: ra.Verb}
		}
	}
	a.mu.Lock()
	a.reqs = append(a.reqs, req)
	valid := a.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	ingresses, services, allow := slices.Clone(a.ingresses), slices.Clone(a.services), a.allow
	a.mu.Unlock()

	switch {
	case !valid:
		writeStatus(w, http.StatusUnauthorized, "Unauthorized", "Unauthorized")
	case req.Access != nil:
		ra := body.Spec.ResourceAttributes
		writeJSON(w, http.StatusCreated, map[string]any{
			"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
			"spec":   map[string]any{"resourceAttributes": ra},
			"status": map[string]any{"allowed": allow(*req.Access)},
		})
	case r.Method != http.MethodGet:
		writeStatus(w, http.StatusMethodNotAllowed, "method not allowed", "MethodNotAllowed")
	default:
		a.serveList(w, r.URL.Path, ingresses, services)
	}
}

func (a *contractAPI) serveList(w http.ResponseWriter, path string, ingresses []fakeIngress, services []string) {
	meta := func(name, uid string) map[string]any {
		return map[string]any{"name": name, "namespace": a.ns, "uid": uid, "resourceVersion": "7"}
	}
	list := func(kind string, items []any) {
		writeJSON(w, http.StatusOK, map[string]any{"kind": kind, "apiVersion": "v1", "metadata": map[string]any{"resourceVersion": "7"}, "items": items})
	}
	switch {
	case path == "/apis/networking.k8s.io/v1/ingressclasses":
		list("IngressClassList", []any{map[string]any{
			"metadata": map[string]any{"name": contractClass, "uid": "uid-class", "resourceVersion": "3"},
			"spec":     map[string]any{"controller": contractController},
		}})
	case path == "/apis/networking.k8s.io/v1/namespaces/"+a.ns+"/ingresses":
		items := []any{}
		for _, ing := range ingresses {
			m := meta(ing.name, ing.uid)
			if ing.entrypoint {
				m["annotations"] = map[string]any{"traefik.ingress.kubernetes.io/router.entrypoints": "websecure"}
			}
			var paths []any
			for _, p := range ing.paths {
				paths = append(paths, map[string]any{"path": p[0], "pathType": "Prefix",
					"backend": map[string]any{"service": map[string]any{"name": p[1], "port": map[string]any{"number": 80}}}})
			}
			items = append(items, map[string]any{"metadata": m, "spec": map[string]any{
				"ingressClassName": contractClass,
				"rules":            []any{map[string]any{"host": ing.host, "http": map[string]any{"paths": paths}}},
			}})
		}
		list("IngressList", items)
	case path == "/api/v1/namespaces/"+a.ns+"/services":
		items := []any{}
		for _, s := range services {
			items = append(items, map[string]any{"metadata": meta(s, "uid-"+s),
				"spec": map[string]any{"type": "ClusterIP", "clusterIP": "10.43.0.1", "ports": []any{map[string]any{"port": 80, "protocol": "TCP"}}}})
		}
		list("ServiceList", items)
	case strings.HasPrefix(path, "/api/v1/namespaces/"), strings.HasPrefix(path, "/apis/networking.k8s.io/v1/namespaces/"):
		writeStatus(w, http.StatusForbidden, "forbidden: the service account cannot list in this namespace", "Forbidden")
	default:
		writeStatus(w, http.StatusNotFound, "not found", "NotFound")
	}
}

// localTarget is the regression-gate target over a contractAPI.
func localTarget(t *testing.T) (*target, *contractAPI) {
	t.Helper()
	api := newContractAPI(t, "tagcess-k8s-lab-0a1b2c3d")
	tg := &target{
		Server: api.url, CAPEM: api.caPEM, ServerName: "kubernetes.lab.test", Namespace: api.ns,
		Class: contractClass, Controller: contractController, Token: api.token(),
		Revoke: api.revokeAll, NewToken: api.token, AddConflict: api.addConflict,
		Record: func(name string, v any) { t.Logf("%s: %s", name, mustJSON(t, v)) },
	}
	return tg, api
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("encode record: %v", err)
	}
	return string(b)
}

// ---- the product stack under test ------------------------------------------------------------------

// stack is the real product path over one target: protected credential file, API policy, profile,
// reader and snapshot store, and the three k8s screens behind the devops/CSRF chain.
type stack struct {
	t        *testing.T
	tg       *target
	store    *store.Store
	policy   *netpolicy.Store
	profiles *ik8s.ProfileStore
	creds    *ik8s.CredentialStore
	snaps    *ik8s.SnapshotStore
	reader   *ik8s.Reader
	clock    *Clock
	csrf     *web.CSRF
	chain    http.Handler
	disc     *stackDiscovery
	profile  ik8s.Profile
}

// stackConnector is the F4-004 read-only connection attempt of the connection screen: a client with the
// candidate credential behind the API policy lists the profile's resources (GET only).
type stackConnector struct {
	policy *netpolicy.Store
	ns     string
}

func (c stackConnector) Connect(ctx context.Context, cred ik8s.Credential) error {
	cl, err := ik8s.NewClient(cred, c.policy)
	if err != nil {
		return err
	}
	defer cl.Close()
	if _, err := cl.ListIngressClasses(ctx); err != nil {
		return err
	}
	_, err = cl.ListIngresses(ctx, c.ns)
	return err
}

// stackDiscovery stands in for the F4-031 wiring of the discovery screen: the stored state of the
// reader, interpreted against the stored profile.
type stackDiscovery struct {
	reader   *ik8s.Reader
	profiles *ik8s.ProfileStore
	managed  []ik8s.ManagedSite
}

func (d *stackDiscovery) Discovery(ctx context.Context) (web.K8sDiscovery, error) {
	st, err := d.reader.State(ctx)
	if err != nil {
		return web.K8sDiscovery{}, err
	}
	p, err := d.profiles.Get(ctx)
	if err != nil {
		return web.K8sDiscovery{}, err
	}
	var inv ik8s.Inventory
	if st.Current != nil {
		inv = st.Current.Inventory
	}
	complete := st.Current != nil && !st.Stale
	report := ik8s.BuildDrafts(ik8s.DraftInputs{
		Report: ik8s.InterpretRoutes(inv, p), Profile: p, Managed: d.managed, Complete: complete,
	})
	return web.K8sDiscovery{Report: report, State: st}, nil
}

// apiPolicyInput allows exactly the API endpoint's addresses and port.
func apiPolicyInput(t *testing.T, server string) netpolicy.Input {
	t.Helper()
	u, err := url.Parse(server)
	if err != nil {
		t.Fatalf("API endpoint %q: %v", server, err)
	}
	port := 443
	if p := u.Port(); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			t.Fatalf("API endpoint port %q: %v", p, err)
		}
	}
	var addrs []string
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		addrs = append(addrs, ip.String())
	} else {
		ips, err := net.DefaultResolver.LookupIPAddr(t.Context(), u.Hostname())
		if err != nil || len(ips) == 0 {
			t.Fatalf("API endpoint host %q does not resolve: %v", u.Hostname(), err)
		}
		for _, ip := range ips {
			addrs = append(addrs, ip.IP.String())
		}
	}
	return netpolicy.Input{Addresses: addrs, Ports: []int{port}}
}

func newStack(t *testing.T, tg *target) *stack {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := &stack{t: t, tg: tg, store: st, clock: NewClock(time.Now().UTC().Truncate(time.Second))}

	s.policy = netpolicy.New(st.DB(), st.Queries())
	if err := s.policy.Set(ctx, netpolicy.ScopeAPI, apiPolicyInput(t, tg.Server)); err != nil {
		t.Fatalf("API policy (the endpoint must be a non-loopback address): %v", err)
	}
	s.profiles = ik8s.NewProfileStore(st.DB(), st.Queries(), s.policy, s.clock.Now)
	s.profile = ik8s.Profile{
		Endpoint: tg.Server, TLSServerName: tg.ServerName, Namespaces: []string{tg.Namespace},
		Controller: tg.Controller, IngressClasses: []string{tg.Class},
		Internal:            []ik8s.Listener{{Address: "10.20.0.10", Port: 8443, EntryPoint: "websecure"}},
		Public:              []ik8s.Listener{{Address: "203.0.113.10", Port: 443, EntryPoint: "websecure-public"}},
		DeclaredTokenExpiry: s.clock.Now().Add(20 * time.Minute),
	}
	if err := s.profiles.Save(ctx, s.profile); err != nil {
		t.Fatalf("profile Save: %v", err)
	}

	// The runtime credential lives in a protected file outside SQLite and the repo.
	s.creds = ik8s.NewCredentialStore(filepath.Join(t.TempDir(), "runtime"))
	if _, err := s.creds.Replace(s.credential(tg.Token)); err != nil {
		t.Fatalf("credential Replace: %v", err)
	}
	s.snaps = ik8s.NewSnapshotStore(st.DB(), st.Queries())
	s.reader = ik8s.NewReader(s.profiles, s.creds, s.snaps, s.policy, s.clock.Now)
	s.disc = &stackDiscovery{reader: s.reader, profiles: s.profiles}

	s.csrf, err = web.NewCSRF([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	aud := audit.New(st.Queries())
	conn, err := web.NewK8sConnectionHandler(web.K8sConnectionConfig{
		Profiles: s.profiles, Creds: s.creds, Connector: stackConnector{policy: s.policy, ns: tg.Namespace},
		Auditor: aud, CSRF: s.csrf, Now: s.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewK8sConnectionHandler: %v", err)
	}
	disc, err := web.NewK8sDiscoveryHandler(web.K8sDiscoveryConfig{Reader: s.disc, CSRF: s.csrf})
	if err != nil {
		t.Fatalf("NewK8sDiscoveryHandler: %v", err)
	}
	setup, err := web.NewK8sSetupHandler(web.K8sSetupConfig{
		Profiles: s.profiles, Policy: s.policy, Review: s.review, Auditor: aud, CSRF: s.csrf, Now: s.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewK8sSetupHandler: %v", err)
	}
	mux := http.NewServeMux()
	conn.Register(mux)
	disc.Register(mux)
	setup.Register(mux)
	s.chain = web.RequireDevops(s.csrf.Protect(mux))
	return s
}

func (s *stack) credential(token string) ik8s.Credential {
	return ik8s.Credential{Endpoint: s.tg.Server, TLSServerName: s.tg.ServerName, CAData: s.tg.CAPEM, Token: token}
}

// review is the F4-005 selected permission review with the stored runtime credential.
func (s *stack) review(ctx context.Context, namespaces []string) (ik8s.Review, error) {
	cred, err := s.creds.Load()
	if err != nil {
		return ik8s.Review{}, err
	}
	prof, err := s.profiles.Get(ctx)
	if err != nil {
		return ik8s.Review{}, err
	}
	cl, err := ik8s.ClientForProfile(prof, cred, s.policy)
	if err != nil {
		return ik8s.Review{}, err
	}
	defer cl.Close()
	return ik8s.ReviewPermissions(ctx, cl, namespaces, s.clock.Now)
}

func (s *stack) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	s.t.Helper()
	var body io.Reader = strings.NewReader("")
	if form != nil {
		form = cloneForm(form)
		form.Set(web.CSRFParam, s.csrf.Token())
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequestWithContext(s.t.Context(), method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("X-Auth-Request-User", "devops-user")
	req.Header.Set("X-Auth-Request-Email", "devops@example.com")
	req.Header.Set("X-Auth-Request-Groups", "devops")
	rec := httptest.NewRecorder()
	s.chain.ServeHTTP(rec, req)
	return rec
}

func cloneForm(in url.Values) url.Values {
	out := url.Values{}
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}

func (s *stack) postCredential(token string) *httptest.ResponseRecorder {
	s.t.Helper()
	return s.do(http.MethodPost, "/k8s/connection/credential", url.Values{
		"endpoint": {s.tg.Server}, "tls_server_name": {s.tg.ServerName}, "ca_data": {s.tg.CAPEM}, "token": {token},
	})
}

func (s *stack) mustRead() ik8s.Snapshot {
	s.t.Helper()
	snap, err := s.reader.Read(s.t.Context())
	if err != nil {
		s.t.Fatalf("Read: %v", err)
	}
	return snap
}

func (s *stack) failedRead() *ik8s.FailedReadError {
	s.t.Helper()
	_, err := s.reader.Read(s.t.Context())
	var fe *ik8s.FailedReadError
	if !errors.As(err, &fe) {
		s.t.Fatalf("Read error = %v, want a *FailedReadError", err)
	}
	return fe
}

func (s *stack) state() ik8s.State {
	s.t.Helper()
	st, err := s.reader.State(s.t.Context())
	if err != nil {
		s.t.Fatalf("State: %v", err)
	}
	return st
}

// dbText is every text cell of every table: where a leaked secret would be found.
func (s *stack) dbText() string {
	s.t.Helper()
	db, ctx := s.store.DB(), s.t.Context()
	tables, err := db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		s.t.Fatalf("list tables: %v", err)
	}
	var names []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			s.t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = tables.Close()
	var all strings.Builder
	for _, n := range names {
		rows, err := db.QueryContext(ctx, "SELECT * FROM \""+n+"\"") //nolint:gosec // table names come from sqlite_master
		if err != nil {
			s.t.Fatalf("dump %s: %v", n, err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			cells := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range cells {
				ptrs[i] = &cells[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				s.t.Fatal(err)
			}
			for _, c := range cells {
				switch v := c.(type) {
				case []byte:
					all.Write(v)
				case string:
					all.WriteString(v)
				}
				all.WriteByte(' ')
			}
		}
		_ = rows.Close()
	}
	return all.String()
}

func (s *stack) count(table string) int {
	s.t.Helper()
	var n int
	if err := s.store.DB().QueryRowContext(s.t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		s.t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// noSecret fails when text holds a token or the CA body.
func noSecret(t *testing.T, where, text string, secrets ...string) {
	t.Helper()
	for _, sec := range secrets {
		if sec != "" && strings.Contains(text, sec) {
			t.Errorf("%s holds a secret value (%d bytes)", where, len(sec))
		}
	}
	if strings.Contains(text, "BEGIN CERTIFICATE") || strings.Contains(text, "PRIVATE KEY") {
		t.Errorf("%s holds PEM material", where)
	}
}

// spec returns the inventory without resourceVersion: a controller may update an object's status
// between two reads, which moves the version but not what tagcess keeps.
func spec(t *testing.T, inv ik8s.Inventory) string {
	t.Helper()
	var c ik8s.Inventory
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	for i := range c.Ingresses {
		c.Ingresses[i].Metadata.ResourceVersion = ""
	}
	for i := range c.Services {
		c.Services[i].Metadata.ResourceVersion = ""
	}
	for i := range c.IngressClasses {
		c.IngressClasses[i].Metadata.ResourceVersion = ""
	}
	out, _ := json.Marshal(c)
	return string(out)
}

// ---- scenarios --------------------------------------------------------------------------------------

// scenarioReadOnly is F4-034 AC1: with the runtime ServiceAccount's own token the reader makes a full
// snapshot of the selected namespace and the permitted IngressClass list, and the read is recorded
// without a secret. A namespace outside the grant is refused (403) and never becomes a snapshot.
func scenarioReadOnly(t *testing.T, tg *target) {
	t.Helper()
	s := newStack(t, tg)
	ctx := t.Context()

	snap := s.mustRead()
	inv := snap.Inventory
	if len(inv.Ingresses) == 0 || len(inv.Services) == 0 {
		t.Fatalf("snapshot is not complete: %d ingresses, %d services", len(inv.Ingresses), len(inv.Services))
	}
	for _, ing := range inv.Ingresses {
		if ing.Metadata.Namespace != tg.Namespace {
			t.Errorf("ingress %s/%s is outside the selected namespace", ing.Metadata.Namespace, ing.Metadata.Name)
		}
	}
	for _, svc := range inv.Services {
		if svc.Metadata.Namespace != tg.Namespace {
			t.Errorf("service %s/%s is outside the selected namespace", svc.Metadata.Namespace, svc.Metadata.Name)
		}
	}
	if !slices.ContainsFunc(inv.IngressClasses, func(c ik8s.IngressClass) bool { return c.Metadata.Name == tg.Class }) {
		t.Errorf("the permitted IngressClass list has no %q", tg.Class)
	}

	// The record of the same read: endpoint, principal and time; no token, no CA, no kubeconfig.
	review, err := s.review(ctx, []string{tg.Namespace})
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if want := "system:serviceaccount:" + tg.Namespace + ":" + ik8s.DefaultServiceAccountName; review.Principal != want {
		t.Errorf("principal = %q, want %q", review.Principal, want)
	}
	rec := struct {
		Endpoint       string    `json:"endpoint"`
		Principal      string    `json:"principal"`
		ObservedAt     time.Time `json:"observedAt"`
		Scope          string    `json:"scope"`
		Ingresses      int       `json:"ingresses"`
		Services       int       `json:"services"`
		IngressClasses int       `json:"ingressClasses"`
	}{tg.Server, review.Principal, snap.ObservedAt, snap.Scope, len(inv.Ingresses), len(inv.Services), len(inv.IngressClasses)}
	tg.Record("k8s-lab-read.json", rec)
	noSecret(t, "read record", mustJSON(t, rec), tg.Token)

	if !review.Passed() {
		t.Errorf("the lab ServiceAccount's selected permission review did not pass: %v", review.Problems())
	}

	// Reading again changes nothing that tagcess keeps: no object was written by the product.
	again := s.mustRead()
	if spec(t, again.Inventory) != spec(t, inv) {
		t.Error("the inventory changed between two reads of an unchanged cluster")
	}

	// A namespace outside the grant: refused, recorded as a failed attempt, never a snapshot. The
	// earlier scope's snapshot stays visible, labelled as old-scope data.
	wide := s.profile
	wide.Namespaces = []string{tg.Namespace, "kube-system"}
	if err := s.profiles.Save(ctx, wide); err != nil {
		t.Fatalf("profile Save (wider scope): %v", err)
	}
	before := s.count("k8s_snapshots")
	fe := s.failedRead()
	if fe.Class != ik8s.ClassForbidden {
		t.Errorf("out-of-scope read class = %q, want %q", fe.Class, ik8s.ClassForbidden)
	}
	if got := s.count("k8s_snapshots"); got != before {
		t.Errorf("a forbidden read left a snapshot (%d -> %d rows)", before, got)
	}
	st := s.state()
	if st.Current != nil || st.Previous == nil || st.Previous.ID != again.ID {
		t.Errorf("wider scope state: current=%v previous=%v, want no current and the old scope's snapshot %d", st.Current, st.Previous, again.ID)
	}
	if st.LastAttempt == nil || st.LastAttempt.Outcome != ik8s.OutcomeFailed || st.LastAttempt.Class != ik8s.ClassForbidden {
		t.Errorf("last attempt = %+v, want a failed forbidden attempt", st.LastAttempt)
	}
	noSecret(t, "stored state", s.dbText(), tg.Token)

	// Back to the granted scope: its last good snapshot is intact and current.
	if err := s.profiles.Save(ctx, s.profile); err != nil {
		t.Fatalf("profile Save (restore): %v", err)
	}
	if st := s.state(); st.Current == nil || st.Current.ID != again.ID || st.Stale {
		t.Errorf("restored scope state = %+v, want snapshot %d current and not stale", st, again.ID)
	}
}

// scenarioExpiry is F4-034 AC3: when the credential stops working and its declared time has passed, the
// last complete snapshot stays, and the discovery and connection screens show the API error, the
// staleness and the expiry warning.
func scenarioExpiry(t *testing.T, tg *target) {
	t.Helper()
	s := newStack(t, tg)
	snap := s.mustRead()

	tg.Revoke()
	s.clock.Advance(21 * time.Minute) // past the declared token expiry
	fe := s.failedRead()
	if fe.Class != ik8s.ClassCredentialExpired {
		t.Fatalf("failed read class = %q, want %q", fe.Class, ik8s.ClassCredentialExpired)
	}

	st := s.state()
	if st.Current == nil || st.Current.ID != snap.ID || !st.Stale {
		t.Fatalf("state = %+v, want the last good snapshot %d, stale", st, snap.ID)
	}
	if spec(t, st.Current.Inventory) != spec(t, snap.Inventory) || !st.Current.ObservedAt.Equal(snap.ObservedAt) {
		t.Error("the last good snapshot changed after the failed read")
	}
	if st.LastAttempt == nil || st.LastAttempt.Outcome != ik8s.OutcomeFailed || st.LastAttempt.Class != ik8s.ClassCredentialExpired {
		t.Errorf("last attempt = %+v, want a failed credential_expired attempt", st.LastAttempt)
	}
	if got := s.count("k8s_snapshots"); got != 1 {
		t.Errorf("snapshot rows = %d, want 1", got)
	}

	page := s.do(http.MethodGet, "/k8s/discovery", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("discovery page = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		`data-freshness="stale"`, "Güncel değil: son tarama başarısız", "credential_expired",
		snap.ObservedAt.UTC().Format(time.RFC3339), `data-snapshot-id="` + fmt.Sprint(snap.ID) + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("discovery page lacks %q", want)
		}
	}
	noSecret(t, "discovery page", body, tg.Token)

	conn := s.do(http.MethodGet, "/k8s/connection", nil)
	if conn.Code != http.StatusOK || !strings.Contains(conn.Body.String(), "beyan edilen süre geçti") {
		t.Errorf("connection page (%d) does not warn that the declared token time has passed", conn.Code)
	}
	noSecret(t, "connection page", conn.Body.String(), tg.Token)
}

// scenarioRotation is F4-034 AC4: after the credential stopped working, the operator uploads a new token
// the installer issued; the upload is checked with a read-only connection attempt, the next full read
// completes with it, and the old snapshot is kept next to the new one.
func scenarioRotation(t *testing.T, tg *target) {
	t.Helper()
	s := newStack(t, tg)
	oldToken := tg.Token
	first := s.mustRead()

	tg.Revoke()
	s.clock.Advance(21 * time.Minute)
	if fe := s.failedRead(); fe.Class != ik8s.ClassCredentialExpired {
		t.Fatalf("failed read class = %q, want %q", fe.Class, ik8s.ClassCredentialExpired)
	}

	// The old (now rejected) token is refused by the connection attempt and the stored credential stays.
	rec := s.postCredential(oldToken)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "önceki credential korundu") {
		t.Errorf("uploading a rejected token = %d, want 502 with the previous credential kept", rec.Code)
	}
	noSecret(t, "refused upload page", rec.Body.String(), oldToken)

	newToken := tg.NewToken()
	rec = s.postCredential(newToken)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "credential güncellendi") {
		t.Fatalf("uploading the new token = %d, want 200 with the success notice", rec.Code)
	}
	noSecret(t, "upload page", rec.Body.String(), oldToken, newToken)
	if cred, err := s.creds.Load(); err != nil || cred.Token != newToken {
		t.Fatalf("the runtime credential is not the uploaded token (err=%v)", err)
	}

	second := s.mustRead()
	if second.ID == first.ID {
		t.Fatal("the read after the rotation did not publish a new snapshot")
	}
	st := s.state()
	if st.Current == nil || st.Current.ID != second.ID || st.Stale || st.LastAttempt == nil || st.LastAttempt.Outcome != ik8s.OutcomeOK {
		t.Errorf("state after the rotation = %+v, want snapshot %d current, not stale, last attempt ok", st, second.ID)
	}
	if got := s.count("k8s_snapshots"); got != 2 {
		t.Errorf("snapshot rows = %d, want the old and the new one", got)
	}
	if spec(t, second.Inventory) != spec(t, first.Inventory) {
		t.Error("the inventory read with the new token differs from the one read before the expiry")
	}

	page := s.do(http.MethodGet, "/k8s/discovery", nil)
	if !strings.Contains(page.Body.String(), `data-freshness="current"`) {
		t.Error("the discovery page does not show the new snapshot as current")
	}
	noSecret(t, "discovery page", page.Body.String(), oldToken, newToken)
	noSecret(t, "stored state and audit", s.dbText(), oldToken, newToken)
}

// scenarioConflict is F4-034 AC5: an Ingress whose paths overlap with different backends is shown as a
// review request with its candidates and no default target, and an existing site is left as it is.
func scenarioConflict(t *testing.T, tg *target) {
	t.Helper()
	tg.AddConflict()
	s := newStack(t, tg)
	existing := ik8s.ManagedSite{ID: 7, Hosts: []string{contractConflict}, AccessChoice: ik8s.AccessChoiceRole, Roles: []string{"devops"}}
	s.disc.managed = []ik8s.ManagedSite{existing}
	s.mustRead()

	got, err := s.disc.Discovery(t.Context())
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}
	if len(got.Report.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want exactly the lab's overlapping Ingress", got.Report.Conflicts)
	}
	c := got.Report.Conflicts[0]
	if c.Host != contractConflict || c.Default != nil || len(c.Candidates) != 2 {
		t.Errorf("conflict = %+v, want host %s, two candidates and no default", c, contractConflict)
	}
	if len(got.Report.Managed) != 1 || got.Report.Managed[0].SiteID != existing.ID ||
		got.Report.Managed[0].AccessChoice != existing.AccessChoice || !reflect.DeepEqual(got.Report.Managed[0].Roles, existing.Roles) {
		t.Errorf("managed observation = %+v, want site %d unchanged", got.Report.Managed, existing.ID)
	}
	if !reflect.DeepEqual(s.disc.managed, []ik8s.ManagedSite{existing}) {
		t.Error("the existing site input was changed")
	}

	body := s.do(http.MethodGet, "/k8s/discovery", nil).Body.String()
	for _, want := range []string{
		contractConflict, "Route çelişkileri", "Varsayılan: bilinmiyor", "/app -&gt; fixture-b", "Mevcut site eşlemeleri",
		"seçili roller", "devops",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("discovery page lacks %q", want)
		}
	}
	noSecret(t, "discovery page", body, tg.Token)

	// The same conflict on a host no site owns is a draft that waits for review, with no default.
	s.disc.managed = nil
	got, err = s.disc.Discovery(t.Context())
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}
	var draft *ik8s.Draft
	for i := range got.Report.Drafts {
		if got.Report.Drafts[i].Host == contractConflict {
			draft = &got.Report.Drafts[i]
		}
	}
	switch {
	case draft == nil:
		t.Fatalf("no draft for %s: %+v", contractConflict, got.Report.Drafts)
	case draft.ReviewState != ik8s.ReviewStateNeeded || draft.ReviewDefault != "" || len(draft.ReviewCandidates) != 2 ||
		!strings.Contains(draft.ReviewReason, string(ik8s.ReasonRouteConflict)) || draft.Complete():
		t.Errorf("conflict draft = %+v, want a review request with two candidates, no default and not complete", *draft)
	}
	body = s.do(http.MethodGet, "/k8s/discovery", nil).Body.String()
	for _, want := range []string{"Çelişen adaylar", "Varsayılan: bilinmiyor", "inceleme gerekli", "route çelişkisi"} {
		if !strings.Contains(body, want) {
			t.Errorf("discovery page lacks %q for the unowned host", want)
		}
	}
}

// ---- regression-gate runs against the local API ----------------------------------------------------

func TestContractLocalAPI_ReadOnlyPermissionsAndForbiddenSnapshot(t *testing.T) {
	tg, api := localTarget(t)
	scenarioReadOnly(t, tg)
	if m := api.mutations(); len(m) != 0 {
		t.Errorf("the product sent non-read requests: %+v", m)
	}
}

func TestContractLocalAPI_CredentialExpiryKeepsLastGoodSnapshot(t *testing.T) {
	tg, api := localTarget(t)
	scenarioExpiry(t, tg)
	if m := api.mutations(); len(m) != 0 {
		t.Errorf("the product sent non-read requests: %+v", m)
	}
}

func TestContractLocalAPI_CredentialRotationKeepsSnapshots(t *testing.T) {
	tg, api := localTarget(t)
	scenarioRotation(t, tg)
	if m := api.mutations(); len(m) != 0 {
		t.Errorf("the product sent non-read requests: %+v", m)
	}
}

func TestContractLocalAPI_ConflictStaysUnknown(t *testing.T) {
	tg, api := localTarget(t)
	scenarioConflict(t, tg)
	if m := api.mutations(); len(m) != 0 {
		t.Errorf("the product sent non-read requests: %+v", m)
	}
}

// AC2: the selected permission review only asks (a SelfSubjectAccessReview is a question and changes
// nothing), reports only what it asked, and shows a denial where the fixture contract says denied.
// A wide fixture, whose answers allow everything, is used only to prove the result claim: it fails the
// review, names each operation that must be denied and still never says "read-only". Nothing is
// created, updated or deleted: no real mutation is attempted, with either fixture.
func TestK8sSelectedPermissionsHaveNoMutation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		allow      func(ns string) func(Access) bool
		wantPassed bool
	}{
		{"narrow fixture", narrowAllow, true},
		{"wide fixture", func(string) func(Access) bool { return func(Access) bool { return true } }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg, api := localTarget(t)
			api.allow = tc.allow(api.ns)
			s := newStack(t, tg)

			rec := s.do(http.MethodPost, "/k8s/setup/review", url.Values{})
			if rec.Code != http.StatusOK {
				t.Fatalf("review = %d", rec.Code)
			}
			page := rec.Body.String()
			noSecret(t, "review page", page, tg.Token)

			review, err := s.review(t.Context(), []string{api.ns})
			if err != nil {
				t.Fatal(err)
			}
			if review.Passed() != tc.wantPassed {
				t.Errorf("Passed = %v, want %v (problems: %v)", review.Passed(), tc.wantPassed, review.Problems())
			}

			// The result is limited to what was asked: every check is an asked access, and the asked
			// accesses are exactly the checks.
			var checks []Access
			for _, c := range append(slices.Clone(review.Required), review.Forbidden...) {
				checks = append(checks, Access{Namespace: c.Namespace, Group: c.Group, Resource: c.Resource, Subresource: c.Subresource, Verb: c.Verb})
				if !c.Answered {
					t.Errorf("%s was not answered", c)
				}
			}
			asked := api.accesses()
			if len(asked) != 2*len(checks) { // once through the screen, once directly
				t.Errorf("%d accesses asked for %d checks twice", len(asked), len(checks))
			}
			for _, a := range asked {
				if !slices.Contains(checks, a) {
					t.Errorf("an access outside the review was asked: %+v", a)
				}
			}

			// Secrets, token creation, mutations and out-of-scope reads are all among the asked
			// denials; the narrow fixture denies them, the wide one is reported as a problem.
			want := map[string]bool{"get secrets": false, "create serviceaccounts/token": false, "delete ingresses": false,
				"update services": false, "list ingresses in namespace \"default\"": false, "list services in all namespaces": false}
			for _, c := range review.Forbidden {
				for k := range want {
					if strings.Contains(strings.ReplaceAll(c.String(), ".networking.k8s.io", ""), k) {
						want[k] = true
						if c.Allowed == !tc.wantPassed {
							continue
						}
						if tc.wantPassed {
							t.Errorf("%s must be denied but was allowed", c)
						}
					}
				}
			}
			for k, seen := range want {
				if !seen {
					t.Errorf("the review did not ask about %q", k)
				}
			}
			if !tc.wantPassed {
				problems := strings.Join(review.Problems(), "\n")
				if !strings.Contains(problems, "get secrets in namespace") || !strings.Contains(problems, "allowed, but must be denied") {
					t.Errorf("wide fixture problems do not name the allowed secret read:\n%s", problems)
				}
				if !strings.Contains(page, "must be denied") && !strings.Contains(page, "reddedilmeli") {
					t.Error("the review page does not show an allowed operation that must be denied")
				}
			}

			summary := review.Summary()
			if !strings.Contains(summary, "Checked only these operations") || strings.Contains(strings.ToLower(summary), "read-only account") ||
				strings.Contains(summary, "is read-only") {
				t.Errorf("summary claims more than it checked: %s", summary)
			}
			if m := api.mutations(); len(m) != 0 {
				t.Errorf("a non-review, non-read request reached the API: %+v", m)
			}
			for _, r := range api.requests() {
				if r.Method == http.MethodPost && r.Access == nil {
					t.Errorf("unexpected POST %s", r.Path)
				}
			}
		})
	}
}
