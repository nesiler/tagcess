package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	k8sfix "github.com/nesiler/tagcess/test/k8s"
)

var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

type env struct {
	profiles *ProfileStore
	policy   *netpolicy.Store
	st       *store.Store
	clock    *k8sfix.Clock
}

// newEnv opens a temporary SQLite database with an API policy that allows 10.0.0.0/8 on 6443 and 443.
func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clock := k8sfix.NewClock(t0)
	e := &env{
		policy: netpolicy.New(st.DB(), st.Queries()),
		st:     st,
		clock:  clock,
	}
	e.profiles = NewProfileStore(st.DB(), st.Queries(), e.policy, clock.Now)
	if err := e.policy.Set(context.Background(), netpolicy.ScopeAPI, netpolicy.Input{
		Addresses: []string{"10.0.0.0/8"}, Ports: []int{6443, 443},
	}); err != nil {
		t.Fatalf("policy Set: %v", err)
	}
	return e
}

func validProfile() Profile {
	return Profile{
		Endpoint:       "https://10.1.2.3:6443",
		Namespaces:     []string{"web", "apps"},
		Controller:     "traefik.io/ingress-controller",
		IngressClasses: []string{"traefik"},
		Internal:       []Listener{{Address: "10.1.2.10", Port: 443, EntryPoint: "websecure-internal"}},
		Public:         []Listener{{Address: "10.1.2.11", Port: 443, EntryPoint: "websecure"}},
	}
}

func rawSetting(t *testing.T, e *env) string {
	t.Helper()
	v, err := e.st.Queries().GetSetting(context.Background(), settingKey)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	return v
}

// AC1: a saved profile reads back with its endpoint, explicit namespace scope, class/controller and
// listeners; the stored value has no credential-shaped fields.
func TestK8sProfile_MetadataRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	in := validProfile()
	in.Endpoint = "HTTPS://10.1.2.3:6443/"
	in.Internal = []Listener{{Address: "::ffff:10.1.2.10", Port: 443}, {Address: "10.1.2.9", Port: 8443}}
	if err := e.profiles.Save(ctx, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := e.profiles.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := Profile{
		Endpoint:       "https://10.1.2.3:6443",
		Namespaces:     []string{"apps", "web"},
		Controller:     "traefik.io/ingress-controller",
		IngressClasses: []string{"traefik"},
		Internal:       []Listener{{Address: "10.1.2.9", Port: 8443}, {Address: "10.1.2.10", Port: 443}},
		Public:         []Listener{{Address: "10.1.2.11", Port: 443, EntryPoint: "websecure"}},
		PolicyScope:    netpolicy.ScopeAPI,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Get = %+v, want %+v", got, want)
	}

	// The stored JSON carries exactly the metadata keys; nothing that could hold a token or key.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawSetting(t, e)), &keys); err != nil {
		t.Fatalf("stored value is not JSON: %v", err)
	}
	var names []string
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	wantKeys := []string{"controller", "endpoint", "ingress_classes", "internal", "namespaces", "policy_scope", "public"}
	if !reflect.DeepEqual(names, wantKeys) {
		t.Fatalf("stored keys = %v, want %v", names, wantKeys)
	}
	if low := strings.ToLower(rawSetting(t, e)); strings.Contains(low, "token") || strings.Contains(low, "private key") {
		t.Fatalf("stored value mentions a credential: %s", rawSetting(t, e))
	}
}

// AC2: an invalid endpoint, namespace, class, controller or listener is refused and the previous
// profile stays byte-for-byte.
func TestK8sProfile_RejectsInvalidScopeAndEndpoints(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if err := e.profiles.Save(ctx, validProfile()); err != nil {
		t.Fatalf("Save valid: %v", err)
	}
	before := rawSetting(t, e)

	cases := []struct {
		name   string
		mutate func(p *Profile)
	}{
		{"http endpoint", func(p *Profile) { p.Endpoint = "http://10.1.2.3:6443" }},
		{"no scheme", func(p *Profile) { p.Endpoint = "10.1.2.3:6443" }},
		{"empty endpoint", func(p *Profile) { p.Endpoint = "" }},
		{"userinfo", func(p *Profile) { p.Endpoint = "https://user:pw@10.1.2.3:6443" }},
		{"username only", func(p *Profile) { p.Endpoint = "https://user@10.1.2.3:6443" }},
		{"query", func(p *Profile) { p.Endpoint = "https://10.1.2.3:6443/?a=b" }},
		{"empty query", func(p *Profile) { p.Endpoint = "https://10.1.2.3:6443?" }},
		{"fragment", func(p *Profile) { p.Endpoint = "https://10.1.2.3:6443#x" }},
		{"empty fragment", func(p *Profile) { p.Endpoint = "https://10.1.2.3:6443#" }},
		{"no host", func(p *Profile) { p.Endpoint = "https:///x" }},
		{"bad port", func(p *Profile) { p.Endpoint = "https://10.1.2.3:99999" }},
		{"zone", func(p *Profile) { p.Endpoint = "https://[fe80::1%25eth0]:6443" }},
		{"space", func(p *Profile) { p.Endpoint = "https://10.1.2.3 :6443" }},
		{"no namespaces", func(p *Profile) { p.Namespaces = nil }},
		{"empty namespace", func(p *Profile) { p.Namespaces = []string{""} }},
		{"wildcard namespace", func(p *Profile) { p.Namespaces = []string{"*"} }},
		{"upper namespace", func(p *Profile) { p.Namespaces = []string{"Web"} }},
		{"duplicate namespace", func(p *Profile) { p.Namespaces = []string{"web", "web"} }},
		{"long namespace", func(p *Profile) { p.Namespaces = []string{strings.Repeat("a", 64)} }},
		{"no classes", func(p *Profile) { p.IngressClasses = nil }},
		{"bad class", func(p *Profile) { p.IngressClasses = []string{"trae fik"} }},
		{"duplicate class", func(p *Profile) { p.IngressClasses = []string{"a", "a"} }},
		{"no controller", func(p *Profile) { p.Controller = "" }},
		{"controller without domain", func(p *Profile) { p.Controller = "traefik" }},
		{"no internal listener", func(p *Profile) { p.Internal = nil }},
		{"listener hostname", func(p *Profile) { p.Internal = []Listener{{Address: "caddy.example", Port: 443}} }},
		{"listener unspecified", func(p *Profile) { p.Internal = []Listener{{Address: "0.0.0.0", Port: 443}} }},
		{"listener port 0", func(p *Profile) { p.Internal = []Listener{{Address: "10.1.2.10", Port: 0}} }},
		{"listener port high", func(p *Profile) { p.Internal = []Listener{{Address: "10.1.2.10", Port: 65536}} }},
		{"listener entrypoint", func(p *Profile) { p.Internal = []Listener{{Address: "10.1.2.10", Port: 443, EntryPoint: "a b"}} }},
		{"duplicate listener", func(p *Profile) {
			p.Internal = []Listener{{Address: "10.1.2.10", Port: 443}, {Address: "10.1.2.10", Port: 443}}
		}},
		{"same listener internal and public", func(p *Profile) {
			p.Internal = []Listener{{Address: "10.1.2.11", Port: 443}}
		}},
		{"foreign policy scope", func(p *Profile) { p.PolicyScope = netpolicy.ScopeProbe }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validProfile()
			p.Namespaces = []string{"other"} // would differ from the stored one if it got through
			tc.mutate(&p)
			err := e.profiles.Save(ctx, p)
			if err == nil {
				t.Fatalf("Save(%+v) succeeded, want rejection", p)
			}
			if _, ok := errors.AsType[*ValidationError](err); !ok {
				t.Fatalf("Save error = %v, want *ValidationError", err)
			}
			if got := rawSetting(t, e); got != before {
				t.Fatalf("stored profile changed after rejection:\n got %s\nwant %s", got, before)
			}
		})
	}
}

// AC1/AC2: an endpoint path keeps its escaping, so whatever Save accepts reads back unchanged, and
// whatever it refuses leaves the previous profile in place.
func TestK8sProfile_EndpointPathRoundTrip(t *testing.T) {
	ctx := context.Background()
	const base = "https://10.1.2.3:6443"
	cases := []struct {
		name, path, want string // want == "" means the path must be refused
	}{
		{"prefix", "/prefix", "/prefix"},
		{"trailing slash", "/prefix/", "/prefix"},
		{"escaped question mark", "/%3Fbad", "/%3Fbad"},
		{"escaped hash", "/%23bad", "/%23bad"},
		{"escaped percent", "/%25bad", "/%25bad"},
		{"escaped space", "/a%20b", "/a%20b"},
		{"escaped newline", "/%0Abad", ""},
		{"escaped NUL", "/%00bad", ""},
		{"escaped DEL", "/%7Fbad", ""},
		{"escaped slash", "/a%2Fb", ""},
		{"escaped dot segment", "/%2e%2e/x", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if err := e.profiles.Save(ctx, validProfile()); err != nil {
				t.Fatalf("Save valid: %v", err)
			}
			before := rawSetting(t, e)
			want, err := e.profiles.Get(ctx)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			p := validProfile()
			p.Namespaces = []string{"other"} // would differ from the stored one if it got through
			p.Endpoint = base + tc.path
			err = e.profiles.Save(ctx, p)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("Save(%q) succeeded, want rejection", p.Endpoint)
				}
				if _, ok := errors.AsType[*ValidationError](err); !ok {
					t.Fatalf("Save error = %v, want *ValidationError", err)
				}
				if got := rawSetting(t, e); got != before {
					t.Fatalf("stored profile changed after rejection:\n got %s\nwant %s", got, before)
				}
				if got, err := e.profiles.Get(ctx); err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("old profile not kept: %+v, %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Save(%q): %v", p.Endpoint, err)
			}
			got, err := e.profiles.Get(ctx)
			if err != nil {
				t.Fatalf("Get after Save(%q): %v", p.Endpoint, err)
			}
			if got.Endpoint != base+tc.want {
				t.Fatalf("Endpoint = %q, want %q", got.Endpoint, base+tc.want)
			}
			// Saving what was read back changes nothing.
			if err := e.profiles.Save(ctx, got); err != nil {
				t.Fatalf("re-Save: %v", err)
			}
			if again, err := e.profiles.Get(ctx); err != nil || !reflect.DeepEqual(again, got) {
				t.Fatalf("round trip differs: %+v vs %+v, %v", again, got, err)
			}
		})
	}
}

// AC3: an IP endpoint carries an explicit TLS server name; there is no way to turn verification off.
func TestK8sProfile_TLSNameAndVerificationRequired(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	p := validProfile()
	p.TLSServerName = "Kube-API.Lab.Example."
	if err := e.profiles.Save(ctx, p); err != nil {
		t.Fatalf("Save with TLS name: %v", err)
	}
	got, err := e.profiles.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TLSServerName != "kube-api.lab.example" {
		t.Fatalf("TLSServerName = %q, want the explicit name kube-api.lab.example", got.TLSServerName)
	}
	if !strings.Contains(rawSetting(t, e), `"tls_server_name":"kube-api.lab.example"`) {
		t.Fatalf("TLS name is not stored explicitly: %s", rawSetting(t, e))
	}
	before := rawSetting(t, e)

	for _, name := range []string{"10.1.2.3", "[::1]", "host:443", "https://x.example", "a b", "-x.example", "x..example", "*.example", strings.Repeat("a", 254)} {
		p := validProfile()
		p.TLSServerName = name
		if err := e.profiles.Save(ctx, p); err == nil {
			t.Fatalf("TLSServerName %q accepted", name)
		}
	}
	if rawSetting(t, e) != before {
		t.Fatalf("stored profile changed after rejected TLS names")
	}

	// Verification cannot be disabled: no field exists, and a stored value that tries is unusable.
	for _, key := range []string{"insecure_skip_tls_verify", "tls_insecure", "insecure", "skip_tls_verify", "tls_verify"} {
		raw := injectKey(t, before, key, true)
		if err := e.st.Queries().UpsertSetting(ctx, upsertParams(raw)); err != nil {
			t.Fatalf("UpsertSetting: %v", err)
		}
		if got, err := e.profiles.Get(ctx); err == nil {
			t.Fatalf("stored profile with %q was accepted: %+v", key, got)
		}
	}
	for f := range reflect.TypeFor[Profile]().Fields() {
		n := strings.ToLower(f.Name)
		if strings.Contains(n, "insecure") || strings.Contains(n, "skip") || strings.Contains(n, "verify") {
			t.Fatalf("Profile has a verification switch: %s", f.Name)
		}
	}
}

// AC4: the declared token expiry and the last successful identity check are separate; saving a
// declaration never counts as a check.
func TestK8sProfile_ExpiryIsDeclaredMetadata(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	p := validProfile()
	exp := t0.Add(48 * time.Hour)
	p.DeclaredTokenExpiry = exp.In(time.FixedZone("x", 3*3600))
	p.LastIdentityCheck = t0 // a declaration must not be able to claim a check
	if err := e.profiles.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := e.profiles.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.DeclaredTokenExpiry.Equal(exp) || got.DeclaredTokenExpiry.Location() != time.UTC {
		t.Fatalf("DeclaredTokenExpiry = %v, want %v UTC", got.DeclaredTokenExpiry, exp)
	}
	if !got.LastIdentityCheck.IsZero() {
		t.Fatalf("LastIdentityCheck = %v after Save, want none", got.LastIdentityCheck)
	}

	// A check is recorded only through RecordIdentityCheck, at the injected clock's time.
	e.clock.Advance(time.Hour)
	if err := e.profiles.RecordIdentityCheck(ctx); err != nil {
		t.Fatalf("RecordIdentityCheck: %v", err)
	}
	got, _ = e.profiles.Get(ctx)
	if !got.LastIdentityCheck.Equal(t0.Add(time.Hour)) || !got.DeclaredTokenExpiry.Equal(exp) {
		t.Fatalf("after check: check=%v expiry=%v", got.LastIdentityCheck, got.DeclaredTokenExpiry)
	}

	// Re-saving the same credential metadata keeps the check; changing endpoint, TLS name or the
	// declared expiry invalidates it (it was made against something else).
	same := validProfile()
	same.DeclaredTokenExpiry = exp
	if err := e.profiles.Save(ctx, same); err != nil {
		t.Fatalf("Save same: %v", err)
	}
	if got, _ = e.profiles.Get(ctx); got.LastIdentityCheck.IsZero() {
		t.Fatalf("identity check lost on unchanged credential metadata")
	}
	for name, mutate := range map[string]func(p *Profile){
		"endpoint": func(p *Profile) { p.Endpoint = "https://10.1.2.4:6443" },
		"tls name": func(p *Profile) { p.TLSServerName = "kube.example" },
		"expiry":   func(p *Profile) { p.DeclaredTokenExpiry = exp.Add(time.Hour) },
	} {
		if err := e.profiles.RecordIdentityCheck(ctx); err != nil {
			t.Fatalf("%s: RecordIdentityCheck: %v", name, err)
		}
		p := same
		mutate(&p)
		if err := e.profiles.Save(ctx, p); err != nil {
			t.Fatalf("%s: Save: %v", name, err)
		}
		if got, _ = e.profiles.Get(ctx); !got.LastIdentityCheck.IsZero() {
			t.Fatalf("%s change kept the old identity check %v", name, got.LastIdentityCheck)
		}
		if err := e.profiles.Save(ctx, same); err != nil {
			t.Fatalf("%s: restore: %v", name, err)
		}
	}

	// Nothing to check without a profile.
	empty := newEnv(t)
	if err := empty.profiles.RecordIdentityCheck(ctx); !errors.Is(err, ErrNotSet) {
		t.Fatalf("RecordIdentityCheck without profile = %v, want ErrNotSet", err)
	}
}

// AC5: a missing, unreadable or corrupt profile yields an error and the zero Profile, never a
// default that spans all namespaces or default listeners.
func TestK8sProfile_UnreadableDoesNotBroadenScope(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	if got, err := e.profiles.Get(ctx); !errors.Is(err, ErrNotSet) || !reflect.DeepEqual(got, Profile{}) {
		t.Fatalf("Get without profile = %+v, %v; want zero Profile and ErrNotSet", got, err)
	}

	good := validProfile()
	if err := e.profiles.Save(ctx, good); err != nil {
		t.Fatalf("Save: %v", err)
	}
	valid := rawSetting(t, e)

	corrupt := []string{
		``,
		`not json`,
		`{}`,
		`null`,
		`[]`,
		valid + `{}`,
		injectKey(t, valid, "surprise", "x"),
		strings.Replace(valid, `"namespaces":["apps","web"]`, `"namespaces":[]`, 1),
		strings.Replace(valid, `"namespaces":["apps","web"]`, `"namespaces":["*"]`, 1),
		strings.Replace(valid, `"namespaces":["apps","web"]`, `"namespaces":["web","apps"]`, 1), // not canonical
		strings.Replace(valid, `"endpoint":"https://10.1.2.3:6443"`, `"endpoint":"http://10.1.2.3:6443"`, 1),
		strings.Replace(valid, `"internal":[{"address":"10.1.2.10","port":443,"entry_point":"websecure-internal"}]`, `"internal":[]`, 1),
		strings.Replace(valid, `"public":[{"address":"10.1.2.11","port":443,"entry_point":"websecure"}]`, `"public":[{"address":"not-an-ip","port":443}]`, 1),
		strings.Replace(valid, `"policy_scope":"api"`, `"policy_scope":"probe"`, 1),
	}
	for i, raw := range corrupt {
		if i >= 5 && raw == valid { // a Replace that did not match would silently test nothing
			t.Fatalf("corrupt case %d did not change the stored value", i)
		}
		if err := e.st.Queries().UpsertSetting(ctx, upsertParams(raw)); err != nil {
			t.Fatalf("UpsertSetting: %v", err)
		}
		got, err := e.profiles.Get(ctx)
		if err == nil || errors.Is(err, ErrNotSet) {
			t.Fatalf("case %d (%q): Get err = %v, want a corruption error", i, raw, err)
		}
		if !reflect.DeepEqual(got, Profile{}) {
			t.Fatalf("case %d (%q): Get returned a usable profile %+v", i, raw, got)
		}
		if after := rawSetting(t, e); after != raw {
			t.Fatalf("case %d: Get rewrote the stored value", i)
		}
		if err := e.profiles.RecordIdentityCheck(ctx); err == nil {
			t.Fatalf("case %d: RecordIdentityCheck on a corrupt profile succeeded", i)
		}
	}

	// A closed database is an error too, not an empty profile.
	_ = e.st.Close()
	if got, err := e.profiles.Get(ctx); err == nil || !reflect.DeepEqual(got, Profile{}) {
		t.Fatalf("Get on closed db = %+v, %v", got, err)
	}
}

// AC6: Save uses the shared F4-043 policy as its validator, keeps the scope reference, and leaves the
// old profile alone when the policy refuses.
func TestK8sProfile_UsesSharedEndpointPolicy(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	p := validProfile()
	p.PolicyScope = "" // defaults to the API scope and is stored explicitly
	if err := e.profiles.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := e.profiles.Get(ctx)
	if err != nil || got.PolicyScope != netpolicy.ScopeAPI {
		t.Fatalf("Get = %+v, %v; want PolicyScope api", got, err)
	}
	if !strings.Contains(rawSetting(t, e), `"policy_scope":"api"`) {
		t.Fatalf("scope reference not stored: %s", rawSetting(t, e))
	}
	before := rawSetting(t, e)

	// The profile never copies the policy's addresses or ports.
	if strings.Contains(before, "10.0.0.0/8") || strings.Contains(before, "6443,") {
		t.Fatalf("profile duplicates the policy: %s", before)
	}

	reject := func(name string, p Profile) {
		t.Helper()
		err := e.profiles.Save(ctx, p)
		if err == nil || !errors.Is(err, netpolicy.ErrDenied) {
			t.Fatalf("%s: Save error = %v, want netpolicy.ErrDenied", name, err)
		}
		if rawSetting(t, e) != before {
			t.Fatalf("%s: stored profile changed", name)
		}
	}

	// Endpoint IP or port outside the stored API policy.
	outside := validProfile()
	outside.Endpoint = "https://192.168.1.5:6443"
	reject("ip outside policy", outside)
	port := validProfile()
	port.Endpoint = "https://10.1.2.3:8443"
	reject("port outside policy", port)
	// The probe scope's permissions do not count.
	if err := e.policy.Set(ctx, netpolicy.ScopeProbe, netpolicy.Input{Addresses: []string{"192.168.0.0/16"}, Ports: []int{6443}}); err != nil {
		t.Fatalf("probe Set: %v", err)
	}
	reject("probe policy does not allow", outside)

	// A forbidden address (loopback) is refused even though no policy entry could ever allow it.
	loop := validProfile()
	loop.Endpoint = "https://127.0.0.1:6443"
	reject("loopback", loop)

	// An unreadable policy is a validator error.
	if _, err := e.st.DB().ExecContext(ctx, `UPDATE settings SET value = 'garbage' WHERE key = 'netpolicy.api'`); err != nil {
		t.Fatalf("corrupt policy: %v", err)
	}
	reject("unreadable policy", validProfile())

	// An unset policy is a validator error too, also for a hostname endpoint (no lookup is made).
	if _, err := e.st.DB().ExecContext(ctx, `DELETE FROM settings WHERE key = 'netpolicy.api'`); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	host := validProfile()
	host.Endpoint = "https://kube-api.lab.example:6443"
	reject("no policy, hostname endpoint", host)

	// With the policy back, a hostname endpoint is accepted and read back.
	if err := e.policy.Set(ctx, netpolicy.ScopeAPI, netpolicy.Input{Addresses: []string{"10.0.0.0/8"}, Ports: []int{6443}}); err != nil {
		t.Fatalf("policy Set: %v", err)
	}
	if err := e.profiles.Save(ctx, host); err != nil {
		t.Fatalf("Save hostname endpoint: %v", err)
	}
	if got, err := e.profiles.Get(ctx); err != nil || got.Endpoint != host.Endpoint || got.PolicyScope != netpolicy.ScopeAPI {
		t.Fatalf("Get = %+v, %v", got, err)
	}
}

// injectKey returns the stored JSON with one extra top-level key.
func injectKey(t *testing.T, raw, key string, value any) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("injectKey: %v", err)
	}
	m[key] = value
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("injectKey: %v", err)
	}
	return string(out)
}

func upsertParams(raw string) db.UpsertSettingParams {
	return db.UpsertSettingParams{Key: settingKey, Value: raw, UpdatedAt: t0.Format("2006-01-02T15:04:05.000Z")}
}

// F5 I3: public listeners are optional. A tailnet-only cluster saves without one and reads it back
// empty; the internal listener stays required (positive and negative control).
func TestK8sProfile_PublicListenersOptional(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	p := validProfile()
	p.Public = nil
	if err := e.profiles.Save(ctx, p); err != nil {
		t.Fatalf("Save without public listeners: %v", err)
	}
	got, err := e.profiles.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Public) != 0 {
		t.Fatalf("Public = %+v, want none", got.Public)
	}
	p.Internal = nil
	if err := e.profiles.Save(ctx, p); err == nil {
		t.Fatal("Save without internal listeners succeeded, want a validation error")
	}
}
