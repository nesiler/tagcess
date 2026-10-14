package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

func openStore(t *testing.T) (*Store, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st.DB(), st.Queries()), st
}

func mustSet(t *testing.T, s *Store, scope Scope, in Input) {
	t.Helper()
	if err := s.Set(context.Background(), scope, in); err != nil {
		t.Fatalf("Set(%s, %+v): %v", scope, in, err)
	}
}

// AC1: a valid policy is stored in canonical form, read back, and the two scopes never share
// permissions.
func TestEndpointPolicy_ScopedRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)

	mustSet(t, s, ScopeAPI, Input{
		Addresses: []string{"10.1.2.3", "192.168.7.9/16", "2001:db8::5", "::ffff:172.16.0.4"},
		Ports:     []int{6443, 443},
	})
	got, err := s.Get(ctx, ScopeAPI)
	if err != nil {
		t.Fatalf("Get api: %v", err)
	}
	want := Policy{
		Addresses: []string{"10.1.2.3/32", "172.16.0.4/32", "192.168.0.0/16", "2001:db8::5/128"},
		Ports:     []int{443, 6443},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Get api = %+v, want %+v", got, want)
	}

	// The probe scope is untouched: nothing is allowed there, and API addresses do not leak over.
	if _, err := s.Get(ctx, ScopeProbe); !errors.Is(err, ErrNotSet) {
		t.Fatalf("Get probe before Set = %v, want ErrNotSet", err)
	}
	if err := s.Check(ctx, ScopeProbe, netip.MustParseAddr("10.1.2.3"), 443); !errors.Is(err, ErrDenied) {
		t.Fatalf("probe Check with only api set = %v, want ErrDenied", err)
	}
	if err := s.Check(ctx, ScopeAPI, netip.MustParseAddr("10.1.2.3"), 443); err != nil {
		t.Fatalf("api Check = %v, want nil", err)
	}

	mustSet(t, s, ScopeProbe, Input{Addresses: []string{"10.50.0.0/24"}, Ports: []int{8080}})
	cases := []struct {
		scope Scope
		addr  string
		port  int
		ok    bool
	}{
		{ScopeAPI, "10.1.2.3", 6443, true},
		{ScopeAPI, "192.168.200.1", 443, true},
		{ScopeAPI, "2001:db8::5", 443, true},
		{ScopeAPI, "10.1.2.3", 8080, false},  // probe port
		{ScopeAPI, "10.50.0.7", 8080, false}, // probe address
		{ScopeProbe, "10.50.0.7", 8080, true},
		{ScopeProbe, "10.50.0.7", 443, false},
		{ScopeProbe, "10.1.2.3", 443, false}, // api address
		{ScopeProbe, "::ffff:10.50.0.7", 8080, true},
		{ScopeProbe, "::ffff:10.50.0.7%eth0", 8080, false}, // zone survives no Unmap
	}
	for _, c := range cases {
		err := s.Check(ctx, c.scope, netip.MustParseAddr(c.addr), c.port)
		if c.ok != (err == nil) {
			t.Errorf("Check(%s, %s, %d) = %v, want ok=%v", c.scope, c.addr, c.port, err, c.ok)
		}
	}

	// A second Set replaces the whole scope.
	mustSet(t, s, ScopeAPI, Input{Addresses: []string{"10.9.9.9"}, Ports: []int{443}})
	got, _ = s.Get(ctx, ScopeAPI)
	if want := (Policy{Addresses: []string{"10.9.9.9/32"}, Ports: []int{443}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("Get api after replace = %+v, want %+v", got, want)
	}
}

// AC2: unsafe input is refused with a field error and the old policy survives byte for byte.
func TestEndpointPolicy_RejectsUnsafeInputsAtomically(t *testing.T) {
	ctx := context.Background()
	s, st := openStore(t)
	mustSet(t, s, ScopeAPI, Input{Addresses: []string{"10.1.2.0/24"}, Ports: []int{443}})
	before, err := st.Queries().GetSetting(ctx, settingKey(ScopeAPI))
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}

	cases := []struct {
		name  string
		in    Input
		field string
	}{
		{"loopback v4", Input{Addresses: []string{"127.0.0.1"}, Ports: []int{443}}, "addresses[0]"},
		{"loopback net", Input{Addresses: []string{"10.0.0.1", "127.0.0.0/8"}, Ports: []int{443}}, "addresses[1]"},
		{"loopback v6", Input{Addresses: []string{"::1"}, Ports: []int{443}}, "addresses[0]"},
		{"link-local", Input{Addresses: []string{"169.254.1.1"}, Ports: []int{443}}, "addresses[0]"},
		{"link-local v6", Input{Addresses: []string{"fe80::1"}, Ports: []int{443}}, "addresses[0]"},
		{"metadata v4", Input{Addresses: []string{"169.254.169.254"}, Ports: []int{80}}, "addresses[0]"},
		{"metadata alibaba", Input{Addresses: []string{"100.100.100.200"}, Ports: []int{80}}, "addresses[0]"},
		{"metadata v6", Input{Addresses: []string{"fd00:ec2::254"}, Ports: []int{80}}, "addresses[0]"},
		{"unspecified", Input{Addresses: []string{"0.0.0.0"}, Ports: []int{443}}, "addresses[0]"},
		{"unspecified v6", Input{Addresses: []string{"::"}, Ports: []int{443}}, "addresses[0]"},
		{"multicast", Input{Addresses: []string{"224.0.0.1"}, Ports: []int{443}}, "addresses[0]"},
		{"multicast v6", Input{Addresses: []string{"ff02::1"}, Ports: []int{443}}, "addresses[0]"},
		{"broadcast", Input{Addresses: []string{"255.255.255.255"}, Ports: []int{443}}, "addresses[0]"},
		{"mapped loopback", Input{Addresses: []string{"::ffff:127.0.0.1"}, Ports: []int{443}}, "addresses[0]"},
		{"mapped metadata", Input{Addresses: []string{"::ffff:169.254.169.254"}, Ports: []int{443}}, "addresses[0]"},
		{"mapped loopback net", Input{Addresses: []string{"::ffff:127.0.0.0/104"}, Ports: []int{443}}, "addresses[0]"},
		{"covers loopback", Input{Addresses: []string{"0.0.0.0/1"}, Ports: []int{443}}, "addresses[0]"},
		{"covers link-local", Input{Addresses: []string{"169.254.0.0/15"}, Ports: []int{443}}, "addresses[0]"},
		{"zero v4", Input{Addresses: []string{"0.0.0.0/0"}, Ports: []int{443}}, "addresses[0]"},
		{"zero v6", Input{Addresses: []string{"::/0"}, Ports: []int{443}}, "addresses[0]"},
		{"mapped zero", Input{Addresses: []string{"::ffff:0.0.0.0/96"}, Ports: []int{443}}, "addresses[0]"},
		{"mapped wide", Input{Addresses: []string{"::ffff:0:0/80"}, Ports: []int{443}}, "addresses[0]"},
		{"zone", Input{Addresses: []string{"fe80::1%eth0"}, Ports: []int{443}}, "addresses[0]"},
		{"zone global", Input{Addresses: []string{"2001:db8::1%eth0"}, Ports: []int{443}}, "addresses[0]"},
		{"bad cidr", Input{Addresses: []string{"10.0.0.0/33"}, Ports: []int{443}}, "addresses[0]"},
		{"bad cidr text", Input{Addresses: []string{"10.0.0.0/"}, Ports: []int{443}}, "addresses[0]"},
		{"hostname", Input{Addresses: []string{"example.com"}, Ports: []int{443}}, "addresses[0]"},
		{"empty entry", Input{Addresses: []string{""}, Ports: []int{443}}, "addresses[0]"},
		{"duplicate", Input{Addresses: []string{"10.0.0.1", "10.0.0.1/32"}, Ports: []int{443}}, "addresses[1]"},
		{"too many addresses", Input{Addresses: manyAddrs(maxEntries + 1), Ports: []int{443}}, "addresses"},
		{"port zero", Input{Addresses: []string{"10.0.0.1"}, Ports: []int{0}}, "ports[0]"},
		{"port negative", Input{Addresses: []string{"10.0.0.1"}, Ports: []int{443, -1}}, "ports[1]"},
		{"port too big", Input{Addresses: []string{"10.0.0.1"}, Ports: []int{65536}}, "ports[0]"},
		{"port duplicate", Input{Addresses: []string{"10.0.0.1"}, Ports: []int{443, 443}}, "ports[1]"},
		{"too many ports", Input{Addresses: []string{"10.0.0.1"}, Ports: manyPorts(maxEntries + 1)}, "ports"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := s.Set(ctx, ScopeAPI, c.in)
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Set = %v, want *ValidationError", err)
			}
			found := false
			for _, f := range verr.Fields {
				if f.Field == c.field {
					found = true
				}
			}
			if !found {
				t.Fatalf("fields = %+v, want one for %q", verr.Fields, c.field)
			}
			after, err := st.Queries().GetSetting(ctx, settingKey(ScopeAPI))
			if err != nil || after != before {
				t.Fatalf("stored policy changed to %q (%v), want %q", after, err, before)
			}
			if err := s.Set(ctx, ScopeProbe, c.in); err == nil {
				t.Fatal("probe Set accepted the same unsafe input")
			}
			if _, err := s.Get(ctx, ScopeProbe); !errors.Is(err, ErrNotSet) {
				t.Fatalf("rejected probe Set left a policy behind: %v", err)
			}
		})
	}

	if err := s.Set(ctx, Scope("other"), Input{Addresses: []string{"10.0.0.1"}, Ports: []int{443}}); err == nil {
		t.Fatal("Set accepted an unknown scope")
	}

	// A private network and a CGNAT range are allowed only because they are listed explicitly.
	mustSet(t, s, ScopeAPI, Input{Addresses: []string{"100.64.0.0/10", "10.0.0.0/8", "fd00::/8"}, Ports: []int{443}})
	// ... yet the metadata host inside the CGNAT range is still refused when dialled.
	if err := s.Check(ctx, ScopeAPI, netip.MustParseAddr("100.100.100.200"), 443); !errors.Is(err, ErrDenied) {
		t.Fatalf("Check metadata inside allowed range = %v, want ErrDenied", err)
	}
	if err := s.Check(ctx, ScopeAPI, netip.MustParseAddr("100.64.1.1"), 443); err != nil {
		t.Fatalf("Check cgnat = %v, want nil", err)
	}
}

func manyAddrs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)}).String()
	}
	return out
}

func manyPorts(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = 1000 + i
	}
	return out
}

type fakeResolver struct {
	answers map[string][]netip.Addr
	calls   int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.calls++
	a, ok := r.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

// fakeConn reports a fixed remote address so the guard can check the real dial target.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }

type fakeDialer struct {
	calls   []string
	remote  string // overrides the remote address when set (a dialer that connects elsewhere)
	failFor map[string]bool
}

func (d *fakeDialer) Dial(_ context.Context, network, address string) (net.Conn, error) {
	d.calls = append(d.calls, network+" "+address)
	if d.failFor[address] {
		return nil, errors.New("connection refused")
	}
	remote := address
	if d.remote != "" {
		remote = d.remote
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return fakeConn{Conn: c1, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote))}, nil
}

// AC3: the guard checks the resolved address and the real dial address against the chosen scope,
// and starts no dial when either is outside it.
func TestEndpointPolicy_ResolutionAndDialUseSameScope(t *testing.T) {
	ctx := context.Background()
	s, _ := openStore(t)
	mustSet(t, s, ScopeAPI, Input{Addresses: []string{"10.1.0.0/16"}, Ports: []int{6443}})
	mustSet(t, s, ScopeProbe, Input{Addresses: []string{"10.2.0.0/16", "2001:db8::/32"}, Ports: []int{443}})

	res := &fakeResolver{answers: map[string][]netip.Addr{
		"api.internal":     {netip.MustParseAddr("10.1.0.5")},
		"probe.internal":   {netip.MustParseAddr("10.2.0.5")},
		"rebind.internal":  {netip.MustParseAddr("127.0.0.1")},
		"mixed.internal":   {netip.MustParseAddr("10.1.0.5"), netip.MustParseAddr("169.254.169.254")},
		"mapped.internal":  {netip.MustParseAddr("::ffff:127.0.0.1")},
		"v6.internal":      {netip.MustParseAddr("2001:db8::7")},
		"mapok.internal":   {netip.MustParseAddr("::ffff:10.1.0.5")},
		"mapzone.internal": {netip.MustParseAddr("::ffff:10.1.0.5%eth0")},
		"empty.internal":   {},
		"outside.internal": {netip.MustParseAddr("10.9.0.1")},
	}}

	cases := []struct {
		name      string
		scope     Scope
		network   string
		address   string
		wantDial  string // "" means no dial must happen
		wantLooks int    // expected resolver calls
	}{
		{"api host ok", ScopeAPI, "tcp", "api.internal:6443", "tcp 10.1.0.5:6443", 1},
		{"api literal ok", ScopeAPI, "tcp", "10.1.0.9:6443", "tcp 10.1.0.9:6443", 0},
		{"probe host ok", ScopeProbe, "tcp", "probe.internal:443", "tcp 10.2.0.5:443", 1},
		{"probe v6 ok", ScopeProbe, "tcp", "v6.internal:443", "tcp [2001:db8::7]:443", 1},
		{"probe v6 literal ok", ScopeProbe, "tcp", "[2001:db8::7]:443", "tcp [2001:db8::7]:443", 0},
		{"api host via probe scope", ScopeProbe, "tcp", "api.internal:443", "", 1},
		{"probe host via api scope", ScopeAPI, "tcp", "probe.internal:6443", "", 1},
		{"api address, probe port", ScopeAPI, "tcp", "api.internal:443", "", 0}, // port refused before any lookup
		{"rebinding to loopback", ScopeAPI, "tcp", "rebind.internal:6443", "", 1},
		{"mixed answer", ScopeAPI, "tcp", "mixed.internal:6443", "", 1},
		{"mapped loopback answer", ScopeAPI, "tcp", "mapped.internal:6443", "", 1},
		{"outside range", ScopeAPI, "tcp", "outside.internal:6443", "", 1},
		{"empty answer", ScopeAPI, "tcp", "empty.internal:6443", "", 1},
		{"lookup error", ScopeAPI, "tcp", "nx.internal:6443", "", 1},
		{"loopback literal", ScopeAPI, "tcp", "127.0.0.1:6443", "", 0},
		{"mapped literal", ScopeAPI, "tcp", "[::ffff:127.0.0.1]:6443", "", 0},
		{"mapped answer ok", ScopeAPI, "tcp", "mapok.internal:6443", "tcp 10.1.0.5:6443", 1},
		{"mapped answer with zone", ScopeAPI, "tcp", "mapzone.internal:6443", "", 1},
		{"mapped literal ok", ScopeAPI, "tcp", "[::ffff:10.1.0.9]:6443", "tcp 10.1.0.9:6443", 0},
		{"mapped literal with zone", ScopeAPI, "tcp", "[::ffff:10.1.0.9%eth0]:6443", "", 0},
		{"zone literal", ScopeProbe, "tcp", "[2001:db8::7%eth0]:443", "", 0},
		{"bad port", ScopeAPI, "tcp", "10.1.0.9:99999", "", 0},
		{"no port", ScopeAPI, "tcp", "10.1.0.9", "", 0},
		{"udp", ScopeAPI, "udp", "10.1.0.9:6443", "", 0},
		{"unknown scope", Scope("x"), "tcp", "10.1.0.9:6443", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res.calls = 0
			d := &fakeDialer{}
			g := NewGuard(s, res, d.Dial)
			conn, err := g.DialContext(c.scope)(ctx, c.network, c.address)
			if res.calls != c.wantLooks {
				t.Errorf("resolver calls = %d, want %d", res.calls, c.wantLooks)
			}
			if c.wantDial == "" {
				if err == nil {
					_ = conn.Close()
					t.Fatal("DialContext succeeded, want denial")
				}
				if len(d.calls) != 0 {
					t.Fatalf("dial started despite denial: %v", d.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			_ = conn.Close()
			if len(d.calls) != 1 || d.calls[0] != c.wantDial {
				t.Fatalf("dial calls = %v, want [%s]", d.calls, c.wantDial)
			}
		})
	}

	t.Run("dial lands elsewhere", func(t *testing.T) {
		d := &fakeDialer{remote: "10.9.9.9:6443"}
		conn, err := NewGuard(s, res, d.Dial).DialContext(ScopeAPI)(ctx, "tcp", "10.1.0.9:6443")
		if err == nil {
			_ = conn.Close()
			t.Fatal("connection to an address outside the scope was returned")
		}
	})

	t.Run("falls back to the next allowed address", func(t *testing.T) {
		multi := &fakeResolver{answers: map[string][]netip.Addr{
			"two.internal": {netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2")},
		}}
		d := &fakeDialer{failFor: map[string]bool{"10.1.0.1:6443": true}}
		conn, err := NewGuard(s, multi, d.Dial).DialContext(ScopeAPI)(ctx, "tcp", "two.internal:6443")
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		_ = conn.Close()
		if len(d.calls) != 2 {
			t.Fatalf("dial calls = %v, want both addresses tried", d.calls)
		}
	})

	t.Run("policy edit applies to the next dial", func(t *testing.T) {
		d := &fakeDialer{}
		dial := NewGuard(s, res, d.Dial).DialContext(ScopeAPI)
		mustSet(t, s, ScopeAPI, Input{Addresses: []string{"10.7.0.0/16"}, Ports: []int{6443}})
		if conn, err := dial(ctx, "tcp", "10.1.0.9:6443"); err == nil {
			_ = conn.Close()
			t.Fatal("dial used a stale policy")
		}
	})
}

// AC4: an empty, corrupt or unreadable policy allows nothing and is never replaced by a wider one.
func TestEndpointPolicy_MissingOrUnreadableDenies(t *testing.T) {
	ctx := context.Background()
	addr := netip.MustParseAddr("10.1.2.3")
	res := &fakeResolver{answers: map[string][]netip.Addr{"h": {addr}}}

	assertDenied := func(t *testing.T, s *Store) {
		t.Helper()
		if err := s.Check(ctx, ScopeAPI, addr, 443); !errors.Is(err, ErrDenied) {
			t.Fatalf("Check = %v, want ErrDenied", err)
		}
		d := &fakeDialer{}
		for _, target := range []string{"h:443", "10.1.2.3:443"} {
			if conn, err := NewGuard(s, res, d.Dial).DialContext(ScopeAPI)(ctx, "tcp", target); err == nil {
				_ = conn.Close()
				t.Fatalf("DialContext %s succeeded", target)
			}
		}
		if len(d.calls) != 0 {
			t.Fatalf("dial started: %v", d.calls)
		}
	}

	t.Run("never set", func(t *testing.T) {
		s, _ := openStore(t)
		if _, err := s.Get(ctx, ScopeAPI); !errors.Is(err, ErrNotSet) {
			t.Fatalf("Get = %v, want ErrNotSet", err)
		}
		assertDenied(t, s)
	})

	t.Run("empty policy", func(t *testing.T) {
		s, _ := openStore(t)
		mustSet(t, s, ScopeAPI, Input{})
		assertDenied(t, s)
		mustSet(t, s, ScopeAPI, Input{Addresses: []string{"10.1.2.3"}})
		assertDenied(t, s) // addresses without ports
		mustSet(t, s, ScopeAPI, Input{Ports: []int{443}})
		assertDenied(t, s) // ports without addresses
	})

	t.Run("corrupt values", func(t *testing.T) {
		for name, raw := range map[string]string{
			"not json":        "{",
			"empty string":    "",
			"wrong shape":     `["10.1.2.3"]`,
			"loopback":        `{"addresses":["127.0.0.1/32"],"ports":[443]}`,
			"zero prefix":     `{"addresses":["0.0.0.0/0"],"ports":[443]}`,
			"bad port":        `{"addresses":["10.1.2.3/32"],"ports":[0]}`,
			"non canonical":   `{"addresses":["10.1.2.3"],"ports":[443]}`,
			"unknown field":   `{"addresses":["10.1.2.3/32"],"ports":[443],"extra":1}`,
			"trailing data":   `{"addresses":["10.1.2.3/32"],"ports":[443]} {}`,
			"mapped loopback": `{"addresses":["::ffff:127.0.0.1/128"],"ports":[443]}`,
		} {
			t.Run(name, func(t *testing.T) {
				s, st := openStore(t)
				if err := st.Queries().UpsertSetting(ctx, db.UpsertSettingParams{
					Key: settingKey(ScopeAPI), Value: raw, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
				}); err != nil {
					t.Fatalf("UpsertSetting: %v", err)
				}
				if _, err := s.Get(ctx, ScopeAPI); err == nil || errors.Is(err, ErrNotSet) {
					t.Fatalf("Get = %v, want a read error", err)
				}
				assertDenied(t, s)
				after, _ := st.Queries().GetSetting(ctx, settingKey(ScopeAPI))
				if after != raw {
					t.Fatalf("reading rewrote the stored value to %q", after)
				}
			})
		}
	})

	t.Run("unreadable store", func(t *testing.T) {
		s, st := openStore(t)
		mustSet(t, s, ScopeAPI, Input{Addresses: []string{"10.1.2.3"}, Ports: []int{443}})
		if err := s.Check(ctx, ScopeAPI, addr, 443); err != nil {
			t.Fatalf("Check before close = %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		assertDenied(t, s)
		if err := s.Set(ctx, ScopeAPI, Input{Addresses: []string{"10.1.2.3"}, Ports: []int{443}}); err == nil {
			t.Fatal("Set on a closed store succeeded")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		s, _ := openStore(t)
		mustSet(t, s, ScopeAPI, Input{Addresses: []string{"10.1.2.3"}, Ports: []int{443}})
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := s.Check(cctx, ScopeAPI, addr, 443); !errors.Is(err, ErrDenied) {
			t.Fatalf("Check on cancelled context = %v, want ErrDenied", err)
		}
	})
}

// Errors name the field and never echo anything beyond it.
func TestEndpointPolicy_ValidationErrorText(t *testing.T) {
	s, _ := openStore(t)
	err := s.Set(context.Background(), ScopeAPI, Input{Addresses: []string{"127.0.0.1"}, Ports: []int{0}})
	var verr *ValidationError
	if !errors.As(err, &verr) || len(verr.Fields) != 2 {
		t.Fatalf("Set = %v, want two field errors", err)
	}
	if !strings.Contains(err.Error(), "addresses[0]") || !strings.Contains(err.Error(), "ports[0]") {
		t.Fatalf("Error() = %q, want both fields", err.Error())
	}
}
