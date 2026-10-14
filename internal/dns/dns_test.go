// Package dns_test is the external test package for the DNS file layer (F2-006): the
// fail-safe atomic write (AC2) and the resolver verification of changed names (AC3).
// It also runs the render→write chain end to end, because AC2 covers the whole
// system: a render rejection must leave the previous file exactly as it was.
package dns_test

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
)

const testAValue = "100.64.0.4"

// mustMarshal marshals or fails the test; every body in this file is valid.
func mustMarshal(t *testing.T, recs []dns.Record) string {
	t.Helper()
	body, err := dns.Marshal(recs)
	if err != nil {
		t.Fatalf("dns.Marshal: %v", err)
	}
	return body
}

// oldBody is a valid previous extra-records file a test can start from.
var oldBody = mustMarshalBody([]dns.Record{
	{Name: "old.example.com", Type: "A", Value: "100.64.0.4"},
})

// mustMarshalBody is mustMarshal for package-level values, where t is not in scope.
func mustMarshalBody(recs []dns.Record) string {
	body, err := dns.Marshal(recs)
	if err != nil {
		panic(err) // a fixed record set cannot fail to marshal
	}
	return body
}

// writeOld plants a previous valid file and returns its path.
func writeOld(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "extra-records.json")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatalf("write old file: %v", err)
	}
	return path
}

// TestRecord_Validate_Families pins the value rule (security.md §5): a plain
// IP of the record's own family. An IPv4-mapped IPv6 value ("::ffff:a.b.c.d")
// belongs to neither family: as an A record it would hide a v6 address behind
// a v4 name, as an AAAA record it is a v4 address in disguise.
func TestRecord_Validate_Families(t *testing.T) {
	const name = "wiki.example.net"
	cases := []struct {
		name    string
		rec     dns.Record
		wantErr bool
	}{
		{"plain_ipv4_as_a", dns.Record{Name: name, Type: "A", Value: "100.64.0.4"}, false},
		{"plain_ipv6_as_aaaa", dns.Record{Name: name, Type: "AAAA", Value: "fd7a:115c:a1e0::1"}, false},
		{"mapped_ipv6_as_a", dns.Record{Name: name, Type: "A", Value: "::ffff:100.64.0.4"}, true},
		{"mapped_ipv6_as_aaaa", dns.Record{Name: name, Type: "AAAA", Value: "::ffff:100.64.0.4"}, true},
		{"zoned_ipv6_as_aaaa", dns.Record{Name: name, Type: "AAAA", Value: "fe80::1%eth0"}, true},
		{"ipv6_as_a", dns.Record{Name: name, Type: "A", Value: "fd7a:115c:a1e0::1"}, true},
		{"ipv4_as_aaaa", dns.Record{Name: name, Type: "AAAA", Value: "100.64.0.4"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rec.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(%s %s %q) = %v, wantErr %v", tc.rec.Name, tc.rec.Type, tc.rec.Value, err, tc.wantErr)
			}
		})
	}
}

func TestDNSFile_FailSafe(t *testing.T) {
	t.Run("write_error_keeps_old_file", func(t *testing.T) {
		dir := t.TempDir()
		path := writeOld(t, dir, oldBody)

		// A read-only directory fails the temp-file creation; the previous
		// file must survive byte for byte and no temp file may be left.
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod dir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if os.Geteuid() == 0 {
			t.Skip("running as root: the read-only directory would still be writable")
		}

		err := dns.WriteFileAtomic(path, mustMarshal(t, []dns.Record{
			{Name: "new.example.com", Type: "A", Value: testAValue},
		}))
		if err == nil {
			t.Fatal("WriteFileAtomic in a read-only directory: want error, got nil")
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read old file after failed write: %v", readErr)
		}
		if string(got) != oldBody {
			t.Errorf("old file was touched by a failed write:\n got %q\nwant %q", got, oldBody)
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() != "extra-records.json" {
				t.Errorf("failed write left %q behind", e.Name())
			}
		}
	})

	t.Run("render_rejection_keeps_old_file", func(t *testing.T) {
		// The AC2 chain: the same name with a different value is rejected at
		// render time, so nothing is written and the old file is untouched.
		dir := t.TempDir()
		path := writeOld(t, dir, oldBody)

		sites := []site.Site{{
			Hosts:      []string{"grafana.example.com"},
			Kind:       site.KindRole,
			Roles:      []string{"devops"},
			Cert:       "le:example.com",
			TargetKind: site.TargetK8s,
			MagicDNS:   true,
		}}
		manual := []dns.Record{
			{Name: "grafana.example.com", Type: "A", Value: "10.0.0.1"},
		}
		if _, err := render.RenderDNSRecords(sites, manual, render.DNSConfig{AValue: testAValue}); err == nil {
			t.Fatal("RenderDNSRecords with a conflicting value: want error, got nil")
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read old file: %v", err)
		}
		if string(got) != oldBody {
			t.Errorf("rejected render changed the file:\n got %q\nwant %q", got, oldBody)
		}
	})

	t.Run("success_replaces_and_cleans_up", func(t *testing.T) {
		dir := t.TempDir()
		path := writeOld(t, dir, oldBody)

		body := mustMarshal(t, []dns.Record{
			{Name: "a.example.com", Type: "A", Value: testAValue},
		})
		if err := dns.WriteFileAtomic(path, body); err != nil {
			t.Fatalf("WriteFileAtomic: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read new file: %v", err)
		}
		if string(got) != body {
			t.Errorf("file content = %q, want %q", got, body)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o640 {
			t.Errorf("file mode = %o, want 640 (ADR 0013 m.4)", perm)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Errorf("directory holds %d entries after a clean write, want 1", len(entries))
		}
	})

	t.Run("rename_failure_keeps_target", func(t *testing.T) {
		// AC2 write error: the target path is a non-empty directory, so the
		// final rename fails. The old state must be kept and the temp file
		// must not be left behind.
		dir := t.TempDir()
		target := filepath.Join(dir, "extra-records.json")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatalf("mkdir target: %v", err)
		}
		inner := filepath.Join(target, "kept.txt")
		if err := os.WriteFile(inner, []byte("kept"), 0o600); err != nil {
			t.Fatalf("write inner file: %v", err)
		}

		if err := dns.WriteFileAtomic(target, oldBody); err == nil {
			t.Fatal("WriteFileAtomic over a non-empty directory: want error, got nil")
		}
		got, err := os.ReadFile(inner)
		if err != nil {
			t.Fatalf("read kept file after failed rename: %v", err)
		}
		if string(got) != "kept" {
			t.Errorf("target content = %q, want %q (old state was touched)", got, "kept")
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 || entries[0].Name() != "extra-records.json" {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("directory holds %v after a failed rename, want only [extra-records.json]", names)
		}
	})
}

func TestDNSFile_ResolverMismatch(t *testing.T) {
	// changed is the record set behind the new body; nameA keeps its value
	// from oldBody, nameB changes and nameC is new, so only nameB and nameC
	// may be verified against the resolver.
	changed := []dns.Record{
		{Name: "old.example.com", Type: "A", Value: "100.64.0.4"},
		{Name: "changed.example.com", Type: "A", Value: "100.64.0.4"},
		{Name: "new.example.com", Type: "A", Value: testAValue},
	}
	newBody := mustMarshal(t, changed)

	apply := func(t *testing.T, dir string, v dns.Verifier) []dns.Mismatch {
		t.Helper()
		path := writeOld(t, dir, oldBody)
		// oldBody holds old.example.com only, so changed.example.com
		// counts as changed against it.
		mismatches, err := dns.Apply(path, changed, v)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read file after apply: %v", err)
		}
		if string(got) != newBody {
			t.Errorf("resolver warnings must keep the new file (ADR 0013 m.5):\n got %q\nwant %q", got, newBody)
		}
		return mismatches
	}

	t.Run("wrong_answer_reports_mismatch", func(t *testing.T) {
		server := newFakeDNS(t, map[string]string{
			"changed.example.com": "203.0.113.1",
			"new.example.com":     "203.0.113.2",
		}, false)
		mismatches := apply(t, t.TempDir(), dns.Verifier{Resolver: server.addr(), Budget: 2 * time.Second})
		names := mismatchNames(mismatches)
		if !slices.Equal(names, []string{"changed.example.com", "new.example.com"}) {
			t.Errorf("mismatches = %v, want the two changed names", names)
		}
		for _, m := range mismatches {
			if m.Want != testAValue {
				t.Errorf("mismatch for %s: want value = %q, want %q", m.Name, m.Want, testAValue)
			}
			if m.Have == "" {
				t.Errorf("mismatch for %s carries no last answer", m.Name)
			}
		}
	})

	t.Run("unreachable_resolver_times_out_within_budget", func(t *testing.T) {
		// 127.0.0.1:1 is a closed port; the query can never be answered.
		start := time.Now()
		mismatches := apply(t, t.TempDir(), dns.Verifier{Resolver: "127.0.0.1:1", Budget: 750 * time.Millisecond})
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("verification took %v, the budget must bound it", elapsed)
		}
		if len(mismatches) != 2 {
			t.Errorf("mismatches = %v, want both changed names", mismatchNames(mismatches))
		}
	})

	t.Run("silent_server_times_out_within_budget", func(t *testing.T) {
		server := newFakeDNS(t, nil, true)
		start := time.Now()
		mismatches := apply(t, t.TempDir(), dns.Verifier{Resolver: server.addr(), Budget: 750 * time.Millisecond})
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("verification took %v, the budget must bound it", elapsed)
		}
		if len(mismatches) != 2 {
			t.Errorf("mismatches = %v, want both changed names", mismatchNames(mismatches))
		}
	})

	t.Run("confirmed_names_report_nothing", func(t *testing.T) {
		server := newFakeDNS(t, map[string]string{
			"changed.example.com": testAValue,
			"new.example.com":     testAValue,
		}, false)
		mismatches := apply(t, t.TempDir(), dns.Verifier{Resolver: server.addr(), Budget: 2 * time.Second})
		if len(mismatches) != 0 {
			t.Errorf("mismatches = %v, want none for confirmed names", mismatchNames(mismatches))
		}
	})

	t.Run("unchanged_names_are_not_verified", func(t *testing.T) {
		// The server answers everything wrong, yet the unchanged name must
		// never be queried: only names the write actually changed are checked.
		server := newFakeDNS(t, map[string]string{
			"old.example.com": "203.0.113.9",
		}, false)
		mismatches := apply(t, t.TempDir(), dns.Verifier{Resolver: server.addr(), Budget: 2 * time.Second})
		if slices.Contains(mismatchNames(mismatches), "old.example.com") {
			t.Error("the unchanged name was verified against the resolver")
		}
	})

	t.Run("aaaa_records_verify_as_ip6", func(t *testing.T) {
		changed6 := []dns.Record{
			{Name: "v6.example.net", Type: "AAAA", Value: "fd7a:115c:a1e0::1"},
		}
		dir := t.TempDir()
		path := writeOld(t, dir, oldBody)
		server := newFakeDNS(t, map[string]string{
			"v6.example.net": "fd7a:115c:a1e0::1",
		}, false)
		mismatches, err := dns.Apply(path, changed6, dns.Verifier{Resolver: server.addr(), Budget: 2 * time.Second})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(mismatches) != 0 {
			t.Errorf("mismatches = %v, want none for a confirmed AAAA name", mismatchNames(mismatches))
		}
	})

	t.Run("queries_are_fully_qualified", func(t *testing.T) {
		// The lookup must be an absolute name (trailing dot), so the
		// resolver's search list is never consulted for a changed name.
		const name = "changed.example.com"
		server := newFakeDNS(t, map[string]string{name: testAValue}, false)
		changed := []dns.Record{{Name: name, Type: "A", Value: testAValue}}
		path := writeOld(t, t.TempDir(), oldBody)
		if _, err := dns.Apply(path, changed, dns.Verifier{Resolver: server.addr(), Budget: 2 * time.Second}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		var got []string
		select {
		case q := <-server.queries:
			got = append(got, q)
		case <-time.After(2 * time.Second):
			t.Fatal("the resolver was never asked")
		}
	drain:
		for {
			select {
			case q := <-server.queries:
				got = append(got, q)
			default:
				break drain
			}
		}
		for _, q := range got {
			if q != name+"." {
				t.Errorf("resolver was asked for %q, want only the fully qualified %q", q, name+".")
			}
		}
	})
}

// mismatchNames returns the verified names in stable order for comparison.
func mismatchNames(ms []dns.Mismatch) []string {
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		names = append(names, m.Name)
	}
	slices.Sort(names)
	return names
}

// fakeDNS is a minimal UDP DNS server that answers every A/AAAA question for
// a name in its table with the table's address, so the resolver verification
// can be exercised without a real tailnet. mute drops every query. queries
// captures every parsed question exactly as sent on the wire (fully
// qualified, trailing dot included); capture is best-effort.
type fakeDNS struct {
	conn    *net.UDPConn
	mute    bool
	ips     map[string]string
	queries chan string
}

// newFakeDNS starts a fake resolver on a free loopback port, ready for
// dns.Verifier through addr().
func newFakeDNS(t *testing.T, ips map[string]string, mute bool) *fakeDNS {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f := &fakeDNS{conn: conn, mute: mute, ips: ips, queries: make(chan string, 64)}
	go f.serve()
	return f
}

// addr is the "host:port" UDP address of the fake resolver.
func (f *fakeDNS) addr() string {
	return f.conn.LocalAddr().String()
}

func (f *fakeDNS) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		name, qtype, question, ok := parseQuestion(buf[:n])
		if !ok || f.mute {
			continue
		}
		select {
		case f.queries <- name + ".":
		default:
		}
		want, known := f.ips[name]
		ip := net.ParseIP(want)
		if !known || ip == nil {
			// Unknown name: answer with an empty response so a lookup fails
			// fast instead of retrying until the budget ends.
			resp := append([]byte{}, buf[:2]...)
			resp = append(resp, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
			resp = append(resp, question...)
			_, _ = f.conn.WriteToUDP(resp, addr)
			continue
		}
		if (qtype == 1 && ip.To4() == nil) || (qtype == 28 && ip.To4() != nil) {
			continue // wrong family for this question: do not answer
		}
		_, _ = f.conn.WriteToUDP(buildAnswer(buf[:2], question, qtype, ip), addr)
	}
}

// parseQuestion splits a raw DNS query into the question name, the qtype and
// the raw question bytes (labels + type + class) for the answer echo.
func parseQuestion(payload []byte) (name string, qtype uint16, question []byte, ok bool) {
	if len(payload) < 12 {
		return "", 0, nil, false
	}
	i := 12
	var labels []string
	for {
		if i >= len(payload) {
			return "", 0, nil, false
		}
		l := int(payload[i])
		i++
		if l == 0 {
			break
		}
		if i+l > len(payload) {
			return "", 0, nil, false
		}
		labels = append(labels, string(payload[i:i+l]))
		i += l
	}
	if i+4 > len(payload) {
		return "", 0, nil, false
	}
	qtype = binary.BigEndian.Uint16(payload[i:])
	return strings.Join(labels, "."), qtype, payload[12 : i+4], true
}

// buildAnswer echoes the question with a single answer record of type qtype.
func buildAnswer(id []byte, question []byte, qtype uint16, ip net.IP) []byte {
	rdata := ip.To4()
	if rdata == nil {
		rdata = ip.To16()
	}
	b := make([]byte, 0, 12+len(question)+16)
	b = append(b, id...)
	b = append(b, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
	b = append(b, question...)
	b = append(b, 0xC0, 0x0C) // pointer to the question name
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	b = binary.BigEndian.AppendUint32(b, 0) // ttl
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// F5 I11: private addresses outside the tailnet are flagged; tailnet, public and non-IP values are not.
func TestPrivateOutsideTailnet(t *testing.T) {
	for value, want := range map[string]bool{
		"10.0.0.3":          true,
		"172.16.4.1":        true,
		"192.168.1.10":      true,
		"127.0.0.1":         true,
		"169.254.1.1":       true,
		"fd00::1":           true,
		"100.64.0.1":        false, // tailnet (CGNAT)
		"100.127.255.254":   false,
		"fd7a:115c:a1e0::1": false, // tailnet ULA
		"203.0.113.10":      false, // public
		"2001:db8::1":       false,
		"not-an-ip":         false,
		"":                  false,
		"::ffff:10.0.0.3":   true, // v4-mapped private
		"::ffff:100.64.0.1": false,
		"fe80::1":           true,
	} {
		if got := dns.PrivateOutsideTailnet(value); got != want {
			t.Errorf("dns.PrivateOutsideTailnet(%q) = %v, want %v", value, got, want)
		}
	}
}
