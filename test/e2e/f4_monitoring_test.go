//go:build integration

package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// F4-040 scenarios: the monitoring UI end to end (run with `make f4-e2e`, same opt-in as F4-035). The
// Caddy gate and the presented leaf are measured on a TLS listener the test starts on a private LAN
// address of this machine; the product's probe policy refuses loopback, so 127.0.0.1 cannot be used.

const (
	f4HealthHost   = "health-e2e.example.com"
	f4TargetIntSec = "3"
)

// labIP returns a private IPv4 address of this machine, or skips the test.
func labIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no network interfaces: %v", err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			return n.IP.String()
		}
	}
	t.Skip("no private IPv4 address on this machine for the probe fixtures")
	return ""
}

// gateFixture is the stand-in Caddy listener on <ip>:443: it presents a generated leaf for the site
// host and answers 403 like the gate does without a session.
type gateFixture struct {
	notAfter time.Time
	mu       sync.Mutex
	sni      []string
}

func startGateFixture(t *testing.T, ip, host string) *gateFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := &gateFixture{notAfter: time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Minute)}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: g.notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			g.mu.Lock()
			g.sni = append(g.sni, h.ServerName)
			g.mu.Unlock()
			return &cert, nil
		},
	})
	if err != nil {
		t.Skipf("cannot listen on %s:443 for the Caddy gate fixture: %v", ip, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return g
}

func (g *gateFixture) sawSNI(host string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.sni {
		if s == host {
			return true
		}
	}
	return false
}

// targetFixture is the upstream the site points at; each path answers its configured status.
type targetFixture struct {
	addr   string
	mu     sync.Mutex
	hits   map[string]int
	status map[string]int
}

func startTargetFixture(t *testing.T, ip string, status map[string]int) *targetFixture {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s for the target fixture: %v", ip, err)
	}
	f := &targetFixture{addr: ln.Addr().String(), hits: map[string]int{}, status: map[string]int{}}
	for k, v := range status {
		f.status[k] = v
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		code, ok := f.status[r.URL.Path]
		f.mu.Unlock()
		if ok {
			w.WriteHeader(code)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *targetFixture) hitsOf(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

// setStatus changes the answer of a path from now on (F4-036: a target that fails, then recovers).
func (f *targetFixture) setStatus(path string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[path] = code
}

func (f *targetFixture) port() string { _, p, _ := net.SplitHostPort(f.addr); return p }

// probeStack is the F4 stack with the two fixtures, the probe policy and the URL-target site.
type probeStack struct {
	*f4Stack
	ip     string
	gate   *gateFixture
	target *targetFixture
}

// newProbeStack starts the fixtures, then the stack with the gate fixture as VPN address and a short
// target/TLS cycle, then lets the devops operator allow the probe addresses and create the site -
// all through the UI.
func newProbeStack(t *testing.T, status map[string]int) *probeStack {
	t.Helper()
	ip := labIP(t)
	p := &probeStack{ip: ip}
	p.gate = startGateFixture(t, ip, f4HealthHost)
	p.target = startTargetFixture(t, ip, status)
	p.f4Stack = newF4StackWith(t, f2Options{vpnAddress: ip, settings: map[string]string{
		"monitor.target_interval_seconds": f4TargetIntSec,
		"monitor.tls_interval_seconds":    f4TargetIntSec,
	}})
	p.setProbePolicy(ip)
	if code, body := p.ui.post("/sites/targets", url.Values{"allowed_targets": {ip}}); code >= 400 {
		t.Fatalf("allow the target host: status %d: %s", code, excerpt(body))
	}
	form := roleSiteForm(f4HealthHost, "devops")
	form.Set("target_kind", "url")
	form.Set("target_url", "http://"+p.target.addr)
	if _, res := p.ui.apply("/sites", form); !res.applied {
		t.Fatalf("the URL-target site was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}
	return p
}

// setProbePolicy saves the F4-043 probe policy: the given address with the gate and target ports.
func (p *probeStack) setProbePolicy(addr string) {
	p.t.Helper()
	code, body := p.ui.post("/k8s/setup/policy", url.Values{"scope": {"probe"}, "addresses": {addr}, "ports": {"443\n" + p.target.port()}})
	if code != http.StatusOK || !strings.Contains(body, "policy kaydedildi") {
		p.t.Fatalf("probe policy: status %d: %s", code, excerpt(body))
	}
}

// cardOf returns the dashboard card of that kind, or "".
func cardOf(body, kind string) string {
	i := strings.Index(body, `data-card="`+kind+`"`)
	if i < 0 {
		return ""
	}
	if j := strings.Index(body[i:], "</section>"); j >= 0 {
		return body[i : i+j]
	}
	return body[i:]
}

// timeIn reports whether t is printed in the card in either zone at the given layout.
func timeIn(card string, t time.Time, layout string) bool {
	return strings.Contains(card, t.UTC().Format(layout)) || strings.Contains(card, t.Local().Format(layout))
}

// TestF4_E2E_HealthTLSAndNoSecrets is F4-040 AC1: the target answer, the Caddy gate answer and the
// presented leaf are three separate cards with their own source, vantage, endpoint and times; the
// leaf's expiry is the one the fixture presents; no Certificate or Secret was requested.
func TestF4_E2E_HealthTLSAndNoSecrets(t *testing.T) {
	p := newProbeStack(t, map[string]int{"/": http.StatusOK})
	p.connect(f4Upstream)

	body := p.waitPage("/", "target, gate and TLS observations of the site", func(b string) bool {
		return strings.Contains(cardOf(b, "target"), "HTTP 200") &&
			strings.Contains(cardOf(b, "caddy_gate"), "HTTP 403") &&
			strings.Contains(cardOf(b, "tls"), "bitiş:")
	})
	target, gate, leaf := cardOf(body, "target"), cardOf(body, "caddy_gate"), cardOf(body, "tls")
	for name, c := range map[string]string{"target": target, "gate": gate, "tls": leaf} {
		for _, want := range []string{f4HealthHost, `data-source="net_probe"`, "Kontrol yeri: " + "tagcess-net", "Hedef: " + p.ip, `class="stt-at"`} {
			if !strings.Contains(c, want) {
				t.Errorf("the %s card lacks %q: %s", name, want, excerpt(c))
			}
		}
	}
	if !strings.Contains(target, "Hedef: "+p.target.addr) {
		t.Errorf("the target card does not name the target endpoint %s: %s", p.target.addr, excerpt(target))
	}
	if !strings.Contains(gate, "Hedef: "+p.ip+":443") || !strings.Contains(leaf, "Hedef: "+p.ip+":443") {
		t.Errorf("the gate and TLS cards do not name %s:443", p.ip)
	}
	if !timeIn(leaf, p.gate.notAfter, "2006-01-02 15:04") {
		t.Errorf("the TLS card does not show the presented leaf's expiry %s: %s", p.gate.notAfter, excerpt(leaf))
	}
	if !p.gate.sawSNI(f4HealthHost) {
		t.Error("the gate fixture never saw the site host as SNI")
	}

	// No Certificate or Secret request: the read-only identity cannot read them (rbac.yaml) and the
	// binary never asks; nothing secret is rendered.
	rbac, err := os.ReadFile(filepath.Join(repoRoot(), "test/k8s/rbac.yaml"))
	if err != nil {
		t.Fatalf("read the lab RBAC: %v", err)
	}
	if r := string(rbac); strings.Contains(r, "secrets") || strings.Contains(r, "certificates") {
		t.Error("the lab ServiceAccount may read secrets or certificates")
	}
	logs := p.proc.stderr.String()
	for _, bad := range []string{"/secrets", "certificates.cert-manager", p.rt.Token} {
		if strings.Contains(logs, bad) || strings.Contains(body, bad) {
			t.Errorf("tagcess logs or the dashboard mention %q", bad)
		}
	}
}

// TestF4_E2E_TwoGateEvidence is F4-040 AC2: the k8s Ingress listens on an entrypoint the profile does
// not declare as internal, so F4-020 records a configuration risk; the card keeps the risk next to
// the measurement's vantage and time (when one exists) and says the internet was not tested.
func TestF4_E2E_TwoGateEvidence(t *testing.T) {
	p := newProbeStack(t, map[string]int{"/": http.StatusOK})
	p.setAPIPolicy()
	// Declared internal listener: the plain web entrypoint, not the websecure one the fixture Ingress uses.
	p.saveProfile(p.ip + " 80 web")
	p.saveCredential()
	// Manage the fixture host, so its Ingress routes are candidates.
	form := roleSiteForm(f4Host, "devops")
	if _, res := p.ui.apply("/sites", form); !res.applied {
		t.Fatalf("the lab host site was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}

	body := p.waitPage("/", "the configuration risk of the lab host", func(b string) bool {
		c := cardOf(b, "two_gate")
		return strings.Contains(c, f4Host) && strings.Contains(c, `data-risk="preserved"`)
	})
	card := cardOf(body, "two_gate")
	if !strings.Contains(card, "config riski") {
		t.Errorf("the two-gate card does not label the risk: %s", excerpt(card))
	}
	if !strings.Contains(card, "İnternet erişimi test edilmedi") {
		t.Errorf("the two-gate card lost the not-tested-from-the-internet note: %s", excerpt(card))
	}
	// A measurement, when present, always carries its network source and time; without one the card
	// says so instead of implying a clean result.
	if strings.Contains(html.UnescapeString(card), "Ağ kontrolü yok") {
		return
	}
	for _, want := range []string{"vantage: tagcess-net", "endpoint:", "zaman: "} {
		if !strings.Contains(card, want) {
			t.Errorf("a two-gate measurement lacks %q: %s", want, excerpt(card))
		}
	}
}

var (
	matrixHeadRE = regexp.MustCompile(`<th scope="col">\s*([^<\s]+)`)
	matrixCellRE = regexp.MustCompile(`data-allowed="([01])"`)
)

// matrixAllows reads the expected-matrix card: does role reach host, and the API exemption text.
func matrixAllows(card, role, host string) (allowed, found bool) {
	var col = -1
	for i, m := range matrixHeadRE.FindAllStringSubmatch(card, -1) {
		if m[1] == host {
			col = i
		}
	}
	i := strings.Index(card, fmt.Sprintf(`<th scope="row">%s</th>`, role))
	if col < 0 || i < 0 {
		return false, false
	}
	row := card[i:]
	if j := strings.Index(row[1:], "</tr>"); j >= 0 {
		row = row[:j+1]
	}
	cells := matrixCellRE.FindAllStringSubmatch(row, -1)
	if col >= len(cells) {
		return false, false
	}
	return cells[col][1] == "1", true
}

// TestF4_E2E_SettingsAndExpectedMatrix is F4-040 AC3: a path/status change and an address-policy
// change made in the UI decide the next measurements, and the dashboard shows the expected Caddy role
// matrix with its source time and the API exemption.
func TestF4_E2E_SettingsAndExpectedMatrix(t *testing.T) {
	p := newProbeStack(t, map[string]int{"/": http.StatusOK, "/ready": http.StatusNoContent})
	p.waitPage("/", "the first target measurement of the default path", func(b string) bool {
		return strings.Contains(cardOf(b, "target"), "HTTP 200")
	})
	if p.target.hitsOf("/ready") != 0 {
		t.Fatal("the target was asked for /ready before the setting was changed")
	}

	// Change the check path and the expected status in the UI; the next cycle uses them.
	code, body := p.ui.post("/monitor/settings", url.Values{
		"target_interval": {f4TargetIntSec}, "inventory_interval": {f4InvSecond}, "tls_interval": {f4TargetIntSec},
		"health_fail": {"3"}, "health_ok": {"2"}, "tls_info": {"30"}, "tls_warn": {"14"}, "tls_critical": {"7"},
		"path": {"/ready"}, "expected_statuses": {"204"}, "timeout": {"5"}, "concurrency": {"4"},
	})
	if code != http.StatusOK || !strings.Contains(body, "İzleme ayarları kaydedildi") {
		t.Fatalf("save the monitoring settings: status %d: %s", code, excerpt(body))
	}
	p.waitPage("/", "a measurement of the saved path and status", func(b string) bool {
		c := cardOf(b, "target")
		return strings.Contains(c, "/ready") && strings.Contains(c, "HTTP 204")
	})
	if p.target.hitsOf("/ready") == 0 {
		t.Error("the target never received a request for the saved path")
	}

	// The probe policy is the saved one: with the target address removed, no new request reaches it.
	p.setProbePolicy("10.254.254.254")
	time.Sleep(2 * time.Second) // a cycle already in flight finishes
	before := p.target.hitsOf("/ready")
	time.Sleep(3 * time.Second * 3)
	if got := p.target.hitsOf("/ready"); got != before {
		t.Errorf("the target was measured %d more times after its address left the probe policy", got-before)
	}
	p.setProbePolicy(p.ip)
	p.waitPage("/", "measurements again after the policy allows the address", func(string) bool {
		return p.target.hitsOf("/ready") > before
	})

	// The expected Caddy role matrix: an API exemption site shows its exemption and the role it allows.
	const apiHost = "health-api.example.com"
	api := withAPIRules(roleSiteForm(apiHost, "devops"), [2]string{"header_present", "Authorization"})
	if _, res := p.ui.apply("/sites", api); !res.applied {
		t.Fatalf("the API site was not applied (status %d, change %q): %s", res.code, res.changeStatus, excerpt(res.body))
	}
	body = p.waitPage("/", "the matrix of the new role sites", func(b string) bool {
		_, ok := matrixAllows(cardOf(b, "matrix"), "devops", apiHost)
		return ok
	})
	card := cardOf(body, "matrix")
	if ok, _ := matrixAllows(card, "devops", apiHost); !ok {
		t.Errorf("devops is not shown as allowed on %s although the site lists it: %s", apiHost, excerpt(card))
	}
	if ok, found := matrixAllows(card, "devops", f4HealthHost); !found || !ok {
		t.Errorf("devops is not shown as allowed on %s: %s", f4HealthHost, excerpt(card))
	}
	if !strings.Contains(html.UnescapeString(card), "API bypass kuralı var (1)") || !strings.Contains(card, `class="stt-at"`) {
		t.Errorf("the matrix lacks the API exemption or the source times: %s", excerpt(card))
	}
	live := blockOf(p.snapshot().caddyfile, apiHost)
	if !strings.Contains(live, "devops") {
		t.Errorf("the Caddyfile block of %s does not list devops, so the matrix claim has no source:\n%s", apiHost, live)
	}
}
