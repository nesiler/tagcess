//go:build integration

// The F2 end-to-end stack (F2-016): the real tagcess binary driven through its web interface
// against a disposable Caddy (the pinned compose image), the compose Headscale's extra-records
// file, the lab Zitadel and a disposable database-mode Headscale. Everything the tests change is
// put back when they end: the Caddy container is removed, the DNS file and the oauth2-proxy app's
// redirect URIs are restored to what they were, and the service user's project role is restored.
//
// Why a disposable Caddy and not the shared compose one: the generated Caddyfile loads certificates
// from /etc/letsencrypt/live/<name>/ (self-signed ones are mounted here) and replaces the whole
// running config, so loading it into the shared Caddy would break the F1 login scenarios. The
// image is the compose pin (f2.CaddyImage); only the admin address (CADDY_ADMIN, which survives a
// /load) and the published ports differ.
package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	internalpermissionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/internal_permission/v2"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/f2"
	"github.com/nesiler/tagcess/test/compose/hsstack"
	"github.com/nesiler/tagcess/test/compose/seed"
)

const (
	// e2eOperator is the identity the test presents on the UI socket, the way Caddy forwards it
	// after oauth2-proxy accepted a devops session.
	e2eOperator = "e2e@tagcess.test"
	// e2eSeedFile and e2eLegacyCaddyfile are the G-01 inputs: today's Caddyfile (placeholders) and
	// the seed that must reproduce it.
	e2eSeedFile         = "test/fixtures/seed-sites.json"
	e2eLegacyCaddyfile  = "test/fixtures/caddyfile-current.caddy"
	e2eCertNames        = "example.com internal.example.org example.net"
	e2eCallbackTemplate = "https://%s/oauth2/callback"
)

// f2Stack is one running scenario.
type f2Stack struct {
	t        *testing.T
	l        *labEnv
	hs       *hsstack.Stack
	caddy    *caddyBox
	proc     *tagcessProc
	cfg      tagcessConfig // what the binary was started with (F4-036: a restart reuses it)
	ui       *uiClient
	zit      *zitadel.Client
	appID    string
	resolver *dnsStandIn

	work      string // scratch directory of the scenario
	caddyfile string // the file tagcess writes (what a Caddy restart would read)
	dnsFile   string // the compose Headscale's watched extra-records file
	since     time.Time
}

// f2Options varies a scenario.
type f2Options struct {
	interval   time.Duration     // sync interval of the binary; default long
	settings   map[string]string // extra settings rows seeded before the binary starts (F4-035)
	vpnAddress string            // sites.vpn_address override (F4-040: a reachable Caddy gate fixture)
}

// newF2Stack builds the stack and runs the first import through the interface, so every scenario
// starts from the same equivalent-to-today state (22 sites, system sites locked).
func newF2Stack(t *testing.T, opts f2Options) *f2Stack {
	t.Helper()
	if opts.interval <= 0 {
		opts.interval = 5 * time.Minute
	}
	l := setupLab(t)
	s := &f2Stack{t: t, l: l, since: time.Now()}

	work, err := os.MkdirTemp("/tmp", "tagcess-e2e-f2-")
	if err != nil {
		t.Fatalf("scenario dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	s.work = work

	// The legacy Caddyfile is both what the Caddy container boots with and what tagcess's file
	// holds before the first import (the parity gate compares the seed against it).
	legacy, err := os.ReadFile(filepath.Join(repoRoot(), e2eLegacyCaddyfile))
	if err != nil {
		t.Fatalf("read the legacy Caddyfile fixture: %v", err)
	}
	initial := filepath.Join(work, "initial.caddy")
	s.caddyfile = filepath.Join(work, "Caddyfile")
	for _, p := range []string{initial, s.caddyfile} {
		if err := os.WriteFile(p, legacy, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	certs := filepath.Join(work, "letsencrypt")
	writeFakeCerts(t, certs, strings.Fields(e2eCertNames))
	s.caddy = startCaddy(t, certs, initial)

	s.dnsFile = filepath.Join(l.composeDir, "dns", "extra-records.json")
	s.resetDNSFile()

	s.openZitadel()
	s.restoreServiceRole() // a crashed earlier run could have left the viewer role behind

	s.hs = hsstack.Start(t)
	s.resolver = startDNSStandIn(t, s.dnsFile)

	s.cfg = tagcessConfig{
		headscaleAddr: s.hs.GRPCAddr(),
		issuer:        l.issuer,
		keyFile:       filepath.Join(l.secrets(), "zitadel-key.json"),
		interval:      opts.interval,
		settings:      opts.settings,
		site: &siteWiring{
			caddyAdmin:  s.caddy.admin,
			caddyfile:   s.caddyfile,
			dnsRecords:  s.dnsFile,
			dnsResolver: s.resolver.addr,
			seedFile:    filepath.Join(repoRoot(), e2eSeedFile),
			vpnAddress:  opts.vpnAddress,
		},
	}
	s.proc = startTagcess(t, l, s.cfg)
	s.ui = newUIClient(t, s.proc.uiSock)
	s.firstImport()
	return s
}

// e2eManualDNS are today's DNS records that no site derives (H-06, F2-022). Every scenario starts
// with them in the file; the first import must keep them for good.
var e2eManualDNS = []dns.Record{
	{Name: "old-db.example.com", Type: dns.TypeA, Value: "100.64.0.9"},
	{Name: "v6-only.example.com", Type: dns.TypeAAAA, Value: "fd7a:115c:a1e0::9"},
}

// resetDNSFile starts the scenario from an extra-records file that holds only the manual records
// and restores the original at the end. The compose Headscale watches the file, so its read errors
// are checked per scenario.
func (s *f2Stack) resetDNSFile() {
	s.t.Helper()
	orig, err := os.ReadFile(s.dnsFile)
	if err != nil {
		s.t.Fatalf("read the compose DNS file (is `make lab-up` done?): %v", err)
	}
	s.t.Cleanup(func() {
		if err := dns.WriteFileAtomic(s.dnsFile, string(orig)); err != nil {
			s.t.Errorf("restore the compose DNS file: %v", err)
		}
	})
	body, err := dns.Marshal(e2eManualDNS)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := dns.WriteFileAtomic(s.dnsFile, body); err != nil {
		s.t.Fatalf("reset the compose DNS file: %v", err)
	}
}

// openZitadel opens the test's own client with tagcess's service key and registers the restore of
// the oauth2-proxy app's redirect URIs. It runs before tagcess starts, so the restore runs after
// tagcess has stopped.
func (s *f2Stack) openZitadel() {
	s.t.Helper()
	u, err := url.Parse(s.l.issuer)
	if err != nil {
		s.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	zc, err := zitadel.New(ctx, zitadel.Config{
		Host:      u.Hostname(),
		KeyFile:   filepath.Join(s.l.secrets(), "zitadel-key.json"),
		ProjectID: s.l.seeded.ProjectID,
	})
	if err != nil {
		s.t.Fatalf("zitadel client: %v", err)
	}
	s.t.Cleanup(func() { _ = zc.Close() })
	s.zit = zc
	if s.appID, err = zc.FindAppID(ctx, seed.OAuth2ProxyAppName); err != nil {
		s.t.Fatalf("find the %s app: %v", seed.OAuth2ProxyAppName, err)
	}
	baseline := s.redirectURIs()
	s.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if sameURIs(s.redirectURIsNoFatal(ctx), baseline) {
			return
		}
		if err := zc.UpdateAppRedirectURIs(ctx, s.appID, baseline); err != nil {
			s.t.Errorf("RESTORE THE LAB APP'S REDIRECT URIs BY HAND: want %v: %v", baseline, err)
		}
	})
}

// redirectURIs reads the oauth2-proxy app's live redirect URIs.
func (s *f2Stack) redirectURIs() []string {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	app, err := s.zit.AppOIDC(ctx, s.appID)
	if err != nil {
		s.t.Fatalf("read the app's redirect URIs: %v", err)
	}
	return app.RedirectUris
}

func (s *f2Stack) redirectURIsNoFatal(ctx context.Context) []string {
	app, err := s.zit.AppOIDC(ctx, s.appID)
	if err != nil {
		return nil
	}
	return app.RedirectUris
}

// setServiceRole switches tagcess's project role. PROJECT_OWNER_VIEWER keeps every read working
// and denies every write, which is how a "Zitadel write breaks" scenario is made real.
func (s *f2Stack) setServiceRole(role string) error {
	ctx, cancel := context.WithTimeout(s.l.adminCtx, 30*time.Second)
	defer cancel()
	_, err := internalpermissionv2.NewInternalPermissionServiceClient(s.l.conn).UpdateAdministrator(ctx,
		&internalpermissionv2.UpdateAdministratorRequest{
			UserId:   s.l.seeded.ServiceUserID,
			Resource: &internalpermissionv2.ResourceType{Resource: &internalpermissionv2.ResourceType_ProjectId{ProjectId: s.l.seeded.ProjectID}},
			Roles:    []string{role},
		})
	return err
}

// restoreServiceRole puts PROJECT_OWNER back; "nothing changed" is not a failure.
func (s *f2Stack) restoreServiceRole() {
	s.t.Helper()
	var last error
	for i := 0; i < 5; i++ {
		if last = s.setServiceRole("PROJECT_OWNER"); last == nil || strings.Contains(strings.ToLower(last.Error()), "no changes") {
			return
		}
		time.Sleep(time.Second)
	}
	s.t.Errorf("RESTORE THE SERVICE USER'S PROJECT_OWNER ROLE BY HAND: %v", last)
}

// firstImport runs G-01 through the interface and fails the scenario unless it applied.
func (s *f2Stack) firstImport() {
	t := s.t
	t.Helper()
	if code, body := s.ui.get("/sites/first-import"); code != http.StatusOK || !strings.Contains(body, "İlk import") {
		t.Fatalf("first-import page: status %d: %s", code, excerpt(body))
	}
	code, body := s.ui.post("/sites/first-import/preview", nil)
	if code != http.StatusOK || !strings.Contains(body, "bugünkü dosyayla eşdeğer (caddy adapt)") {
		t.Fatalf("the seed is not equivalent to the legacy Caddyfile (status %d): %s", code, excerpt(body))
	}
	for _, r := range e2eManualDNS {
		if !strings.Contains(body, r.Name) || !strings.Contains(body, r.Value) {
			t.Errorf("the first-import preview does not show the manual DNS record %s %s: %s", r.Name, r.Value, excerpt(body))
		}
	}
	version := inputValue(body, "parity_version")
	if version == "" {
		t.Fatalf("the first-import preview offers no approval: %s", excerpt(body))
	}
	code, body = s.ui.post("/sites/first-import", url.Values{"parity_version": {version}})
	res := parseResult(code, body)
	if !res.applied {
		t.Fatalf("first import was not applied (status %d, change %q): %s", code, res.changeStatus, excerpt(body))
	}
	s.assertManualDNS("after the first import")
}

// assertManualDNS fails unless every manual record is still in the DNS file and stored as the
// durable manual set (site.manual_dns).
func (s *f2Stack) assertManualDNS(when string) {
	s.t.Helper()
	raw, err := os.ReadFile(s.dnsFile)
	if err != nil {
		s.t.Fatalf("read the DNS file: %v", err)
	}
	var recs []dns.Record
	if err := json.Unmarshal(raw, &recs); err != nil {
		s.t.Fatalf("parse the DNS file: %v: %s", err, raw)
	}
	for _, want := range e2eManualDNS {
		found := false
		for _, r := range recs {
			found = found || r == want
		}
		if !found {
			s.t.Errorf("%s: the manual DNS record %+v is not in the DNS file", when, want)
		}
		if n := s.proc.queryInt(s.t, `SELECT count(*) FROM settings WHERE key = 'site.manual_dns' AND instr(value, ?) > 0`, want.Name); n != 1 {
			s.t.Errorf("%s: %s is not in the stored site.manual_dns setting", when, want.Name)
		}
	}
}

// Disposable Caddy ------------------------------------------------------------

// caddyBox is a throwaway Caddy container with its admin API and HTTPS port published on loopback.
type caddyBox struct {
	t     *testing.T
	name  string
	admin string // http://127.0.0.1:<port>
	https string // 127.0.0.1:<port>
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// startCaddy boots the pinned image with the initial Caddyfile and the fake certificate tree. The
// container resolves no external name (--dns), so Caddy can never reach an ACME server for a
// production hostname; every block that needs a certificate has a mounted one anyway.
func startCaddy(t *testing.T, certs, initial string) *caddyBox {
	t.Helper()
	adminPort, httpsPort := freePort(t), freePort(t)
	c := &caddyBox{
		t:     t,
		name:  fmt.Sprintf("tagcess-e2e-caddy-%d", time.Now().UnixNano()),
		admin: fmt.Sprintf("http://127.0.0.1:%d", adminPort),
		https: fmt.Sprintf("127.0.0.1:%d", httpsPort),
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", c.name).Run() })
	out, err := exec.Command("docker", "run", "-d", "--name", c.name, "--dns", "127.0.0.1",
		"-e", "CADDY_ADMIN=0.0.0.0:2019",
		"-p", fmt.Sprintf("127.0.0.1:%d:2019", adminPort),
		"-p", fmt.Sprintf("127.0.0.1:%d:443", httpsPort),
		"-v", certs+":/etc/letsencrypt:ro",
		"-v", initial+":/etc/caddy/Caddyfile:ro",
		f2.CaddyImage, "caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run caddy: %v: %s", err, out)
	}
	if err := poll(t, 40*time.Second, func() (bool, error) {
		resp, err := http.Get(c.admin + "/config/")
		if err != nil {
			return false, err
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK, nil
	}); err != nil {
		logs, _ := exec.Command("docker", "logs", c.name).CombinedOutput()
		t.Fatalf("caddy admin API did not come up: %v: %s", err, logs)
	}
	return c
}

// config is the running Caddy config as JSON.
func (c *caddyBox) config() string {
	c.t.Helper()
	resp, err := http.Get(c.admin + "/config/")
	if err != nil {
		c.t.Fatalf("read the live Caddy config: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.t.Fatalf("read the live Caddy config: status %d: %v", resp.StatusCode, err)
	}
	return string(body)
}

// get sends one HTTPS request to the published port with the given SNI/Host. The request comes
// from the Docker gateway, i.e. from outside 100.64.0.0/10: it is a source the S-06 key governs.
// A transport error is returned, not fatal, so a test can assert on a stalled proxy.
func (c *caddyBox) get(host, path string, header map[string]string) (int, error) {
	hc := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec // the mounted certificates are self-signed test ones
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, c.https)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// location is get that also returns the Location header (redirect assertions).
func (c *caddyBox) location(host, path string) (int, string, error) {
	hc := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificates
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, c.https)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Get("https://" + host + path)
	if err != nil {
		return 0, "", err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

func (c *caddyBox) pause(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("docker", "pause", c.name).CombinedOutput(); err != nil {
		t.Fatalf("docker pause caddy: %v: %s", err, out)
	}
}

func (c *caddyBox) unpause(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("docker", "unpause", c.name).CombinedOutput(); err != nil {
		t.Fatalf("docker unpause caddy: %v: %s", err, out)
	}
}

// writeFakeCerts creates root/live/<name>/{fullchain,privkey}.pem for each name: a self-signed
// certificate valid for the name and its direct subdomains (the cert:auto coverage rule).
func writeFakeCerts(t *testing.T, root string, names []string) {
	t.Helper()
	for i, name := range names {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     []string{name, "*." + name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "live", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// MagicDNS stand-in ------------------------------------------------------------

// dnsStandIn answers A queries from the extra-records file Headscale watches, the way MagicDNS
// serves them to a node. Compose has no tailscale node to ask 100.100.100.100, so the resolver
// check of the pipeline (S-03.4) talks to this instead; a real dig stays F2-017's job. While
// silent it answers nothing, which makes the pipeline's verification time out.
type dnsStandIn struct {
	addr   string
	file   string
	silent atomic.Bool
	conn   net.PacketConn
}

func startDNSStandIn(t *testing.T, file string) *dnsStandIn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns stand-in: %v", err)
	}
	d := &dnsStandIn{addr: conn.LocalAddr().String(), file: file, conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go d.serve()
	return d
}

func (d *dnsStandIn) serve() {
	buf := make([]byte, 512)
	for {
		n, from, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if d.silent.Load() {
			continue
		}
		if reply := d.answer(buf[:n]); reply != nil {
			_, _ = d.conn.WriteTo(reply, from)
		}
	}
}

// answer builds the reply to one single-question query.
func (d *dnsStandIn) answer(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	i := 12
	var labels []string
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if i+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+5 > len(q) {
		return nil
	}
	name := strings.ToLower(strings.Join(labels, "."))
	qtype := binary.BigEndian.Uint16(q[i+1 : i+3])
	question := q[12 : i+5]

	var ips []net.IP
	if qtype == 1 {
		raw, _ := os.ReadFile(d.file)
		var recs []dns.Record
		_ = json.Unmarshal(raw, &recs)
		for _, r := range recs {
			if r.Type == dns.TypeA && strings.EqualFold(r.Name, name) {
				if ip := net.ParseIP(r.Value).To4(); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	reply := make([]byte, 12, 12+len(question)+16*len(ips))
	copy(reply[0:2], q[0:2])
	binary.BigEndian.PutUint16(reply[2:4], 0x8180) // response, recursion desired + available
	binary.BigEndian.PutUint16(reply[4:6], 1)
	binary.BigEndian.PutUint16(reply[6:8], uint16(len(ips)))
	reply = append(reply, question...)
	for _, ip := range ips {
		reply = append(reply, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		reply = append(reply, ip...)
	}
	return reply
}

// The web interface -------------------------------------------------------------

// uiClient talks to the binary's UI socket as a signed-in devops operator, the way Caddy would
// forward them. State-changing requests carry a CSRF token read from a rendered page.
type uiClient struct {
	t     *testing.T
	hc    *http.Client
	token string
}

func newUIClient(t *testing.T, sock string) *uiClient {
	t.Helper()
	return &uiClient{
		t: t,
		hc: &http.Client{
			// A site change waits for the resolver verification (up to 10 s) and several lab calls.
			Timeout: 3 * time.Minute,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sock)
				},
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *uiClient) do(method, path string, form url.Values) (int, string) {
	c.t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		if form == nil {
			form = url.Values{}
		}
		if form.Get("csrf_token") == "" {
			form.Set("csrf_token", c.csrf())
		}
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, "http://tagcess"+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("X-Auth-Request-User", "e2e")
	req.Header.Set("X-Auth-Request-Email", e2eOperator)
	req.Header.Set("X-Auth-Request-Groups", "devops")
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return resp.StatusCode, string(out)
}

func (c *uiClient) get(path string) (int, string) { return c.do(http.MethodGet, path, nil) }
func (c *uiClient) post(path string, f url.Values) (int, string) {
	return c.do(http.MethodPost, path, f)
}

// csrf reads a token from a rendered form; tokens are stateless signatures, so one serves all.
func (c *uiClient) csrf() string {
	if c.token != "" {
		return c.token
	}
	code, body := c.do(http.MethodGet, "/sites/new", nil)
	if code != http.StatusOK {
		c.t.Fatalf("GET /sites/new for a CSRF token: status %d", code)
	}
	if c.token = inputValue(body, "csrf_token"); c.token == "" {
		c.t.Fatalf("no CSRF token on the site form: %s", excerpt(body))
	}
	return c.token
}

var inputRE = map[string]*regexp.Regexp{}

// inputValue returns the (unescaped) value of the first hidden input with that name.
func inputValue(body, name string) string {
	re, ok := inputRE[name]
	if !ok {
		re = regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
		inputRE[name] = re
	}
	m := re.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return html.UnescapeString(m[1])
}

func excerpt(body string) string {
	body = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]+>`).ReplaceAllString(body, " ")
	body = strings.Join(strings.Fields(body), " ")
	if len(body) > 700 {
		body = body[:700] + "…"
	}
	return body
}

// siteReview is a parsed review screen.
type siteReview struct {
	code    int
	body    string
	diffs   map[string]string // "Caddy" | "DNS" | "Zitadel" -> diff text, "" when unchanged
	request string
	version string
	blocked bool
}

// The review renders each artifact as a ui.Diff box: a head with the title and either the
// "değişmiyor" pill or a summary pill, then one div per diff line.
var (
	diffHeadRE = regexp.MustCompile(`<div class="codehead"><b class="mono">(Caddy|DNS|Zitadel)</b><span class="pill pill-flat">([^<]*)</span></div>`)
	diffLineRE = regexp.MustCompile(`(?s)<div class="ln[^"]*">(.*?)</div>`)
)

// parseDiffBoxes returns the diff text per artifact title, "" when the box says it is unchanged.
func parseDiffBoxes(body string) map[string]string {
	out := map[string]string{}
	heads := diffHeadRE.FindAllStringSubmatchIndex(body, -1)
	for i, h := range heads {
		title := body[h[2]:h[3]]
		if body[h[4]:h[5]] == "değişmiyor" {
			out[title] = ""
			continue
		}
		end := len(body)
		if i+1 < len(heads) {
			end = heads[i+1][0]
		}
		var lines []string
		for _, m := range diffLineRE.FindAllStringSubmatch(body[h[1]:end], -1) {
			lines = append(lines, html.UnescapeString(m[1]))
		}
		out[title] = strings.Join(lines, "\n")
	}
	return out
}

func parseReview(code int, body string) siteReview {
	r := siteReview{code: code, body: body, diffs: parseDiffBoxes(body)}
	r.request = inputValue(body, "request")
	r.version = inputValue(body, "plan_version")
	r.blocked = strings.Contains(body, "Değişiklik mevcut durum yüzünden apply edilemez")
	return r
}

// approvable reports whether the screen offers the approval form.
func (r siteReview) approvable() bool {
	return r.code == http.StatusOK && r.request != "" && r.version != ""
}

// siteResult is a parsed result screen.
type siteResult struct {
	code         int
	body         string
	applied      bool
	changeStatus string
	reason       string
}

var (
	resultStatusRE = regexp.MustCompile(`data-status="([a-z_]+)"`)
	// A failed change shows its reason in an alert block, any other outcome (a rolled-back add, a
	// dry run) as a quiet paragraph.
	resultReasonRE = regexp.MustCompile(`(?s)<strong>Neden</strong></p>\s*<pre><code>(.*?)</code></pre>`)
	resultNoteRE   = regexp.MustCompile(`(?s)data-status="[a-z_]+".*?<p>(.*?)</p>`)
)

func parseResult(code int, body string) siteResult {
	r := siteResult{code: code, body: body, applied: strings.Contains(body, "Değişiklik apply edildi; kayıtlı siteler günceldi")}
	if m := resultStatusRE.FindStringSubmatch(body); m != nil {
		r.changeStatus = m[1]
	}
	if m := resultReasonRE.FindStringSubmatch(body); m != nil {
		r.reason = html.UnescapeString(m[1])
	} else if m := resultNoteRE.FindStringSubmatch(body); m != nil {
		r.reason = html.UnescapeString(m[1])
	}
	return r
}

// review submits a site form and parses the screen it answers with.
func (c *uiClient) review(path string, form url.Values) siteReview {
	c.t.Helper()
	code, body := c.post(path, form)
	return parseReview(code, body)
}

// approve confirms a review screen.
func (c *uiClient) approve(r siteReview) siteResult {
	c.t.Helper()
	if !r.approvable() {
		c.t.Fatalf("the screen offers no approval (status %d): %s", r.code, excerpt(r.body))
	}
	code, body := c.post("/sites/review/approve", url.Values{"request": {r.request}, "plan_version": {r.version}})
	return parseResult(code, body)
}

// apply is review + approve for a change that must go through.
func (c *uiClient) apply(path string, form url.Values) (siteReview, siteResult) {
	c.t.Helper()
	r := c.review(path, form)
	return r, c.approve(r)
}

// roleSiteForm is the form of a role-controlled site.
func roleSiteForm(host string, roles ...string) url.Values {
	return url.Values{
		"kind":        {"role"},
		"hosts":       {host},
		"roles":       {strings.Join(roles, "\n")},
		"cert":        {"auto"},
		"target_kind": {"k8s"},
		"magicdns":    {"1"},
	}
}

// Store, files and lab assertions -------------------------------------------------

// siteID is the id of the site that owns host, or 0.
func (s *f2Stack) siteID(host string) int64 {
	s.t.Helper()
	var id int64
	err := s.proc.storeDB(s.t).QueryRow(`SELECT site_id FROM site_hosts WHERE hostname = ?`, host).Scan(&id)
	if err != nil {
		return 0
	}
	return id
}

func (s *f2Stack) siteCount() int {
	return s.proc.queryInt(s.t, `SELECT count(*) FROM sites`)
}

// auditCount counts audit events by name and result.
func (s *f2Stack) auditCount(event, result string) int {
	return s.proc.queryInt(s.t, `SELECT count(*) FROM audit_events WHERE event = ? AND result = ?`, event, result)
}

// openAlerts counts unresolved alerts of a kind.
func (s *f2Stack) openAlerts(kind string) int {
	return s.proc.queryInt(s.t, `SELECT count(*) FROM alerts WHERE kind = ? AND resolved_at IS NULL`, kind)
}

// snapshot is the state of every artifact a site change may touch.
type snapshot struct {
	caddyfile string
	live      string
	dns       string
	uris      []string
	sites     int
}

func (s *f2Stack) snapshot() snapshot {
	s.t.Helper()
	disk, err := os.ReadFile(s.caddyfile)
	if err != nil {
		s.t.Fatalf("read the Caddyfile: %v", err)
	}
	recs, err := os.ReadFile(s.dnsFile)
	if err != nil {
		s.t.Fatalf("read the DNS file: %v", err)
	}
	return snapshot{caddyfile: string(disk), live: s.caddy.config(), dns: string(recs), uris: s.redirectURIs(), sites: s.siteCount()}
}

// assertUnchanged fails with a precise message for the first artifact that differs.
func (s *f2Stack) assertUnchanged(before snapshot, what string) {
	s.t.Helper()
	after := s.snapshot()
	switch {
	case after.caddyfile != before.caddyfile:
		s.t.Errorf("%s: the Caddyfile on disk changed", what)
	case after.live != before.live:
		s.t.Errorf("%s: the live Caddy config changed", what)
	case after.dns != before.dns:
		s.t.Errorf("%s: the DNS file changed:\nbefore %s\nafter  %s", what, before.dns, after.dns)
	case !sameURIs(after.uris, before.uris):
		s.t.Errorf("%s: the redirect URIs changed:\nbefore %v\nafter  %v", what, before.uris, after.uris)
	case after.sites != before.sites:
		s.t.Errorf("%s: the site count changed: %d -> %d", what, before.sites, after.sites)
	}
}

// dnsHas reports whether the DNS file carries an A record name -> the configured VPN address.
func (s *f2Stack) dnsHas(name string) bool {
	s.t.Helper()
	raw, err := os.ReadFile(s.dnsFile)
	if err != nil {
		s.t.Fatalf("read the DNS file: %v", err)
	}
	var recs []dns.Record
	if err := json.Unmarshal(raw, &recs); err != nil {
		s.t.Fatalf("parse the DNS file: %v: %s", err, raw)
	}
	for _, r := range recs {
		if r.Name == name && r.Type == dns.TypeA && r.Value == e2eVPNAddress {
			return true
		}
	}
	return false
}

func hasURI(uris []string, want string) bool {
	for _, u := range uris {
		if u == want {
			return true
		}
	}
	return false
}

// headscaleReadErrors counts the compose Headscale's "cannot read the extra records" log lines
// since the scenario began: a file it refuses would show up here (F2-006).
func (s *f2Stack) headscaleReadErrors() int {
	s.t.Helper()
	out, err := exec.Command("docker", "compose", "-f", filepath.Join(s.l.composeDir, "compose.yaml"),
		"logs", "headscale", "--since", s.since.UTC().Format(time.RFC3339)).CombinedOutput()
	if err != nil {
		s.t.Fatalf("docker compose logs headscale: %v: %s", err, out)
	}
	return strings.Count(string(out), "reading extra records from path")
}

// gitLog lists the commit subjects of the artifact history, newest first.
func (s *f2Stack) gitLog() []string {
	s.t.Helper()
	out, err := exec.Command("git", "-C", filepath.Join(s.proc.dataDir, "artifact-git"), "log", "--format=%s").CombinedOutput()
	if err != nil {
		s.t.Fatalf("git log of the artifact history: %v: %s", err, out)
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// section runs a scenario step as a subtest and points the stack's helpers at it while it runs, so
// their failures are reported against the step and Fatal never fires on the parent.
func (s *f2Stack) section(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run(name, func(sub *testing.T) {
		prev := s.t
		s.t, s.ui.t, s.caddy.t = sub, sub, sub
		defer func() { s.t, s.ui.t, s.caddy.t = prev, prev, prev }()
		fn(sub)
	})
}
