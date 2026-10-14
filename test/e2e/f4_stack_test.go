//go:build integration

// The F4 end-to-end stack (F4-035): the F2 site stack (real tagcess binary, disposable Caddy, the
// compose DNS file, the lab Zitadel) plus the personal k3s lab of F4-033. The k8s connection is made
// through the UI like an operator would; the test tooling alone holds the bootstrap kubeconfig and
// hands tagcess only the endpoint, the CA and a short-lived read-only ServiceAccount token. F4-040
// adds its scenarios to this same stack (health, TLS, two gates, settings, spoof).
//
// Every F4 e2e test needs the opt-in (`make f4-e2e`); without it the test skips and the target fails,
// so a skip is never counted as a PASS.
package e2e_test

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/test/k8s"
)

const (
	// f4Host is the host of the lab fixture Ingress (test/k8s/lab.sh); k8s-lab.test is on the e2e
	// allowlist of harness_test.go.
	f4Host = "fixture.k8s-lab.test"
	// f4Upstream is the declared internal listener: the address of the fixed (k8s) upstream, the only
	// target a role site renders with (ADR 0010).
	f4Upstream  = "100.64.0.5"
	f4EntryPt   = "websecure"
	f4InvSecond = "3" // inventory interval of the scenarios, seconds
)

// f4Stack is the F2 stack with a k8s lab behind it.
type f4Stack struct {
	*f2Stack
	lab *k8s.Lab
	rt  k8s.Runtime
	pf  k8s.Preflight
}

// newF4Stack skips without the opt-in, then prepares the lab namespace and the read-only identity
// and starts the F2 stack with a short inventory interval. The lab cleans itself up (also on failure).
func newF4Stack(t *testing.T) *f4Stack { return newF4StackWith(t, f2Options{}) }

// newF4StackWith is newF4Stack with extra F2 options (F4-040: the gate fixture as VPN address, faster
// measurement loops). The short inventory interval is always set.
func newF4StackWith(t *testing.T, opts f2Options) *f4Stack {
	t.Helper()
	cfg := k8s.RequireLab(t, os.Getenv)
	lab := k8s.NewLab(t, cfg, nil)
	lab.Setup()
	pf, err := lab.Preflight()
	if err != nil {
		t.Fatalf("k8s lab preflight: %v", err)
	}
	settings := map[string]string{"monitor.inventory_interval_seconds": f4InvSecond}
	for k, v := range opts.settings {
		settings[k] = v
	}
	opts.settings = settings
	s := newF2Stack(t, opts)
	return &f4Stack{f2Stack: s, lab: lab, rt: lab.Runtime(), pf: pf}
}

// apiPolicy is the address and port the API policy must allow: the lab endpoint, resolved.
func (s *f4Stack) apiPolicy() (addresses, port string) {
	s.t.Helper()
	u, err := url.Parse(s.rt.Server)
	if err != nil {
		s.t.Fatalf("lab endpoint: %v", err)
	}
	port = u.Port()
	if port == "" {
		port = "443"
	}
	var ips []string
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		ips = []string{a.String()}
	} else {
		found, err := net.LookupIP(u.Hostname())
		if err != nil {
			s.t.Fatalf("resolve the lab endpoint: %v", err)
		}
		for _, ip := range found {
			if ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	if len(ips) == 0 {
		s.t.Fatalf("the lab endpoint %s has no usable address", u.Hostname())
	}
	sort.Strings(ips)
	return strings.Join(ips, "\n"), strconv.Itoa(mustPort(s.t, port))
}

func mustPort(t *testing.T, p string) int {
	t.Helper()
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port %q: %v", p, err)
	}
	return n
}

// tlsServerName is the name the API certificate is verified for; empty when it is an IP literal.
func (s *f4Stack) tlsServerName() string {
	if _, err := netip.ParseAddr(s.pf.TLSServerName); err == nil {
		return ""
	}
	return s.pf.TLSServerName
}

// restart stops the binary and starts it again on the same data directory and config (F4-036: the
// alert lifecycle must survive it). The UI client is replaced because the socket is new.
func (s *f4Stack) restart() {
	s.t.Helper()
	old := s.proc
	old.stop(s.t)
	cfg := s.cfg
	cfg.dataDir = old.dataDir
	s.proc = startTagcess(s.t, s.l, cfg)
	s.ui = newUIClient(s.t, s.proc.uiSock)
}

// draftReview refreshes the lab draft and reviews it until the S-04 preview is approvable (the
// inventory loop reads on its own interval). The draft is a devops role draft on the k8s upstream.
func (s *f4Stack) draftReview() siteReview {
	s.t.Helper()
	var review siteReview
	deadline := time.Now().Add(90 * time.Second)
	for {
		if code, _ := s.ui.post(draftPath("/refresh"), nil); code == http.StatusOK || code == http.StatusSeeOther {
			review = s.ui.review(draftPath("/review"), nil)
			if review.approvable() {
				return review
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("the draft never reached an approvable review (status %d): %s", review.code, excerpt(review.body))
		}
		time.Sleep(3 * time.Second)
	}
}

// reviewableDraft connects the lab, waits for the discovery, saves the devops role draft and returns
// its approvable preview.
func (s *f4Stack) reviewableDraft() siteReview {
	s.t.Helper()
	s.connect(f4Upstream)
	s.waitPage("/k8s/discovery", "the lab host in the discovery", func(b string) bool { return strings.Contains(b, f4Host) })
	s.saveDraft("devops")
	return s.draftReview()
}
