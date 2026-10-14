package k8s

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// ---- test doubles ---------------------------------------------------------------------------

type fatalSignal struct{ msg string }
type skipSignal struct{ msg string }

// fakeTB is a LabTB that records instead of failing, so a test can look at what the lab helper did
// to a test it does not own. Fatalf and Skipf panic like runtime.Goexit would unwind a real test.
type fakeTB struct {
	t        *testing.T
	cleanups []func()
	errors   []string
	logs     []string
	skip     string
	fatal    string
}

func (f *fakeTB) Helper()           {}
func (f *fakeTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *fakeTB) TempDir() string   { return f.t.TempDir() }
func (f *fakeTB) Errorf(format string, a ...any) {
	f.errors = append(f.errors, fmt.Sprintf(format, a...))
}
func (f *fakeTB) Logf(format string, a ...any)   { f.logs = append(f.logs, fmt.Sprintf(format, a...)) }
func (f *fakeTB) Skipf(format string, a ...any)  { panic(skipSignal{fmt.Sprintf(format, a...)}) }
func (f *fakeTB) Fatalf(format string, a ...any) { panic(fatalSignal{fmt.Sprintf(format, a...)}) }

// play runs body like a test function would run: Fatalf, Skipf and a panic end it, then the registered
// cleanups run in LIFO order, the way testing.T unwinds them. It returns the panic value that is not
// one of the signals, if any.
func (f *fakeTB) play(body func()) (panicked any) {
	func() {
		defer func() {
			switch r := recover().(type) {
			case nil:
			case fatalSignal:
				f.fatal = r.msg
			case skipSignal:
				f.skip = r.msg
			default:
				panicked = r
			}
		}()
		body()
	}()
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
	return panicked
}

type runCall struct {
	env  []string
	args []string
}

// fakeRunner answers lab.sh sub-commands (args[0]) from a table and records every call.
type fakeRunner struct {
	calls []runCall
	out   map[string]string
	err   map[string]error
}

func (f *fakeRunner) run(_ context.Context, env []string, args ...string) (string, error) {
	f.calls = append(f.calls, runCall{env: slices.Clone(env), args: slices.Clone(args)})
	if err := f.err[args[0]]; err != nil {
		return f.out[args[0]], err
	}
	return f.out[args[0]], nil
}

func (f *fakeRunner) called(sub string) []runCall {
	var out []runCall
	for _, c := range f.calls {
		if c.args[0] == sub {
			out = append(out, c)
		}
	}
	return out
}

// labCA generates a CA and a leaf for dnsName at test time and serves TLS with it.
type labCA struct {
	pem    string
	sha256 string
	addr   string
}

func startLabAPI(t *testing.T, dnsName string) labCA {
	t.Helper()
	ca, caKey, _ := newTestCA(t)
	leaf := newLeafCert(t, ca, caKey, dnsName)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(ca.Raw)
	return labCA{
		pem:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		sha256: hex.EncodeToString(sum[:]),
		addr:   srv.Listener.Addr().String(),
	}
}

const (
	traefikController = "traefik.io/ingress-controller"
	fakeToken         = "fake-sa-token-for-tests"
	bootstrapMarker   = "BOOTSTRAP-ADMIN-CREDENTIAL-MARKER"
)

func versionJSON(v string) string {
	return `{"clientVersion":{"gitVersion":"v1.99.0"},"serverVersion":{"gitVersion":"` + v + `"}}`
}

func classesJSON(items ...string) string { return `{"items":[` + strings.Join(items, ",") + `]}` }

func classJSON(name, controller string) string {
	return `{"metadata":{"name":"` + name + `"},"spec":{"controller":"` + controller + `"}}`
}

func traefikJSON(image string, args ...string) string {
	a, _ := json.Marshal(args)
	return `{"items":[{"spec":{"template":{"spec":{"containers":[{"image":"` + image + `","args":` + string(a) + `}]}}}}]}`
}

// healthyOutputs is the read-only cluster view of a matching Traefik profile against api.
func healthyOutputs(api labCA) map[string]string {
	return map[string]string{
		"version":        versionJSON("v1.99.1+k3s1"),
		"ingressclasses": classesJSON(classJSON("other", "example.com/other"), classJSON("traefik", traefikController)),
		"traefik": traefikJSON("rancher/mirrored-library-traefik:3.9.9",
			"--entrypoints.web.address=:8000/tcp", "--entrypoints.websecure.address=:8443/tcp"),
		"server":    "https://" + api.addr,
		"ca":        base64Of(api.pem),
		"token":     fakeToken + "\n",
		"leftovers": "",
	}
}

func newTestLab(t *testing.T, tb LabTB, run *fakeRunner) (*Lab, string) {
	t.Helper()
	kubeconfig := filepath.Join(t.TempDir(), "bootstrap-kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("admin credential "+bootstrapMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := LabConfig{Kubeconfig: kubeconfig, Context: "lab-k3s", RecordDir: t.TempDir(), TLSServerName: "kubernetes.lab.test"}
	return NewLab(tb, cfg, run.run), kubeconfig
}

// ---- AC4 ------------------------------------------------------------------------------------

func TestK8sLabRequiresExplicitOptIn(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		env      map[string]string
		wantSkip []string // substrings the skip reason must carry
	}{
		{"nothing set", nil, []string{EnvOptIn, "SKIP", "not a PASS"}},
		{"opt-in is not exactly 1", map[string]string{EnvOptIn: "true", EnvKubeconfig: existing}, []string{EnvOptIn}},
		{"opt-in without kubeconfig", map[string]string{EnvOptIn: "1"}, []string{EnvKubeconfig}},
		{"kubeconfig file missing", map[string]string{EnvOptIn: "1", EnvKubeconfig: existing + ".missing"}, []string{EnvKubeconfig}},
		{"opt-in without context", map[string]string{EnvOptIn: "1", EnvKubeconfig: existing}, []string{EnvContext}}, // C-L12
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tb := &fakeTB{t: t}
			getenv := func(k string) string { return tc.env[k] }
			tb.play(func() { RequireLab(tb, getenv) })
			if tb.skip == "" {
				t.Fatalf("RequireLab did not skip (fatal=%q)", tb.fatal)
			}
			for _, want := range tc.wantSkip {
				if !strings.Contains(tb.skip, want) {
					t.Errorf("skip reason %q does not mention %q", tb.skip, want)
				}
			}
		})
	}

	t.Run("enabled", func(t *testing.T) {
		tb := &fakeTB{t: t}
		var cfg LabConfig
		tb.play(func() {
			cfg = RequireLab(tb, func(k string) string {
				return map[string]string{EnvOptIn: "1", EnvKubeconfig: existing, EnvContext: "lab-k3s"}[k]
			})
		})
		if tb.skip != "" || tb.fatal != "" {
			t.Fatalf("enabled lab was skipped or failed: skip=%q fatal=%q", tb.skip, tb.fatal)
		}
		if cfg.Context != "lab-k3s" {
			t.Errorf("Context = %q, want lab-k3s", cfg.Context)
		}
		if cfg.Kubeconfig != existing {
			t.Errorf("Kubeconfig = %q, want %q", cfg.Kubeconfig, existing)
		}
	})
}

// ---- AC2 ------------------------------------------------------------------------------------

func TestK8sLabPreflightMatchesTraefikProfile(t *testing.T) {
	api := startLabAPI(t, "kubernetes.lab.test")

	t.Run("matching profile is recorded", func(t *testing.T) {
		run := &fakeRunner{out: healthyOutputs(api)}
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, run)
		var pf Preflight
		tb.play(func() { pf = lab.RequirePreflight() })
		if tb.fatal != "" {
			t.Fatalf("matching profile failed: %s", tb.fatal)
		}
		want := Preflight{
			KubernetesVersion: "v1.99.1+k3s1", TraefikVersion: "3.9.9",
			IngressClass: "traefik", Controller: traefikController,
			Listeners:     []string{"web=:8000/tcp", "websecure=:8443/tcp"},
			APIServer:     api.addr,
			TLSServerName: "kubernetes.lab.test", CAFingerprint: api.sha256, ServerNameVerified: true,
		}
		if pf.KubernetesVersion != want.KubernetesVersion || pf.TraefikVersion != want.TraefikVersion ||
			pf.IngressClass != want.IngressClass || pf.Controller != want.Controller ||
			!slices.Equal(pf.Listeners, want.Listeners) || pf.APIServer != want.APIServer ||
			pf.TLSServerName != want.TLSServerName || pf.CAFingerprint != want.CAFingerprint || !pf.ServerNameVerified {
			t.Fatalf("preflight = %+v, want %+v", pf, want)
		}
		// The record is a nonsecret JSON file in the record dir.
		data, err := os.ReadFile(filepath.Join(lab.cfg.RecordDir, PreflightRecordFile))
		if err != nil {
			t.Fatalf("preflight record not written: %v", err)
		}
		var got Preflight
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("record is not JSON: %v", err)
		}
		if got.TraefikVersion != "3.9.9" || got.CAFingerprint != api.sha256 {
			t.Errorf("record content = %+v", got)
		}
		for _, secret := range []string{fakeToken, bootstrapMarker, "BEGIN"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("record leaks %q", secret)
			}
		}
		// Only reads reach the cluster during preflight; nothing is created.
		for _, c := range run.calls {
			if slices.Contains([]string{"up", "down", "token"}, c.args[0]) {
				t.Errorf("preflight ran %v", c.args)
			}
		}
	})

	mismatch := []struct {
		name   string
		change func(out map[string]string)
		want   string
	}{
		{"controller is not traefik", func(o map[string]string) {
			o["ingressclasses"] = classesJSON(classJSON("nginx", "k8s.io/ingress-nginx"))
		}, "controller"},
		{"no ingress class", func(o map[string]string) { o["ingressclasses"] = classesJSON() }, "IngressClass"},
		{"traefik not found", func(o map[string]string) { o["traefik"] = `{"items":[]}` }, "Traefik"},
		{"no websecure listener", func(o map[string]string) {
			o["traefik"] = traefikJSON("traefik:3.9.9", "--entrypoints.web.address=:8000/tcp")
		}, "websecure"},
		{"unknown kubernetes version", func(o map[string]string) { o["version"] = `{"serverVersion":{}}` }, "version"},
	}
	for _, tc := range mismatch {
		t.Run(tc.name, func(t *testing.T) {
			out := healthyOutputs(api)
			tc.change(out)
			tb := &fakeTB{t: t}
			lab, _ := newTestLab(t, tb, &fakeRunner{out: out})
			tb.play(func() { lab.RequirePreflight() })
			if tb.fatal == "" {
				t.Fatal("profile mismatch did not fail the acceptance test")
			}
			if !strings.Contains(tb.fatal, tc.want) {
				t.Errorf("failure %q does not mention %q", tb.fatal, tc.want)
			}
		})
	}

	t.Run("tls server name not in the certificate", func(t *testing.T) {
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, &fakeRunner{out: healthyOutputs(api)})
		lab.cfg.TLSServerName = "other.lab.test"
		tb.play(func() { lab.RequirePreflight() })
		if tb.fatal == "" || !strings.Contains(tb.fatal, "server name") {
			t.Fatalf("wrong server name must fail the acceptance test, fatal=%q", tb.fatal)
		}
	})

	t.Run("ca does not sign the api certificate", func(t *testing.T) {
		other := startLabAPI(t, "kubernetes.lab.test")
		out := healthyOutputs(api)
		out["ca"] = base64Of(other.pem)
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, &fakeRunner{out: out})
		tb.play(func() { lab.RequirePreflight() })
		if tb.fatal == "" {
			t.Fatal("untrusted API certificate must fail the acceptance test")
		}
	})

	t.Run("server name defaults to the endpoint host", func(t *testing.T) {
		out := healthyOutputs(api)
		out["server"] = "https://localhost:" + api.addr[strings.LastIndex(api.addr, ":")+1:]
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, &fakeRunner{out: out})
		lab.cfg.TLSServerName = ""
		tb.play(func() { lab.RequirePreflight() })
		// localhost is not in the leaf's SAN (kubernetes.lab.test), so the default name must be tried and rejected.
		if tb.fatal == "" || !strings.Contains(tb.fatal, "localhost") {
			t.Fatalf("default server name localhost should be verified and rejected, fatal=%q", tb.fatal)
		}
	})
}

// ---- AC1 ------------------------------------------------------------------------------------

func TestK8sLabSeparatesBootstrapAndRuntimeIdentity(t *testing.T) {
	api := startLabAPI(t, "kubernetes.lab.test")

	t.Run("runtime identity carries a token, never the bootstrap credential", func(t *testing.T) {
		run := &fakeRunner{out: healthyOutputs(api)}
		tb := &fakeTB{t: t}
		lab, kubeconfig := newTestLab(t, tb, run)
		var rt Runtime
		tb.play(func() {
			lab.Setup()
			rt = lab.Runtime()
		})
		if tb.fatal != "" {
			t.Fatalf("setup failed: %s", tb.fatal)
		}
		if rt.Token != fakeToken {
			t.Errorf("runtime token = %q, want the token the token sub-command printed (trimmed)", rt.Token)
		}
		if rt.Namespace != lab.Namespace || !strings.HasPrefix(rt.Namespace, "tagcess-k8s-lab-") {
			t.Errorf("runtime namespace = %q, lab namespace = %q", rt.Namespace, lab.Namespace)
		}
		if rt.Server != "https://"+api.addr || rt.CAPEM != api.pem {
			t.Errorf("runtime endpoint = %q, CA match = %v", rt.Server, rt.CAPEM == api.pem)
		}
		blob, _ := json.Marshal(rt)
		for _, bad := range []string{bootstrapMarker, kubeconfig} {
			if strings.Contains(string(blob), bad) {
				t.Errorf("runtime identity contains bootstrap material %q", bad)
			}
		}
		// The bootstrap kubeconfig is only ever handed to lab.sh through KUBECONFIG, and every
		// lab.sh call gets exactly it.
		for _, c := range run.calls {
			if !slices.Contains(c.env, "KUBECONFIG="+kubeconfig) {
				t.Errorf("call %v has no bootstrap KUBECONFIG", c.args)
			}
			for _, a := range c.args {
				if strings.Contains(a, kubeconfig) || strings.Contains(a, fakeToken) {
					t.Errorf("credential travelled in the argument list of %v", c.args)
				}
			}
		}
		// The token is issued for the runtime ServiceAccount of this run, not for the admin.
		tokens := run.called("token")
		if len(tokens) != 1 || len(tokens[0].args) != 2 || tokens[0].args[1] != lab.RunID {
			t.Fatalf("token calls = %v", tokens)
		}
	})

	t.Run("setup passes the preflight class to the fixture Ingress", func(t *testing.T) {
		run := &fakeRunner{out: healthyOutputs(api)}
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, run)
		tb.play(lab.Setup)
		ups := run.called("up")
		if len(ups) != 1 || !slices.Equal(ups[0].args, []string{"up", lab.RunID, "traefik"}) {
			t.Fatalf("up calls = %v", ups)
		}
		if tb.fatal != "" || len(tb.errors) != 0 {
			t.Errorf("fatal=%q errors=%v", tb.fatal, tb.errors)
		}
	})

	t.Run("a mismatched profile creates nothing", func(t *testing.T) {
		out := healthyOutputs(api)
		out["ingressclasses"] = classesJSON(classJSON("nginx", "k8s.io/ingress-nginx"))
		run := &fakeRunner{out: out}
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, run)
		tb.play(lab.Setup)
		if tb.fatal == "" {
			t.Fatal("setup must fail on a profile mismatch")
		}
		if len(run.called("up")) != 0 {
			t.Error("fixture was created although the profile does not match")
		}
	})

	t.Run("lab.sh up prepares a read-only SA in its own namespace", func(t *testing.T) {
		docs := runScriptUp(t, "abc123", "traefik")
		runNS := "tagcess-k8s-lab-abc123"
		byKind := map[string][]map[string]any{}
		for _, d := range docs {
			kind := str(d["kind"])
			byKind[kind] = append(byKind[kind], d)
			md := d["metadata"].(map[string]any)
			labels, _ := md["labels"].(map[string]any)
			if labels["tagcess.io/k8s-lab"] != "abc123" {
				t.Errorf("%s %v is not labelled with the run id", kind, md["name"])
			}
			if ns, ok := md["namespace"]; ok && ns != runNS {
				t.Errorf("%s %v is in namespace %v, want %s", kind, md["name"], ns, runNS)
			}
		}
		for _, kind := range []string{"Namespace", "ResourceQuota", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Service", "Ingress"} {
			if len(byKind[kind]) != 1 {
				t.Errorf("%s objects = %d, want 1", kind, len(byKind[kind]))
			}
		}
		if byKind["Namespace"][0]["metadata"].(map[string]any)["name"] != runNS {
			t.Errorf("namespace name = %v", byKind["Namespace"][0]["metadata"])
		}
		assertReadOnlyRules(t, byKind["Role"][0], map[string]bool{"ingresses": true, "services": true})
		assertReadOnlyRules(t, byKind["ClusterRole"][0], map[string]bool{"ingressclasses": true})
		for _, kind := range []string{"RoleBinding", "ClusterRoleBinding"} {
			subjects := byKind[kind][0]["subjects"].([]any)
			if len(subjects) != 1 {
				t.Fatalf("%s subjects = %v", kind, subjects)
			}
			s := subjects[0].(map[string]any)
			if s["kind"] != "ServiceAccount" || s["name"] != "tagcess-reader" || s["namespace"] != runNS {
				t.Errorf("%s subject = %v, want only the lab ServiceAccount", kind, s)
			}
		}
		ing := byKind["Ingress"][0]["spec"].(map[string]any)
		if ing["ingressClassName"] != "traefik" {
			t.Errorf("Ingress class = %v", ing["ingressClassName"])
		}
	})
}

func assertReadOnlyRules(t *testing.T, role map[string]any, wantResources map[string]bool) {
	t.Helper()
	rules, _ := role["rules"].([]any)
	if len(rules) == 0 {
		t.Fatalf("%s has no rules", str(role["kind"]))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		rule := r.(map[string]any)
		for _, v := range rule["verbs"].([]any) {
			if v != "get" && v != "list" {
				t.Errorf("%s grants verb %v", role["kind"], v)
			}
		}
		for _, res := range rule["resources"].([]any) {
			seen[res.(string)] = true
			if !wantResources[res.(string)] {
				t.Errorf("%s grants resource %v", role["kind"], res)
			}
		}
	}
	for r := range wantResources {
		if !seen[r] {
			t.Errorf("%s does not cover %s", role["kind"], r)
		}
	}
}

func str(v any) string { s, _ := v.(string); return s }

// ---- AC3 ------------------------------------------------------------------------------------

func TestK8sLabCleanupOnSuccessAndFailure(t *testing.T) {
	api := startLabAPI(t, "kubernetes.lab.test")

	tests := []struct {
		name       string
		out        func(map[string]string)
		errs       map[string]error
		body       func(lab *Lab)
		wantFatal  bool
		wantPanic  bool
		wantErrors int // cleanup failures reported on the test
	}{
		{name: "success", body: func(lab *Lab) { lab.Setup() }},
		{name: "test body fails", body: func(lab *Lab) { lab.Setup(); lab.tb.Fatalf("body failed") }, wantFatal: true},
		{name: "test body panics", body: func(lab *Lab) { lab.Setup(); panic("boom") }, wantPanic: true},
		{
			name: "setup fails half way", errs: map[string]error{"up": errors.New("apply failed")},
			body: func(lab *Lab) { lab.Setup() }, wantFatal: true,
		},
		{
			name: "objects left behind", out: func(o map[string]string) { o["leftovers"] = "namespace/tagcess-k8s-lab-x\n" },
			body: func(lab *Lab) { lab.Setup() }, wantErrors: 1,
		},
		{
			name: "down fails", errs: map[string]error{"down": errors.New("delete denied")},
			body: func(lab *Lab) { lab.Setup() }, wantErrors: 1,
		},
		{
			name: "leftovers cannot be listed", errs: map[string]error{"leftovers": errors.New("api down")},
			body: func(lab *Lab) { lab.Setup() }, wantErrors: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := healthyOutputs(api)
			if tc.out != nil {
				tc.out(out)
			}
			run := &fakeRunner{out: out, err: tc.errs}
			tb := &fakeTB{t: t}
			lab, _ := newTestLab(t, tb, run)
			panicked := tb.play(func() { tc.body(lab) })

			if (tb.fatal != "") != tc.wantFatal {
				t.Errorf("fatal = %q, wantFatal %v", tb.fatal, tc.wantFatal)
			}
			if (panicked != nil) != tc.wantPanic {
				t.Errorf("panic = %v, wantPanic %v", panicked, tc.wantPanic)
			}
			downs := run.called("down")
			if len(downs) != 1 || downs[0].args[1] != lab.RunID {
				t.Fatalf("down calls = %v, want exactly one for run %s", downs, lab.RunID)
			}
			// leftovers are checked after the delete, never before.
			order := []string{}
			for _, c := range run.calls {
				if c.args[0] == "down" || c.args[0] == "leftovers" {
					order = append(order, c.args[0])
				}
			}
			if !slices.Equal(order, []string{"down", "leftovers"}) {
				t.Errorf("cleanup order = %v, want down then leftovers", order)
			}
			if len(tb.errors) != tc.wantErrors {
				t.Errorf("cleanup errors = %v, want %d", tb.errors, tc.wantErrors)
			}
		})
	}

	t.Run("cleanup is registered before anything is created", func(t *testing.T) {
		out := healthyOutputs(api)
		run := &fakeRunner{out: out, err: map[string]error{"up": errors.New("boom")}}
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, run)
		tb.play(lab.Setup)
		if len(run.called("down")) != 1 {
			t.Fatalf("a failed up must still be cleaned up, calls = %v", run.calls)
		}
	})
}

// TestK8sLabCleanupOnSuccessAndFailure_script checks the cleanup contract of lab.sh itself with a
// fake kubectl: only the run's own objects are deleted, and only when they carry the run label.
func TestK8sLabCleanupOnSuccessAndFailure_script(t *testing.T) {
	t.Run("deletes by label and its own namespace", func(t *testing.T) {
		res := runScript(t, scriptEnv{nsOut: "tagcess-k8s-lab-abc123 abc123"}, "down", "abc123")
		if res.err != nil {
			t.Fatalf("down failed: %v\n%s", res.err, res.out)
		}
		log := res.log
		wantCR := "delete clusterrolebinding,clusterrole -l tagcess.io/k8s-lab=abc123 --ignore-not-found"
		if !strings.Contains(log, wantCR) {
			t.Errorf("no label-scoped RBAC delete in:\n%s", log)
		}
		if !strings.Contains(log, "delete namespace tagcess-k8s-lab-abc123 ") {
			t.Errorf("own namespace was not deleted:\n%s", log)
		}
		for _, line := range strings.Split(log, "\n") {
			if strings.HasPrefix(line, "delete ") &&
				!strings.Contains(line, "tagcess.io/k8s-lab=abc123") && !strings.Contains(line, "tagcess-k8s-lab-abc123") {
				t.Errorf("unscoped delete: %s", line)
			}
		}
	})

	t.Run("refuses a namespace that is not labelled for this run", func(t *testing.T) {
		for _, nsOut := range []string{"tagcess-k8s-lab-abc123", "tagcess-k8s-lab-abc123 someone-else"} {
			res := runScript(t, scriptEnv{nsOut: nsOut}, "down", "abc123")
			if res.err == nil {
				t.Errorf("down with namespace %q succeeded", nsOut)
			}
			if strings.Contains(res.log, "delete namespace") {
				t.Errorf("foreign namespace was deleted:\n%s", res.log)
			}
		}
	})

	t.Run("a namespace that is already gone is fine", func(t *testing.T) {
		res := runScript(t, scriptEnv{}, "down", "abc123")
		if res.err != nil {
			t.Fatalf("down failed: %v\n%s", res.err, res.out)
		}
	})

	t.Run("run id is validated before kubectl is called", func(t *testing.T) {
		for _, id := range []string{"", "ABC", "a b", "../x", "abc123;rm", "kube-system", "ab"} {
			for _, sub := range []string{"up", "down", "leftovers", "token"} {
				res := runScript(t, scriptEnv{}, sub, id)
				if res.err == nil {
					t.Errorf("%s %q succeeded", sub, id)
				}
				if res.log != "" {
					t.Errorf("%s %q reached kubectl:\n%s", sub, id, res.log)
				}
			}
		}
	})

	t.Run("leftovers lists the run's objects only", func(t *testing.T) {
		res := runScript(t, scriptEnv{leftovers: "namespace/tagcess-k8s-lab-abc123\n"}, "leftovers", "abc123")
		if res.err != nil {
			t.Fatalf("leftovers failed: %v\n%s", res.err, res.out)
		}
		if strings.TrimSpace(res.out) != "namespace/tagcess-k8s-lab-abc123" {
			t.Errorf("leftovers output = %q", res.out)
		}
		if !strings.Contains(res.log, "get namespace,clusterrole,clusterrolebinding -l tagcess.io/k8s-lab=abc123 -o name") {
			t.Errorf("leftovers is not label-scoped:\n%s", res.log)
		}
	})

	t.Run("token is requested for the lab ServiceAccount only", func(t *testing.T) {
		res := runScript(t, scriptEnv{}, "token", "abc123")
		if res.err != nil {
			t.Fatalf("token failed: %v\n%s", res.err, res.out)
		}
		if !strings.Contains(res.log, "create token tagcess-reader -n tagcess-k8s-lab-abc123 --duration=") {
			t.Errorf("token request = \n%s", res.log)
		}
		if strings.Contains(res.log, "--token") {
			t.Errorf("a token was passed to kubectl:\n%s", res.log)
		}
	})

	t.Run("kubeconfig is required", func(t *testing.T) {
		res := runScript(t, scriptEnv{noKubeconfig: true}, "leftovers", "abc123")
		if res.err == nil || res.log != "" {
			t.Errorf("script ran without a kubeconfig: err=%v log=%q", res.err, res.log)
		}
	})
}

// ---- script harness -------------------------------------------------------------------------

type scriptEnv struct {
	nsOut        string // answer to `get namespace <ns> -o jsonpath=...`
	leftovers    string
	noKubeconfig bool
	noContext    bool
	version      string // answer to `version -o json`; default is a k3s server
}

type scriptResult struct {
	out   string // stdout
	ctxs  string // context of every kubectl call, one per line ("NOCONTEXT ..." when it had none)
	log   string // one line per kubectl call
	stdin string // what the last `kubectl apply -f -` read
	err   error
}

const fakeKubectl = `#!/usr/bin/env bash
if [ "$1" = "--context" ]; then
  printf '%s\n' "$2" >> "$FAKE_CTX"
  shift 2
else
  printf 'NOCONTEXT %s\n' "$*" >> "$FAKE_CTX"
fi
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$*" in
  "version -o json") printf '%s' "${FAKE_VERSION:-{\"serverVersion\":{\"gitVersion\":\"v1.99.1+k3s1\"}}}" ;;
  "apply -f -"*) cat > "$FAKE_STDIN" ;;
  "create token"*) echo "fake-token" ;;
  "get namespace tagcess-k8s-lab-"*) printf '%s' "$FAKE_NS_OUT" ;;
  "get namespace,clusterrole,clusterrolebinding"*) printf '%s' "$FAKE_LEFTOVERS" ;;
esac
exit 0
`

func runScript(t *testing.T, env scriptEnv, args ...string) scriptResult {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(fakeKubectl), 0o700); err != nil {
		t.Fatal(err)
	}
	logPath, stdinPath := filepath.Join(dir, "log"), filepath.Join(dir, "stdin")
	kubeconfig := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "bash", append([]string{"lab.sh"}, args...)...)
	cmd.Env = []string{
		"PATH=" + dir + ":" + os.Getenv("PATH"),
		"FAKE_LOG=" + logPath, "FAKE_STDIN=" + stdinPath,
		"FAKE_NS_OUT=" + env.nsOut, "FAKE_LEFTOVERS=" + env.leftovers,
		"FAKE_CTX=" + filepath.Join(dir, "ctx"),
	}
	if env.version != "" {
		cmd.Env = append(cmd.Env, "FAKE_VERSION="+env.version)
	}
	if !env.noContext {
		cmd.Env = append(cmd.Env, "TAGCESS_K8S_LAB_CONTEXT=lab-k3s")
	}
	if !env.noKubeconfig {
		cmd.Env = append(cmd.Env, "KUBECONFIG="+kubeconfig)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	logData, _ := os.ReadFile(logPath)
	stdinData, _ := os.ReadFile(stdinPath)
	ctxData, _ := os.ReadFile(filepath.Join(dir, "ctx"))
	return scriptResult{out: stdout.String(), ctxs: string(ctxData), log: string(logData), stdin: string(stdinData), err: err}
}

func runScriptUp(t *testing.T, run, class string) []map[string]any {
	t.Helper()
	res := runScript(t, scriptEnv{}, "up", run, class)
	if res.err != nil {
		t.Fatalf("up failed: %v\n%s", res.err, res.out)
	}
	dec := yaml.NewDecoder(strings.NewReader(res.stdin))
	var docs []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("manifest is not YAML: %v\n%s", err, res.stdin)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	for _, bad := range []string{"secrets", `"*"`, "'*'", "- \"*\"", "create", "delete", "update", "patch"} {
		if strings.Contains(res.stdin, bad) {
			t.Errorf("manifest contains %q", bad)
		}
	}
	return docs
}

func base64Of(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// B-H-1: the lab never writes to a cluster that is not clearly the personal k3s. An RKE2 server
// (k8s-host) stops the preflight before any further kubectl call and before `up`.
func TestK8sLabRefusesNonK3sCluster(t *testing.T) {
	api := startLabAPI(t, "kubernetes.lab.test")
	t.Run("rke2 never reaches up", func(t *testing.T) {
		out := healthyOutputs(api)
		out["version"] = versionJSON("v1.36.4+rke2r1")
		run := &fakeRunner{out: out}
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, run)
		tb.play(func() { lab.Setup() })
		if tb.fatal == "" || !strings.Contains(tb.fatal, "k3s") {
			t.Fatalf("fatal = %q, want a refusal that names k3s", tb.fatal)
		}
		for _, sub := range []string{"up", "ingressclasses", "traefik", "server", "ca"} {
			if n := len(run.called(sub)); n != 0 {
				t.Errorf("%s was called %d times against a non-k3s cluster", sub, n)
			}
		}
	})
	t.Run("positive control: k3s passes", func(t *testing.T) {
		run := &fakeRunner{out: healthyOutputs(api)}
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, run)
		tb.play(func() { lab.Setup() })
		if tb.fatal != "" || len(run.called("up")) != 1 {
			t.Fatalf("k3s lab failed: fatal=%q up=%d", tb.fatal, len(run.called("up")))
		}
	})
	t.Run("the context reaches lab.sh", func(t *testing.T) {
		run := &fakeRunner{out: healthyOutputs(api)}
		tb := &fakeTB{t: t}
		lab, _ := newTestLab(t, tb, run)
		tb.play(func() { lab.Setup() })
		for _, c := range run.calls {
			if !slices.Contains(c.env, EnvContext+"=lab-k3s") {
				t.Errorf("%s ran without the lab context: %v", c.args[0], c.env)
			}
		}
	})
}

// B-H-1 / C-L12: lab.sh repeats the k3s check for every write sub-command and names the context on
// every kubectl call.
func TestK8sLabScriptGuard(t *testing.T) {
	writers := [][]string{{"up", "abc123", "traefik"}, {"token", "abc123"}, {"revoke", "abc123"}, {"conflict", "abc123", "traefik"}, {"down", "abc123"}}
	rke2 := `{"serverVersion":{"gitVersion":"v1.36.4+rke2r1"}}`
	for _, args := range writers {
		t.Run(args[0]+" refuses non-k3s", func(t *testing.T) {
			res := runScript(t, scriptEnv{version: rke2}, args...)
			if res.err == nil {
				t.Fatalf("%v succeeded against an rke2 server", args)
			}
			for _, line := range strings.Split(res.log, "\n") {
				if line != "" && line != "version -o json" {
					t.Errorf("kubectl was called after the refusal: %q", line)
				}
			}
		})
		t.Run(args[0]+" passes on k3s with the context on every call", func(t *testing.T) {
			res := runScript(t, scriptEnv{nsOut: "tagcess-k8s-lab-abc123 abc123"}, args...)
			if res.err != nil {
				t.Fatalf("%v failed: %v", args, res.err)
			}
			for _, line := range strings.Split(strings.TrimSpace(res.ctxs), "\n") {
				if line != "lab-k3s" {
					t.Errorf("kubectl call with context %q, want lab-k3s", line)
				}
			}
			if strings.TrimSpace(res.ctxs) == "" {
				t.Error("no kubectl call recorded")
			}
		})
	}
	t.Run("the context is required", func(t *testing.T) {
		res := runScript(t, scriptEnv{noContext: true}, "down", "abc123")
		if res.err == nil || res.log != "" {
			t.Errorf("script ran without a context: err=%v log=%q", res.err, res.log)
		}
	})
}
