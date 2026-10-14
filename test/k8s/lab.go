package k8s

// The opt-in personal k3s test bed (F4-033). It prepares a disposable namespace with a fixture
// Ingress/Service and a read-only ServiceAccount through the bootstrap (admin) kubeconfig, records
// the cluster's real Kubernetes/Traefik profile, hands the tests a runtime identity that is a
// short-lived ServiceAccount token only, and removes everything it created, also when the test
// fails or panics. Lab only (ADR 0014, ADR 0030): it never touches production, and it changes no CRD,
// controller, issuer or firewall. The product itself never writes to Kubernetes; the writes here
// are the test tooling's, made with the bootstrap identity.
//
// lab.sh is a thin kubectl wrapper; the decisions (profile match, cleanup result) live in this file so
// they are unit-tested with a fake Runner and a fake kubectl, and the real cluster is only reached by the
// opt-in `integration` test (`make k8s-lab`).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

// Environment variables of the opt-in lab. Without them the lab test skips (it is never a PASS).
const (
	EnvOptIn         = "TAGCESS_K8S_LAB"                 // must be exactly "1"
	EnvKubeconfig    = "TAGCESS_K8S_LAB_KUBECONFIG"      // bootstrap (admin) kubeconfig of the personal k3s
	EnvContext       = "TAGCESS_K8S_LAB_CONTEXT"         // kubeconfig context of the personal k3s; passed as --context on every kubectl call
	EnvRecordDir     = "TAGCESS_K8S_LAB_RECORD_DIR"      // optional: where the nonsecret preflight record is written
	EnvTLSServerName = "TAGCESS_K8S_LAB_TLS_SERVER_NAME" // optional: API TLS server name when it differs from the endpoint host
)

// PreflightRecordFile is the nonsecret preflight record written into the record directory.
const PreflightRecordFile = "k8s-lab-preflight.json"

// LabTB is the part of testing.TB the lab uses; *testing.T satisfies it.
type LabTB interface {
	Helper()
	Cleanup(func())
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
	Logf(format string, args ...any)
}

// LabConfig is the lab's configuration. Kubeconfig is the bootstrap identity: it only ever reaches
// lab.sh through KUBECONFIG and is never part of Runtime.
type LabConfig struct {
	Kubeconfig    string
	Context       string
	RecordDir     string
	TLSServerName string
}

// RequireLab returns the configuration of the opt-in lab, or skips the test with an explicit reason
// when the opt-in or the kubeconfig is missing. The skip text says it is not a PASS, so the phase
// acceptance evidence cannot count it as one.
func RequireLab(tb LabTB, getenv func(string) string) LabConfig {
	tb.Helper()
	const skipPrefix = "k8s lab SKIPPED (not a PASS in acceptance evidence): "
	if getenv(EnvOptIn) != "1" {
		tb.Skipf("%sset %s=1 and %s to run it against the personal k3s", skipPrefix, EnvOptIn, EnvKubeconfig)
	}
	kubeconfig := getenv(EnvKubeconfig)
	if kubeconfig == "" {
		tb.Skipf("%s%s is not set", skipPrefix, EnvKubeconfig)
	}
	if info, err := os.Stat(kubeconfig); err != nil || info.IsDir() {
		tb.Skipf("%s%s does not point at a readable file", skipPrefix, EnvKubeconfig)
	}
	kctx := getenv(EnvContext)
	if kctx == "" {
		tb.Skipf("%s%s is not set (the lab never relies on the kubeconfig's current-context)", skipPrefix, EnvContext)
	}
	return LabConfig{
		Kubeconfig:    kubeconfig,
		Context:       kctx,
		RecordDir:     getenv(EnvRecordDir),
		TLSServerName: getenv(EnvTLSServerName),
	}
}

// Runner runs one lab.sh sub-command with the given extra environment and returns its stdout.
type Runner func(ctx context.Context, env []string, args ...string) (string, error)

// scriptRunner runs lab.sh next to this file. Only stderr goes into an error: stdout may be a token.
func scriptRunner(ctx context.Context, env []string, args ...string) (string, error) {
	_, file, _, _ := runtime.Caller(0)
	script := filepath.Join(filepath.Dir(file), "lab.sh")
	cmd := exec.CommandContext(ctx, "bash", append([]string{script}, args...)...) //nolint:gosec // lab-only helper; args come from this package
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("lab.sh %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Profile is the controller profile the lab must match. The first F4 profile is Traefik with a
// TLS listener (ADR 0030).
type Profile struct {
	Controller string
	Listener   string
}

// TraefikProfile is the single profile of the first trial.
var TraefikProfile = Profile{Controller: "traefik.io/ingress-controller", Listener: "websecure"}

// Preflight is the nonsecret record of what the cluster really is: versions, class, listeners and the
// API TLS prerequisites (CA fingerprint, server name, whether the CA verifies the name). It holds no
// credential and no certificate body.
type Preflight struct {
	KubernetesVersion  string   `json:"kubernetesVersion"`
	TraefikVersion     string   `json:"traefikVersion"`
	IngressClass       string   `json:"ingressClass"`
	Controller         string   `json:"controller"`
	Listeners          []string `json:"listeners"`
	APIServer          string   `json:"apiServer"`
	TLSServerName      string   `json:"tlsServerName"`
	CAFingerprint      string   `json:"caSha256"`
	ServerNameVerified bool     `json:"serverNameVerified"`
	ServerNameError    string   `json:"serverNameError,omitempty"`
}

// Check reports every way the preflight does not match the profile; nil means it matches.
func (p Preflight) Check(profile Profile) error {
	var errs []error
	if p.KubernetesVersion == "" {
		errs = append(errs, errors.New("unknown Kubernetes server version"))
	}
	if p.IngressClass == "" {
		errs = append(errs, fmt.Errorf("no IngressClass with controller %s", profile.Controller))
	}
	if p.TraefikVersion == "" {
		errs = append(errs, errors.New("no Traefik Deployment or image version found"))
	}
	if !slices.ContainsFunc(p.Listeners, func(l string) bool { return strings.HasPrefix(l, profile.Listener+"=") }) {
		errs = append(errs, fmt.Errorf("no Traefik %s listener (listeners: %v)", profile.Listener, p.Listeners))
	}
	if p.CAFingerprint == "" {
		errs = append(errs, errors.New("API CA unknown"))
	}
	if !p.ServerNameVerified {
		errs = append(errs, fmt.Errorf("API TLS server name %s is not verified by the cluster CA: %s", p.TLSServerName, p.ServerNameError))
	}
	return errors.Join(errs...)
}

// Runtime is the identity the tested tagcess reader gets: endpoint, CA and a short-lived token of the
// read-only ServiceAccount. It never carries the bootstrap kubeconfig or anything derived from it.
type Runtime struct {
	Server    string `json:"server"`
	CAPEM     string `json:"caPem"`
	Token     string `json:"token"`
	Namespace string `json:"namespace"`
}

// Lab is one disposable lab run: a namespace and temporary cluster-scope RBAC objects that all carry
// the run id label.
type Lab struct {
	Namespace string
	RunID     string

	tb  LabTB
	cfg LabConfig
	run Runner

	server string
	caPEM  string
	pre    *Preflight
}

// NewLab prepares a lab run. A nil run uses lab.sh. Nothing touches the cluster until Setup.
func NewLab(tb LabTB, cfg LabConfig, run Runner) *Lab {
	tb.Helper()
	if run == nil {
		run = scriptRunner
	}
	id := make([]byte, 4)
	if _, err := rand.Read(id); err != nil {
		tb.Fatalf("k8s lab: random run id: %v", err)
	}
	runID := hex.EncodeToString(id)
	return &Lab{Namespace: "tagcess-k8s-lab-" + runID, RunID: runID, tb: tb, cfg: cfg, run: run}
}

// env is the only place the bootstrap kubeconfig is handed out: to lab.sh, as KUBECONFIG.
func (l *Lab) env() []string {
	return []string{"KUBECONFIG=" + l.cfg.Kubeconfig, EnvContext + "=" + l.cfg.Context}
}

func (l *Lab) exec(ctx context.Context, args ...string) (string, error) {
	return l.run(ctx, l.env(), args...)
}

// Setup registers the cleanup first (so a half-created lab is removed too), checks the profile and
// creates the namespace, fixture and read-only identity. Any failure ends the test.
func (l *Lab) Setup() {
	l.tb.Helper()
	l.tb.Cleanup(l.cleanup)
	pf := l.RequirePreflight()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := l.exec(ctx, "up", l.RunID, pf.IngressClass); err != nil {
		l.tb.Fatalf("k8s lab: setup: %v", err)
	}
}

// RequirePreflight reads the cluster profile, records it and fails the test on a mismatch. The record
// is written before the check so a mismatch leaves its evidence.
func (l *Lab) RequirePreflight() Preflight {
	l.tb.Helper()
	pf, err := l.Preflight()
	if err != nil {
		l.tb.Fatalf("k8s lab: preflight: %v", err)
	}
	l.record(pf)
	if err := pf.Check(TraefikProfile); err != nil {
		l.tb.Fatalf("k8s lab: cluster does not match the Traefik profile: %v", err)
	}
	return pf
}

func (l *Lab) record(pf Preflight) {
	l.tb.Helper()
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		l.tb.Fatalf("k8s lab: encode preflight record: %v", err)
	}
	l.tb.Logf("k8s lab preflight (nonsecret): %s", data)
	if l.cfg.RecordDir == "" {
		return
	}
	if err := os.MkdirAll(l.cfg.RecordDir, 0o750); err != nil {
		l.tb.Fatalf("k8s lab: record dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(l.cfg.RecordDir, PreflightRecordFile), append(data, '\n'), 0o600); err != nil {
		l.tb.Fatalf("k8s lab: write preflight record: %v", err)
	}
}

// Preflight reads (only reads) the Kubernetes version, the Traefik class/version/listeners and the API
// TLS prerequisites with the bootstrap identity.
func (l *Lab) Preflight() (Preflight, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	get := func(sub string) (string, error) { return l.exec(ctx, sub) }

	var pf Preflight
	versionOut, err := get("version")
	if err != nil {
		return pf, err
	}
	var v struct {
		ServerVersion struct {
			GitVersion string `json:"gitVersion"`
		} `json:"serverVersion"`
	}
	if err := json.Unmarshal([]byte(versionOut), &v); err != nil {
		return pf, fmt.Errorf("decode version: %w", err)
	}
	pf.KubernetesVersion = v.ServerVersion.GitVersion
	// Production guard (rule 1): only the personal k3s is ever written to. Nothing else is asked of a
	// cluster whose server version is not a k3s one (k8s-host is RKE2).
	if !strings.Contains(pf.KubernetesVersion, "+k3s") {
		return pf, fmt.Errorf("refusing a cluster that is not clearly the personal k3s (server version %q has no +k3s)", pf.KubernetesVersion)
	}
	classesOut, err := get("ingressclasses")
	if err != nil {
		return pf, err
	}
	traefikOut, err := get("traefik")
	if err != nil {
		return pf, err
	}
	serverOut, err := get("server")
	if err != nil {
		return pf, err
	}
	caOut, err := get("ca")
	if err != nil {
		return pf, err
	}

	pf.IngressClass, pf.Controller, err = pickIngressClass(classesOut)
	if err != nil {
		return pf, err
	}
	pf.TraefikVersion, pf.Listeners, err = traefikFacts(traefikOut)
	if err != nil {
		return pf, err
	}

	caBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(caOut))
	if err != nil {
		return pf, fmt.Errorf("decode cluster CA: %w", err)
	}
	l.server, l.caPEM = strings.TrimSpace(serverOut), string(caBytes)
	if err := l.tlsFacts(&pf); err != nil {
		return pf, err
	}
	l.pre = &pf
	return pf, nil
}

// pickIngressClass returns the IngressClass of the Traefik controller, preferring the default class.
func pickIngressClass(out string) (name, controller string, err error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Controller string `json:"controller"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return "", "", fmt.Errorf("decode ingressclasses: %w", err)
	}
	best, bestDefault := -1, false
	for i, c := range list.Items {
		if c.Spec.Controller != TraefikProfile.Controller {
			continue
		}
		isDefault := c.Metadata.Annotations["ingressclass.kubernetes.io/is-default-class"] == "true"
		if best < 0 || (isDefault && !bestDefault) || (isDefault == bestDefault && c.Metadata.Name < list.Items[best].Metadata.Name) {
			best, bestDefault = i, isDefault
		}
	}
	if best < 0 {
		return "", "", nil
	}
	return list.Items[best].Metadata.Name, list.Items[best].Spec.Controller, nil
}

// traefikFacts returns the image tag and the entrypoints (name=address) of the first Traefik Deployment.
func traefikFacts(out string) (version string, listeners []string, err error) {
	var list struct {
		Items []struct {
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Image string   `json:"image"`
							Args  []string `json:"args"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return "", nil, fmt.Errorf("decode traefik deployments: %w", err)
	}
	for _, d := range list.Items {
		for _, c := range d.Spec.Template.Spec.Containers {
			if !strings.Contains(c.Image, "traefik") {
				continue
			}
			image, _, _ := strings.Cut(c.Image, "@")
			if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
				version = image[i+1:]
			}
			for _, a := range c.Args {
				rest, ok := strings.CutPrefix(a, "--entrypoints.")
				if !ok {
					continue
				}
				if name, addr, ok := strings.Cut(rest, ".address="); ok {
					listeners = append(listeners, name+"="+addr)
				}
			}
			sort.Strings(listeners)
			return version, listeners, nil
		}
	}
	return "", nil, nil
}

// tlsFacts fills the API endpoint, CA fingerprint and whether the CA verifies the TLS server name by
// handshaking with the API server. The handshake sends no credential.
func (l *Lab) tlsFacts(pf *Preflight) error {
	u, err := url.Parse(l.server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("cluster endpoint %q is not a URL", l.server)
	}
	hostPort := u.Host
	if u.Port() == "" {
		hostPort = net.JoinHostPort(u.Hostname(), "443")
	}
	pf.APIServer = u.Host
	pf.TLSServerName = l.cfg.TLSServerName
	if pf.TLSServerName == "" {
		pf.TLSServerName = u.Hostname()
	}

	block, _ := pem.Decode([]byte(l.caPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("cluster CA is not a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	pf.CAFingerprint = hex.EncodeToString(sum[:])
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(l.caPEM)) {
		return errors.New("cluster CA has no usable certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: pf.TLSServerName, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		pf.ServerNameError = err.Error()
		return nil
	}
	_ = conn.Close()
	pf.ServerNameVerified = true
	return nil
}

// Runtime issues the read-only ServiceAccount token and returns the identity the tested reader uses.
// Setup must have run.
func (l *Lab) Runtime() Runtime {
	l.tb.Helper()
	if l.pre == nil {
		l.tb.Fatalf("k8s lab: Runtime called before Setup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := l.exec(ctx, "token", l.RunID)
	if err != nil {
		l.tb.Fatalf("k8s lab: runtime token: %v", err)
	}
	token := strings.TrimSpace(out)
	if token == "" {
		l.tb.Fatalf("k8s lab: runtime token is empty")
	}
	return Runtime{Server: l.server, CAPEM: l.caPEM, Token: token, Namespace: l.Namespace}
}

// Revoke makes every token issued so far invalid (the API answers 401 for them), as an expired
// short-lived token would be; a real TokenRequest cannot be shorter than 10 minutes. Runtime() then
// issues a new, valid token. Setup must have run.
func (l *Lab) Revoke() {
	l.tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := l.exec(ctx, "revoke", l.RunID); err != nil {
		l.tb.Fatalf("k8s lab: revoke: %v", err)
	}
}

// AddConflict adds one fixture Ingress whose paths overlap with different backends; no controller
// winner is read, so the product must treat it as undecided. Setup must have run.
func (l *Lab) AddConflict() {
	l.tb.Helper()
	if l.pre == nil {
		l.tb.Fatalf("k8s lab: AddConflict called before Setup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := l.exec(ctx, "conflict", l.RunID, l.pre.IngressClass); err != nil {
		l.tb.Fatalf("k8s lab: conflict fixture: %v", err)
	}
}

// cleanup removes the run's own namespace and temporary cluster-scope RBAC, then lists what is left;
// anything left, or a command that failed, fails the test.
func (l *Lab) cleanup() {
	l.tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var errs []error
	if _, err := l.exec(ctx, "down", l.RunID); err != nil {
		errs = append(errs, err)
	}
	left, err := l.exec(ctx, "leftovers", l.RunID)
	switch {
	case err != nil:
		errs = append(errs, err)
	case strings.TrimSpace(left) != "":
		errs = append(errs, fmt.Errorf("objects left over: %s", strings.Join(strings.Fields(left), " ")))
	}
	if len(errs) > 0 {
		l.tb.Errorf("k8s lab: cleanup of run %s failed: %v", l.RunID, errors.Join(errs...))
	}
}
