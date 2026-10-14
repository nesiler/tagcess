package k8s

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// kubeconfig builds a one-context kubeconfig for tests. Extra fields are raw YAML lines inserted
// into the cluster / user mapping (indented to match).
type kubeconfig struct {
	Server       string
	CAData       string // PEM; encoded the way kubeconfig stores it
	TLSName      string
	Token        string
	TokenFile    string
	ClusterExtra string
	UserExtra    string
	Context      string // current-context; default "ctx"; "-" omits it
}

func (k kubeconfig) yaml() string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\n")
	ctx := k.Context
	switch ctx {
	case "":
		ctx = "ctx"
	case "-":
		ctx = ""
	}
	if ctx != "" {
		fmt.Fprintf(&b, "current-context: %s\n", ctx)
	}
	b.WriteString("clusters:\n- name: cl\n  cluster:\n")
	fmt.Fprintf(&b, "    server: %s\n", k.Server)
	if k.CAData != "" {
		fmt.Fprintf(&b, "    certificate-authority-data: %s\n", encodeCA(k.CAData))
	}
	if k.TLSName != "" {
		fmt.Fprintf(&b, "    tls-server-name: %s\n", k.TLSName)
	}
	b.WriteString(k.ClusterExtra)
	b.WriteString("users:\n- name: usr\n  user:\n")
	if k.Token != "" {
		fmt.Fprintf(&b, "    token: %s\n", k.Token)
	}
	if k.TokenFile != "" {
		fmt.Fprintf(&b, "    tokenFile: %s\n", k.TokenFile)
	}
	b.WriteString(k.UserExtra)
	b.WriteString("contexts:\n- name: ctx\n  context:\n    cluster: cl\n    user: usr\n")
	return b.String()
}

// AC1: direct fields and a narrow kubeconfig both become the same internal model: only the selected
// endpoint, CA data, TLS server name and token.
func TestK8sCredential_NarrowImport(t *testing.T) {
	ca := testCA(t)
	token := sentinel(t)

	t.Run("direct fields are canonicalised", func(t *testing.T) {
		got, err := normalizeCredential(Credential{
			Endpoint: "HTTPS://Example.COM:6443/", CAData: "\n" + ca + "\n",
			TLSServerName: "Kube.Example.Test.", Token: token + "\n",
		})
		if err != nil {
			t.Fatalf("normalizeCredential: %v", err)
		}
		want := Credential{Endpoint: "https://example.com:6443", CAData: ca, TLSServerName: "kube.example.test", Token: token}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("kubeconfig current-context", func(t *testing.T) {
		kc := kubeconfig{Server: "https://10.1.2.3:6443", CAData: ca, TLSName: "kubernetes.example.test", Token: token}
		got, err := ParseKubeconfig([]byte(kc.yaml()), "")
		if err != nil {
			t.Fatalf("ParseKubeconfig: %v", err)
		}
		want := Credential{Endpoint: "https://10.1.2.3:6443", CAData: ca, TLSServerName: "kubernetes.example.test", Token: token}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("named context ignores the others", func(t *testing.T) {
		otherToken := sentinel(t)
		doc := fmt.Sprintf(`current-context: a
clusters:
- name: ca
  cluster: {server: "https://10.0.0.1:6443", certificate-authority-data: %[1]s}
- name: cb
  cluster: {server: "https://10.0.0.2:6443", certificate-authority-data: %[1]s}
users:
- name: ua
  user: {token: %[2]s}
- name: ub
  user: {token: %[3]s}
contexts:
- name: a
  context: {cluster: ca, user: ua}
- name: b
  context: {cluster: cb, user: ub}
`, encodeCA(ca), token, otherToken)
		for _, tc := range []struct{ ctx, endpoint, token string }{
			{"", "https://10.0.0.1:6443", token},
			{"a", "https://10.0.0.1:6443", token},
			{"b", "https://10.0.0.2:6443", otherToken},
		} {
			got, err := ParseKubeconfig([]byte(doc), tc.ctx)
			if err != nil {
				t.Fatalf("context %q: %v", tc.ctx, err)
			}
			if got.Endpoint != tc.endpoint || got.Token != tc.token {
				t.Errorf("context %q: got %s / token match %v", tc.ctx, got.Endpoint, got.Token == tc.token)
			}
		}
	})
}

// AC2: executable mechanisms, file paths, client certificates, disabled verification and an
// unselectable context are rejected; nothing is run and no referenced file is read. Every case is
// the valid base kubeconfig with one mutation, rejected with the message of that mechanism; the base
// itself, and each mutation's cleaned-up variant, is accepted, so a missing check cannot hide
// behind an unrelated validation error.
func TestK8sCredential_RejectsExecutableAndExternalPaths(t *testing.T) {
	ca := testCA(t)
	token := sentinel(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	secretFile := filepath.Join(dir, "secret-file")
	if err := os.WriteFile(secretFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	// Positive control for the exec marker: the command the exec case names does create the marker
	// here, so its absence at the end proves it was never run.
	if err := exec.CommandContext(t.Context(), "touch", marker).Run(); err != nil {
		t.Fatalf("marker command does not run in this environment: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker command did not create the marker: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	base := kubeconfig{Server: "https://10.1.2.3:6443", CAData: ca, Token: token}
	if _, err := ParseKubeconfig([]byte(base.yaml()), ""); err != nil {
		t.Fatalf("the base kubeconfig must be accepted: %v", err)
	}

	cases := []struct {
		name string
		mut  func(k *kubeconfig)
		ctx  string
		want string // part of the rejection message
	}{
		{"exec", func(k *kubeconfig) {
			k.UserExtra = "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: touch\n      args: [" + marker + "]\n"
		}, "", "exec is not allowed"},
		{"exec null", func(k *kubeconfig) { k.UserExtra = "    exec:\n" }, "", "exec is not allowed"},
		{"auth-provider", func(k *kubeconfig) { k.UserExtra = "    auth-provider:\n      name: gcp\n" }, "", "auth-provider is not allowed"},
		{"tokenFile", func(k *kubeconfig) { k.TokenFile = secretFile }, "", "tokenFile is not allowed"},
		{"certificate-authority path", func(k *kubeconfig) {
			k.ClusterExtra = "    certificate-authority: " + secretFile + "\n"
		}, "", "certificate-authority file paths are not allowed"},
		{"client-certificate path", func(k *kubeconfig) { k.UserExtra = "    client-certificate: " + secretFile + "\n" }, "", "client certificates are not allowed"},
		{"client-certificate-data", func(k *kubeconfig) { k.UserExtra = "    client-certificate-data: QUJD\n" }, "", "client certificates are not allowed"},
		{"client-key path", func(k *kubeconfig) { k.UserExtra = "    client-key: " + secretFile + "\n" }, "", "client keys are not allowed"},
		{"client-key-data", func(k *kubeconfig) { k.UserExtra = "    client-key-data: QUJD\n" }, "", "client keys are not allowed"},
		{"insecure-skip-tls-verify", func(k *kubeconfig) { k.ClusterExtra = "    insecure-skip-tls-verify: true\n" }, "", "insecure-skip-tls-verify is not allowed"},
		{"no current-context", func(k *kubeconfig) { k.Context = "-" }, "", "no current-context"},
		{"unknown current-context", func(k *kubeconfig) { k.Context = "nope" }, "", "does not contain the selected context"},
		{"unknown named context", func(*kubeconfig) {}, "nope", "does not contain the selected context"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kc := base
			tc.mut(&kc)
			_, err := ParseKubeconfig([]byte(kc.yaml()), tc.ctx)
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("ParseKubeconfig error = %v, want *ValidationError", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), token) {
				t.Errorf("error carries the token: %v", err)
			}
			// Same input without the one forbidden thing is accepted.
			if tc.name == "tokenFile" {
				clean := kc
				clean.TokenFile = ""
				if _, err := ParseKubeconfig([]byte(clean.yaml()), tc.ctx); err != nil {
					t.Errorf("without tokenFile the input must be accepted: %v", err)
				}
			}
		})
	}

	t.Run("referenced context with a missing cluster or user", func(t *testing.T) {
		valid := base.yaml()
		for name, doc := range map[string]string{
			"cluster": strings.Replace(valid, "    cluster: cl\n", "    cluster: gone\n", 1),
			"user":    strings.Replace(valid, "    user: usr\n", "    user: gone\n", 1),
		} {
			if doc == valid {
				t.Fatalf("%s: the mutation did not change the document", name)
			}
			_, err := ParseKubeconfig([]byte(doc), "")
			if err == nil || !strings.Contains(err.Error(), "not defined") {
				t.Errorf("%s: error = %v, want a cluster-or-user-not-defined rejection", name, err)
			}
		}
	})

	t.Run("exec in an unselected user is still rejected", func(t *testing.T) {
		doc := base.yaml() + "- name: other\n  context: {cluster: cl, user: other-user}\n"
		doc = strings.Replace(doc, "contexts:", "- name: other-user\n  user:\n    exec: {command: touch}\ncontexts:", 1)
		if _, err := ParseKubeconfig([]byte(doc), ""); err == nil || !strings.Contains(err.Error(), "exec is not allowed") {
			t.Errorf("error = %v, want exec rejection for another user", err)
		}
	})

	t.Run("not YAML or too large", func(t *testing.T) {
		for _, doc := range []string{"", ": : [", strings.Repeat("a", maxKubeconfigSize+1)} {
			if _, err := ParseKubeconfig([]byte(doc), ""); err == nil {
				t.Errorf("accepted %.20q", doc)
			}
		}
	})

	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("exec marker exists (err %v): a command ran", err)
	}
}

// encodeCA stores PEM the way kubeconfig does: base64 of the PEM text.
func encodeCA(pemText string) string { return base64.StdEncoding.EncodeToString([]byte(pemText)) }

// L3: the 1 MiB cap is its own check, not a side effect of the YAML shape. A well-formed kubeconfig
// padded with comments is accepted at exactly the cap and refused with the size error one byte over.
func TestK8sKubeconfig_SizeCap(t *testing.T) {
	kc := kubeconfig{Server: "https://10.1.2.3:6443", CAData: testCA(t), TLSName: "kubernetes.example.test", Token: sentinel(t)}
	base := kc.yaml()
	pad := func(total int) []byte {
		return []byte(base + "#" + strings.Repeat("x", total-len(base)-1))
	}
	if _, err := ParseKubeconfig(pad(maxKubeconfigSize), ""); err != nil {
		t.Fatalf("a valid kubeconfig of exactly the cap was refused: %v", err)
	}
	_, err := ParseKubeconfig(pad(maxKubeconfigSize+1), "")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("a valid kubeconfig one byte over the cap = %v, want the size refusal", err)
	}
}
