// Package lab_test checks the static side of F1-024: the manifests, values and scripts that put the
// test Zitadel on the developer's k3s lab (namespace tagcess-lab). Nothing here talks to a
// cluster; the live side is the integration tests in test/compose run against the lab (`make lab-integration`).
package lab_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	labNS    = "tagcess-lab"
	labHost  = "tagcess-zitadel.lab.example.com" // the values file's placeholder host (lib.sh LAB_VALUES_HOST)
	pgImage  = "postgres:16.13-alpine"
	zitImage = "v4.16.0"
)

type doc = map[string]any

func decodeAll(t *testing.T, data []byte) []doc {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []doc
	for {
		var d doc
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			return docs
		}
		if err != nil {
			t.Fatalf("decode yaml: %v", err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
}

// at walks nested maps/lists by key or index and returns nil when the path does not exist.
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

func str(v any) string { s, _ := v.(string); return s }

func staticManifests(t *testing.T) []doc {
	t.Helper()
	files, err := filepath.Glob("*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no manifests in test/lab: %v", err)
	}
	var all []doc
	for _, f := range files {
		if f == "zitadel-values.yaml" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, decodeAll(t, data)...)
	}
	return all
}

// AC1
func TestLabManifests_NamespaceQuotaNoSecrets(t *testing.T) {
	docs := staticManifests(t)
	seen := map[string]bool{}
	secretName := regexp.MustCompile(`(?i)pass|secret|key|token`)
	for _, d := range docs {
		kind, name := str(d["kind"]), str(at(d, "metadata", "name"))
		seen[kind] = true
		// Only namespaced kinds (plus the Namespace itself): a cluster-scoped object would ignore the -n pin.
		switch kind {
		case "Namespace", "ResourceQuota", "LimitRange", "StatefulSet", "Service":
		default:
			// A Certificate is deliberately not allowed: the TLS Secret is a copy of the wildcard one (ADR 0014).
			t.Errorf("unexpected kind %q/%s among the lab manifests", kind, name)
		}
		if kind == "Secret" {
			t.Errorf("%s/%s: Secret in the repo; secrets are created at runtime by lab-up", kind, name)
		}
		if kind == "Namespace" {
			if name != labNS {
				t.Errorf("Namespace %q, want only %q", name, labNS)
			}
			continue
		}
		if ns := str(at(d, "metadata", "namespace")); ns != labNS {
			t.Errorf("%s/%s namespace = %q, want %q", kind, name, ns, labNS)
		}
		// Pod templates: every container has limits and no inline secret-looking env value.
		if kind != "StatefulSet" && kind != "Deployment" {
			continue
		}
		containers, _ := at(d, "spec", "template", "spec", "containers").([]any)
		if len(containers) == 0 {
			t.Errorf("%s/%s has no containers", kind, name)
		}
		for _, c := range containers {
			if at(c, "resources", "limits", "memory") == nil {
				t.Errorf("%s/%s container %v has no memory limit", kind, name, at(c, "name"))
			}
			envs, _ := at(c, "env").([]any)
			for _, e := range envs {
				if secretName.MatchString(str(at(e, "name"))) && at(e, "value") != nil {
					t.Errorf("%s/%s env %v has an inline value; use secretKeyRef", kind, name, at(e, "name"))
				}
			}
			if kind == "StatefulSet" && str(at(c, "image")) != pgImage {
				t.Errorf("postgres image = %q, want %q", str(at(c, "image")), pgImage)
			}
		}
	}
	for _, kind := range []string{"Namespace", "ResourceQuota", "LimitRange", "StatefulSet", "Service"} {
		if !seen[kind] {
			t.Errorf("no %s among the lab manifests", kind)
		}
	}
	for _, d := range docs {
		switch str(d["kind"]) {
		case "ResourceQuota":
			for _, k := range []string{"limits.memory", "requests.memory", "limits.cpu", "pods"} {
				if at(d, "spec", "hard", k) == nil {
					t.Errorf("ResourceQuota misses hard[%s]", k)
				}
			}
		case "LimitRange":
			if at(d, "spec", "limits", 0, "default", "memory") == nil || at(d, "spec", "limits", 0, "defaultRequest", "memory") == nil {
				t.Errorf("LimitRange must default memory limit and request so every pod is bounded")
			}
		}
	}
}

// AC1 (scripts): kubectl and helm are only ever called through the wrappers in lib.sh, which pin the
// namespace, so no script can write outside tagcess-lab.
func TestLabScripts_OnlyLabNamespace(t *testing.T) {
	lib, err := os.ReadFile("lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lib), `LAB_NS="`+labNS+`"`) {
		t.Errorf("lib.sh must define LAB_NS=%q as a constant", labNS)
	}
	if !regexp.MustCompile(`(?m)^k\(\) \{ kubectl .*-n "\$LAB_NS"`).Match(lib) || !regexp.MustCompile(`(?m)^h\(\) \{ helm .*--namespace "\$LAB_NS"`).Match(lib) {
		t.Errorf("lib.sh must define k() and h() wrappers that pin -n/--namespace \"$LAB_NS\"")
	}
	raw := regexp.MustCompile(`\b(kubectl|helm)\b`)
	for _, f := range []string{"up.sh", "down.sh"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "#") {
				continue
			}
			if raw.MatchString(l) && !strings.HasPrefix(l, "command -v") && !strings.Contains(l, "for tool in") {
				t.Errorf("%s:%d calls kubectl/helm directly; use k/h from lib.sh: %s", f, i+1, l)
			}
			if strings.Contains(l, "--all-namespaces") || regexp.MustCompile(`\s-A(\s|$)`).MatchString(l) {
				t.Errorf("%s:%d addresses all namespaces: %s", f, i+1, l)
			}
			if strings.Contains(l, "delete namespace") && !strings.Contains(l, `"$LAB_NS"`) {
				t.Errorf("%s:%d deletes a namespace other than $LAB_NS: %s", f, i+1, l)
			}
		}
	}
}

// AC3
func TestLabValues_Zitadel(t *testing.T) {
	data, err := os.ReadFile("zitadel-values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	docs := decodeAll(t, data)
	if len(docs) != 1 {
		t.Fatalf("want one values document, got %d", len(docs))
	}
	v := docs[0]
	cm := at(v, "zitadel", "configmapConfig")
	if str(at(cm, "ExternalDomain")) != labHost {
		t.Errorf("ExternalDomain = %v", at(cm, "ExternalDomain"))
	}
	if at(cm, "ExternalPort") != 443 {
		t.Errorf("ExternalPort = %v, want 443", at(cm, "ExternalPort"))
	}
	if at(cm, "ExternalSecure") != true {
		t.Errorf("ExternalSecure = %v, want true", at(cm, "ExternalSecure"))
	}
	if at(cm, "TLS", "Enabled") != false {
		t.Errorf("TLS.Enabled = %v, want false (TLS ends at Traefik)", at(cm, "TLS", "Enabled"))
	}
	if str(at(v, "image", "tag")) != zitImage {
		t.Errorf("image.tag = %v, want %s (chart 10.0.6 defaults to v4.15.3)", at(v, "image", "tag"), zitImage)
	}
	if str(at(v, "login", "image", "tag")) != zitImage {
		t.Errorf("login.image.tag = %v, want %s (the login image follows the Zitadel version)", at(v, "login", "image", "tag"), zitImage)
	}
	if at(cm, "FirstInstance", "Org", "Machine", "Pat") == nil {
		t.Errorf("FirstInstance machine user with a PAT is required (seed bootstrap)")
	}
	if exp := str(at(cm, "FirstInstance", "Org", "Machine", "Pat", "ExpirationDate")); exp == "" || exp >= "2027" {
		t.Errorf("PAT ExpirationDate = %q; an IAM_OWNER token must expire soon (before 2027)", exp)
	}
	if at(cm, "FirstInstance", "Org", "Human", "Password") != nil {
		t.Errorf("FirstInstance admin password from values does not work; do not set it")
	}
	if s := string(data); regexp.MustCompile(`(?i)masterkey:\s*\S{8}`).MatchString(s) {
		t.Errorf("masterkey value must not be in values; use masterkeySecretName")
	}
	if str(at(v, "zitadel", "masterkeySecretName")) == "" {
		t.Errorf("masterkeySecretName is required (Secret created at runtime)")
	}
	for _, ing := range [][]any{{"ingress"}, {"login", "ingress"}} {
		p := func(rest ...any) any { return at(v, append(append([]any{}, ing...), rest...)...) }
		if p("enabled") != true || str(p("className")) != "traefik" {
			t.Errorf("%v: enabled/className = %v/%v", ing, p("enabled"), p("className"))
		}
		if mw := p("annotations", "traefik.ingress.kubernetes.io/router.middlewares"); mw != nil {
			t.Errorf("%v has middleware %v; the lab ingress is a plain Ingress with TLS", ing, mw)
		}
		if str(p("annotations", "traefik.ingress.kubernetes.io/router.entrypoints")) != "websecure" {
			t.Errorf("%v must only serve on entrypoint websecure", ing)
		}
		if str(p("hosts", 0, "host")) != labHost {
			t.Errorf("%v host = %v", ing, p("hosts", 0, "host"))
		}
		if str(p("tls", 0, "secretName")) == "" {
			t.Errorf("%v has no tls secretName (the copied wildcard Secret)", ing)
		}
	}
	if str(at(v, "login", "ingress", "hosts", 0, "paths", 0, "path")) != "/ui/v2/login" {
		t.Errorf("Login v2 ingress path = %v", at(v, "login", "ingress", "hosts", 0, "paths", 0, "path"))
	}
	for _, k := range [][]any{{"resources", "limits", "memory"}, {"login", "resources", "limits", "memory"}, {"setupJob", "resources", "limits", "memory"}, {"initJob", "resources", "limits", "memory"}} {
		if at(v, k...) == nil {
			t.Errorf("values.%v is unset; every pod must be bounded", k)
		}
	}
	if str(at(v, "resources", "limits", "memory")) != "768Mi" {
		t.Errorf("zitadel memory limit = %v, want 768Mi", at(v, "resources", "limits", "memory"))
	}
}

// F1-025 / ADR 0014: no Certificate is ever requested, so Let's Encrypt limits cannot hit. lab-up copies the
// existing wildcard TLS Secret into tagcess-lab; the source is only read.
func TestLabTLS_WildcardCopyNoCertificate(t *testing.T) {
	if _, err := os.Stat("certificate.yaml"); err == nil {
		t.Errorf("certificate.yaml must not exist")
	}
	lib, err := os.ReadFile("lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("up.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(up), "copy_wildcard_tls") {
		t.Errorf("up.sh must call copy_wildcard_tls")
	}
	for _, f := range []string{"up.sh", "down.sh", "lib.sh", "zitadel-values.yaml"} {
		data, _ := os.ReadFile(f)
		if regexp.MustCompile(`(?i)cert-manager|clusterissuer|kind:\s*Certificate|certificate/`).Match(data) {
			t.Errorf("%s still refers to cert-manager or a Certificate", f)
		}
	}
	// Outside k() and h(), lib.sh may touch the cluster only to read nodes and the wildcard source Secret.
	for i, line := range strings.Split(string(lib), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") || !strings.Contains(l, "kubectl") || strings.HasPrefix(l, "k()") {
			continue
		}
		switch {
		case strings.Contains(l, "get nodes"):
		case strings.Contains(l, `-n default get secret "$WILDCARD_TLS_SECRET" `):
		default:
			t.Errorf("lib.sh:%d unexpected direct kubectl call: %s", i+1, l)
		}
		if regexp.MustCompile(`\b(create|apply|delete|patch|edit|replace|label|annotate)\b`).MatchString(l) {
			t.Errorf("lib.sh:%d writes with a direct kubectl call (only reads are allowed outside tagcess-lab): %s", i+1, l)
		}
	}
	if !strings.Contains(string(lib), `WILDCARD_TLS_SECRET="${TAGCESS_LAB_WILDCARD_TLS_SECRET:-wildcard-lab-tls}"`) || !strings.Contains(string(lib), `--dry-run=client`) {
		t.Errorf("lib.sh must copy wildcard-lab-tls through the namespace-pinned k() wrapper")
	}
}
