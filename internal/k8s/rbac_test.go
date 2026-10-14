package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	k8sfix "github.com/nesiler/tagcess/test/k8s"
)

var updateRBACGolden = flag.Bool("update", false, "rewrite the RBAC manifest golden file instead of comparing")

const (
	rbacGolden    = "../../test/k8s/rbac.yaml"
	ssarAPIPath   = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	netGroup      = "networking.k8s.io"
	testPrincipal = "system:serviceaccount:tagcess:tagcess-reader"
)

var reviewTime = time.Date(2026, 10, 4, 12, 30, 15, 700_000_000, time.UTC)

func reviewNow() time.Time { return reviewTime }

// fakeJWT is a service-account-shaped token: header.payload.signature with a sub claim. The
// signature is random bytes; nothing here is ever verified, as in the production code.
func fakeJWT(t *testing.T, sub string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	claims := map[string]any{
		"sub":                    sub,
		"iss":                    "https://kubernetes.default.svc",
		"kubernetes.io":          map[string]any{"pod": map[string]any{"name": "pod-claim-marker"}},
		"extra-claim-for-marker": "payload-claim-marker",
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc(payload) + "." + enc([]byte(sentinel(t)))
}

func acc(ns, group, resource, sub, verb string) k8sfix.Access {
	return k8sfix.Access{Namespace: ns, Group: group, Resource: resource, Subresource: sub, Verb: verb}
}

// wantRequired is the set of accesses the review must ask for and expect to be allowed.
func wantRequired(namespaces []string) []k8sfix.Access {
	var out []k8sfix.Access
	for _, ns := range namespaces {
		for _, verb := range []string{"get", "list"} {
			out = append(out, acc(ns, netGroup, "ingresses", "", verb), acc(ns, "", "services", "", verb))
		}
	}
	for _, verb := range []string{"get", "list"} {
		out = append(out, acc("", netGroup, "ingressclasses", "", verb))
	}
	return out
}

// wantForbidden is the set of accesses the review must ask for and expect to be denied. probes are
// the out-of-scope namespaces.
func wantForbidden(namespaces, probes []string) []k8sfix.Access {
	var out []k8sfix.Access
	for _, ns := range namespaces {
		out = append(out,
			acc(ns, "", "secrets", "", "get"), acc(ns, "", "secrets", "", "list"),
			acc(ns, "", "serviceaccounts", "token", "create"))
		for _, verb := range []string{"create", "update", "patch", "delete"} {
			out = append(out, acc(ns, netGroup, "ingresses", "", verb), acc(ns, "", "services", "", verb))
		}
	}
	for _, verb := range []string{"create", "update", "patch", "delete"} {
		out = append(out, acc("", netGroup, "ingressclasses", "", verb))
	}
	for _, p := range append(slices.Clone(probes), "") { // "" is all namespaces
		out = append(out, acc(p, netGroup, "ingresses", "", "list"), acc(p, "", "services", "", "list"))
	}
	return out
}

func sortedAccess(in []k8sfix.Access) []k8sfix.Access {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b k8sfix.Access) int {
		return strings.Compare(fmt.Sprintf("%+v", a), fmt.Sprintf("%+v", b))
	})
	return out
}

// rbacEnv is an API stand-in whose token is a service-account-shaped JWT.
func rbacEnv(t *testing.T, sub string) *apiEnv {
	t.Helper()
	e := newAPIEnv(t, envOpts{})
	e.token = fakeJWT(t, sub)
	return e
}

func (e *apiEnv) review(t *testing.T, namespaces []string) Review {
	t.Helper()
	r, err := ReviewPermissions(context.Background(), e.client(t, e.cred(), time.Second), namespaces, reviewNow)
	if err != nil {
		t.Fatalf("ReviewPermissions: %v", err)
	}
	return r
}

func manifestDocs(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var docs []map[string]any
	for {
		var d map[string]any
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			return docs
		}
		if err != nil {
			t.Fatalf("manifest is not valid YAML: %v", err)
		}
		docs = append(docs, d)
	}
}

// AC1: the install manifest is deterministic, narrow and secretless.
func TestK8sRBAC_ManifestGolden(t *testing.T) {
	sa := ServiceAccountRef{Namespace: "tagcess"}
	got, err := RBACManifest([]string{"web", "apps"}, sa)
	if err != nil {
		t.Fatalf("RBACManifest: %v", err)
	}

	if *updateRBACGolden {
		if err := os.WriteFile(rbacGolden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(rbacGolden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("manifest differs from %s (run with -update after reviewing the change):\n%s", rbacGolden, got)
	}

	t.Run("same input same bytes", func(t *testing.T) {
		for _, in := range [][]string{{"apps", "web"}, {"web", "apps"}} {
			again, err := RBACManifest(in, ServiceAccountRef{Namespace: "tagcess", Name: DefaultServiceAccountName})
			if err != nil || !bytes.Equal(again, got) {
				t.Errorf("RBACManifest(%v) = %v, same bytes %v", in, err, bytes.Equal(again, got))
			}
		}
	})

	t.Run("only narrow objects", func(t *testing.T) {
		docs := manifestDocs(t, got)
		kinds := map[string]int{}
		for _, d := range docs {
			kind, _ := d["kind"].(string)
			kinds[kind]++
			switch kind {
			case "ServiceAccount", "ClusterRoleBinding", "RoleBinding":
			case "ClusterRole":
				rules, _ := d["rules"].([]any)
				if len(rules) == 0 {
					t.Errorf("ClusterRole %v has no rules", d["metadata"])
				}
				for _, r := range rules {
					rule := r.(map[string]any)
					if !reflect.DeepEqual(rule["verbs"], []any{"get", "list"}) {
						t.Errorf("rule %v: verbs must be exactly get, list", rule)
					}
					if rule["resourceNames"] != nil || rule["nonResourceURLs"] != nil {
						t.Errorf("rule %v: unexpected scope fields", rule)
					}
				}
			default:
				t.Errorf("unexpected kind %q", kind)
			}
		}
		want := map[string]int{"ServiceAccount": 1, "ClusterRole": 2, "ClusterRoleBinding": 1, "RoleBinding": 2}
		if !reflect.DeepEqual(kinds, want) {
			t.Errorf("kinds = %v, want %v", kinds, want)
		}
		text := string(got)
		for _, bad := range []string{"*", "secrets", "tokenRequest", "serviceaccounts/token", "Secret\n", "\ntoken", "cluster-admin", "view\n"} {
			if strings.Contains(text, bad) {
				t.Errorf("manifest contains %q", bad)
			}
		}
	})

	t.Run("bindings are namespace-scoped and name the service account", func(t *testing.T) {
		var roleBindingNS []string
		for _, d := range manifestDocs(t, got) {
			kind, _ := d["kind"].(string)
			if kind != "RoleBinding" && kind != "ClusterRoleBinding" {
				continue
			}
			subjects := d["subjects"].([]any)
			s := subjects[0].(map[string]any)
			if len(subjects) != 1 || s["kind"] != "ServiceAccount" || s["name"] != DefaultServiceAccountName || s["namespace"] != "tagcess" {
				t.Errorf("%s subjects = %v", kind, subjects)
			}
			if ref := d["roleRef"].(map[string]any); ref["kind"] != "ClusterRole" {
				t.Errorf("%s roleRef = %v", kind, ref)
			}
			if kind == "RoleBinding" {
				roleBindingNS = append(roleBindingNS, d["metadata"].(map[string]any)["namespace"].(string))
			}
		}
		if !slices.Equal(roleBindingNS, []string{"apps", "web"}) {
			t.Errorf("RoleBinding namespaces = %v, want [apps web]", roleBindingNS)
		}
	})

	t.Run("invalid input produces nothing", func(t *testing.T) {
		long := strings.Repeat("a", 64)
		many := make([]string, maxEntries+1)
		for i := range many {
			many[i] = fmt.Sprintf("ns-%d", i)
		}
		for _, tc := range []struct {
			name string
			ns   []string
			sa   ServiceAccountRef
		}{
			{"no namespaces", nil, sa},
			{"too many namespaces", many, sa},
			{"duplicate namespace", []string{"web", "web"}, sa},
			{"upper case", []string{"Web"}, sa},
			{"newline injection", []string{"web\nkind: ClusterRole"}, sa},
			{"yaml injection", []string{"web: {x: y}"}, sa},
			{"path", []string{"web/../kube-system"}, sa},
			{"too long", []string{long}, sa},
			{"wildcard", []string{"*"}, sa},
			{"no service account namespace", []string{"web"}, ServiceAccountRef{}},
			{"bad service account namespace", []string{"web"}, ServiceAccountRef{Namespace: "ta gcess"}},
			{"bad service account name", []string{"web"}, ServiceAccountRef{Namespace: "tagcess", Name: "a\nb"}},
		} {
			out, err := RBACManifest(tc.ns, tc.sa)
			if err == nil || out != nil {
				t.Errorf("%s: RBACManifest = %q, %v; want an error and no output", tc.name, out, err)
			}
		}
	})
}

// AC2: the review asks the API with the runtime token and reports who, what and when.
func TestK8sRBAC_ReviewUsesRuntimeIdentity(t *testing.T) {
	t.Run("required grants are asked with the runtime token", func(t *testing.T) {
		e := rbacEnv(t, testPrincipal)
		required := wantRequired([]string{"apps", "web"})
		e.fx.AllowAccess(required...)

		r := e.review(t, []string{"web", "apps"})

		if r.Principal != testPrincipal {
			t.Errorf("Principal = %q, want %q", r.Principal, testPrincipal)
		}
		if !r.At.Equal(reviewTime.Truncate(time.Second)) || r.At.Location() != time.UTC {
			t.Errorf("At = %v, want %v in UTC", r.At, reviewTime.Truncate(time.Second))
		}
		if !slices.Equal(r.Namespaces, []string{"apps", "web"}) {
			t.Errorf("Namespaces = %v, want [apps web]", r.Namespaces)
		}
		var asked []k8sfix.Access
		for _, c := range r.Required {
			if !c.Want || !c.Answered || !c.Allowed || c.Error != "" {
				t.Errorf("required check %+v is not an answered allow", c)
			}
			asked = append(asked, acc(c.Namespace, c.Group, c.Resource, c.Subresource, c.Verb))
		}
		if !reflect.DeepEqual(sortedAccess(asked), sortedAccess(required)) {
			t.Errorf("required checks = %v\nwant %v", sortedAccess(asked), sortedAccess(required))
		}
		if !r.Passed() {
			t.Errorf("Passed() = false, problems: %v", r.Problems())
		}

		if len(e.Seen()) == 0 {
			t.Fatal("API received no request")
		}
		for _, s := range e.Seen() {
			if s.Method != http.MethodPost || s.Path != ssarAPIPath {
				t.Errorf("request %s %s, want only POST %s", s.Method, s.Path, ssarAPIPath)
			}
			if s.Authorization != "Bearer "+e.token {
				t.Errorf("request to %s did not carry the runtime token", s.Path)
			}
		}
	})

	t.Run("the result never carries the token or other claims", func(t *testing.T) {
		e := rbacEnv(t, testPrincipal)
		e.fx.AllowAccess(wantRequired([]string{"web"})...)
		r := e.review(t, []string{"web"})
		body, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal review: %v", err)
		}
		for _, s := range []string{fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), string(body), r.Summary()} {
			for _, secret := range []string{e.token, strings.Split(e.token, ".")[1], "payload-claim-marker", "pod-claim-marker"} {
				if strings.Contains(s, secret) {
					t.Errorf("review output contains %q", secret)
				}
			}
		}
	})

	t.Run("a token without a readable principal is not passed", func(t *testing.T) {
		for name, token := range map[string]string{
			"opaque":      "opaque-token-" + sentinel(t),
			"no sub":      base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`)) + ".sig",
			"bad payload": "a.%%%.c",
			"control sub": fakeJWT(t, "system:serviceaccount:a:b\nforged"),
		} {
			e := newAPIEnv(t, envOpts{})
			e.token = token
			e.fx.AllowAccess(wantRequired([]string{"web"})...)
			r := e.review(t, []string{"web"})
			if r.Principal != "" {
				t.Errorf("%s: Principal = %q, want empty", name, r.Principal)
			}
			if r.Passed() || !problemMentions(r, "principal") {
				t.Errorf("%s: Passed() = %v, problems %v", name, r.Passed(), r.Problems())
			}
		}
	})

	t.Run("the scope must be valid before anything is asked", func(t *testing.T) {
		e := rbacEnv(t, testPrincipal)
		for _, ns := range [][]string{nil, {"Web"}, {"web", "web"}, {"web/../x"}} {
			if _, err := ReviewPermissions(context.Background(), e.client(t, e.cred(), time.Second), ns, reviewNow); err == nil {
				t.Errorf("ReviewPermissions(%v) succeeded", ns)
			}
		}
		e.noNetwork(t)
	})
}

func problemMentions(r Review, sub string) bool {
	return slices.ContainsFunc(r.Problems(), func(p string) bool { return strings.Contains(p, sub) })
}

// AC3: forbidden operations are only asked, never tried.
func TestK8sRBAC_ReadOnlyPermissionsAndForbiddenSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name       string
		namespaces []string
		probes     []string
	}{
		{"two namespaces", []string{"apps", "web"}, []string{"default", "kube-system"}},
		{"kube-system selected", []string{"kube-system", "web"}, []string{"default"}},
		{"default selected", []string{"default"}, []string{"kube-system"}},
		{"both selected", []string{"default", "kube-system"}, []string{"tagcess-out-of-scope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := rbacEnv(t, testPrincipal)
			e.fx.AllowAccess(wantRequired(tc.namespaces)...)

			r := e.review(t, tc.namespaces)

			wantAll := append(wantRequired(tc.namespaces), wantForbidden(tc.namespaces, tc.probes)...)
			got := e.fx.AccessRequests()
			if !reflect.DeepEqual(sortedAccess(got), sortedAccess(wantAll)) {
				t.Errorf("accesses asked:\n got %v\nwant %v", sortedAccess(got), sortedAccess(wantAll))
			}
			if len(r.Forbidden) != len(wantForbidden(tc.namespaces, tc.probes)) {
				t.Errorf("len(Forbidden) = %d, want %d", len(r.Forbidden), len(wantForbidden(tc.namespaces, tc.probes)))
			}
			for _, c := range r.Forbidden {
				if c.Want || !c.Answered || c.Allowed {
					t.Errorf("forbidden check %+v is not an answered deny", c)
				}
			}
			if !r.Passed() {
				t.Errorf("Passed() = false, problems: %v", r.Problems())
			}

			// Nothing but review POSTs: no list GET, no write, no token request.
			for _, s := range e.Seen() {
				if s.Method != http.MethodPost || s.Path != ssarAPIPath {
					t.Errorf("request %s %s, want only POST %s", s.Method, s.Path, ssarAPIPath)
				}
			}
			if n := len(e.Seen()); n != len(wantAll) {
				t.Errorf("API saw %d requests, want %d", n, len(wantAll))
			}
		})
	}
}

// AC4: an unmet, broad or unfinished review is never a pass and only states what was asked.
func TestK8sRBAC_IncompleteOrBroadReviewIsNotVerified(t *testing.T) {
	ns := []string{"web"}
	required := wantRequired(ns)
	forbidden := wantForbidden(ns, []string{"default", "kube-system"})

	cases := []struct {
		name    string
		prepare func(fx *k8sfix.Fixture)
		timeout time.Duration
		mention string
	}{
		{"required list denied", func(fx *k8sfix.Fixture) {
			fx.AnswerAccess(acc("web", netGroup, "ingresses", "", "list"), k8sfix.AccessAnswer{})
		}, time.Second, "ingresses"},
		{"ingressclass get denied", func(fx *k8sfix.Fixture) {
			fx.AnswerAccess(acc("", netGroup, "ingressclasses", "", "get"), k8sfix.AccessAnswer{})
		}, time.Second, "ingressclasses"},
		{"secret read allowed", func(fx *k8sfix.Fixture) {
			fx.AllowAccess(acc("web", "", "secrets", "", "get"))
		}, time.Second, "secrets"},
		{"token creation allowed", func(fx *k8sfix.Fixture) {
			fx.AllowAccess(acc("web", "", "serviceaccounts", "token", "create"))
		}, time.Second, "serviceaccounts/token"},
		{"write allowed", func(fx *k8sfix.Fixture) {
			fx.AllowAccess(acc("web", netGroup, "ingresses", "", "patch"))
		}, time.Second, "patch"},
		{"all namespaces readable", func(fx *k8sfix.Fixture) {
			fx.AllowAccess(acc("", "", "services", "", "list"))
		}, time.Second, "services"},
		{"other namespace readable", func(fx *k8sfix.Fixture) {
			fx.AllowAccess(acc("kube-system", netGroup, "ingresses", "", "list"))
		}, time.Second, "kube-system"},
		{"review forbidden", func(fx *k8sfix.Fixture) {
			fx.AnswerAccess(required[2], k8sfix.AccessAnswer{Fail: &k8sfix.Failure{Status: http.StatusForbidden}})
		}, time.Second, "403"},
		{"server error", func(fx *k8sfix.Fixture) {
			fx.AnswerAccess(forbidden[3], k8sfix.AccessAnswer{Fail: &k8sfix.Failure{Status: http.StatusInternalServerError}})
		}, time.Second, "500"},
		{"hanging review", func(fx *k8sfix.Fixture) {
			fx.AnswerAccess(forbidden[1], k8sfix.AccessAnswer{Fail: &k8sfix.Failure{Hang: true}})
		}, 100 * time.Millisecond, "timeout"},
		{"evaluation error", func(fx *k8sfix.Fixture) {
			fx.AnswerAccess(forbidden[0], k8sfix.AccessAnswer{EvaluationError: "webhook authorizer unavailable"})
		}, time.Second, "evaluation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := rbacEnv(t, testPrincipal)
			e.fx.AllowAccess(required...)
			tc.prepare(e.fx)

			r, err := ReviewPermissions(context.Background(), e.client(t, e.cred(), tc.timeout), ns, reviewNow)
			if err != nil {
				t.Fatalf("ReviewPermissions: %v (a failed review is a result, not an error)", err)
			}
			if r.Passed() {
				t.Fatalf("Passed() = true for %q", tc.name)
			}
			if !problemMentions(r, tc.mention) {
				t.Errorf("problems %v do not mention %q", r.Problems(), tc.mention)
			}
			assertLimited(t, r)

			// A failed query stops the review; the remaining checks are reported as not run.
			var answered, notRun int
			for _, c := range append(slices.Clone(r.Required), r.Forbidden...) {
				switch {
				case c.Answered:
					answered++
				case c.Error == "not run":
					notRun++
				}
			}
			if strings.HasPrefix(tc.name, "review") || tc.name == "server error" || tc.name == "hanging review" || tc.name == "evaluation error" {
				if notRun == 0 {
					t.Errorf("no check reported as not run after a failed query")
				}
				if got := len(e.fx.AccessRequests()); got != answered+1 {
					t.Errorf("%d queries sent, want %d (answered) + 1 (the failed one)", got, answered)
				}
			}
		})
	}

	t.Run("a passed review states its limits too", func(t *testing.T) {
		e := rbacEnv(t, testPrincipal)
		e.fx.AllowAccess(required...)
		r := e.review(t, ns)
		if !r.Passed() {
			t.Fatalf("Passed() = false: %v", r.Problems())
		}
		assertLimited(t, r)
		if !strings.Contains(r.Summary(), fmt.Sprintf("%d/%d", len(required), len(required))) {
			t.Errorf("Summary() = %q does not count the checks", r.Summary())
		}
	})

	t.Run("a cancelled context is an incomplete review", func(t *testing.T) {
		e := rbacEnv(t, testPrincipal)
		e.fx.AllowAccess(required...)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r, err := ReviewPermissions(ctx, e.client(t, e.cred(), time.Second), ns, reviewNow)
		if err != nil || r.Passed() {
			t.Errorf("ReviewPermissions = passed %v, %v; want a result that is not passed", r.Passed(), err)
		}
		e.noNetwork(t)
	})

	t.Run("an unauthorized token is not a pass", func(t *testing.T) {
		e := rbacEnv(t, testPrincipal)
		e.fx.AllowAccess(required...)
		cred := e.cred()
		cred.Token = fakeJWT(t, testPrincipal) // not the one the API accepts
		r, err := ReviewPermissions(context.Background(), e.client(t, cred, time.Second), ns, reviewNow)
		if err != nil || r.Passed() || !problemMentions(r, "401") {
			t.Errorf("ReviewPermissions = passed %v, %v, problems %v", r.Passed(), err, r.Problems())
		}
		if got := len(e.Seen()); got != 1 {
			t.Errorf("%d requests after a 401, want 1", got)
		}
	})
}

// assertLimited checks that a review never claims more than the operations it asked.
func assertLimited(t *testing.T, r Review) {
	t.Helper()
	s := strings.ToLower(r.Summary())
	if !strings.Contains(s, "only these operations") {
		t.Errorf("Summary() = %q does not say that only the asked operations were checked", r.Summary())
	}
	for _, claim := range []string{"read-only verified", "verified read-only", "is read-only", "verified"} {
		if strings.Contains(s, claim) {
			t.Errorf("Summary() = %q claims %q", r.Summary(), claim)
		}
	}
	for _, f := range reflect.VisibleFields(reflect.TypeOf(r)) {
		if n := strings.ToLower(f.Name); strings.Contains(n, "readonly") || strings.Contains(n, "verified") {
			t.Errorf("Review has a field %s that reads as a blanket claim", f.Name)
		}
	}
}
