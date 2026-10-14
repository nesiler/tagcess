package k8s

// F4-005: the narrow RBAC manifest the UI presents and the review of tagcess's own effective
// permissions. The manifest is applied by an authorised cluster administrator, never by tagcess;
// tagcess creates no resource and requests no token. The review asks the API, with the runtime
// token, whether a chosen set of operations is allowed (SelfSubjectAccessReview). The POST is a
// question and changes nothing, so a forbidden operation is asked about and never attempted.
//
// RBAC is additive: other bindings or authorizers can grant more than this manifest does. The
// review therefore reports only the operations it asked about and never says the account is
// read-only.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DefaultServiceAccountName is the ServiceAccount the manifest creates when none is named.
const DefaultServiceAccountName = "tagcess-reader"

const (
	namespaceRoleName = "tagcess-ingress-service-reader"
	classRoleName     = "tagcess-ingressclass-reader"
	bindingName       = "tagcess-reader"

	ssarMaxBytes   = 1 << 20 // [Ö] one review answer
	notRun         = "not run"
	syntheticProbe = "tagcess-out-of-scope" // out-of-scope namespace when kube-system and default are both selected
	maxPrincipal   = 512
)

// ServiceAccountRef names the ServiceAccount the manifest creates. Namespace must already exist
// and is required; an empty Name means DefaultServiceAccountName.
type ServiceAccountRef struct {
	Namespace string
	Name      string
}

// RBACManifest returns the install manifest as multi-document YAML: the ServiceAccount, two
// ClusterRoles with get/list only, one RoleBinding per selected namespace and one
// ClusterRoleBinding for IngressClasses (list needs the whole resource, so it cannot be narrowed to
// names). No Secret, token or wildcard rule is produced. The same input gives the same bytes; the
// namespaces are sorted. Invalid input gives an error and no output.
func RBACManifest(namespaces []string, sa ServiceAccountRef) ([]byte, error) {
	var verr ValidationError
	fail := func(field, msg string) { verr.Fields = append(verr.Fields, FieldError{field, msg}) }
	sorted := names("namespaces", namespaces, validNamespace, fail)
	if sa.Name == "" {
		sa.Name = DefaultServiceAccountName
	}
	if !validNamespace(sa.Namespace) {
		fail("service_account_namespace", "is required and must be a valid name")
	}
	if !validNamespace(sa.Name) {
		fail("service_account_name", "must be a valid name")
	}
	if len(verr.Fields) > 0 {
		return nil, &verr
	}

	// Every interpolated value passed the DNS label check above; %q keeps names like "true" or
	// "123" strings in YAML.
	var b bytes.Buffer
	doc := func(format string, a ...any) {
		if b.Len() > 0 {
			b.WriteString("---\n")
		}
		fmt.Fprintf(&b, format, a...)
	}
	b.WriteString("# tagcess read-only access: get/list on Ingresses and Services in the listed namespaces and on\n" +
		"# IngressClasses. Apply as a cluster administrator. This file creates no credential.\n" +
		"# A namespace later removed from the profile keeps its RoleBinding: delete it manually.\n")
	doc("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: %q\n  namespace: %q\n", sa.Name, sa.Namespace)
	doc("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: %q\nrules:\n"+
		"- apiGroups: [\"networking.k8s.io\"]\n  resources: [\"ingresses\"]\n  verbs: [\"get\", \"list\"]\n"+
		"- apiGroups: [\"\"]\n  resources: [\"services\"]\n  verbs: [\"get\", \"list\"]\n", namespaceRoleName)
	doc("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: %q\nrules:\n"+
		"- apiGroups: [\"networking.k8s.io\"]\n  resources: [\"ingressclasses\"]\n  verbs: [\"get\", \"list\"]\n", classRoleName)
	for _, ns := range sorted {
		doc("apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: %q\n  namespace: %q\n"+
			"roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: %q\n"+
			"subjects:\n- kind: ServiceAccount\n  name: %q\n  namespace: %q\n",
			bindingName, ns, namespaceRoleName, sa.Name, sa.Namespace)
	}
	doc("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: %q\n"+
		"roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: %q\n"+
		"subjects:\n- kind: ServiceAccount\n  name: %q\n  namespace: %q\n",
		bindingName, classRoleName, sa.Name, sa.Namespace)
	return b.Bytes(), nil
}

func validNamespace(s string) bool { return len(s) <= 63 && dnsLabel.MatchString(s) }

// Check is one operation the review asked about. Namespace is empty for a cluster-scoped resource
// and, on a namespaced one, means all namespaces.
type Check struct {
	Namespace   string `json:"namespace,omitempty"`
	Group       string `json:"group,omitempty"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
	Verb        string `json:"verb"`
	Want        bool   `json:"want_allowed"` // true: tagcess needs it; false: it must be denied
	Answered    bool   `json:"answered"`
	Allowed     bool   `json:"allowed"` // meaningful only when Answered
	Error       string `json:"error,omitempty"`
}

// Met reports whether the API answered and the answer is the wanted one.
func (c Check) Met() bool { return c.Answered && c.Allowed == c.Want }

func (c Check) String() string {
	res := c.Resource
	if c.Subresource != "" {
		res += "/" + c.Subresource
	}
	if c.Group != "" {
		res += "." + c.Group
	}
	scope := "namespace " + strconv.Quote(c.Namespace)
	switch {
	case c.Namespace == "" && c.Resource == "ingressclasses":
		scope = "cluster scope"
	case c.Namespace == "":
		scope = "all namespaces"
	}
	return c.Verb + " " + res + " in " + scope
}

// Review is the result of one effective-permission review. It describes the asked operations only;
// there is deliberately no field that says the account is read-only.
type Review struct {
	// Principal is the identity the token names (its sub claim, read without verification). The API
	// answered for the token as presented, so a mismatch shows up as unexpected answers.
	Principal  string    `json:"principal"`
	At         time.Time `json:"at"`
	Namespaces []string  `json:"namespaces"`
	Required   []Check   `json:"required"`
	Forbidden  []Check   `json:"forbidden"`
}

// Passed reports whether the principal is known and every asked operation was answered as wanted.
// It is not a statement about operations that were not asked.
func (r Review) Passed() bool { return len(r.Problems()) == 0 }

// Problems lists what keeps the review from passing, one line per issue.
func (r Review) Problems() []string {
	var out []string
	if r.Principal == "" {
		out = append(out, "principal could not be read from the token")
	}
	if len(r.Required) == 0 || len(r.Forbidden) == 0 {
		out = append(out, "review has no checks")
	}
	for _, c := range append(slices.Clone(r.Required), r.Forbidden...) {
		switch {
		case c.Error != "":
			out = append(out, c.String()+": "+c.Error)
		case !c.Answered:
			out = append(out, c.String()+": "+notRun)
		case c.Want && !c.Allowed:
			out = append(out, c.String()+": denied, but tagcess needs it")
		case !c.Want && c.Allowed:
			out = append(out, c.String()+": allowed, but must be denied")
		}
	}
	return out
}

// Summary is the one-line statement for the UI: counts, the principal and the limit of the result.
func (r Review) Summary() string {
	count := func(cs []Check) (met int) {
		for _, c := range cs {
			if c.Met() {
				met++
			}
		}
		return met
	}
	state := "did not pass"
	if r.Passed() {
		state = "passed"
	}
	principal := r.Principal
	if principal == "" {
		principal = "unknown principal"
	}
	return fmt.Sprintf("Selected permission checks %s for %s: %d/%d required operations allowed, %d/%d forbidden operations denied. "+
		"Checked only these operations; other bindings and authorizers were not reviewed.",
		state, principal, count(r.Required), len(r.Required), count(r.Forbidden), len(r.Forbidden))
}

// ReviewPermissions asks the API, with the client's token, about the operations tagcess needs and
// the operations it must not have, for the selected namespaces. A failed or unanswered question is
// recorded in the result and stops the review; the remaining checks are "not run". The returned
// error is only for an invalid scope. now is the review time source; nil means time.Now.
func ReviewPermissions(ctx context.Context, c *Client, namespaces []string, now func() time.Time) (Review, error) {
	var verr ValidationError
	sorted := names("namespaces", namespaces, validNamespace, func(field, msg string) {
		verr.Fields = append(verr.Fields, FieldError{field, msg})
	})
	if len(verr.Fields) > 0 {
		return Review{}, &verr
	}
	if now == nil {
		now = time.Now
	}
	r := Review{
		Principal:  principalOf(c.token),
		At:         now().UTC().Truncate(time.Second),
		Namespaces: sorted,
	}

	const netAPI = "networking.k8s.io"
	read := []string{"get", "list"}
	write := []string{"create", "update", "patch", "delete"}
	add := func(dst *[]Check, want bool, ns, group, resource, sub string, verbs ...string) {
		for _, v := range verbs {
			*dst = append(*dst, Check{Namespace: ns, Group: group, Resource: resource, Subresource: sub, Verb: v, Want: want})
		}
	}
	for _, ns := range sorted {
		add(&r.Required, true, ns, netAPI, "ingresses", "", read...)
		add(&r.Required, true, ns, "", "services", "", read...)
	}
	add(&r.Required, true, "", netAPI, "ingressclasses", "", read...)

	for _, ns := range sorted {
		add(&r.Forbidden, false, ns, "", "secrets", "", read...)
		add(&r.Forbidden, false, ns, "", "serviceaccounts", "token", "create")
		add(&r.Forbidden, false, ns, netAPI, "ingresses", "", write...)
		add(&r.Forbidden, false, ns, "", "services", "", write...)
	}
	add(&r.Forbidden, false, "", netAPI, "ingressclasses", "", write...)
	// Out of scope: namespaces that were not selected and all namespaces at once.
	for _, p := range append(outOfScope(sorted), "") {
		add(&r.Forbidden, false, p, netAPI, "ingresses", "", "list")
		add(&r.Forbidden, false, p, "", "services", "", "list")
	}

	stopped := false
	for _, list := range []*[]Check{&r.Required, &r.Forbidden} {
		for i := range *list {
			ch := &(*list)[i]
			if stopped {
				ch.Error = notRun
				continue
			}
			ch.Allowed, ch.Error = c.askAccess(ctx, *ch)
			ch.Answered = ch.Error == ""
			stopped = !ch.Answered
		}
	}
	return r, nil
}

// outOfScope picks namespaces the review must not be able to read: kube-system and default when
// they were not selected, else a name that is not selected. Authorization does not need the
// namespace to exist.
func outOfScope(selected []string) []string {
	var out []string
	for _, ns := range []string{"default", "kube-system"} {
		if !slices.Contains(selected, ns) {
			out = append(out, ns)
		}
	}
	if len(out) == 0 {
		out = append(out, syntheticProbe)
	}
	return out
}

type ssarAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb"`
	Group       string `json:"group,omitempty"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
}

type ssarRequest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		ResourceAttributes ssarAttributes `json:"resourceAttributes"`
	} `json:"spec"`
}

type ssarResponse struct {
	Kind   string `json:"kind"`
	Status struct {
		Allowed         bool   `json:"allowed"`
		EvaluationError string `json:"evaluationError"`
	} `json:"status"`
}

// askAccess posts one SelfSubjectAccessReview with the client's token. It returns the answer or,
// when there is no usable answer, a short reason; the reason never holds the token, a URL or a
// response body. An answer with an evaluation error is not usable: the authorizer says it could not
// decide, so neither its allow nor its deny is evidence.
func (c *Client) askAccess(ctx context.Context, ch Check) (allowed bool, reason string) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		reason, _ := classify(err)
		return false, reason
	}
	var in ssarRequest
	in.APIVersion, in.Kind = "authorization.k8s.io/v1", "SelfSubjectAccessReview"
	in.Spec.ResourceAttributes = ssarAttributes{Namespace: ch.Namespace, Verb: ch.Verb, Group: ch.Group,
		Resource: ch.Resource, Subresource: ch.Subresource}
	body, err := json.Marshal(in)
	if err != nil {
		return false, "request could not be built"
	}
	u := c.base.JoinPath("apis", "authorization.k8s.io", "v1", "selfsubjectaccessreviews")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return false, "request could not be built"
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tagcess")

	resp, err := c.http.Do(req)
	if err != nil {
		reason, _ := classify(err)
		return false, reason
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return false, "redirect refused (HTTP " + strconv.Itoa(resp.StatusCode) + ")"
		}
		return false, "HTTP " + strconv.Itoa(resp.StatusCode)
	}
	var out ssarResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, ssarMaxBytes))
	if err := dec.Decode(&out); err != nil || out.Kind != "SelfSubjectAccessReview" {
		return false, "response is not a valid SelfSubjectAccessReview"
	}
	if out.Status.EvaluationError != "" {
		return false, "authorizer evaluation error"
	}
	return out.Status.Allowed, ""
}

// principalOf reads the sub claim of a JWT-shaped token without verifying it. It is display
// evidence for who the token claims to be; the API's answers are what count. Anything that is not
// a plain, printable sub gives "".
func principalOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil || len(claims.Sub) > maxPrincipal ||
		strings.ContainsFunc(claims.Sub, func(r rune) bool { return !unicode.IsPrint(r) || unicode.IsSpace(r) }) {
		return ""
	}
	return claims.Sub
}
