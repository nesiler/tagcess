// Package k8s is the shared F4 test bed: a fake, in-process Kubernetes JSON API, a local TLS
// server with a test CA and a fake clock. It never dials a real cluster and never reads a real
// credential; all data and certificates are generated while the test runs.
//
// The API fixture answers paginated list requests keyed by (source, namespace, continue) and
// exposes the received requests to the test. Deterministic failures (401, 403, broken JSON, a
// hanging request) can be registered per collection. New and NewTLS register their Close with
// t.Cleanup, so every local server a test starts is closed when the test ends.
package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Source is one Kubernetes list resource the fixture serves.
type Source string

// The list resources the first F4 profile reads (R3 B-02: standard Ingress/Service; F4-001).
const (
	Ingresses      Source = "ingresses"
	Services       Source = "services"
	IngressClasses Source = "ingressclasses"
)

// sourceSpec maps a Source to its API path, scope and Kubernetes list kind.
type sourceSpec struct {
	apiVersion string
	apiPrefix  string
	namespaced bool
	listKind   string
}

var sourceSpecs = map[Source]sourceSpec{
	Ingresses:      {apiVersion: "networking.k8s.io/v1", apiPrefix: "/apis/networking.k8s.io/v1", namespaced: true, listKind: "IngressList"},
	Services:       {apiVersion: "v1", apiPrefix: "/api/v1", namespaced: true, listKind: "ServiceList"},
	IngressClasses: {apiVersion: "networking.k8s.io/v1", apiPrefix: "/apis/networking.k8s.io/v1", namespaced: false, listKind: "IngressClassList"},
}

// Page is one page of a list response. The fixture generates the continue token for every page
// but the last; tests only fill Items.
type Page struct {
	Items []any
}

// Failure makes a collection answer deterministically with an error instead of a list. Status 0
// means 500. An empty Body is replaced with a Kubernetes Status JSON object for Status. Hang makes
// the handler wait until the request context is cancelled instead of answering.
type Failure struct {
	Status int
	Body   string
	Hang   bool
}

// Request is one request the fixture received, exposed to the test through Requests.
type Request struct {
	Method    string
	Path      string
	Source    Source
	Namespace string
	Continue  string
}

// ListResponse is a decoded Kubernetes list page.
type ListResponse struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Continue        string `json:"continue"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []json.RawMessage `json:"items"`
}

// collection is the registered answer for one (source, namespace) key.
type collection struct {
	spec  sourceSpec
	pages []Page
	fail  *Failure
}

// Fixture is a local fake Kubernetes JSON API. Use New to start it; Close closes the local server.
type Fixture struct {
	t *testing.T

	mu          sync.Mutex
	collections map[string]*collection
	requests    []Request
	access      accessState

	server *httptest.Server
	once   sync.Once
}

// New starts the fixture's local HTTP server and registers Close with t.Cleanup.
func New(t *testing.T) *Fixture {
	t.Helper()
	f := &Fixture{t: t, collections: make(map[string]*collection)}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.Close)
	return f
}

// ServeList registers the ordered pages of a list collection. A namespaced source requires a
// namespace; a cluster-scoped source requires an empty one.
func (f *Fixture) ServeList(source Source, namespace string, pages ...Page) *Fixture {
	f.t.Helper()
	f.register(source, namespace, &collection{spec: f.spec(source, namespace), pages: pages})
	return f
}

// Fail registers a deterministic failure for a list collection.
func (f *Fixture) Fail(source Source, namespace string, failure Failure) *Fixture {
	f.t.Helper()
	fail := failure
	f.register(source, namespace, &collection{spec: f.spec(source, namespace), fail: &fail})
	return f
}

func (f *Fixture) spec(source Source, namespace string) sourceSpec {
	f.t.Helper()
	spec, ok := sourceSpecs[source]
	if !ok {
		f.t.Fatalf("k8s fixture: unknown source %q", source)
	}
	if spec.namespaced && namespace == "" {
		f.t.Fatalf("k8s fixture: source %q is namespaced but namespace is empty", source)
	}
	if !spec.namespaced && namespace != "" {
		f.t.Fatalf("k8s fixture: source %q is cluster-scoped but namespace is %q", source, namespace)
	}
	return spec
}

func (f *Fixture) register(source Source, namespace string, col *collection) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.collections[key(source, namespace)] = col
}

// URL is the base URL of the fixture's local server.
func (f *Fixture) URL() string { return f.server.URL }

// Addr is the host:port the fixture's local server listens on.
func (f *Fixture) Addr() string { return f.server.Listener.Addr().String() }

// Client returns an HTTP client that trusts the fixture's server.
func (f *Fixture) Client() *http.Client { return f.server.Client() }

// Path is the canonical API path of a list collection.
func (f *Fixture) Path(source Source, namespace string) string {
	spec, ok := sourceSpecs[source]
	if !ok {
		return "/" + string(source)
	}
	if spec.namespaced {
		return spec.apiPrefix + "/namespaces/" + namespace + "/" + string(source)
	}
	return spec.apiPrefix + "/" + string(source)
}

// List fetches one list page, optionally by continue token, and fails the test on a non-2xx
// response.
func (f *Fixture) List(tb testing.TB, source Source, namespace, continueToken string) ListResponse {
	tb.Helper()
	target := f.URL() + f.Path(source, namespace)
	if continueToken != "" {
		target += "?" + url.Values{"continue": {continueToken}}.Encode()
	}
	req, err := http.NewRequestWithContext(tb.Context(), http.MethodGet, target, nil)
	if err != nil {
		tb.Fatalf("k8s fixture: build request: %v", err)
	}
	resp, err := f.Client().Do(req)
	if err != nil {
		tb.Fatalf("k8s fixture: GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("k8s fixture: read %s: %v", target, err)
	}
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("k8s fixture: GET %s: status %d, body %s", target, resp.StatusCode, body)
	}
	var out ListResponse
	if err := json.Unmarshal(body, &out); err != nil {
		tb.Fatalf("k8s fixture: decode %s: %v", target, err)
	}
	return out
}

// Requests returns a copy of the request log in arrival order.
func (f *Fixture) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Request, len(f.requests))
	copy(out, f.requests)
	return out
}

// Close closes the local server. It is idempotent.
func (f *Fixture) Close() {
	f.once.Do(func() {
		if f.server != nil {
			f.server.Close()
		}
	})
}

func (f *Fixture) handle(w http.ResponseWriter, r *http.Request) {
	source, namespace, ok := parsePath(r.URL.Path)
	// Record every request, including those to unparsable paths, so a client test can see its own
	// typos. An unparsable path leaves Source empty.
	f.record(Request{
		Method:    r.Method,
		Path:      r.URL.Path,
		Source:    source,
		Namespace: namespace,
		Continue:  r.URL.Query().Get("continue"),
	})
	if r.URL.Path == ssarPath {
		f.handleSSAR(w, r)
		return
	}
	if !ok {
		writeStatus(w, http.StatusNotFound, fmt.Sprintf("the server could not find the requested resource %s", r.URL.Path), "NotFound")
		return
	}
	if r.Method != http.MethodGet {
		// The fixture is read-only (ADR 0030): list reads are GET, anything else is refused.
		writeStatus(w, http.StatusMethodNotAllowed, fmt.Sprintf("the server does not allow %s on %s", r.Method, r.URL.Path), "MethodNotAllowed")
		return
	}
	cont := r.URL.Query().Get("continue")

	f.mu.Lock()
	col := f.collections[key(source, namespace)]
	f.mu.Unlock()
	if col == nil {
		writeStatus(w, http.StatusNotFound, fmt.Sprintf("%s %q not found", source, namespace), "NotFound")
		return
	}
	if col.fail != nil {
		respondFailure(w, r, col.fail)
		return
	}

	index, ok := pageIndex(source, namespace, cont, col.pages)
	if !ok {
		writeStatus(w, http.StatusGone, "the provided continue token is no longer valid", "Expired")
		return
	}
	var items []any
	next := ""
	if len(col.pages) > 0 {
		items = col.pages[index].Items
		if index+1 < len(col.pages) {
			next = continueToken(source, namespace, index+1)
		}
	}
	if items == nil {
		items = []any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": col.spec.apiVersion,
		"kind":       col.spec.listKind,
		"metadata": map[string]any{
			"continue":        next,
			"resourceVersion": "1",
		},
		"items": items,
	})
}

func (f *Fixture) record(req Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
}

// pageIndex maps a continue token to a page index. An empty token is the first page; a token the
// fixture did not issue is invalid.
func pageIndex(source Source, namespace, cont string, pages []Page) (int, bool) {
	if cont == "" {
		// An empty token asks for the first page. A collection with zero registered pages is an
		// empty list, not an error: the handler yields items=[] and no continue token.
		return 0, true
	}
	for i := range pages {
		if continueToken(source, namespace, i) == cont {
			return i, true
		}
	}
	return 0, false
}

// continueToken is the token a client must send to fetch page i (0-based). Page j's response
// advertises the token for j+1.
func continueToken(source Source, namespace string, page int) string {
	return strconv.Itoa(page) + "-" + string(source) + "-" + namespace
}

func key(source Source, namespace string) string { return string(source) + "\x00" + namespace }

// parsePath extracts the source and namespace from a Kubernetes list path.
func parsePath(path string) (Source, string, bool) {
	for source, spec := range sourceSpecs {
		if !spec.namespaced {
			if path == spec.apiPrefix+"/"+string(source) {
				return source, "", true
			}
			continue
		}
		prefix := spec.apiPrefix + "/namespaces/"
		suffix := "/" + string(source)
		if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, suffix) {
			namespace := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
			if namespace != "" && !strings.Contains(namespace, "/") {
				return source, namespace, true
			}
		}
	}
	return "", "", false
}

func respondFailure(w http.ResponseWriter, r *http.Request, fail *Failure) {
	if fail.Hang {
		<-r.Context().Done()
		return
	}
	status := fail.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if fail.Body != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, fail.Body)
		return
	}
	writeStatus(w, status, http.StatusText(status), http.StatusText(status))
}

// k8sStatus is the deterministic Kubernetes Status object for an error response.
type k8sStatus struct {
	Kind       string         `json:"kind"`
	APIVersion string         `json:"apiVersion"`
	Metadata   map[string]any `json:"metadata"`
	Status     string         `json:"status"`
	Message    string         `json:"message"`
	Reason     string         `json:"reason,omitempty"`
	Code       int            `json:"code"`
}

func writeStatus(w http.ResponseWriter, status int, message, reason string) {
	writeJSON(w, status, k8sStatus{
		Kind:       "Status",
		APIVersion: "v1",
		Metadata:   map[string]any{},
		Status:     "Failure",
		Message:    message,
		Reason:     reason,
		Code:       status,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
