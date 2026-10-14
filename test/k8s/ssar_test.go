package k8s

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func postSSAR(t *testing.T, f *Fixture, contentType, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.URL()+ssarPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build POST: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const ssarJSON = `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"web","verb":"list","group":"networking.k8s.io","resource":"ingresses"}}}`

func TestFixtureSSAR(t *testing.T) {
	f := New(t)
	a := Access{Namespace: "web", Group: "networking.k8s.io", Resource: "ingresses", Verb: "list"}

	if code, body := postSSAR(t, f, "application/json", ssarJSON); code != http.StatusCreated || !strings.Contains(body, `"allowed":false`) {
		t.Fatalf("unregistered access: %d %s, want 201 and denied", code, body)
	}
	f.AllowAccess(a)
	if code, body := postSSAR(t, f, "application/json", ssarJSON); code != http.StatusCreated || !strings.Contains(body, `"allowed":true`) {
		t.Fatalf("allowed access: %d %s", code, body)
	}
	f.AnswerAccess(a, AccessAnswer{Fail: &Failure{Status: http.StatusForbidden}})
	if code, _ := postSSAR(t, f, "application/json", ssarJSON); code != http.StatusForbidden {
		t.Fatalf("failing access: %d, want 403", code)
	}
	if got := f.AccessRequests(); len(got) != 3 || got[0] != a {
		t.Fatalf("AccessRequests = %v", got)
	}

	for name, tc := range map[string][2]string{
		"wrong content type": {"text/plain", ssarJSON},
		"unknown field":      {"application/json", strings.Replace(ssarJSON, `"verb"`, `"verbs"`, 1)},
		"wrong kind":         {"application/json", strings.Replace(ssarJSON, "SelfSubjectAccessReview", "SubjectAccessReview", 1)},
	} {
		if code, _ := postSSAR(t, f, tc[0], tc[1]); code < 400 {
			t.Errorf("%s: status %d, want an error", name, code)
		}
	}
	if got := len(f.AccessRequests()); got != 3 {
		t.Errorf("malformed requests were recorded as accesses: %d", got)
	}
}
