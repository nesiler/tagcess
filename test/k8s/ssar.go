package k8s

// A fake SelfSubjectAccessReview endpoint (F4-005). The authorization API answers an access query
// with an allow or deny and never changes a resource, so the fixture only records what was asked
// and answers from a table: an access nobody registered is denied, as RBAC denies by default.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ssarPath is the only POST path the fixture accepts.
const ssarPath = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"

// Access is one resource attribute set of an access query. An empty Namespace on a namespaced
// resource means all namespaces, as in the API.
type Access struct {
	Namespace   string
	Group       string
	Resource    string
	Subresource string
	Verb        string
}

// AccessAnswer is the registered answer for one Access. Fail makes the endpoint answer with that
// error instead of a review; EvaluationError is put into status.evaluationError.
type AccessAnswer struct {
	Allowed         bool
	EvaluationError string
	Fail            *Failure
}

type accessState struct {
	answers  map[Access]AccessAnswer
	requests []Access
}

// AllowAccess registers the given accesses as allowed. Every other access is denied.
func (f *Fixture) AllowAccess(accesses ...Access) *Fixture {
	for _, a := range accesses {
		f.AnswerAccess(a, AccessAnswer{Allowed: true})
	}
	return f
}

// AnswerAccess registers the answer for one access.
func (f *Fixture) AnswerAccess(a Access, ans AccessAnswer) *Fixture {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.access.answers == nil {
		f.access.answers = make(map[Access]AccessAnswer)
	}
	f.access.answers[a] = ans
	return f
}

// AccessRequests returns the accesses asked so far, in arrival order.
func (f *Fixture) AccessRequests() []Access {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Access(nil), f.access.requests...)
}

type ssarBody struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		ResourceAttributes struct {
			Namespace   string `json:"namespace,omitempty"`
			Verb        string `json:"verb"`
			Group       string `json:"group,omitempty"`
			Version     string `json:"version,omitempty"`
			Resource    string `json:"resource"`
			Subresource string `json:"subresource,omitempty"`
			Name        string `json:"name,omitempty"`
		} `json:"resourceAttributes"`
	} `json:"spec"`
}

// handleSSAR serves the review endpoint. A malformed request is a 400, like the API's strict
// decoding, so a typo in a client shows up as a failure and not as a silent deny.
func (f *Fixture) handleSSAR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeStatus(w, http.StatusMethodNotAllowed, fmt.Sprintf("the server does not allow %s on %s", r.Method, r.URL.Path), "MethodNotAllowed")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, "unreadable body", "BadRequest")
		return
	}
	var body ssarBody
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	ra := &body.Spec.ResourceAttributes
	switch {
	case !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json"):
		writeStatus(w, http.StatusUnsupportedMediaType, "content type must be application/json", "UnsupportedMediaType")
		return
	case dec.Decode(&body) != nil:
		writeStatus(w, http.StatusBadRequest, "body is not a valid SelfSubjectAccessReview", "BadRequest")
		return
	case body.APIVersion != "authorization.k8s.io/v1" || body.Kind != "SelfSubjectAccessReview":
		writeStatus(w, http.StatusBadRequest, "wrong apiVersion or kind", "BadRequest")
		return
	case ra.Verb == "" || ra.Resource == "" || ra.Name != "":
		writeStatus(w, http.StatusBadRequest, "verb and resource are required and name is not used", "BadRequest")
		return
	}
	a := Access{Namespace: ra.Namespace, Group: ra.Group, Resource: ra.Resource, Subresource: ra.Subresource, Verb: ra.Verb}

	f.mu.Lock()
	f.access.requests = append(f.access.requests, a)
	ans := f.access.answers[a]
	f.mu.Unlock()

	if ans.Fail != nil {
		respondFailure(w, r, ans.Fail)
		return
	}
	status := map[string]any{"allowed": ans.Allowed}
	if !ans.Allowed {
		status["reason"] = "no RBAC policy matched"
	}
	if ans.EvaluationError != "" {
		status["evaluationError"] = ans.EvaluationError
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"metadata":   map[string]any{"creationTimestamp": nil},
		"spec":       map[string]any{"resourceAttributes": ra},
		"status":     status,
	})
}
