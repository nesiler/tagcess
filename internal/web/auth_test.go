package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// AC1: a request whose X-Auth-Request-Groups contains "devops" reaches the handler and the actor is
// bound to its context.
func TestAuth_DevopsAllowed(t *testing.T) {
	var got Actor
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		a, ok := ActorFrom(r.Context())
		if !ok {
			t.Error("ActorFrom: actor not bound to request")
		}
		got = a
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("page"))
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set(headerUser, "alice")
	req.Header.Set(headerEmail, "alice@example.com")
	req.Header.Set(headerGroups, "vpn-users,devops")
	rec := httptest.NewRecorder()
	RequireDevops(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "page" {
		t.Fatalf("status = %d, body = %q, want 200 page", rec.Code, rec.Body.String())
	}
	if !called {
		t.Fatal("inner handler was not called")
	}
	if got.User != "alice" || got.Email != "alice@example.com" {
		t.Errorf("actor = %+v, want alice <alice@example.com>", got)
	}
	if !slices.Contains(got.Groups, "devops") {
		t.Errorf("actor groups = %v, want devops", got.Groups)
	}
}

// The header may arrive as separate lines (oauth2-proxy joins groups differently across versions).
func TestAuth_DevopsInSeparateHeaderLines(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Add(headerGroups, "billing")
	req.Header.Add(headerGroups, "devops")
	rec := httptest.NewRecorder()
	RequireDevops(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("status = %d, called = %v, want 200 true", rec.Code, called)
	}
}

// AC2: without "devops", or with no groups header at all, the request is forbidden and the handler
// never runs.
func TestAuth_NonDevopsForbidden(t *testing.T) {
	cases := []struct {
		name   string
		groups []string
	}{
		{"no headers", nil},
		{"unrelated group", []string{"vpn-users"}},
		{"prefix of devops", []string{"devops-readonly"}},
		{"empty groups header", []string{""}},
		{"only whitespace", []string{" , "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.Header.Set(headerUser, "bob")
			for _, g := range tc.groups {
				req.Header.Add(headerGroups, g)
			}
			rec := httptest.NewRecorder()
			RequireDevops(inner).ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			if called {
				t.Error("inner handler ran for a non-devops request")
			}
		})
	}
}

func TestActorFrom_NoActor(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if _, ok := ActorFrom(req.Context()); ok {
		t.Fatal("ActorFrom reported an actor for a bare request")
	}
}
