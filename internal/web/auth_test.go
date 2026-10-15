package web

import (
	"context"
	"errors"
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

// Issue #3 AC2: with the admin group set to "ops", only actors in "ops" are admitted.
func TestRequireGroup_ConfiguredGroup(t *testing.T) {
	cases := []struct {
		name   string
		src    AdminGroupSource
		groups string
		want   int
	}{
		{"ops admitted", func(context.Context) (string, error) { return "ops", nil }, "vpn-users,ops", http.StatusOK},
		{"devops refused when ops set", func(context.Context) (string, error) { return "ops", nil }, "devops", http.StatusForbidden},
		{"prefix refused", func(context.Context) (string, error) { return "ops", nil }, "ops-readonly", http.StatusForbidden},
		{"no groups", func(context.Context) (string, error) { return "ops", nil }, "", http.StatusForbidden},
		{"nil source is devops", nil, "devops", http.StatusOK},
		{"nil source refuses ops", nil, "ops", http.StatusForbidden},
		{"source error, nothing known: refuse", func(context.Context) (string, error) { return "", errors.New("boom") }, "devops", http.StatusForbidden},
		{"empty group: refuse", func(context.Context) (string, error) { return "", nil }, "devops", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.Header.Set(headerGroups, tc.groups)
			rec := httptest.NewRecorder()
			RequireGroup(tc.src, inner).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// A failing source keeps the last good group instead of widening or opening access.
func TestRequireGroup_KeepsLastGoodOnError(t *testing.T) {
	fail := false
	src := func(context.Context) (string, error) {
		if fail {
			return "", errors.New("db down")
		}
		return "ops", nil
	}
	h := RequireGroup(src, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	do := func(groups string) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.Header.Set(headerGroups, groups)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if do("ops") != http.StatusOK {
		t.Fatal("ops not admitted")
	}
	fail = true
	if do("ops") != http.StatusOK || do("devops") != http.StatusForbidden {
		t.Fatal("last good group not kept on source error")
	}
}
