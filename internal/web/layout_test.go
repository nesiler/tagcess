package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/store/db"
)

// renderAt renders c as Layout would see it for a request to path (WithShell without a status).
func renderAt(t *testing.T, path string, c templ.Component) string {
	t.Helper()
	var b bytes.Buffer
	h := WithShell(nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if err := c.Render(r.Context(), &b); err != nil {
			t.Fatalf("render: %v", err)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
	return b.String()
}

func TestNavCurrent(t *testing.T) {
	tests := []struct {
		path, active, want string
	}{
		{"/", "pano", "/"},
		{"/alerts", "pano", "/alerts"},
		{"/sites/3/edit", "siteler", "/sites"},
		{"/headscale/devices/7/tags", "headscale", "/headscale/devices"},
		{"/headscale/keys/api", "headscale", "/headscale/keys"},
		{"/k8s/drafts/app.example.com", "k8s", "/k8s/discovery"},
		{"/monitor/settings", "pano", "/settings"},
		// A path no entry owns falls back to the first entry of the active area.
		{"/unknown", "headscale", "/headscale/devices"},
		// "/" owns only itself, so it never swallows another path.
		{"/syncx", "sync", "/sync"},
		{"", "audit", "/audit"},
	}
	for _, tc := range tests {
		if got := navCurrent(tc.path, tc.active); got != tc.want {
			t.Errorf("navCurrent(%q, %q) = %q, want %q", tc.path, tc.active, got, tc.want)
		}
	}
}

type fakeShellStatus struct {
	st  ShellStatus
	err error
}

func (f fakeShellStatus) ShellStatus(context.Context) (ShellStatus, error) { return f.st, f.err }

// The top bar shows dry-run and pending changes on every page, and says so when it cannot read them
// instead of showing nothing (fail safe).
func TestLayout_ShellStatus(t *testing.T) {
	tests := []struct {
		name    string
		src     ShellStatusSource
		want    []string
		notWant []string
	}{
		{"quiet", fakeShellStatus{}, nil, []string{"dry-run açık", "onay bekleyen", "okunamadı"}},
		{"dry-run and pending", fakeShellStatus{st: ShellStatus{DryRun: true, Pending: 2}}, []string{"dry-run açık", "2 onay bekleyen değişiklik"}, []string{"okunamadı"}},
		{"unreadable", fakeShellStatus{err: errors.New("db down")}, []string{"sync durumu okunamadı"}, []string{"dry-run açık"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			h := WithShell(tc.src, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				_ = Layout(Actor{Email: "a@example.com"}, "token", "pano", "Pano", templ.Raw("")).Render(r.Context(), &b)
			}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
			page := b.String()
			for _, w := range tc.want {
				if !strings.Contains(page, w) {
					t.Errorf("top bar lacks %q", w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(page, w) {
					t.Errorf("top bar shows %q", w)
				}
			}
		})
	}
}

func TestInitials(t *testing.T) {
	tests := []struct {
		actor Actor
		want  string
	}{
		{Actor{Email: "carol.example@example.com"}, "CE"},
		{Actor{Email: "jdoe@example.com"}, "J"},
		{Actor{User: "deniz-kaya"}, "DK"},
		{Actor{}, "?"},
	}
	for _, tc := range tests {
		if got := initials(tc.actor); got != tc.want {
			t.Errorf("initials(%+v) = %q, want %q", tc.actor, got, tc.want)
		}
	}
}

type fakePending struct {
	n   int
	err error
}

func (f fakePending) ListPendingChanges(context.Context) ([]db.Change, error) {
	return make([]db.Change, f.n), f.err
}

func TestNewShellStatus(t *testing.T) {
	got, err := NewShellStatus(&fakeDryRunReader{on: true}, fakePending{n: 3}).ShellStatus(context.Background())
	if err != nil || got != (ShellStatus{DryRun: true, Pending: 3}) {
		t.Errorf("status = %+v, %v; want dry-run with 3 pending", got, err)
	}
	if _, err := NewShellStatus(&fakeDryRunReader{err: errors.New("x")}, fakePending{}).ShellStatus(context.Background()); err == nil {
		t.Error("a dry-run read error was hidden")
	}
	if _, err := NewShellStatus(&fakeDryRunReader{}, fakePending{err: errors.New("x")}).ShellStatus(context.Background()); err == nil {
		t.Error("a pending-changes read error was hidden")
	}
}
