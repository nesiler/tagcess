//go:build integration

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// TestDeviceActions_Integration (F3-014 AC9) runs every device action against the real Headscale
// v0.29.4 in the disposable hsstack fixture: rename, expire now, set a future expiry, disable the
// expiry and the two-step delete, each through the executor with a verified read-back.
func TestDeviceActions_Integration(t *testing.T) {
	ctx := context.Background()
	h := hsstack.Start(t)
	c, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// The fixture policy only knows tag:server; it is the protected tag here.
	if err := st.Queries().UpsertSetting(ctx, db.UpsertSettingParams{
		Key: hsadmin.ProtectedTagsKey, Value: `["tag:server"]`, UpdatedAt: "2026-10-01T00:00:00.000Z",
	}); err != nil {
		t.Fatal(err)
	}
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(st.Queries()), Store: st.Queries()})
	svc, err := NewDeviceActionsService(c, ex)
	if err != nil {
		t.Fatal(err)
	}
	csrf := testCSRF(t)
	handler, err := NewDeviceActionsHandler(svc, csrf)
	if err != nil {
		t.Fatal(err)
	}

	h.CreateUser(t, "ops")
	laptop := h.NewNode(t, "ops", "laptop", "")
	gw := h.NewNode(t, "ops", "gw", "")
	if _, err := c.SetTags(ctx, gw, []string{"tag:server"}); err != nil {
		t.Fatalf("SetTags: %v", err)
	}

	mk := func(id uint64) *deviceActionSession {
		s := &deviceActionSession{t: t, csrf: csrf, id: id}
		s.read(c)
		return s
	}

	// Rename: applied and visible on a fresh read.
	s := mk(laptop)
	s.post(t, handler, "/rename", url.Values{"name": {"laptop-2"}})
	s.wantApplied(t)
	if nodes, err := c.ListNodes(ctx); err != nil {
		t.Fatal(err)
	} else {
		for _, n := range nodes {
			if n.ID == laptop && n.GivenName != "laptop-2" {
				t.Fatalf("given name = %q, want laptop-2", n.GivenName)
			}
		}
	}

	// Set a future expiry, then disable it again.
	s = mk(laptop)
	s.post(t, handler, "/expiry", url.Values{"expiry": {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")}})
	s.wantApplied(t)
	if exp := h.NodeExpiry(t, laptop); exp == nil || !exp.After(time.Now()) {
		t.Fatalf("expiry = %v, want a future instant", exp)
	}
	s = mk(laptop)
	s.post(t, handler, "/expiry/disable", nil)
	s.wantApplied(t)
	if exp := h.NodeExpiry(t, laptop); exp != nil {
		t.Fatalf("expiry = %v, want none", exp)
	}

	// Expire now: the expiry lands in the past.
	s = mk(laptop)
	s.post(t, handler, "/expire", nil)
	s.wantApplied(t)
	if exp := h.NodeExpiry(t, laptop); exp == nil || exp.After(time.Now()) {
		t.Fatalf("expiry = %v, want a past instant", exp)
	}

	// The protected server node refuses the destructive forms.
	s = mk(gw)
	s.post(t, handler, "/delete", url.Values{"confirm": {"evet"}})
	s.wantStatus(t, http.StatusConflict)
	s.post(t, handler, "/expire", nil)
	s.wantStatus(t, http.StatusConflict)
	if nodes, err := c.ListNodes(ctx); err != nil {
		t.Fatal(err)
	} else {
		found := false
		for _, n := range nodes {
			if n.ID == gw {
				found = true
			}
		}
		if !found {
			t.Fatal("protected node was deleted")
		}
	}

	// Delete the personal node: the confirmed POST removes it.
	s = mk(laptop)
	s.post(t, handler, "/delete", url.Values{"confirm": {"evet"}})
	s.wantApplied(t)
	if nodes, err := c.ListNodes(ctx); err != nil {
		t.Fatal(err)
	} else {
		for _, n := range nodes {
			if n.ID == laptop {
				t.Fatalf("node %d still listed after delete", laptop)
			}
		}
	}
}

// deviceActionSession carries one form's shown state between a read and its POST.
type deviceActionSession struct {
	t        *testing.T
	csrf     *CSRF
	id       uint64
	name     string
	version  string
	expiryOf string
	last     *httptest.ResponseRecorder
}

func (s *deviceActionSession) read(c *admin.AdminClient) {
	s.t.Helper()
	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		s.t.Fatal(err)
	}
	for _, n := range nodes {
		if n.ID == s.id {
			s.version = hsadmin.NodeVersion(n)
			s.name = n.GivenName
			_, s.expiryOf, _ = expiryText(n.Expiry, time.Now())
			return
		}
	}
	s.t.Fatalf("node %d missing", s.id)
}

func (s *deviceActionSession) post(t *testing.T, handler *DeviceActionsHandler, action string, extra url.Values) {
	t.Helper()
	fields := url.Values{
		"expected":     {s.version},
		"current_name": {s.name},
	}
	if s.expiryOf != "" {
		fields.Set("current_expiry", s.expiryOf)
	}
	for k, v := range extra {
		fields[k] = v
	}
	fields.Set(CSRFParam, s.csrf.Token())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/headscale/devices/"+uintText(s.id)+action, strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(headerUser, "devops-user")
	req.Header.Set(headerEmail, "devops@example.com")
	req.Header.Set(headerGroups, "devops")
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	handler.Register(mux)
	RequireDevops(s.csrf.Protect(mux)).ServeHTTP(rec, req)
	t.Logf("POST %s%s = %d", uintText(s.id), action, rec.Code)
	s.last = rec
}

func (s *deviceActionSession) wantApplied(t *testing.T) {
	t.Helper()
	if s.last.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", s.last.Code, s.last.Body.String())
	}
	if !strings.Contains(s.last.Body.String(), "Apply edildi") {
		t.Fatalf("result screen lacks the applied status:\n%s", s.last.Body.String())
	}
}

func (s *deviceActionSession) wantStatus(t *testing.T, code int) {
	t.Helper()
	if s.last.Code != code {
		t.Fatalf("status = %d, want %d:\n%s", s.last.Code, code, s.last.Body.String())
	}
}
