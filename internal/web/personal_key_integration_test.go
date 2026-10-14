//go:build integration

package web

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/hsstack"
)

// AC9 on real Headscale: a key made for an eligible user lists bound to that user, one-time and
// untagged, with the explicit expiry; an ineligible user gets no key. Zitadel is a fixed fake here
// (there is no local Zitadel); the Headscale side, the executor and the audit are the real ones.
func TestPersonalKey_Integration_Create(t *testing.T) {
	h := hsstack.Start(t)
	ctx := context.Background()
	uid := h.CreateUser(t, "alice")
	h.SetProviderID(t, "alice", personalIssuer+"/z1")
	h.CreateUser(t, "norole")
	h.SetProviderID(t, "norole", personalIssuer+"/z2")

	c, err := admin.NewAdmin(headscale.Config{Target: h.GRPCAddr(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	z := &fakeKeyZitadel{
		grants: []zitadel.Grant{{UserID: "z1", Role: "vpn-user"}},
		states: map[string]zitadel.UserState{"z1": zitadel.UserActive, "z2": zitadel.UserActive},
	}
	resolver, err := vpnuser.NewResolver(z, personalIssuer)
	if err != nil {
		t.Fatal(err)
	}
	ex := hsadmin.New(hsadmin.Config{Reader: c, Audit: audit.New(s.Queries()), Store: s.Queries()})
	svc, err := NewPersonalKeyService(PersonalKeyServiceConfig{Admin: c, Users: h.Client(), Resolver: resolver, Exec: ex, Issuer: personalIssuer})
	if err != nil {
		t.Fatal(err)
	}

	out := svc.Create(ctx, "devops@example.com", PersonalKeyInput{User: "1", ExpiresIn: "2h"})
	if out.Status != keyApplied || !strings.HasPrefix(out.Secret, "hskey-auth-") {
		t.Fatalf("Create = %+v", out)
	}
	keys, err := c.ListPreAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys = %+v, want exactly the created one", keys)
	}
	k := keys[0]
	if k.ID != out.KeyID || k.UserID != uid || k.UserName != "alice" || k.Reusable || k.Ephemeral || k.Used || len(k.Tags) != 0 {
		t.Errorf("listed key = %+v, want a one-time untagged key bound to alice", k)
	}
	if k.Expiration == nil || time.Until(*k.Expiration) < time.Hour || time.Until(*k.Expiration) > 2*time.Hour+time.Minute {
		t.Errorf("expiration = %v, want about 2h from now", k.Expiration)
	}

	// A user without a role gets no key; nothing is made.
	if out := svc.Create(ctx, "devops@example.com", PersonalKeyInput{User: "2"}); out.Status != keyRefused {
		t.Errorf("user without a role = %+v", out)
	}
	if keys, _ := c.ListPreAuthKeys(ctx); len(keys) != 1 {
		t.Errorf("keys after the refusal = %d, want 1", len(keys))
	}
}
