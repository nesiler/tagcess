package hostapply

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nesiler/tagcess/internal/store/db"
)

type fakeAlerts struct {
	rows []db.Alert
	err  error
}

func (f fakeAlerts) ListOpenAlerts(context.Context) ([]db.Alert, error) { return f.rows, f.err }

func TestUnknownSources(t *testing.T) {
	ctx := context.Background()
	alerts := fakeAlerts{rows: []db.Alert{
		{Kind: "headscale_admin_unverified", Source: "hsadmin:node.expire:node:4"},
		{Kind: "sync_read_failed", Source: "zitadel"},
		{Kind: "key_revoke_failed", Source: "headscale"},
	}}
	policy := func(context.Context) (string, error) { return "revision #3 (unknown)", nil }

	got, err := NewUnknowns(policy, alerts, "headscale_admin_unverified", "key_revoke_failed").Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []Unknown{
		{Kind: "policy", Detail: "revision #3 (unknown)"},
		{Kind: "headscale_admin_unverified", Detail: "hsadmin:node.expire:node:4"},
		{Kind: "key_revoke_failed", Detail: "headscale"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Open = %v, want %v", got, want)
	}

	clean := func(context.Context) (string, error) { return "", nil }
	if got, err := NewUnknowns(clean, fakeAlerts{}, "key_revoke_failed").Open(ctx); err != nil || len(got) != 0 {
		t.Errorf("clean Open = %v, %v; want none", got, err)
	}
	boom := errors.New("boom")
	if _, err := NewUnknowns(func(context.Context) (string, error) { return "", boom }, fakeAlerts{}).Open(ctx); !errors.Is(err, boom) {
		t.Errorf("policy read error = %v, want %v", err, boom)
	}
	if _, err := NewUnknowns(clean, fakeAlerts{err: boom}).Open(ctx); !errors.Is(err, boom) {
		t.Errorf("alert read error = %v, want %v", err, boom)
	}
}
