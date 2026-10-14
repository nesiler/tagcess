package sync

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// groupsOf parses a rendered policy and returns its top-level groups.
func groupsOf(t *testing.T, policy []byte) map[string][]string {
	t.Helper()
	root, err := hujson.Parse(policy)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	root.Standardize()
	var doc struct {
		Groups map[string][]string `json:"groups"`
	}
	if err := json.Unmarshal(root.Pack(), &doc); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return doc.Groups
}

func activeInput() Input {
	return Input{
		Read: Read{
			Complete: true,
			Grants: []zitadel.Grant{
				{UserID: "1", Role: "ops"},
				{UserID: "2", Role: "dev"},
			},
			States: map[string]zitadel.UserState{"1": zitadel.UserActive, "2": zitadel.UserInactive},
		},
		Policy: []byte(`{"acls":[],"groups":{"group:ops":["https://idp/9@"],"group:old":["https://idp/3@"]}}`),
		Roles:  []string{"ops", "dev"},
		Users:  []headscale.User{{ID: 11, ProviderID: "https://idp/1"}}, // F3-031: holders need a Headscale user
		Format: render.ProviderIDFormat("https://idp"),
		Issuer: "https://idp",
	}
}

// Target renders exactly the groups Compute desired: one group per role, active members only.
func TestTarget(t *testing.T) {
	out, err := Target(activeInput())
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	groups := groupsOf(t, out)
	if len(groups) != 2 {
		t.Fatalf("groups = %v, want group:ops and group:dev", groups)
	}
	if got := groups["group:ops"]; len(got) != 1 || got[0] != "https://idp/1@" {
		t.Errorf("group:ops = %v", got)
	}
	if got, ok := groups["group:dev"]; !ok || len(got) != 0 {
		t.Errorf("group:dev = %v (present=%v), want an empty list", got, ok)
	}
	if _, ok := groups["group:old"]; ok {
		t.Errorf("group with no role survived: %v", groups)
	}
}

// F3-031: Target writes the same members Compute wants, so a holder without a Headscale user is
// left out of the rendered groups too (the policy writer renders with Target).
func TestTarget_SkipsHoldersWithoutHeadscaleUser(t *testing.T) {
	in := activeInput()
	in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: "5", Role: "ops"})
	in.Read.States["5"] = zitadel.UserActive
	out, err := Target(in)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if got := groupsOf(t, out)["group:ops"]; len(got) != 1 || got[0] != "https://idp/1@" {
		t.Errorf("group:ops = %v, want only the holder with a Headscale user", got)
	}
}

// An incomplete role set must never reach the engine: a grant for an unknown role is refused.
func TestTarget_RejectsIncompleteRoles(t *testing.T) {
	in := activeInput()
	in.Read.Grants = append(in.Read.Grants, zitadel.Grant{UserID: "3", Role: "security"})
	in.Read.States["3"] = zitadel.UserActive
	if _, err := Target(in); err == nil {
		t.Fatal("Target with a grant for an unknown role: want error")
	}
}

// Target must not render from a read it does not trust.
func TestTarget_RejectsUntrustedRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Input)
	}{
		{"read error", func(in *Input) { in.Read.Err = errors.New("boom") }},
		{"incomplete read", func(in *Input) { in.Read.Complete = false }},
		{"grant without state", func(in *Input) { delete(in.Read.States, "1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := activeInput()
			tc.mut(&in)
			if _, err := Target(in); err == nil {
				t.Fatal("Target from an untrusted read: want error")
			}
		})
	}
}

// Request must never turn an unapplicable, ungated plan (a failed read) into a change.
func TestRequest_ReadErrorBlocked(t *testing.T) {
	in := activeInput()
	in.Read.Complete = false
	p := Plan{Reason: "okuma hatası: Zitadel okuması eksik"}
	req, err := Request(in, p, "dev@example.com", "periodic", "özet")
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !req.Blocked {
		t.Fatal("a failed-read plan was not blocked")
	}
	if len(req.Target) != 0 {
		t.Fatal("a failed-read plan produced a target")
	}
	if req.Reason == "" {
		t.Error("blocked reason is empty")
	}
}

func TestSettings_Validate(t *testing.T) {
	tests := []struct {
		name    string
		set     Settings
		wantErr string
	}{
		{"default", Settings{}, ""},
		{"percent max", Settings{MaxRemovedPercent: 100}, ""},
		{"users max", Settings{MaxRemovedUsers: MaxRemovedUsersLimit}, ""},
		{"negative percent", Settings{MaxRemovedPercent: -1}, "max_removed_percent"},
		{"too large percent", Settings{MaxRemovedPercent: 101}, "max_removed_percent"},
		{"negative users", Settings{MaxRemovedUsers: -1}, "max_removed_users"},
		{"too large users", Settings{MaxRemovedUsers: MaxRemovedUsersLimit + 1}, "max_removed_users"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.set.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate(%+v) = %v, want nil", tt.set, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate(%+v) = %v, want an error containing %q", tt.set, err, tt.wantErr)
			}
		})
	}
}

// Request carries the plan's gates and the rendered target into the change pipeline.
func TestRequest(t *testing.T) {
	in := activeInput()
	p := Plan{
		NeedsApproval: true,
		Reason:        "eşik aşıldı",
		ExpireNodes:   []NodeExpiry{{NodeID: 7, UserID: "2"}, {NodeID: 8, UserID: "3"}},
	}
	req, err := Request(in, p, "dev@example.com", "manual", "özet")
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !req.NeedsApproval || req.DryRun || req.Blocked {
		t.Errorf("gates = %+v", req)
	}
	if req.Actor != "dev@example.com" || req.Trigger != "manual" || req.Summary != "özet" {
		t.Errorf("metadata = %+v", req)
	}
	if len(req.Expire) != 2 || req.Expire[0] != 7 || req.Expire[1] != 8 {
		t.Errorf("expire = %v, want [7 8]", req.Expire)
	}
	if len(req.Target) == 0 {
		t.Error("target was not rendered")
	}
	if string(req.SourcePolicy) != string(in.Policy) {
		t.Errorf("source policy = %q, want the input policy %q", req.SourcePolicy, in.Policy)
	}

	// Dry run read from settings also covers Compute's early returns, which drop the plan's flag.
	in.Settings.DryRun = true
	dry, err := Request(in, p, "dev@example.com", "manual", "özet")
	if err != nil {
		t.Fatalf("Request (dry run): %v", err)
	}
	if !dry.DryRun {
		t.Error("dry-run setting was not carried into the request")
	}
	in.Settings.DryRun = false

	in.Settings.MaxRemovedPercent = -1
	if _, err := Request(in, p, "dev@example.com", "manual", "özet"); err == nil {
		t.Error("Request with an invalid threshold: want error")
	}
}
