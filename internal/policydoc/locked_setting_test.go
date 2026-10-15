package policydoc

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
)

// mapSettings is a settings store over a map; a missing key is sql.ErrNoRows like the real one.
type mapSettings map[string]string

func (m mapSettings) GetSetting(_ context.Context, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", sql.ErrNoRows
	}
	return v, nil
}

func TestLockedSetting_RoundTrip(t *testing.T) {
	cfg := DefaultLockedConfig(9000)
	cfg.UIPort = 8443
	cfg.SSHDst = []string{"tag:vpn-server", "tag:k8s", "tag:db"}
	raw, err := cfg.Setting()
	if err != nil {
		t.Fatalf("Setting: %v", err)
	}
	got, isDefault, err := LoadLocked(t.Context(), mapSettings{LockedTestsKey: raw}, 1234)
	if err != nil || isDefault {
		t.Fatalf("LoadLocked = %v, default %v", err, isDefault)
	}
	if got.UIPort != 8443 || got.WebhookPort != 9000 || !slices.Equal(got.SSHDst, cfg.SSHDst) || got.ServerTag != cfg.ServerTag {
		t.Errorf("round trip = %+v, want %+v", got, cfg)
	}
	again, _ := got.Setting()
	if again != raw {
		t.Errorf("encoding is not deterministic: %q vs %q", again, raw)
	}
}

func TestLockedSetting_Validation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*LockedConfig)
	}{
		{"server tag uppercase", func(c *LockedConfig) { c.ServerTag = "tag:VPN" }},
		{"server tag no prefix", func(c *LockedConfig) { c.ServerTag = "vpn-server" }},
		{"k8s tag with space", func(c *LockedConfig) { c.K8sTag = "tag:k8s x" }},
		{"tag too long", func(c *LockedConfig) { c.ServerTag = "tag:a" + strings.Repeat("b", 63) }},
		{"devops group bad", func(c *LockedConfig) { c.DevopsGroup = "devops" }},
		{"ssh src quote", func(c *LockedConfig) { c.SSHSrc = `group:de"vops` }},
		{"ssh dst bad", func(c *LockedConfig) { c.SSHDst = []string{"tag:ok", "group:x"} }},
		{"ssh dst empty", func(c *LockedConfig) { c.SSHDst = nil }},
		{"ui port zero", func(c *LockedConfig) { c.UIPort = 0 }},
		{"webhook port high", func(c *LockedConfig) { c.WebhookPort = 65536 }},
		{"ssh port negative", func(c *LockedConfig) { c.SSHPort = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultLockedConfig(9000)
			tc.mut(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate accepted it")
			}
			if _, err := cfg.Setting(); err == nil {
				t.Fatal("Setting encoded it")
			}
		})
	}
	if err := DefaultLockedConfig(9000).Validate(); err != nil {
		t.Errorf("defaults rejected: %v", err)
	}
}

func TestLoadLocked_UnsetIsDefaultAndBadIsError(t *testing.T) {
	got, isDefault, err := LoadLocked(t.Context(), mapSettings{}, 9100)
	if err != nil || !isDefault {
		t.Fatalf("unset: %v, default %v", err, isDefault)
	}
	if want := DefaultLockedConfig(9100); got.WebhookPort != 9100 || got.ServerTag != want.ServerTag {
		t.Errorf("unset = %+v", got)
	}
	for name, raw := range map[string]string{
		"not json":      "nope",
		"unknown field": `{"server_tag":"tag:a","extra":1}`,
		"invalid value": `{"devops_group":"group:devops","server_tag":"TAG","ui_port":443,"k8s_tag":"tag:k8s","webhook_port":9000,"ssh_src":"group:devops","ssh_dst":["tag:a"],"ssh_port":22}`,
		"missing port":  `{"devops_group":"group:devops","server_tag":"tag:a","k8s_tag":"tag:k8s","webhook_port":9000,"ssh_src":"group:devops","ssh_dst":["tag:a"],"ssh_port":22}`,
	} {
		if _, _, err := LoadLocked(t.Context(), mapSettings{LockedTestsKey: raw}, 9000); err == nil {
			t.Errorf("%s: LoadLocked accepted %q", name, raw)
		}
	}
	// A read error other than "not set" is an error, never the default.
	if _, _, err := LoadLocked(t.Context(), errSettings{}, 9000); err == nil {
		t.Error("read error was swallowed")
	}
}

type errSettings struct{}

func (errSettings) GetSetting(context.Context, string) (string, error) {
	return "", errors.New("db down")
}

func TestLockedConfig_Weakens(t *testing.T) {
	base := DefaultLockedConfig(9000)
	cases := []struct {
		name string
		mut  func(*LockedConfig)
		want []string
	}{
		{"same", func(*LockedConfig) {}, nil},
		{"ssh dst added", func(c *LockedConfig) { c.SSHDst = append(c.SSHDst, "tag:db") }, nil},
		{"ssh dst reordered", func(c *LockedConfig) { c.SSHDst = []string{"tag:k8s", "tag:vpn-server"} }, nil},
		{"ssh dst removed", func(c *LockedConfig) { c.SSHDst = []string{"tag:vpn-server"} }, []string{"SSHDst"}},
		{"ui port", func(c *LockedConfig) { c.UIPort = 8443 }, []string{"UIPort"}},
		{"webhook port", func(c *LockedConfig) { c.WebhookPort = 9001 }, []string{"WebhookPort"}},
		{"ssh src", func(c *LockedConfig) { c.SSHSrc = "group:ops" }, []string{"SSHSrc"}},
		{"two fields", func(c *LockedConfig) { c.ServerTag = "tag:gw"; c.K8sTag = "tag:k" }, []string{"ServerTag", "K8sTag"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := base
			next.SSHDst = slices.Clone(base.SSHDst)
			tc.mut(&next)
			if got := base.Weakens(next); !slices.Equal(got, tc.want) {
				t.Errorf("Weakens = %v, want %v", got, tc.want)
			}
		})
	}
}

// Issue #3 AC1/AC5: DevopsGroup is the single admin-group source; bad names are refused on save.
func TestLockedSetting_AdminGroup(t *testing.T) {
	cfg := DefaultLockedConfig(9000)
	if got := cfg.AdminGroup(); got != "devops" {
		t.Fatalf("default AdminGroup = %q, want devops", got)
	}
	cfg.DevopsGroup = "group:ops"
	if got := cfg.AdminGroup(); got != "ops" {
		t.Fatalf("AdminGroup = %q, want ops", got)
	}
	for _, bad := range []string{"group:", "", "group:a b", "group:a/b", "group:a?b", "group:a&allowed_groups=x", "group:a,b", "group:ä"} {
		c := DefaultLockedConfig(9000)
		c.DevopsGroup = bad
		if _, err := c.Setting(); err == nil {
			t.Errorf("Setting accepted DevopsGroup %q", bad)
		}
	}
}
