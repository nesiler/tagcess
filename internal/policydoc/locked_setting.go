package policydoc

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// LockedTestsKey is the settings key holding the locked test parameters as JSON (F3-020, R2
// decision 5). While it is unset the defaults apply; a stored value that does not parse or does
// not validate is an error, never silently replaced by the defaults.
const LockedTestsKey = "headscale.locked_tests"

var (
	tagPattern   = regexp.MustCompile(`^tag:[a-z0-9][a-z0-9-]{0,62}$`)
	groupPattern = regexp.MustCompile(`^group:[a-z0-9_-]{1,32}$`)
)

// ValidTag reports whether s is an acceptable Headscale tag (tag:name, lower case).
func ValidTag(s string) bool { return tagPattern.MatchString(s) }

// ValidGroup reports whether s is an acceptable Headscale group (group:name).
func ValidGroup(s string) bool { return groupPattern.MatchString(s) }

// SettingReader reads one settings row; a missing key is sql.ErrNoRows. *db.Queries satisfies it.
type SettingReader interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// Validate applies the strict settings rules: tags and groups by pattern, ports 1-65535, and at
// least one SSH destination. (Inject itself is more lenient; it only keeps the document safe.)
func (c LockedConfig) Validate() error {
	for name, v := range map[string]string{"ServerTag": c.ServerTag, "K8sTag": c.K8sTag} {
		if !ValidTag(v) {
			return fmt.Errorf("%s %q is not a valid tag", name, v)
		}
	}
	for name, v := range map[string]string{"DevopsGroup": c.DevopsGroup, "SSHSrc": c.SSHSrc} {
		if !ValidGroup(v) {
			return fmt.Errorf("%s %q is not a valid group", name, v)
		}
	}
	for name, p := range map[string]int{"UIPort": c.UIPort, "WebhookPort": c.WebhookPort, "SSHPort": c.SSHPort} {
		if !validPort(p) {
			return fmt.Errorf("%s %d is not a port (1-65535)", name, p)
		}
	}
	if len(c.SSHDst) == 0 {
		return errors.New("SSHDst is empty")
	}
	for _, d := range c.SSHDst {
		if !ValidTag(d) {
			return fmt.Errorf("SSHDst %q is not a valid tag", d)
		}
	}
	return nil
}

// Setting validates the config and returns its stored JSON form.
func (c LockedConfig) Setting() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("locked tests: encode: %w", err)
	}
	return string(b), nil
}

// LoadLocked reads the config fresh from settings. Unset yields DefaultLockedConfig(webhookPort)
// and isDefault true; a corrupt, unknown-field or invalid value is an error (fail safe).
func LoadLocked(ctx context.Context, s SettingReader, webhookPort int) (cfg LockedConfig, isDefault bool, err error) {
	raw, err := s.GetSetting(ctx, LockedTestsKey)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultLockedConfig(webhookPort), true, nil
	}
	if err != nil {
		return LockedConfig{}, false, fmt.Errorf("locked tests: read %s: %w", LockedTestsKey, err)
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return LockedConfig{}, false, fmt.Errorf("locked tests: setting %s is not valid: %w", LockedTestsKey, err)
	}
	if err := cfg.Validate(); err != nil {
		return LockedConfig{}, false, fmt.Errorf("locked tests: setting %s: %w", LockedTestsKey, err)
	}
	return cfg, false, nil
}

// LockedSource returns a function that reads the config on every call, so a changed setting is
// seen by the next policy save without a restart.
func LockedSource(s SettingReader, webhookPort int) func(ctx context.Context) (LockedConfig, error) {
	return func(ctx context.Context) (LockedConfig, error) {
		cfg, _, err := LoadLocked(ctx, s, webhookPort)
		return cfg, err
	}
}

// Weakens names the fields of next that weaken the protection compared with c: every change except
// adding SSH destinations (a superset asserts more). A changed locked source, port or tag stops
// asserting what the old value asserted, so it needs explicit approval.
func (c LockedConfig) Weakens(next LockedConfig) []string {
	var out []string
	add := func(name string, changed bool) {
		if changed {
			out = append(out, name)
		}
	}
	add("DevopsGroup", c.DevopsGroup != next.DevopsGroup)
	add("ServerTag", c.ServerTag != next.ServerTag)
	add("UIPort", c.UIPort != next.UIPort)
	add("K8sTag", c.K8sTag != next.K8sTag)
	add("WebhookPort", c.WebhookPort != next.WebhookPort)
	add("SSHSrc", c.SSHSrc != next.SSHSrc)
	add("SSHPort", c.SSHPort != next.SSHPort)
	missing := false
	for _, d := range c.SSHDst {
		if !slices.Contains(next.SSHDst, d) {
			missing = true
		}
	}
	add("SSHDst", missing)
	return out
}

// AdminGroup is the identity-provider group that may use the tagcess UI: DevopsGroup without its
// "group:" prefix. DevopsGroup is the single source of it (issue #3); validated configs only.
func (c LockedConfig) AdminGroup() string { return strings.TrimPrefix(c.DevopsGroup, "group:") }
