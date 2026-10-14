package hshelper

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const statusName = "status.json"

// Projector reads the live Headscale config and returns the secret-free view status.json carries:
// oidc.allowed_groups in canonical order and the matching base_rev. F3b-008 wires hshelper.Project.
type Projector interface {
	Project() (groups []string, baseRev string, err error)
}

// PublishStatus writes results/status.json: the last request from the journal and the current
// config view. It runs under the lock at the end of every mode. A config that cannot be read is
// published as config_error (null groups, empty rev), never as an empty list. If the journal
// cannot be read nothing is written, so the last status stays.
func PublishStatus(cfg Config) error {
	if cfg.Projector == nil {
		return errors.New("no projector configured")
	}
	j, found, err := ReadJournal(filepath.Join(cfg.Root, privateDir))
	if err != nil {
		return err
	}
	s := hostpatch.Status{Version: hostpatch.Version}
	if found {
		s.RequestID, s.State, s.Phase = j.RequestID, j.State, j.Phase
	}
	groups, rev, perr := cfg.Projector.Project()
	if perr != nil {
		s.ConfigError = hostpatch.CodeConfigUnreadable
		// Only the static reason of a ConfigError is logged; any other error may carry paths or content.
		reason := "read failed"
		var ce *ConfigError
		if errors.As(perr, &ce) {
			reason = ce.reason
		}
		cfg.logf("status: %s: %s", hostpatch.CodeConfigUnreadable, reason)
	} else {
		s.AllowedGroups, s.BaseRev = groups, rev
	}
	b, err := hostpatch.EncodeStatus(s)
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	return atomicWrite(filepath.Join(cfg.Root, resultsDir), statusName, b, 0o644)
}
