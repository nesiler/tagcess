package web

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The site settings service (F2-015): the S-06 key state lives in the settings table and changes
// only through the review flow — the approval re-plans against the target key state, stores the
// value under the writer lock with a fresh dry-run check, and applies the resync whose rendered
// Caddyfile is the new access matrix (ADR 0010 m.5).

// SiteS06Setter stores the S-06 key state.
type SiteS06Setter interface {
	SetS06Open(ctx context.Context, on bool) error
}

// SettingS06 writes the settings-table key the site settings reader reads.
type SettingS06 struct {
	Queries *db.Queries
	Clock   func() time.Time
}

// NewSettingS06 wires the S-06 key writer.
func NewSettingS06(q *db.Queries) SiteS06Setter {
	return SettingS06{Queries: q, Clock: time.Now}
}

// SetS06Open stores the key as "true"/"false", the form siteSettingsReader parses.
func (s SettingS06) SetS06Open(ctx context.Context, on bool) error {
	err := s.Queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key:       "site.s06_open",
		Value:     strconv.FormatBool(on),
		UpdatedAt: s.Clock().UTC().Format(storedTimeFormat),
	})
	if err != nil {
		return fmt.Errorf("web: set S-06 key: %w", err)
	}
	return nil
}

// errSettingsDryRun marks an approval that ran into dry-run mode: nothing is stored, the run is
// reported (Y-06.1).
var errSettingsDryRun = errors.New("web: dry-run mode is on")

// SiteS06ReviewView is the S-06 review page: the diff the flip would produce, the apply order and
// the version-bound approval. Blocked carries the reason the existing state refuses the change.
type SiteS06ReviewView struct {
	Open    bool
	Order   string
	Diff    change.SiteDiff
	Version string
	Blocked string
}
