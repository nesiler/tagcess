package site

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// settingAllowedTargets is the settings key of the UI-editable custom target host allowlist
// (F2-013 AC5). Config seeds it once; after that it is the source of truth and the validator
// reads it on every check.
const settingAllowedTargets = "site.allowed_targets"

// ErrTargetInUse is returned when a new allowlist would drop a host some stored url target still
// points at: the change is refused so no existing site is silently invalidated.
var ErrTargetInUse = errors.New("site: the target host is still used by a site")

// AllowedTargets is the custom target host allowlist the interface edits. It stores the list in
// settings and implements the validator's TargetSource, so a change made in the UI takes effect
// on the next validation without a restart.
type AllowedTargets struct {
	db *sql.DB
	q  *db.Queries
}

// NewAllowedTargets returns the allowlist store over an open database and its queries.
func NewAllowedTargets(sqldb *sql.DB, q *db.Queries) *AllowedTargets {
	return &AllowedTargets{db: sqldb, q: q}
}

// ListTargets reads the current allowlist on every call (TargetSource). A missing, unreadable or
// invalid setting is an error, never an empty allowlist: the validator fails closed.
func (a *AllowedTargets) ListTargets(ctx context.Context) ([]string, error) {
	raw, err := a.q.GetSetting(ctx, settingAllowedTargets)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("site: %s is not set", settingAllowedTargets)
	}
	if err != nil {
		return nil, fmt.Errorf("site: read %s: %w", settingAllowedTargets, err)
	}
	return decodeTargets(raw)
}

// SeedIfMissing writes the config default once, when the setting does not exist yet (F2-013). An
// existing value is left untouched, so an edit made in the UI is never overwritten on restart.
func (a *AllowedTargets) SeedIfMissing(ctx context.Context, defaults []string) error {
	if err := ValidateTargetList(defaults); err != nil {
		return err
	}
	_, err := a.q.GetSetting(ctx, settingAllowedTargets)
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("site: read %s: %w", settingAllowedTargets, err)
	}
	return a.transact(ctx, func(q *db.Queries) error {
		return writeTargets(ctx, q, defaults)
	})
}

// Set validates and stores a new allowlist. The "still used by a site" check and the write run in
// one transaction, so a concurrent site write (serialized by the caller's writer lock,
// change.WithWriterLock) cannot leave a stored url target outside the new list. A list that would
// invalidate an existing site is refused with ErrTargetInUse.
func (a *AllowedTargets) Set(ctx context.Context, list []string) error {
	if err := ValidateTargetList(list); err != nil {
		return err
	}
	return a.transact(ctx, func(q *db.Queries) error {
		rows, err := q.ListSites(ctx)
		if err != nil {
			return fmt.Errorf("site: list sites: %w", err)
		}
		for _, row := range rows {
			if row.TargetKind != TargetURL {
				continue
			}
			host, err := targetHost(row.TargetUrl)
			if err != nil {
				return fmt.Errorf("site: site %d: %w", row.ID, err)
			}
			if !containsFold(list, host) {
				return fmt.Errorf("%w: site %d uses %q", ErrTargetInUse, row.ID, host)
			}
		}
		return writeTargets(ctx, q, list)
	})
}

// targetHost extracts the hostname the validator compared when the site was stored.
func targetHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("stored target url %q is unreadable", raw)
	}
	return u.Hostname(), nil
}

func containsFold(list []string, v string) bool {
	for _, e := range list {
		if strings.EqualFold(e, v) {
			return true
		}
	}
	return false
}

// decodeTargets reads and re-validates the stored list.
func decodeTargets(raw string) ([]string, error) {
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("site: parse %s: %w", settingAllowedTargets, err)
	}
	if err := ValidateTargetList(list); err != nil {
		return nil, err
	}
	return list, nil
}

// writeTargets stores the list as compact JSON in one transaction-provided query set.
func writeTargets(ctx context.Context, q *db.Queries, list []string) error {
	body, err := json.Marshal(nonNil(list))
	if err != nil {
		return fmt.Errorf("site: marshal %s: %w", settingAllowedTargets, err)
	}
	if err := q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key:       settingAllowedTargets,
		Value:     string(body),
		UpdatedAt: time.Now().UTC().Format(timeFormat),
	}); err != nil {
		return fmt.Errorf("site: write %s: %w", settingAllowedTargets, err)
	}
	return nil
}

// transact runs fn in one transaction, rolling everything back when fn fails.
func (a *AllowedTargets) transact(ctx context.Context, fn func(q *db.Queries) error) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("site: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op once Commit has succeeded
	if err := fn(a.q.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("site: commit: %w", err)
	}
	return nil
}
