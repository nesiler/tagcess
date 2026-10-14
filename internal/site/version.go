package site

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

// Durable site source versions (A-03.4, ADR 0017). The change pipeline records one version per site
// of every applied change; the rollback screen lists them and rebuilds the source model from the
// one the operator picks. The rows live next to the site records and are never edited, except to
// bind a revision that was committed late.

// Version operations: the site operation of the change that produced the version.
const (
	VersionAdd    = "add"
	VersionUpdate = "update"
	VersionDelete = "delete"
	VersionResync = "resync"
)

// NewVersion is one version to record. Site is the source model after the change; for a delete it is
// the model the site had when it was deleted, and Deleted is set (a tombstone).
type NewVersion struct {
	SiteID     int64
	ChangeID   int64
	RollbackOf int64 // the version a rollback re-applied; 0 for an ordinary change
	Op         string
	Deleted    bool
	Site       Site
	Revision   string // the Git revision of the change's artifacts; "" while not committed
	Actor      string
	At         time.Time
}

// Version is a stored version with its source model rebuilt.
type Version struct {
	ID         int64
	SiteID     int64
	ChangeID   int64
	RollbackOf int64
	Op         string
	Deleted    bool
	Hosts      []string
	Site       Site
	Revision   string
	Actor      string
	CreatedAt  time.Time
}

// RecordVersion stores a version. It reports false, and stores nothing, when the latest version of
// the site already holds exactly this state: a resync or a no-op update does not pile up copies.
func (s *Store) RecordVersion(ctx context.Context, v NewVersion) (Version, bool, error) {
	switch {
	case v.SiteID <= 0:
		return Version{}, false, errors.New("site: version needs a site id")
	case strings.TrimSpace(v.Actor) == "":
		return Version{}, false, errors.New("site: version needs an actor")
	}
	switch v.Op {
	case VersionAdd, VersionUpdate, VersionDelete, VersionResync:
	default:
		return Version{}, false, fmt.Errorf("site: unknown version operation %q", v.Op)
	}
	body, err := MarshalSnapshot(v.Site)
	if err != nil {
		return Version{}, false, err
	}
	latest, err := s.q.LatestSiteVersion(ctx, v.SiteID)
	switch {
	case err == nil:
		if latest.Snapshot == string(body) && (latest.Deleted != 0) == v.Deleted {
			return Version{}, false, nil
		}
	case !errors.Is(err, sql.ErrNoRows):
		return Version{}, false, fmt.Errorf("site: read latest version of %d: %w", v.SiteID, err)
	}
	at := v.At
	if at.IsZero() {
		at = time.Now()
	}
	row, err := s.q.InsertSiteVersion(ctx, db.InsertSiteVersionParams{
		SiteID: v.SiteID, ChangeID: v.ChangeID, Op: v.Op, Deleted: boolToInt(v.Deleted),
		RollbackOf: v.RollbackOf, Hosts: marshalList(v.Site.Hosts), Snapshot: string(body),
		Revision: v.Revision, Actor: strings.TrimSpace(v.Actor), CreatedAt: at.UTC().Format(timeFormat),
	})
	if err != nil {
		return Version{}, false, fmt.Errorf("site: insert version: %w", err)
	}
	out, err := versionFromRow(row)
	return out, err == nil, err
}

// ListVersions returns the versions of a site, newest first. A deleted site's versions stay listed.
func (s *Store) ListVersions(ctx context.Context, siteID int64) ([]Version, error) {
	rows, err := s.q.ListSiteVersions(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("site: list versions of %d: %w", siteID, err)
	}
	out := make([]Version, 0, len(rows))
	for _, r := range rows {
		v, err := versionFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// GetVersion returns one version, or ErrNotFound.
func (s *Store) GetVersion(ctx context.Context, id int64) (Version, error) {
	row, err := s.q.GetSiteVersion(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("site: get version %d: %w", id, err)
	}
	return versionFromRow(row)
}

// BindRevision sets the revision of every version of a change that has none yet. It never replaces
// a bound revision, so a late retry cannot move a version to another commit.
func (s *Store) BindRevision(ctx context.Context, changeID int64, revision string) error {
	if strings.TrimSpace(revision) == "" {
		return errors.New("site: bind needs a revision")
	}
	if changeID <= 0 {
		// Change 0 is "no change row": binding it would hit every version that has none.
		return errors.New("site: bind needs a change id")
	}
	if _, err := s.q.BindSiteVersionRevision(ctx, db.BindSiteVersionRevisionParams{
		Revision: revision, ChangeID: changeID,
	}); err != nil {
		return fmt.Errorf("site: bind revision of change %d: %w", changeID, err)
	}
	return nil
}

func versionFromRow(r db.SiteVersion) (Version, error) {
	src, err := ParseSnapshot([]byte(r.Snapshot))
	if err != nil {
		return Version{}, fmt.Errorf("site: version %d: %w", r.ID, err)
	}
	hosts, err := unmarshalList(r.Hosts)
	if err != nil {
		return Version{}, err
	}
	at, err := parseTime(r.CreatedAt)
	if err != nil {
		return Version{}, err
	}
	return Version{
		ID: r.ID, SiteID: r.SiteID, ChangeID: r.ChangeID, RollbackOf: r.RollbackOf, Op: r.Op,
		Deleted: r.Deleted != 0, Hosts: hosts, Site: src, Revision: r.Revision, Actor: r.Actor, CreatedAt: at,
	}, nil
}
