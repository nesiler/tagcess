package change

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/gitlog"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The pipelines hand their verified final artifacts to the local history (A-02, ADR 0016) after the
// apply was read back and verified, and only then: a request that failed, was blocked, rolled back,
// ran dry or whose outcome is unknown commits nothing. A commit that fails never changes the
// result of the change: the verified live state stays, gitlog has already written the audit event
// and the critical alert and queued the commit as a durable, ordered retry intent, and the result
// reports no revision (GitFailed) instead of passing the missing one off as a success.

// File names of the artifacts in the history repository.
const (
	GitFileCaddyfile    = "Caddyfile"
	GitFileMagicDNS     = "magicdns.json"
	GitFileRedirectURIs = "zitadel-redirect-uris.txt"
	GitFilePolicy       = "policy.hujson"
)

// ArtifactGit is the local history (satisfied by *gitlog.Log). Pending is how a clean commit learns
// that no earlier intent is still waiting.
type ArtifactGit interface {
	Commit(ctx context.Context, req gitlog.CommitRequest) (gitlog.Result, error)
	Pending(ctx context.Context) ([]gitlog.Retry, error)
}

const gitRefPrefix = "site-change:"

// GitRef is the opaque reference a site change hands to the history. A commit that had to be queued
// reports it back, with the real revision, when it is finally committed.
func GitRef(changeID int64) string { return gitRefPrefix + strconv.FormatInt(changeID, 10) }

// SiteRevisionBinder binds a late revision to the versions of a change (satisfied by *site.Store).
type SiteRevisionBinder interface {
	BindRevision(ctx context.Context, changeID int64, revision string) error
}

// NewRevisionBinder returns the gitlog.Config.OnRetried hook that binds the revision of a queued
// site change to its durable versions (A-03.4). A reference that is not a site change's is ignored.
func NewRevisionBinder(b SiteRevisionBinder) func(ctx context.Context, ref, revision string) error {
	return func(ctx context.Context, ref, revision string) error {
		rest, ok := strings.CutPrefix(ref, gitRefPrefix)
		if !ok {
			return nil
		}
		id, err := strconv.ParseInt(rest, 10, 64)
		if err != nil || id <= 0 {
			return nil
		}
		return b.BindRevision(ctx, id, revision)
	}
}

// NewGitAlerter returns the gitlog.Alerter over the alerts table: a repeated alert keeps one row.
func NewGitAlerter(q *db.Queries) gitlog.Alerter { return gitAlerter{q: q} }

type gitAlerter struct{ q *db.Queries }

func (a gitAlerter) Raise(ctx context.Context, kind, source string) error {
	now := time.Now().UTC().Format(timeFormat)
	touched, err := a.q.TouchAlert(ctx, db.TouchAlertParams{LastSeenAt: now, Kind: kind, Source: source})
	if err != nil {
		return fmt.Errorf("change: touch %s alert: %w", kind, err)
	}
	if touched > 0 {
		return nil
	}
	if _, err := a.q.InsertAlert(ctx, db.InsertAlertParams{Kind: kind, Source: source, FirstSeenAt: now, LastSeenAt: now}); err != nil {
		return fmt.Errorf("change: raise %s alert: %w", kind, err)
	}
	return nil
}

// commitVerified hands the verified artifacts to the history. It returns the revision, or "" and
// failed=true when the history could not commit them (already audited, alerted and queued by
// gitlog). A pipeline without a history returns "", false. A clean commit with no intent left in the
// queue resolves the history's alerts: that is the only proof the problem is gone.
func commitVerified(ctx context.Context, git ArtifactGit, q *db.Queries, req gitlog.CommitRequest) (revision string, failed bool) {
	if git == nil {
		return "", false
	}
	res, err := git.Commit(ctx, req)
	if err != nil || res.Revision == "" {
		return "", true
	}
	if pending, err := git.Pending(ctx); err == nil && len(pending) == 0 {
		now := sql.NullString{String: time.Now().UTC().Format(timeFormat), Valid: true}
		for _, kind := range []string{gitlog.AlertGitFailed, gitlog.AlertGitSecret} {
			// Best effort: a stale alert is only noise, it never widens access.
			_, _ = q.ResolveAlertKind(ctx, db.ResolveAlertKindParams{ResolvedAt: now, Kind: kind})
		}
	}
	return res.Revision, false
}
