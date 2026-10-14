package policywriter

import (
	"context"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/policyrev"
)

// Recorder stores the policy revision of every apply the change pipeline makes (H-04): the editor's
// saves and the sync's group writes. It satisfies change.PolicyRevisions.
type Recorder struct{ repo *policyrev.Repo }

// NewRecorder returns a recorder over repo.
func NewRecorder(repo *policyrev.Repo) *Recorder { return &Recorder{repo: repo} }

// Begin stores the pending revision of req before the write. A request without revision metadata
// comes from the sync flow.
func (r *Recorder) Begin(ctx context.Context, req change.Request, changeID int64) (int64, error) {
	meta := req.Revision
	source := policyrev.Source(meta.Source)
	if source == "" {
		source = policyrev.SourceSync
	}
	reason := meta.Reason
	if reason == "" {
		reason = req.Summary
	}
	base := ""
	if len(req.SourcePolicy) > 0 {
		base = policyrev.HashRaw(string(req.SourcePolicy))
	}
	rev, err := r.repo.Add(ctx, policyrev.NewRevision{
		BaseHash:   base,
		Raw:        string(req.Target),
		Source:     source,
		Actor:      req.Actor,
		Reason:     reason,
		Validation: meta.Validation,
		ChangeID:   changeID,
		RollbackOf: meta.RollbackOf,
	})
	if err != nil {
		return 0, err
	}
	return rev.ID, nil
}

// Finish moves the revision to its final outcome.
func (r *Recorder) Finish(ctx context.Context, id int64, outcome, detail string) error {
	return r.repo.Finish(ctx, id, policyrev.Status(outcome), detail)
}
