package policywriter

import (
	"context"
	"fmt"

	"github.com/nesiler/tagcess/internal/policyrev"
)

// The recovery of an uncertain policy state (F3-029, R2 karar 20/163). It is Save and Preview with
// source=recovery: the writer takes the last applied revision as the target, rebuilds the candidate
// from its raw text with today's Zitadel groups and the locked tests, validates it against Headscale,
// and — only on an explicit Save — applies it under the writer lock and reads it back. Every refusal
// of a normal save applies (Zitadel or Headscale unreadable, a stale base, a held sync, an invalid
// candidate); the approval never skips a check. A failed or unverifiable recovery leaves the state
// uncertain and restores nothing; nothing calls it except the recovery page.

// recoveryTarget is the newest applied revision (the external baseline counts as applied); a failed,
// unknown, pending or dry-run revision never is.
func (w *Writer) recoveryTarget(ctx context.Context) (policyrev.Revision, error) {
	revs, err := w.revs.List(ctx, 200)
	if err != nil {
		return policyrev.Revision{}, fmt.Errorf("policywriter: read revisions: %w", err)
	}
	for _, r := range revs { // newest first
		if r.ApplyStatus == policyrev.StatusApplied {
			return r, nil
		}
	}
	return policyrev.Revision{}, ErrNoRecoveryTarget
}
