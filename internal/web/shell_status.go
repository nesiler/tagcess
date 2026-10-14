package web

import (
	"context"
	"fmt"

	"github.com/nesiler/tagcess/internal/store/db"
)

// DryRunReader reads dry-run mode; *store.Store satisfies it.
type DryRunReader interface {
	DryRun(ctx context.Context) (bool, error)
}

// PendingChangesLister lists the changes waiting for an operator; *db.Queries satisfies it.
type PendingChangesLister interface {
	ListPendingChanges(ctx context.Context) ([]db.Change, error)
}

// storeShellStatus is the production top bar status: two small reads per page.
type storeShellStatus struct {
	dryRun  DryRunReader
	pending PendingChangesLister
}

// NewShellStatus wires the top bar status to the store.
func NewShellStatus(dryRun DryRunReader, pending PendingChangesLister) ShellStatusSource {
	return storeShellStatus{dryRun: dryRun, pending: pending}
}

// ShellStatus reads dry-run mode and counts the pending changes.
func (s storeShellStatus) ShellStatus(ctx context.Context) (ShellStatus, error) {
	on, err := s.dryRun.DryRun(ctx)
	if err != nil {
		return ShellStatus{}, fmt.Errorf("web: read dry-run: %w", err)
	}
	pending, err := s.pending.ListPendingChanges(ctx)
	if err != nil {
		return ShellStatus{}, fmt.Errorf("web: list pending changes: %w", err)
	}
	return ShellStatus{DryRun: on, Pending: len(pending)}, nil
}
