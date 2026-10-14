package site

import (
	"context"

	"github.com/nesiler/tagcess/internal/store/db"
)

// ReadFirstImportState reads the first-import gate over any query handle, including a read-only one (the
// installer's -import-preview, F6-004): pending is true while the gate is open, done once the first apply
// passed. A store that was never seeded is neither.
func ReadFirstImportState(ctx context.Context, q *db.Queries) (pending, done bool, err error) {
	s := &Store{q: q}
	if pending, err = s.FirstImportPending(ctx); err != nil {
		return false, false, err
	}
	done, err = s.FirstImportDone(ctx)
	return pending, done, err
}
