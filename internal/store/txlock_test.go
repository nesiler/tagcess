package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// U-15: a read-then-write transaction must not fail when another connection commits a write
// between its read and its write. With deferred transactions in WAL mode SQLite answers that
// write with SQLITE_BUSY (snapshot) at once, the busy timeout does not help, and a whole alert
// evaluation round was counted as failed ("güncel değil" on Pano for one round). Transactions start
// immediate, so the second writer waits for the first instead.
func TestReadThenWriteTxSurvivesConcurrentWrite(t *testing.T) {
	ctx := context.Background()
	db, err := OpenDB(ctx, filepath.Join(t.TempDir(), "tx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE TABLE t (v INTEGER)`); err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatal(err)
	}

	other := make(chan error, 1)
	go func() {
		_, err := db.ExecContext(ctx, `INSERT INTO t (v) VALUES (2)`)
		other <- err
	}()
	time.Sleep(150 * time.Millisecond) // let the other writer run (and commit, if it can)

	if _, err := tx.ExecContext(ctx, `INSERT INTO t (v) VALUES (1)`); err != nil {
		_ = tx.Rollback()
		t.Fatalf("write after a concurrent commit failed: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := <-other; err != nil {
		t.Fatalf("the other writer failed: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM t`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows = %d (%v), want 2", n, err)
	}
}
