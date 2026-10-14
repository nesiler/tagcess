// Atomic replacement of the generated Caddyfile (ADR 0005 step 4, AC2). Same
// approach as internal/dns (F2-006): a temp file in the target directory,
// fsync, rename, then a directory fsync — but its own copy, because the two
// files need different permissions (the Caddyfile must be readable by the
// caddy user, 0644; the DNS file is 0640 for headscale) and neither package
// should depend on the other for a file primitive.
package caddy

import (
	"fmt"
	"os"
	"path/filepath"
)

// filePerm is the mode of the generated Caddyfile: readable by the caddy user
// (architecture.md §8, /etc/caddy mount note).
const filePerm os.FileMode = 0o644

// writeFileAtomic replaces path with content atomically: the temp file is
// created in the same directory (so the rename never crosses a filesystem),
// carries the final permissions, and is fsynced before the rename; the
// directory entry is fsynced after it. On any error the previous file is
// untouched and the temp file is removed.
func writeFileAtomic(path, content string) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("caddy write: temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}

	if _, err := tmp.WriteString(content); err != nil {
		return cleanup(fmt.Errorf("caddy write: %w", err))
	}
	if err := tmp.Chmod(filePerm); err != nil {
		return cleanup(fmt.Errorf("caddy write: chmod: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("caddy write: fsync: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return cleanup(fmt.Errorf("caddy write: close: %w", err))
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("caddy write: rename: %w", err)
	}
	// The rename itself must survive a crash: sync the directory entry too.
	//nolint:gosec // G304: dir is the parent of the caller's configured path, not user input
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
