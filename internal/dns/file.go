// Atomic replacement of the extra-records file and the Apply flow: diff against
// the previous file, atomic write, resolver verification of the changed names
// (ADR 0013 m.4 and m.5). Every failure path keeps the previous file intact.
package dns

import (
	"fmt"
	"os"
	"path/filepath"
)

// filePerm is the mode ADR 0013 m.4 prescribes: readable by the Headscale user
// (group permission), not world-readable.
const filePerm os.FileMode = 0o640

// WriteFileAtomic replaces path with content the way Headscale's fsnotify watch
// expects: a temp file in the same directory, fsync, rename (ADR 0013 m.4). The
// temp file carries the final permissions, so the renamed file is readable by
// Headscale from the first moment. On any error the previous file is untouched
// and the temp file is removed.
func WriteFileAtomic(path, content string) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("dns write: temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}

	if _, err := tmp.WriteString(content); err != nil {
		return cleanup(fmt.Errorf("dns write: %w", err))
	}
	if err := tmp.Chmod(filePerm); err != nil {
		return cleanup(fmt.Errorf("dns write: chmod: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("dns write: fsync: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return cleanup(fmt.Errorf("dns write: close: %w", err))
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("dns write: rename: %w", err)
	}
	// The rename itself must survive a crash: sync the directory entry too.
	//nolint:gosec // G304: dir is the parent of the caller's configured path, not user input
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Apply is one DNS artifact step (S-03.4): records are the single input — the
// content is derived from them by Marshal, so the written file can never
// disagree with the verified records — and the write itself is atomic over
// path. Every name the write actually changed is verified against the
// verifier's resolver. Resolver mismatches are returned as warnings and keep
// the new file (ADR 0013 m.5: the failure may be propagation delay; the caller
// forwards them to audit/alerts). A write error is a hard error and leaves the
// previous file in place.
func Apply(path string, records []Record, v Verifier) ([]Mismatch, error) {
	changed, err := diffAgainstFile(path, records)
	if err != nil {
		return nil, err
	}
	content, err := Marshal(records)
	if err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(path, content); err != nil {
		return nil, err
	}
	return v.Verify(changed), nil
}

// diffAgainstFile compares records with the file's current content and returns
// the records whose (name, type, value) pair the next write would change: added
// names, removed types and new values. A missing file means every record is
// new. A previous file that no longer parses is treated the same way — the safe
// direction, since the new content is exactly what tagcess wants — and the
// unparseable state itself shows up in the change's audit trail.
func diffAgainstFile(path string, records []Record) ([]Record, error) {
	old, err := os.ReadFile(path) //nolint:gosec // the path comes from the caller's configuration
	if os.IsNotExist(err) {
		return records, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dns apply: read previous file: %w", err)
	}
	previous, err := Unmarshal(old)
	if err != nil {
		return records, nil
	}
	oldKeys := make(map[string]string, len(previous))
	for _, r := range previous {
		oldKeys[r.Name+"/"+r.Type] = r.Value
	}
	changed := make([]Record, 0, len(records))
	for _, r := range records {
		if v, ok := oldKeys[r.Name+"/"+r.Type]; !ok || v != r.Value {
			changed = append(changed, r)
		}
	}
	return changed, nil
}
