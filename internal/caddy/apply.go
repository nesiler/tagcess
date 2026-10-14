// The apply flow of ADR 0005: refuse unsafe site sets, adapt, load, then write
// the file; every failure keeps the last known good state.
package caddy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nesiler/tagcess/internal/site"
)

// FileWriteError reports an atomic file write that failed after the target
// config was already loaded into Caddy (S-04.2): the running config and the
// disk have diverged, and the caller MUST raise a critical alert from this
// error. Restored says whether the previous content was loaded back; when
// there was no previous file (or the restore itself failed) the target config
// stays live while the disk keeps its old (or no) content — a restart would
// then run the stale config, which is exactly what the alert has to say.
type FileWriteError struct {
	// WriteErr is the atomic write failure itself.
	WriteErr error
	// Restored reports whether the previous file content was loaded back.
	Restored bool
	// RestoreErr is the failure of the restore /load, if there was one.
	RestoreErr error
}

func (e *FileWriteError) Error() string {
	var b strings.Builder
	b.WriteString("caddy apply: the loaded config could not be written to disk (critical alert required): ")
	b.WriteString(e.WriteErr.Error())
	switch {
	case e.Restored:
		b.WriteString("; the previous config was loaded back")
	case e.RestoreErr != nil:
		b.WriteString("; loading the previous config back failed: " + e.RestoreErr.Error())
	default:
		b.WriteString("; no previous file existed, nothing was restored")
	}
	return b.String()
}

func (e *FileWriteError) Unwrap() error { return e.WriteErr }

// RequireSystemSites refuses a site set that does not carry exactly one record
// per locked system template (F2-005 handover): the store locks make deletion
// impossible through the service layer, but the apply path must not depend on
// that alone — a set without the tagcess block would leave the UI unreachable
// and one without zitadel would take down the login, so the refusal comes
// before /adapt (S-05, fail closed). wireguard_ui counts even when its switch
// is off: the record exists, only the block disappears.
func RequireSystemSites(sites []site.Site) error {
	counts := make(map[string]int, len(siteTemplates))
	for _, s := range sites {
		if s.Kind != site.KindSystem {
			continue
		}
		counts[s.SystemTemplate]++
	}
	for _, tmpl := range siteTemplates {
		switch counts[tmpl] {
		case 1:
		case 0:
			return fmt.Errorf("caddy apply: system site %q is missing; refusing to apply a set that would take it offline", tmpl)
		default:
			return fmt.Errorf("caddy apply: system site %q is carried by %d sites, want exactly one", tmpl, counts[tmpl])
		}
	}
	return nil
}

// siteTemplates are the four locked system templates in the fixed render order
// (ADR 0010 m.4; render holds its own copy of the order).
var siteTemplates = []string{
	site.TemplateZitadel,
	site.TemplateHeadscale,
	site.TemplateWireGuardUI,
	site.TemplateTagcess,
}

// Apply applies a rendered Caddyfile in the ADR 0005 order:
//
//  1. RequireSystemSites on the site set the target was rendered from.
//  2. Read the previous file content (the config a Caddy restart would run).
//  3. /adapt: syntax only.
//  4. /load: Caddy provisions the target in isolation; a refusal here leaves
//     the running config and the file untouched (AC1).
//  5. Atomically replace the file (temp file, fsync, rename; AC2).
//  6. If the write fails (AC3): load the previous content back so the running
//     config matches the disk again, and return a *FileWriteError the caller
//     must turn into a critical alert. Without a previous file there is
//     nothing to restore; the alert then reports the divergence.
//
// An empty previous file counts as no previous file: restoring it would load
// an empty config, which is a state tagcess never intends to run.
func Apply(ctx context.Context, cl *Client, path string, sites []site.Site, target string) error {
	if err := RequireSystemSites(sites); err != nil {
		return err
	}
	previous, err := readPrevious(path)
	if err != nil {
		return err
	}

	if err := cl.Adapt(ctx, target); err != nil {
		return fmt.Errorf("caddy apply: adapt refused the target, nothing was changed: %w", err)
	}
	if err := cl.Load(ctx, target); err != nil {
		return fmt.Errorf("caddy apply: load refused the target, the running config and the file are untouched: %w", err)
	}
	werr := writeFileAtomic(path, target)
	if werr == nil {
		return nil
	}

	// writeFileAtomic failed: the target is live but the disk write did not
	// happen. Bring the running config back to the disk's state (S-04.2).
	// Restoring can only narrow access — the previous file is what Caddy ran
	// until seconds ago — so the restore is allowed here where a blind policy
	// rollback is not (rule 7).
	fwe := &FileWriteError{WriteErr: werr}
	if previous != "" {
		if rerr := cl.Load(ctx, previous); rerr != nil {
			fwe.RestoreErr = rerr
		} else {
			fwe.Restored = true
		}
	}
	return fwe
}

// readPrevious reads the file the apply would replace. A missing file means
// there is nothing to restore; any other read error aborts the apply before
// the first admin call, because a failed write could then not be rolled back.
func readPrevious(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the path comes from the caller's configuration
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("caddy apply: read the previous Caddyfile, applying nothing: %w", err)
	}
	return string(b), nil
}
