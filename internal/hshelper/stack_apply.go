package hshelper

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nesiler/tagcess/internal/hostpatch"
	"github.com/nesiler/tagcess/internal/stack"
)

const (
	headscaleConfigRel = "headscale/config.yaml"
	composeRel         = "compose.yaml"
)

// stackApplier carries one accepted stack request to a terminal result. The caller holds the shared flock.
type stackApplier struct {
	cfg stackCfgRef
	req StackRequest
	j   stackJournal
	// changed is what the result reports: false until the first write, true after, nil when unknown.
	changed   *bool
	installed []HandoffKind
	service   string
}

type stackCfgRef = StackConfig

func runStackOp(cfg StackConfig, req StackRequest) (Outcome, error) {
	j, found, err := readStackJournal(cfg.priv())
	if err != nil {
		return OutcomeIdle, err
	}
	if !found || j.State != hostpatch.StateAccepted || j.RequestID != req.RequestID {
		return OutcomeIdle, nil
	}
	a := &stackApplier{cfg: cfg, req: req, j: j, changed: new(bool)}
	return a.run()
}

func (a *stackApplier) run() (Outcome, error) {
	if err := a.enter(StackPhaseValidate); err != nil {
		return a.abort(err)
	}
	switch a.req.Op {
	case OpHandoffCleanup:
		deleteHandoff(a.cfg, a.req.TargetID)
		return a.succeed()
	case OpDiscover:
		return a.discover()
	case OpServiceRestart:
		return a.restart()
	case OpStackRemove:
		return a.remove()
	case OpStackUpgrade:
		return a.upgrade()
	default:
		return a.apply()
	}
}

func (a *stackApplier) discover() (Outcome, error) {
	if a.cfg.Discover == nil {
		return a.fail(StackPhaseValidate, StackUnsupported)
	}
	b, err := a.cfg.Discover()
	if err != nil {
		return a.fail(StackPhaseValidate, StackUnsupported)
	}
	if err := atomicWrite(filepath.Join(a.cfg.Root, resultsDir), "discovery.json", b, 0o644); err != nil {
		return a.fail(StackPhaseWrite, StackWriteFailed)
	}
	return a.succeed()
}

// state loads the applied state and the manifest for this request: every component keeps the image it runs, a new
// one gets the embedded manifest's image.
func (a *stackApplier) state() (stackState, stack.Manifest, error) {
	st, err := readStackState(a.cfg.priv())
	if err != nil {
		return st, stack.Manifest{}, err
	}
	m := stack.Manifest{Release: a.cfg.Manifest.Release, Images: map[stack.Component]stack.Image{}, AllowPlaceholder: a.cfg.Manifest.AllowPlaceholder}
	for _, c := range stack.AllComponents() {
		m.Images[c] = a.cfg.Manifest.Images[c]
		if img, ok := st.Images[c]; ok && st.enabled(c) {
			m.Images[c] = img
		}
	}
	return st, m, nil
}

func (a *stackApplier) composeFile() string { return filepath.Join(a.cfg.StackDir, composeRel) }

func (a *stackApplier) apply() (Outcome, error) {
	req := a.req
	st, m, err := a.state()
	if err != nil {
		return a.fail(StackPhaseValidate, StackInvalidRequest)
	}
	next := st
	next.Params = *req.Settings
	next.Params.Components = withComponent(st.Params.Components, req.Component)
	next.Images = map[stack.Component]stack.Image{}
	for _, c := range next.Params.Components {
		next.Images[c] = m.Images[c]
	}
	files, err := a.render(st, next, m, req.Component)
	if err != nil {
		return a.fail(StackPhaseValidate, errCode(err))
	}
	secrets, err := readHandoff(a.cfg, req.RequestID, req.Handoff)
	if err != nil {
		return a.fail(StackPhaseValidate, StackHandoffFailed)
	}
	return a.install(st, next, files, secrets, true)
}

// render renders the full stack for next and returns the files the operation may write. It refuses when a file of
// another component would change, and never includes an existing Headscale config.yaml (ADR 0021 owns it).
func (a *stackApplier) render(cur, next stackState, m stack.Manifest, target stack.Component) (stack.Files, error) {
	files, err := stack.Render(next.Params, m)
	if err != nil {
		return nil, errSettings{StackInvalidRequest}
	}
	// Another component's service block in compose.yaml and its config files must stay byte-identical.
	live, err := os.ReadFile(a.composeFile()) //nolint:gosec // fixed path under the stack dir
	if err == nil {
		old, nw := splitServices(string(live)), splitServices(string(files[composeRel]))
		for _, c := range next.Params.Components {
			if c != target && cur.enabled(c) && old[c] != nw[c] {
				return nil, errSettings{StackSettings}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errSettings{StackWriteFailed}
	}
	// An existing Headscale config.yaml is never re-rendered. A setting that would change it is refused instead of
	// being recorded while the file stays old. allowed_groups is ADR 0021's, so it is held equal.
	// Only a config this stack rendered in a failed, not yet verified install stays replaceable, and only by a
	// Headscale request and while the file is still byte-identical to what that install wrote.
	hsPath := filepath.Join(a.cfg.StackDir, headscaleConfigRel)
	_, lerr := os.Lstat(hsPath)
	exists := lerr == nil
	var oldFiles stack.Files
	if cur.enabled(stack.Headscale) {
		oldFiles, err = stack.Render(cur.Params, m)
		if err != nil {
			return nil, errSettings{StackSettings}
		}
	}
	replaceable := !cur.enabled(stack.Headscale)
	if cur.enabled(stack.Headscale) && cur.failed(stack.Headscale) {
		disk, rerr := os.ReadFile(hsPath) //nolint:gosec // fixed path under the stack dir
		replaceable = rerr == nil && bytes.Equal(disk, oldFiles[headscaleConfigRel])
	}
	rewrite := target == stack.Headscale && (!exists || replaceable)
	if exists && cur.enabled(stack.Headscale) && !rewrite {
		held := next.Params
		held.AdminGroup = cur.Params.AdminGroup
		newFiles, err := stack.Render(held, m)
		if err != nil || !bytes.Equal(oldFiles[headscaleConfigRel], newFiles[headscaleConfigRel]) {
			return nil, errSettings{StackSettings}
		}
	}
	out := stack.Files{}
	for rel, b := range files {
		switch {
		case rel == composeRel:
			out[rel] = b
		case rel == headscaleConfigRel:
			if rewrite {
				out[rel] = b
			}
		case owner(rel) == target:
			out[rel] = b
		default:
			if disk, err := os.ReadFile(filepath.Join(a.cfg.StackDir, rel)); err == nil && !bytes.Equal(disk, b) { //nolint:gosec // fixed layout
				return nil, errSettings{StackSettings}
			}
		}
	}
	return out, nil
}

type errSettings struct{ code StackCode }

func (e errSettings) Error() string { return string(e.code) }

func errCode(err error) StackCode {
	var e errSettings
	if errors.As(err, &e) {
		return e.code
	}
	return StackInvalidRequest
}

// owner maps a config file (relative to the stack dir) to its component.
func owner(rel string) stack.Component {
	d, _, _ := strings.Cut(rel, "/")
	return stack.Component(d)
}

func withComponent(list []stack.Component, c stack.Component) []stack.Component {
	out := slices.Clone(list)
	if !slices.Contains(out, c) {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// splitServices cuts a rendered compose file into its service blocks, keyed by component.
func splitServices(compose string) map[stack.Component]string {
	out := map[stack.Component]string{}
	var cur stack.Component
	var b strings.Builder
	flush := func() {
		if cur != "" {
			out[cur] = b.String()
		}
		b.Reset()
	}
	for _, line := range strings.SplitAfter(compose, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(strings.TrimRight(line, "\n"), ":") {
			flush()
			cur = stack.Component(strings.TrimSuffix(strings.TrimSpace(line), ":"))
		}
		b.WriteString(line)
	}
	flush()
	return out
}

// install validates the candidate, backs up, writes (secrets, files, state), pulls and starts one component.
func (a *stackApplier) install(cur, next stackState, files stack.Files, secrets map[HandoffKind][]byte, start bool) (Outcome, error) {
	target := a.req.Component
	priv := a.cfg.priv()

	// Validate the candidate first. Nothing outside private/ has changed yet.
	cand := filepath.Join(priv, "candidate-"+a.req.RequestID)
	defer func() { _ = os.RemoveAll(cand) }()
	for rel, b := range files {
		if err := writeUnder(cand, rel, b, 0o600); err != nil {
			return a.fail(StackPhaseValidate, StackWriteFailed)
		}
	}
	if err := a.dockerStep(a.cfg.validateTimeout(), func(ctx context.Context) error {
		return a.cfg.Docker.ConfigQuiet(ctx, filepath.Join(cand, composeRel))
	}); err != nil {
		return a.fail(StackPhaseValidate, StackConfigInvalid)
	}

	if err := a.enter(StackPhaseSaveCopy); err != nil {
		return a.abort(err)
	}
	if err := a.saveCopy(files); err != nil {
		return a.fail(StackPhaseSaveCopy, StackSaveCopyFailed)
	}

	// Pull first, from the candidate compose file: a registry failure changes nothing on the host.
	if start {
		if err := a.enter(StackPhasePull); err != nil {
			return a.abort(err)
		}
		if err := a.dockerStep(a.cfg.stepTimeout(), func(ctx context.Context) error {
			return a.cfg.Docker.Pull(ctx, filepath.Join(cand, composeRel), target)
		}); err != nil {
			return a.fail(StackPhasePull, StackPullFailed)
		}
	}

	if err := a.enter(StackPhaseWrite); err != nil {
		return a.abort(err)
	}
	a.changed = nil // from here on the helper cannot tell what a failure left behind
	if err := a.writeSecrets(target, secrets); err != nil {
		return a.failLastGood(StackPhaseWrite, StackWriteFailed, cur, files)
	}
	// Component files first, compose.yaml last: a crash between leaves a compose file that still matches the state.
	rels := make([]string, 0, len(files))
	for rel := range files {
		if rel != composeRel {
			rels = append(rels, rel)
		}
	}
	sort.Strings(rels)
	rels = append(rels, composeRel)
	for _, rel := range rels {
		if err := writeUnder(a.cfg.StackDir, rel, files[rel], 0o644); err != nil {
			return a.failLastGood(StackPhaseWrite, StackWriteFailed, cur, files)
		}
	}
	next.Failed = slices.DeleteFunc(slices.Clone(next.Failed), func(x stack.Component) bool { return x == target })
	if err := writeStackState(priv, next); err != nil {
		return a.failLastGood(StackPhaseWrite, StackWriteFailed, cur, files)
	}
	yes := true
	a.changed = &yes
	if !start {
		return a.succeed()
	}

	if err := a.enter(StackPhaseStart); err != nil {
		return a.abort(err)
	}
	if err := a.dockerStep(a.cfg.stepTimeout(), func(ctx context.Context) error {
		return a.cfg.Docker.Up(ctx, a.composeFile(), target)
	}); err != nil {
		if !cur.enabled(target) {
			// A new service stays written, marked failed, so the UI can retry or remove it.
			next.Failed = withComponent(next.Failed, target)
			_ = writeStackState(priv, next)
			return a.fail(StackPhaseStart, StackStartFailed)
		}
		return a.failLastGood(StackPhaseStart, StackStartFailed, cur, files)
	}
	return a.succeed()
}

// failLastGood puts the files of this request and the state back to the last known good copy, then reports the
// failure. A service that was already running is started again from the restored compose file (best effort).
func (a *stackApplier) failLastGood(p StackPhase, code StackCode, cur stackState, files stack.Files) (Outcome, error) {
	if a.putBack(cur, files) {
		no := false
		a.changed = &no
		if p == StackPhaseStart && cur.enabled(a.req.Component) {
			if err := a.dockerStep(a.cfg.stepTimeout(), func(ctx context.Context) error {
				return a.cfg.Docker.Up(ctx, a.composeFile(), a.req.Component)
			}); err != nil {
				// The old configuration did not come back either: the service may be down and the helper cannot tell.
				a.cfg.logf("stack request %s: restart of %s after the failed start also failed: %v", a.j.RequestID, a.req.Component, err)
				a.changed = nil
				a.service = "down"
				code = StackServiceDown
			}
		}
	}
	return a.fail(p, code)
}

// putBack returns every file of files to its saved copy (or removes it when there was none) and rewrites the
// previous state. It reports whether everything went back.
func (a *stackApplier) putBack(cur stackState, files stack.Files) bool {
	dir := filepath.Join(a.cfg.priv(), "previous-"+a.req.RequestID)
	ok := true
	for rel := range files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))) //nolint:gosec // fixed layout
		switch {
		case err == nil:
			if writeUnder(a.cfg.StackDir, rel, b, 0o644) != nil {
				ok = false
			}
		case errors.Is(err, os.ErrNotExist):
			if e := os.Remove(filepath.Join(a.cfg.StackDir, filepath.FromSlash(rel))); e != nil && !errors.Is(e, os.ErrNotExist) {
				ok = false
			}
		default:
			ok = false
		}
	}
	if writeStackState(a.cfg.priv(), cur) != nil {
		ok = false
	}
	return ok
}

// saveCopy copies the files this request is about to replace into private/previous-<id>/.
func (a *stackApplier) saveCopy(files stack.Files) error {
	dir := filepath.Join(a.cfg.priv(), "previous-"+a.req.RequestID)
	for rel := range files {
		b, err := os.ReadFile(filepath.Join(a.cfg.StackDir, rel)) //nolint:gosec // fixed layout
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := writeUnder(dir, rel, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// secretPath is where a handed-off kind is installed.
func (a *stackApplier) secretPath(k HandoffKind) string {
	switch k {
	case KindOIDCSecretHeadscale:
		return filepath.Join(a.cfg.StackDir, "secrets", "headscale", "oidc_client_secret")
	case KindOIDCSecretOAuth2Proxy:
		return filepath.Join(a.cfg.StackDir, "secrets", "oauth2-proxy", "client_secret")
	default:
		return filepath.Join(a.cfg.tagcessSecretsDir(), string(k))
	}
}

// writeSecrets installs the handed-off values and generates the secrets the helper owns when missing. The
// values never go into a file other than their own (0400, owner = the service).
func (a *stackApplier) writeSecrets(target stack.Component, secrets map[HandoffKind][]byte) error {
	kinds := make([]HandoffKind, 0, len(secrets))
	for k := range secrets {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	for _, k := range kinds {
		if err := a.writeSecret(kindOwner[k], a.secretPath(k), secrets[k]); err != nil {
			return err
		}
		a.installed = append(a.installed, k)
		a.consumeDrop(k)
	}
	if target == stack.OAuth2Proxy {
		p := filepath.Join(a.cfg.StackDir, "secrets", "oauth2-proxy", "cookie_secret")
		if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
			buf := make([]byte, 16) // 32 hex characters: one of the lengths oauth2-proxy accepts
			read := a.cfg.randRead
			if read == nil {
				read = rand.Read
			}
			if _, err := read(buf); err != nil {
				return err
			}
			return a.writeSecret(stack.OAuth2Proxy, p, []byte(hex.EncodeToString(buf)))
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (a *stackApplier) consumeDrop(k HandoffKind) {
	dirfd, err := unix.Open(a.cfg.handoffPath(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(dirfd) }()
	_ = unlinkAt(dirfd, a.req.RequestID+"."+string(k))
}

// writeSecret writes one secret file: a temporary file in the same directory, mode 0400, owner = the service
// when the config names one, fsync, rename.
func (a *stackApplier) writeSecret(c stack.Component, path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	uid, gid, own := -1, -1, false
	if a.cfg.SecretOwner != nil {
		uid, gid, own = a.cfg.SecretOwner(c)
	}
	if own {
		// The service must be able to enter the directory too.
		if err := os.Chown(dir, uid, gid); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // fixed secret layout
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(0o400)
	}
	if err == nil && own {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// writeUnder writes dir/rel atomically, creating its directory.
func writeUnder(dir, rel string, data []byte, perm os.FileMode) error {
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return err
	}
	return atomicWrite(filepath.Dir(full), filepath.Base(full), data, perm)
}

func (a *stackApplier) remove() (Outcome, error) {
	st, m, err := a.state()
	c := a.req.Component
	// Only a service that a failed "install new" added may go; tagcess never.
	if err != nil || !st.enabled(c) || c == stack.Tagcess || !st.failed(c) {
		return a.fail(StackPhaseValidate, StackInvalidRequest)
	}
	next := st
	next.Failed = slices.DeleteFunc(slices.Clone(st.Failed), func(x stack.Component) bool { return x == c })
	next.Params.Components = slices.DeleteFunc(slices.Clone(st.Params.Components), func(x stack.Component) bool { return x == c })
	next.Images = map[stack.Component]stack.Image{}
	for _, x := range next.Params.Components {
		next.Images[x] = m.Images[x]
	}
	// Stop and remove the container with the compose file that still has the service; its data stays.
	if err := a.enter(StackPhaseStart); err != nil {
		return a.abort(err)
	}
	a.changed = nil
	if err := a.dockerStep(a.cfg.stepTimeout(), func(ctx context.Context) error {
		return a.cfg.Docker.Remove(ctx, a.composeFile(), c)
	}); err != nil {
		return a.fail(StackPhaseStart, StackStartFailed)
	}
	if len(next.Params.Components) > 0 {
		files, err := stack.Render(next.Params, m)
		if err != nil {
			return a.fail(StackPhaseWrite, StackWriteFailed)
		}
		if err := writeUnder(a.cfg.StackDir, composeRel, files[composeRel], 0o644); err != nil {
			return a.fail(StackPhaseWrite, StackWriteFailed)
		}
	}
	if err := writeStackState(a.cfg.priv(), next); err != nil {
		return a.fail(StackPhaseWrite, StackWriteFailed)
	}
	yes := true
	a.changed = &yes
	return a.succeed()
}

func (a *stackApplier) restart() (Outcome, error) {
	st, _, err := a.state()
	if err != nil || !st.enabled(a.req.Component) {
		return a.fail(StackPhaseValidate, StackInvalidRequest)
	}
	if err := a.enter(StackPhaseStart); err != nil {
		return a.abort(err)
	}
	a.changed = nil
	if err := a.dockerStep(a.cfg.stepTimeout(), func(ctx context.Context) error {
		return a.cfg.Docker.Restart(ctx, a.composeFile(), a.req.Component)
	}); err != nil {
		return a.fail(StackPhaseStart, StackStartFailed)
	}
	if st.failed(a.req.Component) {
		// The service came back, so the install is no longer unverified: its config is protected from now on.
		st.Failed = slices.DeleteFunc(slices.Clone(st.Failed), func(x stack.Component) bool { return x == a.req.Component })
		if err := writeStackState(a.cfg.priv(), st); err != nil {
			return a.fail(StackPhaseWrite, StackWriteFailed)
		}
	}
	yes := true
	a.changed = &yes
	return a.succeed()
}

// upgrade moves one component to the image of the helper's own manifest. It rewrites only compose.yaml.
func (a *stackApplier) upgrade() (Outcome, error) {
	st, m, err := a.state()
	c := a.req.Component
	if err != nil || !st.enabled(c) {
		return a.fail(StackPhaseValidate, StackInvalidRequest)
	}
	m.Images[c] = a.cfg.Manifest.Images[c]
	next := st
	next.Images = map[stack.Component]stack.Image{}
	for _, x := range st.Params.Components {
		next.Images[x] = m.Images[x]
	}
	files, err := stack.Render(next.Params, m)
	if err != nil {
		return a.fail(StackPhaseValidate, StackInvalidRequest)
	}
	live, err := os.ReadFile(a.composeFile()) //nolint:gosec // fixed path
	if err != nil {
		return a.fail(StackPhaseValidate, StackInvalidRequest)
	}
	old, nw := splitServices(string(live)), splitServices(string(files[composeRel]))
	for _, x := range st.Params.Components {
		if x != c && old[x] != nw[x] {
			return a.fail(StackPhaseValidate, StackSettings)
		}
	}
	return a.install(st, next, stack.Files{composeRel: files[composeRel]}, nil, true)
}

// dockerStep runs fn under its own timeout.
func (a *stackApplier) dockerStep(timeout time.Duration, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return fn(ctx)
}

func (a *stackApplier) save() error { return writeStackJournal(a.cfg.priv(), a.j) }

func (a *stackApplier) enter(p StackPhase) error {
	a.j.State, a.j.Phase = hostpatch.StateApplying, p
	return a.save()
}

func (a *stackApplier) succeed() (Outcome, error) {
	return a.finish(StackResult{
		Version: StackVersion, RequestID: a.j.RequestID, Op: a.req.Op, State: hostpatch.StateSucceeded, Phase: a.j.Phase,
		FinishedAt: a.cfg.now(), Changed: a.changed, Installed: a.installed,
	})
}

func (a *stackApplier) fail(p StackPhase, code StackCode) (Outcome, error) {
	a.cfg.logf("stack request %s failed at %s: %s", a.j.RequestID, p, code)
	return a.finish(StackResult{
		Version: StackVersion, RequestID: a.j.RequestID, Op: a.req.Op, State: hostpatch.StateFailed, Phase: p,
		FinishedAt: a.cfg.now(), ErrorCode: code, Changed: a.changed, Installed: a.installed, Service: a.service,
	})
}

// abort is for a journal that could not be written mid-flow: nothing more runs, the journal keeps its last state
// and the next start turns it into interrupted.
func (a *stackApplier) abort(err error) (Outcome, error) {
	return OutcomeFailed, fmt.Errorf("write journal: %w", err)
}

// finish publishes r, makes the journal terminal and deletes the request's drop files.
func (a *stackApplier) finish(r StackResult) (Outcome, error) {
	defer deleteHandoff(a.cfg, a.j.RequestID)
	if err := writeStackResult(filepath.Join(a.cfg.Root, resultsDir), r); err != nil {
		return OutcomeFailed, fmt.Errorf("publish result: %w", err)
	}
	a.j.State, a.j.Phase, a.j.ErrorCode = r.State, r.Phase, r.ErrorCode
	if err := a.save(); err != nil {
		return OutcomeFailed, fmt.Errorf("write journal: %w", err)
	}
	if r.State == hostpatch.StateSucceeded {
		a.cfg.logf("stack request %s succeeded", r.RequestID)
		return OutcomeSucceeded, nil
	}
	return OutcomeFailed, nil
}
