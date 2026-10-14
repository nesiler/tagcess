//go:build integration

// F2-008 integration: the apply layer against the real pinned Caddy (v2.8.4) of the local
// compose stack, whose admin API F2-008 publishes on 127.0.0.1:2019. It covers what the fake
// admin API in internal/caddy cannot: the real /adapt vs /load split (an invalid path_regexp
// passes /adapt and only fails /load at provisioning, stack-notes), the running config staying
// byte-identical on refusals, the file keeping the applied target, and the AC3 restore path
// against a real /load. Requires the compose stack (`make lab-up`); a stack that predates the
// F2-008 compose change has no published admin port and fails with a recreate hint.
//
// Every config this test loads carries `admin 0.0.0.0:2019`: without the global block the
// endpoint would fall back to the container-local default and the test would lock itself out
// (and the cleanup could not put the original config back). Cleanup reloads the exact JSON
// snapshot taken before each subtest, so the shared stack ends where it started.
package compose_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/site"
)

const f2008Admin = "http://127.0.0.1:2019"

// f2008AdminBlock keeps the published admin endpoint alive in every loaded config.
const f2008AdminBlock = "{\n\tadmin 0.0.0.0:2019\n}\n\n"

func f2008Client(t *testing.T) *caddy.Client {
	t.Helper()
	cl := caddy.NewClient(f2008Admin)
	if _, err := cl.Config(context.Background()); err != nil {
		t.Fatalf("compose caddy admin API is not reachable on %s: %v (the running stack predates F2-008; run: docker compose -f test/compose/compose.yaml up -d caddy)", f2008Admin, err)
	}
	return cl
}

func f2008LiveConfig(t *testing.T, cl *caddy.Client) string {
	t.Helper()
	raw, err := cl.Config(context.Background())
	if err != nil {
		t.Fatalf("read live config: %v", err)
	}
	return string(raw)
}

// f2008Restore puts a JSON config snapshot back with POST /load (application/json).
func f2008Restore(t *testing.T, live string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f2008Admin+"/load", strings.NewReader(live))
	if err != nil {
		t.Fatalf("build restore request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("restore live config: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore live config: status %d: %s", resp.StatusCode, body)
	}
}

// f2008SnapshotRestore snapshots the live config and restores it when the test ends.
func f2008SnapshotRestore(t *testing.T, cl *caddy.Client) string {
	t.Helper()
	live := f2008LiveConfig(t, cl)
	t.Cleanup(func() { f2008Restore(t, live) })
	return live
}

// TestCaddyApply_ComposeCaddy runs the ADR 0005 apply flow against real Caddy.
func TestCaddyApply_ComposeCaddy(t *testing.T) {
	cl := f2008Client(t)

	t.Run("adapt_rejection_leaves_config_and_file", func(t *testing.T) {
		live := f2008SnapshotRestore(t, cl)
		path := f2008Fixture(t, "unused previous")
		target := ":8083 {\n" // unclosed block: real /adapt refuses it

		err := caddy.Apply(context.Background(), cl, path, f2008Sites(), target)
		if err == nil {
			t.Fatal("Apply succeeded despite the broken syntax")
		}
		if !strings.Contains(err.Error(), "adapt") {
			t.Errorf("error %v does not come from /adapt", err)
		}
		var fwe *caddy.FileWriteError
		if errors.As(err, &fwe) {
			t.Errorf("an adapt refusal is not a file write failure: %v", err)
		}
		if got := f2008LiveConfig(t, cl); got != live {
			t.Error("the running config changed on an adapt refusal")
		}
		f2008FileIs(t, path, "unused previous")
	})

	t.Run("load_rejection_leaves_config_and_file", func(t *testing.T) {
		live := f2008SnapshotRestore(t, cl)
		path := f2008Fixture(t, "unused previous")
		// path_regexp compiles at provisioning, not in /adapt (stack-notes): this
		// config passes /adapt and must fail /load with the regexp error.
		target := f2008AdminBlock + ":8083 {\n\t@bad expression `path_regexp('*')`\n\trespond @bad 200\n}\n"

		err := caddy.Apply(context.Background(), cl, path, f2008Sites(), target)
		if err == nil {
			t.Fatal("Apply succeeded although /load must refuse an uncompilable regexp")
		}
		if !strings.Contains(err.Error(), "load") {
			t.Errorf("error %v does not come from /load", err)
		}
		if !strings.Contains(err.Error(), "repetition operator") {
			t.Errorf("error %v does not carry the provisioning regexp error", err)
		}
		var fwe *caddy.FileWriteError
		if errors.As(err, &fwe) {
			t.Errorf("a load refusal is not a file write failure: %v", err)
		}
		if got := f2008LiveConfig(t, cl); got != live {
			t.Error("the running config changed on a load refusal")
		}
		f2008FileIs(t, path, "unused previous")
	})

	t.Run("apply_writes_file_and_live_config", func(t *testing.T) {
		_ = f2008SnapshotRestore(t, cl)
		path := f2008Fixture(t, ":8083 {\n\trespond \"stale\" 200\n}\n")
		target := f2008AdminBlock + ":8083 {\n\trespond \"f2-008-success\" 200\n}\n"

		if err := caddy.Apply(context.Background(), cl, path, f2008Sites(), target); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		f2008FileIs(t, path, target)
		live := f2008LiveConfig(t, cl)
		if !strings.Contains(live, "f2-008-success") {
			t.Error("the live config does not contain the applied target")
		}
		// Restart story: the file on disk is what a Caddy restart reads, so it must
		// still adapt cleanly on its own.
		fileBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the applied file: %v", err)
		}
		if err := cl.Adapt(context.Background(), string(fileBytes)); err != nil {
			t.Errorf("the written Caddyfile does not adapt on its own: %v", err)
		}
	})

	t.Run("disk_failure_restores_previous", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions; the write failure cannot be simulated")
		}
		_ = f2008SnapshotRestore(t, cl)
		dir := t.TempDir()
		path := filepath.Join(dir, "Caddyfile")
		previous := f2008AdminBlock + ":8084 {\n\trespond \"f2-008-previous\" 200\n}\n"
		if err := os.WriteFile(path, []byte(previous), 0o644); err != nil {
			t.Fatalf("write previous file: %v", err)
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatalf("read-only dir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		target := f2008AdminBlock + ":8084 {\n\trespond \"f2-008-diskfail\" 200\n}\n"
		err := caddy.Apply(context.Background(), cl, path, f2008Sites(), target)
		var fwe *caddy.FileWriteError
		if !errors.As(err, &fwe) {
			t.Fatalf("error = %v, want *caddy.FileWriteError (critical alert marker)", err)
		}
		if !fwe.Restored {
			t.Errorf("Restored = false, want the previous config loaded back: %v", err)
		}
		if fwe.RestoreErr != nil {
			t.Errorf("RestoreErr = %v, want nil", fwe.RestoreErr)
		}
		f2008FileIs(t, path, previous)
		// The restore went through the real /load: the live config serves the
		// previous block again, not the target whose write failed.
		live := f2008LiveConfig(t, cl)
		if !strings.Contains(live, "f2-008-previous") {
			t.Error("the live config does not carry the restored previous config")
		}
		if strings.Contains(live, "f2-008-diskfail") {
			t.Error("the live config still carries the target whose file write failed")
		}
	})
}

// f2008Sites is the minimal site set the apply path demands: the four locked
// system site records (S-05). Their hosts must not collide with each other;
// the templates are never rendered in this test, only counted.
func f2008Sites() []site.Site {
	base := func(tmpl, host string) site.Site {
		return site.Site{
			Hosts:          []string{host},
			Kind:           site.KindSystem,
			SystemTemplate: tmpl,
			SystemConfig:   `{}`,
			Cert:           "auto",
			TargetKind:     site.TargetK8s,
			Roles:          []string{}, TargetRoles: []string{},
			APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
		}
	}
	return []site.Site{
		base(site.TemplateZitadel, "auth.integration.invalid"),
		base(site.TemplateHeadscale, "hs.integration.invalid"),
		base(site.TemplateWireGuardUI, "vpn.integration.invalid"),
		base(site.TemplateTagcess, "tagcess.integration.invalid"),
	}
}

// f2008Fixture creates the fixture Caddyfile with the given content.
func f2008Fixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func f2008FileIs(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("file = %q, want %q", got, want)
	}
}
