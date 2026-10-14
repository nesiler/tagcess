package hostapply

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const (
	id1 = "11111111-1111-4111-8111-111111111111"
	id2 = "22222222-2222-4222-8222-222222222222"
)

func newClient(t *testing.T) (*Client, string, string) {
	t.Helper()
	root := t.TempDir()
	req, res := filepath.Join(root, "requests"), filepath.Join(root, "results")
	for _, d := range []string{req, res} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c, err := New(req, res)
	if err != nil {
		t.Fatal(err)
	}
	return c, req, res
}

func buildRequest(t *testing.T, id string) []byte {
	t.Helper()
	rev, err := hostpatch.BaseRev([]string{"devops"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := hostpatch.BuildRequest(id, rev, []string{"devops", "developer"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeResult(t *testing.T, dir, id string, state hostpatch.State) []byte {
	t.Helper()
	code := hostpatch.ErrorCode("")
	if state != hostpatch.StateSucceeded {
		code = hostpatch.CodeHealthFailed
	}
	b, err := hostpatch.EncodeResult(hostpatch.Result{
		Version: hostpatch.Version, RequestID: id, State: state, Phase: hostpatch.PhaseCheck,
		FinishedAt: time.Now(), ErrorCode: code, HealthVerified: state == hostpatch.StateSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "result.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHostApplyClient_PublishOrder(t *testing.T) {
	c, req, _ := newClient(t)
	doc := buildRequest(t, id1)

	var order []string
	c.afterRename = func(name string) { order = append(order, name) }
	if err := c.Publish(doc); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if want := []string{id1 + ".json", "request.ready"}; strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("rename order = %v, want %v", order, want)
	}
	got, err := os.ReadFile(filepath.Join(req, id1+".json"))
	if err != nil || !bytes.Equal(got, doc) {
		t.Fatalf("request file = %q, %v; want the F3b-004 bytes", got, err)
	}
	marker, err := os.ReadFile(filepath.Join(req, "request.ready"))
	if err != nil {
		t.Fatal(err)
	}
	if gotID, err := hostpatch.ParseMarker(marker); err != nil || gotID != id1 {
		t.Fatalf("marker = %q (%v), want %s", marker, err, id1)
	}
	// Nothing but the two files is left: temp files are gone.
	entries, _ := os.ReadDir(req)
	if len(entries) != 2 {
		t.Fatalf("directory has %d entries, want 2: %v", len(entries), entries)
	}
}

func TestHostApplyClient_PublishTempNamesAreHidden(t *testing.T) {
	c, _, _ := newClient(t)
	var temps []string
	c.afterTemp = func(name string) { temps = append(temps, name) }
	if err := c.Publish(buildRequest(t, id1)); err != nil {
		t.Fatal(err)
	}
	if len(temps) != 2 {
		t.Fatalf("temp files = %v, want 2", temps)
	}
	for _, n := range temps {
		if !strings.HasPrefix(n, ".") {
			t.Fatalf("temp name %q does not start with a dot", n)
		}
	}
}

func TestHostApplyClient_PublishRejectsInvalidDocument(t *testing.T) {
	c, req, _ := newClient(t)
	if err := c.Publish([]byte(`{"version":1}`)); !errors.Is(err, hostpatch.ErrInvalidRequest) {
		t.Fatalf("err = %v, want ErrInvalidRequest", err)
	}
	if entries, _ := os.ReadDir(req); len(entries) != 0 {
		t.Fatalf("invalid document left files: %v", entries)
	}
}

func TestHostApplyClient_BusyWhenMarkerExists(t *testing.T) {
	c, req, _ := newClient(t)
	marker := filepath.Join(req, "request.ready")
	if err := os.WriteFile(marker, []byte(id2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Publish(buildRequest(t, id1)); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if _, err := os.Stat(filepath.Join(req, id1+".json")); !os.IsNotExist(err) {
		t.Fatalf("request file written while busy: %v", err)
	}
	if b, _ := os.ReadFile(marker); string(b) != id2 {
		t.Fatalf("marker was changed: %q", b)
	}

	// A dangling symlink named request.ready is still a marker.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(req, "nowhere"), marker); err != nil {
		t.Fatal(err)
	}
	if err := c.Publish(buildRequest(t, id1)); !errors.Is(err, ErrBusy) {
		t.Fatalf("symlink marker: err = %v, want ErrBusy", err)
	}
}

func TestHostApplyClient_ResultForIDOnly(t *testing.T) {
	t.Run("matching id", func(t *testing.T) {
		c, _, res := newClient(t)
		writeResult(t, res, id1, hostpatch.StateSucceeded)
		r, err := c.Result(id1)
		if err != nil || r.RequestID != id1 || r.State != hostpatch.StateSucceeded {
			t.Fatalf("Result = %+v, %v", r, err)
		}
	})
	t.Run("failed result is returned as is", func(t *testing.T) {
		c, _, res := newClient(t)
		writeResult(t, res, id1, hostpatch.StateFailed)
		r, err := c.Result(id1)
		if err != nil || r.State != hostpatch.StateFailed {
			t.Fatalf("Result = %+v, %v", r, err)
		}
	})
	t.Run("other id", func(t *testing.T) {
		c, _, res := newClient(t)
		writeResult(t, res, id2, hostpatch.StateSucceeded)
		if r, err := c.Result(id1); !errors.Is(err, ErrNoResult) || r != (hostpatch.Result{}) {
			t.Fatalf("Result = %+v, %v; want ErrNoResult", r, err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		c, _, _ := newClient(t)
		if _, err := c.Result(id1); !errors.Is(err, ErrNoResult) {
			t.Fatalf("err = %v, want ErrNoResult", err)
		}
	})
	t.Run("bad request id argument", func(t *testing.T) {
		c, _, res := newClient(t)
		writeResult(t, res, id1, hostpatch.StateSucceeded)
		if _, err := c.Result("../x"); err == nil {
			t.Fatal("bad id accepted")
		}
	})

	bad := map[string][]byte{
		"broken json":   []byte(`{"version":1,`),
		"empty":         {},
		"over 4 KiB":    append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), hostpatch.MaxResultBytes)...),
		"unknown field": []byte(`{"version":1,"request_id":"` + id1 + `","state":"succeeded","phase":"check","finished_at":"2026-10-02T10:00:00Z","error_code":"","config_changed":true,"health_verified":true,"x":1}`),
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			c, _, res := newClient(t)
			if err := os.WriteFile(filepath.Join(res, "result.json"), content, 0o644); err != nil {
				t.Fatal(err)
			}
			if r, err := c.Result(id1); err == nil || r != (hostpatch.Result{}) {
				t.Fatalf("Result = %+v, %v; want an error and no result", r, err)
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		c, _, res := newClient(t)
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		b := writeResult(t, res, id1, hostpatch.StateSucceeded)
		if err := os.Rename(filepath.Join(res, "result.json"), target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(res, "result.json")); err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 {
			t.Fatal("fixture empty")
		}
		if r, err := c.Result(id1); err == nil || r != (hostpatch.Result{}) {
			t.Fatalf("Result = %+v, %v; want an error and no result", r, err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		c, _, res := newClient(t)
		if err := os.Mkdir(filepath.Join(res, "result.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Result(id1); err == nil {
			t.Fatal("directory accepted as result")
		}
	})
}

func TestHostApplyClient_StatusUnreadable(t *testing.T) {
	goodStatus := func(t *testing.T) []byte {
		t.Helper()
		rev, _ := hostpatch.BaseRev([]string{"devops"})
		b, err := hostpatch.EncodeStatus(hostpatch.Status{Version: hostpatch.Version, AllowedGroups: []string{"devops"}, BaseRev: rev})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("valid", func(t *testing.T) {
		c, _, res := newClient(t)
		if err := os.WriteFile(filepath.Join(res, "status.json"), goodStatus(t), 0o644); err != nil {
			t.Fatal(err)
		}
		s, err := c.Status()
		if err != nil || len(s.AllowedGroups) != 1 || s.AllowedGroups[0] != "devops" {
			t.Fatalf("Status = %+v, %v", s, err)
		}
	})

	cases := map[string][]byte{
		"invalid json": []byte(`nope`),
		"empty":        {},
		"over 4 KiB":   bytes.Repeat([]byte(" "), hostpatch.MaxResultBytes+1),
		"base_rev mismatch": []byte(`{"version":1,"request_id":"","state":"","phase":"","allowed_groups":["devops"],"base_rev":"` +
			strings.Repeat("0", 64) + `","config_error":""}`),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			c, _, res := newClient(t)
			if err := os.WriteFile(filepath.Join(res, "status.json"), content, 0o644); err != nil {
				t.Fatal(err)
			}
			if s, err := c.Status(); err == nil {
				t.Fatalf("Status = %+v, nil; want an error, not an invented state", s)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		c, _, _ := newClient(t)
		if _, err := c.Status(); err == nil {
			t.Fatal("missing status.json gave no error")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		c, _, res := newClient(t)
		target := filepath.Join(t.TempDir(), "s.json")
		if err := os.WriteFile(target, goodStatus(t), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(res, "status.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Status(); err == nil {
			t.Fatal("symlinked status.json accepted")
		}
	})
}

func TestHostApplyClient_NewRejectsRelativePaths(t *testing.T) {
	for _, tc := range [][2]string{{"requests", "/abs"}, {"/abs", "results"}, {"", "/abs"}, {"/abs", "/abs/../x"}} {
		if _, err := New(tc[0], tc[1]); err == nil {
			t.Errorf("New(%q, %q) accepted", tc[0], tc[1])
		}
	}
}

func TestHostApplyClient_MarkerRenameFailureRemovesRequest(t *testing.T) {
	c, req, _ := newClient(t)
	marker := filepath.Join(req, markerName)
	// Once the request file is in place, a non-empty directory named request.ready makes the marker rename fail.
	c.afterRename = func(name string) {
		if name == id1+".json" {
			if err := os.MkdirAll(filepath.Join(marker, "x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := c.Publish(buildRequest(t, id1)); err == nil {
		t.Fatal("Publish succeeded although the marker rename failed")
	}
	if _, err := os.Lstat(filepath.Join(req, id1+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan request file left behind: %v", err)
	}
}

func TestHostApplyClient_MarkerSyncFailureKeepsRequest(t *testing.T) {
	c, req, _ := newClient(t)
	calls := 0
	c.syncDir = func(string) error {
		calls++
		if calls == 2 { // the marker's directory sync
			return errors.New("injected sync failure")
		}
		return nil
	}
	doc := buildRequest(t, id1)
	if err := c.Publish(doc); err != nil {
		t.Fatalf("Publish after a published marker must not report failure: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(req, id1+".json"))
	if err != nil || !bytes.Equal(got, doc) {
		t.Fatalf("request file must stay in place: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(req, markerName)); err != nil {
		t.Fatalf("marker missing: %v", err)
	}
}
