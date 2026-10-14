package web

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
}

// shortSocket returns a socket path short enough for sun_path (104 bytes on macOS).
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "websock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "ui.sock")
}

func newUnixClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

// AC3: the UI server runs on a unix socket and opens no TCP listener.
func TestServer_UIUnixSocketOnly(t *testing.T) {
	socket := shortSocket(t)
	s, err := New(Config{Socket: socket, SocketGroup: currentGroupName(t), Handler: okHandler()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := s.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	if ln.Addr().Network() != "unix" {
		t.Fatalf("listener network = %q, want unix", ln.Addr().Network())
	}
	if _, ok := any(ln).(*net.UnixListener); !ok {
		t.Fatalf("listener type = %T, want *net.UnixListener", ln)
	}
	if s.http.Addr != "" {
		t.Errorf("http.Server.Addr = %q, want empty (no TCP address)", s.http.Addr)
	}
	if _, _, err := net.SplitHostPort(ln.Addr().String()); err == nil {
		t.Errorf("listener address %q parses as host:port, looks like TCP", ln.Addr())
	}

	go func() { _ = s.Serve() }()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://ui/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newUnixClient(socket).Do(req)
	if err != nil {
		t.Fatalf("request over the unix socket: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status = %d, body = %q, want 200 ok", resp.StatusCode, body)
	}
}

// AC4: the socket is created with the configured group and 0660. When the test user is in more than
// one group, a group other than the process's effective gid is used, so the test would fail if the
// chgrp were removed (the default socket gid is the effective gid).
func TestServer_SocketPermissions(t *testing.T) {
	egid := os.Getgid()
	group, err := user.LookupGroupId(strconv.Itoa(egid))
	if err != nil {
		t.Skipf("cannot resolve the primary group: %v", err)
	}
	wantName, wantGID := group.Name, egid
	if name, gid, ok := otherGroup(t, egid); ok {
		wantName, wantGID = name, gid
	}

	socket := shortSocket(t)
	s, err := New(Config{Socket: socket, SocketGroup: wantName, SocketMode: 0o660, Handler: okHandler()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	fi, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode = %04o, want 0660", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat type = %T, want *syscall.Stat_t", fi.Sys())
	}
	if int(st.Gid) != wantGID {
		t.Errorf("socket gid = %d, want %d (%s)", st.Gid, wantGID, wantName)
	}
}

// otherGroup returns a group the test user belongs to whose gid differs from egid, so a chgrp can be
// observed. It reports false when there is no such group.
func otherGroup(t *testing.T, egid int) (string, int, bool) {
	t.Helper()
	gids, err := os.Getgroups()
	if err != nil {
		t.Skipf("cannot list groups: %v", err)
	}
	for _, gid := range gids {
		if gid == egid {
			continue
		}
		group, err := user.LookupGroupId(strconv.Itoa(gid))
		if err != nil {
			continue
		}
		return group.Name, gid, true
	}
	return "", 0, false
}

func TestLookupGID(t *testing.T) {
	gid := os.Getgid()
	group, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		t.Skipf("cannot resolve the primary group: %v", err)
	}
	got, err := lookupGID(group.Name)
	if err != nil {
		t.Fatalf("lookupGID(%q): %v", group.Name, err)
	}
	if got != gid {
		t.Errorf("lookupGID(%q) = %d, want %d", group.Name, got, gid)
	}
	if _, err := lookupGID("tagcess-no-such-group"); err == nil {
		t.Error("expected an error for an unknown group")
	}
}

// A socket directory that others or the group can write would let a local process replace the
// socket; startup must refuse it (NFR-02, T2). A directory without write bits for group/other is
// accepted.
func TestListenUI_SocketDirPermissions(t *testing.T) {
	for _, tc := range []struct {
		mode    os.FileMode
		wantErr bool
	}{
		{0o777, true},
		{0o770, true},
		{0o755, false},
		{0o750, false},
		{0o700, false},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			dir, err := os.MkdirTemp("", "websock")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			ln, err := ListenUI(filepath.Join(dir, "ui.sock"), currentGroupName(t), 0o660)
			if tc.wantErr {
				if err == nil {
					_ = ln.Close()
					t.Fatal("expected an error for a group/other-writable socket directory")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			_ = ln.Close()
		})
	}
}

// A default mode is applied when the config leaves socket_mode out.
func TestServer_DefaultSocketMode(t *testing.T) {
	socket := shortSocket(t)
	s, err := New(Config{Socket: socket, Handler: okHandler()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.cfg.SocketMode != 0o660 {
		t.Fatalf("default socket mode = %04o, want 0660", s.cfg.SocketMode)
	}
}

// A stale socket from a crashed run is reclaimed; a path that is not a socket is refused.
func TestListenUI_StaleSocket(t *testing.T) {
	group := currentGroupName(t)
	socket := shortSocket(t)

	// A regular file at the socket path must be refused, not deleted.
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUI(socket, group, 0o660); err == nil {
		t.Fatal("expected an error for an existing non-socket file")
	}
	if _, err := os.Stat(socket); err != nil {
		t.Fatalf("the non-socket file was removed: %v", err)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}

	// A leftover socket with no listener is reclaimed.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socket); err != nil {
		t.Fatalf("socket file should still exist: %v", err)
	}
	got, err := ListenUI(socket, group, 0o660)
	if err != nil {
		t.Fatalf("stale socket was not reclaimed: %v", err)
	}
	_ = got.Close()
}

// A live socket must never be stolen.
func TestListenUI_LiveSocketRefused(t *testing.T) {
	group := currentGroupName(t)
	socket := shortSocket(t)
	first, err := ListenUI(socket, group, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	if _, err := ListenUI(socket, group, 0o660); err == nil {
		t.Fatal("expected an error when the socket is already in use")
	}
}

func currentGroupName(t *testing.T) string {
	t.Helper()
	group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("cannot resolve the primary group: %v", err)
	}
	return group.Name
}

func TestNew_Validates(t *testing.T) {
	if _, err := New(Config{Handler: okHandler()}); err == nil {
		t.Error("expected an error for a missing socket")
	}
	if _, err := New(Config{Socket: shortSocket(t)}); err == nil {
		t.Error("expected an error for a missing handler")
	}
}

// Serve without Listen is a programming error, not a silent no-op.
func TestServer_ServeWithoutListen(t *testing.T) {
	s, err := New(Config{Socket: shortSocket(t), Handler: okHandler()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(); err == nil {
		t.Fatal("expected an error when Serve runs before Listen")
	}
}
