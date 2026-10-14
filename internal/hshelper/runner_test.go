package hshelper

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

func fakeLookup(u *user.User, err error) func(string) (*user.User, error) {
	return func(string) (*user.User, error) { return u, err }
}

// AC10: the identity configtest runs under comes from the service user; a user that cannot be
// resolved, or that is root, gives no identity and so no run (never a fallback to root).
func TestRunner_ServiceCredential(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		lookup  func(string) (*user.User, error)
		wantUID uint32
		wantGID uint32
		wantErr bool
	}{
		{"service user", "headscale", fakeLookup(&user.User{Uid: "997", Gid: "996"}, nil), 997, 996, false},
		{"unknown user", "nobody-here", fakeLookup(nil, user.UnknownUserError("nobody-here")), 0, 0, true},
		{"root", "root", fakeLookup(&user.User{Uid: "0", Gid: "0"}, nil), 0, 0, true},
		{"service user with gid 0", "headscale", fakeLookup(&user.User{Uid: "997", Gid: "0"}, nil), 0, 0, true},
		{"non numeric ids", "headscale", fakeLookup(&user.User{Uid: "abc", Gid: "1"}, nil), 0, 0, true},
		{"empty name", "", fakeLookup(&user.User{Uid: "997", Gid: "996"}, nil), 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := serviceCredential(tt.user, tt.lookup)
			if tt.wantErr {
				if !errors.Is(err, errNoServiceUser) || cred != nil {
					t.Fatalf("= %v, %v; want errNoServiceUser", cred, err)
				}
				return
			}
			if err != nil || cred.Uid != tt.wantUID || cred.Gid != tt.wantGID || len(cred.Groups) != 0 || cred.NoSetGroups {
				t.Errorf("= %+v, %v; want uid %d gid %d and no supplementary groups", cred, err, tt.wantUID, tt.wantGID)
			}
		})
	}
}

func recordingRunner(rec *[]*exec.Cmd, err error) *SystemRunner {
	r := NewSystemRunner("http://127.0.0.1:1/health", "/nonexistent.sock")
	r.lookup = fakeLookup(&user.User{Uid: "997", Gid: "996"}, nil)
	r.exec = func(c *exec.Cmd) error { *rec = append(*rec, c); return err }
	return r
}

// AC10: configtest is `headscale configtest -c <candidate>`, started with the service user's
// credential, in a clean environment, with its output discarded.
func TestRunner_ConfigtestCommand(t *testing.T) {
	var cmds []*exec.Cmd
	r := recordingRunner(&cmds, nil)
	if err := r.Configtest(context.Background(), "headscale", "/etc/headscale/.config.tagcess-new.yaml"); err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("commands = %d", len(cmds))
	}
	c := cmds[0]
	if got := strings.Join(c.Args[1:], " "); got != "configtest -c /etc/headscale/.config.tagcess-new.yaml" || filepath.Base(c.Path) != "headscale" {
		t.Errorf("command = %v", c.Args)
	}
	cred := c.SysProcAttr.Credential
	if cred == nil || cred.Uid != 997 || cred.Gid != 996 {
		t.Errorf("credential = %+v", cred)
	}
	if c.Stdout != nil || c.Stderr != nil {
		t.Error("output must not be captured")
	}
	for _, e := range c.Env {
		if !strings.HasPrefix(e, "PATH=") {
			t.Errorf("unexpected environment entry %q", e)
		}
	}
	if c.Dir != "/" {
		t.Errorf("dir = %q", c.Dir)
	}

	t.Run("no identity: nothing runs", func(t *testing.T) {
		var cmds []*exec.Cmd
		r := recordingRunner(&cmds, nil)
		r.lookup = fakeLookup(&user.User{Uid: "0", Gid: "0"}, nil)
		if err := r.Configtest(context.Background(), "root", "/etc/headscale/x"); !errors.Is(err, errNoServiceUser) {
			t.Errorf("err = %v", err)
		}
		if len(cmds) != 0 {
			t.Error("a command was started")
		}
	})
}

func TestRunner_SystemctlCommands(t *testing.T) {
	var cmds []*exec.Cmd
	r := recordingRunner(&cmds, nil)
	if err := r.Restart(context.Background(), "headscale.service"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cmds[0].Args[1:], " "); got != "restart headscale.service" || filepath.Base(cmds[0].Path) != "systemctl" {
		t.Errorf("restart command = %v", cmds[0].Args)
	}
	if cmds[0].SysProcAttr != nil && cmds[0].SysProcAttr.Credential != nil {
		t.Error("systemctl restart runs as the helper itself")
	}
}

func startGRPC(t *testing.T, srv v1.HeadscaleServiceServer) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	v1.RegisterHeadscaleServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return sock
}

type usersServer struct {
	v1.UnimplementedHeadscaleServiceServer
	err   error
	calls []string
}

func (s *usersServer) ListUsers(context.Context, *v1.ListUsersRequest) (*v1.ListUsersResponse, error) {
	s.calls = append(s.calls, "ListUsers")
	return &v1.ListUsersResponse{}, s.err
}

// The check passes only when the unit is active, /health answers 200 and a read-only gRPC call
// works; it makes no other gRPC call.
func TestRunner_Check(t *testing.T) {
	healthy := func(code int) string {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(code)
		}))
		t.Cleanup(hs.Close)
		return hs.URL + "/health"
	}
	tests := []struct {
		name     string
		inactive bool
		health   int
		grpcErr  error
		wantErr  bool
	}{
		{"all good", false, 200, nil, false},
		{"unit not active", true, 200, nil, true},
		{"health 503", false, 503, nil, true},
		{"grpc read fails", false, 200, status.Error(codes.Unavailable, "down"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &usersServer{err: tt.grpcErr}
			var cmds []*exec.Cmd
			var execErr error
			if tt.inactive {
				execErr = errors.New("exit status 3")
			}
			r := recordingRunner(&cmds, execErr)
			r.HealthURL = healthy(tt.health)
			r.Socket = startGRPC(t, srv)
			err := r.Check(context.Background(), "headscale.service")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got := strings.Join(cmds[0].Args[1:], " "); got != "is-active --quiet headscale.service" {
				t.Errorf("active command = %v", cmds[0].Args)
			}
			for _, c := range srv.calls {
				if c != "ListUsers" {
					t.Errorf("unexpected gRPC call %s", c)
				}
			}
		})
	}

	t.Run("health unreachable", func(t *testing.T) {
		var cmds []*exec.Cmd
		r := recordingRunner(&cmds, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if err := r.Check(ctx, "headscale.service"); err == nil {
			t.Error("an unreachable /health must fail the check")
		}
	})
}

// The projector the status and apply paths share reads the live file and is fail-safe.
func TestFileProjector(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(liveConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	groups, rev, err := NewFileProjector(p).Project()
	if err != nil || strings.Join(groups, ",") != "devops" || rev != baseRev {
		t.Errorf("= %v, %q, %v", groups, rev, err)
	}
	if _, _, err := NewFileProjector(filepath.Join(dir, "missing.yaml")).Project(); !errors.Is(err, ErrConfigUnreadable) {
		t.Errorf("missing file: err = %v, want config_unreadable", err)
	}
}
