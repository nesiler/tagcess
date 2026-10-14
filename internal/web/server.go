package web

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxHeaderBytes bounds request headers on the UI server.
const maxHeaderBytes = 16 << 10

// Config wires the UI server.
type Config struct {
	// Socket is the unix socket path Caddy proxies to (ADR 0004). There is no TCP address.
	Socket string
	// SocketGroup owns the socket; only this group (Caddy) may connect (NFR-02).
	SocketGroup string
	// SocketMode is the socket permission; it must not include other bits. Defaults to 0660.
	SocketMode fs.FileMode
	// Handler is the middleware chain that serves the interface.
	Handler http.Handler
	// Logger defaults to slog.Default.
	Logger *slog.Logger
}

// Server serves the UI on a unix socket only. It has no TCP listener by construction.
type Server struct {
	cfg  Config
	http *http.Server
	ln   *net.UnixListener
}

// New validates the wiring. Socket and Handler are required.
func New(cfg Config) (*Server, error) {
	switch {
	case strings.TrimSpace(cfg.Socket) == "":
		return nil, errors.New("web: a unix socket path is required")
	case cfg.Handler == nil:
		return nil, errors.New("web: a handler is required")
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0o660
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{cfg: cfg}
	// Addr is deliberately empty: the server is only ever given a unix listener via Serve.
	s.http = &http.Server{
		Handler:           cfg.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	return s, nil
}

// Listen binds the unix socket with the configured group and mode. It must be called before Serve.
func (s *Server) Listen() (*net.UnixListener, error) {
	ln, err := ListenUI(s.cfg.Socket, s.cfg.SocketGroup, s.cfg.SocketMode)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	return ln, nil
}

// Serve accepts requests on the bound socket until Shutdown. It returns nil on a clean shutdown.
func (s *Server) Serve() error {
	if s.ln == nil {
		return errors.New("web: Listen must be called before Serve")
	}
	err := s.http.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown drains in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// ListenUI creates the UI unix socket and applies the group and mode. Only a unix listener is ever
// created (NFR-02, ADR 0004). A stale socket left by a crash is reclaimed; a live socket or a
// non-socket file at the path is refused rather than deleted.
func ListenUI(socket, group string, mode fs.FileMode) (*net.UnixListener, error) {
	if strings.TrimSpace(socket) == "" {
		return nil, errors.New("web: a unix socket path is required")
	}
	if strings.TrimSpace(group) == "" {
		return nil, errors.New("web: a socket group is required")
	}
	if mode == 0 {
		mode = 0o660
	}
	if err := ensureSocketDir(socket); err != nil {
		return nil, err
	}
	if err := reclaimStaleSocket(socket); err != nil {
		return nil, err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("web: listen on %s: %w", socket, err)
	}
	// Never unlink by path on close: the file could have been replaced, and removing it would take
	// down whoever owns it now. A leftover socket is reclaimed on the next start.
	ln.SetUnlinkOnClose(false)

	if err := os.Chmod(socket, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("web: chmod %s: %w", socket, err)
	}
	gid, err := lookupGID(group)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	if err := os.Chown(socket, -1, gid); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("web: chgrp %s to %s: %w", socket, group, err)
	}
	return ln, nil
}

// ensureSocketDir makes sure the socket's directory exists and that no other user or group can write
// to it. A group- or world-writable directory would let a local process replace the socket and
// receive the identity headers Caddy sends, which breaks the trust boundary (NFR-02, T2).
func ensureSocketDir(socket string) error {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("web: create socket directory: %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("web: stat socket directory %s: %w", dir, err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("web: socket directory %s is group/other writable (mode %04o)", dir, fi.Mode().Perm())
	}
	return nil
}

// reclaimStaleSocket removes a leftover socket with no listener so a crashed run does not block the
// next start. A live socket (connect succeeds) or a socket that cannot be probed is left alone: only
// ECONNREFUSED proves nothing is listening. Anything that is not a socket is never deleted.
func reclaimStaleSocket(socket string) error {
	fi, err := os.Lstat(socket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("web: stat %s: %w", socket, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("web: %s exists and is not a socket", socket)
	}
	conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(context.Background(), "unix", socket)
	switch {
	case err == nil:
		_ = conn.Close()
		return fmt.Errorf("web: %s is already in use", socket)
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, fs.ErrNotExist):
		// Nothing is listening: safe to reclaim.
	default:
		return fmt.Errorf("web: cannot tell whether %s is in use: %w", socket, err)
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("web: remove stale socket %s: %w", socket, err)
	}
	return nil
}

// lookupGID resolves a group name to its numeric id.
func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("web: socket group %q: %w", name, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("web: socket group %q has non-numeric gid %q", name, g.Gid)
	}
	return gid, nil
}
