package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CSRF is the stateless token signer for NFR-03/security.md §3.1. A token is a random nonce plus an
// HMAC of that nonce under the shared key; because it is verified by signature and not compared to
// stored state, the same key works across restarts and no session store is needed.
const (
	// CSRFHeader is where htmx requests send the token (ADR 0007).
	CSRFHeader = "X-CSRF-Token"
	// CSRFParam is the hidden form field name for server-rendered forms.
	CSRFParam = "csrf_token"

	csrfKeySize  = 32
	csrfNonceLen = 16
	// maxFormBody bounds every state-changing request body: a 1 MiB kubeconfig plus form encoding
	// overhead fits, anything larger is refused before a handler reads it.
	maxFormBody = 2 << 20
)

// CSRF signs and verifies CSRF tokens.
type CSRF struct {
	key []byte
}

// NewCSRF returns a signer. The key must be at least 32 bytes (security.md §7 generates 32).
func NewCSRF(key []byte) (*CSRF, error) {
	if len(key) < csrfKeySize {
		return nil, fmt.Errorf("web: csrf key must be at least %d bytes, got %d", csrfKeySize, len(key))
	}
	return &CSRF{key: key}, nil
}

// Token returns a fresh signed token safe for a form field or the X-CSRF-Token header. The token is
// not tied to the actor: only devops reaches the interface, and the goal is to prove the request
// came from a page tagcess rendered (T7).
func (c *CSRF) Token() string {
	nonce := make([]byte, csrfNonceLen)
	// crypto/rand.Read never returns an error in this Go version; it panics if the system source
	// fails, which is the right fail-closed behaviour for a security token.
	_, _ = rand.Read(nonce)
	mac := c.mac(nonce)
	return base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// Valid reports whether token was signed by this key.
func (c *CSRF) Valid(token string) bool {
	noncePart, macPart, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(noncePart)
	if err != nil || len(nonce) != csrfNonceLen {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil {
		return false
	}
	return hmac.Equal(got, c.mac(nonce))
}

// Protect wraps h so every state-changing request must carry a valid token, in the CSRFHeader or as
// the CSRFParam form field. Safe methods pass through. A request that fails gets 403.
func (c *CSRF) Protect(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			h.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > maxFormBody { // an honest client is told so; the reader below caps the rest
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
		token := r.Header.Get(CSRFHeader)
		if token == "" {
			token = r.PostFormValue(CSRFParam)
		}
		if !c.Valid(token) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// isSafeMethod reports whether method only reads. Everything else must present a CSRF token.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// mac computes HMAC-SHA256(key, nonce).
func (c *CSRF) mac(nonce []byte) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write(nonce)
	return m.Sum(nil)
}

// LoadOrCreateCSRFKey reads the CSRF key from path, generating and storing a fresh 0600 key on first
// start (security.md §7). The file must be a regular file that no other user can read; a too-short
// key or loose permissions are errors, because accepting either would weaken every token.
func LoadOrCreateCSRFKey(path string) ([]byte, error) {
	key, err := readCSRFKey(path)
	switch {
	case err == nil:
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("web: create csrf key directory: %w", err)
	}
	key = make([]byte, csrfKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("web: generate csrf key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-provided path
	if err != nil {
		// Another start won the race. Read its key once; never recurse, so a dangling symlink at the
		// path cannot loop forever.
		if errors.Is(err, fs.ErrExist) {
			key, rerr := readCSRFKey(path)
			if rerr != nil {
				return nil, fmt.Errorf("web: csrf key %s appeared but is unusable: %w", path, rerr)
			}
			return key, nil
		}
		return nil, fmt.Errorf("web: create csrf key %s: %w", path, err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("web: write csrf key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("web: write csrf key %s: %w", path, err)
	}
	return key, nil
}

// readCSRFKey loads an existing key after checking it is a regular file that only its owner can
// read. Lstat (not Stat) rejects a symlink, so a link at the path cannot redirect the read.
func readCSRFKey(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("web: csrf key %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("web: csrf key %s has mode %04o, want 0600", path, fi.Mode().Perm())
	}
	// A key owned by another uid could have been planted by a local user who then knows it; refuse
	// it. The file is created 0600 by this process, so its owner is always the effective uid.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("web: csrf key %s is owned by uid %d, want %d", path, st.Uid, os.Geteuid())
	}
	key, err := os.ReadFile(path) // #nosec G304 -- operator-provided path
	if err != nil {
		return nil, fmt.Errorf("web: read csrf key %s: %w", path, err)
	}
	if len(key) < csrfKeySize {
		return nil, fmt.Errorf("web: csrf key %s is too short (%d bytes)", path, len(key))
	}
	return key, nil
}
