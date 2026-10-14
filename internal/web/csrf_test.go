package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testCSRF(t *testing.T) *CSRF {
	t.Helper()
	c, err := NewCSRF(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	return c
}

// AC5: a state-changing request without a valid CSRF token is forbidden; a safe request and a
// request carrying a valid token pass.
func TestCSRF_Rejects(t *testing.T) {
	c := testCSRF(t)
	valid := c.Token()

	other, err := NewCSRF(bytes.Repeat([]byte{0x99}, 32))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		method    string
		header    string
		formToken string
		wantCode  int
		wantRun   bool
	}{
		{"GET needs no token", http.MethodGet, "", "", http.StatusOK, true},
		{"HEAD needs no token", http.MethodHead, "", "", http.StatusOK, true},
		{"POST without token", http.MethodPost, "", "", http.StatusForbidden, false},
		{"POST with malformed token", http.MethodPost, "not-a-token", "", http.StatusForbidden, false},
		{"POST with token from another key", http.MethodPost, other.Token(), "", http.StatusForbidden, false},
		{"POST with valid header token", http.MethodPost, valid, "", http.StatusOK, true},
		{"POST with valid form token", http.MethodPost, "", valid, http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ran := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ran = true
				_, _ = w.Write([]byte("ok"))
			})

			var body *strings.Reader
			if tc.formToken != "" {
				body = strings.NewReader(url.Values{CSRFParam: {tc.formToken}}.Encode())
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequestWithContext(context.Background(), tc.method, "/", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.header != "" {
				req.Header.Set(CSRFHeader, tc.header)
			}
			rec := httptest.NewRecorder()
			c.Protect(inner).ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if ran != tc.wantRun {
				t.Errorf("handler ran = %v, want %v", ran, tc.wantRun)
			}
		})
	}
}

func TestCSRF_TokenIsUnpredictable(t *testing.T) {
	c := testCSRF(t)
	if a, b := c.Token(), c.Token(); a == b {
		t.Fatal("two tokens are identical; the nonce is not random")
	}
}

func TestNewCSRF_RejectsShortKey(t *testing.T) {
	if _, err := NewCSRF(make([]byte, 16)); err == nil {
		t.Fatal("expected an error for a key shorter than 32 bytes")
	}
}

func TestLoadOrCreateCSRFKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csrf-key")

	key, err := LoadOrCreateCSRFKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(key) < 32 {
		t.Fatalf("key is %d bytes, want at least 32", len(key))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", fi.Mode().Perm())
	}

	again, err := LoadOrCreateCSRFKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !bytes.Equal(key, again) {
		t.Error("second call returned a different key")
	}

	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCSRFKey(short); err == nil {
		t.Error("expected an error for a too-short existing key")
	}
}

// An existing key that group or other can read is refused: it would let another local user sign
// tokens (security.md §7).
func TestLoadOrCreateCSRFKey_RejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csrf-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{7}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCSRFKey(path); err == nil {
		t.Fatal("expected an error for a group/other-readable key")
	}
}

// A symlink at the key path is refused (not followed, and not looped over).
func TestLoadOrCreateCSRFKey_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "csrf-key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := LoadOrCreateCSRFKey(link); err == nil {
		t.Fatal("expected an error for a symlinked key path")
	}
}

// A key owned by another uid could have been planted; it is refused. Creating that state needs root.
func TestLoadOrCreateCSRFKey_RejectsForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown the key to another uid")
	}
	path := filepath.Join(t.TempDir(), "csrf-key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCSRFKey(path); err == nil {
		t.Fatal("expected an error for a key owned by another uid")
	}
}
