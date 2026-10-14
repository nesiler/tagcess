package k8s

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
)

// sentinel returns a token-shaped value generated at test time; nothing credential-like is stored in
// the repo.
func sentinel(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return "sentinel-" + hex.EncodeToString(b)
}

// testCA returns a PEM CA certificate generated at test time.
func testCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "tagcess credential test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func validCredential(t *testing.T) Credential {
	t.Helper()
	return Credential{
		Endpoint:      "https://10.1.2.3:6443",
		CAData:        testCA(t),
		TLSServerName: "kubernetes.example.test",
		Token:         sentinel(t),
	}
}

func newCredStore(t *testing.T) (*CredentialStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "runtime")
	return NewCredentialStore(dir), filepath.Join(dir, credentialFile)
}

// AC4: a valid import lands in a file only the owner can read, in a directory outside SQLite; a
// second import replaces it atomically and leaves no temp file; SQLite never sees the token.
func TestK8sCredential_ProtectedAtomicReplace(t *testing.T) {
	ctx := context.Background()
	cs, file := newCredStore(t)

	first := validCredential(t)
	if _, err := cs.Replace(first); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(file))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		t.Errorf("created dir mode = %v, want no group/other access", di.Mode().Perm())
	}
	got, err := cs.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Token != first.Token || got.Endpoint != first.Endpoint || got.TLSServerName != first.TLSServerName {
		t.Errorf("Load returned a different credential")
	}

	second := validCredential(t)
	second.Endpoint = "https://10.9.9.9:6443"
	if _, err := cs.Replace(second); err != nil {
		t.Fatalf("second Replace: %v", err)
	}
	got, err = cs.Load()
	if err != nil || got.Token != second.Token || got.Endpoint != second.Endpoint {
		t.Fatalf("after replace Load = %v, %v; want the second credential", got.Endpoint, err)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Errorf("replaced file mode = %v, want 0600", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(file))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("runtime dir holds %d entries, want only the credential file", len(entries))
	}

	// The credential path never reaches the database or its directory. The scan runs over a real
	// database that is open next to the import, and it is shown to catch a planted token.
	dbDir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dbDir, "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if _, err := NewCredentialStore(filepath.Join(t.TempDir(), "rt")).Replace(second); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, "CREATE TABLE leak_probe (v TEXT)"); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, "INSERT INTO leak_probe (v) VALUES (?)", "x"); err != nil {
		t.Fatalf("insert probe row: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if hits := filesContaining(t, dbDir, second.Token); len(hits) != 0 {
		t.Errorf("token found in %v", hits)
	}
	// Positive control: the same scan finds the token once it really is in the database.
	st, err = store.Open(ctx, filepath.Join(dbDir, "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, "INSERT INTO leak_probe (v) VALUES (?)", second.Token); err != nil {
		t.Fatalf("plant token: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if hits := filesContaining(t, dbDir, second.Token); len(hits) == 0 {
		t.Error("the file scan did not find a token planted in the database: it cannot detect a leak")
	}
}

// filesContaining returns the files directly under dir whose bytes contain secret. A glob or read
// error fails the test: a scan that skips files proves nothing.
func filesContaining(t *testing.T, dir, secret string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("nothing to scan in %s", dir)
	}
	var hits []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if bytes.Contains(b, []byte(secret)) {
			hits = append(hits, filepath.Base(f))
		}
	}
	return hits
}

// AC3: every invalid import is rejected and the stored credential stays byte-for-byte as it was.
func TestK8sCredential_InvalidImportKeepsPrevious(t *testing.T) {
	cs, file := newCredStore(t)
	prev := validCredential(t)
	if _, err := cs.Replace(prev); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	goodCA := testCA(t)
	keyBlock := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")}))
	badKey := "-----BEGIN PRIVATE KEY-----\n!!!not-base64!!!\n-----END PRIVATE KEY-----\n"
	badCert := "-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n"
	cases := []struct {
		name   string
		mutate func(c *Credential)
		field  string
	}{
		{"malformed key block before a valid CA", func(c *Credential) { c.CAData = badKey + goodCA }, "ca_data"},
		{"malformed certificate before a valid CA", func(c *Credential) { c.CAData = badCert + goodCA }, "ca_data"},
		{"valid CA before a malformed certificate", func(c *Credential) { c.CAData = goodCA + badCert }, "ca_data"},
		{"garbage CA", func(c *Credential) { c.CAData = "not a certificate" }, "ca_data"},
		{"bad CA body", func(c *Credential) {
			c.CAData = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		}, "ca_data"},
		{"CA with leading junk", func(c *Credential) { c.CAData = "junk\n" + goodCA }, "ca_data"},
		{"CA with trailing junk", func(c *Credential) { c.CAData = goodCA + "junk" }, "ca_data"},
		{"CA that is a key block", func(c *Credential) { c.CAData = keyBlock }, "ca_data"},
		{"CA missing", func(c *Credential) { c.CAData = "" }, "ca_data"},
		{"endpoint http", func(c *Credential) { c.Endpoint = "http://10.1.2.3:6443" }, "endpoint"},
		{"endpoint user info", func(c *Credential) { c.Endpoint = "https://user:pw@10.1.2.3" }, "endpoint"},
		{"endpoint missing", func(c *Credential) { c.Endpoint = "" }, "endpoint"},
		{"server name is an IP", func(c *Credential) { c.TLSServerName = "10.1.2.3" }, "tls_server_name"},
		{"server name invalid", func(c *Credential) { c.TLSServerName = "bad name!" }, "tls_server_name"},
		{"token missing", func(c *Credential) { c.Token = "" }, "token"},
		{"token blank", func(c *Credential) { c.Token = " \n" }, "token"},
		{"token with whitespace inside", func(c *Credential) { c.Token = "ab cd" }, "token"},
		{"token with control character", func(c *Credential) { c.Token = "ab\x00cd" }, "token"},
		{"token too long", func(c *Credential) { c.Token = strings.Repeat("a", maxTokenLen+1) }, "token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCredential(t)
			tc.mutate(&c)
			_, err := cs.Replace(c)
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Replace error = %v, want *ValidationError", err)
			}
			if !hasField(verr, tc.field) {
				t.Errorf("error fields = %v, want one for %q", verr.Fields, tc.field)
			}
			assertUnchanged(t, cs, file, before, prev)
		})
	}

	t.Run("kubeconfig without a token", func(t *testing.T) {
		kc := kubeconfig{Server: "https://10.1.2.3:6443", CAData: goodCA}
		if _, err := cs.ImportKubeconfig([]byte(kc.yaml()), ""); err == nil {
			t.Fatal("ImportKubeconfig accepted a kubeconfig without a token")
		}
		assertUnchanged(t, cs, file, before, prev)
	})
	t.Run("kubeconfig with an executable mechanism", func(t *testing.T) {
		kc := kubeconfig{Server: "https://10.1.2.3:6443", CAData: goodCA, UserExtra: "    exec:\n      command: true\n"}
		if _, err := cs.ImportKubeconfig([]byte(kc.yaml()), ""); err == nil {
			t.Fatal("ImportKubeconfig accepted exec")
		}
		assertUnchanged(t, cs, file, before, prev)
	})
}

// A bundle of valid certificates is accepted, so the rejections above are about the malformed block.
func TestK8sCredential_CABundleAccepted(t *testing.T) {
	two := testCA(t) + testCA(t)
	c := validCredential(t)
	c.CAData = two
	got, err := normalizeCredential(c)
	if err != nil {
		t.Fatalf("normalizeCredential: %v", err)
	}
	if got.CAData != two {
		t.Errorf("bundle was altered")
	}
	if _, fps, msg := parseCA(two); msg != "" || len(fps) != 2 {
		t.Errorf("parseCA = %d fingerprints, %q; want 2", len(fps), msg)
	}
}

func hasField(v *ValidationError, field string) bool {
	for _, f := range v.Fields {
		if f.Field == field {
			return true
		}
	}
	return false
}

func assertUnchanged(t *testing.T, cs *CredentialStore, file string, before []byte, prev Credential) {
	t.Helper()
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("credential file changed after a rejected import (read err %v)", err)
	}
	got, err := cs.Load()
	if err != nil || got.Token != prev.Token || got.Endpoint != prev.Endpoint {
		t.Errorf("Load after rejected import = %q, %v; want the previous credential", got.Endpoint, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Errorf("runtime dir holds %d entries after a rejected import, want 1", len(entries))
	}
}

// AC5: when replacing the file fails the previous credential stays readable, no temp file is left
// and the error carries no token.
func TestK8sCredential_ReplaceFailureKeepsPrevious(t *testing.T) {
	cs, file := newCredStore(t)
	prev := validCredential(t)
	if _, err := cs.Replace(prev); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	before, _ := os.ReadFile(file)

	next := validCredential(t)
	check := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("Replace succeeded, want an error")
		}
		for _, secret := range []string{next.Token, prev.Token} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error carries a token: %v", err)
			}
		}
		assertUnchanged(t, cs, file, before, prev)
	}

	t.Run("rename fails", func(t *testing.T) {
		cs.rename = func(*os.Root, string, string) error { return errors.New("injected rename failure") }
		defer func() { cs.rename = (*os.Root).Rename }()
		_, err := cs.Replace(next)
		check(t, err)
	})
	t.Run("directory not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		dir := filepath.Dir(file)
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		defer func() { _ = os.Chmod(dir, 0o700) }()
		_, err := cs.Replace(next)
		check(t, err)
	})
}

// AC6: errors, results and metadata carry neither the token, the CA body nor the kubeconfig body; a
// Credential does not print its token.
func TestK8sCredential_NoSecretInResults(t *testing.T) {
	cs, file := newCredStore(t)
	token := sentinel(t)
	ca := testCA(t)
	body := kubeconfig{Server: "https://10.1.2.3:6443", CAData: ca, Token: token}.yaml()

	// Failures built around the token.
	var errs []error
	for _, c := range []Credential{
		{Endpoint: "http://10.1.2.3", CAData: ca, Token: token},
		{Endpoint: "https://10.1.2.3", CAData: "garbage-" + token, Token: token},
		{Endpoint: "https://10.1.2.3", CAData: ca, TLSServerName: token + "!", Token: token},
		{Endpoint: "https://10.1.2.3", CAData: ca, Token: token + " with space"},
	} {
		_, err := cs.Replace(c)
		errs = append(errs, err)
	}
	for _, bad := range []string{
		strings.Replace(body, "token:", "exec:\n      command: "+token+"\n    token:", 1),
		"token: " + token + "\n: : bad yaml [",
		strings.ReplaceAll(body, "https://10.1.2.3:6443", "http://10.1.2.3"),
		kubeconfig{Server: "https://10.1.2.3:6443", CAData: ca, Token: token, TokenFile: "/etc/" + token}.yaml(),
	} {
		_, err := cs.ImportKubeconfig([]byte(bad), "")
		errs = append(errs, err)
	}
	// A stored file that cannot be read back.
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("{\"token\": \""+token+"\" garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, loadErr := cs.Load()
	errs = append(errs, loadErr)
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	_, notSet := cs.Load()
	errs = append(errs, notSet)

	secrets := []string{token, "BEGIN CERTIFICATE", ca[:40]}
	for i, err := range errs {
		if err == nil {
			t.Errorf("case %d: want an error", i)
			continue
		}
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) {
				t.Errorf("case %d: error carries a secret (%q): %v", i, s, err)
			}
		}
	}
	if !errors.Is(notSet, ErrCredentialNotSet) {
		t.Errorf("missing file error = %v, want ErrCredentialNotSet", notSet)
	}

	// Success metadata.
	info, err := cs.ImportKubeconfig([]byte(body), "")
	if err != nil {
		t.Fatalf("ImportKubeconfig: %v", err)
	}
	meta, _ := json.Marshal(info)
	for _, s := range secrets {
		if strings.Contains(string(meta), s) {
			t.Errorf("Info carries %q: %s", s, meta)
		}
	}
	if info.Endpoint != "https://10.1.2.3:6443" || len(info.CAFingerprints) != 1 {
		t.Errorf("Info = %+v, want the endpoint and one CA fingerprint", info)
	}
	if got, err := cs.Info(); err != nil || got.Endpoint != info.Endpoint {
		t.Errorf("Info() = %+v, %v", got, err)
	}

	// The credential itself prints without the token; only the runtime reader gets it.
	c, err := cs.Load()
	if err != nil || c.Token != token {
		t.Fatalf("Load = %v; want the stored token for the runtime reader", err)
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("loaded", "credential", c)
	jsonOut, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	outputs := []string{
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%q", c),
		fmt.Sprintf("%v", &c), logBuf.String(), string(jsonOut),
	}
	for _, out := range outputs {
		if strings.Contains(out, token) || strings.Contains(out, "BEGIN CERTIFICATE") {
			t.Errorf("formatted credential leaks a secret: %q", out)
		}
	}

	// Positive controls: the same checks do fail for a type that prints its fields, and the stored
	// file shape does carry the token as JSON, so the clean results above are not vacuous.
	type plain struct{ Token, CAData string }
	var plainLog bytes.Buffer
	slog.New(slog.NewTextHandler(&plainLog, nil)).Info("loaded", "credential", plain{c.Token, c.CAData})
	storedJSON, _ := json.Marshal(storedCredential(c))
	for name, out := range map[string]string{
		"%+v of a plain struct":  fmt.Sprintf("%+v", plain{c.Token, c.CAData}),
		"slog of a plain struct": plainLog.String(),
		"stored file JSON":       string(storedJSON),
	} {
		if !strings.Contains(out, token) {
			t.Errorf("control %s does not show the token: the leak check cannot fail", name)
		}
	}
	if got := strings.Join(outputs, "\n"); !strings.Contains(got, "10.1.2.3") {
		t.Error("redacted output lost the endpoint; the checks may be reading the wrong output")
	}
}

// The store enforces its own runtime boundary: it refuses an unsafe directory or file instead of
// trusting the deployment. Cases build a good 0700/0600 setup first and break exactly one thing.
func TestK8sCredential_RuntimeLocationIsProtected(t *testing.T) {
	prev := validCredential(t)
	setup := func(t *testing.T) (*CredentialStore, string, string) {
		t.Helper()
		cs, file := newCredStore(t)
		if _, err := cs.Replace(prev); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		if _, err := cs.Load(); err != nil {
			t.Fatalf("Load of the good setup: %v", err)
		}
		return cs, file, filepath.Dir(file)
	}
	next := validCredential(t)

	t.Run("permissive existing directory is refused", func(t *testing.T) {
		cs, file, dir := setup(t)
		before, _ := os.ReadFile(file)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.Replace(next); err == nil {
			t.Fatal("Replace wrote into a 0777 directory")
		}
		if _, err := cs.Load(); err == nil {
			t.Error("Load read from a 0777 directory")
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if after, _ := os.ReadFile(file); !bytes.Equal(before, after) {
			t.Error("the previous file changed")
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Errorf("directory holds %d entries, want only the credential", len(entries))
		}
		// Control: back to 0700 the same store works again.
		if _, err := cs.Replace(next); err != nil {
			t.Errorf("Replace in a 0700 directory: %v", err)
		}
	})

	t.Run("new pre-existing permissive directory gets no file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewCredentialStore(dir).Replace(next); err == nil {
			t.Fatal("Replace accepted a 0755 directory")
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("a file was created in the unsafe directory: %d entries", len(entries))
		}
	})

	t.Run("symlinked directory is refused", func(t *testing.T) {
		cs, _, dir := setup(t)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		viaLink := NewCredentialStore(link)
		if _, err := viaLink.Replace(next); err == nil {
			t.Error("Replace followed a symlinked directory")
		}
		if _, err := viaLink.Load(); err == nil || errors.Is(err, ErrCredentialNotSet) {
			t.Errorf("Load through a symlinked directory = %v, want a refusal", err)
		}
		if got, err := cs.Load(); err != nil || got.Token != prev.Token {
			t.Errorf("the real directory changed: %v", err)
		}
	})

	t.Run("symlinked credential file is refused", func(t *testing.T) {
		cs, file, _ := setup(t)
		raw, _ := os.ReadFile(file)
		outside := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.WriteFile(outside, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, file); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.Load(); err == nil {
			t.Error("Load followed a symlinked credential file")
		}
		if _, err := cs.Replace(next); err != nil {
			t.Fatalf("Replace over a symlink: %v", err)
		}
		if fi, err := os.Lstat(file); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("after Replace the credential is %v, %v; want a regular file", fi, err)
		}
		if b, _ := os.ReadFile(outside); !bytes.Equal(b, raw) {
			t.Error("Replace wrote through the symlink")
		}
		if _, err := cs.Load(); err != nil {
			t.Errorf("Load of the replaced file: %v", err)
		}
	})

	t.Run("group or world readable file is refused", func(t *testing.T) {
		cs, file, _ := setup(t)
		for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
			if err := os.Chmod(file, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := cs.Load(); err == nil {
				t.Errorf("Load accepted mode %v", mode)
			}
		}
		if err := os.Chmod(file, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.Load(); err != nil {
			t.Errorf("Load of a 0600 file: %v", err)
		}
	})

	t.Run("not a regular file or too large is refused", func(t *testing.T) {
		cs, file, _ := setup(t)
		raw, _ := os.ReadFile(file)
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(file, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.Load(); err == nil || errors.Is(err, ErrCredentialNotSet) {
			t.Errorf("Load of a directory = %v, want a refusal", err)
		}
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, append(raw, bytes.Repeat([]byte(" "), 1<<20)...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.Load(); err == nil {
			t.Error("Load read an oversized file")
		}
	})

	t.Run("a missing directory is just not set", func(t *testing.T) {
		cs, _ := newCredStore(t)
		if _, err := cs.Load(); !errors.Is(err, ErrCredentialNotSet) {
			t.Errorf("Load = %v, want ErrCredentialNotSet", err)
		}
	})
}

// L2: a store with no directory refuses everything with ErrCredentialDirNotSet; it never falls back
// to the working directory or any default location.
func TestK8sCredential_EmptyDirIsRefused(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	s := NewCredentialStore("")
	if _, err := s.Replace(validCredential(t)); !errors.Is(err, ErrCredentialDirNotSet) {
		t.Fatalf("Replace with no directory = %v, want ErrCredentialDirNotSet", err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrCredentialDirNotSet) {
		t.Fatalf("Load with no directory = %v, want ErrCredentialDirNotSet", err)
	}
	if _, err := s.Info(); !errors.Is(err, ErrCredentialDirNotSet) {
		t.Fatalf("Info with no directory = %v, want ErrCredentialDirNotSet", err)
	}
	entries, _ := os.ReadDir(cwd)
	if len(entries) != 0 {
		t.Fatalf("a store without a directory wrote into the working directory: %v", entries)
	}
}
