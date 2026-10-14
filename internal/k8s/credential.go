package k8s

// The credential (F4-003) is what tagcess needs to read the cluster: endpoint, CA data, TLS server
// name and a time-limited token. An operator uploads it from the UI; tagcess never creates or
// refreshes it. It lives in one file in a runtime directory outside SQLite, the repo and the backup
// set, replaced atomically so a failed upload keeps the previous one. The token is handed only to
// the runtime reader (Load); results, errors and formatting never carry it.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"
)

const (
	credentialFile = "k8s-credential.json" //nolint:gosec // G101: a file name, not a secret
	maxTokenLen    = 8192                  // [Ö] service account tokens are well under 2 KiB
	maxCADataLen   = 65536                 // [Ö] a handful of certificates
	credentialPerm = 0o600
	runtimeDirPerm = 0o700
	maxStoredLen   = 256 << 10 // [Ö] token + CA bundle as JSON; anything bigger is not our file
)

// ErrCredentialNotSet means no credential has been uploaded yet.
var ErrCredentialNotSet = errors.New("k8s: credential is not set")

// ErrCredentialDirNotSet means no credential directory is configured (k8s_auth_dir): nothing is read
// or stored, and no default location is used.
var ErrCredentialDirNotSet = errors.New("k8s: the credential directory is not configured")

// errCredentialUnreadable is deliberately generic: the stored text is never echoed.
var errCredentialUnreadable = errors.New("k8s: stored credential is not readable")

// errUnsafeLocation means the runtime directory or credential file is not owner-only, not ours, or a
// symlink. Nothing is read from or written to it.
var errUnsafeLocation = errors.New("k8s: credential location is not protected (owner-only directory and 0600 regular file required)")

// Credential is the narrow internal model. Token is a secret: Credential prints without it, and
// json:"-" keeps the token and CA body out of any JSON encoding of it (the file uses storedCredential).
type Credential struct {
	Endpoint      string `json:"endpoint"`                  // https://host[:port][/path], as in Profile
	CAData        string `json:"-"`                         // PEM, CERTIFICATE blocks only
	TLSServerName string `json:"tls_server_name,omitempty"` // optional DNS name for certificate verification when Endpoint is an IP
	Token         string `json:"-"`
}

func (c Credential) redacted() string {
	return fmt.Sprintf("k8s.Credential{Endpoint:%q TLSServerName:%q CAData:<redacted> Token:<redacted>}", c.Endpoint, c.TLSServerName)
}

// String, GoString and LogValue keep the token and CA body out of %v, %+v, %#v and slog.
func (c Credential) String() string   { return c.redacted() }
func (c Credential) GoString() string { return c.redacted() }
func (c Credential) LogValue() slog.Value {
	return slog.StringValue(c.redacted())
}

// Info is the metadata of the stored credential that is safe to show and log: it has no token and
// no certificate body, only the CA fingerprints (SHA-256 of the DER) so an operator can tell which
// CA is active.
type Info struct {
	Endpoint       string   `json:"endpoint"`
	TLSServerName  string   `json:"tls_server_name,omitempty"`
	CAFingerprints []string `json:"ca_fingerprints"`
}

// normalizeCredential validates c and returns its canonical form. Messages never repeat the values.
func normalizeCredential(c Credential) (Credential, error) {
	var verr ValidationError
	fail := func(field, msg string) { verr.Fields = append(verr.Fields, FieldError{field, msg}) }
	var out Credential

	endpoint, msg := parseEndpoint(c.Endpoint)
	if msg != "" {
		fail("endpoint", msg)
	}
	out.Endpoint = endpoint

	if c.TLSServerName != "" {
		name, ok := normalizeServerName(c.TLSServerName)
		if !ok {
			fail("tls_server_name", "must be a DNS name, not an IP address")
		}
		out.TLSServerName = name
	}

	if ca, _, msg := parseCA(c.CAData); msg != "" {
		fail("ca_data", msg)
	} else {
		out.CAData = ca
	}

	token := strings.TrimSpace(c.Token)
	switch {
	case token == "":
		fail("token", "is required")
	case len(token) > maxTokenLen:
		fail("token", "is too long")
	case strings.ContainsFunc(token, func(r rune) bool { return r <= ' ' || r > '~' }):
		fail("token", "must not contain whitespace or control characters")
	}
	out.Token = token

	if len(verr.Fields) > 0 {
		return Credential{}, &verr
	}
	return out, nil
}

// parseCA returns the canonical PEM and the SHA-256 fingerprints of its certificates, or a message
// saying why not. Only CERTIFICATE blocks that parse are accepted, with nothing else around them.
func parseCA(s string) (canonical string, fingerprints []string, msg string) {
	rest := bytes.TrimSpace([]byte(s))
	if len(rest) == 0 {
		return "", nil, "is required"
	}
	if len(rest) > maxCADataLen {
		return "", nil, "is too large"
	}
	const bad = "must be PEM certificates only"
	var out bytes.Buffer
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return "", nil, bad
		}
		var block *pem.Block
		before := rest
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return "", nil, bad
		}
		// pem.Decode skips a malformed block and returns the next valid one; the text it consumed
		// must be exactly one block.
		consumed := before[:len(before)-len(rest)]
		if bytes.Count(consumed, []byte("-----BEGIN ")) != 1 || bytes.Count(consumed, []byte("-----END ")) != 1 {
			return "", nil, bad
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", nil, "contains a certificate that cannot be parsed"
		}
		if err := pem.Encode(&out, block); err != nil {
			return "", nil, bad
		}
		sum := sha256.Sum256(block.Bytes)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
		rest = bytes.TrimSpace(rest)
	}
	return out.String(), fingerprints, ""
}

func infoOf(c Credential) Info {
	_, fps, _ := parseCA(c.CAData)
	return Info{Endpoint: c.Endpoint, TLSServerName: c.TLSServerName, CAFingerprints: fps}
}

// CredentialStore keeps the credential in a file under a runtime directory. The directory comes from
// the deployment; if it does not exist it is created owner-only. An existing directory must already
// be owned by this process's user with no group/other access and must not be a symlink, and the file
// must be a regular 0600 file of ours: otherwise the store refuses to read or write (errUnsafeLocation).
type CredentialStore struct {
	dir    string
	mu     sync.Mutex
	rename func(root *os.Root, oldname, newname string) error // (*os.Root).Rename; replaced in tests
}

// NewCredentialStore returns a store over the runtime directory dir.
func NewCredentialStore(dir string) *CredentialStore {
	return &CredentialStore{dir: dir, rename: (*os.Root).Rename}
}

// ownedByUs reports whether fi belongs to the effective user of this process. Where the owner cannot
// be determined the answer is no.
func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// openDir opens the runtime directory as a root so every later access is relative to the verified
// directory and cannot be redirected by a symlink. With create the directory is made owner-only when
// it is missing. A directory that is a symlink, is not ours or is open to group/other is refused
// before anything is created in it. A missing directory without create is os.ErrNotExist.
func (s *CredentialStore) openDir(create bool) (*os.Root, error) {
	if s.dir == "" {
		return nil, ErrCredentialDirNotSet
	}
	fi, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := os.MkdirAll(s.dir, runtimeDirPerm); err != nil {
			return nil, err
		}
		fi, err = os.Lstat(s.dir)
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errUnsafeLocation // includes a symlink: Lstat does not follow it
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, err
	}
	// The opened directory must be the one inspected, so a swap in between is caught.
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(fi, opened) || !ownedByUs(opened) || opened.Mode().Perm()&0o077 != 0 {
		_ = root.Close()
		return nil, errUnsafeLocation
	}
	return root, nil
}

// storedCredential is the file's JSON shape; unknown keys make the file unreadable.
type storedCredential struct {
	Endpoint      string `json:"endpoint"`
	CAData        string `json:"ca_data"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	Token         string `json:"token"`
}

// ImportKubeconfig parses a kubeconfig (see ParseKubeconfig) and replaces the stored credential.
func (s *CredentialStore) ImportKubeconfig(data []byte, contextName string) (Info, error) {
	c, err := ParseKubeconfig(data, contextName)
	if err != nil {
		return Info{}, err
	}
	return s.Replace(c)
}

// Replace validates c and writes it as the new credential in one atomic step. On any error the
// previous file is untouched and still readable.
func (s *CredentialStore) Replace(c Credential) (Info, error) {
	canon, err := normalizeCredential(c)
	if err != nil {
		return Info{}, err
	}
	body, err := json.Marshal(storedCredential(canon))
	if err != nil {
		return Info{}, errors.New("k8s: encode credential failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeAtomic(body); err != nil {
		return Info{}, fmt.Errorf("k8s: replace credential: %w", err)
	}
	return infoOf(canon), nil
}

// writeAtomic writes body to a temp file in the verified directory (owner-only from creation), syncs
// it and renames it over the credential file. A symlink at the credential name is replaced, not
// followed. The temp file is removed on every failure.
func (s *CredentialStore) writeAtomic(body []byte) error {
	root, err := s.openDir(true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	name := "." + credentialFile + ".tmp-" + hex.EncodeToString(suffix[:])
	tmp, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, credentialPerm)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = tmp.Close()
		_ = root.Remove(name)
		return err
	}
	if err := tmp.Chmod(credentialPerm); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(body); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := s.rename(root, name, credentialFile); err != nil {
		_ = root.Remove(name)
		return err
	}
	if d, err := root.Open("."); err == nil { // make the rename itself durable
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Load reads the stored credential for the runtime reader; it is the only way to get the token
// back. A missing file is ErrCredentialNotSet; an unreadable or invalid one is an error and the file
// is not rewritten.
func (s *CredentialStore) Load() (Credential, error) {
	raw, err := s.readFile()
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, ErrCredentialNotSet
	}
	if err != nil {
		return Credential{}, err
	}
	var st storedCredential
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return Credential{}, errCredentialUnreadable // json errors may quote the input
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Credential{}, errCredentialUnreadable
	}
	c, err := normalizeCredential(Credential(st))
	if err != nil {
		return Credential{}, errCredentialUnreadable
	}
	return c, nil
}

// readFile returns the credential file's bytes after checking that it is a regular, owner-only file of
// ours inside a protected directory, and not larger than a credential can be. Paths are never echoed.
func (s *CredentialStore) readFile() ([]byte, error) {
	root, err := s.openDir(false)
	if err != nil {
		if errors.Is(err, errUnsafeLocation) || errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrCredentialDirNotSet) {
			return nil, err
		}
		return nil, errors.New("k8s: read credential failed")
	}
	defer func() { _ = root.Close() }()

	linfo, err := root.Lstat(credentialFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, errors.New("k8s: read credential failed")
	}
	if !linfo.Mode().IsRegular() {
		return nil, errUnsafeLocation // symlink, directory, device...
	}
	f, err := root.Open(credentialFile)
	if err != nil {
		return nil, errors.New("k8s: read credential failed")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !os.SameFile(linfo, info) || !info.Mode().IsRegular() || !ownedByUs(info) || info.Mode().Perm()&0o077 != 0 {
		return nil, errUnsafeLocation
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxStoredLen+1))
	if err != nil {
		return nil, errors.New("k8s: read credential failed")
	}
	if len(raw) > maxStoredLen {
		return nil, errCredentialUnreadable
	}
	return raw, nil
}

// Info returns the safe metadata of the stored credential, never the token.
func (s *CredentialStore) Info() (Info, error) {
	c, err := s.Load()
	if err != nil {
		return Info{}, err
	}
	return infoOf(c), nil
}
