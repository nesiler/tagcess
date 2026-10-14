package groupsclaim

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/hook"
	"github.com/nesiler/tagcess/internal/zitadel"
)

const (
	testKey     = "zitadel-groups-test-key"
	testProject = "289100000000000001"
)

// fakeGrants is a stub GrantReader that counts reads.
type fakeGrants struct {
	mu     sync.Mutex
	grants []zitadel.Grant
	err    error
	calls  int
}

func (f *fakeGrants) ListGrants(context.Context) ([]zitadel.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.grants, f.err
}

func (f *fakeGrants) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// signatureHeader reproduces Zitadel v4.16.0 ComputeSignatureHeader (pkg/actions/signing.go).
func signatureHeader(t time.Time, body []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = fmt.Fprintf(mac, "%d.", t.Unix())
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", t.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

// payload builds a ContextInfo body; grants is the raw user_grants JSON.
func payload(userID, grants string) []byte {
	return []byte(fmt.Sprintf(`{"function":"function/preuserinfo","user":{"id":%q},"userinfo":{"sub":%q},"user_grants":%s}`, userID, userID, grants))
}

func post(t *testing.T, h *Handler, header string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/groups", bytes.NewReader(body))
	if header != "" {
		req.Header.Set(hook.Header, header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newHandler(t *testing.T, grants GrantReader) *Handler {
	t.Helper()
	h, err := New(Config{SigningKey: []byte(testKey), ProjectID: testProject, Grants: grants})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

// claimResponse parses the append_claims envelope.
type claimResponse struct {
	AppendClaims []struct {
		Key   string   `json:"key"`
		Value []string `json:"value"`
	} `json:"append_claims"`
}

func decodeClaims(t *testing.T, rec *httptest.ResponseRecorder) claimResponse {
	t.Helper()
	var resp claimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return resp
}

// TestGroups_ClaimFromGrants is AC2: a signed preuserinfo payload carrying the vpn project's
// grants yields exactly the append_claims groups response; other projects are ignored and
// duplicate roles are collapsed.
func TestGroups_ClaimFromGrants(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	reader := &fakeGrants{err: errors.New("must not read the API when the payload has grants")}
	h := newHandler(t, reader)
	h.clock = func() time.Time { return now }

	grants := fmt.Sprintf(`[
		{"project_id":"%s","project_name":"vpn","roles":["devops","developer","devops"]},
		{"project_id":"289100000000000099","project_name":"other","roles":["admin"]}
	]`, testProject)
	body := payload("289100000000000042", grants)
	rec := post(t, h, signatureHeader(now, body, testKey), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	got := decodeClaims(t, rec)
	if len(got.AppendClaims) != 1 {
		t.Fatalf("append_claims = %+v, want one groups claim", got.AppendClaims)
	}
	if got.AppendClaims[0].Key != "groups" {
		t.Fatalf("claim key = %q, want %q", got.AppendClaims[0].Key, "groups")
	}
	want := []string{"developer", "devops"}
	if strings.Join(got.AppendClaims[0].Value, ",") != strings.Join(want, ",") {
		t.Fatalf("groups = %v, want %v (sorted, deduped)", got.AppendClaims[0].Value, want)
	}
	if reader.readCount() != 0 {
		t.Fatalf("GrantReader called %d times, want 0 (payload grants are authoritative)", reader.readCount())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

// TestGroups_InvalidSignature is AC2: an unsigned, wrongly signed or stale request is refused with
// 401 and produces no claim.
func TestGroups_InvalidSignature(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	body := payload("289100000000000042", fmt.Sprintf(`[{"project_id":"%s","roles":["devops"]}]`, testProject))

	cases := map[string]string{
		"missing header": "",
		"malformed":      "garbage",
		"wrong key":      signatureHeader(now, body, "not-the-key"),
		"stale":          signatureHeader(now.Add(-10*time.Minute), body, testKey),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHandler(t, nil)
			h.clock = func() time.Time { return now }
			rec := post(t, h, header, body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if strings.Contains(rec.Body.String(), "append_claims") {
				t.Fatalf("rejected request produced a claim: %q", rec.Body.String())
			}
		})
	}
}

// TestGroups_PayloadFallbackReadsAPI is AC6: the payload is used first; only when it has no vpn
// grant is the API read, and when neither source has roles no claim is added.
func TestGroups_PayloadFallbackReadsAPI(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	const userID = "289100000000000042"

	t.Run("payload has no vpn grant, API is read", func(t *testing.T) {
		reader := &fakeGrants{grants: []zitadel.Grant{
			{UserID: userID, Role: "devops"},
			{UserID: "someone-else", Role: "admin"},
		}}
		h := newHandler(t, reader)
		h.clock = func() time.Time { return now }
		body := payload(userID, `[{"project_id":"289100000000000099","roles":["admin"]}]`)

		rec := post(t, h, signatureHeader(now, body, testKey), body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		got := decodeClaims(t, rec)
		if len(got.AppendClaims) != 1 || strings.Join(got.AppendClaims[0].Value, ",") != "devops" {
			t.Fatalf("append_claims = %+v, want groups [devops] from the API", got.AppendClaims)
		}
		if reader.readCount() != 1 {
			t.Fatalf("GrantReader called %d times, want 1", reader.readCount())
		}
	})

	t.Run("empty vpn grant in payload is authoritative", func(t *testing.T) {
		reader := &fakeGrants{grants: []zitadel.Grant{{UserID: userID, Role: "devops"}}}
		h := newHandler(t, reader)
		h.clock = func() time.Time { return now }
		body := payload(userID, fmt.Sprintf(`[{"project_id":"%s","roles":[]}]`, testProject))

		rec := post(t, h, signatureHeader(now, body, testKey), body)
		got := decodeClaims(t, rec)
		if len(got.AppendClaims) != 0 {
			t.Fatalf("append_claims = %+v, want none (empty grant is authoritative)", got.AppendClaims)
		}
		if reader.readCount() != 0 {
			t.Fatalf("GrantReader called %d times, want 0", reader.readCount())
		}
	})

	t.Run("no source, no claim", func(t *testing.T) {
		h := newHandler(t, &fakeGrants{})
		h.clock = func() time.Time { return now }
		body := payload(userID, `[]`)

		rec := post(t, h, signatureHeader(now, body, testKey), body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := decodeClaims(t, rec); len(got.AppendClaims) != 0 {
			t.Fatalf("append_claims = %+v, want none", got.AppendClaims)
		}
		if raw := rec.Body.String(); raw != `{"append_claims":[]}` {
			t.Fatalf("empty claim response = %q, want the array contract", raw)
		}
	})

	t.Run("failed API read adds no claim (fail safe)", func(t *testing.T) {
		h := newHandler(t, &fakeGrants{err: errors.New("zitadel down")})
		h.clock = func() time.Time { return now }
		body := payload(userID, `[]`)

		rec := post(t, h, signatureHeader(now, body, testKey), body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := decodeClaims(t, rec); len(got.AppendClaims) != 0 {
			t.Fatalf("append_claims = %+v, want none (a failed read must never widen access)", got.AppendClaims)
		}
	})
}

// TestGroups_NoRoleStore is AC6: the package keeps no role store (no SQL, no store/db import, no
// migration). Roles are derived from the payload or read from Zitadel, never persisted here.
func TestGroups_NoRoleStore(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	var imports []string
	var source strings.Builder
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path) //nolint:gosec // fixed package dir
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			imports = append(imports, strings.Trim(imp.Path.Value, `"`))
		}
		source.WriteString(strings.ToLower(string(src)))
	}

	for _, imp := range imports {
		for _, bad := range []string{"database/sql", "sqlite", "internal/store"} {
			if strings.Contains(imp, bad) {
				t.Fatalf("groupsclaim imports %q; it must not keep a role store", imp)
			}
		}
	}
	for _, kw := range []string{"create table", "insert into", "delete from", "drop table", "alter table"} {
		if strings.Contains(source.String(), kw) {
			t.Fatalf("groupsclaim source contains SQL (%q); it must not keep a role store", kw)
		}
	}
}

func TestNew_RequiresKeyAndProject(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New returned nil error without a signing key")
	}
	if _, err := New(Config{SigningKey: []byte(testKey)}); err == nil {
		t.Fatal("New returned nil error without a project id")
	}
}

// I13: a served claim with roles fires the OnRoles hook once; refused requests and role-less users
// do not (positive controls).
func TestGroups_OnRolesHook(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	calls := 0
	h, err := New(Config{SigningKey: []byte(testKey), ProjectID: testProject, OnRoles: func() { calls++ }})
	if err != nil {
		t.Fatal(err)
	}
	h.clock = func() time.Time { return now }

	withRole := payload("u1", fmt.Sprintf(`[{"project_id":%q,"roles":["devops"]}]`, testProject))
	noRole := payload("u2", "[]")

	post(t, h, signatureHeader(now, noRole, testKey), noRole)
	post(t, h, signatureHeader(now, withRole, "wrong-key"), withRole)
	if calls != 0 {
		t.Fatalf("hook fired %d times for a role-less user or a bad signature, want 0", calls)
	}
	post(t, h, signatureHeader(now, withRole, testKey), withRole)
	if calls != 1 {
		t.Fatalf("hook fired %d times for a signed request with roles, want 1", calls)
	}
}

type infoLog struct {
	mu    sync.Mutex
	warns []string
	infos [][]any
}

func (l *infoLog) Warn(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}

func (l *infoLog) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, append([]any{msg}, args...))
}

// F5 F1: a served claim leaves one INFO line with the role count and source only; a rejected request
// leaves none (positive control) and the line never carries the user or the role names.
func TestGroups_ServedClaimLogsOneInfoLine(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	lg := &infoLog{}
	h, err := New(Config{SigningKey: []byte(testKey), ProjectID: testProject, Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	h.clock = func() time.Time { return now }
	body := payload("user-secret-id", fmt.Sprintf(`[{"project_id":%q,"roles":["devops"]}]`, testProject))

	post(t, h, signatureHeader(now, body, "wrong-key"), body)
	if len(lg.infos) != 0 {
		t.Fatalf("a rejected request logged INFO: %v", lg.infos)
	}
	post(t, h, signatureHeader(now, body, testKey), body)
	if len(lg.infos) != 1 || lg.infos[0][0] != "groups claim served" {
		t.Fatalf("INFO lines = %v, want exactly one \"groups claim served\"", lg.infos)
	}
	flat := fmt.Sprint(lg.infos)
	for _, leak := range []string{"user-secret-id", "devops", testKey} {
		if strings.Contains(flat, leak) {
			t.Errorf("INFO line leaks %q: %s", leak, flat)
		}
	}
}
