//go:build integration

// Integration tests for F1-026: the seed installs the Actions v2 `rest_call` target that fills the
// `groups` claim during `preuserinfo`, and Caddy's `allowed_groups=devops` enforces that claim
// against a real oauth2-proxy session. They assume `make lab-up` has already run (ADR 0014); run
// them with `make lab-integration`.
package compose_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/grpc/metadata"

	actionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action/v2"

	"github.com/nesiler/tagcess/internal/groupsclaim"
	"github.com/nesiler/tagcess/internal/hook"
	"github.com/nesiler/tagcess/test/compose/seed"
)

// oauth2ProxyCookieName mirrors oauth2-proxy.cfg's cookie_name.
const oauth2ProxyCookieName = "tagcess_test"

// TestCompose_GroupsActionSeeded is AC1: the seed installs a `rest_call` target for the `groups`
// claim plus a `preuserinfo` execution, caches its signing key 0600, and is idempotent.
func TestCompose_GroupsActionSeeded(t *testing.T) {
	pat := readBootstrapPAT(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+pat)
	conn := dialZitadel(t)
	defer func() { _ = conn.Close() }()
	actions := actionv2.NewActionServiceClient(conn)

	webhook := findWebhookTarget(t, listTargets(t, ctx, actions))
	groupsURL := strings.TrimSuffix(webhook.GetEndpoint(), "/hook") + "/groups"

	first, err := seed.SeedZitadel(ctx, groupsSeedConfig(t, pat, webhook.GetEndpoint(), groupsURL))
	if err != nil {
		t.Fatalf("first seed run: %v", err)
	}
	if first.GroupsTargetID == "" {
		t.Fatal("seed did not report a groups target id")
	}

	target := findGroupsTarget(t, listTargets(t, ctx, actions))
	if target.GetRestCall() == nil {
		t.Fatalf("groups target type = %T, want rest_call (the response is applied)", target.GetTargetType())
	}
	if target.GetEndpoint() != groupsURL {
		t.Fatalf("groups target endpoint = %q, want %q", target.GetEndpoint(), groupsURL)
	}
	if target.GetId() != first.GroupsTargetID {
		t.Fatalf("groups target id = %q, seed returned %q", target.GetId(), first.GroupsTargetID)
	}

	// The signing key lives only in the gitignored secrets dir, 0600.
	keyPath := filepath.Join(endpoint(t).SecretsDir, seed.GroupsSigningKeyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("groups signing key not written (Zitadel never shows it again): %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("groups signing key mode = %04o, want 0600", perm)
	}
	if key, err := os.ReadFile(keyPath); err != nil || strings.TrimSpace(string(key)) == "" { //nolint:gosec // test reading the fixture
		t.Fatalf("groups signing key is empty: %v", err)
	}

	assertGroupsExecution(t, ctx, actions, target.GetId())

	// Idempotency: a second seed must not change the target id or add a second execution.
	second, err := seed.SeedZitadel(ctx, groupsSeedConfig(t, pat, webhook.GetEndpoint(), groupsURL))
	if err != nil {
		t.Fatalf("second seed run: %v", err)
	}
	if second.GroupsTargetID != first.GroupsTargetID {
		t.Fatalf("groups target id changed across seed runs: %q then %q", first.GroupsTargetID, second.GroupsTargetID)
	}
	if got := filterTargets(listTargets(t, ctx, actions), seed.GroupsTargetName); len(got) != 1 {
		t.Fatalf("re-seeding left %d groups targets, want 1", len(got))
	}
	assertGroupsExecution(t, ctx, actions, target.GetId())
}

// assertGroupsExecution checks that exactly one `preuserinfo` execution points at targetID.
func assertGroupsExecution(t *testing.T, ctx context.Context, c actionv2.ActionServiceClient, targetID string) {
	t.Helper()
	var matched [][]string
	for _, e := range listExecutions(t, ctx, c) {
		fn := e.GetCondition().GetFunction()
		if fn == nil || fn.GetName() != seed.FunctionPreuserinfo {
			continue
		}
		matched = append(matched, e.GetTargets())
	}
	if len(matched) != 1 || len(matched[0]) != 1 || matched[0][0] != targetID {
		t.Fatalf("preuserinfo execution -> %v, want exactly one pointing at %s", matched, targetID)
	}
}

// TestCompose_GroupsClaimDevopsAllowed is AC3: an oauth2-proxy session whose `groups` claim holds
// devops passes Caddy's `allowed_groups=devops` check and reaches the upstream with 200.
func TestCompose_GroupsClaimDevopsAllowed(t *testing.T) {
	cookie := forgeSessionCookie(t, []string{"devops"})
	if code, _ := getWithSession(t, cookie, ""); code != http.StatusOK {
		t.Fatalf("devops session: status = %d, want %d", code, http.StatusOK)
	}
}

// TestCompose_GroupsClaimDeveloperDenied is AC4: a session that only holds developer is refused
// with 403 before reaching the upstream.
func TestCompose_GroupsClaimDeveloperDenied(t *testing.T) {
	cookie := forgeSessionCookie(t, []string{"developer"})
	if code, _ := getWithSession(t, cookie, ""); code != http.StatusForbidden {
		t.Fatalf("developer session: status = %d, want %d", code, http.StatusForbidden)
	}
}

// TestCompose_SpoofedGroupsHeaderRejected is AC5: a client-supplied X-Auth-Request-Groups header is
// stripped before forward_auth and cannot turn a developer session into a 200.
func TestCompose_SpoofedGroupsHeaderRejected(t *testing.T) {
	cookie := forgeSessionCookie(t, []string{"developer"})
	code, _ := getWithSession(t, cookie, "devops")
	if code != http.StatusForbidden {
		t.Fatalf("spoofed header: status = %d, want %d", code, http.StatusForbidden)
	}
}

// TestCompose_GroupsClaimDelivered serves the real groupsclaim handler at the exact address the
// seeded target calls and proves the HTTP contract with the seeded signing key: an unsigned
// delivery is refused and a signed preuserinfo payload yields the append_claims groups response.
// (Zitadel itself only calls this during a login; that full chain is F1-021.)
func TestCompose_GroupsClaimDelivered(t *testing.T) {
	pat := readBootstrapPAT(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+pat)
	conn := dialZitadel(t)
	defer func() { _ = conn.Close() }()
	actions := actionv2.NewActionServiceClient(conn)

	webhook := findWebhookTarget(t, listTargets(t, ctx, actions))
	groupsURL := strings.TrimSuffix(webhook.GetEndpoint(), "/hook") + "/groups"
	res, err := seed.SeedZitadel(ctx, groupsSeedConfig(t, pat, webhook.GetEndpoint(), groupsURL))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	target := findGroupsTarget(t, listTargets(t, ctx, actions))
	u, err := url.Parse(target.GetEndpoint())
	if err != nil || u.Host == "" {
		t.Fatalf("groups endpoint %q is not usable: %v", target.GetEndpoint(), err)
	}

	key := strings.TrimSpace(readFile(t, filepath.Join(endpoint(t).SecretsDir, seed.GroupsSigningKeyFile)))
	handler, err := groupsclaim.New(groupsclaim.Config{SigningKey: []byte(key), ProjectID: res.ProjectID})
	if err != nil {
		t.Fatalf("build groupsclaim handler: %v", err)
	}
	ln, err := listenWithRetry(t, u.Host)
	if err != nil {
		t.Fatalf("listen on %s (the address the target calls): %v", u.Host, err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	const userID = "289100000000000042"
	body := []byte(fmt.Sprintf(`{"function":"function/preuserinfo","user":{"id":%q},"userinfo":{"sub":%q},"user_grants":[{"project_id":%q,"project_name":"vpn","roles":["devops"]}]}`, userID, userID, res.ProjectID))

	// Unsigned: refused, no claim.
	unsigned, err := http.Post(target.GetEndpoint(), "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unsigned POST: %v", err)
	}
	_ = unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned POST: status %d, want 401", unsigned.StatusCode)
	}

	// Signed with the seeded key (Zitadel's algorithm): the vpn grant becomes the groups claim.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target.GetEndpoint(), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build signed request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hook.Header, signedHeader(body, key, time.Now()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("signed POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed POST: status %d, want 200", resp.StatusCode)
	}
	var got struct {
		AppendClaims []struct {
			Key   string   `json:"key"`
			Value []string `json:"value"`
		} `json:"append_claims"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.AppendClaims) != 1 || got.AppendClaims[0].Key != "groups" || strings.Join(got.AppendClaims[0].Value, ",") != "devops" {
		t.Fatalf("append_claims = %+v, want groups [devops]", got.AppendClaims)
	}
}

// signedHeader reproduces Zitadel v4.16.0's Zitadel-Signature for a payload.
func signedHeader(body []byte, key string, now time.Time) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = fmt.Fprintf(mac, "%d.", now.Unix())
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

// listenWithRetry binds addr, retrying briefly while a prior test's listener is released.
func listenWithRetry(t *testing.T, addr string) (net.Listener, error) {
	t.Helper()
	var (
		ln  net.Listener
		err error
	)
	for i := 0; i < 20; i++ {
		if ln, err = net.Listen("tcp", addr); err == nil {
			return ln, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, err
}

// getWithSession sends a GET to Caddy with the forged session cookie and an optional spoofed
// X-Auth-Request-Groups header, without following redirects (a 302 would mean "no session").
func getWithSession(t *testing.T, cookie, spoofedGroups string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Cookie", oauth2ProxyCookieName+"="+cookie)
	if spoofedGroups != "" {
		req.Header.Set("X-Auth-Request-Groups", spoofedGroups)
	}
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET Caddy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get("Location")
}

// groupsSeedConfig is the seed configuration for the groups activation: the lab endpoint plus the
// existing webhook endpoint and the groups endpoint derived from it.
func groupsSeedConfig(t *testing.T, pat, webhookURL, groupsURL string) seed.Config {
	t.Helper()
	return seed.Config{
		ZitadelAddr:            endpoint(t).Addr,
		ZitadelTLS:             endpoint(t).TLS,
		BootstrapPAT:           pat,
		SecretsDir:             endpoint(t).SecretsDir,
		EnvFile:                filepath.Join(composeDir(t), ".env"),
		HeadscaleRedirectURI:   "http://localhost:8090/oidc/callback",
		OAuth2ProxyRedirectURI: "http://localhost:8080/oauth2/callback",
		WebhookURL:             webhookURL,
		GroupsURL:              groupsURL,
	}
}

// oauth2Session is the subset of oauth2-proxy's sessions.SessionState the forged cookie carries;
// the msgpack tags are oauth2-proxy's (pkg/apis/sessions).
type oauth2Session struct {
	Email             string   `msgpack:"e,omitempty"`
	User              string   `msgpack:"u,omitempty"`
	Groups            []string `msgpack:"g,omitempty"`
	PreferredUsername string   `msgpack:"pu,omitempty"`
}

// forgeSessionCookie builds a valid oauth2-proxy v7 cookie-store session cookie for the given
// groups, exactly as oauth2-proxy does: msgpack -> lz4 -> AES-CFB -> base64, then the
// `<value>|<ts>|<sig>` signature (pkg/sessions/cookie + pkg/encryption). This lets the tests reach
// the downstream authorization path without driving the interactive browser login (F1-020 [Ö]).
func forgeSessionCookie(t *testing.T, groups []string) string {
	t.Helper()
	secret := envFileValue(t, "OAUTH2_PROXY_COOKIE_SECRET")
	now := time.Now()

	packed, err := msgpack.Marshal(oauth2Session{
		Email:             "f126@tagcess.test",
		User:              "f126",
		Groups:            groups,
		PreferredUsername: "f126",
	})
	if err != nil {
		t.Fatalf("msgpack session: %v", err)
	}

	block, err := aes.NewCipher(secretBytes(secret))
	if err != nil {
		t.Fatalf("cookie secret is not a usable AES key: %v", err)
	}
	compressed := lz4Compress(t, packed)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("iv: %v", err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(compressed))
	copy(ciphertext, iv)
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], compressed)

	encoded := base64.URLEncoding.EncodeToString(ciphertext)
	ts := strconv.FormatInt(now.Unix(), 10)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(oauth2ProxyCookieName))
	mac.Write([]byte(encoded))
	mac.Write([]byte(ts))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return encoded + "|" + ts + "|" + sig
}

// secretBytes mirrors oauth2-proxy's encryption.SecretBytes: a base64 secret that decodes to a
// valid AES length is used decoded, otherwise the raw string is the key.
func secretBytes(secret string) []byte {
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(secret, "=")); err == nil {
		for _, n := range []int{16, 24, 32} {
			if len(b) == n {
				return b
			}
		}
	}
	return []byte(secret)
}

// lz4Compress mirrors oauth2-proxy's sessions.lz4Compress (LZ4 block size 64 KiB, fast level).
func lz4Compress(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := lz4.NewWriter(nil)
	zw.Apply(lz4.BlockSizeOption(lz4.BlockSize(65536)), lz4.CompressionLevelOption(lz4.Fast))
	zw.Reset(buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("lz4 write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("lz4 close: %v", err)
	}
	return buf.Bytes()
}

func findGroupsTarget(t *testing.T, targets []*actionv2.Target) *actionv2.Target {
	t.Helper()
	got := filterTargets(targets, seed.GroupsTargetName)
	if len(got) != 1 {
		t.Fatalf("targets named %q = %d, want exactly 1", seed.GroupsTargetName, len(got))
	}
	return got[0]
}
