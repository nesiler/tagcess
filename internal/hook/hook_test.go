package hook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
)

const testKey = "zitadel-webhook-test-key"

// fakeTrigger counts the signals that reach the scheduler.
type fakeTrigger struct {
	mu    sync.Mutex
	count int
}

func (f *fakeTrigger) Signal() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
}

func (f *fakeTrigger) signals() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

// fakeClock is a settable time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// fakeLogger captures the rate-limited rejection entries the hook emits.
type fakeLogger struct {
	mu    sync.Mutex
	msgs  []string
	args  [][]any
	infos [][]any // INFO lines: msg first, then the key/value args
}

func (f *fakeLogger) Warn(msg string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, msg)
	f.args = append(f.args, append([]any(nil), args...))
}

func (f *fakeLogger) Info(msg string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.infos = append(f.infos, append([]any{msg}, args...))
}

func (f *fakeLogger) infoEntries() [][]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]any(nil), f.infos...)
}

func (f *fakeLogger) entries() [][]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]any, len(f.args))
	copy(out, f.args)
	return out
}

func newTestHandler(t *testing.T, clock func() time.Time) (*Handler, *fakeTrigger) {
	t.Helper()
	h, tr, _ := newTestHandlerWithLogger(t, clock)
	return h, tr
}

func newTestHandlerWithLogger(t *testing.T, clock func() time.Time) (*Handler, *fakeTrigger, *fakeLogger) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "hook.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tr := &fakeTrigger{}
	lg := &fakeLogger{}
	h, err := NewHandler(Config{
		SigningKey: []byte(testKey),
		Queries:    st.Queries(),
		Trigger:    tr,
		Clock:      clock,
		Logger:     lg,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, tr, lg
}

// zitadelSignatureHeader reproduces Zitadel v4.16.0 ComputeSignatureHeader
// (pkg/actions/signing.go), the function that signs Actions v2 deliveries. Tests use it so the
// receiver is checked against the sender's real algorithm, not against itself.
func zitadelSignatureHeader(t time.Time, payload []byte, keys ...string) string {
	parts := []string{fmt.Sprintf("t=%d", t.Unix())}
	for _, k := range keys {
		mac := hmac.New(sha256.New, []byte(k))
		_, _ = fmt.Fprintf(mac, "%d.", t.Unix())
		mac.Write(payload)
		parts = append(parts, "v1="+hex.EncodeToString(mac.Sum(nil)))
	}
	return strings.Join(parts, ",")
}

func payload(aggregateID string, sequence uint64) []byte {
	return []byte(fmt.Sprintf(`{"aggregateID":%q,"sequence":%d,"event_type":"user.grant.added"}`, aggregateID, sequence))
}

func post(t *testing.T, h *Handler, header string, body []byte) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/hook", bytes.NewReader(body))
	if header != "" {
		req.Header.Set(Header, header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestHook_ValidSignature(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	h, tr := newTestHandler(t, func() time.Time { return now })
	body := payload("289123456789012345", 42)

	code := post(t, h, zitadelSignatureHeader(now, body, testKey), body)

	if code != http.StatusOK {
		t.Fatalf("status = %d, want %d", code, http.StatusOK)
	}
	if got := tr.signals(); got != 1 {
		t.Fatalf("signals = %d, want 1", got)
	}
}

func TestHook_InvalidSignature(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	body := payload("289123456789012345", 42)
	valid := zitadelSignatureHeader(now, body, testKey)

	cases := map[string]string{
		"missing header":  "",
		"malformed":       "garbage",
		"no timestamp":    strings.TrimPrefix(valid, fmt.Sprintf("t=%d,", now.Unix())),
		"wrong key":       zitadelSignatureHeader(now, body, "not-the-key"),
		"truncated value": fmt.Sprintf("t=%d,v1=abcd", now.Unix()),
		"invalid hex":     fmt.Sprintf("t=%d,v1=zzzz", now.Unix()),
		"signed but stale": func() string {
			old := now.Add(-10 * time.Minute)
			return zitadelSignatureHeader(old, body, testKey)
		}(),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			h, tr := newTestHandler(t, func() time.Time { return now })
			if code := post(t, h, header, body); code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", code, http.StatusUnauthorized)
			}
			if got := tr.signals(); got != 0 {
				t.Fatalf("signals = %d, want 0", got)
			}
		})
	}
}

// TestHook_RejectedRequestLogged checks that a rejected delivery leaves one bounded log entry
// with only a reason and a source, and never any request content (Y-01.2, security.md §6.5).
func TestHook_RejectedRequestLogged(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	body := payload("289123456789012345", 42)

	cases := []struct {
		name   string
		header string
		reason string
	}{
		{
			name:   "bad signature",
			header: "garbage",
			reason: reasonBadSignature,
		},
		{
			name:   "stale timestamp",
			header: zitadelSignatureHeader(now.Add(-10*time.Minute), body, testKey),
			reason: reasonStaleTimestamp,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, tr, lg := newTestHandlerWithLogger(t, func() time.Time { return now })
			if code := post(t, h, tc.header, body); code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", code, http.StatusUnauthorized)
			}
			if got := tr.signals(); got != 0 {
				t.Fatalf("signals = %d, want 0", got)
			}
			entries := lg.entries()
			if len(entries) != 1 {
				t.Fatalf("log entries = %d, want 1", len(entries))
			}
			got := entries[0]
			if len(got) != 4 {
				t.Fatalf("log args = %v, want exactly a reason and a source", got)
			}
			if got[0] != "reason" || got[1] != tc.reason {
				t.Fatalf("log reason = %v/%v, want reason/%s", got[0], got[1], tc.reason)
			}
			if got[2] != "source" || got[3] == "" {
				t.Fatalf("log source = %v/%v, want a non-empty source", got[2], got[3])
			}
			for _, v := range got {
				s, _ := v.(string)
				if s == string(body) || (tc.header != "" && s == tc.header) {
					t.Fatalf("log entry leaked request content: %q", s)
				}
			}
		})
	}
}

// TestHook_ValidRequestNotLogged checks that an accepted delivery writes no rejection entry.
func TestHook_ValidRequestNotLogged(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	h, tr, lg := newTestHandlerWithLogger(t, func() time.Time { return now })
	body := payload("289123456789012345", 42)

	if code := post(t, h, zitadelSignatureHeader(now, body, testKey), body); code != http.StatusOK {
		t.Fatalf("status = %d, want %d", code, http.StatusOK)
	}
	if got := tr.signals(); got != 1 {
		t.Fatalf("signals = %d, want 1", got)
	}
	if got := len(lg.entries()); got != 0 {
		t.Fatalf("log entries = %d, want 0", got)
	}
}

// TestHook_RejectedLoggingRateLimited checks that a flood of rejections produces one entry per
// window, so the log stays bounded (security.md §6.5).
func TestHook_RejectedLoggingRateLimited(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: now}
	h, _, lg := newTestHandlerWithLogger(t, clock.now)
	body := payload("289123456789012345", 42)

	for i := 0; i < 10; i++ {
		if code := post(t, h, "garbage", body); code != http.StatusUnauthorized {
			t.Fatalf("request %d status = %d, want %d", i, code, http.StatusUnauthorized)
		}
	}
	if got := len(lg.entries()); got != 1 {
		t.Fatalf("log entries after flood = %d, want 1", got)
	}

	clock.set(now.Add(rejectLogWindow))
	if code := post(t, h, "garbage", body); code != http.StatusUnauthorized {
		t.Fatalf("post-window status = %d, want %d", code, http.StatusUnauthorized)
	}
	if got := len(lg.entries()); got != 2 {
		t.Fatalf("log entries after window = %d, want 2", got)
	}
}

func TestHook_StaleTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	body := payload("289123456789012345", 42)

	cases := []struct {
		name string
		ts   time.Time
		want int
	}{
		{"inside window past", now.Add(-5 * time.Minute), http.StatusOK},
		{"inside window future", now.Add(5 * time.Minute), http.StatusOK},
		{"too old", now.Add(-6 * time.Minute), http.StatusUnauthorized},
		{"too far future", now.Add(6 * time.Minute), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, tr := newTestHandler(t, func() time.Time { return now })
			code := post(t, h, zitadelSignatureHeader(tc.ts, body, testKey), body)
			if code != tc.want {
				t.Fatalf("status = %d, want %d", code, tc.want)
			}
			if tc.want != http.StatusOK && tr.signals() != 0 {
				t.Fatalf("signals = %d, want 0", tr.signals())
			}
		})
	}
}

func TestHook_ReplayIgnored(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	h, tr := newTestHandler(t, clock.now)
	body := payload("289123456789012345", 42)

	first := clock.now()
	if code := post(t, h, zitadelSignatureHeader(first, body, testKey), body); code != http.StatusOK {
		t.Fatalf("first delivery status = %d, want %d", code, http.StatusOK)
	}
	if got := tr.signals(); got != 1 {
		t.Fatalf("signals after first = %d, want 1", got)
	}

	clock.set(first.Add(23 * time.Hour))
	if code := post(t, h, zitadelSignatureHeader(clock.now(), body, testKey), body); code != http.StatusOK {
		t.Fatalf("replay status = %d, want %d", code, http.StatusOK)
	}
	if got := tr.signals(); got != 1 {
		t.Fatalf("signals after replay = %d, want 1", got)
	}

	clock.set(first.Add(25 * time.Hour))
	if code := post(t, h, zitadelSignatureHeader(clock.now(), body, testKey), body); code != http.StatusOK {
		t.Fatalf("post-window status = %d, want %d", code, http.StatusOK)
	}
	if got := tr.signals(); got != 2 {
		t.Fatalf("signals after window = %d, want 2", got)
	}

	if code := post(t, h, zitadelSignatureHeader(clock.now(), payload("289123456789012345", 43), testKey), payload("289123456789012345", 43)); code != http.StatusOK {
		t.Fatalf("new sequence status = %d, want %d", code, http.StatusOK)
	}
	if got := tr.signals(); got != 3 {
		t.Fatalf("signals after new sequence = %d, want 3", got)
	}
}

func TestHook_BodyLimit(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	h, tr := newTestHandler(t, func() time.Time { return now })

	// A valid, exactly-at-limit body must be accepted.
	atLimit := bodyOfSize(t, maxBody)
	if code := post(t, h, zitadelSignatureHeader(now, atLimit, testKey), atLimit); code != http.StatusOK {
		t.Fatalf("at-limit status = %d, want %d", code, http.StatusOK)
	}
	if tr.signals() != 1 {
		t.Fatalf("signals after at-limit = %d, want 1", tr.signals())
	}

	// One byte over is refused before the signature is even checked: send it unsigned.
	over := bodyOfSize(t, maxBody+1)
	if code := post(t, h, "", over); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit status = %d, want %d", code, http.StatusRequestEntityTooLarge)
	}
	if tr.signals() != 1 {
		t.Fatalf("signals after over-limit = %d, want 1", tr.signals())
	}
}

// bodyOfSize builds a valid JSON payload of exactly n bytes by padding a "pad" field.
func bodyOfSize(t *testing.T, n int) []byte {
	t.Helper()
	const shape = `{"aggregateID":"a","sequence":1,"pad":""}`
	if n < len(shape) {
		t.Fatalf("size %d smaller than the JSON skeleton", n)
	}
	pad := n - len(shape)
	b := []byte(fmt.Sprintf(`{"aggregateID":"a","sequence":1,"pad":%q}`, strings.Repeat("x", pad)))
	if len(b) != n {
		t.Fatalf("built %d bytes, want %d", len(b), n)
	}
	return b
}

func TestHook_MultipleSignatures(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	body := payload("289123456789012345", 42)
	wrong := zitadelSignatureHeader(now, body, "old-key")
	right := zitadelSignatureHeader(now, body, testKey)
	wrongSig := strings.TrimPrefix(wrong, fmt.Sprintf("t=%d,", now.Unix()))
	rightSig := strings.TrimPrefix(right, fmt.Sprintf("t=%d,", now.Unix()))

	cases := []struct {
		name string
		vals string
		want int
	}{
		{"one of two matches", wrongSig + "," + rightSig, http.StatusOK},
		{"match second", rightSig + "," + wrongSig, http.StatusOK},
		{"neither matches", wrongSig + "," + wrongSig, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, tr := newTestHandler(t, func() time.Time { return now })
			header := fmt.Sprintf("t=%d,%s", now.Unix(), tc.vals)
			if code := post(t, h, header, body); code != tc.want {
				t.Fatalf("status = %d, want %d", code, tc.want)
			}
			want := 0
			if tc.want == http.StatusOK {
				want = 1
			}
			if got := tr.signals(); got != want {
				t.Fatalf("signals = %d, want %d", got, want)
			}
		})
	}
}

// TestHook_ZitadelFixture verifies a signature produced by Zitadel v4.16.0's own signing function
// (pkg/actions/signing.go). The payload, timestamp and HMAC below were generated from that
// algorithm with an independent tool; the receiver must accept the exact header.
func TestHook_ZitadelFixture(t *testing.T) {
	const (
		ts      = int64(1790769600) // 2026-09-30T12:00:00Z
		golden  = "4f2d927429064bde3d5424e9f8c788e813095e785a2256f4a3a88879a65d6dae"
		bodyStr = `{"aggregateID":"289123456789012345","aggregateType":"user_grant","resourceOwner":"289100000000000001","instanceID":"289100000000000002","sequence":42,"event_type":"user.grant.added","created_at":"2026-09-30T11:59:00Z","userID":"289100000000000003","event_payload":{}}`
	)
	at := time.Unix(ts, 0).UTC()
	body := []byte(bodyStr)

	header := zitadelSignatureHeader(at, body, testKey)
	if !strings.Contains(header, "v1="+golden) {
		t.Fatalf("reference implementation produced %q, want the pinned v1=%s", header, golden)
	}

	h, tr := newTestHandler(t, func() time.Time { return at })
	if code := post(t, h, header, body); code != http.StatusOK {
		t.Fatalf("status = %d, want %d", code, http.StatusOK)
	}
	if got := tr.signals(); got != 1 {
		t.Fatalf("signals = %d, want 1", got)
	}
}

func TestWithinTolerance(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"now", now, true},
		{"inside past", now.Add(-5 * time.Minute), true},
		{"inside future", now.Add(5 * time.Minute), true},
		{"outside past", now.Add(-5*time.Minute - time.Second), false},
		{"outside future", now.Add(5*time.Minute + time.Second), false},
		{"far future", time.Unix(1<<62, 0), false},
		{"far past", time.Unix(-(1 << 61), 0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := withinTolerance(now, tc.at); got != tc.want {
				t.Fatalf("withinTolerance(%v) = %v, want %v", tc.at, got, tc.want)
			}
		})
	}
}

func TestNewHandler_RequiresDeps(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "hook.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cases := map[string]Config{
		"no key":     {Queries: st.Queries(), Trigger: &fakeTrigger{}},
		"no queries": {SigningKey: []byte(testKey), Trigger: &fakeTrigger{}},
		"no trigger": {SigningKey: []byte(testKey), Queries: st.Queries()},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHandler(cfg); err == nil {
				t.Fatal("NewHandler returned nil error")
			}
		})
	}
}

// F5 F1: an authenticated delivery leaves one INFO line (fresh or replay) with the source only; a
// rejected one leaves none and the line never carries the body, headers or event id.
func TestHook_AcceptedDeliveryLogsOneInfoLine(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	h, _, lg := newTestHandlerWithLogger(t, func() time.Time { return now })
	body := payload("289123456789012345", 42)
	header := zitadelSignatureHeader(now, body, testKey)

	post(t, h, header, body)
	post(t, h, header, body) // replay: accepted too
	post(t, h, zitadelSignatureHeader(now, body, "wrong-key"), body)

	infos := lg.infoEntries()
	if len(infos) != 2 {
		t.Fatalf("INFO lines = %d (%v), want 2 (fresh + replay, not the rejected one)", len(infos), infos)
	}
	if infos[0][0] != "webhook accepted" || infos[0][2] != true || infos[1][2] != false {
		t.Errorf("lines = %v, want fresh=true then fresh=false", infos)
	}
	flat := fmt.Sprint(infos)
	for _, leak := range []string{"289123456789012345", "user.grant.added", testKey, header} {
		if strings.Contains(flat, leak) {
			t.Errorf("INFO line leaks %q: %s", leak, flat)
		}
	}
}
