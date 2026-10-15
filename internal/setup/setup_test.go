package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newService(t *testing.T) (*Service, *fakeClock, string) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	file := filepath.Join(t.TempDir(), "setup-token")
	svc := New(st.Queries(), file)
	clk := &fakeClock{t: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)}
	svc.SetClock(clk.now)
	// keep the raw DB for hash inspection
	svc.rawDB = st.DB()
	return svc, clk, file
}

func TestToken_StoresOnlyHash(t *testing.T) {
	svc, _, file := newService(t)
	tok, err := svc.NewToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	if err := svc.rawDB.QueryRowContext(context.Background(), `SELECT token_hash FROM setup_state`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == "" || strings.Contains(hash, tok) || strings.Contains(tok, hash) {
		t.Fatalf("stored value %q is not a hash of %q", hash, tok)
	}
	// the plain token is nowhere in the database
	var n int
	if err := svc.rawDB.QueryRowContext(context.Background(), `SELECT count(*) FROM setup_state WHERE token_hash LIKE ? OR session_hash LIKE ?`,
		"%"+strings.ReplaceAll(tok, "-", "")+"%", "%"+tok+"%").Scan(&n); err != nil || n != 0 {
		t.Fatalf("plain token found in db: n=%d err=%v", n, err)
	}
	fi, err := os.Stat(file)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	body, _ := os.ReadFile(file)
	if strings.TrimSpace(string(body)) != tok {
		t.Fatal("token file does not hold the token")
	}
}

func TestToken_OnceAnd24h(t *testing.T) {
	tests := []struct {
		name    string
		advance time.Duration
		retry   bool
		wantErr error
	}{
		{"fresh token accepted", 0, false, nil},
		{"just before 24h accepted", TokenTTL - time.Second, false, nil},
		{"at 24h rejected", TokenTTL, false, ErrInvalidToken},
		{"after 24h rejected", TokenTTL + time.Hour, false, ErrInvalidToken},
		{"second use rejected", time.Minute, true, ErrInvalidToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, clk, file := newService(t)
			ctx := context.Background()
			tok, err := svc.NewToken(ctx)
			if err != nil {
				t.Fatal(err)
			}
			clk.t = clk.t.Add(tt.advance)
			_, err = svc.Exchange(ctx, tok, "a")
			if tt.retry {
				if err != nil {
					t.Fatalf("first use: %v", err)
				}
				if _, err = svc.Exchange(ctx, tok, "a"); !errors.Is(err, ErrInvalidToken) {
					t.Fatalf("second use err = %v", err)
				}
				if _, statErr := os.Stat(file); !os.IsNotExist(statErr) {
					t.Fatal("token file must be removed after the exchange")
				}
				return
			}
			if !errors.Is(err, tt.wantErr) && (tt.wantErr != nil || err != nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestToken_Formats(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	tok, _ := svc.NewToken(ctx)
	if _, err := svc.Exchange(ctx, "  "+strings.ToLower(tok)+" ", "a"); err != nil {
		t.Fatalf("lowercase/space tolerant: %v", err)
	}
	for _, bad := range []string{"", "x", strings.Repeat("0", 52)} {
		if _, err := svc.Exchange(ctx, bad, "b"); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestRateLimit_DoesNotBurnToken(t *testing.T) {
	svc, clk, _ := newService(t)
	ctx := context.Background()
	tok, _ := svc.NewToken(ctx)
	bad := strings.Repeat("0", 52)
	for i := 0; i < PerSourceFailures; i++ {
		if _, err := svc.Exchange(ctx, bad, "1.1.1.1"); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// the source is limited, even with the right token
	if _, err := svc.Exchange(ctx, tok, "1.1.1.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("limited source err = %v", err)
	}
	// another source still works: the token was not burned
	clk.t = clk.t.Add(time.Second)
	if _, err := svc.Exchange(ctx, tok, "2.2.2.2"); err != nil {
		t.Fatalf("token burned: %v", err)
	}
}

func TestRateLimit_Window(t *testing.T) {
	svc, clk, _ := newService(t)
	ctx := context.Background()
	tok, _ := svc.NewToken(ctx)
	bad := strings.Repeat("0", 52)
	for i := 0; i < PerSourceFailures; i++ {
		_, _ = svc.Exchange(ctx, bad, "s")
	}
	clk.t = clk.t.Add(attemptWindow)
	if _, err := svc.Exchange(ctx, tok, "s"); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestRateLimit_Total(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	tok, _ := svc.NewToken(ctx)
	bad := strings.Repeat("0", 52)
	for i := 0; i < TotalFailures; i++ {
		// 4 failures per source stays under the per-source limit
		_, _ = svc.Exchange(ctx, bad, "src"+string(rune('a'+i/4))+string(rune('a'+i%4)))
	}
	if _, err := svc.Exchange(ctx, tok, "fresh"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("total limit err = %v", err)
	}
}

func TestSession_Limits(t *testing.T) {
	svc, clk, _ := newService(t)
	ctx := context.Background()
	tok, _ := svc.NewToken(ctx)
	cookie, err := svc.Exchange(ctx, tok, "a")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := svc.Validate(ctx, cookie)
	if err != nil || !strings.HasPrefix(sess.Actor, "setup:") || len(sess.Actor) != len("setup:")+8 {
		t.Fatalf("validate: %+v %v", sess, err)
	}
	// activity every 50 minutes keeps it alive until the 12 h absolute limit
	for i := 0; i < 15; i++ {
		clk.t = clk.t.Add(50 * time.Minute)
		_, err = svc.Validate(ctx, cookie)
		if clk.t.Sub(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)) >= SessionMax {
			if !errors.Is(err, ErrNoSession) {
				t.Fatalf("absolute limit not enforced at %v: %v", clk.t, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	t.Fatal("never reached the absolute limit")
}

func TestSession_Idle(t *testing.T) {
	svc, clk, _ := newService(t)
	ctx := context.Background()
	tok, _ := svc.NewToken(ctx)
	cookie, _ := svc.Exchange(ctx, tok, "a")
	clk.t = clk.t.Add(SessionIdle)
	if _, err := svc.Validate(ctx, cookie); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle err = %v", err)
	}
	if _, err := svc.Validate(ctx, "zz"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("garbage err = %v", err)
	}
}

func TestNewToken_EndsEverySession(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	old, _ := svc.NewToken(ctx)
	cookie, _ := svc.Exchange(ctx, old, "a")
	if _, err := svc.Validate(ctx, cookie); err != nil {
		t.Fatal(err)
	}
	fresh, err := svc.NewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, cookie); !errors.Is(err, ErrNoSession) {
		t.Fatalf("old session survived: %v", err)
	}
	if _, err := svc.Exchange(ctx, old, "a"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("old token still works: %v", err)
	}
	if _, err := svc.Exchange(ctx, fresh, "a"); err != nil {
		t.Fatalf("new token: %v", err)
	}
}

func TestExchange_SealedRejects(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	tok, _ := svc.NewToken(ctx)
	if _, err := svc.rawDB.ExecContext(context.Background(), `UPDATE setup_state SET sealed_at = '2026-10-15T09:00:00.000Z'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exchange(ctx, tok, "a"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("sealed exchange err = %v", err)
	}
}

func TestRateLimit_ConcurrentBurst(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.NewToken(ctx); err != nil {
		t.Fatal(err)
	}
	const n = 50
	var wg sync.WaitGroup
	var reached, limited atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Exchange(ctx, "0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000", "198.51.100.1")
			if errors.Is(err, ErrRateLimited) {
				limited.Add(1)
			} else {
				reached.Add(1)
			}
		}()
	}
	wg.Wait()
	if reached.Load() > PerSourceFailures {
		t.Fatalf("%d attempts reached the token check, want at most %d", reached.Load(), PerSourceFailures)
	}
	// one source cannot fill the shared bucket: another source still gets through to the check
	if _, err := svc.Exchange(ctx, "x", "203.0.113.9"); errors.Is(err, ErrRateLimited) {
		t.Fatal("global bucket filled by one source")
	}
}
