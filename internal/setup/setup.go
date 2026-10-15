// Package setup is setup mode's access control (setup-flow.md §2, security.md §14): the one-time
// setup token, the single setup session it is exchanged for, and the attempt limits on the
// exchange. Only SHA-256 hashes are stored; the plain token exists in the runtime file for the
// install script and in the hands of the admin, the plain session value only in the cookie.
package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/store/db"
)

const (
	// TokenTTL is how long an unused setup token is valid.
	TokenTTL = 24 * time.Hour
	// SessionIdle and SessionMax bound a setup session (setup-flow.md §2.2).
	SessionIdle = time.Hour
	SessionMax  = 12 * time.Hour
	// DefaultTokenFile is where the plain token is written for the install script.
	DefaultTokenFile = "/run/tagcess/setup-token" // #nosec G101 -- a path, not a credential

	// PerSourceFailures and TotalFailures are the failed attempts allowed per minute.
	PerSourceFailures = 5
	TotalFailures     = 60
	attemptWindow     = time.Minute

	// TunnelSource is the source for a loopback request without the Caddy client-IP header (the
	// SSH-tunnel path). It has its own per-minute budget, outside the public global bucket.
	TunnelSource = "tunnel"

	tokenBytes   = 32
	timeFormat   = "2006-01-02T15:04:05.000Z"
	crockford    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	tokenGroupSz = 4
)

var (
	// ErrInvalidToken is returned for a wrong, used or expired token. The cause is not revealed.
	ErrInvalidToken = errors.New("setup: invalid token")
	// ErrRateLimited is returned when the attempt limits are exceeded. It never burns the token.
	ErrRateLimited = errors.New("setup: too many attempts")
	// ErrNoSession is returned for a missing, unknown or expired setup session.
	ErrNoSession = errors.New("setup: no valid session")
)

var tokenEnc = base32.NewEncoding(crockford).WithPadding(base32.NoPadding)

// Service issues setup tokens and sessions.
type Service struct {
	q         *db.Queries
	now       func() time.Time
	tokenFile string
	lim       *limiter
	rawDB     *sql.DB // tests only
}

// New returns a Service. tokenFile is where NewToken writes the plain token ("" disables the file).
func New(q *db.Queries, tokenFile string) *Service {
	return &Service{q: q, now: time.Now, tokenFile: tokenFile, lim: &limiter{}}
}

// SetClock replaces the clock; for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// NewToken creates a token, replacing any earlier one and ending every setup session, and writes
// the plain value to the token file. The plain token is returned for the caller to show on the
// host; it is stored nowhere else.
func (s *Service) NewToken(ctx context.Context) (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("setup: generate token: %w", err)
	}
	plain := formatToken(raw)
	sum := sha256.Sum256(raw)
	err := s.q.ReplaceSetupToken(ctx, db.ReplaceSetupTokenParams{
		TokenHash:      hex.EncodeToString(sum[:]),
		TokenExpiresAt: s.now().UTC().Add(TokenTTL).Format(timeFormat),
	})
	if err != nil {
		return "", fmt.Errorf("setup: store token: %w", err)
	}
	if s.tokenFile != "" {
		if err := writeFile0600(s.tokenFile, plain+"\n"); err != nil {
			return "", err
		}
	}
	return plain, nil
}

// Exchange trades the token for a new setup session and returns the session value for the cookie.
// source identifies the caller for the attempt limits. Failed attempts count; the token itself is
// consumed only by a success.
func (s *Service) Exchange(ctx context.Context, token, source string) (string, error) {
	now := s.now()
	// The attempt is counted up front, in the same locked step as the check, so concurrent
	// attempts cannot all pass before any failure is recorded. Only a success refunds it.
	res, allowed := s.lim.reserve(now, source)
	if !allowed {
		return "", ErrRateLimited
	}
	success := false
	defer func() {
		if success {
			s.lim.refund(res)
		}
	}()
	raw, ok := parseToken(token)
	if !ok {
		return "", ErrInvalidToken
	}
	st, err := s.q.GetSetupState(ctx)
	if err != nil {
		s.lim.refund(res)
		return "", fmt.Errorf("setup: read state: %w", err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	// Constant-time comparison; an empty stored hash never matches.
	if st.TokenHash == "" || subtle.ConstantTimeCompare([]byte(hash), []byte(st.TokenHash)) != 1 {
		return "", ErrInvalidToken
	}
	sess := make([]byte, tokenBytes)
	if _, err := rand.Read(sess); err != nil {
		return "", fmt.Errorf("setup: generate session: %w", err)
	}
	stamp := now.UTC().Format(timeFormat)
	n, err := s.q.ConsumeSetupToken(ctx, db.ConsumeSetupTokenParams{
		SessionHash:       hashSession(sess),
		SessionCreatedAt:  stamp,
		SessionLastSeenAt: stamp,
		TokenHash:         st.TokenHash,
		TokenExpiresAt:    stamp,
	})
	if err != nil {
		return "", fmt.Errorf("setup: consume token: %w", err)
	}
	if n != 1 { // expired, sealed or lost a race with another exchange
		return "", ErrInvalidToken
	}
	success = true
	if s.tokenFile != "" {
		_ = os.Remove(s.tokenFile) // the token is spent; a stale file would only mislead
	}
	return hex.EncodeToString(sess), nil
}

// Session is a validated setup session.
type Session struct {
	// Actor is the audit actor: "setup:" and the first 8 hex digits of the session hash.
	Actor string
	// Hash identifies the session for End.
	Hash string
}

// Validate checks a session cookie value against the idle and absolute limits and refreshes the
// idle timer.
func (s *Service) Validate(ctx context.Context, cookie string) (Session, error) {
	raw, err := hex.DecodeString(cookie)
	if err != nil || len(raw) != tokenBytes {
		return Session{}, ErrNoSession
	}
	hash := hashSession(raw)
	st, err := s.q.GetSetupState(ctx)
	if err != nil {
		return Session{}, fmt.Errorf("setup: read state: %w", err)
	}
	if st.SessionHash == "" || subtle.ConstantTimeCompare([]byte(hash), []byte(st.SessionHash)) != 1 {
		return Session{}, ErrNoSession
	}
	now := s.now().UTC()
	created, err1 := time.Parse(timeFormat, st.SessionCreatedAt)
	seen, err2 := time.Parse(timeFormat, st.SessionLastSeenAt)
	if err1 != nil || err2 != nil || now.Sub(created) >= SessionMax || now.Sub(seen) >= SessionIdle {
		return Session{}, ErrNoSession
	}
	if _, err := s.q.TouchSetupSession(ctx, db.TouchSetupSessionParams{
		SessionLastSeenAt: now.Format(timeFormat), SessionHash: hash,
	}); err != nil {
		return Session{}, fmt.Errorf("setup: touch session: %w", err)
	}
	return Session{Actor: "setup:" + hash[:8], Hash: hash}, nil
}

// End deletes the session.
func (s *Service) End(ctx context.Context, sess Session) error {
	if err := s.q.EndSetupSession(ctx, sess.Hash); err != nil {
		return fmt.Errorf("setup: end session: %w", err)
	}
	return nil
}

func hashSession(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// formatToken renders raw as Crockford base32 in groups of four, joined with dashes.
func formatToken(raw []byte) string {
	enc := tokenEnc.EncodeToString(raw)
	var b strings.Builder
	for i := 0; i < len(enc); i += tokenGroupSz {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(enc[i:min(i+tokenGroupSz, len(enc))])
	}
	return b.String()
}

// parseToken reverses formatToken, tolerating case, dashes, spaces and Crockford look-alikes.
func parseToken(s string) ([]byte, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		b.WriteRune(r)
	}
	raw, err := tokenEnc.DecodeString(b.String())
	if err != nil || len(raw) != tokenBytes {
		return nil, false
	}
	return raw, true
}

// writeFile0600 replaces path atomically with content readable only by the owner.
func writeFile0600(path, content string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".setup-token-*")
	if err != nil {
		return fmt.Errorf("setup: write token file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setup: write token file: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setup: write token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("setup: write token file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("setup: write token file: %w", err)
	}
	return nil
}

// limiter counts failed exchange attempts in a sliding one-minute window.
type limiter struct {
	mu     sync.Mutex
	seq    uint64
	bySrc  map[string][]attempt
	global []attempt
}

// attempt is one reservation; id identifies it so a refund removes exactly that entry.
type attempt struct {
	id uint64
	at time.Time
}

// reservation is the handle reserve returns; pass it to refund.
type reservation struct {
	src string
	id  uint64
}

func prune(ts []attempt, now time.Time) []attempt {
	i := 0
	for i < len(ts) && now.Sub(ts[i].at) >= attemptWindow {
		i++
	}
	return ts[i:]
}

func remove(ts []attempt, id uint64) []attempt {
	for i := range ts {
		if ts[i].id == id {
			return append(ts[:i:i], ts[i+1:]...)
		}
	}
	return ts
}

// reserve checks the limits and records the attempt in one locked step.
func (l *limiter) reserve(now time.Time, src string) (reservation, bool) {
	src = normalizeSource(src)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global = prune(l.global, now)
	tunnel := src == TunnelSource
	if !tunnel && len(l.global) >= TotalFailures {
		return reservation{}, false
	}
	if l.bySrc == nil {
		l.bySrc = map[string][]attempt{}
	}
	// Drop sources whose attempts have all left the window, so the map cannot grow without bound.
	for k, ts := range l.bySrc {
		if ts = prune(ts, now); len(ts) == 0 {
			delete(l.bySrc, k)
		} else {
			l.bySrc[k] = ts
		}
	}
	l.bySrc[src] = prune(l.bySrc[src], now)
	if len(l.bySrc[src]) >= PerSourceFailures {
		return reservation{}, false
	}
	l.seq++
	a := attempt{id: l.seq, at: now}
	l.bySrc[src] = append(l.bySrc[src], a)
	if !tunnel {
		l.global = append(l.global, a)
	}
	return reservation{src: src, id: a.id}, true
}

// refund releases exactly the reserved attempt r (a success, or an internal error that is not
// the caller's fault). An attempt already pruned from the window is a no-op.
func (l *limiter) refund(r reservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ts := remove(l.bySrc[r.src], r.id); len(ts) > 0 {
		l.bySrc[r.src] = ts
	} else {
		delete(l.bySrc, r.src)
	}
	l.global = remove(l.global, r.id)
}

// normalizeSource keys an IPv6 source by its /64, so one host cannot get a fresh budget from each
// address of its prefix. IPv4 and non-IP labels (TunnelSource) are returned unchanged.
func normalizeSource(src string) string {
	ip := net.ParseIP(src)
	if ip == nil || ip.To4() != nil {
		return src
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
