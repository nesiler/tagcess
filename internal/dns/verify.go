// Resolver verification (ADR 0013 m.5, S-03.4): after the file changed, the
// changed names are asked at the MagicDNS resolver until the budget runs out.
// Every name that never answered with the expected value becomes a Mismatch —
// a warning the caller forwards to audit/alerts; the file is kept either way.
package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Defaults for production (ADR 0013 m.5): the tagcess host asks vpn-host's
// tailnet view at the MagicDNS resolver address, with a 10 second budget.
const (
	DefaultResolver = "100.100.100.100:53"
	DefaultBudget   = 10 * time.Second
)

// pollGap is the pause between verification rounds while names are still
// unanswered inside the budget.
const pollGap = 250 * time.Millisecond

// Verifier checks changed records against a resolver.
type Verifier struct {
	// Resolver is the "host:port" UDP address to query. Empty means skip:
	// no resolver configured, no verification, no warnings.
	Resolver string
	// Budget bounds the whole verification round. Zero or negative means
	// DefaultBudget.
	Budget time.Duration
}

// Mismatch is one changed record the resolver did not confirm within the
// budget. Want is the value just written; Have is the last answer seen, empty
// when the name never answered with a usable value.
type Mismatch struct {
	Name string
	Type string
	Want string
	Have string
}

func (m Mismatch) Error() string {
	if m.Have == "" {
		return fmt.Sprintf("dns verify: %s %s did not answer %q within the budget", m.Name, m.Type, m.Want)
	}
	return fmt.Sprintf("dns verify: %s %s answers %q, want %q", m.Name, m.Type, m.Have, m.Want)
}

// Verify asks every changed record's name at the resolver, polling until the
// budget expires, and returns the records that were never confirmed. An empty
// changed list or no configured resolver returns nothing. Reporting happens
// once, at the end of the budget: a late propagation can still confirm a name
// that first answered wrong (security.md §8: a verification mismatch is a
// warning, the applied state is kept).
func (v Verifier) Verify(changed []Record) []Mismatch {
	if len(changed) == 0 || v.Resolver == "" {
		return nil
	}
	budget := v.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Every lookup is pinned to the configured resolver instead of
			// the system's.
			var d net.Dialer
			return d.DialContext(ctx, network, v.Resolver)
		},
	}

	deadline := time.Now().Add(budget)
	pending := make([]Record, len(changed))
	copy(pending, changed)
	// lastSeen remembers a wrong answer, so the final Mismatch can carry what
	// the resolver actually had.
	lastSeen := make(map[string]string, len(pending))
	for len(pending) > 0 {
		pending = verifyRound(resolver, deadline, pending, lastSeen)
		if len(pending) == 0 || !time.Now().Add(pollGap).Before(deadline) {
			break
		}
		time.Sleep(pollGap)
	}
	mismatches := make([]Mismatch, 0, len(pending))
	for _, r := range pending {
		mismatches = append(mismatches, Mismatch{
			Name: r.Name, Type: r.Type, Want: r.Value, Have: lastSeen[r.Name+"/"+r.Type],
		})
	}
	return mismatches
}

// verifyRound runs one lookup per pending record and returns the unconfirmed
// ones for the next round. The name is asked fully qualified (trailing dot),
// so the lookup is absolute: the resolver's search list is never consulted
// and a bare host from /etc/hosts cannot shadow the record.
func verifyRound(resolver *net.Resolver, deadline time.Time, pending []Record, lastSeen map[string]string) []Record {
	remaining := pending[:0]
	for _, r := range pending {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		ips, err := resolver.LookupIP(ctx, family(r.Type), r.Name+".")
		cancel()
		switch {
		case err == nil && hasIP(ips, r.Value):
			// confirmed; drop from pending
		case err == nil && len(ips) > 0:
			lastSeen[r.Name+"/"+r.Type] = ips[0].String()
			remaining = append(remaining, r)
		default:
			remaining = append(remaining, r)
		}
	}
	return remaining
}

func family(t string) string {
	if t == TypeAAAA {
		return "ip6"
	}
	return "ip4"
}

func hasIP(ips []net.IP, want string) bool {
	target := net.ParseIP(want)
	for _, ip := range ips {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}
