package health

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/nesiler/tagcess/internal/netpolicy"
)

// Verification is the verdict on the presented certificate, separate from reachability.
type Verification string

const (
	TLSVerified Verification = "verified" // chain, name and validity period all passed
	TLSFailed   Verification = "failed"   // a leaf was presented but did not verify: "TLS doğrulanmadı"
	TLSUnknown  Verification = "unknown"  // no verdict: the handshake did not complete
)

// Reasons a presented certificate failed verification (Observation.Reason). Expired also covers a
// certificate that is not yet valid (Go reports both the same way). Anything else the verifier
// objects to is TLSReasonInvalid.
const (
	TLSReasonExpired          = "expired"
	TLSReasonHostname         = "hostname"
	TLSReasonUnknownAuthority = "unknown_authority"
	TLSReasonInvalid          = "invalid"
)

// TLSRequest is one TLS check. Host is the approved dial target (the Caddy or internal listener);
// ServerName is the site host sent as SNI. Both must be approved targets and Host:Port must pass
// the probe endpoint policy, exactly as for the HTTP probe. There is no field for a header, body
// or credential.
type TLSRequest struct {
	Host       string
	Port       int
	ServerName string
}

// TLSLeaf is the leaf certificate a listener presented. Only public data is kept.
type TLSLeaf struct {
	Fingerprint string // hex SHA-256 of the DER encoding
	NotAfter    time.Time
}

// LastLeaf is an older observation of a host's leaf, kept only as history. It is never a fresh
// reading: ObservedAt says when it was true.
type LastLeaf struct {
	Leaf       *TLSLeaf
	ObservedAt time.Time
}

// IsZero reports whether there is no earlier leaf.
func (l LastLeaf) IsZero() bool { return l.Leaf == nil }

// TLSObservation is the record of one check of one SNI host.
type TLSObservation struct {
	Host         string // the SNI host
	ObservedAt   time.Time
	Reachable    bool         // a TLS handshake completed, whether or not the certificate verified
	Verification Verification // verified, failed or unknown
	Reason       string       // why verification failed; empty unless Verification is TLSFailed
	Leaf         *TLSLeaf     // the leaf read in THIS check; nil when none could be read
	Diagnostic   bool         // Leaf came from an unverified, credentialless handshake
	Err          string       // short failure text when no handshake completed
	Last         LastLeaf     // older leaf, set by After when this check read none
}

// Healthy is true only for a completed handshake whose certificate verified.
func (o TLSObservation) Healthy() bool {
	return o.Reachable && o.Verification == TLSVerified && o.Leaf != nil
}

// After returns o with the previous observation's leaf carried as history when o read none. A
// check that read a leaf stands alone. A failed check never gets a NotAfter of its own: the old
// one stays in Last, tied to the time it was observed.
func (o TLSObservation) After(prev TLSObservation) TLSObservation {
	if o.Leaf != nil {
		o.Last = LastLeaf{}
		return o
	}
	switch {
	case prev.Leaf != nil:
		o.Last = LastLeaf{Leaf: prev.Leaf, ObservedAt: prev.ObservedAt}
	case !prev.Last.IsZero():
		o.Last = prev.Last
	}
	return o
}

// ProbeTLS reads the leaf certificate that the listener presents for req.ServerName. It returns an
// error only when the request was refused before any connection (ErrRejected, netpolicy.ErrDenied);
// every measured outcome, including an unreachable listener, is in the observation.
//
// The handshake is verified against the system roots (or the test pool). When verification fails
// the leaf may be read again with a bare, unverified handshake so the failure can be explained and
// the expiry shown; that observation is marked Diagnostic and is never healthy. Both attempts share
// one t.timeout budget. Neither handshake sends an HTTP request, a client certificate, a header
// or a body.
func (t *Transport) ProbeTLS(ctx context.Context, req TLSRequest) (TLSObservation, error) {
	if req.ServerName == "" {
		return TLSObservation{}, fmt.Errorf("%w: server name is required", ErrRejected)
	}
	host, name, err := t.check(ctx, Request{Host: req.Host, Port: req.Port, ServerName: req.ServerName})
	if err != nil {
		return TLSObservation{}, err
	}
	// One budget for the whole probe: the verified handshake, the diagnostic read and any
	// cancellation share it (R3 B-06: 5 s per probe).
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	obs := TLSObservation{Host: name, ObservedAt: t.clock(), Verification: TLSUnknown}

	state, err := t.handshake(ctx, host, req.Port, name, false)
	if err == nil {
		obs.Reachable, obs.Verification = true, TLSVerified
		obs.Leaf = leafOf(state.PeerCertificates[0])
		return obs, nil
	}
	if errors.Is(err, netpolicy.ErrDenied) {
		return TLSObservation{}, err
	}
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) {
		obs.Err = shortErr(err)
		return obs, nil
	}

	// The server answered, so it is reachable, but its certificate did not verify.
	obs.Reachable, obs.Verification, obs.Reason = true, TLSFailed, verifyReason(verr.Err)
	if state, err = t.handshake(ctx, host, req.Port, name, true); err == nil && len(state.PeerCertificates) > 0 {
		obs.Leaf, obs.Diagnostic = leafOf(state.PeerCertificates[0]), true
	}
	return obs, nil
}

// ProbeTLSHosts checks every name through the same listener, one handshake each, in order. A host
// that cannot be checked yields an unknown observation; it never stops the others.
func (t *Transport) ProbeTLSHosts(ctx context.Context, host string, port int, names []string) []TLSObservation {
	out := make([]TLSObservation, 0, len(names))
	for _, name := range names {
		obs, err := t.ProbeTLS(ctx, TLSRequest{Host: host, Port: port, ServerName: name})
		if err != nil {
			obs = TLSObservation{Host: name, ObservedAt: t.clock(), Verification: TLSUnknown, Err: shortErr(err)}
		}
		out = append(out, obs)
	}
	return out
}

// handshake dials through the policy guard and completes a TLS handshake, nothing more. With
// unverified set the certificate is not checked: this is the diagnostic read of an invalid leaf.
func (t *Transport) handshake(ctx context.Context, host string, port int, serverName string, unverified bool) (tls.ConnectionState, error) {
	conn, err := t.dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()

	cfg := t.tlsConfig(serverName)
	cfg.InsecureSkipVerify = unverified //nolint:gosec // diagnostic read of an invalid leaf; marked unverified, never healthy
	c := tls.Client(conn, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tls.ConnectionState{}, errors.New("no certificate presented")
	}
	return state, nil
}

func (t *Transport) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func leafOf(c *x509.Certificate) *TLSLeaf {
	sum := sha256.Sum256(c.Raw)
	return &TLSLeaf{Fingerprint: hex.EncodeToString(sum[:]), NotAfter: c.NotAfter.UTC()}
}

func verifyReason(err error) string {
	var (
		hostErr x509.HostnameError
		authErr x509.UnknownAuthorityError
		certErr x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &hostErr):
		return TLSReasonHostname
	case errors.As(err, &authErr):
		return TLSReasonUnknownAuthority
	case errors.As(err, &certErr) && certErr.Reason == x509.Expired:
		return TLSReasonExpired
	}
	return TLSReasonInvalid
}

// shortErr is a bounded failure label without addresses or certificate contents.
func shortErr(err error) string {
	switch {
	case errors.Is(err, ErrRejected):
		return "rejected"
	case errors.Is(err, netpolicy.ErrDenied):
		return "denied by endpoint policy"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return "handshake failed"
}
