package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/nesiler/tagcess/internal/netpolicy"
)

// Protocol is how a target is measured.
type Protocol string

const (
	ProtocolHTTP Protocol = "http" // credentialless GET, judged by the expected statuses
	ProtocolTCP  Protocol = "tcp"  // connect and close; says nothing about what listens
)

// Kind is the bounded verdict on a target measurement. Only KindHealthy and KindTCPConnected mean
// the target endpoint answered as expected; a Caddy gate answer never becomes one of them.
type Kind string

const (
	KindHealthy          Kind = "healthy"           // HTTP status is one of the selected expected statuses
	KindUnexpectedStatus Kind = "unexpected_status" // HTTP answered, status not expected (incl. redirect, 401/403/404)
	KindTCPConnected     Kind = "tcp_connected"     // the endpoint accepted a TCP connection
	KindTimeout          Kind = "timeout"           // no answer within the time limit
	KindUnreachable      Kind = "unreachable"       // connect or TLS handshake failed
	KindUnknown          Kind = "unknown"           // not measurable (fixed template without adapter)
)

// maxStatuses bounds the expectation list so it stays a short, deliberate choice.
const maxStatuses = 8

// TargetRequest is one target measurement. Request carries the host, port, path, Host/SNI and TLS
// choice (and the Header/Credential fields that are refused). Statuses are the HTTP statuses the
// developer selected as healthy; empty means 200. They are ignored by TCP, which takes none.
type TargetRequest struct {
	Request
	Protocol Protocol // default ProtocolHTTP
	Statuses []int    // each in 200..599, at most maxStatuses
}

// TargetResult is the whole evidence of a target measurement: protocol, endpoint (host:port),
// verdict and, for HTTP, the status. No body, header, error text or credential.
type TargetResult struct {
	Protocol   Protocol
	Endpoint   string
	Kind       Kind
	StatusCode int
}

// GateKind is the Caddy access gate's answer, kept apart from target health on purpose: a login
// redirect or a 401/403 shows the gate works, not that the backend does.
type GateKind string

const (
	GateLoginRedirect GateKind = "login_redirect" // 3xx: the gate sent the request to login
	GateUnauthorized  GateKind = "unauthorized"   // 401
	GateForbidden     GateKind = "forbidden"      // 403
	GateAnswered      GateKind = "answered"       // any other final status; says nothing about the backend
	GateTimeout       GateKind = "timeout"
	GateUnreachable   GateKind = "unreachable"
	GateUnknown       GateKind = "unknown"
)

// GateResult is the evidence of a gate measurement.
type GateResult struct {
	Endpoint   string
	Kind       GateKind
	StatusCode int
}

// ProbeTarget measures one target. A request that is invalid, unapproved or refused by the
// endpoint policy returns an error and a zero result without any request on the wire; so does a
// cancelled caller context. A timeout or failed connection is a result, not an error.
func (t *Transport) ProbeTarget(ctx context.Context, req TargetRequest) (TargetResult, error) {
	proto, statuses, err := req.validate()
	if err != nil {
		return TargetResult{}, err
	}
	if req.Template != "" { // no trusted adapter: unknown, whatever address came with it
		return TargetResult{Protocol: proto, Kind: KindUnknown}, nil
	}
	host, serverName, err := t.check(ctx, req.Request)
	if err != nil {
		return TargetResult{}, err
	}
	res := TargetResult{Protocol: proto, Endpoint: net.JoinHostPort(host, strconv.Itoa(req.Port))}

	if proto == ProtocolTCP {
		kind, err := t.connect(ctx, res.Endpoint)
		if err != nil {
			return TargetResult{}, err
		}
		res.Kind = kind
		return res, nil
	}

	got, err := t.get(ctx, req.Request, host, serverName)
	if err != nil {
		if res.Kind, err = failureKind(ctx, err); err != nil {
			return TargetResult{}, err
		}
		return res, nil
	}
	res.StatusCode = got.StatusCode
	if req.SkipVerify {
		// The k8s ingress behind Caddy's (k8s) snippet: any app answer (2xx, a login redirect, 401/403)
		// proves the backend is up; only 5xx and the ingress's own 404 mean it is not (K-02.7).
		res.Kind = KindHealthy
		if got.StatusCode >= 500 || got.StatusCode == http.StatusNotFound {
			res.Kind = KindUnexpectedStatus
		}
		return res, nil
	}
	res.Kind = KindUnexpectedStatus
	for _, s := range statuses {
		if s == got.StatusCode {
			res.Kind = KindHealthy
		}
	}
	return res, nil
}

// ProbeGate measures the Caddy gate with an unauthenticated GET and reports only how the gate
// answered. It takes the same request checks as ProbeTarget.
func (t *Transport) ProbeGate(ctx context.Context, req Request) (GateResult, error) {
	if req.Template != "" {
		return GateResult{Kind: GateUnknown}, nil
	}
	host, serverName, err := t.check(ctx, req)
	if err != nil {
		return GateResult{}, err
	}
	res := GateResult{Endpoint: net.JoinHostPort(host, strconv.Itoa(req.Port))}
	got, err := t.get(ctx, req, host, serverName)
	if err != nil {
		kind, err := failureKind(ctx, err)
		if err != nil {
			return GateResult{}, err
		}
		res.Kind = GateUnreachable
		if kind == KindTimeout {
			res.Kind = GateTimeout
		}
		return res, nil
	}
	res.StatusCode = got.StatusCode
	switch {
	case got.StatusCode >= 300 && got.StatusCode < 400:
		res.Kind = GateLoginRedirect
	case got.StatusCode == http.StatusUnauthorized:
		res.Kind = GateUnauthorized
	case got.StatusCode == http.StatusForbidden:
		res.Kind = GateForbidden
	default:
		res.Kind = GateAnswered
	}
	return res, nil
}

// validate refuses a protocol or expectation the probe will not honour, before anything else.
// It returns the protocol and the effective expected statuses (HTTP only).
func (r TargetRequest) validate() (Protocol, []int, error) {
	switch r.Protocol {
	case "", ProtocolHTTP:
		if len(r.Statuses) > maxStatuses {
			return "", nil, fmt.Errorf("%w: too many expected statuses", ErrRejected)
		}
		for _, s := range r.Statuses {
			if s < 200 || s > 599 {
				return "", nil, fmt.Errorf("%w: expected status %d is out of range", ErrRejected, s)
			}
		}
		if len(r.Statuses) == 0 {
			return ProtocolHTTP, []int{http.StatusOK}, nil
		}
		return ProtocolHTTP, r.Statuses, nil
	case ProtocolTCP:
		if len(r.Statuses) > 0 || r.Path != "" || r.TLS || r.ServerName != "" || len(r.Header) > 0 || r.Credential != "" {
			return "", nil, fmt.Errorf("%w: a tcp probe takes only host and port", ErrRejected)
		}
		return ProtocolTCP, nil, nil
	}
	return "", nil, fmt.Errorf("%w: unknown protocol", ErrRejected)
}

// connect opens one guarded TCP connection to an approved endpoint and closes it at once, sending
// nothing. A failure to connect is a kind; a policy refusal or caller cancellation is the error.
func (t *Transport) connect(ctx context.Context, endpoint string) (Kind, error) {
	dctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	conn, err := t.dial(dctx, "tcp", endpoint)
	if err != nil {
		return failureKind(ctx, err)
	}
	_ = conn.Close()
	return KindTCPConnected, nil
}

// failureKind turns a failed measurement into a bounded kind. Refusals (request or endpoint
// policy) and caller cancellation are not measurements and come back as the error.
func failureKind(ctx context.Context, err error) (Kind, error) {
	if errors.Is(err, ErrRejected) || errors.Is(err, netpolicy.ErrDenied) || errors.Is(ctx.Err(), context.Canceled) {
		return "", err
	}
	var nerr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()) {
		return KindTimeout, nil
	}
	return KindUnreachable, nil
}
