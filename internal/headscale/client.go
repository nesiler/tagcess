// Package headscale is tagcess's narrow view of Headscale's gRPC API (Y-03, Y-04). Headscale's
// unix socket serves unauthenticated, full-admin gRPC (stack-notes), so this package wraps only
// the six RPCs tagcess needs and exposes nothing else: read the policy, users and nodes, validate
// and set the policy, and expire a node. There is no delete, no user creation, no key and no route
// operation (security.md §10); a test pins the method set.
//
// The proto types come from github.com/juanfont/headscale v0.29.4's gen/go package, pinned in
// go.mod to the production version.
package headscale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// DefaultTimeout bounds every call when Config.Timeout is zero.
const DefaultTimeout = 10 * time.Second

// Config says where Headscale's gRPC listens.
type Config struct {
	// Target is "unix:///run/headscale/headscale.sock" or a bare absolute socket path. A loopback
	// "host:port" (for example "127.0.0.1:50444", the compose test relay) is also accepted. The
	// connection has no TLS and Headscale's socket no authentication, so New refuses every
	// other address rather than send admin gRPC over a network.
	Target string
	// Timeout bounds each call; a shorter deadline on the caller's context wins. Zero: DefaultTimeout.
	Timeout time.Duration
}

// Client talks to Headscale. Use New.
type Client struct {
	api     v1.HeadscaleServiceClient
	conn    *grpc.ClientConn
	timeout time.Duration
}

// Policy is the ACL policy Headscale holds.
type Policy struct {
	Text      string
	UpdatedAt time.Time
}

// User is a Headscale user.
type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Email       string
	ProviderID  string
	Provider    string
}

// Node is a Headscale node. Expiry is nil when the node has no expiry. A tagged node (Tags not
// empty) is owned by its tag, not by UserID; callers that expire nodes must skip those (stack-notes).
type Node struct {
	ID        uint64
	Name      string
	GivenName string
	UserID    uint64
	UserName  string
	Tags      []string
	IPs       []string
	Online    bool
	Expiry    *time.Time
	LastSeen  *time.Time
}

// PolicyError means Headscale itself rejected a policy; Message is Headscale's own text. It is
// distinct from a transport or server failure, which is returned as a plain error.
type PolicyError struct{ Message string }

func (e *PolicyError) Error() string { return "headscale: policy rejected: " + e.Message }

// New prepares a client. The connection is lazy: an unreachable socket shows up as an error on the
// first call, bounded by the timeout.
func New(cfg Config) (*Client, error) {
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		return nil, errors.New("headscale: empty target")
	}
	if strings.HasPrefix(target, "/") {
		target = "unix://" + target
	}
	if !strings.HasPrefix(target, "unix://") && !isLoopbackHostPort(target) {
		return nil, fmt.Errorf("headscale: target %q is neither a unix socket nor a loopback address", target)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Headscale restarts (policy writes, H-07) drop the connection; redial quickly instead of
		// backing off for minutes, so tagcess recovers without a restart of its own.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 500 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 5 * time.Second},
			MinConnectTimeout: 2 * time.Second,
		}))
	if err != nil {
		return nil, fmt.Errorf("headscale: dial %s: %w", target, err)
	}
	return &Client{api: v1.NewHeadscaleServiceClient(conn), conn: conn, timeout: timeout}, nil
}

func isLoopbackHostPort(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) ctx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, c.timeout)
}

// GetPolicy returns the policy Headscale currently holds.
func (c *Client) GetPolicy(ctx context.Context) (Policy, error) {
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.GetPolicy(ctx, &v1.GetPolicyRequest{})
	if err != nil {
		return Policy{}, fmt.Errorf("headscale: GetPolicy: %w", err)
	}
	return Policy{Text: resp.GetPolicy(), UpdatedAt: resp.GetUpdatedAt().AsTime()}, nil
}

// CheckPolicy validates a policy against Headscale's live users and nodes without applying it. A
// rejection is a *PolicyError.
func (c *Client) CheckPolicy(ctx context.Context, policy string) error {
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	if _, err := c.api.CheckPolicy(ctx, &v1.CheckPolicyRequest{Policy: policy}); err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.InvalidArgument {
			return &PolicyError{Message: st.Message()}
		}
		return fmt.Errorf("headscale: CheckPolicy: %w", err)
	}
	return nil
}

// SetPolicy applies a policy, but only after CheckPolicy accepted it: a rejected policy never
// reaches Headscale's SetPolicy (rule 7, fail safe). Headscale in file mode refuses SetPolicy; that
// error is returned as is.
func (c *Client) SetPolicy(ctx context.Context, policy string) (Policy, error) {
	if err := c.CheckPolicy(ctx, policy); err != nil {
		return Policy{}, err
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.SetPolicy(ctx, &v1.SetPolicyRequest{Policy: policy})
	if err != nil {
		return Policy{}, fmt.Errorf("headscale: SetPolicy: %w", err)
	}
	return Policy{Text: resp.GetPolicy(), UpdatedAt: resp.GetUpdatedAt().AsTime()}, nil
}

// ListUsers returns every Headscale user.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.ListUsers(ctx, &v1.ListUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("headscale: ListUsers: %w", err)
	}
	out := make([]User, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		out = append(out, User{
			ID: u.GetId(), Name: u.GetName(), DisplayName: u.GetDisplayName(), Email: u.GetEmail(),
			ProviderID: u.GetProviderId(), Provider: u.GetProvider(),
		})
	}
	return out, nil
}

// ListNodes returns every Headscale node.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.ListNodes(ctx, &v1.ListNodesRequest{})
	if err != nil {
		return nil, fmt.Errorf("headscale: ListNodes: %w", err)
	}
	out := make([]Node, 0, len(resp.GetNodes()))
	for _, n := range resp.GetNodes() {
		out = append(out, nodeFromProto(n))
	}
	return out, nil
}

// ExpireNode expires a node now and checks the answer: Headscale must report the same node with an
// expiry that is no longer in the future. Anything else is an error, so a caller never records a
// node as cut off when it is not.
func (c *Client) ExpireNode(ctx context.Context, id uint64) (Node, error) {
	if id == 0 {
		return Node{}, errors.New("headscale: ExpireNode: node id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	now := time.Now()
	resp, err := c.api.ExpireNode(ctx, &v1.ExpireNodeRequest{NodeId: id, Expiry: timestamppb.New(now)})
	if err != nil {
		return Node{}, fmt.Errorf("headscale: ExpireNode %d: %w", id, err)
	}
	n := resp.GetNode()
	if n == nil || n.GetId() != id {
		return Node{}, fmt.Errorf("headscale: ExpireNode %d: response is for node %d", id, n.GetId())
	}
	node := nodeFromProto(n)
	// The server stores the expiry we sent; a backend that rounds it up by microseconds still lands
	// before the moment the answer arrived.
	if node.Expiry == nil || node.Expiry.After(time.Now()) {
		return Node{}, fmt.Errorf("headscale: ExpireNode %d: expiry is %v, not in the past", id, node.Expiry)
	}
	return node, nil
}

func nodeFromProto(n *v1.Node) Node {
	return Node{
		ID: n.GetId(), Name: n.GetName(), GivenName: n.GetGivenName(),
		UserID: n.GetUser().GetId(), UserName: n.GetUser().GetName(),
		Tags: n.GetTags(), IPs: n.GetIpAddresses(), Online: n.GetOnline(),
		Expiry: timeOrNil(n.GetExpiry()), LastSeen: timeOrNil(n.GetLastSeen()),
	}
}

// timeOrNil maps an unset or zero timestamp to nil; Headscale sends the zero time for "never".
func timeOrNil(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	if t.Unix() <= 0 {
		return nil
	}
	return &t
}
