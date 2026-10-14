// Package admin is tagcess's client for the destructive Headscale RPCs (R2 decision 19): node
// rename, delete, expiry, tags and approved routes, and pre-auth and API key management. The
// Headscale unix socket serves unauthenticated, full-admin gRPC (stack-notes), so this package
// exists to keep those operations out of the narrow F1 client (internal/headscale), whose pinned
// surface stays unchanged; callers here are the devops-approved UI flows and the F3 executor.
//
// The guardrails mirror the F1 client: only a unix socket or a loopback address is accepted as
// the target, every call is bounded by a timeout, errors are returned wrapped and never retried.
// Pre-auth key secrets never enter the DTOs; a created key's secret is returned once, as a
// separate value, and it is the caller's job not to log it. API keys are addressed by ID only.
package admin

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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"

	"github.com/nesiler/tagcess/internal/headscale"
)

// Config says where Headscale's gRPC listens; it is the F1 client's Config.
type Config = headscale.Config

// AdminClient talks to Headscale for the destructive RPCs. Use NewAdmin.
type AdminClient struct {
	api     v1.HeadscaleServiceClient
	conn    *grpc.ClientConn
	timeout time.Duration
}

// AdminNode is a Headscale node with the fields the admin views need: routes, expiry, tags,
// owner and registration time. Expiry is nil when the node never expires.
type AdminNode struct {
	ID              uint64
	Name            string
	GivenName       string
	UserID          uint64
	UserName        string
	Tags            []string
	IPs             []string
	Online          bool
	Expiry          *time.Time
	LastSeen        *time.Time
	CreatedAt       time.Time
	ApprovedRoutes  []string
	AvailableRoutes []string
	SubnetRoutes    []string
}

// PreAuthKey is a pre-auth key as the list returns it. It deliberately has no key field: the
// secret exists only at creation time, as CreatePreAuthKey's separate return value.
type PreAuthKey struct {
	ID         uint64
	UserID     uint64
	UserName   string
	Reusable   bool
	Ephemeral  bool
	Used       bool
	Expiration *time.Time
	CreatedAt  time.Time
	Tags       []string
}

// PreAuthKeyOptions describes a pre-auth key to create.
type PreAuthKeyOptions struct {
	Reusable  bool
	Ephemeral bool
	// Expiration bounds the key's validity. Zero sends no expiration, which Headscale v0.29.4 stores
	// as the zero time: the key is expired from the start (grpcv1.go CreatePreAuthKey,
	// types/preauth_key.go Validate). There is no "never expires" pre-auth key; set a time.
	Expiration time.Time
	// Tags are the ACL tags assigned to nodes registered with the key.
	Tags []string
}

// APIKey is a Headscale API key as the list returns it. The prefix is not secret; Headscale
// shows it to identify keys.
type APIKey struct {
	ID         uint64
	Prefix     string
	Expiration *time.Time
	CreatedAt  time.Time
	LastSeen   *time.Time
}

// NewAdmin prepares an admin client. The target rule is the F1 client's: a unix socket or a
// loopback address, nothing else. The connection is lazy: an unreachable socket shows up as an
// error on the first call, bounded by the timeout.
func NewAdmin(cfg Config) (*AdminClient, error) {
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		return nil, errors.New("headscale/admin: empty target")
	}
	if strings.HasPrefix(target, "/") {
		target = "unix://" + target
	}
	if !strings.HasPrefix(target, "unix://") && !isLoopbackHostPort(target) {
		return nil, fmt.Errorf("headscale/admin: target %q is neither a unix socket nor a loopback address", target)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = headscale.DefaultTimeout
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Headscale restarts (policy writes, H-07) drop the connection; redial quickly instead of
		// backing off for minutes, so tagcess recovers without a restart of its own.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 500 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 5 * time.Second},
			MinConnectTimeout: 2 * time.Second,
		}))
	if err != nil {
		return nil, fmt.Errorf("headscale/admin: dial %s: %w", target, err)
	}
	return &AdminClient{api: v1.NewHeadscaleServiceClient(conn), conn: conn, timeout: timeout}, nil
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
func (c *AdminClient) Close() error { return c.conn.Close() }

func (c *AdminClient) ctx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, c.timeout)
}

// RenameNode gives a node a new name.
func (c *AdminClient) RenameNode(ctx context.Context, id uint64, newName string) (AdminNode, error) {
	if id == 0 {
		return AdminNode{}, errors.New("headscale/admin: RenameNode: node id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.RenameNode(ctx, &v1.RenameNodeRequest{NodeId: id, NewName: newName})
	if err != nil {
		return AdminNode{}, fmt.Errorf("headscale/admin: RenameNode %d: %w", id, err)
	}
	return respNode(resp.GetNode(), id)
}

// DeleteNode removes a node from the tailnet. It cannot be undone; callers (the F3 executor)
// own approval and protection rules.
func (c *AdminClient) DeleteNode(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("headscale/admin: DeleteNode: node id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	if _, err := c.api.DeleteNode(ctx, &v1.DeleteNodeRequest{NodeId: id}); err != nil {
		return fmt.Errorf("headscale/admin: DeleteNode %d: %w", id, err)
	}
	return nil
}

// ExpireNode sets the node's expiry to the given time: a past time cuts the node off now, a
// future time schedules it. The F1 client's ExpireNode (expire now, verified) stays the tool for
// the Y-04 role-loss flow.
func (c *AdminClient) ExpireNode(ctx context.Context, id uint64, expiry time.Time) (AdminNode, error) {
	if id == 0 {
		return AdminNode{}, errors.New("headscale/admin: ExpireNode: node id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.ExpireNode(ctx, &v1.ExpireNodeRequest{NodeId: id, Expiry: timestamppb.New(expiry)})
	if err != nil {
		return AdminNode{}, fmt.Errorf("headscale/admin: ExpireNode %d: %w", id, err)
	}
	return respNode(resp.GetNode(), id)
}

// EnableNode clears the node's expiry, so it never expires again. This widens access; callers
// own the approval and re-checks around it.
func (c *AdminClient) EnableNode(ctx context.Context, id uint64) (AdminNode, error) {
	if id == 0 {
		return AdminNode{}, errors.New("headscale/admin: EnableNode: node id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.ExpireNode(ctx, &v1.ExpireNodeRequest{NodeId: id, DisableExpiry: true})
	if err != nil {
		return AdminNode{}, fmt.Errorf("headscale/admin: EnableNode %d: %w", id, err)
	}
	n, err := respNode(resp.GetNode(), id)
	if err != nil {
		return AdminNode{}, err
	}
	if n.Expiry != nil {
		return AdminNode{}, fmt.Errorf("headscale/admin: EnableNode %d: expiry is %v, want none", id, n.Expiry)
	}
	return n, nil
}

// SetTags replaces the node's ACL tags with the given full list; an empty list is refused here
// because Headscale rejects it too (a node cannot lose its owner tag this way).
func (c *AdminClient) SetTags(ctx context.Context, id uint64, tags []string) (AdminNode, error) {
	if id == 0 {
		return AdminNode{}, errors.New("headscale/admin: SetTags: node id 0")
	}
	if len(tags) == 0 {
		return AdminNode{}, errors.New("headscale/admin: SetTags: empty tag list")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.SetTags(ctx, &v1.SetTagsRequest{NodeId: id, Tags: tags})
	if err != nil {
		return AdminNode{}, fmt.Errorf("headscale/admin: SetTags %d: %w", id, err)
	}
	return respNode(resp.GetNode(), id)
}

// SetApprovedRoutes replaces the node's approved routes with the given full CIDR list; an empty
// list withdraws all approvals. Every entry must parse as a CIDR, checked before the RPC.
func (c *AdminClient) SetApprovedRoutes(ctx context.Context, id uint64, routes []string) (AdminNode, error) {
	if id == 0 {
		return AdminNode{}, errors.New("headscale/admin: SetApprovedRoutes: node id 0")
	}
	for _, r := range routes {
		if _, err := netip.ParsePrefix(r); err != nil {
			return AdminNode{}, fmt.Errorf("headscale/admin: SetApprovedRoutes: route %q: %w", r, err)
		}
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.SetApprovedRoutes(ctx, &v1.SetApprovedRoutesRequest{NodeId: id, Routes: routes})
	if err != nil {
		return AdminNode{}, fmt.Errorf("headscale/admin: SetApprovedRoutes %d: %w", id, err)
	}
	return respNode(resp.GetNode(), id)
}

// ListNodes returns every node with the admin fields.
func (c *AdminClient) ListNodes(ctx context.Context) ([]AdminNode, error) {
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.ListNodes(ctx, &v1.ListNodesRequest{})
	if err != nil {
		return nil, fmt.Errorf("headscale/admin: ListNodes: %w", err)
	}
	out := make([]AdminNode, 0, len(resp.GetNodes()))
	for _, n := range resp.GetNodes() {
		out = append(out, adminNodeFromProto(n))
	}
	return out, nil
}

func respNode(n *v1.Node, id uint64) (AdminNode, error) {
	if n == nil || n.GetId() != id {
		return AdminNode{}, fmt.Errorf("headscale/admin: response is for node %d, want %d", n.GetId(), id)
	}
	return adminNodeFromProto(n), nil
}

func adminNodeFromProto(n *v1.Node) AdminNode {
	return AdminNode{
		ID: n.GetId(), Name: n.GetName(), GivenName: n.GetGivenName(),
		UserID: n.GetUser().GetId(), UserName: n.GetUser().GetName(),
		Tags: n.GetTags(), IPs: n.GetIpAddresses(), Online: n.GetOnline(),
		Expiry:          timeOrNil(n.GetExpiry()),
		LastSeen:        timeOrNil(n.GetLastSeen()),
		CreatedAt:       n.GetCreatedAt().AsTime(),
		ApprovedRoutes:  n.GetApprovedRoutes(),
		AvailableRoutes: n.GetAvailableRoutes(),
		SubnetRoutes:    n.GetSubnetRoutes(),
	}
}

// CreatePreAuthKey creates a key and returns its metadata and, once, its secret. The secret is a
// separate return value on purpose: the DTO the UI works with never carries it, so it cannot leak
// through templates or logs by accident. The caller shows it once and does not store it.
func (c *AdminClient) CreatePreAuthKey(ctx context.Context, userID uint64, opts PreAuthKeyOptions) (PreAuthKey, string, error) {
	// A tagged key may have no owner (user 0, verified on v0.29.4: the nodes it registers are owned
	// by their tags); a personal key must name its user.
	if userID == 0 && len(opts.Tags) == 0 {
		return PreAuthKey{}, "", errors.New("headscale/admin: CreatePreAuthKey: user id 0 needs tags")
	}
	req := &v1.CreatePreAuthKeyRequest{User: userID, Reusable: opts.Reusable, Ephemeral: opts.Ephemeral, AclTags: opts.Tags}
	if !opts.Expiration.IsZero() {
		req.Expiration = timestamppb.New(opts.Expiration)
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.CreatePreAuthKey(ctx, req)
	if err != nil {
		return PreAuthKey{}, "", fmt.Errorf("headscale/admin: CreatePreAuthKey: %w", err)
	}
	pk := resp.GetPreAuthKey()
	if pk == nil {
		return PreAuthKey{}, "", errors.New("headscale/admin: CreatePreAuthKey: empty response")
	}
	return preAuthKeyFromProto(pk), pk.GetKey(), nil
}

// ListPreAuthKeys returns every pre-auth key. The response may still contain legacy plaintext
// secrets; they are dropped here and never reach the DTO.
func (c *AdminClient) ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.ListPreAuthKeys(ctx, &v1.ListPreAuthKeysRequest{})
	if err != nil {
		return nil, fmt.Errorf("headscale/admin: ListPreAuthKeys: %w", err)
	}
	out := make([]PreAuthKey, 0, len(resp.GetPreAuthKeys()))
	for _, k := range resp.GetPreAuthKeys() {
		out = append(out, preAuthKeyFromProto(k))
	}
	return out, nil
}

// ExpirePreAuthKey marks the key expired.
func (c *AdminClient) ExpirePreAuthKey(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("headscale/admin: ExpirePreAuthKey: key id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	if _, err := c.api.ExpirePreAuthKey(ctx, &v1.ExpirePreAuthKeyRequest{Id: id}); err != nil {
		return fmt.Errorf("headscale/admin: ExpirePreAuthKey %d: %w", id, err)
	}
	return nil
}

// DeletePreAuthKey removes the key.
func (c *AdminClient) DeletePreAuthKey(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("headscale/admin: DeletePreAuthKey: key id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	if _, err := c.api.DeletePreAuthKey(ctx, &v1.DeletePreAuthKeyRequest{Id: id}); err != nil {
		return fmt.Errorf("headscale/admin: DeletePreAuthKey %d: %w", id, err)
	}
	return nil
}

// ListApiKeys returns every API key.
func (c *AdminClient) ListApiKeys(ctx context.Context) ([]APIKey, error) {
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	resp, err := c.api.ListApiKeys(ctx, &v1.ListApiKeysRequest{})
	if err != nil {
		return nil, fmt.Errorf("headscale/admin: ListApiKeys: %w", err)
	}
	out := make([]APIKey, 0, len(resp.GetApiKeys()))
	for _, k := range resp.GetApiKeys() {
		out = append(out, APIKey{
			ID: k.GetId(), Prefix: k.GetPrefix(),
			Expiration: timeOrNil(k.GetExpiration()), CreatedAt: k.GetCreatedAt().AsTime(),
			LastSeen: timeOrNil(k.GetLastSeen()),
		})
	}
	return out, nil
}

// ExpireApiKey marks the API key expired, addressed by ID only; the request's prefix field stays
// unset (R2 decisions 7–8: no prefix addressing, no key creation).
func (c *AdminClient) ExpireApiKey(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("headscale/admin: ExpireApiKey: key id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	if _, err := c.api.ExpireApiKey(ctx, &v1.ExpireApiKeyRequest{Id: id}); err != nil {
		return fmt.Errorf("headscale/admin: ExpireApiKey %d: %w", id, err)
	}
	return nil
}

// DeleteApiKey removes the API key, addressed by ID only.
func (c *AdminClient) DeleteApiKey(ctx context.Context, id uint64) error {
	if id == 0 {
		return errors.New("headscale/admin: DeleteApiKey: key id 0")
	}
	ctx, cancel := c.ctx(ctx)
	defer cancel()
	if _, err := c.api.DeleteApiKey(ctx, &v1.DeleteApiKeyRequest{Id: id}); err != nil {
		return fmt.Errorf("headscale/admin: DeleteApiKey %d: %w", id, err)
	}
	return nil
}

func preAuthKeyFromProto(k *v1.PreAuthKey) PreAuthKey {
	return PreAuthKey{
		ID: k.GetId(), UserID: k.GetUser().GetId(), UserName: k.GetUser().GetName(),
		Reusable: k.GetReusable(), Ephemeral: k.GetEphemeral(), Used: k.GetUsed(),
		Expiration: timeOrNil(k.GetExpiration()), CreatedAt: k.GetCreatedAt().AsTime(),
		Tags: k.GetAclTags(),
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
