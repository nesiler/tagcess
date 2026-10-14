package hsadmin

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/nesiler/tagcess/internal/headscale/admin"
)

// AC4: the protected list comes from settings: default when unset, a change is seen by the next
// operation, a corrupt value fails closed for tagged nodes.
func TestProtectedTags_Settings(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	got, err := h.ex.ProtectedTags(ctx)
	if err != nil || !equalStrings(got, []string{"tag:vpn-server", "tag:k8s"}) {
		t.Fatalf("default = %v, %v", got, err)
	}

	// The default protects the gateway.
	if _, err := h.ex.Do(ctx, h.nodeOp(KindNodeDelete, 2, nil, nil)); !errors.Is(err, ErrBlocked) {
		t.Fatalf("default list: err = %v, want ErrBlocked", err)
	}

	// A new list applies to the very next operation: tag:other is protected, tag:vpn-server is not.
	h.setSetting(`["tag:other"]`)
	if _, err := h.ex.Do(ctx, h.nodeOp(KindNodeDelete, 3, nil, nil)); !errors.Is(err, ErrBlocked) {
		t.Fatalf("new list, tag:other: err = %v, want ErrBlocked", err)
	}
	if _, err := h.ex.Do(ctx, h.nodeOp(KindNodeDelete, 2, nil, nil)); err != nil {
		t.Fatalf("new list, tag:vpn-server: %v", err)
	}

	// An empty list protects nothing.
	h.setSetting(`[]`)
	if _, err := h.ex.Do(ctx, h.nodeOp(KindNodeDelete, 3, nil, nil)); err != nil {
		t.Fatalf("empty list: %v", err)
	}

	// A corrupt value: tagged nodes are protected, untagged ones are not.
	h = newHarness(t)
	h.setSetting(`not json`)
	if _, err := h.ex.ProtectedTags(ctx); err == nil {
		t.Fatal("corrupt value was accepted")
	}
	if _, err := h.ex.Do(ctx, h.nodeOp(KindNodeDelete, 3, nil, nil)); !errors.Is(err, ErrBlocked) {
		t.Fatalf("corrupt list, tagged node: err = %v, want ErrBlocked", err)
	}
	// Assigning any tag cannot be judged either.
	op := h.nodeOp(KindNodeTags, 1, nil, nil)
	op.Tags = []string{"tag:harmless"}
	if _, err := h.ex.Do(ctx, op); !errors.Is(err, ErrBlocked) {
		t.Fatalf("corrupt list, tag assignment: err = %v, want ErrBlocked", err)
	}
	if h.rpcs.Load() != 0 {
		t.Errorf("rpcs = %d, want 0", h.rpcs.Load())
	}
	if _, err := h.ex.Do(ctx, h.nodeOp(KindNodeDelete, 1, nil, nil)); err != nil {
		t.Fatalf("corrupt list, untagged node: %v", err)
	}
}

func TestNodeVersion_IgnoresVolatileFields(t *testing.T) {
	a := admin.AdminNode{ID: 1, GivenName: "x", Tags: []string{"b", "a"}, Online: false}
	b := admin.AdminNode{ID: 1, GivenName: "x", Tags: []string{"a", "b"}, Online: true}
	if NodeVersion(a) != NodeVersion(b) {
		t.Error("online state or tag order changed the version")
	}
	c := a
	c.GivenName = "y"
	if NodeVersion(a) == NodeVersion(c) {
		t.Error("rename did not change the version")
	}
}

func TestValidateProtectedTags(t *testing.T) {
	got, err := ValidateProtectedTags([]string{" tag:vpn-server ", "tag:k8s", "tag:k8s"})
	if err != nil || !equalStrings(got, []string{"tag:vpn-server", "tag:k8s"}) {
		t.Fatalf("trim and dedupe = %v, %v", got, err)
	}
	for _, bad := range [][]string{nil, {}, {"tag:UP"}, {"k8s"}, {"tag:"}, {"tag:ok", "group:x"}, {"tag:a b"}} {
		if _, err := ValidateProtectedTags(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLoadProtectedTags(t *testing.T) {
	ctx := context.Background()
	tags, isDefault, err := LoadProtectedTags(ctx, fakeSettings{err: sql.ErrNoRows})
	if err != nil || !isDefault || !equalStrings(tags, []string{"tag:vpn-server", "tag:k8s"}) {
		t.Fatalf("unset = %v, %v, %v", tags, isDefault, err)
	}
	tags, isDefault, err = LoadProtectedTags(ctx, fakeSettings{value: `["tag:a"]`})
	if err != nil || isDefault || !equalStrings(tags, []string{"tag:a"}) {
		t.Fatalf("set = %v, %v, %v", tags, isDefault, err)
	}
	for _, s := range []fakeSettings{{value: "nope"}, {value: "null"}, {err: errors.New("db down")}} {
		if _, _, err := LoadProtectedTags(ctx, s); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}

type fakeSettings struct {
	value string
	err   error
}

func (f fakeSettings) GetSetting(context.Context, string) (string, error) { return f.value, f.err }
