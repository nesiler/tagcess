package hsadmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/policydoc"
)

// ProtectedTagsKey is the settings key holding the protected tag list as a JSON array of strings
// (R2 decision 6). The settings screen (F3-020) edits it; this package only reads it.
const ProtectedTagsKey = "headscale.protected_tags"

// defaultProtectedTags applies while the setting has never been written.
var defaultProtectedTags = []string{"tag:vpn-server", "tag:k8s"}

// SettingReader reads one settings row; a missing key is sql.ErrNoRows. *db.Queries satisfies it.
type SettingReader interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// LoadProtectedTags reads the list fresh from settings. An unset key yields the default and
// isDefault true. An unreadable or corrupt value is an error: callers fail closed. A stored empty
// list is readable (it protects nothing); the settings screen never writes one.
func LoadProtectedTags(ctx context.Context, s SettingReader) (tags []string, isDefault bool, err error) {
	raw, err := s.GetSetting(ctx, ProtectedTagsKey)
	if errors.Is(err, sql.ErrNoRows) {
		return slices.Clone(defaultProtectedTags), true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("hsadmin: read %s: %w", ProtectedTagsKey, err)
	}
	if err := json.Unmarshal([]byte(raw), &tags); err != nil || tags == nil {
		return nil, false, fmt.Errorf("hsadmin: setting %s is not a JSON string array", ProtectedTagsKey)
	}
	return tags, false, nil
}

// ProtectedTags reads the list fresh from settings, so a change is seen by the next operation.
func (e *Executor) ProtectedTags(ctx context.Context) ([]string, error) {
	tags, _, err := LoadProtectedTags(ctx, e.store)
	return tags, err
}

// ValidateProtectedTags checks a list the settings screen is about to store: trimmed, de-duplicated
// in order, every entry a valid tag, never empty (fail safe: an empty list would protect nothing).
func ValidateProtectedTags(tags []string) ([]string, error) {
	var out []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if !policydoc.ValidTag(t) {
			return nil, fmt.Errorf("%q is not a valid tag (tag:name, lower case, digits, hyphen)", t)
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("the protected tag list cannot be empty")
	}
	return out, nil
}

// ProtectedTagsSetting validates the list and returns its stored JSON form.
func ProtectedTagsSetting(tags []string) (string, error) {
	tags, err := ValidateProtectedTags(tags)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return "", fmt.Errorf("hsadmin: encode protected tags: %w", err)
	}
	return string(b), nil
}

// protectedKinds are the operations a protected node rejects. node.rename and node.routes stay
// allowed (R2: the decision names only delete, expire and tags; node.expiry and tag assignment
// are in scope because a near expiry is an expire and a protected tag grants server rights).
var protectedKinds = []Kind{KindNodeDelete, KindNodeExpire, KindNodeExpiry, KindNodeTags}

// blockReason returns why op must not run against node, or "" when it may. tags is the protected
// list, listErr why it could not be read: then every tagged node is protected and no tag can be
// assigned, because nothing can be judged (rule 7).
func blockReason(op Op, node admin.AdminNode, tags []string, listErr error) string {
	if !slices.Contains(protectedKinds, op.Kind) {
		return ""
	}
	if listErr != nil {
		if len(node.Tags) > 0 || (op.Kind == KindNodeTags && len(op.Tags) > 0) {
			return "korumalı tag listesi okunamadı veya bozuk; tag'li node'lara yazılmaz"
		}
		return ""
	}
	for _, t := range node.Tags {
		if slices.Contains(tags, t) {
			return fmt.Sprintf("node korumalı %s tag'ini taşıyor", t)
		}
	}
	if op.Kind == KindNodeTags {
		for _, t := range op.Tags {
			if slices.Contains(tags, t) {
				return fmt.Sprintf("%s korumalı tag'i atanamaz", t)
			}
		}
	}
	return ""
}
