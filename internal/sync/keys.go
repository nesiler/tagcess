package sync

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// AlertKeyRevokeFailed is raised when the personal pre-auth key revocation could not list or expire
// keys. It never stops the group and node steps; the next reconcile retries, and a clean key step
// resolves it (F3-013 AC5).
const AlertKeyRevokeFailed = "key_revoke_failed"

// KeyRevoker is the narrow Headscale key surface a reconcile sees (F3-013). The F1 client and its
// exported-surface test stay untouched: expiring a key is an admin operation, so the real
// implementation is the executor-backed adapter from NewKeyRevoker.
type KeyRevoker interface {
	ListPreAuthKeys(ctx context.Context) ([]admin.PreAuthKey, error)
	// ExpirePreAuthKey expires one key read by ListPreAuthKeys; reason is written to the audit log.
	ExpirePreAuthKey(ctx context.Context, key admin.PreAuthKey, reason string) error
}

// KeyRevocation is a personal pre-auth key the reconcile expires (or, in dry run, would expire).
type KeyRevocation struct {
	KeyID  uint64
	UserID string // Zitadel user ID
	Why    string
}

// keyOwners maps a Headscale user ID to its Zitadel user ID, for the users that belong to this issuer.
func keyOwners(users []headscale.User, issuer string) map[uint64]string {
	out := map[uint64]string{}
	for _, u := range users {
		if id, ok := render.MatchUserID(u.ProviderID, issuer); ok {
			out[u.ID] = id
		}
	}
	return out
}

// usableKey reports whether a key can still register a device: not expired and either unused or
// reusable. Headscale sends no expiration for a key that never expires.
func usableKey(k admin.PreAuthKey, now time.Time) bool {
	if k.Expiration != nil && !k.Expiration.After(now) {
		return false
	}
	return !k.Used || k.Reusable
}

// personalKeyCandidates returns the usable personal keys (no ACL tags, owned by a user of this
// issuer) with their Zitadel owner. Tagged keys belong to their tag and are never touched.
func personalKeyCandidates(keys []admin.PreAuthKey, owners map[uint64]string, now time.Time) map[uint64][]admin.PreAuthKey {
	out := map[uint64][]admin.PreAuthKey{}
	for _, k := range keys {
		if len(k.Tags) > 0 || !usableKey(k, now) {
			continue
		}
		if _, ok := owners[k.UserID]; !ok {
			continue
		}
		out[k.UserID] = append(out[k.UserID], k)
	}
	return out
}

// keyRevocations decides which candidate keys to revoke with the Y-04 rule for nodes: the owner's
// account is inactive, locked or removed, or the owner holds no role. An owner whose state is unknown
// is skipped (fail safe).
func keyRevocations(cands map[uint64][]admin.PreAuthKey, owners map[uint64]string, grants []zitadel.Grant, states map[string]zitadel.UserState) []KeyRevocation {
	hasRole := map[string]bool{}
	for _, g := range grants {
		hasRole[g.UserID] = true
	}
	var out []KeyRevocation
	for hsID, keys := range cands {
		zid := owners[hsID]
		state, known := states[zid]
		if !known {
			continue
		}
		var why string
		switch {
		case state == zitadel.UserInactive || state == zitadel.UserLocked || state == zitadel.UserDeleted:
			why = "kullanıcı " + state.String()
		case !hasRole[zid]:
			why = "hiç rol kalmadı"
		default:
			continue
		}
		for _, k := range keys {
			out = append(out, KeyRevocation{KeyID: k.ID, UserID: zid, Why: why})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out
}

// revokeKeys is the key step of a reconcile. The caller runs it only after a healthy read and after
// the group and node steps, so a failure here cannot hold them back. Dry run only reports. A failure
// becomes the AlertKeyRevokeFailed alert and Result.KeyErr; the next reconcile retries because a key
// that could not be expired is still usable and still a candidate.
func (r *Reconciler) revokeKeys(ctx context.Context, ev evaluation, res *Result) error {
	if r.keys == nil {
		return nil
	}
	planned, err := r.keyPlan(ctx, ev)
	switch {
	case err != nil:
	case ev.in.Settings.DryRun:
		for _, p := range planned {
			res.RevokedKeys = append(res.RevokedKeys, p.KeyRevocation)
		}
		if len(planned) > 0 {
			res.Plan.Warnings = append(res.Plan.Warnings,
				fmt.Sprintf("dry-run: %d pre-auth key iptal edilecekti", len(planned)))
		}
	default:
		var failed []error
		for _, p := range planned {
			if kerr := r.keys.ExpirePreAuthKey(ctx, p.key, p.Why); kerr != nil {
				failed = append(failed, fmt.Errorf("key %d: %w", p.KeyID, kerr))
				continue
			}
			res.RevokedKeys = append(res.RevokedKeys, p.KeyRevocation)
		}
		err = errors.Join(failed...)
	}
	res.KeyErr = err
	return r.updateAlert(ctx, AlertKeyRevokeFailed, SourceHeadscale, err, ev.now)
}

// plannedKey is a revocation with the listed key it targets.
type plannedKey struct {
	KeyRevocation
	key admin.PreAuthKey
}

// keyPlan lists the keys and decides which to revoke. Zitadel states the plan already read are
// reused; an owner outside them (no grant, no node) is asked once more, and one Zitadel cannot
// answer is left alone.
func (r *Reconciler) keyPlan(ctx context.Context, ev evaluation) ([]plannedKey, error) {
	keys, err := r.keys.ListPreAuthKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("pre-auth key listesi: %w", err)
	}
	owners := keyOwners(ev.in.Users, r.issuer)
	cands := personalKeyCandidates(keys, owners, ev.now)

	states := map[string]zitadel.UserState{}
	for id, st := range ev.in.Read.States {
		states[id] = st
	}
	var missing []string
	for hsID := range cands {
		if _, ok := states[owners[hsID]]; !ok {
			missing = append(missing, owners[hsID])
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		got, err := r.z.UserStates(ctx, missing)
		if err != nil {
			return nil, fmt.Errorf("kullanıcı durumları: %w", err)
		}
		for id, st := range got {
			states[id] = st
		}
	}

	byID := map[uint64]admin.PreAuthKey{}
	for _, k := range keys {
		byID[k.ID] = k
	}
	var out []plannedKey
	for _, rev := range keyRevocations(cands, owners, ev.in.Read.Grants, states) {
		out = append(out, plannedKey{KeyRevocation: rev, key: byID[rev.KeyID]})
	}
	return out, nil
}

// NewKeyRevoker returns the KeyRevoker that expires keys through the admin pipeline (F3-009), so
// every revocation takes the writer lock, is read back and leaves a started and a result audit row
// under actor (system:sync). The client lists and expires; it is the admin client in production.
func NewKeyRevoker(ex *hsadmin.Executor, c KeyClient, actor string) KeyRevoker {
	return &executorKeyRevoker{ex: ex, c: c, actor: actor, clock: time.Now}
}

// KeyClient is the admin client's key surface the adapter needs (*admin.AdminClient).
type KeyClient interface {
	ListPreAuthKeys(ctx context.Context) ([]admin.PreAuthKey, error)
	ExpirePreAuthKey(ctx context.Context, id uint64) error
}

type executorKeyRevoker struct {
	ex    *hsadmin.Executor
	c     KeyClient
	actor string
	clock func() time.Time
}

func (e *executorKeyRevoker) ListPreAuthKeys(ctx context.Context) ([]admin.PreAuthKey, error) {
	return e.c.ListPreAuthKeys(ctx)
}

func (e *executorKeyRevoker) ExpirePreAuthKey(ctx context.Context, key admin.PreAuthKey, reason string) error {
	op := hsadmin.Op{
		Actor:    e.actor,
		Kind:     hsadmin.KindPreAuthExpire,
		ID:       key.ID,
		Target:   "preauth:" + strconv.FormatUint(key.ID, 10),
		Expected: hsadmin.PreAuthVersion(key),
		Diff: audit.Diff{
			{Field: "user", After: key.UserName},
			{Field: "expiration", Before: expirationText(key.Expiration), After: "expired"},
			{Field: "reason", After: reason},
		},
		Apply: func(ctx context.Context) error { return e.c.ExpirePreAuthKey(ctx, key.ID) },
		// A key that is gone or no longer usable has reached the intended state.
		Verify: func(ctx context.Context, _ hsadmin.Reader) (bool, error) {
			keys, err := e.c.ListPreAuthKeys(ctx)
			if err != nil {
				return false, err
			}
			for _, k := range keys {
				if k.ID == key.ID {
					return k.Expiration != nil && !k.Expiration.After(e.clock()), nil
				}
			}
			return true, nil
		},
	}
	_, err := e.ex.Do(ctx, op)
	return err
}

func expirationText(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}
