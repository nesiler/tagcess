package sync

import (
	"errors"
	"fmt"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/zitadel"
)

// maxRemovedPercent is the largest allowed percentage threshold; anything above 100% is meaningless.
const maxRemovedPercent = 100

// MaxRemovedUsersLimit bounds the user-count threshold. The target scale is 15-30 users (00 §6.2), so
// a limit this high already means "never ask for approval on count"; a larger value would silently
// disable the Y-03.4 protection, which must be rejected instead.
const MaxRemovedUsersLimit = 10000

// Validate rejects a threshold the settings layer must never store. Zero means "use the default", so
// it is valid; negative and out-of-range values are not (Y-03.4).
func (s Settings) Validate() error {
	if s.MaxRemovedPercent < 0 || s.MaxRemovedPercent > maxRemovedPercent {
		return fmt.Errorf("sync: max_removed_percent must be between 0 and %d, got %d", maxRemovedPercent, s.MaxRemovedPercent)
	}
	if s.MaxRemovedUsers < 0 || s.MaxRemovedUsers > MaxRemovedUsersLimit {
		return fmt.Errorf("sync: max_removed_users must be between 0 and %d, got %d", MaxRemovedUsersLimit, s.MaxRemovedUsers)
	}
	return nil
}

// Target renders the policy the plan would produce from in: one group per role of the vpn project,
// with the active holders as members. It mirrors Compute's "wanted" set, so applying the plan and
// rendering it cannot disagree (F1-008 RenderGroups, F1-009 Compute).
//
// Every grant role must be in in.Roles: an incomplete role set would make RenderGroups drop a
// group that still has holders, so it is refused rather than passed to the engine (decision on
// F1-009/F1-010).
func Target(in Input) ([]byte, error) {
	if in.Read.Err != nil {
		return nil, fmt.Errorf("sync: Zitadel read failed: %w", in.Read.Err)
	}
	if !in.Read.Complete {
		return nil, errors.New("sync: Zitadel read is incomplete")
	}
	if in.Format == nil {
		return nil, errors.New("sync: member format is nil")
	}
	roleSet := make(map[string]bool, len(in.Roles))
	roles := make(map[string][]string, len(in.Roles))
	// Only holders with a Headscale user are written (R2 decision 27); see Compute.
	_, hasHSUser := headscaleIdentities(in)
	for _, r := range in.Roles {
		roleSet[r] = true
		roles[r] = []string{}
	}
	for _, g := range in.Read.Grants {
		if !roleSet[g.Role] {
			return nil, fmt.Errorf("sync: grant for role %q but the required role set is incomplete", g.Role)
		}
		state, ok := in.Read.States[g.UserID]
		if !ok {
			return nil, fmt.Errorf("sync: grant user %s has no known state", g.UserID)
		}
		if state != zitadel.UserActive || !hasHSUser[g.UserID] {
			continue
		}
		roles[g.Role] = append(roles[g.Role], g.UserID)
	}
	return render.RenderGroups(in.Policy, roles, in.Format)
}

// Request turns a computed plan into a change request: the plan's gates, the rendered target and the
// node expiries. The request names its source (sync) explicitly: the maintenance gate lets only that
// source write while the reconcile is pending, and must not guess it from an empty field (H-07).
// Settings are validated here so an out-of-range threshold never reaches the engine
// (the settings layer's job is to reject them at the boundary; this is the last check before use).
func Request(in Input, p Plan, actor, trigger, summary string) (change.Request, error) {
	if err := in.Settings.Validate(); err != nil {
		return change.Request{}, err
	}
	req := change.Request{
		Kind:          change.KindPolicy,
		Actor:         actor,
		Trigger:       trigger,
		Summary:       summary,
		Blocked:       p.Blocked,
		NeedsApproval: p.NeedsApproval,
		// Compute's early returns (a failed read) do not carry the dry-run flag, so read it from
		// the settings as well: with dry run on, only sync_runs may be written (Y-06).
		DryRun:       p.DryRun || in.Settings.DryRun,
		Reason:       p.Reason,
		SourcePolicy: in.Policy,
		Revision:     change.RevisionMeta{Source: string(policyrev.SourceSync)},
	}
	// A plan with no gate that is not applicable (WillApply false) is an incomplete or failed read:
	// Compute returns it without Blocked set. Treat it as blocked so the pipeline records it and
	// writes nothing; never render an empty membership from a read we do not trust (Y-03.3, Y-04.5).
	if !p.WillApply && !p.NeedsApproval && !p.DryRun && !p.Blocked {
		req.Blocked = true
		if req.Reason == "" {
			req.Reason = "plan apply edilemez durumda"
		}
		return req, nil
	}
	if p.Blocked {
		return req, nil
	}
	target, err := Target(in)
	if err != nil {
		return change.Request{}, err
	}
	req.Target = target
	for _, e := range p.ExpireNodes {
		req.Expire = append(req.Expire, e.NodeID)
	}
	return req, nil
}
