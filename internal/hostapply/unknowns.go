package hostapply

import (
	"context"
	"slices"

	"github.com/nesiler/tagcess/internal/store/db"
)

// AlertLister lists the open alerts; *db.Queries satisfies it.
type AlertLister interface {
	ListOpenAlerts(ctx context.Context) ([]db.Alert, error)
}

// KindPolicy is the Unknown kind for an uncertain policy write.
const KindPolicy = "policy"

type unknowns struct {
	policy func(ctx context.Context) (string, error)
	alerts AlertLister
	kinds  []string
}

// NewUnknowns builds the source of unresolved outcomes: the policy writer's uncertain state (policy
// returns a description, "" when resolved) and the open alerts of the given kinds (the admin
// executor's unverified alert and the key revocation alert). Any unreadable part is an error, so
// a caller that must not start blind refuses.
func NewUnknowns(policy func(ctx context.Context) (string, error), alerts AlertLister, alertKinds ...string) UnknownSource {
	return &unknowns{policy: policy, alerts: alerts, kinds: alertKinds}
}

func (u *unknowns) Open(ctx context.Context) ([]Unknown, error) {
	var out []Unknown
	detail, err := u.policy(ctx)
	if err != nil {
		return nil, err
	}
	if detail != "" {
		out = append(out, Unknown{Kind: KindPolicy, Detail: detail})
	}
	rows, err := u.alerts.ListOpenAlerts(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		if slices.Contains(u.kinds, a.Kind) {
			out = append(out, Unknown{Kind: a.Kind, Detail: a.Source})
		}
	}
	return out, nil
}
