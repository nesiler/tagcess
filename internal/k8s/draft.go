package k8s

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/nesiler/tagcess/internal/site"
)

// draft.go maps the declared routes of one complete k8s snapshot (routes.go) onto host-based R1
// site proposals (F4-010). It is a pure function: it never writes the site store, Caddy, DNS,
// Zitadel, the cluster or the draft store. A draft is the incomplete, not-yet-applied proposal for
// one host and stays separate from the applicable site record; the user's access choice, roles and
// note are never derived from the Ingress. For a private site the operator chooses either all VPN
// users (open/intentional) or selected roles (role, at least one role); an unfinished proposal is
// storable but not complete, and a real route conflict always needs review with an unknown target.

const (
	// AccessChoiceOpen is the private access choice for all VPN users: an R1 open site with
	// open_reason intentional. It is never inferred from an empty role list.
	AccessChoiceOpen = "open"
	// AccessChoiceRole is the private access choice for selected roles: an R1 role site. It needs
	// at least one role to be complete but may be stored while the role list is still empty.
	AccessChoiceRole = "role"
)

// Review states of a draft, as stored in k8s_drafts.review_state.
const (
	ReviewStateNone     = ""
	ReviewStateNeeded   = "needed"
	ReviewStateResolved = "resolved"
)

// CertAuto is the certificate selection the first profile proposes. It never copies an Ingress
// tls.secretName and leaves the auto/le choice to R1 (F4-013).
const CertAuto = "auto"

// Draft-mapping review reasons (ReasonRouteConflict is shared with gates.go). They join the
// route-interpretation reasons (routes.go) in Draft.ReviewReason.
const (
	ReasonTargetUnresolved Reason = "target_unresolved"
	ReasonInvalidHost      Reason = "invalid_host"
)

// Draft is one host-based, not-yet-applied R1 site proposal (F4-010). It mirrors the persisted
// k8s_drafts choices/provenance (F4-009) but is a pure value; Routes is the merged route evidence
// of the host. A draft is never a SiteStore row.
type Draft struct {
	Host             string
	Target           string // https://<internal listener address>:<port>
	Cert             string // CertAuto
	AccessChoice     string // "", AccessChoiceOpen or AccessChoiceRole
	Roles            []string
	Note             string
	ReviewState      string
	ReviewReason     string
	ReviewCandidates []string
	ReviewDefault    string // "" while the first profile has no proven controller winner
	Routes           []Route
}

// Complete reports whether the draft carries everything R1 needs to be applied: a target, a
// certificate selection, no pending review and a private access choice whose pairing holds (open
// with no roles, or role with at least one role). An incomplete draft is still storable.
func (d Draft) Complete() bool {
	if d.ReviewState == ReviewStateNeeded || d.Target == "" || d.Cert == "" {
		return false
	}
	switch d.AccessChoice {
	case AccessChoiceOpen:
		return len(d.Roles) == 0
	case AccessChoiceRole:
		return len(d.Roles) > 0
	default:
		return false
	}
}

// SetPrivateAccess sets the private access choice on a draft and enforces the R1 pairing. An empty
// role list with AccessChoiceRole is kept as role (never silently turned into open); it just leaves
// the draft incomplete. Format/existence of a role is checked by the site validator at apply time.
func SetPrivateAccess(d Draft, choice string, roles []string) (Draft, error) {
	switch choice {
	case AccessChoiceOpen:
		d.AccessChoice = AccessChoiceOpen
		d.Roles = []string{}
	case AccessChoiceRole:
		d.AccessChoice = AccessChoiceRole
		d.Roles = normalizeRoles(roles)
	default:
		return Draft{}, fmt.Errorf("k8s: private access choice %q is neither %s nor %s",
			choice, AccessChoiceOpen, AccessChoiceRole)
	}
	return d, nil
}

// ManagedSite is an applied R1 site the mapping must not split or change (AC1/AC5). RouteKeys is
// the last known route identity set; empty means the routes were never observed, so a difference
// cannot be claimed.
type ManagedSite struct {
	ID           int64
	Hosts        []string
	AccessChoice string
	Roles        []string
	RouteKeys    []string
	// System marks a system-template site (zitadel, headscale, wireguard_ui, tagcess): it is not
	// served by k8s routes, so a missing route is expected (F5 L5).
	System bool
}

// ManagedStatus describes how an applied site's hosts relate to the observed routes.
type ManagedStatus string

const (
	// ManagedMatched: the hosts still have a route and no stored difference was seen.
	ManagedMatched ManagedStatus = "matched"
	// ManagedNoRoute: a complete read found no route for any of the site's hosts.
	ManagedNoRoute ManagedStatus = "no_route"
	// ManagedChanged: the observed route identity set differs from the stored one.
	ManagedChanged ManagedStatus = "changed"
	// ManagedUnknown: the read was incomplete, so absence of a route is not inferred.
	ManagedUnknown ManagedStatus = "unknown"
	// ManagedSystem: a system-template site without a k8s route; that is its normal state (F5 L5).
	ManagedSystem ManagedStatus = "system"
	// ManagedConflict: a host of the site is in an internal route conflict; which backend serves
	// it is unknown, so the mapping is not shown as matched (U-17).
	ManagedConflict ManagedStatus = "conflict"
)

// ManagedObservation is the read-only mapping result for an applied site: an observation, never an
// apply proposal. AccessChoice/Roles are echoed unchanged.
type ManagedObservation struct {
	SiteID       int64
	Hosts        []string
	Status       ManagedStatus
	AccessChoice string
	Roles        []string
}

// DraftInputs carries everything BuildDrafts reads. Complete says whether the report comes from a
// complete successful read; when false, absence of a route is not a finding.
type DraftInputs struct {
	Report   RouteReport
	Profile  Profile
	Existing []Draft
	Managed  []ManagedSite
	Complete bool
}

// DraftReport is the host-based mapping of one route interpretation.
type DraftReport struct {
	Drafts        []Draft
	Uncertainties []Uncertainty // passed through / added review items
	Conflicts     []Conflict    // every real conflict, Default always nil
	Managed       []ManagedObservation
	Scope         Scope
	Complete      bool
}

// BuildDrafts maps a route interpretation onto per-host R1 draft proposals. existing carries saved
// drafts whose user choices must be preserved; managed carries applied sites that must not be split
// or changed. It performs no I/O.
func BuildDrafts(in DraftInputs) DraftReport {
	out := DraftReport{
		Drafts:        []Draft{},
		Uncertainties: append([]Uncertainty{}, in.Report.Uncertainties...),
		Conflicts:     append([]Conflict{}, in.Report.Conflicts...),
		Managed:       []ManagedObservation{},
		Scope:         in.Report.Scope,
		Complete:      in.Complete,
	}

	target, hasTarget := internalTarget(in.Profile)
	if !hasTarget {
		// Fail safe: without a declared internal target no host can be proposed. Every routable
		// host becomes a review item instead of an applicable draft.
		for _, r := range in.Report.Routes {
			if !site.ValidHostname(normalizeHost(r.Host)) {
				continue
			}
			out.Uncertainties = append(out.Uncertainties, Uncertainty{
				Namespace: r.Namespace, Ingress: r.Ingress, UID: r.UID, Host: r.Host,
				Reasons: []Reason{ReasonTargetUnresolved},
			})
		}
		out.Managed = managedObservations(in)
		slices.SortFunc(out.Uncertainties, compareUncertainty)
		return out
	}

	existingByHost := map[string]Draft{}
	for _, d := range in.Existing {
		if h := normalizeHost(d.Host); h != "" {
			existingByHost[h] = d
		}
	}
	managedHost := map[string]bool{}
	for _, m := range in.Managed {
		for _, h := range m.Hosts {
			managedHost[normalizeHost(h)] = true
		}
	}

	type evidence struct {
		routes  []Route
		reasons []Reason
	}
	evidenceByHost := map[string]*evidence{}
	var order []string
	add := func(h string) *evidence {
		e := evidenceByHost[h]
		if e == nil {
			e = &evidence{}
			evidenceByHost[h] = e
			order = append(order, h)
		}
		return e
	}

	// Internal route evidence. Public-bound routes are out of scope (R3 B-04).
	for _, r := range in.Report.Routes {
		if !isInternal(r.Listener, in.Profile) {
			continue
		}
		h := normalizeHost(r.Host)
		if !site.ValidHostname(h) {
			out.Uncertainties = append(out.Uncertainties, Uncertainty{
				Namespace: r.Namespace, Ingress: r.Ingress, UID: r.UID, Host: r.Host,
				Reasons: []Reason{ReasonInvalidHost},
			})
			continue
		}
		e := add(h)
		e.routes = append(e.routes, r)
	}

	// Host-scoped review reasons from the route interpretation.
	for _, u := range in.Report.Uncertainties {
		if u.Host == "" || strings.Contains(u.Host, "*") {
			continue // Ingress-wide and wildcard ones are applied to every host they could cover below
		}
		h := normalizeHost(u.Host)
		if !site.ValidHostname(h) {
			continue
		}
		add(h).reasons = append(add(h).reasons, u.Reasons...)
	}

	// Conflicts are keyed by host so the draft can carry the review request. Only internal conflicts
	// make a draft: a host with public-bound evidence only is out of scope (R3 B-04).
	conflictByHost := map[string][]Route{}
	for _, c := range in.Report.Conflicts {
		h := normalizeHost(c.Host)
		if !site.ValidHostname(h) || len(c.Candidates) == 0 || !isInternal(c.Candidates[0].Listener, in.Profile) {
			continue
		}
		conflictByHost[h] = append(conflictByHost[h], c.Candidates...)
		add(h)
	}

	// An Ingress-wide, wildcard or catch-all uncertainty could concern any host it covers: that host
	// needs review too (B-M-3).
	for _, u := range in.Report.Uncertainties {
		if u.Host != "" && !strings.Contains(u.Host, "*") {
			continue
		}
		for _, h := range order {
			if u.covers(h) {
				evidenceByHost[h].reasons = append(evidenceByHost[h].reasons, u.Reasons...)
			}
		}
	}

	for _, h := range order {
		if managedHost[h] {
			continue // an applied host is observed, never re-drafted
		}
		e := evidenceByHost[h]
		d := Draft{
			Host: h, Target: target, Cert: CertAuto,
			AccessChoice: "", Roles: []string{},
			Routes: mergeRoutes(nil, e.routes),
		}
		if ex, ok := existingByHost[h]; ok {
			d.AccessChoice = ex.AccessChoice
			d.Roles = normalizeRoles(ex.Roles)
			d.Note = ex.Note
			d.Routes = mergeRoutes(ex.Routes, e.routes)
			if ex.ReviewState == ReviewStateResolved {
				d.ReviewState = ReviewStateResolved
			}
		}
		for _, reason := range e.reasons {
			d.ReviewState = ReviewStateNeeded
			d.ReviewReason = joinReasons(d.ReviewReason, reason)
		}
		if candidates, ok := conflictByHost[h]; ok {
			d.ReviewState = ReviewStateNeeded
			d.ReviewReason = joinReasons(d.ReviewReason, ReasonRouteConflict)
			d.ReviewCandidates = candidateLabels(candidates)
			d.ReviewDefault = "" // no proven controller winner in the first profile
		}
		out.Drafts = append(out.Drafts, d)
	}

	slices.SortFunc(out.Drafts, func(a, b Draft) int { return cmp.Compare(a.Host, b.Host) })
	slices.SortFunc(out.Uncertainties, compareUncertainty)
	out.Managed = managedObservations(in)
	return out
}

// internalTarget is the Caddy -> internal ingress target of the profile: the first declared internal
// listener. It is deliberately not a Service/ClusterIP/PodIP URL, and never a public listener.
func internalTarget(p Profile) (string, bool) {
	if len(p.Internal) == 0 {
		return "", false
	}
	l := p.Internal[0]
	return "https://" + net.JoinHostPort(l.Address, strconv.Itoa(l.Port)), true
}

// normalizeHost lower-cases a host and drops a trailing dot, so the host identity is unique (AC7).
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// normalizeRoles de-duplicates and sorts a selected role list; blank entries are dropped.
func normalizeRoles(roles []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// mergeRoutes unions two route evidence lists by route identity, deterministically ordered.
func mergeRoutes(a, b []Route) []Route {
	seen := map[string]bool{}
	out := []Route{}
	for _, r := range slices.Concat(a, b) {
		k := routeKey(r)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	slices.SortFunc(out, compareRoute)
	return out
}

// joinReasons appends a reason label to a comma-joined list without duplicates.
func joinReasons(existing string, add Reason) string {
	if existing == "" {
		return string(add)
	}
	if slices.Contains(strings.Split(existing, ","), string(add)) {
		return existing
	}
	return existing + "," + string(add)
}

// candidateLabels is the sorted, human-readable list of the conflicting route candidates.
func candidateLabels(candidates []Route) []string {
	labels := make([]string, 0, len(candidates))
	for _, r := range candidates {
		labels = append(labels, candidateLabel(r))
	}
	slices.Sort(labels)
	return labels
}

func candidateLabel(r Route) string {
	port := r.Backend.PortName
	if port == "" {
		port = strconv.Itoa(r.Backend.PortNumber)
	}
	return fmt.Sprintf("%s/%s %s%s -> %s:%s", r.Namespace, r.Ingress, r.Host, r.Path, r.Backend.Service, port)
}

// managedObservations reports how every applied site's hosts relate to the observed routes, without
// proposing a change. An incomplete read yields unknown, never absence (AC5).
func managedObservations(in DraftInputs) []ManagedObservation {
	conflicted := map[string]bool{}
	for _, c := range in.Report.Conflicts {
		if len(c.Candidates) > 0 && isInternal(c.Candidates[0].Listener, in.Profile) {
			conflicted[normalizeHost(c.Host)] = true
		}
	}
	out := make([]ManagedObservation, 0, len(in.Managed))
	for _, m := range in.Managed {
		obs := ManagedObservation{
			SiteID: m.ID, Hosts: slices.Clone(m.Hosts),
			AccessChoice: m.AccessChoice, Roles: slices.Clone(m.Roles),
		}
		switch {
		case !in.Complete:
			obs.Status = ManagedUnknown
		case slices.ContainsFunc(m.Hosts, func(h string) bool { return conflicted[normalizeHost(h)] }):
			obs.Status = ManagedConflict
		default:
			keys := routeKeysForHosts(in.Report.Routes, m.Hosts)
			switch {
			case len(keys) == 0 && m.System:
				obs.Status = ManagedSystem
			case len(keys) == 0:
				obs.Status = ManagedNoRoute
			case len(m.RouteKeys) > 0 && !sameStrings(keys, m.RouteKeys):
				obs.Status = ManagedChanged
			default:
				obs.Status = ManagedMatched
			}
		}
		out = append(out, obs)
	}
	return out
}

// routeKeysForHosts is the sorted route identity set of the given hosts.
func routeKeysForHosts(routes []Route, hosts []string) []string {
	want := map[string]bool{}
	for _, h := range hosts {
		want[normalizeHost(h)] = true
	}
	keys := []string{}
	for _, r := range routes {
		if want[normalizeHost(r.Host)] {
			keys = append(keys, routeKey(r))
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

// sameStrings compares two string sets regardless of order.
func sameStrings(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
