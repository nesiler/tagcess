package k8s

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// This file interprets the standard Ingress/Service objects of one complete snapshot (F4-007) against
// the first declared Traefik profile (F4-002). It never contacts a cluster and never runs a controller:
// a Route is derived from declared metadata, so it is evidence of what is configured, never of what
// the network actually serves. Wrong, missing or ambiguous metadata produces an uncertainty that
// requires UI review (R3 B-04/B-05, ADR 0030/0031). The first profile reads no runtime winner, so an
// overlapping conflict keeps every candidate and chooses no default.

// Basis says where a route comes from. The first profile only ever declares routes from the profile's
// own metadata; it holds no proof that the route is reachable, so there is deliberately no other value.
type Basis string

// BasisDeclaredProfile is a route built from Ingress metadata and the declared profile listeners.
const BasisDeclaredProfile Basis = "declared_profile"

// PathType is the match type the route was created with.
type PathType string

// The path types the first profile can bind. ImplementationSpecific is not one of them: it is left to
// the controller and therefore uncertain.
const (
	PathExact  PathType = "Exact"
	PathPrefix PathType = "Prefix"
)

// Backend is the Service a path points at, with the port as named or numeric. Namespace, UID, host,
// path and backend are the provenance of a route.
type Backend struct {
	Service    string
	PortName   string
	PortNumber int
}

// Route is one standard Ingress path bound to a declared profile listener. Listener is the entry the
// path maps to through its Traefik entryPoint annotation.
type Route struct {
	Namespace string
	Ingress   string
	UID       string
	Host      string
	Path      string
	PathType  PathType
	Backend   Backend
	Listener  Listener
	Basis     Basis
}

// Reason is why a route was not turned into an applicable Route.
type Reason string

// The uncertainty reasons of the first profile. Class/default-class contradictions and a different
// controller mean the profile cannot claim the route; an unresolvable entryPoint means the listener is
// unknown; the rest are object shapes the first profile refuses to map automatically.
const (
	ReasonClassAmbiguous         Reason = "class_ambiguous"
	ReasonClassUnknown           Reason = "class_not_in_profile"
	ReasonControllerMismatch     Reason = "controller_mismatch"
	ReasonEntryPointUnresolved   Reason = "entry_point_unresolved"
	ReasonWildcardHost           Reason = "wildcard_host"
	ReasonEmptyHost              Reason = "empty_host"
	ReasonResourceBackend        Reason = "resource_backend"
	ReasonBackendUnresolved      Reason = "backend_unresolved"
	ReasonDefaultBackend         Reason = "default_backend"
	ReasonImplementationSpecific Reason = "implementation_specific_path"
)

// Uncertainty is an Ingress, host or path that needs UI review before it can become a route. Host and
// Path are empty when the reason applies to the whole Ingress.
type Uncertainty struct {
	Namespace string
	Ingress   string
	UID       string
	Host      string
	Path      string
	Reasons   []Reason
	// Hosts is, for an Ingress-wide uncertainty (Host empty), every non-empty host the Ingress
	// declares: the hosts it could concern.
	Hosts []string
}

// covers reports whether the uncertainty could concern host: a host-level one names it (a
// single-label wildcard covers every host one label below it), an Ingress-wide one covers the hosts
// the Ingress declares, and an empty-host or default-backend one is a catch-all that covers every host.
func (u Uncertainty) covers(host string) bool {
	if u.Host != "" {
		return hostMatches(u.Host, host)
	}
	if slices.ContainsFunc(u.Reasons, func(r Reason) bool { return r == ReasonEmptyHost || r == ReasonDefaultBackend }) {
		return true
	}
	return slices.ContainsFunc(u.Hosts, func(h string) bool { return hostMatches(h, host) })
}

// hostMatches compares a host pattern with a host: exact, or "*.zone" matching exactly one label.
func hostMatches(pattern, host string) bool {
	pattern, host = normalizeHost(pattern), normalizeHost(host)
	if zone, ok := strings.CutPrefix(pattern, "*."); ok {
		label, tail, found := strings.Cut(host, ".")
		return found && label != "" && tail == zone
	}
	return pattern == host
}

// Conflict is a group of routes under one ingress/host that overlap but point at different backends.
// The first profile reads no controller winner, so Default is always nil; every candidate is kept and
// the UI asks for review.
type Conflict struct {
	Namespace  string
	Ingress    string
	UID        string
	Host       string
	Candidates []Route
	Default    *Route
}

// ScopeItem names one resource class the scan does or does not read.
type ScopeItem string

// What the first profile reads and, explicitly, what it does not.
const (
	ScannedIngress      ScopeItem = "networking.k8s.io/v1/ingresses"
	ScannedService      ScopeItem = "core/v1/services"
	ScannedIngressClass ScopeItem = "networking.k8s.io/v1/ingressclasses"

	UnscannedGatewayAPI      ScopeItem = "gateway.networking.k8s.io"
	UnscannedTraefikCRD      ScopeItem = "traefik.io CRDs"
	UnscannedOtherController ScopeItem = "other controllers"
	UnscannedOtherPaths      ScopeItem = "hostNetwork and other non-Ingress paths"
)

// Scope describes what a scan covers. Conclusive is always false: absence of a route is not proof that
// access is closed, because CRDs, Gateways, other controllers and other paths are not scanned.
type Scope struct {
	Scanned    []ScopeItem
	Unscanned  []ScopeItem
	Conclusive bool
}

// FirstProfileScope is the fixed scan scope of the first Traefik profile.
func FirstProfileScope() Scope {
	return Scope{
		Scanned:    []ScopeItem{ScannedIngress, ScannedService, ScannedIngressClass},
		Unscanned:  []ScopeItem{UnscannedGatewayAPI, UnscannedTraefikCRD, UnscannedOtherController, UnscannedOtherPaths},
		Conclusive: false,
	}
}

// RouteReport is the interpretation of one snapshot against the profile.
type RouteReport struct {
	Routes        []Route
	Uncertainties []Uncertainty
	Conflicts     []Conflict
	Scope         Scope
}

// InterpretRoutes binds the standard Ingress paths of inv to the listeners declared by p. It performs
// no I/O. Every returned Route carries BasisDeclaredProfile; anything the profile cannot bind is an
// Uncertainty, and overlapping routes with mismatching backends become a Conflict with no default.
func InterpretRoutes(inv Inventory, p Profile) RouteReport {
	rep := RouteReport{
		Routes:        []Route{},
		Uncertainties: []Uncertainty{},
		Conflicts:     []Conflict{},
		Scope:         FirstProfileScope(),
	}

	classes := make(map[string]IngressClass, len(inv.IngressClasses))
	for _, c := range inv.IngressClasses {
		classes[c.Metadata.Name] = c
	}
	var defaults []string
	for _, c := range inv.IngressClasses {
		if c.Metadata.Annotations["ingressclass.kubernetes.io/is-default-class"] == "true" {
			defaults = append(defaults, c.Metadata.Name)
		}
	}
	slices.Sort(defaults)

	for _, ing := range inv.Ingresses {
		class, reason := resolveIngressClass(ing, p, classes, defaults)
		if reason != "" {
			rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, "", "", reason))
			continue
		}
		if classes[class].Spec.Controller != p.Controller {
			rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, "", "", ReasonControllerMismatch))
			continue
		}
		// The default backend is a catch-all the profile refuses to map automatically; it also makes
		// the whole Ingress ambiguous, so no route is claimed from it.
		if ing.Spec.DefaultBackend != nil {
			rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, "", "", ReasonDefaultBackend))
			continue
		}
		listeners, reason := resolveEntryPoints(ing, p)
		if reason != "" {
			rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, "", "", reason))
			continue
		}

		for _, rule := range ing.Spec.Rules {
			switch {
			case rule.Host == "":
				rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, "", "", ReasonEmptyHost))
				continue
			case strings.Contains(rule.Host, "*"):
				rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, rule.Host, "", ReasonWildcardHost))
				continue
			case rule.HTTP == nil:
				continue
			}
			for _, hp := range rule.HTTP.Paths {
				pathType, reason := resolvePathType(hp.PathType)
				if reason != "" {
					rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, rule.Host, hp.Path, reason))
					continue
				}
				backend, reason := resolveBackend(hp.Backend)
				if reason != "" {
					rep.Uncertainties = append(rep.Uncertainties, uncertainty(ing, rule.Host, hp.Path, reason))
					continue
				}
				for _, l := range listeners {
					rep.Routes = append(rep.Routes, Route{
						Namespace: ing.Metadata.Namespace, Ingress: ing.Metadata.Name, UID: ing.Metadata.UID,
						Host: rule.Host, Path: hp.Path, PathType: pathType, Backend: backend,
						Listener: l, Basis: BasisDeclaredProfile,
					})
				}
			}
		}
	}

	rep.Conflicts = findConflicts(rep.Routes)
	slices.SortFunc(rep.Routes, compareRoute)
	slices.SortFunc(rep.Uncertainties, compareUncertainty)
	slices.SortFunc(rep.Conflicts, compareConflict)
	return rep
}

func uncertainty(ing Ingress, host, path string, reason Reason) Uncertainty {
	u := Uncertainty{
		Namespace: ing.Metadata.Namespace, Ingress: ing.Metadata.Name, UID: ing.Metadata.UID,
		Host: host, Path: path, Reasons: []Reason{reason},
	}
	if host == "" {
		for _, rule := range ing.Spec.Rules {
			if rule.Host != "" && !slices.Contains(u.Hosts, rule.Host) {
				u.Hosts = append(u.Hosts, rule.Host)
			}
		}
		slices.Sort(u.Hosts)
	}
	return u
}

// resolveIngressClass returns the class the Ingress is served by, or the reason it cannot be decided.
// An explicit spec.ingressClassName and the legacy annotation must agree; without either, exactly one
// default class is required. The class must be one the profile covers and must be present in the
// snapshot so its controller can be checked.
func resolveIngressClass(ing Ingress, p Profile, classes map[string]IngressClass, defaults []string) (string, Reason) {
	annotation := ing.Metadata.Annotations["kubernetes.io/ingress.class"]
	spec := ing.Spec.IngressClassName
	if annotation != "" && spec != "" && annotation != spec {
		return "", ReasonClassAmbiguous
	}
	class := spec
	if class == "" {
		class = annotation
	}
	if class == "" {
		if len(defaults) != 1 {
			return "", ReasonClassAmbiguous
		}
		class = defaults[0]
	}
	if !slices.Contains(p.IngressClasses, class) {
		return "", ReasonClassUnknown
	}
	if _, ok := classes[class]; !ok {
		// The profile covers the class name but the snapshot has no such IngressClass, so its
		// controller is unknown.
		return "", ReasonControllerMismatch
	}
	return class, ""
}

// resolveEntryPoints maps the Traefik entryPoint annotation to declared listeners. Every named
// entryPoint must resolve; an Ingress that names none relies on a controller default the profile does
// not declare, so it is uncertain too.
func resolveEntryPoints(ing Ingress, p Profile) ([]Listener, Reason) {
	raw := strings.TrimSpace(ing.Metadata.Annotations["traefik.ingress.kubernetes.io/router.entrypoints"])
	if raw == "" {
		return nil, ReasonEntryPointUnresolved
	}
	declared := slices.Concat(p.Internal, p.Public)
	var out []Listener
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		idx := slices.IndexFunc(declared, func(l Listener) bool { return l.EntryPoint == name })
		if idx < 0 {
			return nil, ReasonEntryPointUnresolved
		}
		out = append(out, declared[idx])
	}
	if len(out) == 0 {
		return nil, ReasonEntryPointUnresolved
	}
	return out, ""
}

func resolvePathType(s string) (PathType, Reason) {
	switch s {
	case string(PathExact):
		return PathExact, ""
	case string(PathPrefix):
		return PathPrefix, ""
	default:
		return "", ReasonImplementationSpecific
	}
}

func resolveBackend(b IngressBackend) (Backend, Reason) {
	switch {
	case b.Resource != nil:
		return Backend{}, ReasonResourceBackend
	case b.Service == nil:
		return Backend{}, ReasonBackendUnresolved
	default:
		return Backend{Service: b.Service.Name, PortName: b.Service.Port.Name, PortNumber: b.Service.Port.Number}, ""
	}
}

// findConflicts groups routes by listener and normalized host across every Ingress and namespace and
// reports every route that overlaps another route of the group with a different {namespace, backend}.
// A different listener or host is never a conflict here. [Ö] Nested Prefix paths are still reported:
// that fails safe (review noise), not open.
func findConflicts(routes []Route) []Conflict {
	type groupKey struct {
		listener Listener
		host     string
	}
	groups := map[groupKey][]Route{}
	var order []groupKey
	for _, r := range routes {
		k := groupKey{r.Listener, normalizeHost(r.Host)}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}

	var out []Conflict
	for _, k := range order {
		group := groups[k]
		involved := map[string]Route{}
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				if sameBackend(group[i], group[j]) || !pathsOverlap(group[i], group[j]) {
					continue
				}
				involved[routeKey(group[i])] = group[i]
				involved[routeKey(group[j])] = group[j]
			}
		}
		if len(involved) == 0 {
			continue
		}
		candidates := make([]Route, 0, len(involved))
		for _, r := range involved {
			candidates = append(candidates, r)
		}
		slices.SortFunc(candidates, compareRoute)
		first := candidates[0]
		out = append(out, Conflict{
			Namespace: first.Namespace, Ingress: first.Ingress, UID: first.UID, Host: k.host,
			Candidates: candidates, Default: nil,
		})
	}
	return out
}

// sameBackend compares {namespace, service, port}: a Service name in another namespace is another backend.
func sameBackend(a, b Route) bool { return a.Namespace == b.Namespace && a.Backend == b.Backend }

// pathsOverlap reports whether two routes of the same listener and host can match the same request
// path. Exact matches only an identical path; Prefix matches element-wise, so /a does not overlap /ab
// but does overlap /a/b and /.
func pathsOverlap(a, b Route) bool {
	switch {
	case a.PathType == PathExact && b.PathType == PathExact:
		return cleanPath(a.Path) == cleanPath(b.Path)
	case a.PathType == PathPrefix && b.PathType == PathPrefix:
		return prefixMatches(a.Path, b.Path) || prefixMatches(b.Path, a.Path)
	case a.PathType == PathExact && b.PathType == PathPrefix:
		return prefixMatches(b.Path, a.Path)
	case a.PathType == PathPrefix && b.PathType == PathExact:
		return prefixMatches(a.Path, b.Path)
	}
	return false
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	return strings.TrimSuffix(p, "/")
}

// prefixMatches reports whether the Prefix pattern matches the exact path at a path-element boundary.
func prefixMatches(prefix, path string) bool {
	prefix, path = cleanPath(prefix), cleanPath(path)
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	return rest == "" || strings.HasPrefix(rest, "/")
}

func routeKey(r Route) string {
	return strings.Join([]string{
		r.Namespace, r.Ingress, r.UID, r.Host, r.Path, string(r.PathType),
		r.Backend.Service, r.Backend.PortName, strconv.Itoa(r.Backend.PortNumber),
		r.Listener.Address, strconv.Itoa(r.Listener.Port), r.Listener.EntryPoint,
	}, "\x00")
}

func compareRoute(a, b Route) int {
	return cmp.Or(
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Ingress, b.Ingress),
		cmp.Compare(a.UID, b.UID),
		cmp.Compare(a.Host, b.Host),
		cmp.Compare(a.Path, b.Path),
		cmp.Compare(string(a.PathType), string(b.PathType)),
		cmp.Compare(a.Backend.Service, b.Backend.Service),
		cmp.Compare(a.Backend.PortName, b.Backend.PortName),
		cmp.Compare(a.Backend.PortNumber, b.Backend.PortNumber),
		cmp.Compare(a.Listener.Address, b.Listener.Address),
		cmp.Compare(a.Listener.Port, b.Listener.Port),
		cmp.Compare(a.Listener.EntryPoint, b.Listener.EntryPoint),
	)
}

func compareUncertainty(a, b Uncertainty) int {
	return cmp.Or(
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Ingress, b.Ingress),
		cmp.Compare(a.UID, b.UID),
		cmp.Compare(a.Host, b.Host),
		cmp.Compare(a.Path, b.Path),
	)
}

func compareConflict(a, b Conflict) int {
	return cmp.Or(
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Ingress, b.Ingress),
		cmp.Compare(a.UID, b.UID),
		cmp.Compare(a.Host, b.Host),
	)
}
