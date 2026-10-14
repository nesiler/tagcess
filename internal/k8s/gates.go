package k8s

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// This file turns one complete snapshot into two-gate candidates (F4-020, K-03, R3 B-05, ADR 0031):
// for each managed host, the routes that are bound to an entrypoint other than the declared internal
// one, and the Service exposure paths (LoadBalancer, NodePort, externalIPs) of the route's backend.
// A candidate is declared configuration only. It never says the path is reachable (Reachability is
// always "not measured"; a network measurement is a separate observation in internal/health), the
// expected Caddy to internal proxy, an intentional open site and an API exemption are named next to
// it without clearing it, and anything the profile cannot judge stays unknown. The evaluation is a
// pure function: it reads its input, writes nothing and never contacts a cluster.

// GateKind says which alternative path a candidate is.
type GateKind string

// The candidate kinds of the first Traefik profile. GateUnresolved is a path that could not be
// judged (an Ingress the profile cannot interpret, a backend Service that is missing).
const (
	GateWrongEntryPoint GateKind = "wrong_entrypoint"
	GateLoadBalancer    GateKind = "service_load_balancer"
	GateNodePort        GateKind = "service_node_port"
	GateExternalIP      GateKind = "service_external_ip"
	GateUnresolved      GateKind = "unresolved"
)

// GateStatus separates a configured alternative path from one the evidence cannot settle.
type GateStatus string

const (
	GateStatusCandidate GateStatus = "candidate"
	GateStatusUnknown   GateStatus = "unknown"
)

// GateContext names an expected reason for a path to exist. It explains the candidate and never
// removes it: the alternative path risk stays.
type GateContext string

const (
	ContextCaddyProxy      GateContext = "expected_caddy_proxy" // the host also has the internal route Caddy proxies to
	ContextIntentionalOpen GateContext = "intentional_open"     // the site is an intentionally open site
	ContextAPIExemption    GateContext = "api_exemption"        // the site carries an R1 API exemption
)

// Why a candidate is unknown, next to the route reasons of routes.go (Uncertainty.Reasons).
const (
	ReasonProfileIncomplete     Reason = "profile_incomplete" // no declared internal listener to compare with
	ReasonRouteConflict         Reason = "route_conflict"     // overlapping routes with different backends
	ReasonServiceNotInSnapshot  Reason = "service_not_in_snapshot"
	ReasonServicePortUnresolved Reason = "service_port_unresolved"
)

// Reachability is what the candidate says about network access: nothing. It is declared metadata.
type Reachability string

const ReachabilityNotMeasured Reachability = "not_measured"

// ManagedHost is one managed site host and what is expected of it. The caller fills it from the
// site records.
type ManagedHost struct {
	Site            string
	Host            string
	IntentionalOpen bool
	APIExemption    bool
}

// GateInput is what one evaluation reads. NodeAddresses are the approved profile targets of the
// NodePort paths (Nodes are not read).
type GateInput struct {
	Inventory     Inventory
	Profile       Profile
	Hosts         []ManagedHost
	NodeAddresses []string
}

// GateCandidate is one alternative path of a managed host, with the route and source it comes from.
// Address is empty when the declared path has no address to measure (a pending load balancer, a
// NodePort without approved node addresses).
type GateCandidate struct {
	Site     string
	Host     string
	Path     string
	PathType PathType
	Kind     GateKind
	Status   GateStatus
	Reasons  []Reason
	Context  []GateContext

	Namespace string
	Ingress   string
	UID       string
	Backend   Backend

	Address    string
	Port       int
	EntryPoint string
	TLS        bool

	Reachability Reachability
	Basis        Basis
}

// RouteKey names the declared route behind the candidate (kind, Ingress and backend), for a
// measurement key. Address, port and path are separate key parts.
func (c GateCandidate) RouteKey() string {
	return strings.Join([]string{string(c.Kind), c.Namespace + "/" + c.Ingress, c.Backend.Service + ":" + backendPort(c.Backend)}, "|")
}

func backendPort(b Backend) string {
	if b.PortName != "" {
		return b.PortName
	}
	return strconv.Itoa(b.PortNumber)
}

// GateReport is the candidates and the scan scope they were found under. The scope is never
// conclusive: zero candidates is not a safe result.
type GateReport struct {
	Candidates []GateCandidate
	Scope      Scope
	// PublicChecked is false when the profile declares no public listener: the internet-exposure
	// check was not performed and the report holds no candidates (F5 I3).
	PublicChecked bool
}

// UnscannedLabels is the short label of every unscanned path, for the observation's scope column.
func (s Scope) UnscannedLabels() []string {
	labels := make([]string, 0, len(s.Unscanned))
	for _, item := range s.Unscanned {
		switch item {
		case UnscannedGatewayAPI:
			labels = append(labels, "gateway")
		case UnscannedTraefikCRD:
			labels = append(labels, "crd")
		case UnscannedOtherController:
			labels = append(labels, "other_controller")
		case UnscannedOtherPaths:
			labels = append(labels, "hostnetwork")
		default:
			labels = append(labels, string(item))
		}
	}
	return labels
}

// EvaluateGates builds the candidates of the managed hosts from the snapshot and the profile.
func EvaluateGates(in GateInput) GateReport {
	rep := InterpretRoutes(in.Inventory, in.Profile)
	out := GateReport{Candidates: []GateCandidate{}, Scope: rep.Scope, PublicChecked: len(in.Profile.Public) > 0}
	if !out.PublicChecked {
		return out
	}

	services := make(map[string]Service, len(in.Inventory.Services))
	for _, s := range in.Inventory.Services {
		services[s.Metadata.Namespace+"/"+s.Metadata.Name] = s
	}
	conflicted := map[string]bool{}
	for _, c := range rep.Conflicts {
		for _, r := range c.Candidates {
			conflicted[routeKey(r)] = true
		}
	}
	incomplete := len(in.Profile.Internal) == 0

	seen := map[string]bool{}
	add := func(c GateCandidate) {
		key := strings.Join([]string{string(c.Kind), c.Site, c.Namespace, c.Ingress, c.UID, c.Host, c.Path, c.Backend.Service,
			c.Address, strconv.Itoa(c.Port), c.EntryPoint, strings.Join(reasonStrings(c.Reasons), ",")}, "\x00")
		if !seen[key] {
			seen[key] = true
			out.Candidates = append(out.Candidates, c)
		}
	}

	for _, h := range in.Hosts {
		routes := slices.DeleteFunc(slices.Clone(rep.Routes), func(r Route) bool { return !strings.EqualFold(r.Host, h.Host) })
		wrongEntryPoint := func(base GateCandidate, r Route, conflict bool) {
			c := base
			c.Kind, c.Address, c.Port, c.EntryPoint, c.TLS = GateWrongEntryPoint, r.Listener.Address, r.Listener.Port, r.Listener.EntryPoint, r.Listener.Port == 443
			switch {
			case incomplete:
				c.Status, c.Reasons = GateStatusUnknown, []Reason{ReasonProfileIncomplete}
			case conflict:
				c.Status, c.Reasons = GateStatusUnknown, []Reason{ReasonRouteConflict}
			}
			add(c)
		}
		newBase := func(r Route, routes []Route) GateCandidate {
			return GateCandidate{
				Site: h.Site, Host: r.Host, Path: r.Path, PathType: r.PathType, Status: GateStatusCandidate,
				Context:   contextsFor(h, r, routes, in.Profile),
				Namespace: r.Namespace, Ingress: r.Ingress, UID: r.UID, Backend: r.Backend,
				Reachability: ReachabilityNotMeasured, Basis: BasisDeclaredProfile,
			}
		}
		backends := map[string]bool{}
		for _, r := range routes {
			backends[r.Namespace+"/"+r.Backend.Service] = true
			base := newBase(r, routes)
			conflict := conflicted[routeKey(r)]

			if !isInternal(r.Listener, in.Profile) {
				wrongEntryPoint(base, r, conflict)
			}
			for _, c := range serviceCandidates(base, r, services, in.NodeAddresses) {
				if conflict && c.Status == GateStatusCandidate {
					c.Status, c.Reasons = GateStatusUnknown, []Reason{ReasonRouteConflict}
				}
				add(c)
			}
		}
		// A non-internal route of another host to the same backend is another way to it (R3 B-05).
		for _, r := range rep.Routes {
			if strings.EqualFold(r.Host, h.Host) || isInternal(r.Listener, in.Profile) || !backends[r.Namespace+"/"+r.Backend.Service] {
				continue
			}
			wrongEntryPoint(newBase(r, nil), r, conflicted[routeKey(r)])
		}
		for _, u := range rep.Uncertainties {
			if !u.covers(h.Host) {
				continue
			}
			add(GateCandidate{
				Site: h.Site, Host: h.Host, Path: u.Path, Kind: GateUnresolved, Status: GateStatusUnknown, Reasons: u.Reasons,
				Context:   hostContexts(h),
				Namespace: u.Namespace, Ingress: u.Ingress, UID: u.UID,
				Reachability: ReachabilityNotMeasured, Basis: BasisDeclaredProfile,
			})
		}
	}

	slices.SortFunc(out.Candidates, compareGate)
	return out
}

// serviceCandidates is the Service exposure of one route's backend: LoadBalancer addresses,
// NodePort on the approved node addresses and externalIPs. A backend that cannot be found or whose
// port does not resolve is one unknown candidate, never a clean result.
func serviceCandidates(base GateCandidate, r Route, services map[string]Service, nodes []string) []GateCandidate {
	unknown := func(reason Reason) []GateCandidate {
		c := base
		c.Kind, c.Status, c.Reasons = GateUnresolved, GateStatusUnknown, []Reason{reason}
		return []GateCandidate{c}
	}
	svc, ok := services[r.Namespace+"/"+r.Backend.Service]
	if !ok {
		return unknown(ReasonServiceNotInSnapshot)
	}
	idx := slices.IndexFunc(svc.Spec.Ports, func(p ServicePort) bool {
		return (r.Backend.PortName != "" && p.Name == r.Backend.PortName) || (r.Backend.PortName == "" && p.Port == r.Backend.PortNumber)
	})
	if idx < 0 {
		return unknown(ReasonServicePortUnresolved)
	}
	port := svc.Spec.Ports[idx]
	tls := port.Port == 443 || port.Name == "https"

	var out []GateCandidate
	with := func(kind GateKind, address string, number int) {
		c := base
		c.Kind, c.Address, c.Port, c.TLS = kind, address, number, tls
		out = append(out, c)
	}
	switch svc.Spec.Type {
	case "LoadBalancer":
		var addrs []string
		for _, lb := range svc.Status.LoadBalancer.Ingress {
			addrs = append(addrs, cmp.Or(lb.IP, lb.Hostname))
		}
		if len(addrs) == 0 {
			addrs = []string{""}
		}
		for _, a := range addrs {
			with(GateLoadBalancer, a, port.Port)
		}
	}
	// A LoadBalancer Service allocates a node port too.
	if (svc.Spec.Type == "NodePort" || svc.Spec.Type == "LoadBalancer") && port.NodePort > 0 {
		addrs := nodes
		if len(addrs) == 0 {
			addrs = []string{""}
		}
		for _, a := range addrs {
			with(GateNodePort, a, port.NodePort)
		}
	}
	for _, ip := range svc.Spec.ExternalIPs {
		with(GateExternalIP, ip, port.Port)
	}
	return out
}

func isInternal(l Listener, p Profile) bool { return slices.Contains(p.Internal, l) }

// contextsFor names the expected reasons for a path of host h: the internal route Caddy proxies to
// (the same backend on an internal listener) plus the site's own exceptions.
func contextsFor(h ManagedHost, r Route, routes []Route, p Profile) []GateContext {
	var out []GateContext
	if slices.ContainsFunc(routes, func(o Route) bool {
		return isInternal(o.Listener, p) && o.Namespace == r.Namespace && o.Backend == r.Backend
	}) {
		out = append(out, ContextCaddyProxy)
	}
	return append(out, hostContexts(h)...)
}

func hostContexts(h ManagedHost) []GateContext {
	var out []GateContext
	if h.IntentionalOpen {
		out = append(out, ContextIntentionalOpen)
	}
	if h.APIExemption {
		out = append(out, ContextAPIExemption)
	}
	return out
}

func reasonStrings(rs []Reason) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

func compareGate(a, b GateCandidate) int {
	return cmp.Or(
		cmp.Compare(a.Site, b.Site),
		cmp.Compare(a.Host, b.Host),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Ingress, b.Ingress),
		cmp.Compare(a.Path, b.Path),
		cmp.Compare(a.Address, b.Address),
		cmp.Compare(a.Port, b.Port),
		cmp.Compare(a.EntryPoint, b.EntryPoint),
	)
}
