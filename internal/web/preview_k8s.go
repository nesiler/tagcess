package web

import (
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/k8s"
)

func init() {
	previewPages = append(previewPages,
		previewPage{"/k8s/discovery", "k8s/discovery", "k8s discovery", func(r *http.Request) templ.Component {
			return K8sDiscoveryPage(previewK8sDiscovery(r.URL.Query().Get("state")), previewCSRF)
		}},
		previewPage{"/k8s/drafts/app.example.com", "k8s/discovery", "k8s draft'ı", func(r *http.Request) templ.Component {
			return K8sDraftPage(previewK8sDraft(r.URL.Query().Get("state")), previewCSRF)
		}},
	)
}

// previewK8sSnapshot uses fixed synthetic data; no cluster or credential is read.
func previewK8sSnapshot() *k8s.Snapshot {
	return &k8s.Snapshot{ID: 12, Scope: "apps,web", ProfileVersion: "preview-profile-v2",
		ObservedAt: time.Date(2026, 10, 5, 17, 44, 30, 0, time.UTC)}
}

func previewK8sRoute(service string) k8s.Route {
	return k8s.Route{
		Namespace: "apps", Ingress: "app", UID: "preview-ingress-1", Host: "app.example.com",
		Path: "/", PathType: k8s.PathPrefix, Backend: k8s.Backend{Service: service, PortNumber: 8080},
		Listener: k8s.Listener{Address: "100.64.0.5", Port: 443}, Basis: k8s.BasisDeclaredProfile,
	}
}

func previewK8sDiscovery(state string) K8sDiscoveryView {
	snapshot := previewK8sSnapshot()
	route := previewK8sRoute("app")
	reviewRoute, reviewNext := previewK8sRoute("app"), previewK8sRoute("app-next")
	reviewRoute.Host, reviewNext.Host = "review.example.com", "review.example.com"
	v := K8sDiscoveryView{
		Complete: true, PublicChecked: true, Scope: k8s.FirstProfileScope(),
		Freshness: K8sFreshnessView{Current: snapshot, LastAttempt: &k8s.Attempt{
			AttemptedAt: snapshot.ObservedAt, Outcome: k8s.OutcomeOK, SnapshotID: snapshot.ID}},
		Candidates: []K8sCandidateView{
			{Host: route.Host, Target: "https://100.64.0.5:443", Cert: "auto", Routes: []k8s.Route{route}},
			{Host: "review.example.com", Cert: "auto", ReviewState: k8s.ReviewStateNeeded,
				ReviewReason: string(k8s.ReasonRouteConflict), ReviewCandidates: []string{"app:8080", "app-next:8080"}},
		},
		Managed: []K8sManagedView{
			{SiteID: 1, Hosts: []string{"git.example.com"}, Status: k8s.ManagedMatched, AccessChoice: k8s.AccessChoiceRole, Roles: []string{"devops", "yazilim"}},
			{SiteID: 2, Hosts: []string{"old.example.com"}, Status: k8s.ManagedNoRoute, AccessChoice: k8s.AccessChoiceOpen},
		},
		Uncertainties: []k8s.Uncertainty{{Namespace: "web", Ingress: "legacy", UID: "preview-ingress-2",
			Host: "legacy.example.com", Path: "/", Reasons: []k8s.Reason{k8s.ReasonEntryPointUnresolved}}},
		Conflicts: []k8s.Conflict{{Namespace: route.Namespace, Ingress: route.Ingress, UID: route.UID,
			Host: reviewRoute.Host, Candidates: []k8s.Route{reviewRoute, reviewNext}}},
	}
	switch state {
	case "empty":
		v.Candidates, v.Managed, v.Uncertainties, v.Conflicts = nil, nil, nil, nil
	case "error":
		return K8sDiscoveryView{Error: "discovery verisi okunamadı; gösterilen erişim/okuma durumu değişmedi"}
	case "setup":
		return K8sDiscoveryView{NotSetUp: true}
	case "stale", "previous":
		v.Complete, v.Freshness.Stale = false, true
		v.Freshness.LastAttempt = &k8s.Attempt{AttemptedAt: snapshot.ObservedAt.Add(5 * time.Minute),
			Outcome: k8s.OutcomeFailed, Class: "unreachable", Message: "k8s API bağlantısı zaman aşımına uğradı"}
		for i := range v.Managed {
			v.Managed[i].Status = k8s.ManagedUnknown
		}
		if state == "previous" {
			v.Freshness.Previous, v.Freshness.Current = snapshot, nil
		}
	}
	return v
}

func previewK8sDraft(state string) K8sDraftView {
	snapshot := previewK8sSnapshot()
	v := K8sDraftView{
		Host: "app.example.com", Saved: true, Source: "current", Current: snapshot,
		Provenance: k8s.Provenance{SnapshotID: snapshot.ID, ProfileVersion: snapshot.ProfileVersion, ObservedAt: snapshot.ObservedAt},
		Draft: k8s.Draft{Host: "app.example.com", Target: "https://100.64.0.5:443", Cert: "auto",
			AccessChoice: k8s.AccessChoiceRole, Roles: []string{"devops", "yazilim"}, Note: "k8s discovery'den",
			Routes: []k8s.Route{previewK8sRoute("app")}},
		LastAttempt: &k8s.Attempt{AttemptedAt: snapshot.ObservedAt, Outcome: k8s.OutcomeOK, SnapshotID: snapshot.ID},
	}
	switch state {
	case "new":
		v.Saved, v.Draft.AccessChoice, v.Draft.Roles = false, "", nil
	case "empty":
		v.Saved, v.Source, v.Current, v.LastAttempt = false, "unknown", nil, nil
		v.Draft = k8s.Draft{Host: v.Host}
	case "error":
		v.Source, v.Current, v.LastAttempt = "unknown", nil, nil
		v.Error = "güncel discovery okunamadı; kayıtlı draft ve seçimler korundu"
	case "stale":
		v.Source = "stale"
		v.StaleReason = []string{"draft daha eski bir taramadan hazırlandı"}
		v.Provenance.SnapshotID = 11
		v.Provenance.ObservedAt = snapshot.ObservedAt.Add(-time.Hour)
		v.Diff = k8s.RouteDiff{Added: []k8s.Route{previewK8sRoute("app-next")}, Removed: v.Draft.Routes}
	case "review":
		v.Draft.ReviewState, v.Draft.ReviewReason = k8s.ReviewStateNeeded, string(k8s.ReasonRouteConflict)
		v.Draft.Target, v.Draft.ReviewCandidates = "", []string{"app:8080", "app-next:8080"}
	}
	v.Complete = v.Draft.Complete()
	return v
}
