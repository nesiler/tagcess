package web

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/k8s"
	caddyrender "github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
)

// The draft hand-off (F4-013): a complete k8s draft becomes an ordinary "add site" request for the
// existing site review pipeline (F2-014). There is no second render/apply path: preview, the fresh
// Zitadel role check, approval, rollback and result all belong to change.SitePipeline; this file only
// maps the draft to a change.SiteRequest and refuses drafts that are not ready.

// errDraftNotReady is returned for a draft that must not reach the pipeline.
var errDraftNotReady = errors.New("draft apply edilmeye hazır değil")

// draftSiteRequest maps a stored draft to the site add request. A review request that is still open
// or a missing target/cert/access choice stops here (the draft stays storable but never applies). The
// actor is set by the review handler from the signed-in operator, role existence is checked by the
// pipeline's validator on every preview and approval.
//
// upstream is the configured (k8s) snippet upstream (sites.k8s_upstream); empty means the renderer's default.
func draftSiteRequest(d k8s.Draft, upstream string) (change.SiteRequest, error) {
	if d.ReviewState == k8s.ReviewStateNeeded {
		return change.SiteRequest{}, fmt.Errorf("%w: route incelemesi tamamlanmadı", errDraftNotReady)
	}
	if !d.Complete() {
		return change.SiteRequest{}, fmt.Errorf("%w: hedef, sertifika veya erişim seçimi eksik", errDraftNotReady)
	}
	s := site.Site{
		Hosts: []string{d.Host}, Cert: d.Cert, TargetKind: site.TargetURL, TargetURL: d.Target, MagicDNS: true,
		Note:        d.Note,
		TargetRoles: []string{}, APIRules: []site.APIRule{}, Redirects: []site.Redirect{}, Headers: []site.Header{},
	}
	if d.AccessChoice == k8s.AccessChoiceRole {
		// Role sites render only through the vpn_site snippets, whose upstream is fixed (ADR 0010).
		// A draft is mapped to that target only when it already is that upstream; any other listener
		// is refused, never rewritten (R3: tagcess invents no target).
		if upstream == "" {
			upstream = caddyrender.K8sUpstream
		}
		if !sameHTTPSOrigin(d.Target, upstream) {
			return change.SiteRequest{}, fmt.Errorf("%w: rol siteleri yalnız %s upstream'i ile apply edilir, draft hedefi %s", errDraftNotReady, upstream, d.Target)
		}
		s.TargetKind, s.TargetURL = site.TargetK8s, ""
	}
	if d.AccessChoice == k8s.AccessChoiceOpen {
		s.Kind, s.OpenReason, s.Roles = site.KindOpen, site.OpenReasonIntentional, []string{}
	} else {
		s.Kind, s.Roles = site.KindRole, append([]string{}, d.Roles...)
	}
	return change.SiteRequest{Op: change.SiteAdd, Site: s}, nil
}

// sameHTTPSOrigin reports whether a and b are the same https host and port (443 when omitted).
func sameHTTPSOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil || ua.Scheme != "https" || ub.Scheme != "https" || ua.Path != "" || ub.Path != "" {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		return "443"
	}
	return ua.Hostname() == ub.Hostname() && port(ua) == port(ub)
}
