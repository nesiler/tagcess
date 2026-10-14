package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	caddyrender "github.com/nesiler/tagcess/internal/render"
)

// NavItem is one entry of a navigation list: the sidebar, a tab bar or a sub-navigation.
type NavItem struct {
	// Key names the entry. In the sidebar it is the work area a page passes to Layout as active.
	Key   string
	Label string
	Href  string
	Icon  string
	// Also lists further path prefixes that belong to this entry (/k8s/drafts under discovery).
	Also []string
}

// NavGroup is a titled block of the sidebar.
type NavGroup struct {
	Label string
	Items []NavItem
}

// Nav is the sidebar, one entry per screen family (overview.md §5). Layout marks the entry
// that owns the request path (WithShell); without a path it marks the first entry of the active
// work area.
var Nav = []NavGroup{
	{Label: "Genel", Items: []NavItem{
		{Key: "pano", Label: "Pano", Href: "/", Icon: "dashboard"},
		{Key: "pano", Label: "Uyarılar", Href: "/alerts", Icon: "bell"},
		{Key: "sync", Label: "Sync", Href: "/sync", Icon: "sync"},
	}},
	{Label: "Siteler", Items: []NavItem{
		{Key: "siteler", Label: "Siteler", Href: "/sites", Icon: "sites"},
	}},
	{Label: "Headscale", Items: headscaleTabs},
	{Label: "Kubernetes", Items: []NavItem{
		{Key: "k8s", Label: "Discovery", Href: "/k8s/discovery", Icon: "k8s", Also: []string{"/k8s/drafts"}},
		{Key: "k8s", Label: "Bağlantı", Href: "/k8s/connection", Icon: "link"},
		{Key: "k8s", Label: "Kurulum", Href: "/k8s/setup", Icon: "tool"},
	}},
	{Label: "Sistem", Items: []NavItem{
		{Key: "audit", Label: "Audit", Href: "/audit", Icon: "list"},
		{Key: "ayarlar", Label: "Ayarlar", Href: "/settings", Icon: "settings", Also: []string{"/monitor"}},
	}},
}

// navCurrent returns the Href of the sidebar entry to mark: the entry whose Href (or Also prefix)
// is the longest prefix of path, or, without a path match, the first entry of the active area.
func navCurrent(path, active string) string {
	best, bestLen := "", 0
	for _, g := range Nav {
		for _, it := range g.Items {
			for _, p := range append([]string{it.Href}, it.Also...) {
				if pathUnder(path, p) && len(p) > bestLen {
					best, bestLen = it.Href, len(p)
				}
			}
		}
	}
	if best != "" {
		return best
	}
	for _, g := range Nav {
		for _, it := range g.Items {
			if it.Key == active {
				return it.Href
			}
		}
	}
	return ""
}

// pathUnder reports whether path is prefix or below it. "/" matches only itself.
func pathUnder(path, prefix string) bool {
	if prefix == "/" {
		return path == "/"
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// ShellStatus is what the top bar shows on every page: dry-run mode and the number of changes
// waiting for an operator (Y-06, G-03).
type ShellStatus struct {
	DryRun  bool
	Pending int
}

// ShellStatusSource reads the top bar status. It must be cheap: it runs on every page.
type ShellStatusSource interface {
	ShellStatus(ctx context.Context) (ShellStatus, error)
}

type shellKey struct{}

type shellCtx struct {
	path   string
	status ShellStatusSource
}

// WithShell binds the request path (for the sidebar mark) and the top bar status source to the
// request context, so Layout can draw both without every handler passing them. src may be nil.
func WithShell(src ShellStatusSource, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), shellKey{}, shellCtx{path: r.URL.Path, status: src})
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// shellView is what Layout draws around the page.
type shellView struct {
	current string
	status  ShellStatus
	// statusErr is a status that could not be read; the bar says so instead of showing nothing.
	statusErr bool
}

func shellFor(ctx context.Context, active string) shellView {
	sc, _ := ctx.Value(shellKey{}).(shellCtx)
	v := shellView{current: navCurrent(sc.path, active)}
	if sc.status != nil {
		st, err := sc.status.ShellStatus(ctx)
		if err != nil {
			v.statusErr = true
		} else {
			v.status = st
		}
	}
	return v
}

// initials is the avatar text: the first letters of the user part of the e-mail (or user name).
func initials(a Actor) string {
	name := a.Email
	if name == "" {
		name = a.User
	}
	name, _, _ = strings.Cut(name, "@")
	var out []rune
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == '-' || r == '_' || r == ' ' }) {
		for _, r := range part {
			out = append(out, r)
			break
		}
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return strings.ToUpper(string(out))
}

// SignOutHref ends the shared oauth2-proxy session (one cookie for all sites, so this signs the
// browser out everywhere). The default only clears that cookie and returns to "/"; SetSignOut
// replaces it at startup with the link that also ends the Zitadel session (J1), which is what makes
// "sign out" and "sign in with another account" real. The target is relative on purpose: the Host
// header is user input and must not feed a redirect.
var SignOutHref = "/oauth2/sign_out?rd=%2F"

// SetSignOut sets SignOutHref from the gate settings; an empty clientID keeps the plain link. It is
// called once at startup, before the server handles requests.
func SetSignOut(issuer, clientID, returnURL string) error {
	href, err := caddyrender.SignOutPath(issuer, clientID, returnURL)
	if err != nil {
		return err
	}
	SignOutHref = href
	return nil
}

// csrfHeaders builds the JSON value for the hx-headers attribute that makes htmx attach the CSRF
// token to every request it sends (NFR-03). templ escapes it as an attribute value and the browser
// decodes it; htmx reads hx-headers from <body> and inherits it for its requests.
func csrfHeaders(token string) string {
	b, err := json.Marshal(map[string]string{CSRFHeader: token})
	if err != nil {
		// A map of plain strings cannot fail to marshal.
		panic(err)
	}
	return string(b)
}

// pendingLabel is the top bar pill text for n changes waiting for approval.
func pendingLabel(n int) string {
	return strconv.Itoa(n) + " onay bekleyen değişiklik"
}
