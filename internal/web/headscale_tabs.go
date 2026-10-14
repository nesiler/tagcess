package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/a-h/templ"

	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/web/ui"
)

// The Headscale section skeleton (F3-012): the tab list under /headscale, the sub-navigation of
// the keys tab, and HeadscaleTabs — the tab bar plus the section-wide maintenance band (F3b-020).

// headscaleTabs is the Headscale section of the sidebar (Nav), in display order. This list is the
// single definition of the section's pages.
var headscaleTabs = []NavItem{
	{Key: "headscale", Label: "Cihazlar", Href: "/headscale/devices", Icon: "device"},
	{Key: "headscale", Label: "Kullanıcılar", Href: "/headscale/users", Icon: "user"},
	{Key: "headscale", Label: "Key'ler", Href: "/headscale/keys", Icon: "key"},
	{Key: "headscale", Label: "ACL", Href: "/headscale/policy", Icon: "shield"},
	{Key: "headscale", Label: "DNS", Href: "/headscale/dns", Icon: "dns"},
	{Key: "headscale", Label: "Ayarlar", Href: "/headscale/settings", Icon: "settings"},
	{Key: "headscale", Label: "Config", Href: "/headscale/config", Icon: "file"},
}

// keysSubNav is the navigation below the keys tab, in display order.
var keysSubNav = []NavItem{
	{Key: "preauth", Label: "Pre-auth", Href: "/headscale/keys/preauth"},
	{Key: "personal", Label: "Kişisel key", Href: "/headscale/keys/personal"},
	{Key: "api", Label: "API", Href: "/headscale/keys/api"},
}

// dryRunNote is the note under the section tab bar while dry-run is on (R2 karar 22): automatic
// sync and policy writes stop, manual device/key actions still apply.
const dryRunNote = "dry-run açık: otomatik sync ve policy yazmaları durur; elle cihaz/key eylemleri apply edilir"

// dryRunSkippedNote is the close note a successful config change leaves when dry-run was on
// (R2:29 f, F3b-019): the reconcile was counted as done but applied no diff.
const dryRunSkippedNote = "dry-run açık, fark apply edilmedi"

// MaintenanceBannerSource reads the durable maintenance row for the section-wide band;
// *maintenance.Service satisfies it.
type MaintenanceBannerSource interface {
	Get(ctx context.Context) (maintenance.Status, error)
}

type maintenanceBannerKey struct{}

// WithMaintenanceBanner binds src to the request context so every Headscale page that renders
// HeadscaleTabs shows the maintenance band (F3b-020 AC4) without each handler reading the row.
// It is deliberately lazy: the row is read only when a Headscale tab actually renders.
func WithMaintenanceBanner(src MaintenanceBannerSource, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), maintenanceBannerKey{}, src)))
	})
}

// HeadscaleTabs is the top of every Headscale page: the dry-run note and the maintenance band. The
// band comes from the request context bound by WithMaintenanceBanner, so no page has to thread the
// maintenance row through its own view. active names the page's screen; the sidebar marks it from
// the request path, so it is kept only to document the caller.
func HeadscaleTabs(active string, dryRun bool) templ.Component {
	_ = active
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		return headscaleTabsView(dryRun, maintenanceBanner(ctx)).Render(ctx, w)
	})
}

// navTabs turns a navigation list into tabs keyed by the entry key.
func navTabs(items []NavItem) []ui.Tab {
	out := make([]ui.Tab, 0, len(items))
	for _, it := range items {
		out = append(out, ui.Tab{Key: it.Key, Label: it.Label, Href: it.Href})
	}
	return out
}

// maintenanceBannerView is the band's content: the maintenance state at render time, or the last
// close note. Unreadable is fail-safe: an unreadable row never reads as "no maintenance".
type maintenanceBannerView struct {
	Unreadable bool
	Active     bool
	Pending    bool
	State      maintenance.State
	RequestID  string
	Elapsed    string
	// DryRunSkipped is the last close note being dry_run_skipped (AC8).
	DryRunSkipped bool
}

// maintenanceBanner reads the source bound to ctx. Without a source (a page rendered outside the
// middleware, as in some tests) it renders nothing; an unreadable row renders the warning band.
func maintenanceBanner(ctx context.Context) maintenanceBannerView {
	src, _ := ctx.Value(maintenanceBannerKey{}).(MaintenanceBannerSource)
	if src == nil {
		return maintenanceBannerView{}
	}
	st, err := src.Get(ctx)
	if err != nil {
		return maintenanceBannerView{Unreadable: true}
	}
	return maintenanceBannerView{
		Active:        st.State == maintenance.Active,
		Pending:       st.State == maintenance.ReconcilePending,
		State:         st.State,
		RequestID:     st.RequestID,
		Elapsed:       formatElapsed(st.Elapsed),
		DryRunSkipped: st.CloseNote == "dry_run_skipped",
	}
}

// wideningBlockedNote is the explanation a disabled widening control shows while a host config
// change is open (F3b-020 AC4). Narrowing actions (expire, delete, revoke, rename) are never gated.
const wideningBlockedNote = "bakım sürüyor; genişleten bu işlem devre dışı, daraltan işlemler açık"

// wideningUnreadableNote is the fail-safe explanation when the maintenance row cannot be read.
const wideningUnreadableNote = "bakım durumu okunamadı; genişleten bu işlem güvenli tarafta devre dışı"

// wideningNotice returns the reason the widening controls under ctx are disabled, or "" when they
// are allowed. It reads the same maintenance source as the band, so every Headscale page shares one
// rule; without a source (a bare render in a test) widening is allowed, and an unreadable row is
// fail-safe (disabled).
func wideningNotice(ctx context.Context) string {
	src, _ := ctx.Value(maintenanceBannerKey{}).(MaintenanceBannerSource)
	if src == nil {
		return ""
	}
	st, err := src.Get(ctx)
	if err != nil {
		return wideningUnreadableNote
	}
	if st.State == maintenance.Active || st.State == maintenance.ReconcilePending {
		return wideningBlockedNote
	}
	return ""
}

// formatElapsed renders a duration the band can show; it is fixed-width enough to read at a glance.
func formatElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	s := (d % time.Minute) / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%d sa %d dk", h, m)
	case m > 0:
		return fmt.Sprintf("%d dk %d sn", m, s)
	default:
		return fmt.Sprintf("%d sn", s)
	}
}
