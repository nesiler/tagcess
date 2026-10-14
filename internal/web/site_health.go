package web

import (
	"context"
	"time"

	"github.com/nesiler/tagcess/internal/health"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The site list's health column (S-01): one plain state per site, summarised from the same stored
// checks the dashboard health cards show (target, Caddy gate, TLS). Fail safe: a site is "sağlıklı"
// only when every current check succeeded and is not overdue; a failed latest check is "sorunlu";
// no checks, an overdue check or an unreadable store is "bilinmiyor" or "güncel değil", never healthy.

// The site health states the list shows.
const (
	siteHealthOK      = "sağlıklı"
	siteHealthProblem = "sorunlu"
	siteHealthStale   = "güncel değil"
	siteHealthOff     = "kontrol edilmiyor"
)

// SiteHealth is one site's summarised health and the time of its latest check (zero when unknown).
type SiteHealth struct {
	Status    string
	CheckedAt time.Time
}

// ObservationSiteHealth summarises a site's stored checks. Rows reads the checks of one site key
// (the site's first host, as the health runner stores them). Settings and Now are optional.
type ObservationSiteHealth struct {
	Rows     func(ctx context.Context, siteKey string) ([]db.Observation, error)
	Settings func(ctx context.Context) (monitor.Settings, error)
	Now      func() time.Time
}

// Health implements SiteHealthReader. ok is false when nothing can be said (no reader, unreadable
// store, no checks yet); the list then shows "bilinmiyor".
func (o ObservationSiteHealth) Health(ctx context.Context, s site.Site) (SiteHealth, bool) {
	if o.Rows == nil || len(s.Hosts) == 0 {
		return SiteHealth{}, false
	}
	if disabledSystem(s) {
		return SiteHealth{Status: siteHealthOff}, true
	}
	rows, err := o.Rows(ctx, s.Hosts[0])
	if err != nil {
		return SiteHealth{}, false
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	settings := monitor.DefaultSettings()
	if o.Settings != nil {
		got, err := o.Settings(ctx)
		if err != nil {
			// Without the saved intervals freshness cannot be judged; never guess healthy.
			return SiteHealth{}, false
		}
		settings = got
	}
	return summariseSiteHealth(rows, now, settings)
}

// summariseSiteHealth reduces the newest check per subject to one state; the config-risk rows are
// not health signals and are left out.
func summariseSiteHealth(rows []db.Observation, now time.Time, settings monitor.Settings) (SiteHealth, bool) {
	var out SiteHealth
	n, failed, stale := 0, false, false
	for _, r := range health.NewestPerSubject(rows) {
		if r.Category != obsCategoryTarget && r.Category != obsCategoryGate && r.Category != obsCategoryTLS {
			continue
		}
		n++
		at := parseObsTime(r.LastAttemptAt)
		if at.IsZero() {
			at = parseObsTime(r.ObservedAt)
		}
		if at.After(out.CheckedAt) {
			out.CheckedAt = at
		}
		switch {
		case r.Success != 1 && r.LastAttemptAt != "":
			failed = true
		case health.ObservationFreshness(r, now, health.ObservationInterval(r.Category, settings)) != health.RowFresh:
			stale = true
		}
	}
	switch {
	case n == 0:
		return SiteHealth{}, false
	case failed:
		out.Status = siteHealthProblem
	case stale:
		out.Status = siteHealthStale
	default:
		out.Status = siteHealthOK
	}
	return out, true
}

// disabledSystem reports a system site whose template is switched off; it is not checked at all.
func disabledSystem(s site.Site) bool {
	if s.Kind != site.KindSystem || s.SystemTemplate != site.TemplateWireGuardUI {
		return false
	}
	cfg, err := site.ParseSystemConfig(s.SystemTemplate, s.SystemConfig)
	return err == nil && !cfg.Enabled
}
