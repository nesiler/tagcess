package zitadel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// This file keeps the oauth2-proxy app's redirect URI list in line with the site records
// (S-03, ADR 0012). The desired set D is the callback of every host that sits behind
// forward_auth: the hosts of role sites and the tagcess system site. tagcess remembers the set
// O it last wrote; the merge only ever removes URIs from O, so a URI somebody else added is
// never touched (S-03.3).

// Drift kinds a URISync reports. They are warnings for the operator (P-02): the live list and the
// site records disagree, or a step could not be completed and the last known-good state was kept.
const (
	DriftReadFailed    = "read_failed"     // the app could not be read: nothing was written
	DriftWriteFailed   = "write_failed"    // the write or its read-back verification failed: O was not updated
	DriftOwnedNotSaved = "owned_not_saved" // the write was verified but O could not be stored
	DriftMissing       = "missing"         // a desired URI is not in the list (not written yet)
	DriftOwnedRemoved  = "owned_removed"   // a URI tagcess wrote and still wants was removed by someone else
	DriftStaleOwned    = "stale_owned"     // a URI tagcess wrote and no longer wants is still in the list
)

// AlertURIDrift is the dashboard alert kind (alerts table) raised while any drift is open;
// SourceOAuth2ProxyApp is its source.
const (
	AlertURIDrift        = "zitadel_uri_drift"
	SourceOAuth2ProxyApp = "oauth2-proxy"
)

const uriTimeFormat = "2006-01-02T15:04:05.000Z" // matches the audit log and the other alert writers

// URIDrift is one warning. URI is empty for a failed step, whose cause is in Detail.
type URIDrift struct {
	Kind   string
	URI    string
	Detail string
}

// URIResult is what a Sync or CheckDrift run found. Foreign lists the URIs in the live list that
// tagcess neither owns nor wants (S-03.3): they are shown to the operator, never changed.
type URIResult struct {
	Written bool
	Foreign []string
	Drift   []URIDrift
}

// URISync reconciles the redirect URIs of one Zitadel OIDC app. It serializes its runs, so two
// callers cannot interleave a read-merge-write.
type URISync struct {
	client *Client
	appID  string
	// appName is set instead of appID by NewNamedURISync: the app is found by name on first use.
	appName string
	q       *db.Queries
	mu      sync.Mutex
	// postLogoutURI, when set, is added to the app's post-logout redirect URIs after every successful
	// Sync (J1). It is additive only and never part of the O/D bookkeeping.
	postLogoutURI string
}

// WithPostLogoutURI makes Sync also register uri as a post-logout redirect URI of the app, so the
// sign-out links can return to tagcess. Call it before the first run.
func (u *URISync) WithPostLogoutURI(uri string) *URISync {
	u.postLogoutURI = uri
	return u
}

// NewURISync returns a URISync for the app appID, keeping O and the drift alert in q.
func NewURISync(c *Client, appID string, q *db.Queries) *URISync {
	return &URISync{client: c, appID: appID, q: q}
}

// NewNamedURISync returns a URISync for the app with that name in the vpn project. The app is
// looked up on first use and cached, so an unreachable Zitadel at startup is a failed read of the
// first run (a warning, nothing written) rather than a reason not to start.
func NewNamedURISync(c *Client, appName string, q *db.Queries) *URISync {
	return &URISync{client: c, appName: appName, q: q}
}

// app returns the app id, finding it by name on first use. The caller holds u.mu.
func (u *URISync) app(ctx context.Context) (string, error) {
	if u.appID != "" {
		return u.appID, nil
	}
	id, err := u.client.FindAppID(ctx, u.appName)
	if err != nil {
		return "", err
	}
	u.appID = id
	return id, nil
}

// callbackURI is the one URI shape tagcess writes. The host is re-validated here, so a record that
// slipped past (or predates) validation can never put anything but a plain hostname into a URI.
func callbackURI(host string) (string, error) {
	if !site.ValidHostname(host) {
		return "", fmt.Errorf("zitadel: host %q is not a valid hostname, refusing to build a redirect URI", host)
	}
	return "https://" + host + "/oauth2/callback", nil
}

// DesiredURIs returns D: the callback URI of every host behind forward_auth, sorted and without
// duplicates. Open sites and the other system templates do not use oauth2-proxy, so they have none.
// Whatever the S-06 key says, role sites keep their forward_auth flow (only the outside-the-tailnet
// branch changes), so D does not depend on it. One invalid host fails the whole call: D is never
// built from part of the records.
func DesiredURIs(sites []site.Site) ([]string, error) {
	set := map[string]bool{}
	for _, s := range sites {
		behindForwardAuth := s.Kind == site.KindRole || (s.Kind == site.KindSystem && s.SystemTemplate == site.TemplateTagcess)
		if !behindForwardAuth {
			continue
		}
		for _, host := range s.Hosts {
			uri, err := callbackURI(host)
			if err != nil {
				return nil, err
			}
			set[uri] = true
		}
	}
	out := make([]string, 0, len(set))
	for uri := range set {
		out = append(out, uri)
	}
	sort.Strings(out)
	return out, nil
}

// mergeURIs is ADR 0012 step 3: the current list keeps its order minus the URIs tagcess owns but
// no longer wants (O \ D), then the missing desired URIs follow, sorted. changed is false when the
// result equals the current list, which then needs no write. current is not modified.
func mergeURIs(current, owned, desired []string) (merged []string, changed bool) {
	merged = make([]string, 0, len(current)+len(desired))
	present := map[string]bool{}
	for _, uri := range current {
		if slices.Contains(owned, uri) && !slices.Contains(desired, uri) {
			continue
		}
		merged = append(merged, uri)
		present[uri] = true
	}
	var add []string
	for _, uri := range desired {
		if !present[uri] {
			add = append(add, uri)
			present[uri] = true
		}
	}
	sort.Strings(add)
	merged = append(merged, add...)
	return merged, !slices.Equal(merged, current)
}

// Sync brings the live list in line with the sites (S-03.1): read, merge, write only when the
// result differs, and record O only once the client has verified the write by reading it back.
// Any failed step keeps O as it was, reports a drift warning and raises the drift alert (rule 7);
// nothing is written after a failed read. The first run, with no O stored, takes O as the current
// list ∩ D and leaves every other URI alone (ADR 0012 step 2).
func (u *URISync) Sync(ctx context.Context, sites []site.Site) (URIResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	desired, err := DesiredURIs(sites)
	if err != nil {
		return URIResult{}, err
	}
	owned, haveOwned, err := u.loadOwned(ctx)
	if err != nil {
		return URIResult{}, err
	}
	var res URIResult
	appID, err := u.app(ctx)
	if err != nil {
		return u.fail(ctx, res, DriftReadFailed, err)
	}
	cur, err := u.client.AppOIDC(ctx, appID)
	if err != nil {
		return u.fail(ctx, res, DriftReadFailed, err)
	}
	if !haveOwned {
		owned = intersect(cur.RedirectUris, desired)
		if err := u.saveOwned(ctx, owned); err != nil {
			return u.fail(ctx, res, DriftOwnedNotSaved, err)
		}
	}
	res.Foreign = foreignURIs(cur.RedirectUris, owned, desired)

	merged, changed := mergeURIs(cur.RedirectUris, owned, desired)
	if changed {
		// UpdateAppRedirectURIs re-reads the app first (to carry the four fields) and verifies the
		// result afterwards; an error from it means O must not move.
		if err := u.client.UpdateAppRedirectURIs(ctx, appID, merged); err != nil {
			return u.fail(ctx, res, DriftWriteFailed, err)
		}
		res.Written = true
	}
	// The list now holds all of D and none of O \ D, so D is what tagcess owns.
	if err := u.saveOwned(ctx, desired); err != nil {
		return u.fail(ctx, res, DriftOwnedNotSaved, err)
	}
	if u.postLogoutURI != "" {
		if err := u.client.EnsureAppPostLogoutURI(ctx, appID, u.postLogoutURI); err != nil {
			return u.fail(ctx, res, DriftWriteFailed, err)
		}
	}
	return res, u.resolveAlert(ctx)
}

// CheckDrift is the periodic Y-02 comparison (ADR 0012 step 6). It never writes to Zitadel and
// never changes O: it reads the list and reports what differs from D and O, and keeps the drift
// alert in step with the result. With no O stored yet only D ⊆ list can be checked.
func (u *URISync) CheckDrift(ctx context.Context, sites []site.Site) (URIResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	desired, err := DesiredURIs(sites)
	if err != nil {
		return URIResult{}, err
	}
	owned, haveOwned, err := u.loadOwned(ctx)
	if err != nil {
		return URIResult{}, err
	}
	var res URIResult
	appID, err := u.app(ctx)
	if err != nil {
		return u.fail(ctx, res, DriftReadFailed, err)
	}
	cur, err := u.client.AppOIDC(ctx, appID)
	if err != nil {
		return u.fail(ctx, res, DriftReadFailed, err)
	}
	res.Foreign = foreignURIs(cur.RedirectUris, owned, desired)
	for _, uri := range desired {
		if slices.Contains(cur.RedirectUris, uri) {
			continue
		}
		kind := DriftMissing
		if haveOwned && slices.Contains(owned, uri) {
			kind = DriftOwnedRemoved
		}
		res.Drift = append(res.Drift, URIDrift{Kind: kind, URI: uri})
	}
	for _, uri := range cur.RedirectUris {
		if slices.Contains(owned, uri) && !slices.Contains(desired, uri) {
			res.Drift = append(res.Drift, URIDrift{Kind: DriftStaleOwned, URI: uri})
		}
	}
	if len(res.Drift) == 0 {
		return res, u.resolveAlert(ctx)
	}
	return res, u.raiseAlert(ctx)
}

// OwnedURIs returns O, the URIs the last successful Sync wrote, sorted; ok is false while none is
// stored. It reads only the local record, never Zitadel.
func (u *URISync) OwnedURIs(ctx context.Context) (uris []string, ok bool, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	uris, ok, err = u.loadOwned(ctx)
	sort.Strings(uris)
	return uris, ok, err
}

// fail records a failed step as a drift warning and an open alert, and returns the step's error.
func (u *URISync) fail(ctx context.Context, res URIResult, kind string, cause error) (URIResult, error) {
	res.Drift = append(res.Drift, URIDrift{Kind: kind, Detail: cause.Error()})
	return res, errors.Join(cause, u.raiseAlert(ctx))
}

// intersect returns the URIs of a that are also in b, in a's order.
func intersect(a, b []string) []string {
	out := []string{}
	for _, uri := range a {
		if slices.Contains(b, uri) {
			out = append(out, uri)
		}
	}
	return out
}

// foreignURIs returns the live URIs that tagcess neither owns nor wants, in list order.
func foreignURIs(current, owned, desired []string) []string {
	out := []string{}
	for _, uri := range current {
		if !slices.Contains(owned, uri) && !slices.Contains(desired, uri) {
			out = append(out, uri)
		}
	}
	return out
}

// loadOwned reads O. ok is false while no ownership record exists (the first import has not run).
// An unreadable record is an error, not an empty O: guessing would let the merge drop or keep
// the wrong URIs.
func (u *URISync) loadOwned(ctx context.Context) (uris []string, ok bool, err error) {
	stored, err := u.q.GetOwnedURIs(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("zitadel: read owned redirect URIs: %w", err)
	}
	if err := json.Unmarshal([]byte(stored), &uris); err != nil {
		return nil, false, fmt.Errorf("zitadel: parse owned redirect URIs %q: %w", stored, err)
	}
	if uris == nil {
		uris = []string{}
	}
	return uris, true, nil
}

// saveOwned stores O sorted, so the record is deterministic.
func (u *URISync) saveOwned(ctx context.Context, uris []string) error {
	sorted := slices.Clone(uris)
	if sorted == nil {
		sorted = []string{}
	}
	sort.Strings(sorted)
	body, err := json.Marshal(sorted)
	if err != nil {
		return fmt.Errorf("zitadel: encode owned redirect URIs: %w", err)
	}
	if err := u.q.UpsertOwnedURIs(ctx, db.UpsertOwnedURIsParams{
		Uris: string(body), UpdatedAt: time.Now().UTC().Format(uriTimeFormat),
	}); err != nil {
		return fmt.Errorf("zitadel: store owned redirect URIs: %w", err)
	}
	return nil
}

// raiseAlert opens the drift alert, or bumps its last_seen_at when one is already open, so a
// recurring drift keeps one row (same pattern as the reconcile read alerts).
func (u *URISync) raiseAlert(ctx context.Context) error {
	stamp := time.Now().UTC().Format(uriTimeFormat)
	touched, err := u.q.TouchAlert(ctx, db.TouchAlertParams{LastSeenAt: stamp, Kind: AlertURIDrift, Source: SourceOAuth2ProxyApp})
	if err != nil {
		return fmt.Errorf("zitadel: touch %s alert: %w", AlertURIDrift, err)
	}
	if touched > 0 {
		return nil
	}
	if _, err := u.q.InsertAlert(ctx, db.InsertAlertParams{
		Kind: AlertURIDrift, Source: SourceOAuth2ProxyApp, FirstSeenAt: stamp, LastSeenAt: stamp,
	}); err != nil {
		return fmt.Errorf("zitadel: raise %s alert: %w", AlertURIDrift, err)
	}
	return nil
}

// resolveAlert closes the open drift alert: the list matches the records again.
func (u *URISync) resolveAlert(ctx context.Context) error {
	if _, err := u.q.ResolveAlerts(ctx, db.ResolveAlertsParams{
		ResolvedAt: sql.NullString{String: time.Now().UTC().Format(uriTimeFormat), Valid: true},
		Kind:       AlertURIDrift, Source: SourceOAuth2ProxyApp,
	}); err != nil {
		return fmt.Errorf("zitadel: resolve %s alert: %w", AlertURIDrift, err)
	}
	return nil
}
