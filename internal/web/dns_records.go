package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/site"
)

// The manual MagicDNS records screen (F3-008, H-06, ADR 0013): /headscale/dns lists the
// site-derived records (read-only, with the site link) next to the manual ones, and an add,
// edit or delete goes through the shared preview → version-bound approval → result flow. The
// pipeline's manual_dns operation is the only writer: it re-renders the DNS file from the carried
// set, applies it behind the same drift gate, audit and history as every site change, and skips
// the Caddy and Zitadel steps that cannot change here.

// SiteManualDNSReader reads the stored manual MagicDNS records (H-06, F2-022). It is satisfied by
// *site.Store.
type SiteManualDNSReader interface {
	ManualDNS(ctx context.Context) ([]dns.Record, error)
}

// DNSRecordsConfig wires the manual DNS records screen.
type DNSRecordsConfig struct {
	Reviewer SiteReviewer
	Lister   SiteLister
	Manual   SiteManualDNSReader
	// Settings carries the render inputs; the site records' value is the global VPN address.
	Settings SiteSettingsSource
	Changes  SiteChangeReader
	Auditor  SiteAuditor
	// DryRun carries the dry-run state of the section tab bar's note (R2 karar 22, F3-012). Required.
	DryRun change.DryRun
	CSRF   *CSRF
}

// DNSRecordsHandler serves the manual DNS records screen.
type DNSRecordsHandler struct {
	cfg DNSRecordsConfig
}

// NewDNSRecordsHandler validates the wiring.
func NewDNSRecordsHandler(cfg DNSRecordsConfig) (*DNSRecordsHandler, error) {
	switch {
	case cfg.Reviewer == nil:
		return nil, errors.New("web: dns records needs a reviewer")
	case cfg.Lister == nil:
		return nil, errors.New("web: dns records needs a lister")
	case cfg.Manual == nil:
		return nil, errors.New("web: dns records needs a manual record reader")
	case cfg.Settings == nil:
		return nil, errors.New("web: dns records needs a settings source")
	case cfg.Changes == nil:
		return nil, errors.New("web: dns records needs a change reader")
	case cfg.Auditor == nil:
		return nil, errors.New("web: dns records needs an auditor")
	case cfg.DryRun == nil:
		return nil, errors.New("web: dns records needs a dry-run source")
	case cfg.CSRF == nil:
		return nil, errors.New("web: dns records needs a CSRF signer")
	}
	return &DNSRecordsHandler{cfg: cfg}, nil
}

// Register adds the manual DNS records routes to mux.
func (h *DNSRecordsHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /headscale/dns", h.page)
	mux.HandleFunc("POST /headscale/dns/preview", h.preview)
	mux.HandleFunc("POST /headscale/dns/approve", h.approve)
}

// dnsRecordRow is one row of the records table.
type dnsRecordRow struct {
	Name, Type, Value string
	// SiteID and SiteLabel are set for site-derived rows only; a manual row has neither.
	SiteID    int64
	SiteLabel string
	// OffTailnet marks a private address outside the tailnet (F5 I11): not every client can reach it.
	OffTailnet bool
}

// dnsRecordsView is the /headscale/dns page data. FormError carries a refused record; the form
// that produced it stays on the page. DryRun carries the section tab bar's note (F3-012).
type dnsRecordsView struct {
	SiteRows   []dnsRecordRow
	ManualRows []dnsRecordRow
	FormError  string
	DryRun     bool
}

// dnsPreviewView is the preview page data (the dns diff and the version-bound approval). Blocked
// carries the reason the existing state refuses the change; the approval is then not offered and
// the resync way out is.
type dnsPreviewView struct {
	Diff    change.SiteDiff
	Version string
	Request string
	Blocked string
	// OffTailnet is the new record's value when it is a private address outside the tailnet.
	OffTailnet string
}

// page renders the records screen.
func (h *DNSRecordsHandler) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	actor, _ := ActorFrom(r.Context())
	sites, err := h.cfg.Lister.ListSites(r.Context())
	if err != nil {
		http.Error(w, "siteler okunamadı", http.StatusInternalServerError)
		return
	}
	manual, err := h.cfg.Manual.ManualDNS(r.Context())
	if err != nil {
		http.Error(w, "elle DNS kayıtları okunamadı", http.StatusInternalServerError)
		return
	}
	settings, err := h.cfg.Settings.Settings(r.Context())
	if err != nil {
		http.Error(w, "ayarlar okunamadı", http.StatusInternalServerError)
		return
	}
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v := buildDNSRecordsView(sites, manual, settings.DNS.AValue)
	v.DryRun = dryRun
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "MagicDNS kayıtları",
		DNSRecordsPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// buildDNSRecordsView splits the records by source: the site-derived set (the same rule the
// renderer applies: every host of a MagicDNS site as an A record at the VPN address) and the
// stored manual set.
func buildDNSRecordsView(sites []site.Site, manual []dns.Record, vpnAddr string) dnsRecordsView {
	var v dnsRecordsView
	for _, s := range sites {
		if !s.MagicDNS {
			continue
		}
		for _, host := range s.Hosts {
			v.SiteRows = append(v.SiteRows, dnsRecordRow{
				Name: host, Type: dns.TypeA, Value: vpnAddr, SiteID: s.ID, SiteLabel: s.Hosts[0],
			})
		}
	}
	for _, r := range manual {
		v.ManualRows = append(v.ManualRows, dnsRecordRow{Name: r.Name, Type: r.Type, Value: r.Value, OffTailnet: dns.PrivateOutsideTailnet(r.Value)})
	}
	return v
}

// errNotManual marks an edit or delete aimed at a record that is not in the stored manual set:
// the site-derived records are not editable (AC6).
var errNotManual = errors.New("web: record is not in the manual set")

// preview builds the new manual set from the form and plans the change read-only. A field error
// re-shows the page with the reason; a state block shows the reason and the resync way out.
func (h *DNSRecordsHandler) preview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	action := strings.TrimSpace(r.PostFormValue("action"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	value := strings.TrimSpace(r.PostFormValue("value"))
	oldName := strings.TrimSpace(r.PostFormValue("old_name"))
	oldType := strings.TrimSpace(r.PostFormValue("old_type"))
	delType := strings.TrimSpace(r.PostFormValue("type"))

	sites, err := h.cfg.Lister.ListSites(r.Context())
	if err != nil {
		http.Error(w, "siteler okunamadı", http.StatusInternalServerError)
		return
	}
	stored, err := h.cfg.Manual.ManualDNS(r.Context())
	if err != nil {
		http.Error(w, "elle DNS kayıtları okunamadı", http.StatusInternalServerError)
		return
	}

	newSet, rec, hasRec, err := applyDNSForm(stored, dnsForm{action: action, name: name, value: value, oldName: oldName, oldType: oldType, delType: delType})
	if errors.Is(err, errNotManual) {
		h.auditOutcome(r, actor, "dns.manual_preview", change.TargetManualDNS, "failed", err.Error())
		http.Error(w, "kayıt elle eklenmemiş; site kayıtları değiştirilemez", http.StatusBadRequest)
		return
	}
	if err != nil {
		h.auditOutcome(r, actor, "dns.manual_preview", change.TargetManualDNS, "failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if hasRec {
		// The record is refused next to the form (AC3), before anything is planned.
		if verr := change.ValidateManualRecord(rec, sites); verr != nil {
			h.auditOutcome(r, actor, "dns.manual_preview", change.TargetManualDNS, "failed", verr.Error())
			h.renderPage(w, r, dnsRecordsView{FormError: verr.Error()})
			return
		}
	}
	if err := h.audit(r, actor, "dns.manual_preview", change.TargetManualDNS, "requested", ""); err != nil {
		http.Error(w, "işlem kaydedilemedi", http.StatusInternalServerError)
		return
	}
	req := change.SiteRequest{Actor: actor, Op: change.SiteManualDNS, ManualDNS: newSet}
	pl, err := h.cfg.Reviewer.Preview(r.Context(), req)
	switch {
	case errors.Is(err, change.ErrBlocked):
		h.auditOutcome(r, actor, "dns.manual_preview", change.TargetManualDNS, "blocked", err.Error())
		h.renderPreview(w, r, dnsPreviewView{Blocked: err.Error()})
		return
	case err != nil:
		// Set-level problems (a duplicate name and type, the cap) come from the pipeline's own
		// validation; they are shown next to the form too.
		h.auditOutcome(r, actor, "dns.manual_preview", change.TargetManualDNS, "failed", err.Error())
		h.renderPage(w, r, dnsRecordsView{FormError: err.Error()})
		return
	}
	encoded, err := encodeSiteRequest(req)
	if err != nil {
		http.Error(w, "istek hazırlanamadı", http.StatusInternalServerError)
		return
	}
	pv := dnsPreviewView{Diff: pl.Diff, Version: SitePlanVersion(pl), Request: encoded}
	if hasRec && dns.PrivateOutsideTailnet(rec.Value) {
		pv.OffTailnet = rec.Value
	}
	h.renderPreview(w, r, pv)
}

// approve re-plans the carried request and applies it only when the plan still matches the one
// the operator saw (AC7): the same version-bound flow as the site review screens.
func (h *DNSRecordsHandler) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := operatorActor(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	req, err := decodeSiteRequest(r.PostFormValue("request"))
	if err != nil || req.Op != change.SiteManualDNS {
		http.Error(w, "geçersiz değişiklik isteği", http.StatusBadRequest)
		return
	}
	// The actor never travels with the form: the signed-in operator owns the decision.
	req.Actor = actor
	version := strings.TrimSpace(r.PostFormValue("plan_version"))
	if version == "" {
		http.Error(w, "plan sürümü yok; preview'u yenileyin", http.StatusBadRequest)
		return
	}
	if err := h.audit(r, actor, "dns.manual", change.TargetManualDNS, "requested", ""); err != nil {
		http.Error(w, "onay kaydedilemedi", http.StatusInternalServerError)
		return
	}
	pl, err := h.cfg.Reviewer.Preview(r.Context(), req)
	switch {
	case err != nil:
		h.auditOutcome(r, actor, "dns.manual", change.TargetManualDNS, "failed", err.Error())
		http.Error(w, "plan yeniden hesaplanamadı: "+err.Error(), http.StatusConflict)
		return
	case SitePlanVersion(pl) != version:
		h.auditOutcome(r, actor, "dns.manual", change.TargetManualDNS, "failed", "plan değişti")
		http.Error(w, "plan değişti; preview'u yenileyip yeniden onaylayın", http.StatusConflict)
		return
	}
	res, err := h.cfg.Reviewer.Submit(r.Context(), req)
	h.auditOutcome(r, actor, "dns.manual", change.TargetManualDNS, auditResult(res, err), reasonOr(res, err))
	h.renderResult(w, r, res, err)
}

// dnsForm is the raw preview form.
type dnsForm struct {
	action, name, value, oldName, oldType, delType string
}

// applyDNSForm applies the form to the stored set and returns the new set plus, for add and
// edit, the record that has to pass the field validation. An edit or delete that does not name a
// stored manual record is errNotManual (AC6): the site-derived records are not reachable here.
func applyDNSForm(stored []dns.Record, f dnsForm) (newSet []dns.Record, rec dns.Record, hasRec bool, err error) {
	switch f.action {
	case "add":
		rec, err = dnsFormRecord(f.name, f.value)
		if err != nil {
			return nil, rec, false, err
		}
		return append(append([]dns.Record{}, stored...), rec), rec, true, nil
	case "edit":
		i := slicesIndex(stored, f.oldName, f.oldType)
		if i < 0 {
			return nil, rec, false, errNotManual
		}
		rec, err = dnsFormRecord(f.name, f.value)
		if err != nil {
			return nil, rec, false, err
		}
		newSet = append(append([]dns.Record{}, stored[:i]...), stored[i+1:]...)
		return append(newSet, rec), rec, true, nil
	case "delete":
		i := slicesIndex(stored, f.name, f.delType)
		if i < 0 {
			return nil, rec, false, errNotManual
		}
		return append(append([]dns.Record{}, stored[:i]...), stored[i+1:]...), rec, false, nil
	default:
		return nil, rec, false, fmt.Errorf("bilinmeyen işlem %q", f.action)
	}
}

// dnsFormRecord builds the record of an add or edit; the type derives from the value (security.md
// §5: A for IPv4, AAAA for IPv6). A value that is not an IP keeps an empty type so the record
// validation reports the value.
func dnsFormRecord(name, value string) (dns.Record, error) {
	if name == "" && value == "" {
		return dns.Record{}, errors.New("ad ve değer boş")
	}
	rec := dns.Record{Name: name, Value: value}
	if addr, err := netip.ParseAddr(value); err == nil {
		switch {
		case addr.Is4():
			rec.Type = dns.TypeA
		case addr.Is6() && !addr.Is4In6() && addr.Zone() == "":
			rec.Type = dns.TypeAAAA
		}
	}
	return rec, nil
}

// slicesIndex finds a record by name and type.
func slicesIndex(recs []dns.Record, name, typ string) int {
	for i, r := range recs {
		if r.Name == name && r.Type == typ {
			return i
		}
	}
	return -1
}

func (h *DNSRecordsHandler) renderPage(w http.ResponseWriter, r *http.Request, v dnsRecordsView) {
	dryRun, err := h.cfg.DryRun.DryRun(r.Context())
	if err != nil {
		http.Error(w, "dry-run durumu okunamadı", http.StatusInternalServerError)
		return
	}
	v.DryRun = dryRun
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "MagicDNS kayıtları",
		DNSRecordsPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

func (h *DNSRecordsHandler) renderPreview(w http.ResponseWriter, r *http.Request, v dnsPreviewView) {
	actor, _ := ActorFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Elle DNS kaydı preview'u",
		DNSPreviewPage(v, h.cfg.CSRF.Token())).Render(r.Context(), w)
}

// renderResult writes the shared result screen (AC2).
func (h *DNSRecordsHandler) renderResult(w http.ResponseWriter, r *http.Request, res change.SiteResult, applyErr error) {
	actor, _ := ActorFrom(r.Context())
	view := buildSiteResultView(r.Context(), h.cfg.Changes, h.cfg.Lister, res, applyErr)
	view.Back = resultBackDNS
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = Layout(actor, h.cfg.CSRF.Token(), "headscale", "Değişiklik sonucu",
		SiteResultPage(view)).Render(r.Context(), w)
}

// audit writes one operator action before the pipeline runs.
func (h *DNSRecordsHandler) audit(r *http.Request, actor, event, target, result, reason string) error {
	var diff audit.Diff
	if reason != "" {
		diff = audit.Diff{{Field: "error", After: reason}}
	}
	_, err := h.cfg.Auditor.Write(r.Context(), audit.Entry{
		Actor: actor, Event: event, Target: target, Diff: diff, Result: result,
	})
	return err
}

// auditOutcome writes the post-action result; the requested entry already records the action.
func (h *DNSRecordsHandler) auditOutcome(r *http.Request, actor, event, target, result, reason string) {
	if err := h.audit(r, actor, event, target, result, reason); err != nil {
		slog.Default().Warn("dns records: audit outcome write failed", "event", event, "target", target, "err", err)
	}
}
