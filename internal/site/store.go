package site

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/nesiler/tagcess/internal/store/db"
)

// Store reads and writes site records in SQLite (ADR 0010). Every write runs in a single
// transaction that rewrites the site's sub-records, so a site and its hosts, API rules,
// redirects and headers change together and a refused write leaves nothing behind. Every write
// is validated first by the Validator (F2-003, AC1): an invalid record is refused before any
// database work happens, and a failed role read stops the write (AC3).
type Store struct {
	db       *sql.DB
	q        *db.Queries
	validate *Validator
}

// New returns a site store over the given database, its sqlc queries and the validator every
// write passes through. A nil validator is refused: no write may bypass validation.
func New(sqldb *sql.DB, q *db.Queries, v *Validator) (*Store, error) {
	if v == nil {
		return nil, fmt.Errorf("site: store needs a validator, refusing to open one without it")
	}
	return &Store{db: sqldb, q: q, validate: v}, nil
}

// CreateSite validates the record, then writes a new site with all of its sub-records and
// returns the stored form. An invalid record (F2-003) or an already owned host (F2-002 AC2) is
// refused with the existing records untouched.
func (s *Store) CreateSite(ctx context.Context, in Site) (Site, error) {
	return s.createSite(ctx, in, true)
}

// PreviewCreateSite runs every check and write of CreateSite inside a transaction it rolls back:
// the result is the record as it would be stored (with the id it would get) and nothing is
// written. The change pipeline (F2-011) uses it to validate and render a new site before any
// external system is touched.
func (s *Store) PreviewCreateSite(ctx context.Context, in Site) (Site, error) {
	return s.createSite(ctx, in, false)
}

func (s *Store) createSite(ctx context.Context, in Site, commit bool) (Site, error) {
	if err := s.validate.Validate(ctx, in); err != nil {
		return Site{}, err
	}
	if err := checkSystemShape(in); err != nil {
		return Site{}, err
	}
	n, err := normalize(in)
	if err != nil {
		return Site{}, err
	}
	now := time.Now().UTC().Format(timeFormat)
	var stored Site
	err = s.transactMode(ctx, commit, func(txq *db.Queries) error {
		// The new site has no id yet, so any existing owner is a conflict.
		if err := checkHosts(ctx, txq, 0, in.Hosts); err != nil {
			return err
		}
		if err := checkTemplateFree(ctx, txq, in); err != nil {
			return err
		}
		row, err := txq.InsertSite(ctx, db.InsertSiteParams{
			Kind:              in.Kind,
			OpenReason:        n.openReason,
			SystemTemplate:    n.systemTemplate,
			SystemConfig:      in.SystemConfig,
			Roles:             n.roles,
			TargetRoles:       n.targetRoles,
			Cert:              in.Cert,
			TargetKind:        in.TargetKind,
			TargetUrl:         in.TargetURL,
			TargetTlsInsecure: boolToInt(in.TargetTLSInsecure),
			Magicdns:          boolToInt(in.MagicDNS),
			Maintenance:       boolToInt(in.Maintenance),
			Note:              in.Note,
			Owner:             in.Owner,
			CreatedAt:         now,
			UpdatedAt:         now,
		})
		if err != nil {
			return fmt.Errorf("site: insert: %w", err)
		}
		if err := rewriteRecords(ctx, txq, row.ID, in); err != nil {
			return err
		}
		stored, err = s.assemble(ctx, txq, row)
		return err
	})
	if err != nil {
		return Site{}, err
	}
	return stored, nil
}

// UpdateSite validates the record, then replaces the site and all of its sub-records and
// returns the stored form. If any host of the new record already belongs to another site the
// write is refused with ErrHostTaken; the site's own hosts may be kept or reordered. A system
// site only takes changes to its template switches and note/owner; any other change is
// refused with ErrSystemLocked (S-05).
func (s *Store) UpdateSite(ctx context.Context, id int64, in Site) (Site, error) {
	return s.updateSite(ctx, id, in, true)
}

// PreviewUpdateSite is UpdateSite without the commit: every check runs, the transaction is rolled
// back and the record as it would be stored is returned (see PreviewCreateSite).
func (s *Store) PreviewUpdateSite(ctx context.Context, id int64, in Site) (Site, error) {
	return s.updateSite(ctx, id, in, false)
}

func (s *Store) updateSite(ctx context.Context, id int64, in Site, commit bool) (Site, error) {
	if err := s.validate.Validate(ctx, in); err != nil {
		return Site{}, err
	}
	if err := checkSystemShape(in); err != nil {
		return Site{}, err
	}
	n, err := normalize(in)
	if err != nil {
		return Site{}, err
	}
	var stored Site
	err = s.transactMode(ctx, commit, func(txq *db.Queries) error {
		// The lock compares against the record as stored inside this transaction, so a
		// concurrent write cannot slip a locked change past it (S-05).
		oldRow, err := txq.GetSite(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("site: get %d: %w", id, err)
		}
		old, err := s.assemble(ctx, txq, oldRow)
		if err != nil {
			return err
		}
		if err := checkSystemUpdate(old, in); err != nil {
			return err
		}
		row, err := txq.UpdateSite(ctx, db.UpdateSiteParams{
			Kind:              in.Kind,
			OpenReason:        n.openReason,
			SystemTemplate:    n.systemTemplate,
			SystemConfig:      in.SystemConfig,
			Roles:             n.roles,
			TargetRoles:       n.targetRoles,
			Cert:              in.Cert,
			TargetKind:        in.TargetKind,
			TargetUrl:         in.TargetURL,
			TargetTlsInsecure: boolToInt(in.TargetTLSInsecure),
			Magicdns:          boolToInt(in.MagicDNS),
			Maintenance:       boolToInt(in.Maintenance),
			Note:              in.Note,
			Owner:             in.Owner,
			UpdatedAt:         time.Now().UTC().Format(timeFormat),
			ID:                id,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("site: update %d: %w", id, err)
		}
		// The site's own hosts still sit in site_hosts, so the check lets them through.
		if err := checkHosts(ctx, txq, id, in.Hosts); err != nil {
			return err
		}
		if err := rewriteRecords(ctx, txq, id, in); err != nil {
			return err
		}
		stored, err = s.assemble(ctx, txq, row)
		return err
	})
	if err != nil {
		return Site{}, err
	}
	return stored, nil
}

// GetSite reads one site with all of its sub-records. The whole read runs in a single
// transaction, so a concurrent UpdateSite that commits mid-read can never mix the main row of
// one version with the sub-records of another: the transaction sees one consistent snapshot.
func (s *Store) GetSite(ctx context.Context, id int64) (Site, error) {
	var stored Site
	err := s.transact(ctx, func(txq *db.Queries) error {
		row, err := txq.GetSite(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("site: get %d: %w", id, err)
		}
		site, err := s.assemble(ctx, txq, row)
		if err != nil {
			return err
		}
		stored = site
		return nil
	})
	if err != nil {
		return Site{}, err
	}
	return stored, nil
}

// ListSites reads every site with all of its sub-records, in id order. Like GetSite, the whole
// read runs in a single transaction snapshot, so a listing can never mix versions of a site
// that a concurrent write commits mid-read.
func (s *Store) ListSites(ctx context.Context) ([]Site, error) {
	var out []Site
	err := s.transact(ctx, func(txq *db.Queries) error {
		rows, err := txq.ListSites(ctx)
		if err != nil {
			return fmt.Errorf("site: list: %w", err)
		}
		out = make([]Site, 0, len(rows))
		for _, row := range rows {
			site, err := s.assemble(ctx, txq, row)
			if err != nil {
				return err
			}
			out = append(out, site)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteSite removes a site and, through the schema's ON DELETE CASCADE, all of its
// sub-records, which frees its hostnames for reuse. A system site cannot be deleted: the
// write is refused with ErrSystemLocked (S-05).
func (s *Store) DeleteSite(ctx context.Context, id int64) error {
	return s.deleteSite(ctx, id, true)
}

// PreviewDeleteSite is DeleteSite without the commit: it reports whether the delete would be
// accepted (not found, system lock) and leaves the site in place.
func (s *Store) PreviewDeleteSite(ctx context.Context, id int64) error {
	return s.deleteSite(ctx, id, false)
}

func (s *Store) deleteSite(ctx context.Context, id int64, commit bool) error {
	return s.transactMode(ctx, commit, func(txq *db.Queries) error {
		row, err := txq.GetSite(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("site: get %d: %w", id, err)
		}
		if row.Kind == KindSystem {
			return fmt.Errorf("%w: the %s site cannot be deleted", ErrSystemLocked, row.SystemTemplate.String)
		}
		deleted, err := txq.DeleteSite(ctx, id)
		if err != nil {
			return fmt.Errorf("site: delete %d: %w", id, err)
		}
		if deleted == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// checkTemplateFree refuses a second system site of the same template: each template exists
// once (ADR 0010), so a duplicate would render two blocks from one template.
func checkTemplateFree(ctx context.Context, q *db.Queries, in Site) error {
	if in.Kind != KindSystem {
		return nil
	}
	rows, err := q.ListSites(ctx)
	if err != nil {
		return fmt.Errorf("site: list for template check: %w", err)
	}
	for _, row := range rows {
		if row.SystemTemplate.Valid && row.SystemTemplate.String == in.SystemTemplate {
			return fmt.Errorf("%w: the %s site already exists", ErrSystemLocked, in.SystemTemplate)
		}
	}
	return nil
}

// transact runs fn in one transaction, rolling everything back when fn fails.
func (s *Store) transact(ctx context.Context, fn func(txq *db.Queries) error) error {
	return s.transactMode(ctx, true, fn)
}

// transactMode is transact with a switch: without commit the transaction is always rolled back,
// which is how the Preview methods run a write for its checks and result only.
func (s *Store) transactMode(ctx context.Context, commit bool, fn func(txq *db.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("site: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op once Commit has succeeded
	if err := fn(s.q.WithTx(tx)); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("site: commit: %w", err)
	}
	return nil
}

// normalized is the storage form of the fields that need conversion before they reach SQL.
type normalized struct {
	openReason     sql.NullString
	systemTemplate sql.NullString
	roles          string
	targetRoles    string
}

// normalize checks the kind pairings the schema's CHECK constraints pin (ADR 0010: an open
// reason only on open sites, a system template only on system sites, roles only on role sites,
// target roles only on open sites) and converts the list fields to their storage form. It does
// not judge field contents: that is the validation layer's job (F2-003).
func normalize(in Site) (normalized, error) {
	var n normalized
	switch in.Kind {
	case KindRole, KindOpen, KindSystem:
	default:
		return n, fmt.Errorf("site: unknown kind %q", in.Kind)
	}
	if in.Kind == KindOpen {
		if in.OpenReason != OpenReasonIntentional && in.OpenReason != OpenReasonTransition {
			return n, fmt.Errorf("site: open site needs open_reason %s or %s, got %q",
				OpenReasonIntentional, OpenReasonTransition, in.OpenReason)
		}
		n.openReason = sql.NullString{String: in.OpenReason, Valid: true}
	} else if in.OpenReason != "" {
		return n, fmt.Errorf("site: kind %q cannot have an open_reason", in.Kind)
	}
	if in.Kind == KindSystem {
		switch in.SystemTemplate {
		case TemplateZitadel, TemplateHeadscale, TemplateWireGuardUI, TemplateTagcess:
		default:
			return n, fmt.Errorf("site: unknown system template %q", in.SystemTemplate)
		}
		n.systemTemplate = sql.NullString{String: in.SystemTemplate, Valid: true}
	} else if in.SystemTemplate != "" {
		return n, fmt.Errorf("site: kind %q cannot have a system template", in.Kind)
	}
	if in.Kind != KindRole && len(in.Roles) > 0 {
		return n, fmt.Errorf("site: kind %q cannot have roles", in.Kind)
	}
	if in.Kind != KindOpen && len(in.TargetRoles) > 0 {
		return n, fmt.Errorf("site: kind %q cannot have target roles", in.Kind)
	}
	n.roles = marshalList(in.Roles)
	n.targetRoles = marshalList(in.TargetRoles)
	return n, nil
}

// checkHosts refuses a write that would give a site a hostname owned by another site
// (F2-002 AC2). Hosts of site ownID pass, so an update may keep or reorder them. A new site
// has no id yet and passes 0, which no real site id equals, so any owner is a conflict.
func checkHosts(ctx context.Context, q *db.Queries, ownID int64, hosts []string) error {
	for _, host := range hosts {
		owner, err := q.GetHostOwner(ctx, host)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("site: check host %q: %w", host, err)
		}
		if owner != ownID {
			return fmt.Errorf("site: host %q: %w", host, ErrHostTaken)
		}
	}
	return nil
}

// rewriteRecords replaces every sub-record of the site with the given ordered lists. It runs
// inside the caller's transaction. Host insertions map the site_hosts.hostname unique index
// backstop to ErrHostTaken (the driver enables extended result codes, so the violation carries
// SQLITE_CONSTRAINT_UNIQUE).
func rewriteRecords(ctx context.Context, q *db.Queries, siteID int64, in Site) error {
	if err := q.DeleteSiteHosts(ctx, siteID); err != nil {
		return fmt.Errorf("site: clear hosts: %w", err)
	}
	for i, host := range in.Hosts {
		err := q.InsertSiteHost(ctx, db.InsertSiteHostParams{
			SiteID:   siteID,
			Position: int64(i + 1),
			Hostname: host,
		})
		if err != nil {
			var serr *sqlite.Error
			if errors.As(err, &serr) && serr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
				return fmt.Errorf("site: host %q: %w", host, ErrHostTaken)
			}
			return fmt.Errorf("site: insert host %q: %w", host, err)
		}
	}
	if err := q.DeleteSiteAPIRules(ctx, siteID); err != nil {
		return fmt.Errorf("site: clear api rules: %w", err)
	}
	for i, rule := range in.APIRules {
		if err := q.InsertSiteAPIRule(ctx, db.InsertSiteAPIRuleParams{
			SiteID:   siteID,
			Position: int64(i + 1),
			Type:     rule.Type,
			Value:    rule.Value,
		}); err != nil {
			return fmt.Errorf("site: insert api rule %q: %w", rule.Type, err)
		}
	}
	if err := q.DeleteSiteRedirects(ctx, siteID); err != nil {
		return fmt.Errorf("site: clear redirects: %w", err)
	}
	for i, redirect := range in.Redirects {
		if err := q.InsertSiteRedirect(ctx, db.InsertSiteRedirectParams{
			SiteID:     siteID,
			Position:   int64(i + 1),
			SourcePath: redirect.Source,
			Target:     redirect.Target,
			Code:       int64(redirect.Code),
		}); err != nil {
			return fmt.Errorf("site: insert redirect %q: %w", redirect.Source, err)
		}
	}
	if err := q.DeleteSiteHeaders(ctx, siteID); err != nil {
		return fmt.Errorf("site: clear headers: %w", err)
	}
	for i, header := range in.Headers {
		if err := q.InsertSiteHeader(ctx, db.InsertSiteHeaderParams{
			SiteID:   siteID,
			Position: int64(i + 1),
			Name:     header.Name,
			Value:    header.Value,
		}); err != nil {
			return fmt.Errorf("site: insert header %q: %w", header.Name, err)
		}
	}
	return nil
}

// assemble combines a sites row with its sub-records into the stored form.
func (s *Store) assemble(ctx context.Context, q *db.Queries, row db.Site) (Site, error) {
	hostRows, err := q.ListSiteHosts(ctx, row.ID)
	if err != nil {
		return Site{}, fmt.Errorf("site: list hosts of %d: %w", row.ID, err)
	}
	hosts := make([]string, 0, len(hostRows))
	for _, h := range hostRows {
		hosts = append(hosts, h.Hostname)
	}

	ruleRows, err := q.ListSiteAPIRules(ctx, row.ID)
	if err != nil {
		return Site{}, fmt.Errorf("site: list api rules of %d: %w", row.ID, err)
	}
	rules := make([]APIRule, 0, len(ruleRows))
	for _, r := range ruleRows {
		rules = append(rules, APIRule{Type: r.Type, Value: r.Value})
	}

	redirectRows, err := q.ListSiteRedirects(ctx, row.ID)
	if err != nil {
		return Site{}, fmt.Errorf("site: list redirects of %d: %w", row.ID, err)
	}
	redirects := make([]Redirect, 0, len(redirectRows))
	for _, r := range redirectRows {
		redirects = append(redirects, Redirect{Source: r.SourcePath, Target: r.Target, Code: int(r.Code)})
	}

	headerRows, err := q.ListSiteHeaders(ctx, row.ID)
	if err != nil {
		return Site{}, fmt.Errorf("site: list headers of %d: %w", row.ID, err)
	}
	headers := make([]Header, 0, len(headerRows))
	for _, h := range headerRows {
		headers = append(headers, Header{Name: h.Name, Value: h.Value})
	}

	roles, err := unmarshalList(row.Roles)
	if err != nil {
		return Site{}, err
	}
	targetRoles, err := unmarshalList(row.TargetRoles)
	if err != nil {
		return Site{}, err
	}
	createdAt, err := parseTime(row.CreatedAt)
	if err != nil {
		return Site{}, err
	}
	updatedAt, err := parseTime(row.UpdatedAt)
	if err != nil {
		return Site{}, err
	}

	return Site{
		ID:                row.ID,
		Hosts:             hosts,
		Kind:              row.Kind,
		OpenReason:        row.OpenReason.String,
		SystemTemplate:    row.SystemTemplate.String,
		SystemConfig:      row.SystemConfig,
		Roles:             roles,
		TargetRoles:       targetRoles,
		Cert:              row.Cert,
		TargetKind:        row.TargetKind,
		TargetURL:         row.TargetUrl,
		TargetTLSInsecure: row.TargetTlsInsecure != 0,
		MagicDNS:          row.Magicdns != 0,
		Maintenance:       row.Maintenance != 0,
		Note:              row.Note,
		Owner:             row.Owner,
		APIRules:          rules,
		Redirects:         redirects,
		Headers:           headers,
		CreatedAt:         createdAt,
		UpdatedAt:         updatedAt,
	}, nil
}

// parseTime reads back the fixed-width timestamps this package writes.
func parseTime(stored string) (time.Time, error) {
	t, err := time.Parse(timeFormat, stored)
	if err != nil {
		return time.Time{}, fmt.Errorf("site: parse time %q: %w", stored, err)
	}
	return t, nil
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
