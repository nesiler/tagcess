package site

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nesiler/tagcess/internal/store"
)

// openTestStore opens a migrated temporary database and a validated site store over it.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(st.DB(), st.Queries(), newTestValidator(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// roleSite is a fully populated role-controlled site; the lists are deliberately in a
// non-alphabetical order so a lost ordering cannot pass unnoticed (AC1).
func roleSite() Site {
	return Site{
		Hosts:       []string{"git.example.com", "git-dev.example.com"},
		Kind:        KindRole,
		Roles:       []string{"developer", "devops"},
		TargetRoles: []string{},
		Cert:        "le:example",
		TargetKind:  TargetK8s,
		MagicDNS:    true,
		Note:        "git sitesi",
		Owner:       "devops@example.com",
		APIRules:    []APIRule{{Type: APIRuleHeaderPresent, Value: "Authorization"}},
		Redirects:   []Redirect{{Source: "/old", Target: "/new", Code: 301}},
		Headers:     []Header{{Name: "X-Frame-Options", Value: "DENY"}},
	}
}

// openSite is an open site in transition with a url target (S-02.5 fields).
func openSite() Site {
	return Site{
		Hosts:             []string{"blog-admin.example.com"},
		Kind:              KindOpen,
		OpenReason:        OpenReasonTransition,
		Roles:             []string{},
		TargetRoles:       []string{"developer"},
		Cert:              "auto",
		TargetKind:        TargetURL,
		TargetURL:         "https://100.64.0.5:30443",
		TargetTLSInsecure: true,
		MagicDNS:          false,
		Maintenance:       true,
		APIRules:          []APIRule{},
		Redirects:         []Redirect{},
		Headers:           []Header{},
	}
}

// systemSite is a locked system site with template-specific configuration. Since F2-005 the
// store holds system records to the canonical shape (ADR 0010); since F2-013 the zitadel
// template carries its internal source list and login paths on the record and no target of its
// own.
func systemSite() Site {
	return Site{
		Hosts:          []string{"auth.example.com"},
		Kind:           KindSystem,
		SystemTemplate: TemplateZitadel,
		SystemConfig:   `{"internal_sources":["10.8.0.0/24"],"login_paths":["/ui/login"]}`,
		Roles:          []string{},
		TargetRoles:    []string{},
		Cert:           "le:example",
		TargetKind:     TargetK8s,
		MagicDNS:       false,
		APIRules:       []APIRule{},
		Redirects:      []Redirect{},
		Headers:        []Header{},
	}
}

// assertSameFields compares every caller-supplied field, field by field, so a field the store
// fails to write or read back cannot slip through (AC1). ID and the timestamps are set by the
// store and checked separately; list fields must arrive in the exact order given (and non-nil).
func assertSameFields(t *testing.T, want, got Site) {
	t.Helper()
	if !reflect.DeepEqual(got.Hosts, want.Hosts) {
		t.Errorf("hosts = %v, want %v", got.Hosts, want.Hosts)
	}
	if got.Kind != want.Kind {
		t.Errorf("kind = %q, want %q", got.Kind, want.Kind)
	}
	if got.OpenReason != want.OpenReason {
		t.Errorf("open_reason = %q, want %q", got.OpenReason, want.OpenReason)
	}
	if got.SystemTemplate != want.SystemTemplate {
		t.Errorf("system_template = %q, want %q", got.SystemTemplate, want.SystemTemplate)
	}
	if got.SystemConfig != want.SystemConfig {
		t.Errorf("system_config = %q, want %q", got.SystemConfig, want.SystemConfig)
	}
	if !reflect.DeepEqual(got.Roles, want.Roles) {
		t.Errorf("roles = %v, want %v", got.Roles, want.Roles)
	}
	if !reflect.DeepEqual(got.TargetRoles, want.TargetRoles) {
		t.Errorf("target_roles = %v, want %v", got.TargetRoles, want.TargetRoles)
	}
	if got.Cert != want.Cert {
		t.Errorf("cert = %q, want %q", got.Cert, want.Cert)
	}
	if got.TargetKind != want.TargetKind {
		t.Errorf("target_kind = %q, want %q", got.TargetKind, want.TargetKind)
	}
	if got.TargetURL != want.TargetURL {
		t.Errorf("target_url = %q, want %q", got.TargetURL, want.TargetURL)
	}
	if got.TargetTLSInsecure != want.TargetTLSInsecure {
		t.Errorf("target_tls_insecure = %v, want %v", got.TargetTLSInsecure, want.TargetTLSInsecure)
	}
	if got.MagicDNS != want.MagicDNS {
		t.Errorf("magicdns = %v, want %v", got.MagicDNS, want.MagicDNS)
	}
	if got.Maintenance != want.Maintenance {
		t.Errorf("maintenance = %v, want %v", got.Maintenance, want.Maintenance)
	}
	if got.Note != want.Note {
		t.Errorf("note = %q, want %q", got.Note, want.Note)
	}
	if got.Owner != want.Owner {
		t.Errorf("owner = %q, want %q", got.Owner, want.Owner)
	}
	if !reflect.DeepEqual(got.APIRules, want.APIRules) {
		t.Errorf("api_rules = %#v, want %#v", got.APIRules, want.APIRules)
	}
	if !reflect.DeepEqual(got.Redirects, want.Redirects) {
		t.Errorf("redirects = %#v, want %#v", got.Redirects, want.Redirects)
	}
	if !reflect.DeepEqual(got.Headers, want.Headers) {
		t.Errorf("headers = %#v, want %#v", got.Headers, want.Headers)
	}
}

// assertRoundTrip writes in, reads it back by id and through ListSites, and checks that every
// field and the list orderings survived: first against the original input, then against the
// stored form the create returned. It returns the stored form.
func assertRoundTrip(t *testing.T, s *Store, in Site) Site {
	t.Helper()
	ctx := context.Background()

	created, err := s.CreateSite(ctx, in)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if created.ID <= 0 {
		t.Fatalf("CreateSite returned id %d, want > 0", created.ID)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("CreateSite returned zero timestamps (%v/%v)", created.CreatedAt, created.UpdatedAt)
	}
	// Every input field must have been stored (AC1) — comparing against the input catches a
	// field the store drops or rewrites.
	assertSameFields(t, in, created)

	got, err := s.GetSite(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSite(%d): %v", created.ID, err)
	}
	if got.ID != created.ID {
		t.Errorf("GetSite id = %d, want %d", got.ID, created.ID)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) || !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("GetSite timestamps = %v/%v, want %v/%v",
			got.CreatedAt, got.UpdatedAt, created.CreatedAt, created.UpdatedAt)
	}
	assertSameFields(t, created, got)

	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	var listed *Site
	for i := range sites {
		if sites[i].ID == created.ID {
			listed = &sites[i]
			break
		}
	}
	if listed == nil {
		t.Fatalf("ListSites did not return site %d", created.ID)
	}
	if !listed.CreatedAt.Equal(created.CreatedAt) || !listed.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("ListSites timestamps = %v/%v, want %v/%v",
			listed.CreatedAt, listed.UpdatedAt, created.CreatedAt, created.UpdatedAt)
	}
	assertSameFields(t, created, *listed)
	// ListSites must return sites in id order so callers cannot get a varying order.
	for i := 1; i < len(sites); i++ {
		if sites[i-1].ID >= sites[i].ID {
			t.Errorf("ListSites not in id order: %d before %d", sites[i-1].ID, sites[i].ID)
		}
	}
	return created
}

// AC1: saving a site with an ordered host/role list preserves the ordering and every field
// on re-read, for all three site kinds.
func TestSiteStore_RoundTrip(t *testing.T) {
	s := openTestStore(t)

	t.Run("role site keeps every field", func(t *testing.T) {
		assertRoundTrip(t, s, roleSite())
	})

	t.Run("open transition site keeps target roles and url target", func(t *testing.T) {
		assertRoundTrip(t, s, openSite())
	})

	t.Run("system site keeps template and config", func(t *testing.T) {
		assertRoundTrip(t, s, systemSite())
	})

	t.Run("list keeps all three kinds", func(t *testing.T) {
		sites, err := s.ListSites(context.Background())
		if err != nil {
			t.Fatalf("ListSites: %v", err)
		}
		if len(sites) != 3 {
			t.Fatalf("ListSites = %d sites, want 3", len(sites))
		}
		kinds := map[string]bool{}
		for _, s := range sites {
			kinds[s.Kind] = true
		}
		for _, kind := range []string{KindRole, KindOpen, KindSystem} {
			if !kinds[kind] {
				t.Errorf("ListSites missing a %q site", kind)
			}
		}
	})
}

// AC2: a host that already belongs to a site cannot be taken by a second site; the rejected
// write leaves every existing record untouched.
func TestSiteStore_UniqueHost(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	first, err := s.CreateSite(ctx, Site{
		Hosts:      []string{"shared.example.com", "first.example.com"},
		Kind:       KindRole,
		Roles:      []string{"devops"},
		Cert:       "auto",
		TargetKind: TargetK8s,
	})
	if err != nil {
		t.Fatalf("create first site: %v", err)
	}

	// A new site claiming an existing host is refused.
	second := Site{
		Hosts:      []string{"second.example.com", "shared.example.com"},
		Kind:       KindRole,
		Roles:      []string{"developer"},
		Cert:       "auto",
		TargetKind: TargetK8s,
	}
	if _, err := s.CreateSite(ctx, second); !errors.Is(err, ErrHostTaken) {
		t.Fatalf("CreateSite with a taken host: err = %v, want ErrHostTaken", err)
	}

	// The rejection preserved the existing record: unchanged fields, unchanged host list,
	// and no second site row.
	got, err := s.GetSite(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetSite after refused create: %v", err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Errorf("refused create changed the existing site:\n got %#v\nwant %#v", got, first)
	}
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites after refused create: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("ListSites = %d sites after refused create, want 1", len(sites))
	}

	// An update claiming a host owned by another site is refused as well.
	third, err := s.CreateSite(ctx, Site{
		Hosts:      []string{"third.example.com"},
		Kind:       KindRole,
		Roles:      []string{"devops"},
		Cert:       "auto",
		TargetKind: TargetK8s,
	})
	if err != nil {
		t.Fatalf("create third site: %v", err)
	}
	conflict := first
	conflict.Hosts = []string{"third.example.com"}
	if _, err := s.UpdateSite(ctx, first.ID, conflict); !errors.Is(err, ErrHostTaken) {
		t.Fatalf("UpdateSite with a taken host: err = %v, want ErrHostTaken", err)
	}
	got, err = s.GetSite(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetSite after refused update: %v", err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Errorf("refused update changed the existing site:\n got %#v\nwant %#v", got, first)
	}
	gotThird, err := s.GetSite(ctx, third.ID)
	if err != nil {
		t.Fatalf("GetSite(third) after refused update: %v", err)
	}
	if !reflect.DeepEqual(gotThird, third) {
		t.Errorf("refused update changed the other site:\n got %#v\nwant %#v", gotThird, third)
	}

	// Keeping and reordering a site's own hosts is not a conflict.
	moved := first
	moved.Hosts = []string{"first.example.com", "shared.example.com"}
	updated, err := s.UpdateSite(ctx, first.ID, moved)
	if err != nil {
		t.Fatalf("UpdateSite reordering own hosts: %v", err)
	}
	if !reflect.DeepEqual(updated.Hosts, moved.Hosts) {
		t.Errorf("reordered hosts = %v, want %v", updated.Hosts, moved.Hosts)
	}
}

// Store operations beyond the two acceptance criteria: delete cascades and frees its hosts,
// and missing sites are reported as ErrNotFound.
func TestSiteStore_Delete(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	created, err := s.CreateSite(ctx, Site{
		Hosts:      []string{"gone.example.com"},
		Kind:       KindRole,
		Roles:      []string{"devops"},
		Cert:       "auto",
		TargetKind: TargetK8s,
	})
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	if err := s.DeleteSite(ctx, created.ID); err != nil {
		t.Fatalf("DeleteSite: %v", err)
	}
	if _, err := s.GetSite(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSite after delete: err = %v, want ErrNotFound", err)
	}
	// The unique index must have been freed with the site (ON DELETE CASCADE).
	again, err := s.CreateSite(ctx, Site{
		Hosts:      []string{"gone.example.com"},
		Kind:       KindRole,
		Roles:      []string{"devops"},
		Cert:       "auto",
		TargetKind: TargetK8s,
	})
	if err != nil {
		t.Fatalf("recreate with the freed host: %v", err)
	}
	if again.ID == created.ID {
		t.Error("recreated site reused the deleted id")
	}
	if err := s.DeleteSite(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteSite(missing): err = %v, want ErrNotFound", err)
	}
}

// assertIntactVersion checks that a read site is one committed version: the host and the role
// carry the same version number. A torn read (main row from one commit, sub-records from
// another) pairs different numbers and fails.
func assertIntactVersion(t *testing.T, got Site) {
	t.Helper()
	if len(got.Hosts) != 1 || len(got.Roles) != 1 {
		t.Fatalf("site has hosts %v and roles %v, want one of each", got.Hosts, got.Roles)
	}
	var k int
	if _, err := fmt.Sscanf(got.Hosts[0], "h-%d.example.com", &k); err != nil {
		t.Fatalf("unexpected host %q: %v", got.Hosts[0], err)
	}
	want := fmt.Sprintf("role-%d", k)
	if got.Roles[0] != want {
		t.Fatalf("torn read: host %q came with role %q, want %q", got.Hosts[0], got.Roles[0], want)
	}
}

// A read must return one intact committed version even while updates commit concurrently: a
// concurrent writer rotates the host and the role together, and every GetSite/ListSites
// observation has to pair matching versions, never a mix of two commits.
func TestSiteStore_ReadConsistentUnderConcurrentUpdate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tagcess.db")
	readerPool, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reader store.Open: %v", err)
	}
	t.Cleanup(func() { _ = readerPool.Close() })
	writerPool, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("writer store.Open: %v", err)
	}
	t.Cleanup(func() { _ = writerPool.Close() })
	v, err := NewValidator(ValidatorConfig{
		AllowedDomains: []string{"example.com"},
		AllowedTargets: []string{"100.64.0.5"},
	}, funcRoles{n: 500})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	s, err := New(readerPool.DB(), readerPool.Queries(), v)
	if err != nil {
		t.Fatalf("reader New: %v", err)
	}
	w, err := New(writerPool.DB(), writerPool.Queries(), v)
	if err != nil {
		t.Fatalf("writer New: %v", err)
	}

	current, err := w.CreateSite(ctx, Site{
		Hosts:      []string{"h-0.example.com"},
		Kind:       KindRole,
		Roles:      []string{"role-0"},
		Cert:       "auto",
		TargetKind: TargetK8s,
	})
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	id := current.ID

	const versions = 500
	writerErr := make(chan error, 1)
	go func() {
		for k := 1; k < versions; k++ {
			// Every version pairs its host with its role; the two only change together.
			next := Site{
				Hosts:      []string{fmt.Sprintf("h-%d.example.com", k)},
				Kind:       KindRole,
				Roles:      []string{fmt.Sprintf("role-%d", k)},
				Cert:       "auto",
				TargetKind: TargetK8s,
			}
			if _, err := w.UpdateSite(ctx, id, next); err != nil {
				writerErr <- err
				return
			}
		}
		writerErr <- nil
	}()

	for {
		select {
		case err := <-writerErr:
			if err != nil {
				t.Fatalf("concurrent writer: %v", err)
			}
			// The writer is done: the last state must read back intact as well.
			got, err := s.GetSite(ctx, id)
			if err != nil {
				t.Fatalf("final GetSite: %v", err)
			}
			assertIntactVersion(t, got)
			sites, err := s.ListSites(ctx)
			if err != nil {
				t.Fatalf("final ListSites: %v", err)
			}
			for _, site := range sites {
				assertIntactVersion(t, site)
			}
			return
		default:
		}
		got, err := s.GetSite(ctx, id)
		if err != nil {
			t.Fatalf("GetSite: %v", err)
		}
		assertIntactVersion(t, got)
		sites, err := s.ListSites(ctx)
		if err != nil {
			t.Fatalf("ListSites: %v", err)
		}
		for _, site := range sites {
			assertIntactVersion(t, site)
		}
	}
}
