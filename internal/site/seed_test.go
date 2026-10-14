package site

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
)

// seedFixturePath is the first-import seed (G-01): today's 21 Caddyfile blocks, 23 hosts.
const seedFixturePath = "../../test/fixtures/seed-sites.json"

const testTagcessHost = "tagcess.example.com"

func readSeedFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(seedFixturePath))
	if err != nil {
		t.Fatalf("read seed fixture: %v", err)
	}
	return data
}

// openSeedStore is openTestStore with the three example domains the seed hosts live under.
func openSeedStore(t *testing.T) *Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir()+"/tagcess.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := NewValidator(ValidatorConfig{
		AllowedDomains: []string{"example.com", "internal.example.org", "example.net"},
		AllowedTargets: []string{"100.64.0.5"},
	}, testRoles)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	s, err := New(st.DB(), st.Queries(), v)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func seedOpts() SeedOptions { return SeedOptions{TagcessHost: testTagcessHost} }

func allHosts(sites []Site) []string {
	var hosts []string
	for _, s := range sites {
		hosts = append(hosts, s.Hosts...)
	}
	slices.Sort(hosts)
	return hosts
}

// TestSiteSeed_Idempotent is AC1: loading the seed twice leaves one record per host (23 seed
// hosts plus the tagcess system host), and a site edited after the first load keeps its edit.
func TestSiteSeed_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := openSeedStore(t)
	data := readSeedFixture(t)

	first, err := s.LoadSeed(ctx, data, seedOpts())
	if err != nil {
		t.Fatalf("first LoadSeed: %v", err)
	}
	if first.Created != 22 || first.Existing != 0 {
		t.Fatalf("first load = %+v, want 22 created (21 seed sites + tagcess), 0 existing", first)
	}
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	hosts := allHosts(sites)
	if len(hosts) != 24 {
		t.Fatalf("hosts after the first load = %d, want 24 (23 + tagcess): %v", len(hosts), hosts)
	}
	if !slices.Contains(hosts, testTagcessHost) {
		t.Errorf("tagcess host %s missing", testTagcessHost)
	}

	// Edit one seeded site the way an operator would, then load the seed again.
	var mon Site
	for _, st := range sites {
		if st.Hosts[0] == "monitor.example.com" {
			mon = st
		}
	}
	if mon.ID == 0 {
		t.Fatal("monitor site not found")
	}
	mon.Roles = []string{"devops"}
	mon.Note = "edited after import"
	mon.MagicDNS = false
	edited, err := s.UpdateSite(ctx, mon.ID, mon)
	if err != nil {
		t.Fatalf("UpdateSite: %v", err)
	}

	second, err := s.LoadSeed(ctx, data, seedOpts())
	if err != nil {
		t.Fatalf("second LoadSeed: %v", err)
	}
	if second.Created != 0 || second.Existing != 22 {
		t.Fatalf("second load = %+v, want 0 created, 22 existing", second)
	}
	after, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(after) != 22 || len(allHosts(after)) != 24 {
		t.Fatalf("after the second load: %d sites, %d hosts, want 22 and 24", len(after), len(allHosts(after)))
	}
	got, err := s.GetSite(ctx, mon.ID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if !reflect.DeepEqual(got, edited) {
		t.Errorf("the second load overwrote an edited site\n got: %+v\nwant: %+v", got, edited)
	}
}

// TestSiteSeed_Records checks the seed content against R1 B-01: kinds, system templates with
// explicit keys (F2-005; the zitadel config is filled by the loader, F2-013), and the open
// reasons of the two open blocks.
func TestSiteSeed_Records(t *testing.T) {
	ctx := context.Background()
	s := openSeedStore(t)
	if _, err := s.LoadSeed(ctx, readSeedFixture(t), seedOpts()); err != nil {
		t.Fatalf("LoadSeed: %v", err)
	}
	sites, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	byHost := map[string]Site{}
	for _, st := range sites {
		byHost[st.Hosts[0]] = st
	}
	kinds := map[string]int{}
	for _, st := range sites {
		kinds[st.Kind]++
	}
	if kinds[KindRole] != 16 || kinds[KindOpen] != 2 || kinds[KindSystem] != 4 {
		t.Errorf("kinds = %v, want role 16, open 2, system 4", kinds)
	}
	for host, want := range map[string]string{
		"auth.example.com": `{"internal_sources":[],"login_paths":["/.well-known/*","/oauth/v2/*","/oidc/v1/*","/ui/v2/login","/ui/v2/login/*","/ui/login","/ui/login/*","/assets/v1/*"]}`,
		"hs.example.com":   `{"headplane":true}`,
		"vpn.example.com":  `{"enabled":true}`,
		testTagcessHost:    `{}`,
	} {
		st := byHost[host]
		if st.Kind != KindSystem || st.SystemConfig != want {
			t.Errorf("%s = kind %q config %q, want a system site with config %q", host, st.Kind, st.SystemConfig, want)
		}
	}
	for _, host := range []string{"store-staging.internal.example.org"} {
		if st := byHost[host]; st.Kind != KindOpen || st.OpenReason != OpenReasonTransition {
			t.Errorf("%s = %s/%s, want open/transition", host, st.Kind, st.OpenReason)
		}
	}
	// hs and vpn resolve from public DNS; every other seed host is a MagicDNS name (R1 B-05).
	for _, st := range sites {
		want := st.Hosts[0] != "hs.example.com" && st.Hosts[0] != "vpn.example.com"
		if st.MagicDNS != want {
			t.Errorf("%s magicdns = %v, want %v", st.Hosts[0], st.MagicDNS, want)
		}
	}
}

// TestSiteSeed_PrepareSeed pins what the first-import preview relies on: PrepareSeed returns the
// records exactly as LoadSeed stores them (the zitadel record filled from the settings, no tagcess
// record), and refuses a seed that carries the tagcess site.
func TestSiteSeed_PrepareSeed(t *testing.T) {
	ctx := context.Background()
	opts := SeedOptions{TagcessHost: testTagcessHost, ZitadelInternalSources: []string{"198.51.100.0/24", "127.0.0.1/32"}}
	prepared, err := PrepareSeed(readSeedFixture(t), opts)
	if err != nil {
		t.Fatalf("PrepareSeed: %v", err)
	}
	if len(prepared) != 21 {
		t.Fatalf("prepared %d sites, want the 21 of the seed (the tagcess record is not part of it)", len(prepared))
	}

	s := openSeedStore(t)
	if _, err := s.LoadSeed(ctx, readSeedFixture(t), opts); err != nil {
		t.Fatalf("LoadSeed: %v", err)
	}
	stored, err := s.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	byHost := map[string]Site{}
	for _, st := range stored {
		byHost[st.Hosts[0]] = st
	}
	for _, p := range prepared {
		st, ok := byHost[p.Hosts[0]]
		if !ok {
			t.Fatalf("%s was prepared but not stored", p.Hosts[0])
		}
		if p.SystemConfig != st.SystemConfig {
			t.Errorf("%s: prepared system_config %q, stored %q", p.Hosts[0], p.SystemConfig, st.SystemConfig)
		}
	}

	withTagcess := []byte(`{"sites":[{"hosts":["tagcess.example.com"],"kind":"system","system_template":"tagcess",
		"system_config":{},"cert":"auto","target":"k8s","magicdns":true,"note":""}]}`)
	if _, err := PrepareSeed(withTagcess, opts); err == nil {
		t.Error("a seed that carries the tagcess site was accepted")
	}
}

// TestSiteSeed_Refusals pins the fail-closed loader: a malformed or conflicting seed is refused
// as a whole and leaves the store untouched.
func TestSiteSeed_Refusals(t *testing.T) {
	ctx := context.Background()
	good := string(readSeedFixture(t))

	cases := []struct {
		name string
		seed string
		opts SeedOptions
		want string
	}{
		{"unknown top-level field", `{"sites":[],"extra":1}`, seedOpts(), "unknown field"},
		{"unknown site field", `{"sites":[{"hosts":["a.example.com"],"kind":"role","roles":["devops"],"cert":"auto","target":"k8s","bogus":true}]}`, seedOpts(), "unknown field"},
		{"trailing data", good + `{}`, seedOpts(), "trailing"},
		{"not json", `sites: []`, seedOpts(), "seed"},
		{"empty seed", `{"sites":[]}`, seedOpts(), "no sites"},
		{"tagcess host missing", good, SeedOptions{}, "tagcess host"},
		{"tagcess host invalid", good, SeedOptions{TagcessHost: "Tagcess.Example.com"}, "tagcess host"},
		{"tagcess host collides with a seed host", good, SeedOptions{TagcessHost: "monitor.example.com"}, "monitor.example.com"},
		{"seed carries its own tagcess site", strings.Replace(good,
			`"system_template": "wireguard_ui"`, `"system_template": "tagcess"`, 1), seedOpts(), "tagcess"},
		{"same host in two seed sites", `{"sites":[
			{"hosts":["a.example.com"],"kind":"role","roles":["devops"],"cert":"auto","target":"k8s"},
			{"hosts":["a.example.com"],"kind":"role","roles":["devops"],"cert":"auto","target":"k8s"}]}`, seedOpts(), "a.example.com"},
		{"unknown role", `{"sites":[{"hosts":["a.example.com"],"kind":"role","roles":["nope"],"cert":"auto","target":"k8s"}]}`, seedOpts(), "nope"},
		{"foreign domain", `{"sites":[{"hosts":["a.evil.example"],"kind":"role","roles":["devops"],"cert":"auto","target":"k8s"}]}`, seedOpts(), "allowed domain"},
		{"host with a caddyfile injection", `{"sites":[{"hosts":["a.example.com {\n respond 200\n}\nb.example.com"],"kind":"role","roles":["devops"],"cert":"auto","target":"k8s"}]}`, seedOpts(), "hosts"},
		{"role with a caddyfile injection", `{"sites":[{"hosts":["a.example.com"],"kind":"role","roles":["devops\nimport evil"],"cert":"auto","target":"k8s"}]}`, seedOpts(), "roles"},
		{"cert with a path trick", `{"sites":[{"hosts":["a.example.com"],"kind":"role","roles":["devops"],"cert":"le:../../etc/x","target":"k8s"}]}`, seedOpts(), "cert"},
		{"api regex with a backtick", `{"sites":[{"hosts":["a.example.com"],"kind":"role","roles":["devops"],"cert":"auto","target":"k8s","api_rules":[{"type":"path_regex","value":"^/a` + "`" + `"}]}]}`, seedOpts(), "api_rules"},
		{"redirect to a foreign host", `{"sites":[{"hosts":["a.example.com"],"kind":"role","roles":["devops"],"cert":"auto","target":"k8s","redirects":[{"source":"/x","target":"https://evil.example/","code":302}]}]}`, seedOpts(), "redirects"},
		{"system config that is not canonical", strings.Replace(good, `"headplane": true`, `"headplane": "yes"`, 1), seedOpts(), "system_config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openSeedStore(t)
			_, err := s.LoadSeed(ctx, []byte(tc.seed), tc.opts)
			if err == nil {
				t.Fatalf("LoadSeed accepted %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			sites, lerr := s.ListSites(ctx)
			if lerr != nil {
				t.Fatalf("ListSites: %v", lerr)
			}
			if len(sites) != 0 {
				t.Errorf("a refused seed left %d sites behind", len(sites))
			}
		})
	}
}

// TestSiteSeed_ConflictingExisting: a seed site that shares only some hosts with an existing site
// is a conflict, never a merge or an overwrite.
func TestSiteSeed_ConflictingExisting(t *testing.T) {
	ctx := context.Background()
	s := openSeedStore(t)
	// projects-auth and storage-api are one block in the seed; here a site owns only projects-auth.
	own := Site{
		Hosts: []string{"projects-auth.example.com"}, Kind: KindRole, Roles: []string{"devops"},
		Cert: "auto", TargetKind: TargetK8s,
	}
	created, err := s.CreateSite(ctx, own)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	_, err = s.LoadSeed(ctx, readSeedFixture(t), seedOpts())
	if !errors.Is(err, ErrHostTaken) {
		t.Fatalf("LoadSeed error = %v, want ErrHostTaken", err)
	}
	sites, _ := s.ListSites(ctx)
	if len(sites) != 1 {
		t.Errorf("the conflicting seed left %d sites, want only the existing one", len(sites))
	}
	got, _ := s.GetSite(ctx, created.ID)
	if !reflect.DeepEqual(got, created) {
		t.Errorf("the existing site changed: %+v", got)
	}
}

// TestSiteSeed_FirstImportState: loading the seed into an empty store opens the first-import
// gate; completing it closes the gate for good, and a re-load never re-opens it.
func TestSiteSeed_FirstImportState(t *testing.T) {
	ctx := context.Background()
	s := openSeedStore(t)

	pending, err := s.FirstImportPending(ctx)
	if err != nil || pending {
		t.Fatalf("fresh store: pending=%v err=%v, want false/nil", pending, err)
	}
	if _, err := s.LoadSeed(ctx, readSeedFixture(t), seedOpts()); err != nil {
		t.Fatalf("LoadSeed: %v", err)
	}
	if pending, err = s.FirstImportPending(ctx); err != nil || !pending {
		t.Fatalf("after the seed: pending=%v err=%v, want true/nil", pending, err)
	}
	if err := s.CompleteFirstImport(ctx); err != nil {
		t.Fatalf("CompleteFirstImport: %v", err)
	}
	if pending, err = s.FirstImportPending(ctx); err != nil || pending {
		t.Fatalf("after completion: pending=%v err=%v, want false/nil", pending, err)
	}
	if _, err := s.LoadSeed(ctx, readSeedFixture(t), seedOpts()); err != nil {
		t.Fatalf("re-LoadSeed: %v", err)
	}
	if pending, err = s.FirstImportPending(ctx); err != nil || pending {
		t.Errorf("a re-load re-opened the gate: pending=%v err=%v", pending, err)
	}
}

// TestSiteSeed_FirstImportUnknownState: an unreadable state value fails closed with an error, not
// a silent "no gate".
func TestSiteSeed_FirstImportUnknownState(t *testing.T) {
	ctx := context.Background()
	s := openSeedStore(t)
	if err := s.q.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingFirstImport, Value: "garbage", UpdatedAt: "2026-10-01T00:00:00.000Z"}); err != nil {
		t.Fatalf("UpsertSetting: %v", err)
	}
	if _, err := s.FirstImportPending(ctx); err == nil {
		t.Error("FirstImportPending accepted an unknown state value")
	}
}

// TestSiteSeed_ManualDNSRecords is AC4: old extra-records that are not site hosts stay as manual
// records; site-derived ones are re-derived from the sites and not copied.
func TestSiteSeed_ManualDNSRecords(t *testing.T) {
	const vpnAddr = "100.64.0.4"
	sites := []Site{
		{Hosts: []string{"monitor.example.com", "docs.example.com"}, Kind: KindRole, MagicDNS: true},
		{Hosts: []string{"hs.example.com"}, Kind: KindSystem, MagicDNS: false},
	}
	a := func(name, value string) dns.Record { return dns.Record{Name: name, Type: dns.TypeA, Value: value} }

	t.Run("splits site records from manual ones", func(t *testing.T) {
		old := []dns.Record{
			a("monitor.example.com", vpnAddr),
			a("docs.example.com", vpnAddr),
			a("old-db.example.com", "100.64.0.9"),
			{Name: "v6.example.com", Type: dns.TypeAAAA, Value: "fd7a:115c:a1e0::9"},
		}
		got, err := SplitDNSRecords(old, sites, vpnAddr)
		if err != nil {
			t.Fatalf("SplitDNSRecords: %v", err)
		}
		want := []dns.Record{
			a("old-db.example.com", "100.64.0.9"),
			{Name: "v6.example.com", Type: dns.TypeAAAA, Value: "fd7a:115c:a1e0::9"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("manual = %+v, want %+v", got, want)
		}
	})

	t.Run("a site host with a different value is kept, not dropped", func(t *testing.T) {
		old := []dns.Record{a("monitor.example.com", "100.64.0.77")}
		got, err := SplitDNSRecords(old, sites, vpnAddr)
		if err != nil {
			t.Fatalf("SplitDNSRecords: %v", err)
		}
		if !reflect.DeepEqual(got, old) {
			t.Errorf("manual = %+v, want the divergent record kept: %+v", got, old)
		}
	})

	t.Run("a site host with magicdns off is kept", func(t *testing.T) {
		old := []dns.Record{a("hs.example.com", vpnAddr)}
		got, err := SplitDNSRecords(old, sites, vpnAddr)
		if err != nil {
			t.Fatalf("SplitDNSRecords: %v", err)
		}
		if !reflect.DeepEqual(got, old) {
			t.Errorf("manual = %+v, want %+v", got, old)
		}
	})

	t.Run("every record of today's file is accounted for", func(t *testing.T) {
		old := []dns.Record{a("monitor.example.com", vpnAddr), a("other.example.com", "100.64.0.9")}
		got, err := SplitDNSRecords(old, sites, vpnAddr)
		if err != nil {
			t.Fatalf("SplitDNSRecords: %v", err)
		}
		if len(got) != 1 || got[0].Name != "other.example.com" {
			t.Errorf("manual = %+v", got)
		}
	})

	t.Run("an invalid record or address is refused", func(t *testing.T) {
		if _, err := SplitDNSRecords([]dns.Record{{Name: "Bad Name", Type: dns.TypeA, Value: vpnAddr}}, sites, vpnAddr); err == nil {
			t.Error("an invalid record was imported")
		}
		if _, err := SplitDNSRecords(nil, sites, "not-an-ip"); err == nil {
			t.Error("an invalid vpn address was accepted")
		}
	})

	t.Run("an empty old file leaves no manual records", func(t *testing.T) {
		got, err := SplitDNSRecords(nil, sites, vpnAddr)
		if err != nil || len(got) != 0 {
			t.Errorf("got %+v, %v", got, err)
		}
	})
}
