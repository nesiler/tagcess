package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/netpolicy"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store/db"
)

// The installer's read-only CLI (F6-004, [Ö]): the verify phase and k8s_access get the first-import parity and
// the RBAC manifest without the web UI and without forging identity headers (NFR-02). Neither command writes a
// file, a database row, Caddy's config, Headscale or Zitadel. -import-preview asks Caddy only to adapt (POST
// /adapt converts text; it loads nothing); -k8s-manifest makes no network call at all.

// Exit codes of -import-preview.
const (
	previewEqual = 0
	previewError = 1
	previewDiff  = 3
)

// previewTimeout bounds the Caddy adapt calls of one preview.
const previewTimeout = 60 * time.Second

// importPreview is the -import-preview report (stdout, JSON). It carries names and counts only: no secret
// file is read.
type importPreview struct {
	Imported   bool     `json:"imported"`
	Pending    bool     `json:"pending"`
	Parity     string   `json:"parity"` // equal | accepted | diff | not_compared
	DiffCount  int      `json:"diff_count"`
	FirstDiffs []string `json:"first_diffs,omitempty"`
	// Accepted lists the site blocks that differ only by the accepted class (render.AcceptedS06OpenStart); parity
	// is then "accepted", never "equal". Narrower lists the blocks whose generated form lets fewer sources in.
	Accepted     []render.AcceptedDifference `json:"accepted,omitempty"`
	Narrower     []render.NarrowerDifference `json:"narrower,omitempty"`
	SeedSites    int                         `json:"seed_sites"`
	ManualDNS    []manualView                `json:"manual_dns"`
	ManualDNSErr string                      `json:"manual_dns_error,omitempty"`
	Error        string                      `json:"error,omitempty"`
}

type manualView struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// maxReportedDiffs caps first_diffs; diff_count keeps the full number.
const maxReportedDiffs = 20

var moreDiffs = regexp.MustCompile(`^\.\.\. and (\d+) more differences$`)

// openReadOnly opens the tagcess database read-only, without migrating it. A database that has no WAL file
// (nothing writing it now) is opened immutable, so not even SQLite's shared-memory file is created.
func openReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	q := url.Values{"mode": {"ro"}, "_busy_timeout": {"5000"}}
	if _, err := os.Stat(path + "-wal"); errors.Is(err, os.ErrNotExist) {
		q.Set("immutable", "1")
	}
	dsn := url.URL{Scheme: "file", OmitHost: true, Path: path, RawQuery: q.Encode()}
	sqldb, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, err
	}
	return sqldb, nil
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// runImportPreview reports whether the seed's Caddyfile means today's file (ADR 0010, the same comparison as the
// UI's first-import screen). 0 equal or already imported, 3 different, 1 error.
func runImportPreview(cfg *config.Config, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), previewTimeout)
	defer cancel()
	rep := importPreview{Parity: "not_compared", ManualDNS: []manualView{}}
	fail := func(format string, a ...any) int {
		rep.Error = fmt.Sprintf(format, a...)
		writeJSON(stdout, rep)
		_, _ = fmt.Fprintf(stderr, "tagcess: import preview: %s\n", rep.Error)
		return previewError
	}

	dbPath := filepath.Join(cfg.DataDir, dbName)
	sqldb, err := openReadOnly(ctx, dbPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// No database yet (tagcess never started): the gate is open by definition.
	case err != nil:
		return fail("open %s read-only: %v", dbPath, err)
	default:
		defer func() { _ = sqldb.Close() }()
		pending, done, err := site.ReadFirstImportState(ctx, db.New(sqldb))
		if err != nil {
			return fail("first-import state: %v", err)
		}
		rep.Pending = pending
		if done {
			// tagcess owns the Caddyfile now; there is nothing to compare (verify: "içe aktarıldı").
			rep.Imported = true
			writeJSON(stdout, rep)
			return previewEqual
		}
	}

	if cfg.Sites.SeedFile == "" {
		return fail("sites.seed_file is not set")
	}
	seed, err := os.ReadFile(cfg.Sites.SeedFile) // #nosec G304 -- operator-provided path
	if err != nil {
		return fail("read the seed: %v", err)
	}
	sites, err := site.PrepareSeed(seed, site.SeedOptions{TagcessHost: cfg.Sites.TagcessHost, ZitadelInternalSources: cfg.Sites.ZitadelInternalSources})
	if err != nil {
		return fail("seed: %v", err)
	}
	rep.SeedSites = len(sites)
	compared := site.WithTagcess(sites, cfg.Sites.TagcessHost)

	cf := change.NewCaddyFile(caddy.NewClient(cfg.Caddy.AdminURL), cfg.Caddy.CaddyfilePath)
	current, err := cf.Current(ctx)
	if err != nil {
		return fail("%v", err)
	}
	ccfg := render.CaddyConfig{
		ACMEEmail: cfg.Sites.ACMEEmail, S06Open: true, Certs: cfg.Sites.Certificates,
		ZitadelIssuer: cfg.Zitadel.Issuer, GateClientID: cfg.Gate.ClientID, LogoutReturnURL: logoutReturnURL(cfg),
		K8sUpstream: cfg.Sites.K8sUpstream,
	}
	res, err := render.SeedParity(ctx, cf.AdaptJSON, current, compared, ccfg)
	var parity *render.ParityError
	switch {
	case err == nil && len(res.Accepted) > 0:
		rep.Parity = "accepted"
		rep.Accepted = res.Accepted
	case err == nil:
		rep.Parity = "equal"
	case errors.As(err, &parity):
		rep.Parity = "diff"
		rep.Accepted, rep.Narrower = parity.Accepted, parity.Narrower
		lines := strings.Split(strings.TrimSpace(parity.Diff), "\n")
		rep.DiffCount = len(lines)
		if m := moreDiffs.FindStringSubmatch(lines[len(lines)-1]); m != nil {
			n, _ := strconv.Atoi(m[1])
			rep.DiffCount = len(lines) - 1 + n
		}
		rep.FirstDiffs = lines[:min(len(lines), maxReportedDiffs)]
	default:
		return fail("%v", err)
	}

	content, exists, err := readDNSFile(cfg.DNS.RecordsPath)
	if err != nil {
		rep.ManualDNSErr = err.Error()
	} else if manual, err := render.ImportManualDNS(content, exists, sites, render.DNSConfig{AValue: cfg.Sites.VPNAddress}); err != nil {
		rep.ManualDNSErr = err.Error()
	} else {
		for _, r := range manual {
			rep.ManualDNS = append(rep.ManualDNS, manualView{Name: r.Name, Type: r.Type, Value: r.Value})
		}
	}
	writeJSON(stdout, rep)
	warnAccepted(stderr, rep.Accepted)
	if rep.Parity == "diff" {
		return previewDiff
	}
	return previewEqual
}

// warnAccepted names the accepted difference on stderr: it widens access during the transition and is never
// passed silently (developer decision 2026-10-07).
func warnAccepted(stderr io.Writer, accepted []render.AcceptedDifference) {
	if len(accepted) == 0 {
		return
	}
	hosts := make([]string, 0, len(accepted))
	for _, a := range accepted {
		hosts = append(hosts, strings.Join(a.Hosts, ","))
	}
	_, _ = fmt.Fprintf(stderr, "tagcess: import preview: WARNING: accepted difference %s (%s) for %d sites: %s; "+
		"after the first import these sites are reachable from every source until S-06 is closed in the UI\n",
		accepted[0].Class, accepted[0].Description, len(accepted), strings.Join(hosts, " "))
}

func readDNSFile(path string) (string, bool, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-provided path
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

// runK8sManifest prints the read-only RBAC manifest the UI serves at /k8s/setup/manifest (same function, same
// inputs: the profile's namespaces, ServiceAccount tagcess/tagcess-reader unless named). No network call.
func runK8sManifest(cfg *config.Config, saNamespace, saName, namespaces string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ns []string
	if strings.TrimSpace(namespaces) != "" {
		for _, n := range strings.Split(namespaces, ",") {
			if n = strings.TrimSpace(n); n != "" {
				ns = append(ns, n)
			}
		}
	} else {
		sqldb, err := openReadOnly(ctx, filepath.Join(cfg.DataDir, dbName))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "tagcess: k8s manifest: no tagcess database to read the profile from (%v); save the profile at /k8s/setup or pass -k8s-namespaces\n", err)
			return 1
		}
		defer func() { _ = sqldb.Close() }()
		q := db.New(sqldb)
		p, err := k8s.NewProfileStore(sqldb, q, netpolicy.New(sqldb, q), time.Now).Get(ctx)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "tagcess: k8s manifest: connection profile: %v (save it at /k8s/setup or pass -k8s-namespaces)\n", err)
			return 1
		}
		ns = p.Namespaces
	}
	body, err := k8s.RBACManifest(ns, k8s.ServiceAccountRef{Namespace: saNamespace, Name: saName})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tagcess: k8s manifest: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(body)
	return 0
}
