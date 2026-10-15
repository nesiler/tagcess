// Command tagcess is the access-management bridge for Caddy, Headscale and Zitadel.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nesiler/tagcess/internal/alert"
	"github.com/nesiler/tagcess/internal/audit"
	"github.com/nesiler/tagcess/internal/caddy"
	"github.com/nesiler/tagcess/internal/change"
	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/internal/dns"
	"github.com/nesiler/tagcess/internal/gitlog"
	"github.com/nesiler/tagcess/internal/groupsclaim"
	"github.com/nesiler/tagcess/internal/headscale"
	"github.com/nesiler/tagcess/internal/headscale/admin"
	"github.com/nesiler/tagcess/internal/hook"
	"github.com/nesiler/tagcess/internal/hostapply"
	"github.com/nesiler/tagcess/internal/hsadmin"
	"github.com/nesiler/tagcess/internal/k8s"
	"github.com/nesiler/tagcess/internal/maintenance"
	"github.com/nesiler/tagcess/internal/monitor"
	"github.com/nesiler/tagcess/internal/policydoc"
	"github.com/nesiler/tagcess/internal/policyrev"
	"github.com/nesiler/tagcess/internal/policywriter"
	"github.com/nesiler/tagcess/internal/render"
	"github.com/nesiler/tagcess/internal/setup"
	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/store/db"
	"github.com/nesiler/tagcess/internal/sync"
	"github.com/nesiler/tagcess/internal/version"
	"github.com/nesiler/tagcess/internal/vpnuser"
	"github.com/nesiler/tagcess/internal/web"
	"github.com/nesiler/tagcess/internal/zitadel"
)

const (
	// webhookPath is where the Zitadel Actions v2 target points (the listener itself is reachable
	// over Tailscale only; ADR 0003).
	webhookPath = "/hook"
	// groupsPath is where the Zitadel preuserinfo rest_call target for the groups claim points.
	groupsPath = "/groups"
	dbName     = "tagcess.db"
	// gitDirName is the artifact history repository under the data directory (A-02, ADR 0016).
	gitDirName = "artifact-git"
	// shutdownTimeout bounds the HTTP drain; the reconcile wait is the trigger's own timeout.
	shutdownTimeout = 10 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if version.IsVersionFlag(args) {
		_, _ = fmt.Fprintln(stdout, version.String("tagcess"))
		return 0
	}
	fs := flag.NewFlagSet("tagcess", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path of the YAML settings file (required)")
	check := fs.Bool("check", false, "validate the config and exit")
	healthcheck := fs.Bool("healthcheck", false, "probe the running server: the UI socket and the hook listener must accept connections (exit 0 ready, 1 not ready)")
	preview := fs.Bool("import-preview", false, "read-only first-import parity report as JSON (exit 0 equal, 3 different, 1 error)")
	manifest := fs.Bool("k8s-manifest", false, "print the read-only k8s RBAC manifest the UI serves (no network call)")
	saNamespace := fs.String("sa-namespace", "tagcess", "-k8s-manifest: namespace of the reader ServiceAccount")
	saName := fs.String("sa-name", k8s.DefaultServiceAccountName, "-k8s-manifest: name of the reader ServiceAccount")
	k8sNamespaces := fs.String("k8s-namespaces", "", "-k8s-manifest: comma-separated namespaces (default: the saved connection profile)")
	setupToken := fs.Bool("setup-token", false, "replace the setup token, end every setup session and print the new token (needs -config)")
	setupTokenFile := fs.String("setup-token-file", setup.DefaultTokenFile, "-setup-token: file the plain token is also written to")
	var boot bootstrapOptions
	bootstrap := fs.Bool("bootstrap-caddyfile", false, "print the installer's fresh-mode bootstrap Caddyfile for -seed (no -config; read-only)")
	fs.StringVar(&boot.seedPath, "seed", "", "-bootstrap-caddyfile: site seed JSON")
	fs.StringVar(&boot.acmeEmail, "acme-email", "", "-bootstrap-caddyfile: ACME e-mail of the global block")
	fs.StringVar(&boot.certs, "certs", "", "-bootstrap-caddyfile: comma-separated certificate names under /etc/letsencrypt/live")
	fs.StringVar(&boot.internalSources, "zitadel-internal-sources", "", "-bootstrap-caddyfile: comma-separated internal sources of the zitadel template")
	fs.StringVar(&boot.sitesImport, "sites-import", "sites/*.caddy", "-bootstrap-caddyfile: the import line of the sites directory (empty: none)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bootstrap {
		return runBootstrapCaddyfile(boot, stdout, stderr)
	}
	if *configPath == "" {
		_, _ = fmt.Fprintln(stderr, "tagcess: -config is required")
		fs.Usage()
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tagcess: %v\n", err)
		return 1
	}
	if *check {
		_, _ = fmt.Fprintln(stdout, "config ok")
		return 0
	}
	if *healthcheck {
		if err := probeServer(cfg, healthcheckTimeout); err != nil {
			_, _ = fmt.Fprintf(stderr, "tagcess: not ready: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, "ready")
		return 0
	}
	if *preview {
		return runImportPreview(cfg, stdout, stderr)
	}
	if *setupToken {
		return runSetupToken(cfg, *setupTokenFile, stdout, stderr)
	}
	if *manifest {
		return runK8sManifest(cfg, *saNamespace, *saName, *k8sNamespaces, stdout, stderr)
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))
	log.Info("tagcess starting", "version", version.Version, "commit", version.Commit)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, cfg, log); err != nil {
		_, _ = fmt.Fprintf(stderr, "tagcess: %v\n", err)
		return 1
	}
	return 0
}

// newHookMux builds the hook listener's mux: /hook always, and /groups (the Zitadel preuserinfo
// groups claim receiver, F1-026) only when a groups signing key is configured. Without it nothing
// answers /groups and the claim stays unset.
func newHookMux(hookHandler http.Handler, groupsKey []byte, projectID string, grants groupsclaim.GrantReader, onLogin func(), log *slog.Logger) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	mux.Handle(webhookPath, hookHandler)
	if len(groupsKey) == 0 {
		log.Info("groups claim endpoint is off (hook.groups_signing_key_file is not set)")
		return mux, nil
	}
	gh, err := groupsclaim.New(groupsclaim.Config{SigningKey: groupsKey, ProjectID: projectID, Grants: grants, OnRoles: onLogin, Logger: log})
	if err != nil {
		return nil, fmt.Errorf("groups claim handler: %w", err)
	}
	mux.Handle(groupsPath, gh)
	log.Info("groups claim endpoint is on", "path", groupsPath)
	return mux, nil
}

// serve wires every component and runs until ctx is canceled. The webhook listener and the
// debounced scheduler are the two long-running parts; the periodic reconcile is the scheduler's.
func serve(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	// Read secrets first: a missing key must stop startup before anything is opened (fail safe).
	key, err := os.ReadFile(string(cfg.Hook.SigningKeyFile)) // #nosec G304 -- operator-provided path
	if err != nil {
		return fmt.Errorf("read webhook signing key: %w", err)
	}

	var groupsKey []byte
	if f := string(cfg.Hook.GroupsSigningKeyFile); f != "" {
		groupsKey, err = os.ReadFile(f) // #nosec G304 -- operator-provided path
		if err != nil {
			return fmt.Errorf("read groups signing key: %w", err)
		}
	}

	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, dbName))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	// The UI key is created on first start (security.md §7); a bad key stops startup before the
	// interface is served.
	csrfKey, err := web.LoadOrCreateCSRFKey(filepath.Join(cfg.DataDir, "csrf-key"))
	if err != nil {
		return err
	}
	csrf, err := web.NewCSRF(csrfKey)
	if err != nil {
		return err
	}

	hs, err := headscale.New(headscale.Config{Target: cfg.Headscale.Socket})
	if err != nil {
		return err
	}
	defer func() { _ = hs.Close() }()

	// The admin client (F3-004) serves the Headscale management screens; the narrow F1 client
	// above stays the tool for the sync pipeline (R2 karar 19). Same socket, separate type.
	adminHS, err := admin.NewAdmin(headscale.Config{Target: cfg.Headscale.Socket})
	if err != nil {
		return err
	}
	defer func() { _ = adminHS.Close() }()

	zs, err := openZitadel(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = zs.Close() }()

	// The site layer (F2): the validator reads the vpn project roles from Zitadel and the editable
	// target allowlist from settings; config seeds that setting once, on first start.
	allowedTargets := site.NewAllowedTargets(st.DB(), st.Queries())
	if err := allowedTargets.SeedIfMissing(ctx, cfg.Sites.AllowedTargets); err != nil {
		return fmt.Errorf("seed allowed targets: %w", err)
	}
	validator, err := site.NewValidator(site.ValidatorConfig{
		AllowedDomains: cfg.Sites.AllowedDomains,
		TargetSource:   allowedTargets,
	}, zs)
	if err != nil {
		return err
	}
	siteStore, err := site.New(st.DB(), st.Queries(), validator)
	if err != nil {
		return err
	}

	// One audit logger serves the reconcile pipeline, the audit page and the sync page: all read the
	// same append-only table.
	auditor := audit.New(st.Queries())
	// The Headscale maintenance gate (H-07): the admin write pipeline refuses widening device and key
	// writes while a host config change is open (F3b-014).
	maint := maintenance.New(st.Queries())
	// The pipeline reads dry-run under its writer lock right before every write (Y-06), and the sync
	// page's toggle writes it under the same lock, so the two cannot interleave.
	// The local artifact history (F2-019, A-02): verified artifacts are committed under the data
	// directory, and a commit that had to be queued binds its late revision to the durable site
	// version (A-03.4). The site pipeline takes the same history (change.SiteConfig.Git).
	artifactGit, err := gitlog.New(gitlog.Config{
		Dir:       filepath.Join(cfg.DataDir, gitDirName),
		Auditor:   auditor,
		Alerter:   change.NewGitAlerter(st.Queries()),
		OnRetried: change.NewRevisionBinder(siteStore),
	})
	if err != nil {
		return err
	}
	// Every policy apply, the sync's included, is recorded as a revision (H-04, F3-010 AC12), so the
	// live policy never looks externally changed after tagcess wrote it.
	// The maintenance gate (H-07, F3b-015) stops every policy write while a Headscale host change runs.
	pipeline := change.New(hs, st.Queries(), auditor, st).WithGit(artifactGit).
		WithRevisions(policywriter.NewRecorder(policyrev.New(st.Queries()))).
		WithMaintenance(maintenance.New(st.Queries()))

	// The site change pipeline (F2-011) with its three artifact surfaces. The URI sync keeps the
	// oauth2-proxy app's redirect URIs in line with the site records (ADR 0012); the app is found
	// by name on first use. Startup does not depend on Zitadel (an outage must not take the
	// interface and the other safeguards down, F1-021 AC4): until the app is found every run is a
	// failed read, which blocks site changes and raises the drift alert.
	uriSync := zitadel.NewNamedURISync(zs, cfg.Zitadel.OAuth2ProxyApp, st.Queries())
	if ret := logoutReturnURL(cfg); ret != "" {
		uriSync.WithPostLogoutURI(ret)
	}
	if err := web.SetSignOut(cfg.Zitadel.Issuer, cfg.Gate.ClientID, logoutReturnURL(cfg)); err != nil {
		return fmt.Errorf("sign-out link: %w", err)
	}
	probeCtx, cancelProbe := context.WithTimeout(ctx, 10*time.Second)
	_, probeErr := zs.FindAppID(probeCtx, cfg.Zitadel.OAuth2ProxyApp)
	cancelProbe()
	if err := probeErr; err != nil {
		log.Warn("the oauth2-proxy app is not resolvable yet; site changes stay blocked until it is", "app", cfg.Zitadel.OAuth2ProxyApp, "err", err)
	}
	dnsFile := change.NewDNSFile(cfg.DNS.RecordsPath, dnsVerifier(cfg.DNS.Resolver))
	siteSettings := siteSettingsReader(st.Queries(), siteStore, cfg)
	// The monitoring loops are built after the site pipeline (buildF4 below); an applied site change
	// triggers them through this pointer so stale drift alerts are re-measured at once (F5 L3).
	var siteApplied atomic.Pointer[func()]
	sitePipeline, err := change.NewSite(change.SiteConfig{
		Queries: st.Queries(),
		Audit:   auditor,
		DryRun:  st,
		Sites:   siteStore,
		Caddy:   change.NewCaddyFile(caddy.NewClient(cfg.Caddy.AdminURL), cfg.Caddy.CaddyfilePath),
		DNS:     dnsFile,
		URIs:    uriSync,
		Git:     artifactGit,
		Settings: func(ctx context.Context) (change.SiteSettings, error) {
			return siteSettings(ctx)
		},
		// The first import records the live policy as the applied baseline, so the drift card can
		// compare it instead of staying "temel yok" (F5 I9).
		PolicyBaseline: func(ctx context.Context, actor string) error {
			live, err := hs.GetPolicy(ctx)
			if err != nil {
				return err
			}
			_, _, err = policyrev.New(st.Queries()).EnsureBaseline(ctx, live.Text, actor)
			return err
		},
		OnApplied: func() {
			if f := siteApplied.Load(); f != nil {
				(*f)()
			}
		},
	})
	if err != nil {
		return err
	}

	rec, err := sync.NewReconciler(sync.ReconcilerConfig{
		Zitadel:   zs,
		Headscale: hs,
		Pipeline:  pipeline,
		Queries:   st.Queries(),
		DryRun:    st,
		Issuer:    cfg.Zitadel.Issuer,
		// A reconcile the maintenance gate held becomes the durable pending intent (F3b-016).
		Maintenance: maint,
		// Usable personal pre-auth keys of users without a role or with a closed account are
		// expired through the admin pipeline as system:sync (F3-013, Y-04).
		Keys: sync.NewKeyRevoker(hsadmin.New(hsadmin.Config{Reader: adminHS, Audit: auditor, Store: st.Queries(), Log: log, Maintenance: maint}), adminHS, sync.SystemActor),
		// The periodic run also compares the oauth2-proxy app's redirect URIs with the site
		// records and raises the drift alert (Y-02, ADR 0012 step 6; F2-011 AC6).
		PeriodicCheck: sitePipeline.CheckURIDrift,
	})
	if err != nil {
		return err
	}

	trigger, err := sync.NewTrigger(sync.TriggerConfig{
		Run: func(runCtx context.Context, trig string) error {
			_, err := rec.Run(runCtx, trig)
			return err
		},
		// The interval is read from the settings table on every period (Y-02.1), so a value the UI
		// changes takes effect from the next tick. A missing or invalid setting falls back to the
		// validated config default (F1-017 AC7 bounds the stored value to 1-60 minutes).
		Interval: func() time.Duration {
			value, err := st.Queries().GetSetting(ctx, sync.SyncIntervalSetting)
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					log.Warn("read sync interval setting", "err", err)
				}
				return cfg.Sync.Interval
			}
			return sync.IntervalFromSetting(value, cfg.Sync.Interval)
		},
		Logger: log,
	})
	if err != nil {
		return err
	}

	handler, err := hook.NewHandler(hook.Config{
		SigningKey: key,
		Queries:    st.Queries(),
		Trigger:    trigger,
		Logger:     log,
	})
	if err != nil {
		return err
	}

	// The interface serves its embedded assets at /static/ (ADR 0007), the audit page (F1-018) and the
	// sync page (F1-017). The identity and CSRF middleware wrap the whole interface so the trust
	// boundary is exercised end to end.
	auditPage, err := web.NewAuditHandler(web.AuditHandlerConfig{Auditor: auditor, CSRF: csrf})
	if err != nil {
		return err
	}
	overview, err := web.NewOverviewReader(web.OverviewConfig{
		Queries:         st.Queries(),
		Preview:         rec.Preview,
		DefaultInterval: cfg.Sync.Interval,
	})
	if err != nil {
		return err
	}
	syncPage, err := web.NewSyncHandler(web.SyncHandlerConfig{
		Overview: overview,
		Approver: web.NewPipelineApprover(pipeline, rec.Replan),
		Rejecter: web.NewChangeRejecter(st.Queries()),
		DryRun:   web.NewSettingDryRun(st.Queries()),
		Interval: web.NewSettingInterval(st.Queries()),
		Trigger:  trigger,
		Auditor:  auditor,
		CSRF:     csrf,
	})
	if err != nil {
		return err
	}
	// The list's health column summarises the stored checks the monitoring loop writes (F4); it only
	// reads, and an unreadable store or settings fall back to "bilinmiyor" / the default intervals.
	sitesPage, err := web.NewSitesHandler(web.SitesHandlerConfig{Lister: siteStore, CSRF: csrf,
		Health: web.ObservationSiteHealth{
			Rows:     st.Queries().ListObservationsBySite,
			Settings: monitor.NewSettingsStore(st.DB(), st.Queries()).Get,
		}})
	if err != nil {
		return err
	}
	// The review flow (F2-014): the shared preview/approval/result screens and the first-import
	// action. The seed is optional; without it the action is hidden.
	var seed *web.SiteSeedSource
	if cfg.Sites.SeedFile != "" {
		seed = &web.SiteSeedSource{
			Read: func(ctx context.Context) ([]byte, error) {
				return os.ReadFile(cfg.Sites.SeedFile) // #nosec G304 -- operator-provided path
			},
			Caddy:                  change.NewCaddyFile(caddy.NewClient(cfg.Caddy.AdminURL), cfg.Caddy.CaddyfilePath),
			DNS:                    dnsFile,
			TagcessHost:            cfg.Sites.TagcessHost,
			ZitadelInternalSources: cfg.Sites.ZitadelInternalSources,
		}
	}
	siteReview, err := web.NewSiteReviewHandler(web.SiteReviewConfig{
		Reviewer: sitePipeline,
		Lister:   siteStore,
		URIs:     uriSync,
		Settings: web.SiteSettingsFunc(siteSettings),
		Changes:  st.Queries(),
		Gate:     firstImportGate(seed, siteStore),
		Seed:     seed,
		DryRun:   st,
		Auditor:  auditor,
		CSRF:     csrf,
		// The (k8s) upstream every apply writes; the preview names it.
		K8sUpstream: cfg.Sites.K8sUpstream,
	})
	if err != nil {
		return err
	}
	siteForm, err := web.NewSiteFormHandler(web.SiteFormConfig{
		Store:   siteStore,
		Targets: allowedTargets,
		Auditor: auditor,
		Roles:   zs,
		// The allowlist check and write share the pipeline's writer lock, so a concurrent site
		// write cannot leave a stored target outside the new list (F2-013 AC5).
		Lock:   change.WithWriterLock,
		Review: siteReview,
		CSRF:   csrf,
	})
	if err != nil {
		return err
	}
	// The site settings screen (F2-015): the S-06 key changes through the review flow; the value
	// is stored under the writer lock with a fresh dry-run check.
	siteSettingsPage, err := web.NewSiteSettingsHandler(web.SiteSettingsHandlerConfig{
		Previewer: sitePipeline,
		Settings:  web.SiteSettingsFunc(siteSettings),
		DryRun:    st,
		Setter:    web.NewSettingS06(st.Queries()),
		Changes:   st.Queries(),
		Lister:    siteStore,
		Auditor:   auditor,
		CSRF:      csrf,
	})
	if err != nil {
		return err
	}
	// The site history and rollback screens (F2-020): the rollback is applied through the same
	// site pipeline as any other change.
	siteHistory, err := web.NewSiteHistoryHandler(web.SiteHistoryConfig{
		Versions: siteStore,
		Rollback: sitePipeline,
		CSRF:     csrf,
	})
	if err != nil {
		return err
	}
	// The resync action (F2-021): re-applies the stored records over the live artifacts through
	// the site pipeline's own resync path, behind the version-bound review.
	siteResync, err := web.NewSiteResyncHandler(web.SiteResyncConfig{
		Reviewer: sitePipeline,
		Changes:  st.Queries(),
		Lister:   siteStore,
		Auditor:  auditor,
		CSRF:     csrf,
	})
	if err != nil {
		return err
	}
	// The users screen (F3-007, H-02): Headscale users matched against Zitadel, read-only. The
	// same resolver answers the personal-access eligibility checks of the later device/key flows.
	resolver, err := vpnuser.NewResolver(zs, cfg.Zitadel.Issuer)
	if err != nil {
		return err
	}
	usersService, err := web.NewUsersService(hs, resolver)
	if err != nil {
		return err
	}
	usersPage, err := web.NewUsersHandler(web.UsersHandlerConfig{Reader: usersService, DryRun: st, CSRF: csrf})
	if err != nil {
		return err
	}
	// The devices screens (F3-012, H-01 read side): the device list with its periodic refresh and
	// the detail page, read-only through the admin client.
	devicesService, err := web.NewDevicesService(adminHS)
	if err != nil {
		return err
	}
	// The device write pipeline (F3-009 executor) serves the device actions (F3-014) and the
	// personal-device reopen (F3-021): fresh read, server-node protection, staleness refusal,
	// audit, RPC, read-back. The reopen's eligibility check is the resolver's fresh Zitadel read
	// and a success asks the scheduler for a manual reconcile.
	adminExec := hsadmin.New(hsadmin.Config{Reader: adminHS, Audit: auditor, Store: st.Queries(), Log: log, Maintenance: maint})
	actionsService, err := web.NewDeviceActionsService(adminHS, adminExec)
	if err != nil {
		return err
	}
	deviceActions, err := web.NewDeviceActionsHandler(actionsService, csrf)
	if err != nil {
		return err
	}
	reopenService, err := web.NewDeviceReopenService(adminHS, hs, resolver.Eligibility, adminExec, trigger)
	if err != nil {
		return err
	}
	deviceReopen, err := web.NewDeviceReopenHandler(reopenService, csrf)
	if err != nil {
		return err
	}
	devicesPage, err := web.NewDevicesHandler(web.DevicesHandlerConfig{Reader: devicesService, DryRun: st, CSRF: csrf, Actions: actionsService})
	if err != nil {
		return err
	}
	// The device tag screens (F3-016, H-01/H-05): tag changes and the personal → tagged conversion
	// run through the admin operation pipeline (F3-009), the single writer path for device RPCs.
	deviceTags, err := web.NewDeviceTagsHandler(web.DeviceTagsConfig{
		Nodes: adminHS, Policy: hs, Setter: adminHS, Executor: adminExec, DryRun: st, CSRF: csrf,
	})
	if err != nil {
		return err
	}
	// The device routes screen (F3-015, H-01): approve and revoke the advertised routes and the
	// exit node as a full set. The policy read for the autoApprovers hint is the narrow F1 client.
	deviceRoutesPage, err := web.NewDeviceRoutesHandler(web.DeviceRoutesHandlerConfig{
		Reader:   adminHS,
		Writer:   adminHS,
		Policy:   hs,
		Executor: adminExec,
		DryRun:   st,
		CSRF:     csrf,
	})
	if err != nil {
		return err
	}
	// The pre-auth key screens (F3-017, H-03/H-05): list, confirmed expire and delete, and tagged
	// keys for shared devices. Writes go through the admin executor (writer lock, audit, read-back).
	keysService, err := web.NewKeysService(web.KeysServiceConfig{Admin: adminHS, Policy: hs, Exec: adminExec})
	if err != nil {
		return err
	}
	keysPage, err := web.NewKeysHandler(web.KeysHandlerConfig{Service: keysService, DryRun: st, CSRF: csrf})
	if err != nil {
		return err
	}
	// The policy editor (F3-019, H-04): a textarea over the policy writer, which rebuilds the
	// Zitadel-owned groups, adds the locked tests, validates and applies through the pipeline. The
	// locked tests' webhook port is the hook listener's; the rest is the F3-020 settings, read per operation.
	_, hookPort, err := net.SplitHostPort(cfg.Hook.Listen)
	if err != nil {
		return fmt.Errorf("hook.listen: %w", err)
	}
	webhookPortNum, err := strconv.Atoi(hookPort)
	if err != nil {
		return fmt.Errorf("hook.listen port: %w", err)
	}
	policyWriter, err := policywriter.New(policywriter.Config{
		Evaluator:    rec,
		Pipeline:     pipeline,
		Revisions:    policyrev.New(st.Queries()),
		Checker:      hs,
		LockedSource: policydoc.LockedSource(st.Queries(), webhookPortNum),
	})
	if err != nil {
		return err
	}
	// The H-07 service (F3b-018): preview/apply of oidc.allowed_groups through the host helper's shared
	// directories, and the watcher that records the helper's result. Unset directories leave it off.
	// The success hand-over and the close service (F3b-019) live here; the UI (F3b-020) attaches below.
	var hsConfigPage registrar
	if cfg.HostApply.Enabled() {
		hostClient, err := hostapply.New(cfg.HostApply.RequestsDir, cfg.HostApply.ResultsDir)
		if err != nil {
			return err
		}
		hostApply, err := hostapply.NewService(hostapply.Config{
			Host:        hostClient,
			Maintenance: maint,
			Audit:       auditor,
			Settings:    st.Queries(),
			Unknowns: hostapply.NewUnknowns(func(ctx context.Context) (string, error) {
				live, err := policyWriter.Live(ctx)
				if err != nil {
					return "", err
				}
				if live.HeadscaleErr != nil {
					return "", live.HeadscaleErr
				}
				return live.Uncertain, nil
			}, st.Queries(), hsadmin.AlertUnverified, sync.AlertKeyRevokeFailed),
			Log: log,
			// A recorded success, and the operator's close, hand over to a reconcile (F3b-019).
			Reconcile: trigger.RequestManual,
		})
		if err != nil {
			return err
		}
		// The H-07 config screen (F3b-020): the secret-free status, the preview/approval flow and
		// "close the maintenance". Registered only when the helper directories are configured.
		hsConfig, err := web.NewHSConfigHandler(web.HSConfigConfig{
			Service: hostApply, Maintenance: maint, Host: hostClient, Switch: st.Queries(), DryRun: st, CSRF: csrf,
		})
		if err != nil {
			return err
		}
		hsConfigPage = hsConfig
		watchCtx, stopWatch := context.WithCancel(ctx)
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			hostApply.Watch(watchCtx, hostapply.PollInterval)
		}()
		defer func() {
			stopWatch()
			<-watchDone
		}()
	}
	// The rules/tagOwners/autoApprovers forms (F3-023/024) read the node counts and the protected
	// tags fresh on the page; the draft edits stay policydoc-only, saving stays the writer's.
	policyPage, err := web.NewPolicyHandler(web.PolicyHandlerConfig{Editor: policyWriter, DryRun: st, CSRF: csrf, Nodes: adminHS, Protected: adminExec})
	if err != nil {
		return err
	}
	// The policy history and rollback pages (F3-025, A-03): the revision list, and a rollback that
	// goes through the same writer as the editor (source=rollback).
	policyHistory, err := web.NewPolicyHistoryHandler(web.PolicyHistoryConfig{
		Editor: policyWriter, Revisions: policyrev.New(st.Queries()), DryRun: st, CSRF: csrf,
	})
	if err != nil {
		return err
	}
	// The controlled recovery of an uncertain policy state (F3-029): reachable only from its page, never
	// from a background, startup or reconcile path.
	policyRecovery, err := web.NewPolicyRecoveryHandler(web.PolicyRecoveryConfig{Editor: policyWriter, DryRun: st, CSRF: csrf})
	if err != nil {
		return err
	}
	// The personal pre-auth key screen (F3-022, H-03): a one-time key for a user a fresh Zitadel
	// read, under the writer lock, shows active with a vpn role.
	personalKeyService, err := web.NewPersonalKeyService(web.PersonalKeyServiceConfig{
		Admin: adminHS, Users: hs, Resolver: resolver, Exec: adminExec, Issuer: cfg.Zitadel.Issuer,
	})
	if err != nil {
		return err
	}
	personalKeyPage, err := web.NewPersonalKeyHandler(web.PersonalKeyHandlerConfig{Service: personalKeyService, DryRun: st, CSRF: csrf})
	if err != nil {
		return err
	}
	// The API keys screen (F3-018, H-03): list, expire, delete — no create (R2 karar 7). The same
	// admin executor as the other device and key writes.
	apiKeysPage, err := web.NewAPIKeysHandler(web.APIKeysHandlerConfig{
		Reader:   adminHS,
		Writer:   adminHS,
		Executor: adminExec,
		DryRun:   st,
		CSRF:     csrf,
	})
	if err != nil {
		return err
	}
	// The manual MagicDNS records screen (F3-008, H-06): the site-derived records next to the
	// editable manual set, written only through the site pipeline's manual_dns operation.
	dnsRecords, err := web.NewDNSRecordsHandler(web.DNSRecordsConfig{
		Reviewer: sitePipeline,
		Lister:   siteStore,
		Manual:   siteStore,
		Settings: web.SiteSettingsFunc(siteSettings),
		Changes:  st.Queries(),
		Auditor:  auditor,
		DryRun:   st,
		CSRF:     csrf,
	})
	if err != nil {
		return err
	}
	// The Headscale settings screen (F3-020): protected server tags and the locked policy test
	// parameters, stored in settings and read fresh by the admin executor and the policy writer.
	webhookPort, err := listenPort(cfg.Hook.Listen)
	if err != nil {
		return err
	}
	// The admin group the middleware enforces moves only after the Caddy gate carries it too (issue #3).
	adminState := web.NewAdminGroupState(func(ctx context.Context) (string, error) {
		c, _, err := policydoc.LoadLocked(ctx, st.Queries(), webhookPort)
		return c.AdminGroup(), err
	})
	hsSettings, err := web.NewHSSettingsHandler(web.HSSettingsConfig{
		Store: st.Queries(), Policy: hs, Checker: hs, Auditor: auditor,
		WebhookPort: webhookPort, DryRun: st, CSRF: csrf,
		AdminApply: sitePipeline, AdminState: adminState,
	})
	if err != nil {
		return err
	}
	// The F4 services (F4-031): read-only dashboard, k8s screens and the monitoring loops. They are
	// given no reconcile or apply callback; the loops start and stop with the process below.
	f4s, err := buildF4(f4Inputs{
		Cfg: cfg, Log: log, Store: st, CSRF: csrf, Auditor: auditor,
		Sites: siteStore, Targets: allowedTargets, Nodes: adminHS, Roles: zs,
		Policy: hs, Caddy: change.NewCaddyFile(caddy.NewClient(cfg.Caddy.AdminURL), cfg.Caddy.CaddyfilePath),
		DNS: dnsFile, URIs: alert.NewZitadelURIs(zs, cfg.Zitadel.OAuth2ProxyApp, st.Queries()),
		Settings: siteSettings, Review: siteReview, Maintenance: maint,
	})
	if err != nil {
		return err
	}
	rerunLoops := f4s.loops.Trigger
	siteApplied.Store(&rerunLoops)
	pages := uiPages{
		AdminGroup:    adminState.Current,
		Audit:         auditPage,
		Sync:          syncPage,
		Sites:         sitesPage,
		SiteForm:      siteForm,
		SiteReview:    siteReview,
		SiteSettings:  siteSettingsPage,
		SiteHistory:   siteHistory,
		SiteResync:    siteResync,
		Users:         usersPage,
		Devices:       devicesPage,
		DeviceTags:    deviceTags,
		DeviceRoutes:  deviceRoutesPage,
		APIKeys:       apiKeysPage,
		DNSRecords:    dnsRecords,
		Keys:          keysPage,
		PersonalKey:   personalKeyPage,
		HSSettings:    hsSettings,
		HSConfig:      hsConfigPage,
		DeviceActions: deviceActions,
		DeviceReopen:  deviceReopen,
		Policy:        policyPage,
		PolicyHistory: policyHistory,
		RecoveryPage:  policyRecovery,
		Maintenance:   maint,
		Shell:         web.NewShellStatus(st, st.Queries()),
	}
	pages.Dashboard, pages.Alerts, pages.MonitorSettings = f4s.Pages.Dashboard, f4s.Pages.Alerts, f4s.Pages.MonitorSettings
	pages.K8sDiscovery, pages.K8sConnection, pages.K8sSetup, pages.K8sDraft = f4s.Pages.K8sDiscovery, f4s.Pages.K8sConnection, f4s.Pages.K8sSetup, f4s.Pages.K8sDraft
	pages.Health = web.NewHealthz(func(ctx context.Context) error { return st.CheckReadable(ctx) }, version.Version)
	uiHandler := newUIHandler(csrf, pages)
	ui, err := web.New(web.Config{
		Socket:      cfg.UI.Socket,
		SocketGroup: cfg.UI.SocketGroup,
		SocketMode:  cfg.UI.SocketMode.Perm(),
		Handler:     uiHandler,
		Logger:      log,
	})
	if err != nil {
		return err
	}
	if _, err := ui.Listen(); err != nil {
		return err
	}

	mux, err := newHookMux(handler, groupsKey, cfg.Zitadel.ProjectID, zs, debounced(trigger.Signal, loginSyncWindow, time.Now), log)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Hook.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	trigger.Start()
	f4s.Runtime.Start(ctx)
	defer f4s.Runtime.Stop()
	serveErr := make(chan error, 2)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("hook listener: %w", err)
		}
	}()
	go func() {
		if err := ui.Serve(); err != nil {
			serveErr <- fmt.Errorf("ui listener: %w", err)
		}
	}()
	log.Info("tagcess started", "hook", cfg.Hook.Listen, "path", webhookPath, "ui_socket", cfg.UI.Socket)

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		return errors.Join(err, trigger.Stop())
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(drainCtx)
	_ = ui.Shutdown(drainCtx)
	return trigger.Stop()
}

// firstImportGate returns gate only when a seed is configured. The review handler takes the
// first-import gate and the seed together or not at all; without a seed the action stays hidden.
func firstImportGate(seed *web.SiteSeedSource, gate web.SiteFirstImportGate) web.SiteFirstImportGate {
	if seed == nil {
		return nil
	}
	return gate
}

// listenPort is the port of an ip:port listen address (hook.listen); config validation already
// requires the host:port shape.
func listenPort(addr string) (int, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("hook.listen %q: %w", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("hook.listen %q: port: %w", addr, err)
	}
	return n, nil
}

// dnsVerifier builds the post-write resolver check. An empty dns.resolver means the MagicDNS
// default (config reference); the verifier itself reads an empty address as "skip".
func dnsVerifier(resolver string) dns.Verifier {
	if resolver == "" {
		resolver = dns.DefaultResolver
	}
	return dns.Verifier{Resolver: resolver}
}

// openZitadel turns the issuer URL and key file into a client. Config validation already checked
// that the issuer is a plain https URL.
func openZitadel(ctx context.Context, cfg *config.Config) (*zitadel.Client, error) {
	u, err := url.Parse(cfg.Zitadel.Issuer)
	if err != nil {
		return nil, fmt.Errorf("zitadel issuer: %w", err)
	}
	var port uint16
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("zitadel issuer port %q: %w", p, err)
		}
		port = uint16(n)
	}
	return zitadel.New(ctx, zitadel.Config{
		Host:      u.Hostname(),
		Port:      port,
		KeyFile:   string(cfg.Zitadel.KeyFile),
		ProjectID: cfg.Zitadel.ProjectID,
	})
}

// Settings keys of the site layer. The S-06 key defaults to open: today's behaviour and the state
// the first import compares against (S-06.3).
const settingS06Open = "site.s06_open"

// siteSettingsReader returns the render inputs that do not come from site records (F2-014): the
// S-06 key state from the settings table (default open, S-06.3), the manual MagicDNS records
// (H-06, stored by the first import) and the config-fixed inputs. A bad stored value is an error,
// never a default: the plan then blocks instead of rendering with a guessed key.
func siteSettingsReader(q *db.Queries, sites *site.Store, cfg *config.Config) func(ctx context.Context) (change.SiteSettings, error) {
	return func(ctx context.Context) (change.SiteSettings, error) {
		s06 := true
		if v, err := q.GetSetting(ctx, settingS06Open); err == nil {
			on, perr := strconv.ParseBool(v)
			if perr != nil {
				return change.SiteSettings{}, fmt.Errorf("setting %s = %q: %w", settingS06Open, v, perr)
			}
			s06 = on
		} else if !errors.Is(err, sql.ErrNoRows) {
			return change.SiteSettings{}, fmt.Errorf("read setting %s: %w", settingS06Open, err)
		}
		manual, err := sites.ManualDNS(ctx)
		if err != nil {
			return change.SiteSettings{}, err
		}
		// The UI block admits the policy settings' admin group (issue #3); a bad stored value blocks the plan.
		locked, _, err := policydoc.LoadLocked(ctx, q, 0)
		if err != nil {
			return change.SiteSettings{}, err
		}
		return change.SiteSettings{
			Caddy: render.CaddyConfig{
				ACMEEmail: cfg.Sites.ACMEEmail,
				S06Open:   s06,
				Certs:     cfg.Sites.Certificates,
				// J1: the 403 page signs out through Zitadel's end_session and returns to tagcess.
				ZitadelIssuer:   cfg.Zitadel.Issuer,
				GateClientID:    cfg.Gate.ClientID,
				LogoutReturnURL: logoutReturnURL(cfg),
				// The (k8s) upstream the first-import parity was checked with is the one every apply writes.
				K8sUpstream:  cfg.Sites.K8sUpstream,
				GateUpstream: cfg.Gate.Upstream,
				AdminGroup:   locked.AdminGroup(),
			},
			DNS:       render.DNSConfig{AValue: cfg.Sites.VPNAddress},
			ManualDNS: manual,
		}, nil
	}
}

// logoutReturnURL is the post-logout redirect URI: the tagcess host's root. Empty while the gate client
// id is unset (config validation requires the host whenever the client id is set).
func logoutReturnURL(cfg *config.Config) string {
	if cfg.Gate.ClientID == "" {
		return ""
	}
	return "https://" + cfg.Sites.TagcessHost + "/"
}

// registrar is a page handler that mounts its own routes.
type registrar interface {
	Register(mux *http.ServeMux)
}

// uiPages are the pages of the interface. A nil page is not mounted (tests build partial sets).
type uiPages struct {
	Health        http.Handler // /healthz, the one route outside the identity middleware
	Audit         http.Handler
	Sync          registrar
	Sites         registrar
	SiteForm      registrar
	SiteReview    registrar
	SiteSettings  registrar
	SiteHistory   registrar
	SiteResync    registrar
	Users         registrar
	Devices       registrar
	DeviceTags    registrar
	DeviceRoutes  registrar
	APIKeys       registrar
	DNSRecords    registrar
	Keys          registrar
	PersonalKey   registrar
	HSSettings    registrar
	HSConfig      registrar
	DeviceActions registrar
	DeviceReopen  registrar
	Policy        registrar
	PolicyHistory registrar
	RecoveryPage  registrar
	// Maintenance feeds the section-wide maintenance band on every Headscale tab (F3b-020).
	Maintenance web.MaintenanceBannerSource
	// AdminGroup reads the group admitted to the UI; nil means "devops" (tests).
	AdminGroup web.AdminGroupSource
	// Shell feeds the top bar's dry-run and pending-change pills on every page.
	Shell web.ShellStatusSource
	// The F4 pages (F4-031): the root dashboard, alerts, monitoring settings and the k8s screens.
	Dashboard       registrar
	Alerts          registrar
	MonitorSettings registrar
	K8sDiscovery    registrar
	K8sConnection   registrar
	K8sSetup        registrar
	K8sDraft        registrar
}

// newUIHandler mounts the pages and wraps the whole interface in the identity and CSRF middleware,
// so the trust boundary covers every route, the site history and rollback ones included.
func newUIHandler(csrf *web.CSRF, p uiPages) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", web.Static()))
	web.NewNavPages(csrf).Register(mux)
	if p.Audit != nil {
		mux.Handle("/audit", p.Audit)
	}
	for _, r := range []registrar{p.Sync, p.Sites, p.SiteForm, p.SiteReview, p.SiteSettings, p.SiteHistory, p.SiteResync, p.Users, p.Devices, p.DeviceTags, p.DeviceRoutes, p.APIKeys, p.DNSRecords, p.Keys, p.PersonalKey, p.HSSettings, p.HSConfig, p.DeviceActions, p.DeviceReopen, p.Policy, p.PolicyHistory, p.RecoveryPage, p.Alerts, p.MonitorSettings, p.K8sDiscovery, p.K8sConnection, p.K8sSetup, p.K8sDraft} {
		if r != nil {
			r.Register(mux)
		}
	}
	// The dashboard owns only the exact root; every other unknown path stays a 404.
	if p.Dashboard != nil {
		root := http.NewServeMux()
		p.Dashboard.Register(root)
		mux.Handle("GET /{$}", root)
	}
	mux.Handle("/", http.NotFoundHandler())
	h := web.RequireGroup(p.AdminGroup, csrf.Protect(mux))
	// The maintenance band on every Headscale tab (F3b-020 AC4): the reader is bound once here.
	if p.Maintenance != nil {
		h = web.WithMaintenanceBanner(p.Maintenance, h)
	}
	// The sidebar mark and the top bar status on every page; Shell may be nil (tests).
	h = web.WithShell(p.Shell, h)
	if p.Health == nil {
		return h
	}
	// The liveness probe needs no identity headers; every other path goes through the full chain.
	outer := http.NewServeMux()
	outer.Handle("GET /healthz", p.Health)
	outer.Handle("/", h)
	return outer
}
