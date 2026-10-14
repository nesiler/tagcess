// Command tagcess-zitadel-adopt is the installer's Zitadel step (F6-004): it finds or creates the vpn project, its
// roles and the headscale/oauth2-proxy OIDC applications in an existing Zitadel, and reports the tagcess service
// user, Actions v1/v2 and (on request) how many active users have no vpn role. It never creates a person, a grant
// or a membership and never deletes anything. Output: JSON on stdout (ids, plan, report, guide, secret file
// paths); secrets Zitadel shows once go only to 0600 files under --secret-out-dir.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nesiler/tagcess/internal/version"
	"github.com/nesiler/tagcess/internal/zitadeladopt"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, dial))
}

// dialer connects to Zitadel; tests replace it.
type dialer func(ctx context.Context, c zitadeladopt.Conn) (zitadeladopt.API, func() error, error)

func dial(ctx context.Context, c zitadeladopt.Conn) (zitadeladopt.API, func() error, error) {
	g, err := zitadeladopt.Dial(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	return g, g.Close, nil
}

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func run(args []string, stdout, stderr io.Writer, d dialer) int {
	if version.IsVersionFlag(args) {
		_, _ = fmt.Fprintln(stdout, version.String("tagcess-zitadel-adopt"))
		return 0
	}
	fs := flag.NewFlagSet("tagcess-zitadel-adopt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	issuer := fs.String("issuer", "", "Zitadel issuer URL, e.g. https://auth.example.com (required)")
	insecure := fs.Bool("insecure", false, "plaintext h2c to a loopback Zitadel (local test stack only)")
	keyFile := fs.String("admin-key-file", "", "administrator JWT profile key JSON (path)")
	patFile := fs.String("admin-pat-file", "", "administrator personal access token file (path; fresh lab)")
	project := fs.String("project", "vpn", "project name")
	roles := fs.String("roles", "devops,developer,standart", "project roles tagcess needs (comma-separated)")
	serviceUser := fs.String("service-user", "tagcess", "the tagcess service user to report (ADR 0009); never created")
	hsRedirect := fs.String("headscale-redirect", "", "redirect URIs the headscale app must have (comma-separated)")
	opRedirect := fs.String("oauth2-proxy-redirect", "", "redirect URIs the oauth2-proxy app must have (comma-separated)")
	opPostLogout := fs.String("oauth2-proxy-post-logout", "", "post-logout URIs the oauth2-proxy app must have (comma-separated)")
	webhookURL := fs.String("webhook-url", "", "Actions v2 webhook target endpoint (tagcess /hook)")
	groupsURL := fs.String("groups-url", "", "Actions v2 groups claim target endpoint (tagcess /groups)")
	createActions := fs.Bool("create-actions", false, "create the webhook target + executions and the groups target")
	groupsExecution := fs.Bool("groups-execution", false, "bind the groups target to preuserinfo (lab only)")
	reportUnroled := fs.Bool("report-unroled", false, "report how many active users have no vpn role (a number only)")
	dryRun := fs.Bool("dry-run", false, "write the plan only; no write call")
	secretOut := fs.String("secret-out-dir", "", "directory for secrets Zitadel shows once (0600 files)")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	u, err := url.Parse(*issuer)
	if *issuer == "" || err != nil || u.Hostname() == "" {
		_, _ = fmt.Fprintln(stderr, "tagcess-zitadel-adopt: --issuer must be a URL such as https://auth.example.com")
		return 2
	}
	conn := zitadeladopt.Conn{Host: u.Hostname(), Insecure: *insecure, KeyFile: *keyFile, PATFile: *patFile}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "tagcess-zitadel-adopt: bad issuer port %q\n", p)
			return 2
		}
		conn.Port = uint16(n)
	}
	if u.Scheme == "http" && !*insecure {
		_, _ = fmt.Fprintln(stderr, "tagcess-zitadel-adopt: an http issuer needs --insecure (loopback only)")
		return 2
	}
	opts := zitadeladopt.Options{
		ProjectName: *project, Roles: list(*roles), ServiceUser: *serviceUser, WebhookURL: *webhookURL, GroupsURL: *groupsURL,
		CreateActions: *createActions, GroupsExecution: *groupsExecution, ReportUnroled: *reportUnroled, DryRun: *dryRun,
		SecretOutDir: *secretOut,
	}
	if r := list(*hsRedirect); len(r) > 0 {
		opts.Apps = append(opts.Apps, zitadeladopt.AppSpec{Name: "headscale", SecretKey: "headscale_oidc_client_secret", RedirectURIs: r}) // #nosec G101 -- the secret_files key name, not a credential
	}
	if r := list(*opRedirect); len(r) > 0 {
		opts.Apps = append(opts.Apps, zitadeladopt.AppSpec{Name: "oauth2-proxy", SecretKey: "oauth2_proxy_client_secret", RedirectURIs: r, // #nosec G101 -- the secret_files key name, not a credential
			PostLogoutURIs: list(*opPostLogout)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	api, closeFn, err := d(ctx, conn)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tagcess-zitadel-adopt: %v; nothing was written\n", err)
		return 1
	}
	defer func() { _ = closeFn() }()
	res, err := zitadeladopt.Run(ctx, api, opts)
	if res != nil {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	}
	if err != nil {
		if errors.Is(err, zitadeladopt.ErrUnreachable) {
			_, _ = fmt.Fprintf(stderr, "tagcess-zitadel-adopt: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(stderr, "tagcess-zitadel-adopt: stopped: %v (what was done stays; run again to complete)\n", err)
		}
		return 1
	}
	return 0
}
