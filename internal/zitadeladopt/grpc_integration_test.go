//go:build integration

package zitadeladopt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	projectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"

	"github.com/nesiler/tagcess/test/labenv"
)

// The lab Zitadel (ADR 0014) with the bootstrap PAT `make lab-up` leaves in test/compose/.secrets/lab. Each test
// uses its own project (vpn-f6test-<random>) and deletes only that project afterwards. Actions v2 executions are
// instance-wide, so --create-actions/--groups-execution are NOT exercised here (they would replace the lab's own
// executions); the decision table covers them.
func labConn(t *testing.T) Conn {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pat := filepath.Join(filepath.Dir(file), "..", "..", "test", "compose", ".secrets", "lab", "bootstrap-pat")
	if _, err := os.Stat(pat); err != nil {
		t.Skipf("lab Zitadel PAT not found (%v): run make lab-up", err)
	}
	host := os.Getenv("TAGCESS_F6_ZITADEL_HOST")
	if host == "" {
		host = labenv.ZitadelHost()
	}
	return Conn{Host: host, PATFile: pat}
}

func randomName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "vpn-f6test-" + hex.EncodeToString(b)
}

// deleteProject removes the test's own project (test cleanup only; the tool itself never deletes).
func deleteProject(t *testing.T, c Conn, id string) {
	t.Helper()
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, _ := os.ReadFile(c.PATFile) // #nosec G304 -- test file
	api, err := client.New(ctx, zitadel.New(c.Host), client.WithAuth(client.PAT(strings.TrimSpace(string(raw)))))
	if err != nil {
		t.Errorf("cleanup connect: %v", err)
		return
	}
	defer func() { _ = api.Close() }()
	if _, err := api.ProjectServiceV2().DeleteProject(ctx, &projectv2.DeleteProjectRequest{ProjectId: id}); err != nil {
		t.Errorf("cleanup: delete test project %s: %v", id, err)
	}
}

func TestZitadelAdoptLab_FindOrCreateAddOnlyIdempotent(t *testing.T) {
	c := labConn(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	g, err := Dial(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	name := randomName(t)
	o := Options{ProjectName: name, Roles: []string{"devops", "developer", "standart"}, ServiceUser: "tagcess", ReportUnroled: true,
		SecretOutDir: t.TempDir(), Apps: []AppSpec{
			{Name: "headscale", SecretKey: "headscale_oidc_client_secret", RedirectURIs: []string{"https://hs.f6test.example.test/oidc/callback"}},
			{Name: "oauth2-proxy", SecretKey: "oauth2_proxy_client_secret", RedirectURIs: []string{"https://tagcess.f6test.example.test/oauth2/callback"}},
		}}

	// Dry run against nothing: a plan, no project.
	dry := o
	dry.DryRun = true
	res, err := Run(ctx, g, dry)
	if err != nil || res.Changed || res.ProjectID != "" {
		t.Fatalf("dry run: %v %+v", err, res)
	}
	if p, _ := g.FindProject(ctx, res.OrgID, name); p != nil {
		t.Fatal("the dry run created the project")
	}

	first, err := Run(ctx, g, o)
	t.Cleanup(func() { deleteProject(t, c, first.ProjectID) })
	if err != nil || !first.Changed || first.ProjectID == "" || first.Secrets["headscale_oidc_client_secret"] == "" {
		t.Fatalf("first run: %v %+v", err, first)
	}
	if first.Report.UnroledUsers == nil || first.Report.ServiceUser.ProjectOwner {
		t.Fatalf("report: %+v", first.Report)
	}

	// An extra URI added out of band survives; a missing expected one is added.
	app, err := g.FindApp(ctx, first.ProjectID, "oauth2-proxy")
	if err != nil {
		t.Fatal(err)
	}
	extra := "https://site.f6test.example.test/oauth2/callback"
	if err := g.SetAppURIs(ctx, first.ProjectID, *app, append(app.RedirectURIs, extra), app.PostLogoutURIs); err != nil {
		t.Fatal(err)
	}
	o.Apps[1].RedirectURIs = append(o.Apps[1].RedirectURIs, "https://tagcess2.f6test.example.test/oauth2/callback")
	second, err := Run(ctx, g, o)
	if err != nil || !second.Changed || second.Apps["oauth2-proxy"] != first.Apps["oauth2-proxy"] {
		t.Fatalf("second run: %v %+v", err, second)
	}
	app, _ = g.FindApp(ctx, first.ProjectID, "oauth2-proxy")
	if !slices.Contains(app.RedirectURIs, extra) || !slices.Contains(app.RedirectURIs, "https://tagcess2.f6test.example.test/oauth2/callback") {
		t.Fatalf("redirect URIs %v", app.RedirectURIs)
	}

	third, err := Run(ctx, g, o)
	if err != nil || third.Changed {
		t.Fatalf("third run must change nothing: %v %+v", err, third.Plan)
	}
}
