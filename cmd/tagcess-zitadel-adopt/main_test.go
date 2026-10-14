package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/zitadeladopt"
)

// emptyZitadel is a Zitadel without the vpn project; it records writes and hands out secret values.
type emptyZitadel struct {
	writes  []string
	secrets []string
	project string
	apps    map[string]zitadeladopt.App
}

func (e *emptyZitadel) OrgID(context.Context) (string, error) { return "org", nil }
func (e *emptyZitadel) FindProject(context.Context, string, string) (*zitadeladopt.Project, error) {
	if e.project == "" {
		return nil, nil
	}
	return &zitadeladopt.Project{ID: e.project, Name: "vpn"}, nil
}
func (e *emptyZitadel) CreateProject(context.Context, string, string) (string, error) {
	e.writes = append(e.writes, "project")
	e.project = "p1"
	return e.project, nil
}
func (e *emptyZitadel) ProjectRoles(context.Context, string) ([]string, error) { return nil, nil }
func (e *emptyZitadel) AddProjectRole(_ context.Context, _, k string) error {
	e.writes = append(e.writes, "role "+k)
	return nil
}
func (e *emptyZitadel) FindApp(_ context.Context, _, name string) (*zitadeladopt.App, error) {
	if a, ok := e.apps[name]; ok {
		return &a, nil
	}
	return nil, nil
}
func (e *emptyZitadel) CreateApp(_ context.Context, _, name string, r, p []string) (zitadeladopt.App, string, error) {
	e.writes = append(e.writes, "app "+name)
	a := zitadeladopt.App{ID: "a-" + name, Name: name, ClientID: "c-" + name, RedirectURIs: r, PostLogoutURIs: p}
	e.apps[name] = a
	s := "CliSecret9" + strings.Repeat("Xy7", 10) + name
	e.secrets = append(e.secrets, s)
	return a, s, nil
}
func (e *emptyZitadel) SetAppURIs(context.Context, string, zitadeladopt.App, []string, []string) error {
	e.writes = append(e.writes, "uris")
	return nil
}
func (e *emptyZitadel) FindUser(context.Context, string) (*zitadeladopt.User, error) { return nil, nil }
func (e *emptyZitadel) MemberRoles(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (e *emptyZitadel) KeyCount(context.Context, string) (int, error) { return 0, nil }
func (e *emptyZitadel) FindTarget(context.Context, string) (*zitadeladopt.Target, error) {
	return nil, nil
}
func (e *emptyZitadel) CreateTarget(_ context.Context, name, _, _ string) (string, string, error) {
	e.writes = append(e.writes, "target "+name)
	s := "SignKey7" + strings.Repeat("Pq3", 10) + name
	e.secrets = append(e.secrets, s)
	return "t-" + name, s, nil
}
func (e *emptyZitadel) Executions(context.Context) ([]zitadeladopt.Execution, error) { return nil, nil }
func (e *emptyZitadel) SetExecution(_ context.Context, c string, _ []string) error {
	e.writes = append(e.writes, "exec "+c)
	return nil
}
func (e *emptyZitadel) V1Actions(context.Context) ([]string, map[string]bool, error) {
	return nil, map[string]bool{}, nil
}
func (e *emptyZitadel) UnroledActiveUsers(context.Context, string, string) (int, error) {
	return 3, nil
}

func fixed(api zitadeladopt.API) dialer {
	return func(context.Context, zitadeladopt.Conn) (zitadeladopt.API, func() error, error) {
		return api, func() error { return nil }, nil
	}
}

var baseArgs = []string{"--issuer", "https://auth.example.test", "--admin-key-file", "/x/admin.json",
	"--headscale-redirect", "https://hs.example.test/oidc/callback", "--oauth2-proxy-redirect", "https://tagcess.example.test/oauth2/callback",
	"--webhook-url", "http://100.64.0.4:9443/hook", "--groups-url", "http://100.64.0.4:9443/groups"}

func TestCLI_DryRunWritesNothing(t *testing.T) {
	z := &emptyZitadel{apps: map[string]zitadeladopt.App{}}
	var out, errb bytes.Buffer
	code := run(append(baseArgs, "--dry-run", "--create-actions", "--report-unroled"), &out, &errb, fixed(z))
	var res zitadeladopt.Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s\n%s", code, err, out.String(), errb.String())
	}
	// No project yet: there is nothing to count users against, so the count is absent (not 0).
	if len(z.writes) != 0 || !res.DryRun || len(res.Plan) == 0 || res.Report.UnroledUsers != nil {
		t.Fatalf("writes %v result %+v", z.writes, res)
	}
}

func TestCLI_SecretsOnlyInFiles(t *testing.T) {
	z := &emptyZitadel{apps: map[string]zitadeladopt.App{}}
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := run(append(baseArgs, "--create-actions", "--secret-out-dir", dir), &out, &errb, fixed(z)); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if len(z.secrets) != 4 {
		t.Fatalf("secrets handed out: %d", len(z.secrets))
	}
	for _, s := range z.secrets {
		if strings.Contains(out.String()+errb.String(), s) {
			t.Fatal("a secret reached stdout/stderr")
		}
	}
	var res zitadeladopt.Result
	_ = json.Unmarshal(out.Bytes(), &res)
	for k, p := range res.Secrets {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", k, err, st)
		}
	}
}

func TestCLI_UnreachableAndUsage(t *testing.T) {
	failing := func(context.Context, zitadeladopt.Conn) (zitadeladopt.API, func() error, error) {
		return nil, nil, errors.New("connect: refused")
	}
	var out, errb bytes.Buffer
	if code := run(baseArgs, &out, &errb, failing); code != 1 || !strings.Contains(errb.String(), "nothing was written") {
		t.Fatalf("code %d stderr %s", code, errb.String())
	}
	for _, args := range [][]string{
		{"--admin-key-file", "/x"},
		{"--issuer", "http://auth.example.test", "--admin-key-file", "/x"},
	} {
		errb.Reset()
		if code := run(args, &out, &errb, fixed(&emptyZitadel{})); code != 2 {
			t.Fatalf("%v: code %d", args, code)
		}
	}
}
