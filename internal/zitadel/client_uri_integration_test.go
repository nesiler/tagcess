//go:build integration

// F2-009 probes the lab Zitadel (ADR 0014) with the persistent tagcess service user (project
// member PROJECT_OWNER, ADR 0009): may it read and update the oauth2-proxy app's redirect URIs?
// R1's production write test only proved this with a temporary PROJECT_OWNER_GLOBAL account
// (open issue in docs/overview.md, ADR 0012 follow-up). The lab is shared state: every write here is
// undone — the original URI list is captured before the first write and restored and re-verified
// in t.Cleanup, even when the test fails.
package zitadel_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"

	"github.com/nesiler/tagcess/internal/site"
	"github.com/nesiler/tagcess/internal/store"
	"github.com/nesiler/tagcess/internal/zitadel"
	"github.com/nesiler/tagcess/test/compose/seed"
)

// spikeURI is the temporary probe URI: a reserved .test domain that can never collide with a real
// site. If it is ever found in the lab list, a previous run leaked it and the test refuses to run.
const spikeURI = "https://f2-009-spike.tagcess.test/oauth2/callback"

func labAppID(t *testing.T, e *env, ctx context.Context) string {
	t.Helper()
	id, err := e.client.FindAppID(ctx, seed.OAuth2ProxyAppName)
	if err != nil {
		t.Fatalf("find the %s app as the service user (was `make lab-up` run?): %v", seed.OAuth2ProxyAppName, err)
	}
	return id
}

// sameShape fails when one of the fields UpdateApplication resets to defaults (stack-notes,
// Zitadel v4.16.0) drifted between two reads.
func sameShape(t *testing.T, before, after *zitadel.AppOIDC) {
	t.Helper()
	if !slices.Equal(before.ResponseTypes, after.ResponseTypes) || !slices.Equal(before.GrantTypes, after.GrantTypes) {
		t.Fatalf("response/grant types drifted: %v/%v -> %v/%v",
			before.ResponseTypes, before.GrantTypes, after.ResponseTypes, after.GrantTypes)
	}
	if !proto.Equal(before.ClockSkew, after.ClockSkew) || !proto.Equal(before.LoginVersion, after.LoginVersion) {
		t.Fatalf("clockSkew/loginVersion drifted: %v/%v -> %v/%v",
			before.ClockSkew, before.LoginVersion, after.ClockSkew, after.LoginVersion)
	}
}

// TestLabZitadel_ProjectOwnerURIWrite is AC1: with the persistent role the service user reads the
// app, adds a temporary URI, reads it back, restores the old list and reads the restore back. The
// four reset-prone fields must survive both writes unchanged.
func TestLabZitadel_ProjectOwnerURIWrite(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	appID := labAppID(t, e, ctx)
	before, err := e.client.AppOIDC(ctx, appID)
	if err != nil {
		t.Fatalf("read app as the service user (project.app.read): %v", err)
	}
	if len(before.RedirectUris) == 0 {
		t.Fatalf("the lab %s app has no redirect URIs; nothing to verify a restore against", seed.OAuth2ProxyAppName)
	}
	if slices.Contains(before.RedirectUris, spikeURI) {
		t.Fatalf("%s is already in the lab list; a previous run leaked it: %v", spikeURI, before.RedirectUris)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cur, err := e.client.AppOIDC(ctx, appID)
		if err != nil {
			t.Errorf("cleanup read: %v", err)
			return
		}
		if slices.Equal(cur.RedirectUris, before.RedirectUris) {
			return
		}
		if err := e.client.UpdateAppRedirectURIs(ctx, appID, before.RedirectUris); err != nil {
			t.Errorf("cleanup restore write: %v (the lab may still hold %s)", err, spikeURI)
			return
		}
		final, err := e.client.AppOIDC(ctx, appID)
		if err != nil {
			t.Errorf("cleanup read back: %v", err)
			return
		}
		if !slices.Equal(final.RedirectUris, before.RedirectUris) {
			t.Errorf("cleanup restore read back %v, want %v", final.RedirectUris, before.RedirectUris)
		}
	})

	withSpike := append(slices.Clone(before.RedirectUris), spikeURI)
	if err := e.client.UpdateAppRedirectURIs(ctx, appID, withSpike); err != nil {
		t.Fatalf("write as the service user (project.app.write): %v", err)
	}
	mid, err := e.client.AppOIDC(ctx, appID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(mid.RedirectUris, withSpike) {
		t.Fatalf("after the add the list is %v, want %v", mid.RedirectUris, withSpike)
	}
	sameShape(t, before, mid)

	if err := e.client.UpdateAppRedirectURIs(ctx, appID, before.RedirectUris); err != nil {
		t.Fatalf("restore write: %v", err)
	}
	after, err := e.client.AppOIDC(ctx, appID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(after.RedirectUris, before.RedirectUris) {
		t.Fatalf("after the restore the list is %v, want %v", after.RedirectUris, before.RedirectUris)
	}
	sameShape(t, before, after)
}

// TestLabZitadel_URIPermissionDenied is AC2: an identity without app permission (a throwaway
// machine user with no member role at all) gets an explicitly typed permission error and the lab
// list stays untouched — the caller must never read a denial as "maybe written anyway".
func TestLabZitadel_URIPermissionDenied(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	appID := labAppID(t, e, ctx)
	before, err := e.client.AppOIDC(ctx, appID)
	if err != nil {
		t.Fatal(err)
	}

	users := userv2.NewUserServiceClient(e.conn)
	name := fmt.Sprintf("f2009-noperm-%s", strconv.FormatInt(time.Now().UnixNano(), 36))
	desc := "F2-009 permission-denied probe; deleted by the test"
	cu, err := users.CreateUser(e.adminCx, &userv2.CreateUserRequest{
		OrganizationId: e.seeded.OrgID,
		Username:       &name,
		UserType: &userv2.CreateUserRequest_Machine_{Machine: &userv2.CreateUserRequest_Machine{
			Name:        name,
			Description: &desc,
		}},
	})
	if err != nil {
		t.Fatalf("create the probe user: %v", err)
	}
	id := cu.GetId()
	t.Cleanup(func() {
		_, _ = users.DeleteUser(e.adminCx, &userv2.DeleteUserRequest{UserId: id})
	})

	key, err := users.AddKey(e.adminCx, &userv2.AddKeyRequest{
		UserId:         id,
		ExpirationDate: timestamppb.New(time.Now().Add(24 * time.Hour)),
	})
	if err != nil {
		t.Fatalf("add a key to the probe user: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(keyPath, key.GetKeyContent(), 0o600); err != nil {
		t.Fatal(err)
	}

	port, err := strconv.ParseUint(e.ep.Port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	noPerm, err := zitadel.New(ctx, zitadel.Config{
		Host: e.ep.Host, Port: uint16(port), Insecure: !e.ep.TLS,
		KeyFile: keyPath, ProjectID: e.seeded.ProjectID,
	})
	if err != nil {
		t.Fatalf("connect as the probe user: %v", err)
	}
	t.Cleanup(func() { _ = noPerm.Close() })

	err = noPerm.UpdateAppRedirectURIs(ctx, appID, append(slices.Clone(before.RedirectUris), spikeURI))
	if err == nil {
		t.Fatal("an identity without app permission wrote the URI list; refusing to treat the lab as writable")
	}
	if !errors.Is(err, zitadel.ErrPermissionDenied) {
		t.Fatalf("error %v is not ErrPermissionDenied; the caller could not tell denial from failure", err)
	}

	// The refused write must have changed nothing.
	deadline := time.Now().Add(30 * time.Second)
	for {
		after, aerr := e.client.AppOIDC(ctx, appID)
		if aerr != nil {
			t.Fatal(aerr)
		}
		if slices.Equal(after.RedirectUris, before.RedirectUris) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lab list changed to %v without permission; want %v", after.RedirectUris, before.RedirectUris)
		}
		time.Sleep(time.Second)
	}
}

// TestLabZitadel_SiteURISync is F2-010 against the real lab app: the first import takes O as
// current ∩ D (empty here, the spike hosts are new), every pre-existing URI stays in place and
// is listed as foreign, an added host appends, a removed host disappears and nothing else moves.
// As above, the original list is restored and re-verified in t.Cleanup.
func TestLabZitadel_SiteURISync(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	appID := labAppID(t, e, ctx)
	before, err := e.client.AppOIDC(ctx, appID)
	if err != nil {
		t.Fatal(err)
	}
	hostA, hostB := "f2-010-a.tagcess.test", "f2-010-b.tagcess.test"
	uriA, uriB := "https://"+hostA+"/oauth2/callback", "https://"+hostB+"/oauth2/callback"
	for _, u := range []string{uriA, uriB} {
		if slices.Contains(before.RedirectUris, u) {
			t.Fatalf("%s is already in the lab list; a previous run leaked it: %v", u, before.RedirectUris)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cur, err := e.client.AppOIDC(ctx, appID)
		if err != nil {
			t.Errorf("cleanup read: %v", err)
			return
		}
		if slices.Equal(cur.RedirectUris, before.RedirectUris) {
			return
		}
		if err := e.client.UpdateAppRedirectURIs(ctx, appID, before.RedirectUris); err != nil {
			t.Errorf("cleanup restore write: %v (the lab may still hold %s or %s)", err, uriA, uriB)
		}
	})

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sync := zitadel.NewURISync(e.client, appID, st.Queries())
	role := func(hosts ...string) []site.Site { return []site.Site{{Kind: site.KindRole, Hosts: hosts}} }
	list := func() []string {
		t.Helper()
		cur, err := e.client.AppOIDC(ctx, appID)
		if err != nil {
			t.Fatal(err)
		}
		sameShape(t, before, cur)
		return cur.RedirectUris
	}

	res, err := sync.Sync(ctx, role(hostA, hostB))
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if !res.Written || !slices.Equal(res.Foreign, before.RedirectUris) {
		t.Fatalf("first sync written=%v foreign=%v, want a write and every old URI foreign (%v)", res.Written, res.Foreign, before.RedirectUris)
	}
	if want := append(slices.Clone(before.RedirectUris), uriA, uriB); !slices.Equal(list(), want) {
		t.Fatalf("after the add the list is %v, want %v", list(), want)
	}

	if _, err := sync.Sync(ctx, role(hostA)); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if want := append(slices.Clone(before.RedirectUris), uriA); !slices.Equal(list(), want) {
		t.Fatalf("after the delete the list is %v, want %v", list(), want)
	}
	if res, err := sync.CheckDrift(ctx, role(hostA)); err != nil || len(res.Drift) != 0 {
		t.Fatalf("periodic check: drift=%v err=%v, want clean", res.Drift, err)
	}

	if _, err := sync.Sync(ctx, nil); err != nil {
		t.Fatalf("third sync: %v", err)
	}
	if !slices.Equal(list(), before.RedirectUris) {
		t.Fatalf("after removing every host the list is %v, want the original %v", list(), before.RedirectUris)
	}
}
