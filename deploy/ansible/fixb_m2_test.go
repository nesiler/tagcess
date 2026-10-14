//go:build installer

package installer

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/test/adopttarget"
)

func fixB_rollback(t *testing.T, tg *adopttarget.Target, home string, vars map[string]any, extra map[string]string, tag string) adopttarget.Result {
	t.Helper()
	return adopttarget.RunPlaybook(t, adopttarget.PlaybookOpts{Playbook: "rollback.yml", Inventories: []string{tg.Inventory}, ConfigHome: home,
		Vars: vars, ExtraVars: extra, Tags: []string{tag}})
}

// M2: a second, no-op hs_tags run must not erase what the first run recorded for rollback: the tag the installer added
// is still removed again by the rollback (and the phase backed up the Headscale database before the first tag change).
func TestFixB_NoopSecondRunKeepsTagRollback(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	// A second, untagged node named like the k8s host (userspace tailscaled; the real one is never reached).
	tg.Sh(t, `set -e
		mkdir -p /var/lib/ts2
		systemd-run --unit=ts2 tailscaled --tun=userspace-networking --state=/var/lib/ts2/tailscaled.state --socket=/run/ts2.sock --port=41642
		headscale users create k8s >/dev/null
		uid=$(headscale users list -o json | python3 -c 'import json,sys;print([u["id"] for u in json.load(sys.stdin) if u["name"]=="k8s"][0])')
		key=$(headscale preauthkeys create --user "$uid" --expiration 10m 2>/dev/null | tail -1)
		sleep 2
		tailscale --socket=/run/ts2.sock up --login-server http://127.0.0.1:8080 --authkey "$key" --hostname k8s-host-like --accept-dns=false >/dev/null
		# Headscale does not take the last tag off a tagged node: this node has another tag before the installer adds its own.
		nid=$(headscale nodes list -o json | python3 -c 'import json,sys;print([n["id"] for n in json.load(sys.stdin) if n["given_name"]=="k8s-host-like"][0])')
		headscale nodes tag -i "$nid" -t tag:vpn-server >/dev/null`)
	vars := adopttarget.Merge(adopttarget.AdoptVars(), map[string]any{"hs_k8s_node": "k8s-host-like"})
	home := t.TempDir()
	yes := map[string]string{"confirm_hs_tags": "yes"}
	first := mustRun(t, tg, home, vars, yes, "hs_tags")
	if err := fixB_backupFirst(first.Output, "hs_tags"); err != nil {
		t.Error(err)
	}
	if !strings.Contains(tg.Sh(t, "headscale nodes list -o json"), `"tag:k8s"`) {
		t.Fatal("the confirmed tag was not applied")
	}
	mustRun(t, tg, home, vars, yes, "hs_tags") // nothing left to add
	if st := tg.ReadFile(t, "/var/lib/tagcess-install/state.json"); !strings.Contains(st, "k8s-host-like") {
		t.Fatalf("the second run erased the added tag from the state:\n%s", st)
	}
	rb := fixB_rollback(t, tg, home, vars, nil, "hs_tags")
	if rb.ExitCode != 0 {
		t.Fatalf("rollback hs_tags:\n%s", tail(rb.Output, 30))
	}
	var nodes []struct {
		GivenName string   `json:"given_name"`
		Tags      []string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(tg.Sh(t, "headscale nodes list -o json")), &nodes); err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.GivenName == "k8s-host-like" && strings.Join(n.Tags, ",") != "tag:vpn-server" {
			t.Fatalf("after the rollback the node has tags %v, want only the one it had before the installer", n.Tags)
		}
	}
	if len(fixB_backupIDs(t, tg, "rollback-hs_tags")) != 1 {
		t.Fatal("the rollback did not back up today's state first")
	}
}

// M2: a pre-existing tagcess image/config pair comes back after two app runs (the second one with another image under
// the same tag): the rollback returns to the first backup's config and the image from before the installer's first run.
func TestFixB_AppRollbackAfterSecondRunRestoresOriginalPair(t *testing.T) {
	t.Parallel()
	tg := adopttarget.Up(t, "adopt")
	vars := appVars(t, tg)
	home := t.TempDir()
	mustRun(t, tg, home, vars, nil, "host", "hshelper")
	archive, tag := imageArchive(t, tg)
	if out, err := exec.Command("docker", "cp", archive, tg.Name+":/root/pre-image.tar.gz").CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v %s", err, out)
	}
	// The pair that exists before the installer's first app run.
	tg.Sh(t, "gunzip -c /root/pre-image.tar.gz | docker load >/dev/null")
	original := strings.TrimSpace(tg.Sh(t, "docker image inspect -f '{{.Id}}' "+tag))
	const preConfig = "# pre-existing tagcess config\n"
	tg.WriteFile(t, "/etc/tagcess/config.yaml", preConfig, "0644", "root:root")

	mustRun(t, tg, home, vars, nil, "app")
	// Another image under the same tag (what a later run's image would be), then a second app run.
	tg.Sh(t, `set -e
		docker create --name fixb-img `+tag+` >/dev/null
		docker commit --change 'LABEL fixb=2' fixb-img `+tag+` >/dev/null
		docker rm fixb-img >/dev/null`)
	if now := strings.TrimSpace(tg.Sh(t, "docker image inspect -f '{{.Id}}' "+tag)); now == original {
		t.Fatal("test setup: the second image has the same id")
	}
	res := mustRun(t, tg, home, vars, nil, "app")
	if err := fixB_backupFirst(res.Output, "app (second run)"); err != nil {
		t.Error(err)
	}
	if !strings.Contains(tg.ReadFile(t, "/etc/tagcess/config.yaml"), "tagcess") || tg.ReadFile(t, "/etc/tagcess/config.yaml") == preConfig {
		t.Fatal("test setup: the installer did not write its config")
	}

	rb := fixB_rollback(t, tg, home, vars, nil, "app")
	if rb.ExitCode != 0 {
		t.Fatalf("rollback app:\n%s", tail(rb.Output, 40))
	}
	if got := tg.ReadFile(t, "/etc/tagcess/config.yaml"); got != preConfig {
		t.Fatalf("the config is not the pre-existing one after the rollback:\n%s", got)
	}
	if got := strings.TrimSpace(tg.Sh(t, "docker image inspect -f '{{.Id}}' "+tag)); got != original {
		t.Fatalf("the image under %s is %s after the rollback, want the pre-existing %s (the rollback used the last run's image)", tag, got, original)
	}
}
