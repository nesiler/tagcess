package k8s

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// F4-034 lab additions: `revoke` makes every token issued so far invalid (the API answers 401, the
// same signal as an expired short-lived token: a real TokenRequest cannot be shorter than 10 minutes)
// and `conflict` adds one Ingress whose paths overlap with different backends. Both only touch the
// run's own namespace, with the bootstrap identity, through lab.sh.

func yamlDocs(t *testing.T, s string) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(s))
	var docs []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if errors.Is(err, io.EOF) {
				return docs
			}
			t.Fatalf("manifest is not YAML: %v\n%s", err, s)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
}

func TestK8sLabRevokeAndConflictScript(t *testing.T) {
	t.Run("revoke recreates only the lab ServiceAccount", func(t *testing.T) {
		res := runScript(t, scriptEnv{}, "revoke", "abc123")
		if res.err != nil {
			t.Fatalf("revoke failed: %v\n%s", res.err, res.out)
		}
		if !strings.Contains(res.log, "delete serviceaccount tagcess-reader -n tagcess-k8s-lab-abc123 ") {
			t.Errorf("the lab ServiceAccount was not deleted:\n%s", res.log)
		}
		for _, line := range strings.Split(res.log, "\n") {
			if strings.HasPrefix(line, "delete ") && !strings.Contains(line, "-n tagcess-k8s-lab-abc123") {
				t.Errorf("unscoped delete: %s", line)
			}
		}
		docs := yamlDocs(t, res.stdin)
		if len(docs) != 1 || str(docs[0]["kind"]) != "ServiceAccount" {
			t.Fatalf("revoke must re-apply exactly the ServiceAccount, got %s", res.stdin)
		}
		meta, _ := docs[0]["metadata"].(map[string]any)
		if str(meta["name"]) != "tagcess-reader" || str(meta["namespace"]) != "tagcess-k8s-lab-abc123" {
			t.Errorf("ServiceAccount metadata = %v", meta)
		}
		labels, _ := meta["labels"].(map[string]any)
		if str(labels["tagcess.io/k8s-lab"]) != "abc123" {
			t.Errorf("ServiceAccount lost its run label: %v", labels)
		}
	})

	t.Run("conflict adds one overlapping Ingress and its second Service", func(t *testing.T) {
		res := runScript(t, scriptEnv{}, "conflict", "abc123", "traefik")
		if res.err != nil {
			t.Fatalf("conflict failed: %v\n%s", res.err, res.out)
		}
		for _, bad := range []string{"secrets", "ClusterRole", "Role", `"*"`, "create", "delete", "patch"} {
			if strings.Contains(res.stdin, bad) {
				t.Errorf("conflict manifest contains %q", bad)
			}
		}
		var kinds []string
		var ingress map[string]any
		for _, d := range yamlDocs(t, res.stdin) {
			kinds = append(kinds, str(d["kind"]))
			meta, _ := d["metadata"].(map[string]any)
			if str(meta["namespace"]) != "tagcess-k8s-lab-abc123" {
				t.Errorf("%s is not in the run namespace: %v", str(d["kind"]), meta)
			}
			if labels, _ := meta["labels"].(map[string]any); str(labels["tagcess.io/k8s-lab"]) != "abc123" {
				t.Errorf("%s has no run label", str(d["kind"]))
			}
			if str(d["kind"]) == "Ingress" {
				ingress = d
			}
		}
		slices.Sort(kinds)
		if !slices.Equal(kinds, []string{"Ingress", "Service"}) {
			t.Fatalf("conflict manifest kinds = %v", kinds)
		}
		spec, _ := ingress["spec"].(map[string]any)
		if str(spec["ingressClassName"]) != "traefik" {
			t.Errorf("ingressClassName = %v", spec["ingressClassName"])
		}
		if !strings.Contains(res.stdin, "traefik.ingress.kubernetes.io/router.entrypoints: websecure") {
			t.Errorf("the Ingress does not name the websecure entrypoint:\n%s", res.stdin)
		}
		// Both paths overlap (/ and /app, Prefix) and point at different Services.
		if !strings.Contains(res.stdin, "path: /app") || strings.Count(res.stdin, "pathType: Prefix") != 2 {
			t.Errorf("the Ingress has no overlapping Prefix paths:\n%s", res.stdin)
		}
	})

	t.Run("run id and class are validated before kubectl is called", func(t *testing.T) {
		for _, id := range []string{"", "ABC", "../x", "abc123;rm", "kube-system"} {
			for _, sub := range []string{"revoke", "conflict"} {
				res := runScript(t, scriptEnv{}, sub, id, "traefik")
				if res.err == nil || res.log != "" {
					t.Errorf("%s %q: err=%v, kubectl log=%q", sub, id, res.err, res.log)
				}
			}
		}
		res := runScript(t, scriptEnv{}, "conflict", "abc123", "Bad Class")
		if res.err == nil || res.log != "" {
			t.Errorf("an invalid class reached kubectl: err=%v log=%q", res.err, res.log)
		}
	})
}

// Lab.Revoke and Lab.AddConflict drive the two sub-commands with the bootstrap identity and fail the
// test when the script fails; they never need a second identity.
func TestK8sLabRevokeAndConflictCommands(t *testing.T) {
	api := startLabAPI(t, "kubernetes.lab.test")
	run := &fakeRunner{out: healthyOutputs(api)}
	tb := &fakeTB{t: t}
	lab, _ := newTestLab(t, tb, run)
	if p := tb.play(lab.Setup); p != nil {
		t.Fatalf("Setup panicked: %v", p)
	}
	lab.Revoke()
	lab.AddConflict()
	if got := run.called("revoke"); len(got) != 1 || !slices.Equal(got[0].args, []string{"revoke", lab.RunID}) {
		t.Errorf("revoke calls = %+v", got)
	}
	if got := run.called("conflict"); len(got) != 1 || !slices.Equal(got[0].args, []string{"conflict", lab.RunID, "traefik"}) {
		t.Errorf("conflict calls = %+v", got)
	}

	failing := &fakeRunner{out: healthyOutputs(api), err: map[string]error{"revoke": errors.New("boom")}}
	tb2 := &fakeTB{t: t}
	lab2, _ := newTestLab(t, tb2, failing)
	tb2.play(lab2.Setup)
	tb2.fatal = ""
	tb2.play(lab2.Revoke)
	if !strings.Contains(tb2.fatal, "revoke") {
		t.Errorf("a failed revoke must fail the test, fatal = %q", tb2.fatal)
	}
}
