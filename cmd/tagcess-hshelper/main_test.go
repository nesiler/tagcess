package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const goodConfig = "server_url: https://hs.example.test\noidc:\n  allowed_groups:\n    - devops\n"

func helperRoot(t *testing.T) (root, conf string) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"requests", "results", "private"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	conf = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(conf, []byte(goodConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	return root, conf
}

// flags builds a complete flag list; overrides replace a flag's value, an empty override drops it.
func flags(root, conf string, overrides map[string]string) []string {
	base := [][2]string{
		{"--config", conf},
		{"--root", root},
		{"--unit", "headscale.service"},
		{"--service-user", "headscale"},
		{"--health", "http://127.0.0.1:8080/health"},
		{"--socket", "/var/run/headscale/headscale.sock"},
		{"--request-uid", strconv.Itoa(os.Getuid())},
	}
	var out []string
	for _, kv := range base {
		v, ok := overrides[kv[0]]
		if !ok {
			v = kv[1]
		}
		if v == "" {
			continue
		}
		out = append(out, kv[0], v)
	}
	return out
}

// AC9: the binary validates its flags (--service-user included) in run, boot and finalize, and
// refuses a missing or relative path; a request cannot supply any of them.
func TestHelperMain_Flags(t *testing.T) {
	root, conf := helperRoot(t)
	bad := map[string]map[string]string{
		"missing config":            {"--config": ""},
		"missing root":              {"--root": ""},
		"missing unit":              {"--unit": ""},
		"missing service-user":      {"--service-user": ""},
		"missing health":            {"--health": ""},
		"missing socket":            {"--socket": ""},
		"missing request-uid":       {"--request-uid": ""},
		"relative config":           {"--config": "config.yaml"},
		"relative root":             {"--root": "var/lib/tagcess-headscale"},
		"relative socket":           {"--socket": "headscale.sock"},
		"config with dot dot":       {"--config": "/etc/headscale/../shadow"},
		"unit without .service":     {"--unit": "headscale"},
		"unit with a slash":         {"--unit": "../headscale.service"},
		"unit with a space":         {"--unit": "head scale.service"},
		"service-user root":         {"--service-user": "root"},
		"service-user with a space": {"--service-user": "head scale"},
		"service-user flag-like":    {"--service-user": "-x"},
		"health on another host":    {"--health": "http://10.0.0.5:8080/health"},
		"health over https":         {"--health": "https://127.0.0.1:8080/health"},
		"health other path":         {"--health": "http://127.0.0.1:8080/metrics"},
		"health with credentials":   {"--health": "http://user:pw@127.0.0.1:8080/health"},
		"request-uid not a number":  {"--request-uid": "abc"},
		"request-uid negative":      {"--request-uid": "-1"},
		"request-uid out of range":  {"--request-uid": "4294967296"},
	}
	for _, mode := range []string{"run", "boot", "finalize"} {
		for name, ov := range bad {
			t.Run(mode+"/"+name, func(t *testing.T) {
				var stderr bytes.Buffer
				if code := run(append([]string{mode}, flags(root, conf, ov)...), &stderr); code != 2 {
					t.Errorf("exit = %d, want 2 (usage); stderr: %s", code, stderr.String())
				}
				if stderr.Len() == 0 {
					t.Error("no message")
				}
			})
		}
	}

	for _, args := range [][]string{
		nil,
		{"apply"},
		{"--config", conf},
		append([]string{"boot", "extra"}, flags(root, conf, nil)...),
	} {
		var stderr bytes.Buffer
		if code := run(args, &stderr); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}

	// Nothing the flags name was touched by the failures above.
	if ents, _ := os.ReadDir(filepath.Join(root, "results")); len(ents) != 0 {
		t.Errorf("results/ was written to: %v", ents)
	}
}

func TestHelperMain_ParsesValidFlags(t *testing.T) {
	root, conf := helperRoot(t)
	mode, s, err := parseArgs(append([]string{"run"}, flags(root, conf, nil)...))
	if err != nil {
		t.Fatal(err)
	}
	if mode != "run" || s.cfg.Root != root || s.cfg.ConfigPath != conf || s.cfg.Unit != "headscale.service" ||
		s.cfg.ServiceUser != "headscale" || s.cfg.RequestUID != uint32(os.Getuid()) ||
		s.health != "http://127.0.0.1:8080/health" || s.socket != "/var/run/headscale/headscale.sock" {
		t.Errorf("mode %q, settings %+v", mode, s)
	}
}

// With valid flags boot works end to end on an empty root: no request, so it only publishes
// status.json from the config's projection.
func TestHelperMain_BootPublishesStatus(t *testing.T) {
	root, conf := helperRoot(t)
	var stderr bytes.Buffer
	if code := run(append([]string{"boot"}, flags(root, conf, nil)...), &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	b, err := os.ReadFile(filepath.Join(root, "results", "status.json"))
	if err != nil || !strings.Contains(string(b), `"allowed_groups":["devops"]`) {
		t.Errorf("status.json = %s, %v", b, err)
	}
	if strings.Contains(stderr.String(), "hs.example.test") {
		t.Error("config content in the log")
	}
}

// A root that is not laid out as installed is a runtime failure (1), not a usage error.
func TestHelperMain_MissingDirsExitOne(t *testing.T) {
	_, conf := helperRoot(t)
	var stderr bytes.Buffer
	if code := run(append([]string{"run"}, flags(t.TempDir(), conf, nil)...), &stderr); code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}
}
