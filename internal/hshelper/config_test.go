package hshelper

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

var update = flag.Bool("update", false, "rewrite golden files")

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustRev(t *testing.T, groups []string) string {
	t.Helper()
	rev, err := hostpatch.BaseRev(groups)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// AC1: the projection and base_rev match F3b-004's; a missing field projects to [].
func TestHelperConfig_Project(t *testing.T) {
	tests := []struct {
		file string
		want []string
	}{
		{"no_field.in.yaml", []string{}},
		{"empty.in.yaml", []string{}},
		{"flow.in.yaml", []string{"devops", "standart"}},
		{"commented.in.yaml", []string{"devops", "developer"}},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			groups, rev, err := Project(readFixture(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if groups == nil || !slices.Equal(groups, tc.want) {
				t.Fatalf("groups = %#v, want %#v", groups, tc.want)
			}
			if rev != mustRev(t, tc.want) {
				t.Fatalf("base_rev = %s, want hostpatch.BaseRev of %v", rev, tc.want)
			}
		})
	}

	t.Run("null value and non-canonical order", func(t *testing.T) {
		groups, rev, err := Project([]byte("oidc:\n  allowed_groups:\n"))
		if err != nil || len(groups) != 0 || rev != mustRev(t, nil) {
			t.Fatalf("null: %v %v %v", groups, rev, err)
		}
		groups, rev, err = Project([]byte("oidc:\n  allowed_groups: [standart, devops]\n"))
		if err != nil || !slices.Equal(groups, []string{"devops", "standart"}) || rev != mustRev(t, []string{"devops", "standart"}) {
			t.Fatalf("order: %v %v %v", groups, rev, err)
		}
	})
}

// stripTarget decodes a document and removes oidc.allowed_groups, leaving every other path.
func stripTarget(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("candidate does not parse: %v", err)
	}
	oidc, ok := m["oidc"].(map[string]any)
	if !ok {
		t.Fatalf("oidc missing or not a map: %#v", m["oidc"])
	}
	delete(oidc, "allowed_groups")
	return m
}

var commentRE = regexp.MustCompile(`#.*$`)

func comments(b []byte) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if c := commentRE.FindString(line); c != "" {
			out = append(out, strings.TrimSpace(c))
		}
	}
	return out
}

// AC2: only oidc.allowed_groups changes; comments survive; output matches the golden file.
func TestHelperConfig_CandidateOnlyTarget(t *testing.T) {
	want := []string{"devops", "developer"}
	for _, name := range []string{"no_field", "empty", "flow", "commented"} {
		t.Run(name, func(t *testing.T) {
			src := readFixture(t, name+".in.yaml")
			cand, err := Candidate(src, []string{"developer", "devops"})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(stripTarget(t, src), stripTarget(t, cand)) {
				t.Fatalf("a path other than oidc.allowed_groups changed:\n%s", cand)
			}

			// Every comment must stay, including the ones on the replaced list.
			gotComments := comments(cand)
			for _, c := range comments(src) {
				if !slices.Contains(gotComments, c) {
					t.Errorf("comment %q lost", c)
				}
			}

			golden := filepath.Join("testdata", name+".out.golden.yaml")
			if *update {
				if err := os.WriteFile(golden, cand, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			wantOut, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if string(cand) != string(wantOut) {
				t.Errorf("candidate differs from %s:\n%s", golden, cand)
			}

			// Deterministic.
			again, err := Candidate(src, []string{"devops", "developer"})
			if err != nil || string(again) != string(cand) {
				t.Errorf("candidate is not deterministic (err %v)", err)
			}
			groups, _, err := Project(cand)
			if err != nil || !slices.Equal(groups, want) {
				t.Errorf("candidate projects to %v, %v", groups, err)
			}
		})
	}
}

// AC3: the candidate projects to the requested list with the new base_rev.
func TestHelperConfig_CandidateProjects(t *testing.T) {
	tests := []struct {
		name string
		file string
		in   []string
		want []string
	}{
		{"add to missing", "no_field.in.yaml", []string{"devops"}, []string{"devops"}},
		{"replace empty", "empty.in.yaml", []string{"standart", "devops", "developer"}, []string{"devops", "developer", "standart"}},
		{"replace flow", "flow.in.yaml", []string{"devops"}, []string{"devops"}},
		{"replace block", "commented.in.yaml", []string{"devops", "standart"}, []string{"devops", "standart"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := readFixture(t, tc.file)
			_, oldRev, err := Project(src)
			if err != nil {
				t.Fatal(err)
			}
			cand, err := Candidate(src, tc.in)
			if err != nil {
				t.Fatal(err)
			}
			groups, rev, err := Project(cand)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(groups, tc.want) || rev != mustRev(t, tc.want) {
				t.Fatalf("projected %v / %s", groups, rev)
			}
			if rev == oldRev {
				t.Fatal("base_rev did not change")
			}
		})
	}

	t.Run("invalid groups are not a config error", func(t *testing.T) {
		src := readFixture(t, "no_field.in.yaml")
		for _, in := range [][]string{nil, {"developer"}, {"devops", "devops"}, {"devops", "root"}} {
			_, err := Candidate(src, in)
			if !errors.Is(err, hostpatch.ErrInvalidRequest) || errors.Is(err, ErrConfigUnreadable) {
				t.Errorf("Candidate(%v) err = %v", in, err)
			}
		}
	})
}

// AC4: every unreadable shape is rejected with config_unreadable, by both entry points.
func TestHelperConfig_RejectsUnreadable(t *testing.T) {
	tests := map[string]string{
		"empty file":               "",
		"comment only":             "# nothing\n",
		"not yaml":                 "oidc: [unclosed\n",
		"tab indent":               "oidc:\n\tallowed_groups: [devops]\n",
		"root is a list":           "- oidc\n",
		"root is a scalar":         "just text\n",
		"no oidc":                  "server_url: https://hs.example.test\n",
		"oidc null":                "oidc:\nserver_url: x\n",
		"oidc scalar":              "oidc: enabled\n",
		"oidc list":                "oidc:\n  - a\n",
		"multiple documents":       "oidc:\n  issuer: a\n---\noidc:\n  issuer: b\n",
		"two documents, 2nd empty": "oidc:\n  issuer: a\n---\n",
		"duplicate oidc":           "oidc:\n  issuer: a\noidc:\n  issuer: b\n",
		"duplicate target":         "oidc:\n  allowed_groups: [devops]\n  allowed_groups: [devops, developer]\n",
		"duplicate elsewhere":      "log:\n  level: info\n  level: debug\noidc:\n  issuer: a\n",
		"anchored oidc":            "oidc: &o\n  issuer: a\n",
		"aliased oidc":             "base: &b\n  issuer: a\noidc: *b\n",
		"alias inside oidc":        "x: &g [devops]\noidc:\n  allowed_groups: *g\n",
		"anchor inside oidc":       "oidc:\n  issuer: &i a\n  client_id: *i\n",
		"merge into oidc":          "base: &b\n  issuer: a\noidc:\n  <<: *b\n",
		"merge at root":            "base: &b\n  oidc:\n    issuer: a\n<<: *b\n",
		"groups is a scalar":       "oidc:\n  allowed_groups: devops\n",
		"groups is a map":          "oidc:\n  allowed_groups:\n    devops: true\n",
		"group is a number":        "oidc:\n  allowed_groups: [1]\n",
		"group is a null":          "oidc:\n  allowed_groups: [~]\n",
		"group is a list":          "oidc:\n  allowed_groups: [[devops]]\n",
		"group outside set":        "oidc:\n  allowed_groups: [devops, admins]\n",
		"group repeated":           "oidc:\n  allowed_groups: [devops, devops]\n",
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Project([]byte(src)); !errors.Is(err, ErrConfigUnreadable) {
				t.Errorf("Project err = %v", err)
			}
			if _, err := Candidate([]byte(src), []string{"devops"}); !errors.Is(err, ErrConfigUnreadable) {
				t.Errorf("Candidate err = %v", err)
			}
		})
	}

	t.Run("error code", func(t *testing.T) {
		_, _, err := Project(nil)
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Code() != hostpatch.CodeConfigUnreadable {
			t.Fatalf("err = %#v", err)
		}
	})
}

// AC5: errors never carry config content, secrets or the offending value.
func TestHelperConfig_ErrorsCarryNoContent(t *testing.T) {
	const secret = "s3cr3t-VALUE-9f2c"
	bad := map[string]string{
		"not yaml":        "oidc:\n  client_secret: " + secret + "\n  bad: [unclosed\n",
		"inline secret":   "oidc:\n  client_secret: " + secret + "\n  allowed_groups: [devops, " + secret + "]\n",
		"secret as group": "oidc:\n  allowed_groups: [" + secret + "]\n",
		"secret as key":   "oidc:\n  " + secret + ": 1\n  " + secret + ": 2\n",
		"secret anchor":   "oidc:\n  client_secret: &" + strings.ReplaceAll(secret, "-", "_") + " " + secret + "\n",
		"no oidc":         "client_secret: " + secret + "\n",
		"two docs":        "a: " + secret + "\n---\nb: " + secret + "\n",
		"secret scalar":   secret + "\n",
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			_, _, perr := Project([]byte(src))
			_, cerr := Candidate([]byte(src), []string{"devops"})
			for _, err := range []error{perr, cerr} {
				if err == nil {
					t.Fatal("expected an error")
				}
				if msg := err.Error(); strings.Contains(msg, secret) || strings.Contains(msg, strings.ReplaceAll(secret, "-", "_")) {
					t.Errorf("error carries content: %q", msg)
				}
			}
		})
	}

	// A readable config with a secret still never leaks it through a request-validation error.
	src := "oidc:\n  client_secret: " + secret + "\n"
	if _, err := Candidate([]byte(src), []string{"devops", secret}); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("invalid-group error = %v", err)
	}
	// The candidate itself keeps the secret (it is the host's file); the projection never has it.
	cand, err := Candidate([]byte(src), []string{"devops"})
	if err != nil || !strings.Contains(string(cand), secret) {
		t.Errorf("candidate dropped the inline secret (err %v)", err)
	}
	groups, rev, err := Project(cand)
	if err != nil || strings.Contains(strings.Join(groups, ",")+rev, secret) {
		t.Errorf("projection leaks: %v %v %v", groups, rev, err)
	}
}
