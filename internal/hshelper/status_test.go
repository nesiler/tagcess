package hshelper

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

func (e *env) status() (hostpatch.Status, []byte) {
	e.t.Helper()
	b := e.read("results/status.json")
	s, err := hostpatch.DecodeStatus(b)
	if err != nil {
		e.t.Fatalf("status.json is not a valid status: %v\n%s", err, b)
	}
	return s, b
}

// AC4: every mode publishes status.json atomically with the last request and the current view,
// and nothing but IDs, states, groups and the rev.
func TestStatus_PublishedNoSecrets(t *testing.T) {
	modes := []struct {
		name  string
		setup func(e *env)
		run   func(e *env)
		id    string
		state hostpatch.State
		phase hostpatch.Phase
	}{
		{"run", func(e *env) { e.publish(idA, "devops", "developer") }, func(e *env) { e.run() }, idA, hostpatch.StateAccepted, ""},
		{"boot", func(e *env) {
			e.setFullJournal(Journal{RequestID: idA, State: hostpatch.StateApplying, Phase: hostpatch.PhaseReplace})
		}, func(e *env) { e.boot() }, idA, hostpatch.StateInterrupted, hostpatch.PhaseReplace},
		{"finalize", func(e *env) {
			e.setFullJournal(Journal{RequestID: idA, State: hostpatch.StateApplying, Phase: hostpatch.PhaseCheck})
		}, func(e *env) { e.finalize() }, idA, hostpatch.StateInterrupted, hostpatch.PhaseCheck},
		{"finalize on a terminal journal", func(e *env) { e.setJournal(idA, hostpatch.StateFailed) }, func(e *env) { e.finalize() }, idA, hostpatch.StateFailed, ""},
		{"boot on a fresh helper", func(e *env) {}, func(e *env) { e.boot() }, "", "", ""},
	}
	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.proj.groups = []string{"devops", "developer"}
			tt.setup(e)
			tt.run(e)

			s, raw := e.status()
			wantRev, _ := hostpatch.BaseRev(e.proj.groups)
			if s.RequestID != tt.id || s.State != tt.state || s.Phase != tt.phase || s.BaseRev != wantRev ||
				strings.Join(s.AllowedGroups, ",") != "devops,developer" || s.ConfigError != "" {
				t.Errorf("status = %+v", s)
			}
			if len(raw) > hostpatch.MaxResultBytes {
				t.Errorf("status.json is %d bytes", len(raw))
			}
			for _, bad := range []string{"secret", "client_id", "client_secret", "oidc:", "/etc/", "backup"} {
				if strings.Contains(strings.ToLower(string(raw)), bad) {
					t.Errorf("status.json mentions %q: %s", bad, raw)
				}
			}
			if st, err := os.Stat(e.path("results/status.json")); err != nil || st.Mode().Perm() != 0o644 {
				t.Errorf("status.json: %v, %v", st, err)
			}
			if m, _ := os.ReadDir(e.path("results")); len(m) > 2 {
				t.Errorf("results/ holds leftovers: %v", m)
			}
			if _, err := os.Stat(e.path("private/journal.json")); err == nil {
				if st, _ := os.Stat(e.path("private/journal.json")); st.Mode().Perm() != 0o600 {
					t.Errorf("journal mode = %v, want 0600", st.Mode().Perm())
				}
			}
			if e.exists("results/result.json") {
				if st, _ := os.Stat(e.path("results/result.json")); st.Mode().Perm() != 0o644 {
					t.Errorf("result mode = %v, want 0644", st.Mode().Perm())
				}
			}
		})
	}

	t.Run("a rejected run still publishes the status", func(t *testing.T) {
		e := newEnv(t)
		e.write("requests/request.ready", "junk")
		e.run()
		if s, _ := e.status(); s.RequestID != "" {
			t.Errorf("status = %+v; a rejection does not touch the journal", s)
		}
	})

	t.Run("an unreadable journal keeps the last status", func(t *testing.T) {
		e := newEnv(t)
		e.boot()
		before := e.read("results/status.json")
		e.write("private/journal.json", `{"version":`)
		_, _ = Run(e.cfg)
		if string(before) != string(e.read("results/status.json")) {
			t.Error("status.json was replaced although the journal cannot be read")
		}
	})
}

// AC5: an unreadable config is an error in status.json, never an empty list.
func TestStatus_ProjectorFailureNotEmptyList(t *testing.T) {
	leaky := errors.New("open /etc/headscale/config.yaml: client_secret: hunter2")
	tests := []struct {
		name string
		err  error
	}{
		{"config error", &ConfigError{reason: "several documents"}},
		{"any other read failure", leaky},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.proj.err = tt.err
			e.setJournal(idA, hostpatch.StateSucceeded)
			if out, err := Boot(e.cfg); err != nil || out != OutcomeIdle {
				t.Fatalf("Boot = %v, %v; a status failure must not fail the mode", out, err)
			}
			s, raw := e.status()
			if s.ConfigError != hostpatch.CodeConfigUnreadable || s.AllowedGroups != nil || s.BaseRev != "" {
				t.Errorf("status = %+v, want config_error and no groups/rev", s)
			}
			if !strings.Contains(string(raw), `"allowed_groups":null`) {
				t.Errorf("allowed_groups must be null, not []: %s", raw)
			}
			if s.RequestID != idA || s.State != hostpatch.StateSucceeded {
				t.Errorf("the last request is still reported: %+v", s)
			}
			logged := strings.Join(e.logs, "\n")
			if !strings.Contains(logged, "config_unreadable") {
				t.Errorf("no config_unreadable log entry: %q", logged)
			}
			if strings.Contains(logged, "hunter2") || strings.Contains(string(raw), "hunter2") {
				t.Errorf("a raw error leaked: %q %s", logged, raw)
			}
		})
	}

	t.Run("recovers once the config is readable", func(t *testing.T) {
		e := newEnv(t)
		e.proj.err = leaky
		e.boot()
		e.proj.err = nil
		e.boot()
		if s, _ := e.status(); s.ConfigError != "" || len(s.AllowedGroups) != 1 {
			t.Errorf("status = %+v", s)
		}
	})
}
