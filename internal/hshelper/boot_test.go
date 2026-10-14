package hshelper

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

func (e *env) boot() Outcome {
	e.t.Helper()
	out, err := Boot(e.cfg)
	if err != nil {
		e.t.Fatalf("Boot: %v", err)
	}
	return out
}

func (e *env) finalize() Outcome {
	e.t.Helper()
	out, err := Finalize(e.cfg)
	if err != nil {
		e.t.Fatalf("Finalize: %v", err)
	}
	return out
}

func (e *env) setFullJournal(j Journal) {
	e.t.Helper()
	j.Version = hostpatch.Version
	if err := WriteJournal(e.path("private"), j); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(rel string) []byte {
	e.t.Helper()
	b, err := os.ReadFile(e.path(rel))
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// wantInterrupted checks result.json and the journal agree on an interrupted request.
func (e *env) wantInterrupted(id string, code hostpatch.ErrorCode, phase hostpatch.Phase, changed *bool) {
	e.t.Helper()
	r := e.result()
	if r.RequestID != id || r.State != hostpatch.StateInterrupted || r.ErrorCode != code || r.Phase != phase || r.HealthVerified {
		e.t.Errorf("result = %+v, want interrupted/%s/%s for %s", r, code, phase, id)
	}
	switch {
	case changed == nil && r.ConfigChanged != nil:
		e.t.Errorf("config_changed = %v, want unknown (null)", *r.ConfigChanged)
	case changed != nil && (r.ConfigChanged == nil || *r.ConfigChanged != *changed):
		e.t.Errorf("config_changed = %v, want %v", r.ConfigChanged, *changed)
	}
	j := e.journal()
	if j.RequestID != id || j.State != hostpatch.StateInterrupted || j.ErrorCode != code {
		e.t.Errorf("journal = %+v, want interrupted/%s for %s", j, code, id)
	}
}

func boolp(b bool) *bool { return &b }

// AC1: an accepted/applying journal is not resumed; it becomes interrupted and its ID gets a result.
func TestBoot_MarksInterrupted(t *testing.T) {
	tests := []struct {
		name    string
		journal Journal
		changed *bool
	}{
		{"accepted: nothing was touched yet", Journal{RequestID: idA, State: hostpatch.StateAccepted}, boolp(false)},
		{"applying at backup", Journal{
			RequestID: idA, State: hostpatch.StateApplying, Phase: hostpatch.PhaseBackup,
			BaseHash: "b", CandidateHash: "c", BackupRef: "backup-1",
		}, nil},
		{"applying at restart", Journal{RequestID: idA, State: hostpatch.StateApplying, Phase: hostpatch.PhaseRestart}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.setFullJournal(tt.journal)
			if out := e.boot(); out != OutcomeInterrupted {
				t.Fatalf("outcome = %v", out)
			}
			e.wantInterrupted(idA, hostpatch.CodeInterrupted, tt.journal.Phase, tt.changed)
			j := e.journal()
			if j.Phase != tt.journal.Phase || j.BaseHash != tt.journal.BaseHash || j.CandidateHash != tt.journal.CandidateHash ||
				j.BackupRef != tt.journal.BackupRef {
				t.Errorf("journal lost its trail: %+v, was %+v", j, tt.journal)
			}
			if out := e.boot(); out != OutcomeIdle {
				t.Errorf("second boot: outcome = %v, want idle", out)
			}
		})
	}
}

func TestBoot_TerminalOrFreshJournalChangesNothing(t *testing.T) {
	for _, st := range []hostpatch.State{hostpatch.StateSucceeded, hostpatch.StateFailed, hostpatch.StateInterrupted} {
		e := newEnv(t)
		e.setJournal(idA, st)
		before := e.read("private/journal.json")
		if out := e.boot(); out != OutcomeIdle {
			t.Errorf("%s: outcome = %v", st, out)
		}
		if e.exists("results/result.json") || !bytes.Equal(before, e.read("private/journal.json")) {
			t.Errorf("%s: boot changed a terminal journal or invented a result", st)
		}
	}
	e := newEnv(t)
	if out := e.boot(); out != OutcomeIdle || e.exists("results/result.json") || e.exists("private/journal.json") {
		t.Errorf("fresh helper: outcome = %v; boot must not invent a journal or result", out)
	}
}

// AC1: a published but never journalled request is not run; its marker is consumed with an
// interrupted result.
func TestBoot_ConsumesStaleMarker(t *testing.T) {
	tests := []struct {
		name  string
		setup func(e *env)
		id    string
	}{
		{"fresh helper", func(e *env) {}, idB},
		{"terminal journal of an older ID", func(e *env) { e.setJournal(idA, hostpatch.StateSucceeded) }, idB},
		{"journal accepted for the same ID (crash before the marker was consumed)", func(e *env) {
			e.setJournal(idB, hostpatch.StateAccepted)
		}, idB},
		{"non-terminal journal of another ID", func(e *env) {
			e.setFullJournal(Journal{RequestID: idA, State: hostpatch.StateApplying, Phase: hostpatch.PhaseReplace})
		}, idB},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			tt.setup(e)
			e.publish(tt.id)
			if out := e.boot(); out != OutcomeInterrupted {
				t.Fatalf("outcome = %v", out)
			}
			if e.exists("requests/request.ready") || e.exists("requests/"+tt.id+".json") {
				t.Error("marker or request file not consumed")
			}
			if e.exists("private/request.json") {
				t.Error("the stale request was copied to private/")
			}
			// Same-ID crash after the journal: the request was accepted but never run, so the config
			// is still the old one in every case here.
			e.wantInterrupted(tt.id, hostpatch.CodeInterrupted, "", boolp(false))
			if out := e.run(); out != OutcomeIdle {
				t.Errorf("run after boot: outcome = %v; the stale request must not run", out)
			}
		})
	}
}

func TestBoot_MarkerOfAnAnsweredIDKeepsItsResult(t *testing.T) {
	e := newEnv(t)
	e.setJournal(idA, hostpatch.StateSucceeded)
	if err := WriteResult(e.path("results"), hostpatch.Result{
		Version: 1, RequestID: idA, State: hostpatch.StateSucceeded, Phase: hostpatch.PhaseCheck,
		FinishedAt: e.now, ConfigChanged: boolp(true), HealthVerified: true,
	}); err != nil {
		t.Fatal(err)
	}
	before := e.read("results/result.json")
	e.publish(idA)
	e.boot()
	if e.exists("requests/request.ready") {
		t.Error("marker not consumed")
	}
	if !bytes.Equal(before, e.read("results/result.json")) {
		t.Error("a repeated ID overwrote the existing result")
	}
}

func TestBoot_JunkMarkerIsConsumedWithoutAResult(t *testing.T) {
	e := newEnv(t)
	e.setJournal(idA, hostpatch.StateSucceeded)
	e.write("requests/request.ready", "not a uuid")
	e.boot()
	if e.exists("requests/request.ready") {
		t.Error("junk marker kept")
	}
	if e.exists("results/result.json") {
		t.Error("a junk marker must not overwrite or create a result")
	}
}

// AC2: a corrupt or lost journal is kept aside, interrupted/journal_corrupt is published, and the
// next request starts a new sound journal.
func TestJournal_CorruptPreservedAndReplaced(t *testing.T) {
	corrupt := []byte(`{"version":1,"request_id":"` + idA + `","state":"appl`)
	preserved := func(e *env) []string {
		m, _ := filepath.Glob(e.path("private", "journal.json.corrupt-*"))
		return m
	}
	tests := []struct {
		name  string
		setup func(e *env)
		keep  []byte
	}{
		{"truncated journal", func(e *env) { e.write("private/journal.json", string(corrupt)) }, corrupt},
		{"unknown state", func(e *env) {
			e.write("private/journal.json", `{"version":1,"request_id":"`+idA+`","state":"done","phase":"","base_hash":"","candidate_hash":"","backup_ref":"","error_code":""}`)
		}, nil},
		{"lost journal with a trace of a request", func(e *env) { e.write("private/request.json", "{}") }, nil},
	}
	for _, tt := range tests {
		for _, mode := range []string{"boot", "finalize"} {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				e := newEnv(t)
				tt.setup(e)
				var out Outcome
				if mode == "boot" {
					out = e.boot()
				} else {
					out = e.finalize()
				}
				if out != OutcomeInterrupted {
					t.Fatalf("outcome = %v", out)
				}
				e.wantInterrupted(nilID, hostpatch.CodeJournalCorrupt, "", nil)
				if tt.name == "lost journal with a trace of a request" {
					if n := preserved(e); len(n) != 0 {
						t.Errorf("nothing to preserve, found %v", n)
					}
				} else {
					n := preserved(e)
					if len(n) != 1 {
						t.Fatalf("preserved files = %v, want 1", n)
					}
					if tt.keep != nil {
						if got, _ := os.ReadFile(n[0]); !bytes.Equal(got, tt.keep) {
							t.Errorf("preserved content = %q", got)
						}
					}
				}
				if st, err := os.Stat(e.path("private/journal.json")); err != nil || st.Mode().Perm() != 0o600 {
					t.Errorf("new journal: %v, %v", st, err)
				}

				// The next request is accepted with the new journal.
				e.publish(idB)
				if out := e.run(); out != OutcomeAccepted {
					t.Fatalf("next request: outcome = %v", out)
				}
				if j := e.journal(); j.RequestID != idB || j.State != hostpatch.StateAccepted {
					t.Errorf("journal = %+v", j)
				}
			})
		}
	}

	t.Run("lost journal without any trace is a fresh helper", func(t *testing.T) {
		e := newEnv(t)
		if out := e.boot(); out != OutcomeIdle || e.exists("results/result.json") || e.exists("private/journal.json") {
			t.Errorf("outcome = %v; nothing should be created", out)
		}
	})
	t.Run("a corrupt journal never lets Run write", func(t *testing.T) {
		e := newEnv(t)
		e.write("private/journal.json", string(corrupt))
		e.publish(idB)
		if _, err := Run(e.cfg); err == nil {
			t.Fatal("Run on a corrupt journal returned no error")
		}
		if !e.exists("requests/request.ready") || e.exists("private/request.json") || e.exists("results/result.json") {
			t.Error("Run changed something with a corrupt journal")
		}
	})
}

// AC3: finalize interrupts a non-terminal journal and leaves a terminal one alone.
func TestFinalize_Interrupted(t *testing.T) {
	t.Run("non-terminal", func(t *testing.T) {
		for _, st := range []hostpatch.State{hostpatch.StateAccepted, hostpatch.StateApplying} {
			e := newEnv(t)
			e.setFullJournal(Journal{RequestID: idA, State: st, Phase: hostpatch.PhaseRestart})
			if out := e.finalize(); out != OutcomeInterrupted {
				t.Fatalf("%s: outcome = %v", st, out)
			}
			var changed *bool
			if st == hostpatch.StateAccepted {
				changed = boolp(false)
			}
			e.wantInterrupted(idA, hostpatch.CodeInterrupted, hostpatch.PhaseRestart, changed)
		}
	})
	t.Run("terminal journal is untouched", func(t *testing.T) {
		for _, st := range []hostpatch.State{hostpatch.StateSucceeded, hostpatch.StateFailed, hostpatch.StateInterrupted} {
			e := newEnv(t)
			e.setJournal(idA, st)
			if err := WriteResult(e.path("results"), hostpatch.Result{
				Version: 1, RequestID: idA, State: hostpatch.StateInterrupted, FinishedAt: e.now, ErrorCode: hostpatch.CodeInterrupted,
			}); err != nil {
				t.Fatal(err)
			}
			j, r := e.read("private/journal.json"), e.read("results/result.json")
			if out := e.finalize(); out != OutcomeIdle {
				t.Errorf("%s: outcome = %v", st, out)
			}
			if !bytes.Equal(j, e.read("private/journal.json")) || !bytes.Equal(r, e.read("results/result.json")) {
				t.Errorf("%s: finalize changed a terminal journal or its result", st)
			}
		}
	})
	t.Run("a pending marker is left for run", func(t *testing.T) {
		e := newEnv(t)
		e.setJournal(idA, hostpatch.StateSucceeded)
		e.publish(idB)
		e.finalize()
		if !e.exists("requests/request.ready") {
			t.Error("finalize consumed the marker")
		}
	})
}
