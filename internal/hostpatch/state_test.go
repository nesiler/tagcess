package hostpatch

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func rawResult(state, phase, errCode, changed, health string) string {
	return fmt.Sprintf(`{"version":1,"request_id":%q,"state":%q,"phase":%q,"finished_at":"2026-10-02T10:00:00Z","error_code":%q,"config_changed":%s,"health_verified":%s}`,
		testID, state, phase, errCode, changed, health)
}

// AC5: result.json is read strictly and "unknown" config_changed stays null.
func TestHostPatch_DecodeResultStrict(t *testing.T) {
	t.Run("valid results", func(t *testing.T) {
		tests := []struct {
			name        string
			doc         string
			state       State
			phase       Phase
			code        ErrorCode
			changedNil  bool
			changed     bool
			healthy     bool
			wantEncoded bool
		}{
			{"succeeded", rawResult("succeeded", "check", "", "true", "true"), StateSucceeded, PhaseCheck, "", false, true, true, true},
			{"failed before the replace", rawResult("failed", "validate", "configtest_failed", "false", "false"), StateFailed, PhaseValidate, CodeConfigtestFailed, false, false, false, true},
			{"failed with unknown change", rawResult("failed", "restart", "restart_failed", "null", "false"), StateFailed, PhaseRestart, CodeRestartFailed, true, false, false, true},
			{"interrupted without a phase", rawResult("interrupted", "", "journal_corrupt", "null", "false"), StateInterrupted, "", CodeJournalCorrupt, true, false, false, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				r, err := DecodeResult([]byte(tt.doc))
				if err != nil {
					t.Fatalf("DecodeResult: %v", err)
				}
				if r.Version != 1 || r.RequestID != testID || r.State != tt.state || r.Phase != tt.phase || r.ErrorCode != tt.code {
					t.Errorf("decoded = %+v", r)
				}
				if got := r.FinishedAt; !got.Equal(time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)) {
					t.Errorf("finished_at = %v", got)
				}
				if tt.changedNil != (r.ConfigChanged == nil) {
					t.Fatalf("config_changed = %v, want nil=%v", r.ConfigChanged, tt.changedNil)
				}
				if r.ConfigChanged != nil && *r.ConfigChanged != tt.changed {
					t.Errorf("config_changed = %v", *r.ConfigChanged)
				}
				if r.HealthVerified != tt.healthy {
					t.Errorf("health_verified = %v", r.HealthVerified)
				}
				enc, err := EncodeResult(r)
				if err != nil {
					t.Fatalf("EncodeResult: %v", err)
				}
				if string(enc) != tt.doc {
					t.Errorf("round trip:\n%s\n%s", enc, tt.doc)
				}
			})
		}
	})

	good := rawResult("failed", "replace", "replace_failed", "null", "false")
	tests := []struct{ name, doc string }{
		{"empty", ``},
		{"not an object", `[]`},
		{"unknown state", rawResult("running", "check", "", "true", "true")},
		{"non-terminal state accepted", rawResult("accepted", "validate", "", "false", "false")},
		{"non-terminal state applying", rawResult("applying", "backup", "", "null", "false")},
		{"state uppercase", rawResult("Succeeded", "check", "", "true", "true")},
		{"unknown phase", rawResult("failed", "rollback", "replace_failed", "null", "false")},
		{"unknown error code", rawResult("failed", "check", "disk_full", "null", "false")},
		{"error code on success", rawResult("succeeded", "check", "health_failed", "true", "true")},
		{"failure without error code", rawResult("failed", "check", "", "true", "false")},
		{"extra field", strings.TrimSuffix(good, "}") + `,"config":"x"}`},
		{"extra field raw_output", strings.TrimSuffix(good, "}") + `,"raw_output":"..."}`},
		{"duplicate key", strings.Replace(good, `{"version":1,`, `{"version":1,"version":1,`, 1)},
		{"duplicate state", strings.Replace(good, `"state":"failed",`, `"state":"failed","state":"succeeded",`, 1)},
		{"wrong version", strings.Replace(good, `"version":1`, `"version":2`, 1)},
		{"bad request id", strings.Replace(good, testID, strings.ToUpper(testID), 1)},
		{"bad finished_at", strings.Replace(good, `2026-10-02T10:00:00Z`, `yesterday`, 1)},
		{"finished_at without zone", strings.Replace(good, `2026-10-02T10:00:00Z`, `2026-10-02T10:00:00`, 1)},
		{"config_changed missing", strings.Replace(good, `"config_changed":null,`, ``, 1)},
		{"config_changed as string", strings.Replace(good, `"config_changed":null`, `"config_changed":"yes"`, 1)},
		{"health_verified null", strings.Replace(good, `"health_verified":false`, `"health_verified":null`, 1)},
		{"health_verified missing", strings.Replace(good, `,"health_verified":false`, ``, 1)},
		{"trailing data", good + `{}`},
		{"invalid utf-8", strings.Replace(good, `"replace"`, "\"rep\xfflace\"", 1)},
		{"over 4 KiB", strings.TrimSuffix(good, "}") + `,"x":"` + strings.Repeat("a", MaxResultBytes) + `"}`},
	}
	for _, tt := range tests {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			if _, err := DecodeResult([]byte(tt.doc)); !errors.Is(err, ErrInvalidResult) {
				t.Errorf("err = %v, want ErrInvalidResult", err)
			}
		})
	}

	t.Run("encode refuses an invalid result", func(t *testing.T) {
		if _, err := EncodeResult(Result{Version: 1, RequestID: testID, State: "bogus"}); !errors.Is(err, ErrInvalidResult) {
			t.Errorf("err = %v, want ErrInvalidResult", err)
		}
	})
	t.Run("encode writes UTC seconds", func(t *testing.T) {
		yes := true
		loc := time.FixedZone("x", 3*3600)
		b, err := EncodeResult(Result{
			Version: 1, RequestID: testID, State: StateSucceeded, Phase: PhaseCheck,
			FinishedAt: time.Date(2026, 10, 2, 13, 0, 0, 123, loc), ConfigChanged: &yes, HealthVerified: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if want := rawResult("succeeded", "check", "", "true", "true"); string(b) != want {
			t.Errorf("encoded:\n%s\nwant\n%s", b, want)
		}
	})
}

func rawStatus(id, state, phase, groups, rev string) string {
	return rawStatusErr(id, state, phase, groups, rev, "")
}

func rawStatusErr(id, state, phase, groups, rev, configErr string) string {
	return fmt.Sprintf(`{"version":1,"request_id":%q,"state":%q,"phase":%q,"allowed_groups":%s,"base_rev":%q,"config_error":%q}`,
		id, state, phase, groups, rev, configErr)
}

func mustRev(t *testing.T, groups ...string) string {
	t.Helper()
	rev, err := BaseRev(groups)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// AC5: status.json is read strictly.
func TestHostPatch_DecodeStatusStrict(t *testing.T) {
	emptyRev := mustRev(t)
	devopsRev := mustRev(t, "devops")
	twoRev := mustRev(t, "devops", "developer")

	t.Run("valid statuses", func(t *testing.T) {
		tests := []struct {
			name   string
			doc    string
			id     string
			state  State
			groups []string
		}{
			{"fresh helper without a request", rawStatus("", "", "", `[]`, emptyRev), "", "", []string{}},
			{"succeeded", rawStatus(testID, "succeeded", "check", `["devops","developer"]`, twoRev), testID, StateSucceeded, []string{"devops", "developer"}},
			{"applying", rawStatus(testID, "applying", "restart", `["devops"]`, devopsRev), testID, StateApplying, []string{"devops"}},
			{"accepted", rawStatus(testID, "accepted", "validate", `["devops"]`, devopsRev), testID, StateAccepted, []string{"devops"}},
			{"interrupted without a phase", rawStatus(testID, "interrupted", "", `["devops"]`, devopsRev), testID, StateInterrupted, []string{"devops"}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, err := DecodeStatus([]byte(tt.doc))
				if err != nil {
					t.Fatalf("DecodeStatus: %v", err)
				}
				if s.RequestID != tt.id || s.State != tt.state || strings.Join(s.AllowedGroups, ",") != strings.Join(tt.groups, ",") {
					t.Errorf("decoded = %+v", s)
				}
				if s.AllowedGroups == nil {
					t.Error("allowed_groups must decode to a non-nil slice")
				}
				enc, err := EncodeStatus(s)
				if err != nil {
					t.Fatalf("EncodeStatus: %v", err)
				}
				if string(enc) != tt.doc {
					t.Errorf("round trip:\n%s\n%s", enc, tt.doc)
				}
			})
		}
	})

	good := rawStatus(testID, "succeeded", "check", `["devops"]`, devopsRev)
	tests := []struct{ name, doc string }{
		{"empty", ``},
		{"not an object", `null`},
		{"unknown state", rawStatus(testID, "done", "check", `["devops"]`, devopsRev)},
		{"unknown phase", rawStatus(testID, "succeeded", "finish", `["devops"]`, devopsRev)},
		{"state without an id", rawStatus("", "succeeded", "check", `["devops"]`, devopsRev)},
		{"id without a state", rawStatus(testID, "", "", `["devops"]`, devopsRev)},
		{"phase without an id", rawStatus("", "", "check", `[]`, emptyRev)},
		{"bad id", rawStatus(strings.ToUpper(testID), "succeeded", "check", `["devops"]`, devopsRev)},
		{"allowed_groups null", rawStatus(testID, "succeeded", "check", `null`, devopsRev)},
		{"unknown group", rawStatus(testID, "succeeded", "check", `["admins"]`, devopsRev)},
		{"duplicate group", rawStatus(testID, "succeeded", "check", `["devops","devops"]`, devopsRev)},
		{"non-canonical order", rawStatus(testID, "succeeded", "check", `["developer","devops"]`, twoRev)},
		{"base_rev for other groups", rawStatus(testID, "succeeded", "check", `["devops"]`, twoRev)},
		{"base_rev uppercase", rawStatus(testID, "succeeded", "check", `["devops"]`, strings.ToUpper(devopsRev))},
		{"extra field", strings.TrimSuffix(good, "}") + `,"config":"x"}`},
		{"unknown config_error", rawStatusErr("", "", "", `null`, "", "boom")},
		{"config_error with groups", rawStatusErr("", "", "", `["devops"]`, devopsRev, "config_unreadable")},
		{"config_error with a rev", rawStatusErr("", "", "", `null`, emptyRev, "config_unreadable")},
		{"config_error with an empty list", rawStatusErr("", "", "", `[]`, "", "config_unreadable")},
		{"missing config_error", strings.Replace(good, `,"config_error":""`, ``, 1)},
		{"duplicate key", strings.Replace(good, `"state":"succeeded",`, `"state":"succeeded","state":"failed",`, 1)},
		{"missing base_rev", strings.Replace(good, `,"base_rev":"`+devopsRev+`"`, ``, 1)},
		{"wrong version", strings.Replace(good, `"version":1`, `"version":2`, 1)},
		{"trailing data", good + `x`},
		{"invalid utf-8", strings.Replace(good, `"check"`, "\"che\xffck\"", 1)},
		{"over 4 KiB", strings.TrimSuffix(good, "}") + `,"x":"` + strings.Repeat("a", MaxResultBytes) + `"}`},
	}
	for _, tt := range tests {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			if _, err := DecodeStatus([]byte(tt.doc)); !errors.Is(err, ErrInvalidStatus) {
				t.Errorf("err = %v, want ErrInvalidStatus", err)
			}
		})
	}

	t.Run("config_error status", func(t *testing.T) {
		doc := rawStatusErr(testID, "succeeded", "check", `null`, "", "config_unreadable")
		s, err := DecodeStatus([]byte(doc))
		if err != nil {
			t.Fatalf("DecodeStatus: %v", err)
		}
		if s.ConfigError != CodeConfigUnreadable || s.AllowedGroups != nil || s.BaseRev != "" {
			t.Errorf("decoded = %+v: an unreadable config must not become an empty list", s)
		}
		enc, err := EncodeStatus(s)
		if err != nil || string(enc) != doc {
			t.Errorf("round trip: %s, %v", enc, err)
		}
		bad := Status{Version: 1, ConfigError: CodeConfigUnreadable, AllowedGroups: []string{}}
		if _, err := EncodeStatus(bad); !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("empty list with config_error: err = %v, want ErrInvalidStatus", err)
		}
	})
	t.Run("encode refuses an inconsistent status", func(t *testing.T) {
		s := Status{Version: 1, AllowedGroups: []string{"devops"}, BaseRev: emptyRev}
		if _, err := EncodeStatus(s); !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("err = %v, want ErrInvalidStatus", err)
		}
	})
	t.Run("encode writes an empty list, not null", func(t *testing.T) {
		b, err := EncodeStatus(Status{Version: 1, BaseRev: emptyRev})
		if err != nil {
			t.Fatal(err)
		}
		if want := rawStatus("", "", "", `[]`, emptyRev); string(b) != want {
			t.Errorf("encoded:\n%s\nwant\n%s", b, want)
		}
	})
}

// AC6: a marker is one valid UUID, at most 64 bytes.
func TestHostPatch_Marker(t *testing.T) {
	t.Run("accepts", func(t *testing.T) {
		for name, in := range map[string]string{
			"bare uuid":        testID,
			"trailing newline": testID + "\n",
		} {
			id, err := ParseMarker([]byte(in))
			if err != nil || id != testID {
				t.Errorf("%s: id = %q, err = %v", name, id, err)
			}
		}
	})
	t.Run("rejects", func(t *testing.T) {
		tests := []struct{ name, in string }{
			{"empty", ""},
			{"only a newline", "\n"},
			{"uppercase", strings.ToUpper(testID)},
			{"no dashes", strings.ReplaceAll(testID, "-", "")},
			{"short", testID[:35]},
			{"non-hex", testID[:35] + "g"},
			{"leading space", " " + testID},
			{"trailing space", testID + " "},
			{"two newlines", testID + "\n\n"},
			{"crlf", testID + "\r\n"},
			{"two lines", testID + "\n" + testID},
			{"newline in the middle", testID[:10] + "\n" + testID[11:]},
			{"nul byte", testID + "\x00"},
			{"trailing garbage within the limit", testID + "x"},
			{"over 64 bytes", testID + strings.Repeat(" ", 64-len(testID)+1)},
			{"far over 64 bytes", strings.Repeat("a", 4096)},
			{"invalid utf-8", testID[:35] + "\xff"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if id, err := ParseMarker([]byte(tt.in)); !errors.Is(err, ErrInvalidMarker) {
					t.Errorf("id = %q, err = %v, want ErrInvalidMarker", id, err)
				}
			})
		}
	})
	t.Run("a marker of exactly 64 bytes still needs a valid uuid", func(t *testing.T) {
		if _, err := ParseMarker([]byte(testID + strings.Repeat("0", 64-len(testID)))); !errors.Is(err, ErrInvalidMarker) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("FormatMarker round trips and validates", func(t *testing.T) {
		b, err := FormatMarker(testID)
		if err != nil {
			t.Fatal(err)
		}
		if id, err := ParseMarker(b); err != nil || id != testID {
			t.Errorf("id = %q, err = %v", id, err)
		}
		if _, err := FormatMarker(strings.ToUpper(testID)); !errors.Is(err, ErrInvalidMarker) {
			t.Errorf("err = %v", err)
		}
	})
}
