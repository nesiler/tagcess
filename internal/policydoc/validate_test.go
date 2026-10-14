package policydoc

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/headscale"
)

// fakeChecker is the Checker stand-in; it records whether it was called.
type fakeChecker struct {
	err    error
	calls  int
	gotDoc string
}

func (f *fakeChecker) CheckPolicy(_ context.Context, policy string) error {
	f.calls++
	f.gotDoc = policy
	return f.err
}

var testCfg = DefaultLockedConfig(9000)

func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../render/testdata/prod-policy-anonymized.hujson")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// validDoc is the prod fixture with the locked tests injected: what the writer would validate.
func validDoc(t *testing.T) string {
	t.Helper()
	res, err := Inject(fixture(t), testCfg)
	if err != nil {
		t.Fatal(err)
	}
	return res.Text
}

func TestValidate_RejectsEmptyOversizeBadUTF8(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"whitespace only", " \n\t\r\n "},
		{"oversize", `{"acls":[],"#pad":"` + strings.Repeat("a", MaxSize) + `"}`},
		{"bad utf8", "{\"acls\":[],\"#x\":\"\xff\"}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &fakeChecker{}
			r := Validate(context.Background(), tc.text, testCfg, c)
			if r.Valid() {
				t.Fatal("Valid() = true")
			}
			if got := r.Stage(StageInput).State; got != StateFail {
				t.Errorf("input state = %q, want fail", got)
			}
			for _, s := range []Stage{StageSyntax, StageStructure, StageLocked, StageCheck} {
				if got := r.Stage(s).State; got != StateSkipped {
					t.Errorf("stage %s state = %q, want skipped (rejected before syntax)", s, got)
				}
			}
			if c.calls != 0 {
				t.Errorf("CheckPolicy called %d times for an input-stage rejection", c.calls)
			}
			if r.Hash == "" {
				t.Error("report has no hash")
			}
		})
	}
}

func TestValidate_SyntaxPosition(t *testing.T) {
	// The parser reports the byte offset of the offending character; line/column are derived
	// from it. `]` below sits on line 3, column 8.
	pos := Validate(context.Background(), "{\n  \"a\": 1,\n  \"b\": ]\n}", testCfg, &fakeChecker{})
	st := pos.Stage(StageSyntax)
	if st.State != StateFail {
		t.Fatalf("syntax state = %q, want fail", st.State)
	}
	if st.Line != 3 || st.Column != 8 {
		t.Errorf("position = %d:%d, want 3:8 (message %q)", st.Line, st.Column, st.Message)
	}
	if st.Message == "" {
		t.Error("empty message")
	}
	if pos.Stage(StageStructure).State != StateSkipped {
		t.Error("structure stage ran after a syntax failure")
	}

	// The parser pins bad literals to their start too.
	lit := Validate(context.Background(), `{"acls": [], "#x": "\q"}`, testCfg, &fakeChecker{}).Stage(StageSyntax)
	if lit.State != StateFail || lit.Line != 1 || lit.Column != 20 {
		t.Errorf("bad escape = %+v, want fail at 1:20", lit)
	}

	// An error that carries no offset yields only a message: no position is invented.
	nopos := syntaxFailure(errors.New("something went wrong"))
	if nopos.State != StateFail || nopos.Message == "" || nopos.Line != 0 || nopos.Column != 0 {
		t.Errorf("no-offset error = %+v, want message only", nopos)
	}
}

func TestValidate_NoAclsNoGrants(t *testing.T) {
	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"neither", `{"groups": {}}`, false},
		{"null acls", `{"acls": null}`, false},
		{"acls not an array", `{"acls": {}}`, false},
		{"empty object", `{}`, false},
		{"grants empty (deny-all)", `{"grants": []}`, true},
		{"acls empty (deny-all)", `{"acls": []}`, true},
		{"both", `{"acls": [], "grants": []}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Validate(context.Background(), tc.text, testCfg, &fakeChecker{})
			got := r.Stage(StageStructure).State
			if tc.ok && got != StatePass {
				t.Errorf("structure state = %q (%s), want pass", got, r.Stage(StageStructure).Message)
			}
			if !tc.ok && got != StateFail {
				t.Errorf("structure state = %q, want fail", got)
			}
		})
	}
	msg := Validate(context.Background(), `{"groups": {}}`, testCfg, &fakeChecker{}).Stage(StageStructure).Message
	if !strings.Contains(msg, "allow-all") {
		t.Errorf("message %q does not explain the allow-all risk", msg)
	}
}

func TestValidate_Structure(t *testing.T) {
	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"array root", `[]`, false},
		{"string root", `"x"`, false},
		{"unknown top field", `{"acls": [], "aclz": []}`, false},
		{"duplicate top key", `{"acls": [], "acls": []}`, false},
		{"duplicate differing in case", `{"acls": [], "ACLs": []}`, false},
		{"metadata member, comment, trailing comma",
			"{\n  // c\n  \"#note\": \"x\",\n  /* b */ \"acls\": [],\n}", true},
		{"case-insensitive known name", `{"ACLs": [], "TagOwners": {}}`, true},
		{"every known field", `{"groups":{},"tagOwners":{},"hosts":{},"acls":[],"grants":[],"ssh":[],` +
			`"autoApprovers":{},"nodeAttrs":[],"tests":[],"sshTests":[],"randomizeClientPort":true}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Validate(context.Background(), tc.text, testCfg, &fakeChecker{})
			if r.Stage(StageSyntax).State != StatePass && tc.name != "" && tc.ok {
				t.Fatalf("syntax: %+v", r.Stage(StageSyntax))
			}
			got := r.Stage(StageStructure).State
			if tc.ok && got != StatePass {
				t.Errorf("structure = %q (%s), want pass", got, r.Stage(StageStructure).Message)
			}
			if !tc.ok && got != StateFail {
				t.Errorf("structure = %q, want fail", got)
			}
		})
	}
}

func TestValidate_CheckPolicyStates(t *testing.T) {
	doc := validDoc(t)

	// Accepted: every stage passes and the checker saw exactly the text.
	ok := &fakeChecker{}
	r := Validate(context.Background(), doc, testCfg, ok)
	if !r.Valid() {
		t.Fatalf("valid document rejected: %+v", r.Stages)
	}
	if ok.gotDoc != doc || ok.calls != 1 {
		t.Errorf("checker calls=%d, doc equal=%v", ok.calls, ok.gotDoc == doc)
	}

	// Headscale rejects: its message comes back as a semantic rejection.
	rej := &fakeChecker{err: &headscale.PolicyError{Message: `group "group:nobody" is not defined`}}
	r = Validate(context.Background(), doc, testCfg, rej)
	st := r.Stage(StageCheck)
	if r.Valid() || st.State != StateFail || st.Message != `group "group:nobody" is not defined` {
		t.Errorf("rejection: valid=%v stage=%+v", r.Valid(), st)
	}
	if r.Unverified() {
		t.Error("a semantic rejection is not 'unverified'")
	}

	// Transport trouble: unverified, never valid.
	for _, err := range []error{
		context.DeadlineExceeded,
		errors.New("headscale: CheckPolicy: rpc error: code = Unavailable"),
		context.Canceled,
	} {
		r = Validate(context.Background(), doc, testCfg, &fakeChecker{err: err})
		st = r.Stage(StageCheck)
		if r.Valid() || st.State != StateUnverified || !r.Unverified() {
			t.Errorf("%v: valid=%v stage=%+v", err, r.Valid(), st)
		}
	}

	// Earlier failures never reach Headscale.
	bad := &fakeChecker{}
	if r := Validate(context.Background(), `{"groups": {}}`, testCfg, bad); r.Valid() || bad.calls != 0 {
		t.Errorf("structure failure reached CheckPolicy (calls=%d)", bad.calls)
	}
}

func TestValidate_ReportBoundToText(t *testing.T) {
	doc := validDoc(t)
	r := Validate(context.Background(), doc, testCfg, &fakeChecker{})
	if !r.Valid() {
		t.Fatalf("not valid: %+v", r.Stages)
	}
	if !r.Matches(doc) {
		t.Error("report does not match the text it validated")
	}
	if r.Matches(doc + " ") {
		t.Error("report matches a different text (trailing space)")
	}
	if r.Matches("") {
		t.Error("report matches the empty text")
	}
	other := Validate(context.Background(), doc+"\n", testCfg, &fakeChecker{})
	if other.Hash == r.Hash {
		t.Error("different texts produced the same hash")
	}
	// Even a rejected report is bound to its text.
	rej := Validate(context.Background(), "", testCfg, &fakeChecker{})
	if !rej.Matches("") || rej.Matches(doc) {
		t.Error("rejected report is not bound to its text")
	}
}

func TestValidate_LockedStage(t *testing.T) {
	// A document without the locked tests is rejected before Headscale sees it.
	c := &fakeChecker{}
	r := Validate(context.Background(), fixture(t), testCfg, c)
	st := r.Stage(StageLocked)
	if r.Valid() || st.State != StateFail || c.calls != 0 {
		t.Fatalf("missing locked tests: valid=%v locked=%+v calls=%d", r.Valid(), st, c.calls)
	}
	if !strings.Contains(st.Message, "ui") {
		t.Errorf("message %q does not name the missing rule", st.Message)
	}
}

func TestValidate_CheckPolicyContext(t *testing.T) {
	// The context reaches the checker so a caller deadline bounds the call.
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "v")
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var seen any
	c := checkerFunc(func(ctx context.Context, _ string) error { seen = ctx.Value(key{}); return nil })
	Validate(ctx, validDoc(t), testCfg, c)
	if seen != "v" {
		t.Error("context not passed to CheckPolicy")
	}
}

type checkerFunc func(context.Context, string) error

func (f checkerFunc) CheckPolicy(ctx context.Context, p string) error { return f(ctx, p) }
