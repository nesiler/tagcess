package policydoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/headscale"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	wantUI      = `{ /* tagcess:locked */ "src": "group:devops", "accept": ["tag:vpn-server:443"] }`
	wantWebhook = `{ /* tagcess:locked */ "src": "tag:k8s", "accept": ["tag:vpn-server:9000"] }`
	wantSSH     = `{ /* tagcess:locked */ "src": "group:devops", "accept": ["tag:vpn-server:22", "tag:k8s:22"] }`
	marker      = `/* tagcess:locked */`
)

func TestLockedTests_InjectIdempotent(t *testing.T) {
	orig := fixture(t)
	res, err := Inject(orig, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed() || len(res.Changes) != 3 {
		t.Fatalf("changes = %+v, want 3 additions", res.Changes)
	}
	for _, c := range res.Changes {
		if c.Kind != ChangeAdded {
			t.Errorf("change %+v, want added", c)
		}
	}
	for _, want := range []string{wantUI, wantWebhook, wantSSH} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("injected text lacks %s", want)
		}
	}

	// The prod fixture, with the locked tests, as a golden file.
	golden := "testdata/prod-policy-locked.golden.hujson"
	if *update {
		if err := os.WriteFile(golden, []byte(res.Text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != string(want) {
		t.Errorf("injected fixture differs from %s (run with -update after reviewing)\n%s", golden, res.Text)
	}

	// Second call: no change at all.
	again, err := Inject(res.Text, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed() || again.Text != res.Text {
		t.Errorf("second Inject changed the document: %+v", again.Changes)
	}

	// The result is a valid document for the other stages.
	if r := Validate(t.Context(), res.Text, testCfg, &fakeChecker{}); !r.Valid() {
		t.Errorf("injected document is not valid: %+v", r.Stages)
	}
}

// TestLockedTests_InjectPreservesRest: an existing tests array with a user test, comments and a
// trailing comma keeps every original line; only the three canonical lines are new.
func TestLockedTests_InjectPreservesRest(t *testing.T) {
	orig := `{
  // keep me
  "acls": [], /* and me */
  "tests": [
    // user test
    { "src": "group:devops", "accept": ["tag:k8s:6443"] },
  ],
  "#tail": "x",
}
`
	res, err := Inject(orig, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 3 {
		t.Fatalf("changes = %+v", res.Changes)
	}
	// Remove the three canonical lines: what is left must be the original byte for byte, except
	// the comma the new elements need after the user test (which already had one here).
	rest := res.Text
	for _, line := range []string{wantUI, wantWebhook, wantSSH} {
		i := strings.Index(rest, line)
		if i < 0 {
			t.Fatalf("missing %s in\n%s", line, res.Text)
		}
		// drop the line break and indentation before the entry and the comma after it
		start := strings.LastIndex(rest[:i], "\n")
		end := i + len(line)
		if strings.HasPrefix(rest[end:], ",") {
			end++
		}
		rest = rest[:start] + rest[end:]
	}
	if rest != orig {
		t.Errorf("rest differs from the original:\n--- got\n%s\n--- want\n%s", rest, orig)
	}
	if again, _ := Inject(res.Text, testCfg); again.Changed() {
		t.Error("not idempotent")
	}
}

func TestLockedTests_ModifiedEntryReplaced(t *testing.T) {
	orig := `{
  "acls": [],
  "tests": [
    { "src": "group:devops", "accept": ["tag:k8s:6443"] },
    { /* tagcess:locked */ "src": "group:devops", "accept": ["tag:vpn-server:4443"] },
    { /* tagcess:locked */ "src": "group:nobody", "accept": ["tag:k8s:1"] },
    { /* tagcess:locked */ "src": "group:devops", "accept": ["tag:vpn-server:22", "tag:k8s:22"] }
  ]
}`
	res, err := Inject(orig, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "4443") || strings.Contains(res.Text, "group:nobody") {
		t.Errorf("the user's version of a locked entry survived:\n%s", res.Text)
	}
	if !strings.Contains(res.Text, `{ "src": "group:devops", "accept": ["tag:k8s:6443"] }`) {
		t.Error("the unmarked user test was touched")
	}
	if n := strings.Count(res.Text, marker); n != 3 {
		t.Errorf("%d marked entries, want 3", n)
	}
	if !strings.Contains(res.Text, wantUI) || !strings.Contains(res.Text, wantWebhook) {
		t.Errorf("canonical entries missing:\n%s", res.Text)
	}
	if n := strings.Count(res.Text, wantSSH); n != 1 {
		t.Errorf("ssh entry present %d times, want 1 (kept, not duplicated)", n)
	}
	kinds := map[ChangeKind]int{}
	rules := map[string]bool{}
	for _, c := range res.Changes {
		kinds[c.Kind]++
		rules[c.Rule] = true
	}
	if kinds[ChangeReplaced] != 2 || kinds[ChangeAdded]+kinds[ChangeRemoved] != 0 {
		t.Errorf("changes = %+v, want two replacements (ui, webhook)", res.Changes)
	}
	if !rules["ui"] || !rules["webhook"] {
		t.Errorf("changes name rules %v, want ui and webhook", rules)
	}
	if again, _ := Inject(res.Text, testCfg); again.Changed() {
		t.Error("not idempotent")
	}

	// A marked entry beyond the canonical set is removed.
	extra := `{"acls": [], "tests": [
    { /* tagcess:locked */ "src": "group:x", "accept": ["tag:k8s:1"] }
  ]}`
	res, err = Inject(extra, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "group:x") || strings.Count(res.Text, marker) != 3 {
		t.Errorf("stale marked entry kept:\n%s", res.Text)
	}

	// A changed parameter (webhook port) replaces the stale entry.
	moved := testCfg
	moved.WebhookPort = 9100
	res, err = Inject(validDoc(t), moved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "vpn-server:9000") || !strings.Contains(res.Text, "vpn-server:9100") {
		t.Errorf("webhook entry not rebuilt:\n%s", res.Text)
	}
	if len(res.Changes) != 1 || res.Changes[0].Kind != ChangeReplaced || res.Changes[0].Rule != "webhook" {
		t.Errorf("changes = %+v", res.Changes)
	}
}

// strictTests mirrors Headscale's policy decoding of a tests entry: unknown members are an error
// (0.29.3 rejects `"#tagcess"` with "unknown field", F5 L1).
type strictTests struct {
	ACLs  json.RawMessage `json:"acls"`
	Tests []struct {
		Src    string   `json:"src"`
		Proto  string   `json:"proto"`
		Accept []string `json:"accept"`
		Deny   []string `json:"deny"`
	} `json:"tests"`
}

func decodeStrict(text string) error {
	std, err := hujson.Standardize([]byte(text))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	var v strictTests
	return dec.Decode(&v)
}

// TestLockedTests_NoMetadataMember (F5 L1): the injected entries carry no extra JSON member, so a
// parser that rejects unknown fields accepts them. The control: the old "#tagcess" member fails it.
func TestLockedTests_NoMetadataMember(t *testing.T) {
	res, err := Inject(`{"tests": []}`, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(res.Text); err != nil {
		t.Errorf("injected tests rejected by a strict parser: %v\n%s", err, res.Text)
	}
	legacy := `{"tests": [{ "#tagcess": "locked", "src": "group:devops", "accept": ["tag:vpn-server:443"] }]}`
	if err := decodeStrict(legacy); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("control: legacy member not rejected: %v", err)
	}
}

// TestLockedTests_LegacyMemberMigrated (F5 L1): entries written with the old "#tagcess" member are
// still recognised as locked and rewritten with the comment marker on the next Inject; no
// "#tagcess" member and no duplicate remains, and the user's test is untouched.
func TestLockedTests_LegacyMemberMigrated(t *testing.T) {
	orig := `{
  "acls": [],
  "tests": [
    { "src": "group:devops", "accept": ["tag:k8s:6443"] },
    { "#tagcess": "locked", "src": "group:devops", "accept": ["tag:vpn-server:443"] },
    { "#tagcess": "locked", "src": "tag:k8s", "accept": ["tag:vpn-server:9000"] },
    { "#tagcess": "locked", "src": "group:devops", "accept": ["tag:vpn-server:22", "tag:k8s:22"] },
    { "#tagcess": "locked", "src": "group:old", "accept": ["tag:k8s:1"] }
  ]
}`
	res, err := Inject(orig, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "#tagcess") || strings.Contains(res.Text, "group:old") {
		t.Errorf("legacy entries survived:\n%s", res.Text)
	}
	for _, want := range []string{wantUI, wantWebhook, wantSSH, `{ "src": "group:devops", "accept": ["tag:k8s:6443"] }`} {
		if n := strings.Count(res.Text, want); n != 1 {
			t.Errorf("%s present %d times, want 1:\n%s", want, n, res.Text)
		}
	}
	if err := decodeStrict(res.Text); err != nil {
		t.Errorf("migrated document rejected by a strict parser: %v", err)
	}
	if again, _ := Inject(res.Text, testCfg); again.Changed() {
		t.Error("not idempotent")
	}
	// Validate sees the legacy entries as not canonical: the writer must Inject first.
	if r := Validate(t.Context(), orig, testCfg, &fakeChecker{}); r.Valid() {
		t.Error("legacy document passed the locked stage")
	}
}

// TestLockedTests_UnmarkedCanonicalAdopted (F5 L1): a canonical entry whose marker comment was
// removed is taken back (marked again), not duplicated.
func TestLockedTests_UnmarkedCanonicalAdopted(t *testing.T) {
	marked, err := Inject(`{"acls": []}`, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Replace(marked.Text, wantUI, `{ "src": "group:devops", "accept": ["tag:vpn-server:443"] }`, 1)
	if stripped == marked.Text {
		t.Fatal("test bug: nothing stripped")
	}
	res, err := Inject(stripped, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != marked.Text {
		t.Errorf("unmarked canonical entry not re-marked in place:\n%s", res.Text)
	}
}

func TestLockedTests_InjectErrors(t *testing.T) {
	for name, text := range map[string]string{
		"syntax":          `{"acls": `,
		"root not object": `[]`,
		"tests not array": `{"acls": [], "tests": {}}`,
		"duplicate tests": `{"acls": [], "tests": [], "tests": []}`,
	} {
		if _, err := Inject(text, testCfg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	for name, mutate := range map[string]func(*LockedConfig){
		"zero webhook port": func(c *LockedConfig) { c.WebhookPort = 0 },
		"port too big":      func(c *LockedConfig) { c.UIPort = 70000 },
		"empty group":       func(c *LockedConfig) { c.DevopsGroup = "" },
		"quote in tag":      func(c *LockedConfig) { c.ServerTag = `tag:a"b` },
		"no ssh dst":        func(c *LockedConfig) { c.SSHDst = nil },
	} {
		cfg := testCfg
		cfg.SSHDst = append([]string(nil), testCfg.SSHDst...)
		mutate(&cfg)
		if _, err := Inject(`{"acls": []}`, cfg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestLockedTests_FailureNamesRule(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		rule string // "" = not a locked test
	}{
		{"ui", "test(s) failed:\ngroup:devops -> tag:vpn-server:443: expected ALLOWED, got DENIED", "ui"},
		{"webhook", "test(s) failed:\ntag:k8s -> tag:vpn-server:9000: expected ALLOWED, got DENIED", "webhook"},
		{"ssh", "test(s) failed:\ngroup:devops -> tag:k8s:22: expected ALLOWED, got DENIED", "ssh"},
		{"ssh with proto", "test(s) failed:\ngroup:devops -> tag:vpn-server:22 (tcp): expected ALLOWED, got DENIED", "ssh"},
		{"resolve error", "test(s) failed:\ngroup:devops: error testing \"tag:vpn-server:443\": destination resolved to no IP addresses: \"tag:vpn-server:443\"", "ui"},
		{"user test only", "test(s) failed:\ngroup:developer -> tag:k8s:6443: expected ALLOWED, got DENIED", ""},
		{"not a test failure", `group "group:nobody" is not defined`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &headscale.PolicyError{Message: tc.msg}
			out := ClassifyCheckError(testCfg, in)
			var le *LockedTestError
			if tc.rule == "" {
				if errors.As(out, &le) {
					t.Fatalf("classified as locked test %q", le.Rule)
				}
				if !errors.Is(out, in) {
					t.Errorf("error replaced: %v", out)
				}
				return
			}
			if !errors.As(out, &le) {
				t.Fatalf("not a LockedTestError: %v", out)
			}
			if le.Rule != tc.rule {
				t.Errorf("rule = %q, want %q", le.Rule, tc.rule)
			}
			if !strings.Contains(le.Error(), tc.rule) || le.Detail == "" {
				t.Errorf("error %q lacks the rule name or detail", le.Error())
			}
		})
	}
	// Transport errors are never reclassified.
	plain := errors.New("rpc unavailable")
	if !errors.Is(ClassifyCheckError(testCfg, plain), plain) {
		t.Error("plain error replaced")
	}

	// End to end: Validate reports the rule.
	c := &fakeChecker{err: &headscale.PolicyError{Message: cases[0].msg}}
	r := Validate(t.Context(), validDoc(t), testCfg, c)
	if r.Valid() || r.Locked == nil || r.Locked.Rule != "ui" {
		t.Fatalf("report: valid=%v locked=%v", r.Valid(), r.Locked)
	}
	if st := r.Stage(StageCheck); st.State != StateFail || !strings.Contains(st.Message, "ui") {
		t.Errorf("check stage = %+v", st)
	}
}

// TestLockedTests_MarkerOnlyExact (F5 L1, Codex review): the marker counts only as the whole comment
// tagcess writes before the first member. A user test whose comment merely mentions the marker text
// is the user's and survives Inject. Controls: real entries are re-injected, legacy ones migrated.
func TestLockedTests_MarkerOnlyExact(t *testing.T) {
	for name, entry := range map[string]string{
		"before": `{ /* see tagcess:locked */ "src": "group:x", "accept": ["tag:a:1"] }`,
		"after":  `{ /* tagcess:locked */ /* mine */ "src": "group:x", "accept": ["tag:a:1"] }`,
		"within": `{ /* do not remove: tagcess:locked is reserved */ "src": "group:x", "deny": ["tag:a:1"] }`,
		"line":   "{ // mentions /* tagcess:locked */ here\n \"src\": \"group:x\", \"deny\": [\"tag:a:1\"] }",
	} {
		t.Run(name, func(t *testing.T) {
			res, err := Inject(`{"tests": [`+entry+`]}`, testCfg)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(res.Text, "group:x") {
				t.Errorf("user test deleted:\n%s", res.Text)
			}
			for _, want := range []string{wantUI, wantWebhook, wantSSH} {
				if strings.Count(res.Text, want) != 1 {
					t.Errorf("%s not injected once:\n%s", want, res.Text)
				}
			}
		})
	}
	// Controls: the real marker replaces a modified entry; a legacy member still migrates.
	res, err := Inject(`{"tests": [{ /* tagcess:locked */ "src": "group:old", "accept": ["tag:k8s:1"] }, { "#tagcess": "locked", "src": "group:old2", "accept": ["tag:k8s:2"] }]}`, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "group:old") || strings.Contains(res.Text, "#tagcess") {
		t.Errorf("tagcess-owned entries survived:\n%s", res.Text)
	}
}
