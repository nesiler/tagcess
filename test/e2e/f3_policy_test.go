//go:build integration

// End-to-end scenarios for F3-030 (the policy half of the F3 exit criteria): the real tagcess
// binary driven through its interface on the unix socket, a disposable database-mode Headscale
// with registered nodes (so the locked tests resolve to real addresses instead of passing on an
// empty source) and the lab Zitadel. See f3_stack_test.go and `make e2e`.
package e2e_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/nesiler/tagcess/internal/policyrev"
)

const (
	f3K8sTag     = "tag:k8s"
	lockedMarker = `/* tagcess:locked */`
)

// f3RichPolicy is the document the policy scenarios start from: every section the interface does
// not own (hosts, grants, ssh, autoApprovers, nodeAttrs, a user test, an unknown metadata member),
// comments in odd places and trailing commas. The ACLs satisfy the three locked tests: devops
// reach the tagcess port (443) on the server tag, the k8s tag reaches the webhook port (9443, the
// port the e2e binary listens on) and devops reach ssh on both server tags.
const f3RichPolicy = `// F3-030 rich fixture: kept byte for byte by an editor save.
{
  "#note": "kept as is",
  "groups": {
    // Zitadel owns this section
    "group:devops": [],
    "group:standart": [], // trailing comment
  },
  "hosts": {
    "lab-net": "10.20.0.0/16", // lab network
    "lab-host": "10.20.0.7",
  },
  "tagOwners": {
    // vpn-host: Caddy, Headscale
    "tag:vpn-server": ["group:devops"], // owner note
    /* k8s node */
    "tag:k8s": ["group:devops"],
    "tag:shared": ["group:devops"],
  },
  "acls": [ // access rules
    // everyone reaches the gate
    { "action": "accept", "src": ["autogroup:member"], "dst": ["tag:vpn-server:80"] }, // gate
    // the tagcess interface
    { "action": "accept", "src": ["group:devops"], "dst": ["tag:vpn-server:443"] }, // ui
    // the webhook caller
    { "action": "accept", "src": ["tag:k8s"], "dst": ["tag:vpn-server:9443"] }, // webhook
    // devops ssh
    // (two comment lines)
    {
      "action": "accept",
      "proto": "tcp",
      "src": ["group:devops"],
      "dst": ["tag:vpn-server:22", "tag:k8s:22"],
    },
  ],
  "grants": [
    { "src": ["group:devops"], "dst": ["tag:k8s"], "ip": ["*"] },
  ],
  "ssh": [
    {
      "action": "accept",
      "src": ["group:devops"],
      "dst": ["tag:k8s"],
      "users": ["root"],
    },
  ],
  "autoApprovers": {
    // subnet routes
    "routes": {
      "10.20.0.0/16": ["group:devops"], // lab
    },
    "exitNode": ["tag:vpn-server"],
  },
  "nodeAttrs": [
    { "target": ["tag:k8s"], "attr": ["admin"] },
  ],
  "tests": [
    { "src": "100.64.9.9", "deny": ["lab-host:443"] },
  ],
  "randomizeClientPort": true,
}
`

// The lines the scenarios edit, as they stand in the fixture.
const (
	gateRule   = `"dst": ["tag:vpn-server:80"] }, // gate`
	gateEdited = `"dst": ["tag:vpn-server:80,8080"] }, // gate`
	uiRule     = `    { "action": "accept", "src": ["group:devops"], "dst": ["tag:vpn-server:443"] }, // ui` + "\n"
)

// policyStack is an F3 stack on the rich document with a devops user, its laptop and the two
// server nodes the locked tests resolve to.
type policyStack struct {
	*f3Stack
	ops f3User
}

// newPolicyStack builds the stack and waits for the start-up reconcile to put the lab's role
// holders into the groups, so the editor's first base hash is the one it keeps for the scenario.
func newPolicyStack(t *testing.T, opts f3Options) *policyStack {
	t.Helper()
	var ops f3User
	more := opts.prepare
	opts.policy = f3RichPolicy
	opts.prepare = func(s *f3Stack) {
		ops = s.user("ops", "devops")
		s.hs.NewNode(s.t, ops.hsName, "ops-laptop", "")
		s.hs.NewNode(s.t, ops.hsName, "gw-1", f3ServerTag)
		s.hs.NewNode(s.t, ops.hsName, "k8s-1", f3K8sTag)
		if more != nil {
			more(s)
		}
	}
	s := newF3Stack(t, opts)
	s.waitMember("devops", ops.zitadelID, true)
	// The groups are live a moment before the reconcile's revision is final, and an unfinished
	// revision reads as an unresolved write: start from a quiet store.
	if err := poll(t, 30*time.Second, func() (bool, error) {
		return s.proc.queryInt(t, `SELECT count(*) FROM policy_revisions WHERE apply_status = 'pending'`) == 0, nil
	}); err != nil {
		t.Fatalf("a policy revision stayed pending after the start-up reconcile: %v", err)
	}
	s.settledAuditCount()
	return &policyStack{f3Stack: s, ops: ops}
}

// The page and the store ------------------------------------------------------------------------

var policyTextRE = regexp.MustCompile(`(?s)<textarea[^>]*\bid="policy-text"[^>]*>(.*?)</textarea>`)

// policyText is the policy a page shows in its textarea (the browser drops the leading newline).
func policyText(t *testing.T, body string) string {
	t.Helper()
	m := policyTextRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the page has no policy textarea: %s", excerpt(body))
	}
	return strings.TrimPrefix(html.UnescapeString(m[1]), "\n")
}

// editorState reads the editor: the text and the base hash a browser would post back. The lab
// network is intermittently slow, and a Zitadel read that times out closes the editor for that
// request, so the page is read again for a while before the editor counts as closed.
func (s *f3Stack) editorState() (text, base string) {
	s.t.Helper()
	var page string
	if err := poll(s.t, 40*time.Second, func() (bool, error) {
		page = s.ui.getOK("/headscale/policy")
		return strings.Contains(page, `id="policy-editor"`), nil
	}); err != nil {
		s.t.Fatalf("the editor is not open: %s", excerpt(page))
	}
	return policyText(s.t, page), inputValue(page, "base_hash")
}

// livePolicy reads the policy straight from Headscale.
func (s *f3Stack) livePolicy() string {
	s.t.Helper()
	p, err := s.hs.Client().GetPolicy(context.Background())
	if err != nil {
		s.t.Fatalf("read the live policy: %v", err)
	}
	return p.Text
}

// previewPolicy posts a text to the preview.
func (s *f3Stack) previewPolicy(text, base string) (int, string) {
	return s.ui.post("/headscale/policy/preview", url.Values{"text": {text}, "base_hash": {base}})
}

// saveEditor is the browser's path: preview, then the confirm form's own hidden fields. A preview
// that offers no confirm form (the text did not pass) is returned as it is.
func (s *f3Stack) saveEditor(text, base string) (int, string) {
	s.t.Helper()
	code, body := s.previewPolicy(text, base)
	if code != http.StatusOK || inputValue(body, "report_hash") == "" {
		return code, body
	}
	return s.ui.post("/headscale/policy/save", url.Values{
		"text": {inputValue(body, "text")}, "base_hash": {inputValue(body, "base_hash")}, "report_hash": {inputValue(body, "report_hash")},
	})
}

// saveRaw posts a save without the preview step, the way a hand-made request would.
func (s *f3Stack) saveRaw(text, base string) (int, string) {
	return s.ui.post("/headscale/policy/save", url.Values{
		"text": {text}, "base_hash": {base}, "report_hash": {policyrev.HashRaw(text)},
	})
}

func wantPolicyApplied(t *testing.T, what string, code int, body string) {
	t.Helper()
	if code != http.StatusOK || !strings.Contains(body, "Policy apply edildi") {
		t.Fatalf("%s: status %d, want an applied policy: %s", what, code, excerpt(body))
	}
}

// revision is the newest policy revision row.
type revision struct {
	id         int
	source     string
	status     string
	rollbackOf int
	raw        string
}

func (s *f3Stack) lastRevision() revision {
	s.t.Helper()
	var r revision
	err := s.proc.storeDB(s.t).QueryRow(
		`SELECT id, source, apply_status, rollback_of, raw FROM policy_revisions ORDER BY id DESC LIMIT 1`,
	).Scan(&r.id, &r.source, &r.status, &r.rollbackOf, &r.raw)
	if err != nil {
		s.t.Fatalf("read the newest policy revision: %v", err)
	}
	return r
}

func (s *f3Stack) revisionCount() int {
	return s.proc.queryInt(s.t, `SELECT count(*) FROM policy_revisions`)
}

// newestApplied is the id of the newest applied revision.
func (s *f3Stack) newestApplied() int {
	return s.proc.queryInt(s.t, `SELECT COALESCE(MAX(id), 0) FROM policy_revisions WHERE apply_status = 'applied'`)
}

// maskOwned replaces the two sections tagcess owns (the groups Zitadel fills and the tests it
// injects) with null and packs the document again. Everything else, comments and commas and
// spacing included, stays as it is, so two masked documents are equal exactly when the rest of the
// document is byte for byte the same.
func maskOwned(t *testing.T, text string) string {
	t.Helper()
	root, err := hujson.Parse([]byte(text))
	if err != nil {
		t.Fatalf("parse the policy: %v\n%s", err, text)
	}
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		t.Fatalf("the policy is not an object: %s", text)
	}
	for i := range obj.Members {
		if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok && (lit.String() == "groups" || lit.String() == "tests") {
			obj.Members[i].Value.Value = hujson.Literal("null")
		}
	}
	return string(root.Pack())
}

// wantSameOutsideOwned fails unless the two policies differ only in groups and tests.
func wantSameOutsideOwned(t *testing.T, what, got, want string) {
	t.Helper()
	if g, w := maskOwned(t, got), maskOwned(t, want); g != w {
		t.Errorf("%s: the document changed outside groups and tests:\n--- got\n%s\n--- want\n%s", what, g, w)
	}
}

// AC1: an editor save keeps the rich document byte for byte, adds the locked tests (which a real
// Headscale runs against real nodes) and rebuilds the role groups from Zitadel, whatever the
// submitted groups said.
func TestE2E_F3_PolicySaveLossless(t *testing.T) {
	s := newPolicyStack(t, f3Options{})
	before, base := s.editorState()
	if live := s.livePolicy(); before != live {
		t.Fatalf("the editor does not show the live policy byte for byte:\n--- page\n%s\n--- live\n%s", before, live)
	}
	if n := strings.Count(before, lockedMarker); n != 0 {
		t.Fatalf("the fixture already carries %d locked tests", n)
	}
	if !strings.Contains(before, gateRule) {
		t.Fatalf("the fixture's gate rule is not in the live policy: %s", before)
	}

	// The edit: one ACL port list, and a forged group member the save must not keep.
	edited := strings.Replace(before, gateRule, gateEdited, 1)
	edited = strings.Replace(edited, `"group:devops": [`, `"group:devops": ["mallory@evil.test",`, 1)
	if edited == before || !strings.Contains(edited, "mallory@evil.test") {
		t.Fatal("test bug: the edit changed nothing")
	}

	code, body := s.previewPolicy(edited, base)
	if code != http.StatusOK {
		t.Fatalf("preview: status %d: %s", code, excerpt(body))
	}
	mustContain(t, "preview", body, "Kilitli testler eklendi", "Gruplar tagcess tarafından", "Onayla ve apply et")
	code, body = s.saveEditor(edited, base)
	wantPolicyApplied(t, "editor save", code, body)

	after := s.livePolicy()
	wantSameOutsideOwned(t, "editor save", after, strings.Replace(before, gateRule, gateEdited, 1))
	for _, keep := range []string{
		"// F3-030 rich fixture", `"#note": "kept as is"`, "// lab network", "// vpn-host: Caddy, Headscale", "/* k8s node */",
		"// access rules", "// (two comment lines)", `"randomizeClientPort": true`, `"users": ["root"],`, gateEdited,
	} {
		mustContain(t, "the saved policy", after, keep)
	}
	// The user's own test survived and the three locked ones were added.
	mustContain(t, "the saved policy", after, `"deny": ["lab-host:443"]`)
	if n := strings.Count(after, lockedMarker); n != 3 {
		t.Errorf("the saved policy carries %d locked tests, want 3: %s", n, after)
	}
	// The groups are Zitadel's: the devops user is in, the forged member is not.
	groups := s.hs.PolicyGroups(t)
	if !containsMember(groups["group:devops"], s.l.providerID(s.ops.zitadelID)) {
		t.Errorf("group:devops = %v, want the lab devops user %s", groups["group:devops"], s.l.providerID(s.ops.zitadelID))
	}
	for g, members := range groups {
		if containsMember(members, "mallory@evil.test") {
			t.Errorf("%s kept the forged member", g)
		}
	}
	// The revision is the exact text, applied, from the editor.
	rev := s.lastRevision()
	if rev.source != "ui" || rev.status != "applied" || rev.raw != after {
		t.Errorf("newest revision = #%d source %s status %s (raw equal to live: %v), want an applied ui revision of the live text",
			rev.id, rev.source, rev.status, rev.raw == after)
	}
}

// AC2: every text the system must refuse leaves the live policy and the revision history exactly
// as they were, and a valid edit before and after proves the refusals are about the text.
func TestE2E_F3_PolicyRejections(t *testing.T) {
	s := newPolicyStack(t, f3Options{})
	text, base := s.editorState()

	// The control: a valid edit goes through.
	code, body := s.saveEditor(strings.Replace(text, gateRule, gateEdited, 1), base)
	wantPolicyApplied(t, "control save", code, body)

	text, base = s.editorState()
	live, revs := s.livePolicy(), s.revisionCount()
	if text != live || strings.Count(live, lockedMarker) != 3 {
		t.Fatalf("the control save left an unexpected live policy: %s", live)
	}
	unchanged := func(what string) {
		t.Helper()
		if got := s.livePolicy(); got != live {
			t.Errorf("%s changed the live policy:\n--- before\n%s\n--- after\n%s", what, live, got)
		}
		if n := s.revisionCount(); n != revs {
			t.Errorf("%s added %d revision(s)", what, n-revs)
		}
	}

	// stages is the expected state of the five report rows, in the order the panel lists them: the
	// panel names every stage on every refusal (skipped ones too), so only the state of each row
	// shows which stage refused the text and that the earlier ones passed.
	const pass, fail, skip = "geçti", "hata", "atlandı"
	stageLabels := []string{"Girdi", "Sözdizimi", "Yapı", "Kilitli testler", "Headscale"}
	cases := []struct {
		name, text string
		stages     []string
		message    string // text that must appear in the failing row; empty when only the state is checked
	}{
		{"invalid HuJSON", `{ "acls": [`, []string{pass, fail, skip, skip, skip}, ""},
		{"empty document", "", []string{fail, skip, skip, skip, skip}, "the policy is empty"},
		{"no acls and no grants", `{ "groups": {"group:devops": []}, "tagOwners": {"tag:vpn-server": ["group:devops"]} }`,
			[]string{pass, pass, fail, skip, skip}, `neither "acls" nor "grants"`},
		{"CheckPolicy rejects", strings.Replace(text, `"tag:vpn-server:80,8080"`, `"tag:undefined:80"`, 1),
			[]string{pass, pass, pass, pass, fail}, "tag:undefined"},
		{"locked test broken", strings.Replace(text, uiRule, "", 1),
			[]string{pass, pass, pass, pass, fail}, "locked test failed: ui"},
	}
	rowRE := regexp.MustCompile(`<td><strong>([^<]*)</strong></td>\s*<td><span class="st"><span class="dot[^"]*"></span>([^<]*)</span></td>`)
	for _, c := range cases {
		s.section(t, c.name, func(t *testing.T) {
			if c.name != "empty document" && c.name != "invalid HuJSON" && c.name != "no acls and no grants" && c.text == text {
				t.Fatal("test bug: the case did not change the text")
			}
			code, body := s.previewPolicy(c.text, base)
			if (code != http.StatusOK && code != http.StatusUnprocessableEntity) || strings.Contains(body, `action="/headscale/policy/save"`) {
				t.Errorf("preview offers to save a refused text: status %d: %s", code, excerpt(body))
			}
			code, body = s.saveRaw(c.text, base)
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("save: status %d, want 422: %s", code, excerpt(body))
			}
			mustContain(t, "refusal", body, "Policy kaydedilmedi", "hiçbir şey yazılmadı")
			rows := rowRE.FindAllStringSubmatch(body, -1)
			if len(rows) != len(stageLabels) {
				t.Fatalf("the report has %d stage rows, want %d: %s", len(rows), len(stageLabels), excerpt(body))
			}
			for i, row := range rows {
				if row[1] != stageLabels[i] || row[2] != c.stages[i] {
					t.Errorf("stage row %d = %s: %s, want %s: %s", i+1, row[1], row[2], stageLabels[i], c.stages[i])
				}
			}
			if c.message != "" {
				mustContain(t, "refusal", html.UnescapeString(body), c.message)
			}
			unchanged(c.name)
		})
	}

	s.section(t, "stale base", func(t *testing.T) {
		// Someone edits the policy behind the editor's back.
		external := live + "\n// an edit made outside tagcess\n"
		if _, err := s.hs.Client().SetPolicy(context.Background(), external); err != nil {
			t.Fatalf("external edit: %v", err)
		}
		code, body := s.saveRaw(strings.Replace(text, gateEdited, `"dst": ["tag:vpn-server:80,8081"] }, // gate`, 1), base)
		if code != http.StatusConflict {
			t.Fatalf("save on a stale base: status %d, want 409: %s", code, excerpt(body))
		}
		mustContain(t, "stale refusal", body, "Policy dışarıdan değişti")
		if got := s.livePolicy(); got != external {
			t.Errorf("the stale save changed the live policy:\n%s", got)
		}
		if n := s.revisionCount(); n != revs {
			t.Errorf("the stale save added %d revision(s)", n-revs)
		}
		live = external
	})

	// The control again: the same system accepts a fresh edit, so none of the above was an
	// environment failure.
	text, base = s.editorState()
	code, body = s.saveEditor(strings.Replace(text, gateEdited, `"dst": ["tag:vpn-server:80,8082"] }, // gate`, 1), base)
	wantPolicyApplied(t, "closing control save", code, body)
}

// AC4: the forms add a rule and a tag to the draft, the save applies them, and a rollback to an
// earlier revision brings the live policy back to that revision (with today's groups and the
// rebuilt locked tests). A role change that arrives through the webhook afterwards updates the
// groups only and leaves the editor's change alone; the sync's own revision says so.
func TestE2E_F3_FormsHistoryRollbackAndSyncCoexist(t *testing.T) {
	s := newPolicyStack(t, f3Options{})
	start, base := s.editorState()

	// The forms: a rule, then a tag, both only in the draft until the save.
	code, body := s.ui.post("/headscale/policy/rules/add", url.Values{
		"text": {start}, "base_hash": {base}, "add_src": {"group:standart"}, "add_dst": {"tag:vpn-server:8080"}, "add_proto": {"tcp"},
	})
	if code != http.StatusOK {
		t.Fatalf("add rule: status %d: %s", code, excerpt(body))
	}
	mustContain(t, "rule form", body, "Kural draft'a eklendi")
	draft := policyText(t, body)
	code, body = s.ui.post("/headscale/policy/tags/set", url.Values{
		"text": {draft}, "base_hash": {base}, "tag_new_name": {"tag:f3-new"}, "tag_new_owners": {"group:devops"},
	})
	if code != http.StatusOK {
		t.Fatalf("add tag: status %d: %s", code, excerpt(body))
	}
	mustContain(t, "tag form", body, "Tag draft'a eklendi")
	draft = policyText(t, body)
	if got := s.livePolicy(); got != start {
		t.Fatalf("the forms changed the live policy before the save:\n%s", got)
	}
	code, body = s.saveEditor(draft, base)
	wantPolicyApplied(t, "save of the form edit", code, body)
	edited := s.livePolicy()
	mustContain(t, "the saved policy", edited, `"tag:vpn-server:8080"`, `"tag:f3-new"`)
	formRev := s.lastRevision()
	if formRev.source != "ui" || formRev.status != "applied" {
		t.Fatalf("newest revision = %+v, want an applied ui revision", formRev)
	}

	s.section(t, "rollback", func(t *testing.T) {
		// The target is the revision that holds the text the editor started from.
		target := s.proc.queryInt(t, `SELECT COALESCE(MAX(id), 0) FROM policy_revisions WHERE raw = ? AND apply_status = 'applied'`, start)
		if target == 0 {
			t.Fatal("no applied revision holds the text the form edit started from")
		}
		list := s.ui.getOK("/headscale/policy/history")
		mustContain(t, "history", list, "#"+revID(target), "#"+revID(formRev.id), "Bu sürüme dön")
		rbPath := "/headscale/policy/history/" + revID(target) + "/rollback"
		page := s.ui.getOK(rbPath)
		mustContain(t, "rollback page", page, "Onayla ve apply et", "tag:f3-new")
		code, body := s.ui.post(rbPath, url.Values{"base_hash": {inputValue(page, "base_hash")}})
		wantPolicyApplied(t, "rollback", code, body)

		after := s.livePolicy()
		wantSameOutsideOwned(t, "rollback", after, start)
		mustNotContain(t, "the rolled-back policy", after, `"tag:vpn-server:8080"`, `"tag:f3-new"`)
		if n := strings.Count(after, lockedMarker); n != 3 {
			t.Errorf("the rolled-back policy carries %d locked tests, want 3", n)
		}
		groups := s.hs.PolicyGroups(t)
		if !containsMember(groups["group:devops"], s.l.providerID(s.ops.zitadelID)) {
			t.Errorf("group:devops = %v after the rollback, want today's Zitadel group", groups["group:devops"])
		}
		rev := s.lastRevision()
		if rev.source != "rollback" || rev.status != "applied" || rev.rollbackOf != target || rev.raw != after {
			t.Errorf("newest revision = %+v, want an applied rollback of #%d holding the live text", revisionBrief(rev), target)
		}
		list = s.ui.getOK("/headscale/policy/history")
		mustContain(t, "history", list, "revision #"+revID(target)+" geri yüklendi", "<code>rollback</code>")
	})

	s.section(t, "webhook role change keeps the editor's change", func(t *testing.T) {
		// The editor's change again, so there is something for the sync not to overwrite.
		text, base := s.editorState()
		code, body := s.saveEditor(strings.Replace(text, gateRule, gateEdited, 1), base)
		wantPolicyApplied(t, "second editor save", code, body)
		editorState := s.livePolicy()
		groupsNow := s.hs.PolicyGroups(t)

		// No manual trigger: the lab's webhook is the only thing that can tell tagcess.
		holder := s.user("holder", "")
		s.l.grant(t, holder.zitadelID, "standart")
		member := s.l.providerID(holder.zitadelID)
		if err := poll(t, 45*time.Second, func() (bool, error) {
			return containsMember(s.hs.PolicyGroups(t)["group:standart"], member), nil
		}); err != nil {
			t.Fatalf("the webhook never put the new role holder into group:standart: %v", err)
		}
		after := s.livePolicy()
		wantSameOutsideOwned(t, "the sync", after, editorState)
		if got := s.hs.PolicyGroups(t); !equalMembers(got["group:devops"], groupsNow["group:devops"]) {
			t.Errorf("group:devops changed from %v to %v", groupsNow["group:devops"], got["group:devops"])
		}
		// The write is live a moment before its revision is final.
		if err := poll(t, 20*time.Second, func() (bool, error) { return s.lastRevision().status == "applied", nil }); err != nil {
			t.Fatalf("the sync's revision never became applied: %v", err)
		}
		rev := s.lastRevision()
		if rev.source != "sync" || rev.status != "applied" || rev.raw != after {
			t.Errorf("newest revision = %+v, want an applied sync revision holding the live text", revisionBrief(rev))
		}
		list := s.ui.getOK("/headscale/policy/history")
		mustContain(t, "history", list, "#"+revID(rev.id), "<code>sync</code>")
	})
}

func revID(id int) string { return strconv.Itoa(id) }

// revisionBrief is a revision without its (long) text.
func revisionBrief(r revision) revision {
	r.raw = ""
	return r
}

func equalMembers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, m := range a {
		if !containsMember(b, m) {
			return false
		}
	}
	return true
}

// settledAuditCount waits until the audit log has been quiet for two seconds (a reconcile that
// the stack's start-up triggered may still be writing its rows) and returns its size.
func (s *f3Stack) settledAuditCount() int {
	s.t.Helper()
	n := s.proc.queryInt(s.t, `SELECT count(*) FROM audit_events`)
	for i := 0; i < 15; i++ {
		time.Sleep(2 * time.Second)
		next := s.proc.queryInt(s.t, `SELECT count(*) FROM audit_events`)
		if next == n {
			return n
		}
		n = next
	}
	s.t.Fatal("the audit log never went quiet")
	return 0
}

// f3PolicyRoutes are the policy, history, recovery and settings routes, GET and POST.
var f3PolicyRoutes = []struct{ method, path string }{
	{http.MethodGet, "/headscale/policy"},
	{http.MethodGet, "/headscale/policy/revalidate"},
	{http.MethodPost, "/headscale/policy/preview"},
	{http.MethodPost, "/headscale/policy/save"},
	{http.MethodPost, "/headscale/policy/rules/add"},
	{http.MethodPost, "/headscale/policy/rules/update"},
	{http.MethodPost, "/headscale/policy/rules/delete"},
	{http.MethodPost, "/headscale/policy/tags/set"},
	{http.MethodPost, "/headscale/policy/tags/delete"},
	{http.MethodPost, "/headscale/policy/routes/set"},
	{http.MethodPost, "/headscale/policy/routes/delete"},
	{http.MethodPost, "/headscale/policy/routes/exitnode"},
	{http.MethodGet, "/headscale/policy/history"},
	{http.MethodGet, "/headscale/policy/history/1"},
	{http.MethodGet, "/headscale/policy/history/1/rollback"},
	{http.MethodPost, "/headscale/policy/history/1/rollback"},
	{http.MethodGet, "/headscale/policy/recovery"},
	{http.MethodPost, "/headscale/policy/recovery"},
	{http.MethodGet, "/headscale/settings"},
	{http.MethodPost, "/headscale/settings/tags"},
	{http.MethodPost, "/headscale/settings/locked"},
	{http.MethodPost, "/headscale/settings/config-write"},
	{http.MethodGet, "/headscale/config"},
	{http.MethodGet, "/headscale/config/status"},
	{http.MethodPost, "/headscale/config/preview"},
	{http.MethodPost, "/headscale/config/apply"},
	{http.MethodPost, "/headscale/config/close"},
}

// AC7: an identity without devops, with or without forged X-Auth-Request-* headers, gets 403 on
// every policy, history, recovery and settings route, and nothing is written.
func TestE2E_F3_PolicyRoutesSpoofedHeaderRejected(t *testing.T) {
	s := newPolicyStack(t, f3Options{})
	audits := s.settledAuditCount()
	revs, live := s.revisionCount(), s.livePolicy()
	csrf := s.ui.csrf()

	// The control first: the devops identity reaches the same pages.
	for _, p := range []string{"/headscale/policy", "/headscale/policy/history", "/headscale/policy/recovery", "/headscale/settings"} {
		if code, body := s.ui.get(p); code != http.StatusOK {
			t.Fatalf("devops control: GET %s: status %d: %s", p, code, excerpt(body))
		}
	}

	identities := map[string]map[string]string{
		"no identity":             nil,
		"developer":               {"X-Auth-Request-User": "dev", "X-Auth-Request-Email": "dev@tagcess.test", "X-Auth-Request-Groups": "developer"},
		"forged user, no groups":  {"X-Auth-Request-User": "devops", "X-Auth-Request-Email": "devops@tagcess.test"},
		"empty groups":            {"X-Auth-Request-User": "devops", "X-Auth-Request-Groups": ""},
		"look-alike group":        {"X-Auth-Request-User": "x", "X-Auth-Request-Groups": "devops-readonly,devopsx"},
		"other case":              {"X-Auth-Request-User": "x", "X-Auth-Request-Groups": "DevOps"},
		"foreign forwarded group": {"X-Auth-Request-User": "x", "X-Auth-Request-Groups": "developer", "X-Forwarded-Groups": "devops"},
	}
	// A short body: the interface answers 403 without reading it, and a long one would race that answer.
	text, base := "{}", policyrev.HashRaw("{}")
	for name, header := range identities {
		for _, r := range f3PolicyRoutes {
			var form url.Values
			if r.method == http.MethodPost {
				form = url.Values{
					"csrf_token": {csrf}, "text": {text}, "base_hash": {base}, "report_hash": {policyrev.HashRaw(text)},
					"confirm": {"1"}, "action": {"add"}, "tag": {"tag:forged"},
				}
			}
			if code, _ := uiRaw(t, s.proc.uiSock, r.method, r.path, header, form); code != http.StatusForbidden {
				t.Errorf("%s: %s %s: status %d, want 403", name, r.method, r.path, code)
			}
		}
	}
	if got := s.proc.queryInt(t, `SELECT count(*) FROM audit_events`); got != audits {
		rows, _ := s.proc.storeDB(t).Query(`SELECT event, actor, target, result FROM audit_events ORDER BY id DESC LIMIT ?`, got-audits)
		var added []string
		for rows != nil && rows.Next() {
			var e, a, tg, r string
			_ = rows.Scan(&e, &a, &tg, &r)
			added = append(added, e+" by "+a+" on "+tg+" = "+r)
		}
		if rows != nil {
			_ = rows.Close()
		}
		t.Errorf("rejected requests wrote %d audit rows: %v", got-audits, added)
	}
	if n := s.revisionCount(); n != revs {
		t.Errorf("rejected requests added %d policy revisions", n-revs)
	}
	if got := s.livePolicy(); got != live {
		t.Errorf("rejected requests changed the live policy:\n%s", got)
	}
}
