package render

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

func rolesFixture() map[string][]string {
	return map[string][]string{
		"devops":    {"2002", "2001", "2001"},
		"developer": {"1003", "1001", "1007", "1002", "1005", "1004", "1006"},
		"standart":  {},
	}
}

// groupsOf parses a policy and returns its top-level groups section.
func groupsOf(t *testing.T, policy []byte) map[string][]string {
	t.Helper()
	v, err := hujson.Parse(policy)
	if err != nil {
		t.Fatalf("parse rendered policy: %v", err)
	}
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		t.Fatalf("rendered policy root is %T, want object", v.Value)
	}
	i := findMember(obj, groupsKey)
	if i < 0 {
		t.Fatalf("rendered policy has no %q section", groupsKey)
	}
	gobj, ok := obj.Members[i].Value.Value.(*hujson.Object)
	if !ok {
		t.Fatalf("groups value is %T, want object", obj.Members[i].Value.Value)
	}
	res := make(map[string][]string, len(gobj.Members))
	for _, m := range gobj.Members {
		name := m.Name.Value.(hujson.Literal).String()
		arr, ok := m.Value.Value.(*hujson.Array)
		if !ok {
			t.Fatalf("group %q value is %T, want array", name, m.Value.Value)
		}
		members := make([]string, 0, len(arr.Elements))
		for _, e := range arr.Elements {
			members = append(members, e.Value.(hujson.Literal).String())
		}
		res[name] = members
	}
	return res
}

// The policy outside the groups value must stay byte-for-byte identical.
func stripGroups(t *testing.T, policy []byte) (before, after []byte) {
	t.Helper()
	v, err := hujson.Parse(policy)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	v.UpdateOffsets()
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		t.Fatalf("policy root is %T, want object", v.Value)
	}
	i := findMember(obj, groupsKey)
	if i < 0 {
		t.Fatalf("policy has no %q section", groupsKey)
	}
	return policy[:obj.Members[i].Value.StartOffset], policy[obj.Members[i].Value.EndOffset:]
}

func TestRenderGroups_Deterministic(t *testing.T) {
	got, err := RenderGroups([]byte(`{"groups": {}}`), rolesFixture(), testFormat())
	if err != nil {
		t.Fatalf("RenderGroups: %v", err)
	}
	groups := groupsOf(t, got)

	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3: %v", len(groups), groups)
	}
	wantDeveloper := []string{
		"https://auth.example.com/1001@",
		"https://auth.example.com/1002@",
		"https://auth.example.com/1003@",
		"https://auth.example.com/1004@",
		"https://auth.example.com/1005@",
		"https://auth.example.com/1006@",
		"https://auth.example.com/1007@",
	}
	if got := groups["group:developer"]; !slices.Equal(got, wantDeveloper) {
		t.Errorf("group:developer = %v, want %v", got, wantDeveloper)
	}
	wantDevops := []string{
		"https://auth.example.com/2001@",
		"https://auth.example.com/2002@",
	}
	if got := groups["group:devops"]; !slices.Equal(got, wantDevops) {
		t.Errorf("group:devops = %v, want %v", got, wantDevops)
	}
	// Role order in the output must be deterministic (sorted by role name),
	// not the random map iteration order.
	devIdx := bytes.Index(got, []byte(`"group:developer"`))
	opsIdx := bytes.Index(got, []byte(`"group:devops"`))
	stdIdx := bytes.Index(got, []byte(`"group:standart"`))
	if devIdx >= opsIdx || opsIdx >= stdIdx {
		t.Errorf("groups are not sorted: developer=%d devops=%d standart=%d", devIdx, opsIdx, stdIdx)
	}
}

func TestRenderGroups_PreservesOtherSections(t *testing.T) {
	in := readTestdata(t, "prod-policy-anonymized.hujson")
	got, err := RenderGroups(in, rolesFixture(), testFormat())
	if err != nil {
		t.Fatalf("RenderGroups: %v", err)
	}

	want := readTestdata(t, "prod-policy-anonymized.golden.hujson")
	if !bytes.Equal(got, want) {
		t.Errorf("rendered policy does not match golden file\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	beforeIn, afterIn := stripGroups(t, in)
	beforeGot, afterGot := stripGroups(t, got)
	if !bytes.Equal(beforeIn, beforeGot) {
		t.Errorf("bytes before groups changed:\n got %q\nwant %q", beforeGot, beforeIn)
	}
	if !bytes.Equal(afterIn, afterGot) {
		t.Errorf("bytes after groups changed:\n got %q\nwant %q", afterGot, afterIn)
	}
	for _, comment := range []string{
		"Ağ katmanı.",
		"vpn-host: Caddy",
		"k8s-host: k8s node'u",
		"SSH: yalnız devops",
	} {
		if !bytes.Contains(got, []byte(comment)) {
			t.Errorf("comment %q was not preserved", comment)
		}
	}
}

func TestRenderGroups_EmptyGroupKept(t *testing.T) {
	got, err := RenderGroups([]byte(`{"groups": {"group:standart": ["old@example.com"]}}`), rolesFixture(), testFormat())
	if err != nil {
		t.Fatalf("RenderGroups: %v", err)
	}
	groups := groupsOf(t, got)
	members, ok := groups["group:standart"]
	if !ok {
		t.Fatalf("empty role was dropped; groups = %v", groups)
	}
	if len(members) != 0 {
		t.Errorf("group:standart = %v, want empty list", members)
	}
	if !bytes.Contains(got, []byte(`"group:standart": []`)) {
		t.Errorf("empty group is not an empty list:\n%s", got)
	}
}

func TestRenderGroups_RejectsBadRoleName(t *testing.T) {
	bad := []string{"", "DevOps", "dev.ops", "dev ops", "dev/ops", "a:b", "ä", "x@y", strings.Repeat("a", 33)}
	for _, role := range bad {
		t.Run(role, func(t *testing.T) {
			_, err := RenderGroups([]byte(`{"groups": {}}`), map[string][]string{role: {"1"}}, testFormat())
			if err == nil {
				t.Fatalf("RenderGroups accepted role name %q", role)
			}
		})
	}

	good := []string{"a", "devops", "a-b_c", "0", strings.Repeat("a", 32)}
	for _, role := range good {
		t.Run(role, func(t *testing.T) {
			if _, err := RenderGroups([]byte(`{"groups": {}}`), map[string][]string{role: {}}, testFormat()); err != nil {
				t.Fatalf("RenderGroups rejected role name %q: %v", role, err)
			}
		})
	}
}

func TestRenderGroups_Stable(t *testing.T) {
	roles := rolesFixture()
	first, err := RenderGroups([]byte(`{"groups": {}}`), roles, testFormat())
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	for i := 0; i < 20; i++ {
		next, err := RenderGroups([]byte(`{"groups": {}}`), roles, testFormat())
		if err != nil {
			t.Fatalf("render %d: %v", i, err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("render %d differs:\n%s\n---\n%s", i, first, next)
		}
	}
}

func TestRenderGroups_AddsMissingSection(t *testing.T) {
	in := []byte("{\n  \"acls\": [ { \"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"] } ],\n  // keep me\n  \"tagOwners\": {}\n}\n")
	got, err := RenderGroups(in, map[string][]string{"devops": {"1"}}, testFormat())
	if err != nil {
		t.Fatalf("RenderGroups: %v", err)
	}
	groups := groupsOf(t, got)
	if !slices.Equal(groups["group:devops"], []string{"https://auth.example.com/1@"}) {
		t.Errorf("group:devops = %v", groups["group:devops"])
	}
	if !bytes.Contains(got, []byte(`"acls"`)) || !bytes.Contains(got, []byte(`// keep me`)) {
		t.Errorf("existing sections were not preserved:\n%s", got)
	}
}

func TestRenderGroups_EmptyRoles(t *testing.T) {
	got, err := RenderGroups([]byte(`{"groups": {"group:devops": ["old@example.com"]}}`), map[string][]string{}, testFormat())
	if err != nil {
		t.Fatalf("RenderGroups: %v", err)
	}
	if groups := groupsOf(t, got); len(groups) != 0 {
		t.Errorf("empty roles produced groups %v, want none", groups)
	}
	if !bytes.Contains(got, []byte(`"groups": {}`)) {
		t.Errorf("empty roles did not produce an empty groups object:\n%s", got)
	}
}

func TestRenderGroups_RegeneratesFromRoles(t *testing.T) {
	in := []byte(`{"groups": {"group:legacy": ["legacy@example.com"], "group:devops": ["old@example.com"]}}`)
	got, err := RenderGroups(in, map[string][]string{"devops": {"1"}}, testFormat())
	if err != nil {
		t.Fatalf("RenderGroups: %v", err)
	}
	groups := groupsOf(t, got)
	if len(groups) != 1 {
		t.Fatalf("groups = %v, want only group:devops", groups)
	}
	if !slices.Equal(groups["group:devops"], []string{"https://auth.example.com/1@"}) {
		t.Errorf("group:devops = %v", groups["group:devops"])
	}
}

func TestRenderGroups_DuplicateGroupsSection(t *testing.T) {
	in := []byte(`{"groups": {}, "groups": {"group:stale": ["stale@example.com"]}}`)
	if _, err := RenderGroups(in, map[string][]string{"devops": {"1"}}, testFormat()); err == nil {
		t.Fatal("RenderGroups accepted a policy with duplicate top-level groups sections")
	}
}

func TestRenderGroups_NonObjectRoot(t *testing.T) {
	if _, err := RenderGroups([]byte(`[]`), map[string][]string{"a": {}}, testFormat()); err == nil {
		t.Fatal("RenderGroups accepted a non-object root")
	}
}

func TestRenderGroups_BadMember(t *testing.T) {
	_, err := RenderGroups([]byte(`{"groups": {}}`), map[string][]string{"devops": {"not a url"}}, testFormat())
	if err == nil {
		t.Fatal("RenderGroups accepted an invalid provider identifier")
	}
}

func testFormat() MemberFormat {
	return ProviderIDFormat("https://auth.example.com")
}

func TestFormatProviderIdentifier(t *testing.T) {
	good := []struct {
		issuer string
		userID string
		want   string
	}{
		{"https://auth.example.com", "123", "https://auth.example.com/123@"},
		{"http://localhost:8080", "abcdef", "http://localhost:8080/abcdef@"},
		{"https://auth.example.com/", "123", "https://auth.example.com/123@"},
	}
	for _, c := range good {
		got, err := FormatProviderIdentifier(c.issuer, c.userID)
		if err != nil {
			t.Errorf("FormatProviderIdentifier(%q, %q): %v", c.issuer, c.userID, err)
			continue
		}
		if got != c.want {
			t.Errorf("FormatProviderIdentifier(%q, %q) = %q, want %q", c.issuer, c.userID, got, c.want)
		}
	}

	bad := []struct {
		issuer string
		userID string
	}{
		{"", "1"},
		{"auth.example.com", "1"},
		{"ftp://auth.example.com", "1"},
		{"https://user@auth.example.com", "1"},
		{"https://auth.example.com?x=1", "1"},
		{"https://auth.example.com#frag", "1"},
		{"https://auth.example.com", ""},
		{"https://auth.example.com", "user@example.com"},
		{"https://auth.example.com", "12 3"},
		{"https://auth.example.com", "12\n3"},
		{"https://auth.example.com", "a/b"},
		{"https://auth.example.com", "a?b"},
		{"https://auth.example.com", "."},
		{"https://auth.example.com", ".."},
		{"https://auth.example.com", "a\x00b"},
		{"https://auth.example.com", "a\x1bb"},
		{"https://auth.example.com", "a\x7fb"},
	}
	for _, c := range bad {
		if got, err := FormatProviderIdentifier(c.issuer, c.userID); err == nil {
			t.Errorf("FormatProviderIdentifier(%q, %q) = %q, want error", c.issuer, c.userID, got)
		}
	}
}

// MatchUserID is the read direction of the ADR 0002 identifier: it must accept exactly what
// FormatProviderIdentifier writes (minus the policy's trailing "@") and refuse everything else.
func TestMatchUserID(t *testing.T) {
	cases := []struct {
		name       string
		providerID string
		issuer     string
		wantID     string
		wantOK     bool
	}{
		{"issuer form", "https://auth.example.com/123", "https://auth.example.com", "123", true},
		{"empty provider id", "", "https://auth.example.com", "", false},
		{"other issuer", "https://other.example.com/123", "https://auth.example.com", "", false},
		{"prefix only", "https://auth.example.com/", "https://auth.example.com", "", false},
		{"second path segment", "https://auth.example.com/a/b", "https://auth.example.com", "", false},
		{"issuer is a prefix of a longer host", "https://auth.example.com.evil/123", "https://auth.example.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := MatchUserID(tc.providerID, tc.issuer)
			if ok != tc.wantOK || id != tc.wantID {
				t.Errorf("MatchUserID(%q, %q) = %q, %v; want %q, %v", tc.providerID, tc.issuer, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	return b
}

func findMember(obj *hujson.Object, name string) int {
	matches := memberIndexes(obj, name)
	if len(matches) == 0 {
		return -1
	}
	return matches[0]
}

func TestRenderGroups_LastMemberTrailingCommaAndComments(t *testing.T) {
	in := []byte("{\n  // before\n  \"acls\": [], // acls tail\n  /* c1 */ \"groups\": {\"group:x\": []} /* c2 */, // c3\n  // end comment\n}\n")
	out, err := RenderGroups(in, map[string][]string{"a": {"1"}}, testFormat())
	if err != nil {
		t.Fatalf("RenderGroups: %v", err)
	}
	b1, a1 := stripGroups(t, in)
	b2, a2 := stripGroups(t, out)
	if !bytes.Equal(b1, b2) || !bytes.Equal(a1, a2) {
		t.Errorf("bytes outside groups value changed:\nin:  %q\nout: %q", in, out)
	}
	for _, c := range []string{"// before", "/* c1 */", "/* c2 */", "// c3", "// end comment", "// acls tail"} {
		if !bytes.Contains(out, []byte(c)) {
			t.Errorf("comment %q lost: %q", c, out)
		}
	}
	if got := groupsOf(t, out); len(got) != 1 || len(got["group:a"]) != 1 {
		t.Errorf("groups = %v", got)
	}
}
