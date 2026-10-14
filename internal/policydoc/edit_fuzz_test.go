package policydoc

import (
	"bytes"
	"os"
	"testing"

	"github.com/tailscale/hujson"
)

// FuzzPolicyDoc_Edit is AC4: whatever the input, an operation either fails and leaves the
// document unchanged, or yields valid HuJSON whose groups section is untouched.
func FuzzPolicyDoc_Edit(f *testing.F) {
	prod, err := readFile("../render/testdata/prod-policy-anonymized.hujson")
	if err != nil {
		f.Fatal(err)
	}
	rich, err := readFile("testdata/rich-policy.hujson")
	if err != nil {
		f.Fatal(err)
	}
	for op := uint8(0); op < 8; op++ {
		f.Add(op, "tag:a", "group:devops", "tcp", "10.0.0.0/8", true)
		f.Add(op, "tag:a\"", "a\nb", "", "*", false)
		f.Add(op, "", "*:*", "udp", "", true)
	}
	f.Fuzz(func(t *testing.T, op uint8, a, b, c, d string, useRich bool) {
		text := string(prod)
		if useRich {
			text = string(rich)
		}
		doc, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		switch op % 8 {
		case 0:
			err = doc.AddACLRule(Rule{Action: "accept", Proto: c, Src: []string{a}, Dst: []string{b}})
		case 1:
			var cur []Rule
			if cur, err = doc.ACLRules(); err == nil {
				err = doc.UpdateACLRule(0, cur[0], Rule{Proto: c, Src: []string{a}, Dst: []string{b}})
			}
		case 2:
			err = doc.DeleteACLRule(len(a)%3, Rule{Src: []string{b}, Dst: []string{d}})
		case 3:
			err = doc.SetTagOwners(a, []string{b, d})
		case 4:
			err = doc.DeleteTag(a)
		case 5:
			err = doc.SetRouteApprovers(d, []string{a, b})
		case 6:
			err = doc.DeleteRoute(d)
		case 7:
			err = doc.SetExitNodeApprovers([]string{a, b})
		}
		got := doc.Text()
		if err != nil {
			if got != text {
				t.Fatalf("the document changed although the operation failed: %v", err)
			}
			return
		}
		if _, err := hujson.Parse([]byte(got)); err != nil {
			t.Fatalf("result is not valid HuJSON: %v\n%s", err, got)
		}
		if groupsSection(t, got) != groupsSection(t, text) {
			t.Fatal("the groups section changed")
		}
		if bytes.Contains([]byte(got), []byte{0}) {
			t.Fatal("a control character reached the document")
		}
	})
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }
