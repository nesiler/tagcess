package policydoc

import (
	"reflect"
	"testing"
)

func TestPolicyDoc_TagOwnersReader(t *testing.T) {
	t.Run("fixture", func(t *testing.T) {
		got, err := TagOwners(fixture(t))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string][]string{"tag:vpn-server": {}, "tag:k8s": {}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("owners, comments, metadata", func(t *testing.T) {
		got, err := TagOwners(`{
  // c
  "tagOwners": {
    "#note": "ignored",
    "tag:a": ["group:devops", "user@"],
    "tag:b": ["tag:a",],
  },
  "acls": [],
}`)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string][]string{"tag:a": {"group:devops", "user@"}, "tag:b": {"tag:a"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("case-insensitive section name", func(t *testing.T) {
		got, err := TagOwners(`{"TAGOWNERS": {"tag:a": ["x@"]}}`)
		if err != nil || !reflect.DeepEqual(got, map[string][]string{"tag:a": {"x@"}}) {
			t.Errorf("got %v, %v", got, err)
		}
	})
	t.Run("no section: empty map", func(t *testing.T) {
		got, err := TagOwners(`{"acls": []}`)
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("got %#v, %v; want empty non-nil map", got, err)
		}
	})
	for name, text := range map[string]string{
		"syntax error":        `{"tagOwners": `,
		"root not an object":  `[]`,
		"section not object":  `{"tagOwners": []}`,
		"owners not an array": `{"tagOwners": {"tag:a": "x@"}}`,
		"owner not a string":  `{"tagOwners": {"tag:a": [1]}}`,
		"duplicate section":   `{"tagOwners": {}, "tagOwners": {}}`,
		"duplicate tag":       `{"tagOwners": {"tag:a": [], "tag:a": []}}`,
		"empty":               ``,
	} {
		t.Run("error/"+name, func(t *testing.T) {
			if got, err := TagOwners(text); err == nil {
				t.Errorf("got %v, want an error", got)
			}
		})
	}
}
