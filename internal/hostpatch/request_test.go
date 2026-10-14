package hostpatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	testID      = "0b7f4c1e-52d3-4a8e-9c61-3f2d8a7e5b10"
	testBaseRev = "740a57b59f3878100ec9dd17b117f5239adbb93bd7686cb4cce8a1645bc49ad5"
)

// rawRequest builds a request document around a raw allowed_groups JSON literal.
func rawRequest(list string) string {
	return fmt.Sprintf(`{"version":1,"request_id":%q,"base_rev":%q,"patch":{"oidc":{"allowed_groups":%s}}}`,
		testID, testBaseRev, list)
}

// AC1: a valid list builds the ADR 0021 a request and the same bytes decode back.
func TestHostPatch_BuildRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   string // canonical list in the request
	}{
		{"devops only", []string{"devops"}, `["devops"]`},
		{"two groups", []string{"devops", "developer"}, `["devops","developer"]`},
		{"all three", []string{"devops", "developer", "standart"}, `["devops","developer","standart"]`},
		{"order is canonicalised", []string{"standart", "developer", "devops"}, `["devops","developer","standart"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := BuildRequest(testID, testBaseRev, tt.groups)
			if err != nil {
				t.Fatalf("BuildRequest: %v", err)
			}
			if want := rawRequest(tt.want); string(b) != want {
				t.Fatalf("request =\n%s\nwant\n%s", b, want)
			}
			req, err := ParseRequest(b)
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if req.Version != 1 || req.RequestID != testID || req.BaseRev != testBaseRev {
				t.Fatalf("decoded header = %+v", req)
			}
			again, err := BuildRequest(req.RequestID, req.BaseRev, req.Patch.OIDC.AllowedGroups)
			if err != nil {
				t.Fatalf("rebuild: %v", err)
			}
			if !bytes.Equal(again, b) {
				t.Fatalf("round trip changed the bytes:\n%s\n%s", again, b)
			}
		})
	}
}

// AC2: bad group lists are rejected at every entry point.
func TestHostPatch_RejectsGroups(t *testing.T) {
	tests := []struct{ name, list string }{
		{"empty list", `[]`},
		{"null list", `null`},
		{"more than three", `["devops","developer","standart","devops"]`},
		{"duplicate", `["devops","devops"]`},
		{"duplicate beyond devops", `["devops","developer","developer"]`},
		{"empty string", `["devops",""]`},
		{"unknown value", `["devops","admin"]`},
		{"case differs", `["devops","Developer"]`},
		{"padded value", `["devops"," standart"]`},
		{"devops missing", `["developer"]`},
		{"devops missing, all others", `["developer","standart"]`},
		{"null element", `["devops",null]`},
		{"number element", `["devops",1]`},
		{"not an array", `"devops"`},
		{"object instead of array", `{"devops":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseRequest([]byte(rawRequest(tt.list))); !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("ParseRequest err = %v, want ErrInvalidRequest", err)
			}
			var groups []string
			if json.Unmarshal([]byte(tt.list), &groups) != nil {
				return // not representable as []string; the parser case above covers it
			}
			if err := ValidateGroups(groups); !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("ValidateGroups err = %v, want ErrInvalidRequest", err)
			}
			if _, err := BuildRequest(testID, testBaseRev, groups); !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("BuildRequest err = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

// AC3: everything outside the exact request shape is rejected.
func TestHostPatch_RejectsRequest(t *testing.T) {
	valid := rawRequest(`["devops"]`)
	if _, err := ParseRequest([]byte(valid)); err != nil {
		t.Fatalf("baseline request must parse: %v", err)
	}
	groups := `"allowed_groups":["devops"]`
	patch := `"patch":{"oidc":{` + groups + `}}`
	head := fmt.Sprintf(`"version":1,"request_id":%q,"base_rev":%q`, testID, testBaseRev)

	tests := []struct{ name, doc string }{
		{"empty input", ``},
		{"not json", `devops`},
		{"not an object", `[]`},
		{"unknown top-level key", `{` + head + `,` + patch + `,"extra":1}`},
		{"created_at", `{` + head + `,"created_at":"2026-10-02T00:00:00Z",` + patch + `}`},
		{"recovery_of", `{` + head + `,"recovery_of":"` + testID + `",` + patch + `}`},
		{"dns field next to oidc", `{` + head + `,"patch":{"oidc":{` + groups + `},"dns":{"magic_dns":true}}}`},
		{"dns field inside oidc", `{` + head + `,"patch":{"oidc":{` + groups + `,"allowed_domains":["x.example"]}}}`},
		{"unknown patch key only", `{` + head + `,"patch":{"dns":{}}}`},
		{"duplicate version", `{"version":1,` + head + `,` + patch + `}`},
		{"duplicate request_id", `{` + head + `,"request_id":"` + testID + `",` + patch + `}`},
		{"duplicate patch", `{` + head + `,` + patch + `,` + patch + `}`},
		{"duplicate oidc", `{` + head + `,"patch":{"oidc":{` + groups + `},"oidc":{` + groups + `}}}`},
		{"duplicate allowed_groups", `{` + head + `,"patch":{"oidc":{` + groups + `,` + groups + `}}}`},
		{"key case differs", `{"Version":1,"request_id":"` + testID + `","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"case-variant duplicate", `{` + head + `,"VERSION":1,` + patch + `}`},
		{"version 2", `{"version":2,"request_id":"` + testID + `","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"version 0", `{"version":0,"request_id":"` + testID + `","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"version as string", `{"version":"1","request_id":"` + testID + `","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"version as float", `{"version":1.0,"request_id":"` + testID + `","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"version missing", `{"request_id":"` + testID + `","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"request_id missing", `{"version":1,"base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"base_rev missing", `{"version":1,"request_id":"` + testID + `",` + patch + `}`},
		{"patch missing", `{` + head + `}`},
		{"oidc missing", `{` + head + `,"patch":{}}`},
		{"patch null", `{` + head + `,"patch":null}`},
		{"uppercase uuid", `{"version":1,"request_id":"` + strings.ToUpper(testID) + `","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"uuid without dashes", `{"version":1,"request_id":"0b7f4c1e52d34a8e9c613f2d8a7e5b10","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"uuid with suffix", `{"version":1,"request_id":"` + testID + `0","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"uuid with newline", `{"version":1,"request_id":"` + testID + `\n","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"uuid with non-hex", `{"version":1,"request_id":"0b7f4c1e-52d3-4a8e-9c61-3f2d8a7e5b1g","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"empty request_id", `{"version":1,"request_id":"","base_rev":"` + testBaseRev + `",` + patch + `}`},
		{"base_rev uppercase", `{"version":1,"request_id":"` + testID + `","base_rev":"` + strings.ToUpper(testBaseRev) + `",` + patch + `}`},
		{"base_rev too short", `{"version":1,"request_id":"` + testID + `","base_rev":"` + testBaseRev[:63] + `",` + patch + `}`},
		{"base_rev too long", `{"version":1,"request_id":"` + testID + `","base_rev":"` + testBaseRev + `0",` + patch + `}`},
		{"base_rev non-hex", `{"version":1,"request_id":"` + testID + `","base_rev":"` + strings.Repeat("g", 64) + `",` + patch + `}`},
		{"base_rev empty", `{"version":1,"request_id":"` + testID + `","base_rev":"",` + patch + `}`},
		{"base_rev number", `{"version":1,"request_id":"` + testID + `","base_rev":1,` + patch + `}`},
		{"trailing garbage", valid + `x`},
		{"trailing second document", valid + valid},
		{"trailing comma", strings.TrimSuffix(valid, "}") + `,}`},
		{"invalid utf-8 in value", `{"version":1,"request_id":"` + testID + `","base_rev":"` + testBaseRev + `",` + patch + "\xff}"},
		{"invalid utf-8 in a string", strings.Replace(valid, `"devops"`, "\"dev\xffops\"", 1)},
		{"utf-8 BOM", "\xef\xbb\xbf" + valid},
		{"over 4 KiB", `{` + head + `,` + patch + `,"extra":"` + strings.Repeat("a", MaxRequestBytes) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseRequest([]byte(tt.doc)); !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("ParseRequest err = %v, want ErrInvalidRequest", err)
			}
		})
	}

	t.Run("exactly 4 KiB is not rejected for size", func(t *testing.T) {
		// A padded-with-whitespace valid document at the limit still parses; one byte more does not.
		pad := MaxRequestBytes - len(valid)
		atLimit := valid + strings.Repeat(" ", pad)
		if _, err := ParseRequest([]byte(atLimit)); err != nil {
			t.Errorf("document of %d bytes: %v", len(atLimit), err)
		}
		if _, err := ParseRequest([]byte(atLimit + " ")); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("document of %d bytes err = %v, want ErrInvalidRequest", len(atLimit)+1, err)
		}
	})

	t.Run("Build rejects a bad id or base_rev", func(t *testing.T) {
		for _, c := range []struct{ id, rev string }{
			{strings.ToUpper(testID), testBaseRev},
			{"", testBaseRev},
			{testID, ""},
			{testID, strings.ToUpper(testBaseRev)},
		} {
			if _, err := BuildRequest(c.id, c.rev, []string{"devops"}); !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("BuildRequest(%q, %q) err = %v, want ErrInvalidRequest", c.id, c.rev, err)
			}
		}
	})

	t.Run("errors never echo the offending input", func(t *testing.T) {
		_, err := ParseRequest([]byte(rawRequest(`["devops","SECRET-VALUE"]`)))
		if err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
			t.Errorf("err = %v", err)
		}
	})
}

type goldenCase struct {
	Name       string   `json:"name"`
	Groups     []string `json:"groups"`
	Projection string   `json:"projection"`
	BaseRev    string   `json:"base_rev"`
}

// AC4: the projection is canonical and base_rev matches the golden values.
func TestHostPatch_BaseRevCanonical(t *testing.T) {
	raw, err := os.ReadFile("testdata/base_rev.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden []goldenCase
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) < 4 {
		t.Fatalf("golden file has %d cases", len(golden))
	}
	seen := map[string]string{}
	for _, g := range golden {
		t.Run(g.Name, func(t *testing.T) {
			proj, err := Projection(g.Groups)
			if err != nil {
				t.Fatalf("Projection: %v", err)
			}
			if string(proj) != g.Projection {
				t.Errorf("projection = %s, want %s", proj, g.Projection)
			}
			rev, err := BaseRev(g.Groups)
			if err != nil {
				t.Fatalf("BaseRev: %v", err)
			}
			if rev != g.BaseRev {
				t.Errorf("base_rev = %s, want %s", rev, g.BaseRev)
			}
			if !validBaseRev(rev) {
				t.Errorf("base_rev %q is not 64 lowercase hex", rev)
			}
			if other, dup := seen[rev]; dup {
				t.Errorf("same base_rev as %q", other)
			}
			seen[rev] = g.Name
		})
	}

	t.Run("missing and empty field give the same base_rev", func(t *testing.T) {
		a, errA := BaseRev(nil)
		b, errB := BaseRev([]string{})
		if errA != nil || errB != nil || a != b {
			t.Fatalf("nil: %q %v, empty: %q %v", a, errA, b, errB)
		}
	})
	t.Run("order does not matter", func(t *testing.T) {
		a, _ := BaseRev([]string{"devops", "developer", "standart"})
		b, _ := BaseRev([]string{"standart", "devops", "developer"})
		if a != b {
			t.Fatalf("%s != %s", a, b)
		}
	})
	t.Run("a different value changes it", func(t *testing.T) {
		a, _ := BaseRev([]string{"devops", "developer"})
		b, _ := BaseRev([]string{"devops", "standart"})
		if a == b {
			t.Fatal("different lists share a base_rev")
		}
	})
	t.Run("values outside the closed set are an error", func(t *testing.T) {
		for _, groups := range [][]string{{"admins"}, {"devops", "devops"}, {"devops", "developer", "standart", "x"}, {""}} {
			if _, err := BaseRev(groups); err == nil {
				t.Errorf("BaseRev(%q) succeeded", groups)
			}
			if _, err := Projection(groups); err == nil {
				t.Errorf("Projection(%q) succeeded", groups)
			}
		}
	})
	t.Run("the input slice is not reordered", func(t *testing.T) {
		in := []string{"standart", "devops"}
		if _, err := BaseRev(in); err != nil {
			t.Fatal(err)
		}
		if in[0] != "standart" || in[1] != "devops" {
			t.Fatalf("input mutated: %v", in)
		}
	})
}
