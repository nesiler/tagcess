package render

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// TestParity_DropKnownAdditions: only the exact friendly 403 page of the renderer is dropped, and
// only where today's side has no entry; every deviation stays a reported diff.
func TestParity_DropKnownAdditions(t *testing.T) {
	const signOut = "/oauth2/sign_out?rd=%2F"
	page := func(body string, status int, extra bool, matchCode int) map[string]any {
		handles := []any{
			map[string]any{"handler": "headers", "response": map[string]any{"set": map[string]any{"Content-Type": []any{"text/html; charset=utf-8"}}}},
			map[string]any{"handler": "static_response", "status_code": json.Number(strconv.Itoa(status)), "body": body},
		}
		if extra {
			handles = append(handles, map[string]any{"handler": "vars"})
		}
		return map[string]any{
			"match":  map[string]any{"status_code": []any{json.Number(strconv.Itoa(matchCode))}},
			"routes": []any{map[string]any{"handle": handles}},
		}
	}
	redir := func() any {
		return map[string]any{"match": map[string]any{"status_code": []any{json.Number("401")}}, "routes": []any{}}
	}
	doc := func(entries ...any) any {
		return map[string]any{"routes": []any{map[string]any{"handle": []any{
			map[string]any{"handler": "reverse_proxy", "handle_response": entries},
		}}}}
	}
	good := page(caddyForbiddenPage(signOut), 403, false, 403)

	cases := []struct {
		name     string
		cur, gen any
		wantDiff bool
	}{
		{"exact page is dropped", doc(redir()), doc(redir(), good), false},
		{"changed body is a diff", doc(redir()), doc(redir(), page("<p>x</p>", 403, false, 403)), true},
		{"status 200 is a diff", doc(redir()), doc(redir(), page(caddyForbiddenPage(signOut), 200, false, 403)), true},
		{"extra handler is a diff", doc(redir()), doc(redir(), page(caddyForbiddenPage(signOut), 403, true, 403)), true},
		{"other matcher is a diff", doc(redir()), doc(redir(), page(caddyForbiddenPage(signOut), 403, false, 404)), true},
		{"other sign-out link is a diff", doc(redir()), doc(redir(), page(caddyForbiddenPage("/other"), 403, false, 403)), true},
		{"page on both sides compares normally", doc(redir(), good), doc(redir(), good), false},
		{"page on both sides, changed generated body", doc(redir(), good), doc(redir(), page("<p>x</p>", 403, false, 403)), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dropKnownAdditions(c.cur, c.gen, signOut)
			var diffs []string
			diffJSON("", c.cur, c.gen, &diffs)
			if got := len(diffs) > 0; got != c.wantDiff {
				t.Errorf("diff = %v, want %v: %s", got, c.wantDiff, strings.Join(diffs, "\n"))
			}
		})
	}
}
