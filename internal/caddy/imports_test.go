package caddy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAbsImports: Caddy resolves a relative file import against the directory of the file that holds it,
// but POST /adapt gets text without a file name, so Caddy resolves it against its own working directory and
// a glob that matches nothing there is only a warning (the 20 adopt-target site files silently vanished from the
// first-import comparison). AbsImports rewrites exactly the file imports Caddy would read relative to the
// Caddyfile's directory; snippet imports, absolute paths, comments, strings and placeholders stay as written.
func TestAbsImports(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "common.caddy"), []byte("# x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs := func(p string) string { return filepath.Join(dir, p) }
	snippets := "(k8s) {\n\treverse_proxy https://100.64.0.5\n}\n(vpn_site) {\n\timport k8s\n}\n"
	cases := []struct {
		name, in, want string
	}{
		{"relative glob", "import sites/*.caddy\n", "import " + abs("sites/*.caddy") + "\n"},
		{"relative glob without trailing newline", "a.example {\n}\nimport sites/*.caddy", "a.example {\n}\nimport " + abs("sites/*.caddy")},
		{"existing bare file name, indented in a block", "a.example {\n\timport common.caddy\n}\n", "a.example {\n\timport " + abs("common.caddy") + "\n}\n"},
		{"dot-relative path", "import ./x/y.caddy\n", "import " + abs("x/y.caddy") + "\n"},
		{"snippet import stays", snippets + "a.example {\n\timport vpn_site c.example devops,developer\n}\n", ""},
		{"snippet imported before its definition is still a snippet name", "a.example {\n\timport k8s\n}\n" + snippets, ""},
		{"absolute path stays", "import /etc/caddy/sites/*.caddy\n", ""},
		{"bare name that is neither a snippet nor a file stays (Caddy decides)", "a.example {\n\timport defined_elsewhere\n}\n", ""},
		{"placeholder stays", "(s) {\n\timport {args[0]}\n}\n", ""},
		{"comment stays", "# import sites/*.caddy\na.example {\n\t# import sites/*.caddy\n}\n", ""},
		{"import as an argument stays", "a.example {\n\trespond import 200\n}\n", ""},
		{"inside a quoted string stays", "a.example {\n\trespond \"x\nimport sites/*.caddy\n\" 200\n}\n", ""},
		{"inside a backtick string stays", "a.example {\n\trespond `x\nimport sites/*.caddy\n` 200\n}\n", ""},
		{"inside a heredoc stays", "a.example {\n\trespond <<EOF\n\timport sites/*.caddy\n\tEOF 200\n}\n", ""},
		{"escaped quote does not end the string", "a.example {\n\trespond \"a\\\"\nimport sites/*.caddy\n\" 200\n}\n", ""},
		{"quoted pattern stays", "import \"sites/*.caddy\"\n", ""},
		{"second import on the next line is rewritten too", "import sites/*.caddy\nimport more/*.caddy\n",
			"import " + abs("sites/*.caddy") + "\nimport " + abs("more/*.caddy") + "\n"},
		{"CRLF line ends", "import sites/*.caddy\r\na.example {\r\n}\r\n", "import " + abs("sites/*.caddy") + "\r\na.example {\r\n}\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == "" {
				want = tc.in
			}
			if got := AbsImports(tc.in, dir); got != want {
				t.Errorf("AbsImports:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// TestAbsImports_UnsafeDirectory: a directory that cannot be written as one plain Caddyfile token leaves the
// text unchanged (the comparison then reports the missing sites; it never guesses).
func TestAbsImports_UnsafeDirectory(t *testing.T) {
	for _, dir := range []string{"", "relative/dir", "/etc/my caddy", "/etc/{x}", "/etc/\"q\"", "/etc/a#b", "/etc/`b`"} {
		in := "import sites/*.caddy\n"
		if got := AbsImports(in, dir); got != in {
			t.Errorf("dir %q: got %q, want the text unchanged", dir, got)
		}
	}
}

// TestAbsImports_SnippetFromImportedFile (review D3): a snippet defined in an imported file is a snippet name for
// Caddy too, so `import <name>` stays as written even when a file of that name exists next to the Caddyfile.
func TestAbsImports_SnippetFromImportedFile(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"snippets/common.caddy": "(k8s) {\n\treverse_proxy https://100.64.0.5\n}\n",
		"k8s":                   "# a file that happens to share the snippet's name\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	in := "import snippets/*.caddy\na.example {\n\timport k8s\n}\n"
	want := "import " + filepath.Join(dir, "snippets/*.caddy") + "\na.example {\n\timport k8s\n}\n"
	if got := AbsImports(in, dir); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// Without the snippet file the same name is a file import, as before.
	if err := os.Remove(filepath.Join(dir, "snippets/common.caddy")); err != nil {
		t.Fatal(err)
	}
	if got := AbsImports(in, dir); got != "import "+filepath.Join(dir, "snippets/*.caddy")+"\na.example {\n\timport "+filepath.Join(dir, "k8s")+"\n}\n" {
		t.Fatalf("a file import must still be rewritten:\n%s", got)
	}
}
