package caddy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Caddy resolves a relative file import (`import sites/*.caddy`) against the directory of the file
// that holds it. POST /adapt receives text without a file name, so Caddy resolves the same import
// against its own working directory, and a glob that matches nothing there is only a warning: the
// imported site blocks silently vanish from the adapted config. AbsImports gives /adapt the text
// as Caddy would read it from the Caddyfile's own directory. It only rewrites text; Caddy itself
// reads the imported files, exactly as it does when it loads the Caddyfile.

// heredocMarker is the marker rule of Caddy's lexer (`<<MARKER` at the end of a line).
var heredocMarker = regexp.MustCompile(`^<<[A-Za-z0-9_-]+$`)

// AbsImports rewrites the relative file imports of a Caddyfile that lives in dir to absolute
// paths under dir. An import stays as written when its argument is a snippet defined in the text,
// already absolute, quoted, holds a placeholder or escape, or is a bare name that is neither a
// file in dir nor a path or glob (Caddy then treats it as it always would). Comments, quoted,
// backtick and heredoc strings are never touched. A dir that is not an absolute path writable as
// one plain Caddyfile token leaves the text unchanged.
func AbsImports(caddyfile, dir string) string {
	if !filepath.IsAbs(dir) || strings.ContainsFunc(dir, func(r rune) bool {
		return r <= ' ' || r == 0x7f || strings.ContainsRune("\"`{}#\\", r)
	}) {
		return caddyfile
	}
	toks := lexTokens(caddyfile)
	snippets := make(map[string]bool)
	addSnippets(toks, snippets)
	// A snippet defined in an imported file is a snippet name too (review D3). Only the files of path or glob
	// imports are read here; a bare name is resolved against the snippets found so far.
	for i := 0; i+1 < len(toks); i++ {
		imp, arg := toks[i], toks[i+1]
		if !imp.first || imp.quoted || imp.text != "import" || arg.first || arg.quoted ||
			filepath.IsAbs(arg.text) || !strings.ContainsAny(arg.text, "/*?[") || strings.ContainsAny(arg.text, "{}\\") {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(dir, arg.text))
		for _, f := range files {
			if body, err := os.ReadFile(f); err == nil { // #nosec G304 -- the Caddyfile's own imports
				addSnippets(lexTokens(string(body)), snippets)
			}
		}
	}
	var b strings.Builder
	last := 0
	for i := 0; i+1 < len(toks); i++ {
		imp, arg := toks[i], toks[i+1]
		if !imp.first || imp.quoted || imp.text != "import" || arg.first || arg.quoted || !fileImport(arg.text, dir, snippets) {
			continue
		}
		b.WriteString(caddyfile[last:arg.start])
		b.WriteString(filepath.Join(dir, arg.text))
		last = arg.end
	}
	if last == 0 {
		return caddyfile
	}
	b.WriteString(caddyfile[last:])
	return b.String()
}

// addSnippets adds the names of the snippets the tokens define, "(name)" at a line start.
func addSnippets(toks []lexToken, snippets map[string]bool) {
	for _, t := range toks {
		if t.first && !t.quoted && len(t.text) > 2 && t.text[0] == '(' && t.text[len(t.text)-1] == ')' {
			snippets[t.text[1:len(t.text)-1]] = true
		}
	}
}

// fileImport reports whether Caddy reads the import argument p as a file path relative to dir.
func fileImport(p, dir string, snippets map[string]bool) bool {
	if p == "" || filepath.IsAbs(p) || snippets[p] || strings.ContainsAny(p, "{}\\") {
		return false
	}
	if strings.ContainsAny(p, "/*?[") {
		return true
	}
	_, err := os.Stat(filepath.Join(dir, p))
	return err == nil
}

// lexToken is one Caddyfile token: its byte range, whether it was quoted (", ` or heredoc) and
// whether it is the first token of its line (a directive or a block key).
type lexToken struct {
	start, end int
	text       string
	quoted     bool
	first      bool
}

// lexTokens splits a Caddyfile into tokens the way Caddy's lexer does for the parts AbsImports
// needs: whitespace separates tokens, "#" at a token start comments out the rest of the line,
// quotes and backticks open only at a token start and may span lines, a backslash escapes the
// next character, and `<<MARKER` at the end of a line opens a heredoc that ends at the marker.
func lexTokens(s string) []lexToken {
	var toks []lexToken
	line, lastEndLine := 1, 0
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case '\n':
			line++
			i++
			continue
		case ' ', '\t', '\r':
			i++
			continue
		case '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		tok := lexToken{start: i, first: line > lastEndLine}
		switch c {
		case '"', '`':
			tok.quoted = true
			i++
			for i < len(s) && s[i] != c {
				if s[i] == '\\' && c == '"' && i+1 < len(s) {
					if s[i+1] == '\n' {
						line++
					}
					i++
				} else if s[i] == '\n' {
					line++
				}
				i++
			}
			i++ // the closing quote
		default:
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n' {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] != '\n' {
					i++
				}
				i++
			}
			tok.text = s[tok.start:i]
			if heredocMarker.MatchString(tok.text) && (i == len(s) || s[i] == '\n' || s[i] == '\r') {
				marker := tok.text[2:]
				end := strings.Index(s[i:], marker)
				if end < 0 {
					end = len(s) - i
				} else {
					end += len(marker)
				}
				line += strings.Count(s[i:i+end], "\n")
				i += end
				tok.quoted, tok.text = true, ""
			}
		}
		tok.end = min(i, len(s))
		toks = append(toks, tok)
		lastEndLine = line
	}
	return toks
}
