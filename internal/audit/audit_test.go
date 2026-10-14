package audit

import (
	"context"
	"errors"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/store"
)

// openLogger returns a logger backed by a fresh SQLite database.
func openLogger(t *testing.T) (*Logger, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tagcess.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(s.Queries()), s
}

// AC1: a written event is stored with actor, time, event, target, diff and result, and read back
// with the same values (A-01.1).
func TestAudit_WriteAndRead(t *testing.T) {
	ctx := context.Background()
	l, _ := openLogger(t)
	at := time.Date(2026, 9, 29, 12, 34, 56, 0, time.UTC)
	l.clock = func() time.Time { return at }

	diff := Diff{
		{Field: "groups.standart", Before: "[]", After: `["devops"]`},
		{Field: "policy.mode", Before: "file", After: "database"},
	}
	written, err := l.Write(ctx, Entry{
		Actor:  "devops@example.com",
		Event:  "policy.update",
		Target: "headscale/policy",
		Diff:   diff,
		Result: "applied",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written.ID == 0 {
		t.Fatal("Write returned id 0")
	}
	if !written.At.Equal(at) {
		t.Errorf("stored at = %v, want %v", written.At, at)
	}

	read, err := l.Get(ctx, written.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if read.Actor != "devops@example.com" {
		t.Errorf("actor = %q", read.Actor)
	}
	if !read.At.Equal(at) {
		t.Errorf("time = %v, want %v", read.At, at)
	}
	if read.Event != "policy.update" {
		t.Errorf("event = %q", read.Event)
	}
	if read.Target != "headscale/policy" {
		t.Errorf("target = %q", read.Target)
	}
	if read.Result != "applied" {
		t.Errorf("result = %q", read.Result)
	}
	if len(read.Diff) != len(diff) {
		t.Fatalf("diff length = %d, want %d", len(read.Diff), len(diff))
	}
	for i := range diff {
		if read.Diff[i] != diff[i] {
			t.Errorf("diff[%d] = %+v, want %+v", i, read.Diff[i], diff[i])
		}
	}
}

// List returns the newest event first, filters by exact actor or event and refuses a non-positive
// limit so a listing request never reads the whole table by accident.
func TestAudit_List(t *testing.T) {
	ctx := context.Background()
	l, _ := openLogger(t)
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		{Actor: "alice@example.com", Event: "policy.update", Result: "applied"},
		{Actor: "bob@example.com", Event: "policy.update", Result: "applied"},
		{Actor: "alice@example.com", Event: "node.expire", Result: "applied"},
	}
	for i, e := range entries {
		at := base.Add(time.Duration(i) * time.Minute)
		l.clock = func() time.Time { return at }
		if _, err := l.Write(ctx, e); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	all, err := l.List(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != len(entries) {
		t.Fatalf("len = %d, want %d", len(all), len(entries))
	}
	if all[0].Event != "node.expire" {
		t.Errorf("first event = %q, want the newest (node.expire)", all[0].Event)
	}

	byActor, err := l.List(ctx, Filter{Actor: "alice@example.com", Limit: 10})
	if err != nil {
		t.Fatalf("List by actor: %v", err)
	}
	if len(byActor) != 2 {
		t.Errorf("actor filter len = %d, want 2", len(byActor))
	}
	byEvent, err := l.List(ctx, Filter{Event: "policy.update", Limit: 10})
	if err != nil {
		t.Fatalf("List by event: %v", err)
	}
	if len(byEvent) != 2 {
		t.Errorf("event filter len = %d, want 2", len(byEvent))
	}

	if _, err := l.List(ctx, Filter{}); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("List without a limit error = %v, want ErrInvalidFilter", err)
	}
}

// AC3: a value marked secret is masked before it reaches the database, and other values in the
// same diff are kept (security.md 7, 9).
func TestAudit_MasksSecrets(t *testing.T) {
	ctx := context.Background()
	l, s := openLogger(t)

	written, err := l.Write(ctx, Entry{
		Actor:  "system:sync",
		Event:  "headscale.config",
		Target: "headscale/config",
		Diff: Diff{
			{Field: "oidc.client_secret", Before: "old-secret", After: "new-secret", Secret: true},
			{Field: "oidc.issuer", Before: "https://a", After: "https://b"},
		},
		Result: "applied",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// The raw stored text must not contain the secret, whatever the read path does later.
	var raw string
	if err := s.DB().QueryRowContext(ctx,
		"SELECT diff FROM audit_events WHERE id = ?", written.ID).Scan(&raw); err != nil {
		t.Fatalf("read raw diff: %v", err)
	}
	for _, secret := range []string{"old-secret", "new-secret"} {
		if strings.Contains(raw, secret) {
			t.Errorf("secret %q reached the database: %s", secret, raw)
		}
	}

	read, err := l.Get(ctx, written.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if read.Diff[0].Field != "oidc.client_secret" {
		t.Errorf("secret field name was changed: %q", read.Diff[0].Field)
	}
	if read.Diff[0].Before != Mask || read.Diff[0].After != Mask {
		t.Errorf("secret value not masked: %+v", read.Diff[0])
	}
	if read.Diff[1].Before != "https://a" || read.Diff[1].After != "https://b" {
		t.Errorf("non-secret value was altered: %+v", read.Diff[1])
	}
}

// AC4: an event without an actor is refused and nothing is written (A-01.1, security.md 9).
func TestAudit_RequiresActor(t *testing.T) {
	ctx := context.Background()
	l, s := openLogger(t)

	for _, actor := range []string{"", "   "} {
		if _, err := l.Write(ctx, Entry{Actor: actor, Event: "policy.update", Result: "applied"}); !errors.Is(err, ErrNoActor) {
			t.Errorf("Write(actor=%q) error = %v, want ErrNoActor", actor, err)
		}
	}
	var count int
	if err := s.DB().QueryRowContext(ctx, "SELECT count(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatalf("count audit_events: %v", err)
	}
	if count != 0 {
		t.Fatalf("audit_events rows = %d, want 0", count)
	}
}

// AC2: no source file or sqlc query mutates audit_events; the table is append-only. Go comments and
// SQL comments are removed (a comment naming a forbidden statement is not code), quoted identifiers
// and a "main." prefix are normalized, and each statement is checked for a mutating keyword. For a
// CREATE TRIGGER only the body after BEGIN is scanned, so a protective trigger header naming
// UPDATE/DELETE ON audit_events passes while a mutation hidden in the body is caught. A static scan
// cannot see a statement assembled at runtime; the migration-level trigger is tracked as follow-up
// hardening.
func TestAudit_NoMutationQueries(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".sql") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// SQL lives either directly in a .sql file or in the string literals of a .go file.
		code := string(body)
		if strings.HasSuffix(path, ".go") {
			if code = goStringLiterals(body); code == "" {
				return nil
			}
		}
		for _, statement := range auditStatements(code) {
			if kind := auditMutation(statement); kind != "" {
				offenders = append(offenders, path+": "+kind)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, offender := range offenders {
		t.Errorf("audit_events is mutated by: %s", offender)
	}
}

// AC2 regression: a CREATE TRIGGER header may name UPDATE/DELETE ON audit_events (that is how a
// protective append-only trigger is declared), but a mutation hidden in the trigger body must still
// be caught. The body is what follows the BEGIN keyword.
func TestAudit_NoMutationQueries_TriggerBodies(t *testing.T) {
	cases := []struct {
		name    string
		trigger string
		want    string // "" means the statement is allowed
	}{
		{
			name:    "protective raise on update is allowed",
			trigger: "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'append-only'); END",
			want:    "",
		},
		{
			name:    "protective raise on delete is allowed",
			trigger: "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'append-only'); END",
			want:    "",
		},
		{
			name:    "protective raise with quoted begin trigger name is allowed",
			trigger: `CREATE TRIGGER "begin" BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'append-only'); END`,
			want:    "",
		},
		{
			name:    "protective raise with backtick begin trigger name is allowed",
			trigger: "CREATE TRIGGER `begin` BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'append-only'); END",
			want:    "",
		},
		{
			name:    "protective raise with bracket begin trigger name is allowed",
			trigger: "CREATE TRIGGER [begin] BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'append-only'); END",
			want:    "",
		},
		{
			name:    "update hidden in body of quoted begin trigger is caught",
			trigger: `CREATE TRIGGER "begin" AFTER INSERT ON settings BEGIN UPDATE audit_events SET result = 1; END`,
			want:    "update",
		},
		{
			name:    "update hidden in trigger body is caught",
			trigger: "CREATE TRIGGER overwrite_audit AFTER INSERT ON settings BEGIN UPDATE audit_events SET result = 1; END",
			want:    "update",
		},
		{
			name:    "delete hidden in trigger body is caught",
			trigger: "CREATE TRIGGER wipe_audit AFTER INSERT ON settings BEGIN DELETE FROM audit_events; END",
			want:    "delete",
		},
		{
			name:    "insert into audit_events is allowed",
			trigger: "CREATE TRIGGER mirror AFTER INSERT ON settings BEGIN INSERT INTO audit_events (actor) VALUES ('system'); END",
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			for _, statement := range auditStatements(tc.trigger) {
				if kind := auditMutation(statement); kind != "" {
					got = kind
				}
			}
			if got != tc.want {
				t.Errorf("mutation = %q, want %q", got, tc.want)
			}
		})
	}
}

// goStringLiterals returns the string literals of a Go source file, each terminated by ";" so
// unrelated literals in the same file are never merged into one statement. It uses go/scanner, so
// Go comments are ignored and a comment naming a statement is never scanned as code.
func goStringLiterals(src []byte) string {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, 0)
	var b strings.Builder
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.STRING && tok != token.CHAR {
			continue
		}
		if value, err := strconv.Unquote(lit); err == nil {
			b.WriteString(value)
		} else {
			b.WriteString(lit)
		}
		b.WriteByte(';')
	}
	return b.String()
}

var (
	// auditEventsRef matches the audit_events table, not a name that merely contains it (an index
	// such as idx_audit_events_at or a table audit_events_old is not the table).
	auditEventsRef = regexp.MustCompile(`\baudit_events\b`)
	// auditMutationVerb finds a statement that changes existing rows (update, delete or replace).
	auditMutationVerb = regexp.MustCompile(`\b(update|delete|replace)\b`)
	// auditSchemaDrop finds a statement that removes or rewrites the table itself.
	auditSchemaDrop = regexp.MustCompile(`\b(drop|alter)\s+table\b`)
)

// auditStatements strips SQL comments and string literals, keeps quoted identifiers with their
// delimiters, then splits the result into normalized statements. Comments and string contents become
// a space, so a keyword cannot be glued to the table name and a ";" inside a string cannot split a
// statement. Keeping the delimiters lets a later keyword scan tell a quoted "begin" from the BEGIN
// keyword.
func auditStatements(code string) []string {
	var b strings.Builder
	for i := 0; i < len(code); {
		switch {
		case code[i] == '-' && i+1 < len(code) && code[i+1] == '-':
			for i < len(code) && code[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case code[i] == '/' && i+1 < len(code) && code[i+1] == '*':
			i += 2
			for i+1 < len(code) && (code[i] != '*' || code[i+1] != '/') {
				i++
			}
			i = min(i+2, len(code))
			b.WriteByte(' ')
		case code[i] == '\'':
			i++
			for i < len(code) {
				if code[i] == '\'' {
					if i+1 < len(code) && code[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			b.WriteByte(' ')
		case code[i] == '"' || code[i] == '`' || code[i] == '[':
			open := code[i]
			closeByte := byte(']')
			switch open {
			case '"':
				closeByte = '"'
			case '`':
				closeByte = '`'
			}
			b.WriteByte(open)
			i++
			for i < len(code) && code[i] != closeByte {
				b.WriteByte(code[i])
				i++
			}
			if i < len(code) {
				b.WriteByte(closeByte)
				i++
			}
		default:
			b.WriteByte(code[i])
			i++
		}
	}
	// Casefold, drop the schema qualifier and collapse whitespace so identifiers compare plainly.
	normalized := strings.NewReplacer("main.", "", "main ", " ").Replace(strings.ToLower(b.String()))
	fields := strings.Fields(normalized)
	out := make([]string, 0)
	for _, statement := range strings.Split(strings.Join(fields, " "), ";") {
		if statement = strings.TrimSpace(statement); statement != "" {
			out = append(out, statement)
		}
	}
	return out
}

// auditMutation returns the mutating keyword when the statement touches audit_events and changes
// data or schema, else "". A CREATE TRIGGER is DDL: its header may legitimately name UPDATE or
// DELETE ON audit_events, which is how a protective append-only trigger is declared. That header is
// separated from the trigger body, and only the body is scanned, so a mutation hidden inside a
// trigger cannot ride on the exemption.
func auditMutation(statement string) string {
	if strings.HasPrefix(statement, "create trigger") {
		statement = triggerBody(statement)
	}
	if !auditEventsRef.MatchString(statement) {
		return ""
	}
	if verb := auditMutationVerb.FindString(statement); verb != "" {
		return verb
	}
	return auditSchemaDrop.FindString(statement)
}

// triggerBody returns the statements of a CREATE TRIGGER, i.e. the part after the BEGIN keyword.
// BEGIN is found by scanning tokens, so a quoted identifier (a trigger may legitimately be named
// "begin") or a string literal cannot stand in for the separator: only a bare BEGIN opens the body.
// A valid trigger always has BEGIN, so the header (which names the triggering event and table) is
// dropped and a protective "BEFORE UPDATE/DELETE ON audit_events" is not mistaken for a mutation.
// When BEGIN is absent the whole statement is returned, so an inline mutation is never hidden.
func triggerBody(statement string) string {
	for i := 0; i < len(statement); {
		switch statement[i] {
		case '"', '`', '[':
			closeByte := byte(']')
			if statement[i] != '[' {
				closeByte = statement[i]
			}
			i++
			for i < len(statement) && statement[i] != closeByte {
				i++
			}
			if i < len(statement) {
				i++
			}
		case '\'':
			i++
			for i < len(statement) {
				if statement[i] == '\'' {
					if i+1 < len(statement) && statement[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case ' ':
			i++
		default:
			start := i
			for i < len(statement) && statement[i] != ' ' {
				i++
			}
			if statement[start:i] == "begin" {
				return statement[i:]
			}
		}
	}
	return statement
}
