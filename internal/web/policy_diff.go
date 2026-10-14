package web

import (
	"strings"

	"github.com/nesiler/tagcess/internal/policywriter"
)

// The policy editor's diff view (F3-019, H-04): the writer's raw line diff and meaning-level diff
// turned into rows the page renders. The diffs themselves come from change.LineDiff and
// policywriter.SemanticDiff; nothing here compares texts.

type diffKind string

const (
	diffAdd  diffKind = "add"
	diffDel  diffKind = "del"
	diffNote diffKind = "note"
)

// diffRow is one line of the raw diff.
type diffRow struct {
	Kind diffKind
	Text string
}

// rawDiffRows splits change.LineDiff's "+line" / "-line" output into rows. A "!" line is the
// diff's own remark (only the trailing newline differs) and stays a note, not a changed line.
func rawDiffRows(raw string) []diffRow {
	if raw == "" {
		return nil
	}
	var rows []diffRow
	for _, l := range strings.Split(raw, "\n") {
		switch {
		case strings.HasPrefix(l, "+"):
			rows = append(rows, diffRow{Kind: diffAdd, Text: l[1:]})
		case strings.HasPrefix(l, "-"):
			rows = append(rows, diffRow{Kind: diffDel, Text: l[1:]})
		default:
			rows = append(rows, diffRow{Kind: diffNote, Text: strings.TrimPrefix(l, "! ")})
		}
	}
	return rows
}

// changedEntry is an object member whose value differs between the two texts.
type changedEntry struct {
	Key, Before, After string
}

// semanticRow is one section's meaning-level change: entries only in the new text, only in the old
// one, and members present in both with a different value.
type semanticRow struct {
	Section string
	Label   string
	Added   []string
	Removed []string
	Changed []changedEntry
}

// sectionLabels names the policy sections an operator reads; others show their own name.
var sectionLabels = map[string]string{
	"acls":          "ACL kuralı",
	"tagOwners":     "tag owner'ları",
	"autoApprovers": "otomatik onay (route/exit node)",
	"groups":        "gruplar",
	"tests":         "testler",
	"hosts":         "hosts",
	"grants":        "grants",
	"ssh":           "ssh",
	"nodeAttrs":     "nodeAttrs",
}

// semanticRows turns the writer's section changes into rows. An object member removed and added
// under the same key is one change, not a pair; array entries (ACL rules) stay a removal and an
// addition.
func semanticRows(changes []policywriter.SectionChange) []semanticRow {
	var rows []semanticRow
	for _, c := range changes {
		label := sectionLabels[c.Section]
		if label == "" {
			label = c.Section
		}
		row := semanticRow{Section: c.Section, Label: label}
		removed := map[string]string{}
		for _, r := range c.Removed {
			if k, v, ok := memberEntry(r); ok {
				removed[k] = v
			}
		}
		paired := map[string]bool{}
		for _, a := range c.Added {
			if k, v, ok := memberEntry(a); ok {
				if before, was := removed[k]; was {
					row.Changed = append(row.Changed, changedEntry{Key: k, Before: before, After: v})
					paired[k] = true
					continue
				}
			}
			row.Added = append(row.Added, a)
		}
		for _, r := range c.Removed {
			if k, _, ok := memberEntry(r); ok && paired[k] {
				continue
			}
			row.Removed = append(row.Removed, r)
		}
		rows = append(rows, row)
	}
	return rows
}

// memberEntry splits an object member entry ("key: value"). Array entries (compact JSON values) are
// not members: they start with a brace, bracket or quote.
func memberEntry(e string) (key, value string, ok bool) {
	if e == "" || strings.ContainsAny(e[:1], `{["`) {
		return "", "", false
	}
	key, value, ok = strings.Cut(e, ": ")
	return key, value, ok
}

// hasSection reports whether the rows include a change of the named section.
func hasSection(rows []semanticRow, name string) bool {
	for _, r := range rows {
		if r.Section == name {
			return true
		}
	}
	return false
}
