package ui

import (
	"strconv"
	"strings"
)

// diffLine is one rendered line of a unified diff. text is the raw line, its +/- marker included,
// so a copied diff is still a diff.
type diffLine struct {
	class string
	text  string
}

// parsedDiff is a unified diff split into lines, with its change counts.
type parsedDiff struct {
	lines []diffLine
	adds  int
	dels  int
}

// parseDiff reads unified diff text ("---"/"+++" headers, "@@" hunks, "+"/"-"/" " lines). The file
// headers are dropped (the Diff title names the artifact), but only as the leading "---", "+++",
// "@@" triple: the site diffs (change.lineDiff) have no headers, and there a removed "-- x" line is
// "--- x". Anything else is kept as context, so a plain text block still renders.
func parseDiff(text string) parsedDiff {
	var d parsedDiff
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) >= 3 && strings.HasPrefix(lines[0], "---") && strings.HasPrefix(lines[1], "+++") && strings.HasPrefix(lines[2], "@@") {
		lines = lines[2:]
	}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "@@"):
			d.lines = append(d.lines, diffLine{class: "ln ln-hunk", text: l})
		case strings.HasPrefix(l, "+"):
			d.adds++
			d.lines = append(d.lines, diffLine{class: "ln ln-add", text: l})
		case strings.HasPrefix(l, "-"):
			d.dels++
			d.lines = append(d.lines, diffLine{class: "ln ln-del", text: l})
		default:
			d.lines = append(d.lines, diffLine{class: "ln", text: l})
		}
	}
	return d
}

func (d parsedDiff) summary() string {
	return strconv.Itoa(d.adds) + " ekleme · " + strconv.Itoa(d.dels) + " silme"
}
