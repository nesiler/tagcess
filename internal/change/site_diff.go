package change

import "strings"

// lineDiffLimit bounds the LCS table (cells). A Caddyfile of the real site count is a few thousand
// lines; past the limit the diff falls back to a plain per-line added/removed listing, which is
// less precise about order but never expensive.
const lineDiffLimit = 4_000_000

// lineDiff returns the line-level difference of two artifact texts as "-line" (only in before) and
// "+line" (only in after) lines in file order, and "" when the texts are identical. It is the
// diff shown for the Caddyfile, the DNS file and the URI set (S-04.3).
func lineDiff(before, after string) string {
	if before == after {
		return ""
	}
	a, b := splitLines(before), splitLines(after)
	// Common head and tail carry no change; trimming them keeps the table small for the usual
	// one-site edit.
	head := 0
	for head < len(a) && head < len(b) && a[head] == b[head] {
		head++
	}
	tail := 0
	for tail < len(a)-head && tail < len(b)-head && a[len(a)-1-tail] == b[len(b)-1-tail] {
		tail++
	}
	a, b = a[head:len(a)-tail], b[head:len(b)-tail]
	if len(a) == 0 && len(b) == 0 {
		return "! only the trailing newline differs"
	}

	var out []string
	if len(a)*len(b) > lineDiffLimit {
		out = setDiff(a, b)
	} else {
		out = lcsDiff(a, b)
	}
	return strings.Join(out, "\n")
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// lcsDiff walks the longest-common-subsequence table of a and b.
func lcsDiff(a, b []string) []string {
	n, m := len(a), len(b)
	// lcs[i][j] is the LCS length of a[i:] and b[j:].
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, "-"+a[i])
			i++
		default:
			out = append(out, "+"+b[j])
			j++
		}
	}
	return out
}

// setDiff lists the lines that occur more often on one side than on the other.
func setDiff(a, b []string) []string {
	counts := map[string]int{}
	for _, l := range b {
		counts[l]++
	}
	var out []string
	for _, l := range a {
		if counts[l] > 0 {
			counts[l]--
			continue
		}
		out = append(out, "-"+l)
	}
	counts = map[string]int{}
	for _, l := range a {
		counts[l]++
	}
	for _, l := range b {
		if counts[l] > 0 {
			counts[l]--
			continue
		}
		out = append(out, "+"+l)
	}
	return out
}

// LineDiff is lineDiff for other packages: the policy editor's raw preview diff (F3-010).
func LineDiff(before, after string) string { return lineDiff(before, after) }
