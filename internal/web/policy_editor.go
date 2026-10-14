package web

import "github.com/nesiler/tagcess/internal/policydoc"

// reportErrorLine is the line of the first failed validation stage that names one, for the editor's
// error mark; 0 when no stage points at a line.
func reportErrorLine(r policydoc.Report) int {
	for _, s := range r.Stages {
		if s.State == policydoc.StateFail && s.Line > 0 {
			return s.Line
		}
	}
	return 0
}

// errorLine is the line the editor marks: from the refused save's report or the preview's.
func (v policyPageView) errorLine() int {
	switch {
	case v.Report != nil:
		return reportErrorLine(*v.Report)
	case v.Preview != nil:
		return reportErrorLine(v.Preview.Report)
	}
	return 0
}

// diffComputed reports whether the text could be read at all. When the input or HuJSON syntax
// stage failed there is nothing to compare, so the page must not claim "same as live" (U-8).
func (p policyPreviewView) diffComputed() bool {
	return p.Report.Stage(policydoc.StageInput).State == policydoc.StatePass &&
		p.Report.Stage(policydoc.StageSyntax).State == policydoc.StatePass
}
