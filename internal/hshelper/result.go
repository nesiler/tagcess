package hshelper

import (
	"io"
	"os"
	"path/filepath"

	"github.com/nesiler/tagcess/internal/hostpatch"
)

const resultName = "result.json"

// WriteResult publishes r as resultsDir/result.json: validated, at most 4 KiB, atomic, 0644 so the
// container can read it. Only the last result is kept (ADR 0021 b). F3b-008 reuses this for the
// success and failure results.
func WriteResult(resultsDir string, r hostpatch.Result) error {
	b, err := hostpatch.EncodeResult(r)
	if err != nil {
		return err
	}
	return atomicWrite(resultsDir, resultName, b, 0o644)
}

// readResultID returns the request ID of the published result.json, or "" when there is none or it
// is not a valid result. results/ is root-written, so a plain read is enough.
func readResultID(resultsDir string) string {
	f, err := os.Open(filepath.Join(resultsDir, resultName)) //nolint:gosec // root-owned results dir
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, hostpatch.MaxResultBytes+1))
	if err != nil {
		return ""
	}
	r, err := hostpatch.DecodeResult(b)
	if err != nil {
		return ""
	}
	return r.RequestID
}
