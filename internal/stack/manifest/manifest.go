// Package manifest embeds the release's version manifest. Only cmd/tagcess-hshelper may import it; the tagcess
// binary keeps no copy (setup-flow.md §5.5). internal/stack's tests fail if cmd/tagcess depends on internal/stack.
package manifest

import _ "embed"

// JSON is the manifest of this release (parsed by stack.Load).
//
//go:embed manifest.json
var JSON []byte
