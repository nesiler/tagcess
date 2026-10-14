package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// staticFS holds the front-end assets pinned in internal/web/static (see static/README.md). The
// interface must not depend on a CDN (ADR 0007), so every file the pages need is served from the
// binary. Only the assets are embedded; the README stays in the repository.
//
//go:embed static/htmx.min.js static/tokens.css static/components.css static/ui.js static/editor.js
var staticFS embed.FS

// Static serves the embedded assets at a path the caller mounts under /static/ (ADR 0007). Only the
// exact embedded files are served: directory requests are refused, and every response carries a
// nosniff type so a browser never guesses a different one. Assets change only with a release, so
// they are revalidated instead of cached.
func Static() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// Only reachable if the embed paths and this prefix disagree, which is a build-time mistake.
		panic(err)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}
