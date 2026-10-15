package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

const healthzTimeout = 2 * time.Second

// NewHealthz returns the liveness handler: 200 when ping succeeds (the database is readable), 503
// otherwise. The body carries the status and the version only; the error is never exposed. It needs
// no identity, so it is mounted outside the identity middleware (and nothing else is).
func NewHealthz(ping func(context.Context) error, version string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), healthzTimeout)
		defer cancel()
		code, status := http.StatusOK, "ok"
		if err := ping(ctx); err != nil {
			code, status = http.StatusServiceUnavailable, "unavailable"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status, "version": version})
	})
}
