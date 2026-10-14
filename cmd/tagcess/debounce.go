package main

import (
	"sync"
	"time"
)

// loginSyncWindow is the shortest gap between two syncs started by sign-ins (F5 I13).
const loginSyncWindow = 30 * time.Second

// debounced returns fn limited to one call per window. The first call runs at once; calls inside
// the window are dropped (the sync it started already reads the newest state). Safe for concurrent use.
func debounced(fn func(), window time.Duration, now func() time.Time) func() {
	var (
		mu   sync.Mutex
		last time.Time
		ran  bool
	)
	return func() {
		mu.Lock()
		if ran && now().Sub(last) < window {
			mu.Unlock()
			return
		}
		ran, last = true, now()
		mu.Unlock()
		fn()
	}
}
