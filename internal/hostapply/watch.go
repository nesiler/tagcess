package hostapply

import (
	"context"
	"time"
)

// PollInterval is how often the watcher looks for the helper's result (F3b-018 [Ö]).
const PollInterval = 2 * time.Second

// Watch polls until ctx is cancelled. It starts at once, so a container restart picks the open
// request up from the database without waiting a tick. A missed result only produces a warning
// (once per request ID); the flag is never closed here. Repeated identical errors log once.
func (s *Service) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var lastErr, warned string
	for {
		pr, err := s.Poll(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			if msg := err.Error(); msg != lastErr {
				s.Log.Warn("headscale config result poll failed", "err", err)
				lastErr = msg
			}
		default:
			lastErr = ""
		}
		if pr.Overdue && warned != pr.RequestID {
			s.Log.Warn("headscale config result has not arrived; maintenance stays open", "request_id", pr.RequestID, "wait", ResultWait.String())
			warned = pr.RequestID
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
