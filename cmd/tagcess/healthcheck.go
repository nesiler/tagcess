package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/nesiler/tagcess/internal/config"
)

// healthcheckTimeout bounds each dial of -healthcheck; a listener that is not there fails fast.
const healthcheckTimeout = 2 * time.Second

// probeServer reports whether the running server is ready: serve opens the database before it
// binds the UI socket and the hook listener, so both accepting connections means it got that far.
// Local only; GET /healthz on the UI socket is the HTTP liveness signal.
func probeServer(cfg *config.Config, timeout time.Duration) error {
	for _, t := range []struct{ name, network, addr string }{
		{"ui socket", "unix", cfg.UI.Socket},
		{"hook listener", "tcp", cfg.Hook.Listen},
	} {
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(context.Background(), t.network, t.addr)
		if err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
		_ = c.Close()
	}
	return nil
}
