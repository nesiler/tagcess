package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/nesiler/tagcess/internal/config"
)

func TestProbeServer(t *testing.T) {
	ctx := context.Background()
	var lc net.ListenConfig
	cfg := &config.Config{}
	cfg.UI.Socket = filepath.Join(t.TempDir(), "ui.sock")
	cfg.Hook.Listen = "127.0.0.1:0"

	// Pick a free hook port without binding it yet.
	hl, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hook.Listen = hl.Addr().String()
	_ = hl.Close()

	if err := probeServer(cfg, time.Second); err == nil {
		t.Fatal("probe passed before the server was ready")
	}

	ul, err := lc.Listen(ctx, "unix", cfg.UI.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ul.Close() }()
	if err := probeServer(cfg, time.Second); err == nil {
		t.Fatal("probe passed with only the UI socket up")
	}

	tl, err := lc.Listen(ctx, "tcp", cfg.Hook.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tl.Close() }()
	if err := probeServer(cfg, time.Second); err != nil {
		t.Fatalf("probe failed after both listeners were up: %v", err)
	}
}
