package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/internal/setup"
	"github.com/nesiler/tagcess/internal/store"
)

// runSetupToken is `tagcess -setup-token` (setup-flow.md §2.1): it replaces the setup token, ends
// every setup session, writes the plain token to tokenFile and prints it on stdout, the one place
// it is shown. It runs on the host through `docker compose exec`, so reaching it already needs
// root or the docker group.
func runSetupToken(cfg *config.Config, tokenFile string, stdout, stderr io.Writer) int {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, dbName))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tagcess: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()
	token, err := setup.New(st.Queries(), tokenFile).NewToken(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tagcess: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, token)
	return 0
}
