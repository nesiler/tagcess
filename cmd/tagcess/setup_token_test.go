package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nesiler/tagcess/internal/config"
	"github.com/nesiler/tagcess/internal/setup"
	"github.com/nesiler/tagcess/internal/store"
)

func TestSetupToken_ReplacesTokenAndEndsSessions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	old := setup.New(st.Queries(), "")
	live, err := old.NewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := old.Exchange(ctx, live, "a") // a live setup session when the CLI runs
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Validate(ctx, cookie); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(dir, "setup-token")
	var out, errb bytes.Buffer
	if code := runSetupToken(&config.Config{DataDir: dir}, file, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	newToken := strings.TrimSpace(out.String())
	if newToken == "" || newToken == live {
		t.Fatalf("printed token %q", newToken)
	}
	if body, err := os.ReadFile(file); err != nil || strings.TrimSpace(string(body)) != newToken {
		t.Fatalf("token file: %q %v", body, err)
	}

	st, err = store.Open(ctx, filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := setup.New(st.Queries(), "")
	if _, err := svc.Validate(ctx, cookie); err == nil {
		t.Fatal("an earlier setup session survived -setup-token")
	}
	if _, err := svc.Exchange(ctx, newToken, "b"); err != nil {
		t.Fatalf("the new token does not work: %v", err)
	}
}
