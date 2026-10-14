package seed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// HeadscaleUserName is the Headscale user test nodes register under via pre-auth key.
const HeadscaleUserName = "tagcess-test"

// HeadscaleResult is the Headscale user and pre-auth key SeedHeadscale produced or reused.
type HeadscaleResult struct {
	UserID     string
	PreAuthKey string
}

// SeedHeadscale creates (or reuses) a Headscale user and a reusable pre-auth key, so F1-021's
// end-to-end test can register a tailscale node without a browser (F1-004 [Ö]: this only concerns
// the local test stack — production nodes still register interactively through Zitadel OIDC).
//
// It shells out to `docker compose exec headscale headscale ...`: the admin gRPC is only reachable
// over headscale's unix socket (stack-notes/reference.md), and the CLI already talks to it from
// inside the same container. Safe to call repeatedly (AC2): it reuses an existing user and an
// existing unexpired reusable key when one is already there.
func SeedHeadscale(ctx context.Context, composeFile string) (*HeadscaleResult, error) {
	userID, err := getOrCreateHeadscaleUser(ctx, composeFile, HeadscaleUserName)
	if err != nil {
		return nil, err
	}
	cachePath := filepath.Join(filepath.Dir(composeFile), ".secrets", "headscale-preauthkey.json")
	key, err := getOrCreatePreAuthKey(ctx, composeFile, userID, cachePath)
	if err != nil {
		return nil, err
	}
	return &HeadscaleResult{UserID: userID, PreAuthKey: key}, nil
}

type hsUser struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type hsExpiration struct {
	Seconds int64 `json:"seconds"`
}

type hsPreAuthKey struct {
	ID         int64        `json:"id"`
	User       hsUser       `json:"user"`
	Key        string       `json:"key"`
	Reusable   bool         `json:"reusable"`
	Expiration hsExpiration `json:"expiration"`
}

func (k hsPreAuthKey) expired() bool {
	return k.Expiration.Seconds > 0 && time.Unix(k.Expiration.Seconds, 0).Before(time.Now())
}

// cachedPreAuthKey is what getOrCreatePreAuthKey persists to cachePath: `preauthkeys list`
// masks the key value ("hskey-auth-xxxx-***"), so the only way to reuse the full, usable key
// across seed runs is to have created it and remembered it ourselves.
type cachedPreAuthKey struct {
	ID  int64  `json:"id"`
	Key string `json:"key"`
}

func getOrCreateHeadscaleUser(ctx context.Context, composeFile, name string) (string, error) {
	var list []hsUser
	if err := headscaleJSON(ctx, composeFile, &list, "users", "list"); err != nil {
		return "", err
	}
	for _, u := range list {
		if u.Name == name {
			return strconv.FormatInt(u.ID, 10), nil
		}
	}
	var created hsUser
	if err := headscaleJSON(ctx, composeFile, &created, "users", "create", name); err != nil {
		return "", err
	}
	return strconv.FormatInt(created.ID, 10), nil
}

func getOrCreatePreAuthKey(ctx context.Context, composeFile, userID, cachePath string) (string, error) {
	// `preauthkeys list` has no --user filter (unlike `create`); filter client-side.
	var list []hsPreAuthKey
	if err := headscaleJSON(ctx, composeFile, &list, "preauthkeys", "list"); err != nil {
		return "", err
	}
	live := make(map[int64]hsPreAuthKey, len(list))
	for _, k := range list {
		if k.Reusable && !k.expired() && strconv.FormatInt(k.User.ID, 10) == userID {
			live[k.ID] = k
		}
	}

	if cached, err := readCachedPreAuthKey(cachePath); err != nil {
		return "", err
	} else if cached != nil {
		if _, ok := live[cached.ID]; ok {
			return cached.Key, nil
		}
		// Cached key's id is gone or expired server-side (e.g. `docker compose down -v` without
		// `make lab-down`); fall through and mint a new one.
	}

	var created hsPreAuthKey
	if err := headscaleJSON(ctx, composeFile, &created, "preauthkeys", "create", "--user", userID, "--reusable", "--expiration", "24h"); err != nil {
		return "", err
	}
	if created.Key == "" {
		return "", fmt.Errorf("seed: headscale preauthkeys create returned no key")
	}
	if err := writeCachedPreAuthKey(cachePath, cachedPreAuthKey{ID: created.ID, Key: created.Key}); err != nil {
		return "", err
	}
	return created.Key, nil
}

func readCachedPreAuthKey(path string) (*cachedPreAuthKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed path under this dev tool's own secrets dir
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("seed: read %s: %w", path, err)
	}
	var c cachedPreAuthKey
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("seed: parse %s: %w", path, err)
	}
	return &c, nil
}

func writeCachedPreAuthKey(path string, c cachedPreAuthKey) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("seed: marshal %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("seed: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("seed: write %s: %w", path, err)
	}
	return nil
}

// headscaleJSON runs `docker compose -f composeFile exec -T headscale headscale <args...> --output json`
// and decodes the result into v.
func headscaleJSON(ctx context.Context, composeFile string, v any, args ...string) error {
	full := append([]string{"compose", "-f", composeFile, "exec", "-T", "headscale", "headscale"}, args...)
	full = append(full, "--output", "json")
	cmd := exec.CommandContext(ctx, "docker", full...) // #nosec G204 -- fixed argv built from this dev tool's own args, not user input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("seed: docker %s: %w: %s", strings.Join(full, " "), err, strings.TrimSpace(stderr.String()))
	}
	if err := json.Unmarshal(stdout.Bytes(), v); err != nil {
		return fmt.Errorf("seed: parse headscale %s output: %w: %s", strings.Join(args, " "), err, stdout.String())
	}
	return nil
}
